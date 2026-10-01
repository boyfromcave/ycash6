#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Enforcement under v3 (v3 plan Phase A2): the stock miner (node 1) mines an ACTIVE-vault claim
that breaks a v3 rule and the enforcing nodes reject the block at DoS 0 while the observer
(node 5, -yellowbackenforce=0) follows it.

1. ``unarmed_v2_behaviour``: with no registrations the v2 enforcement cases run unchanged —
   imported from yellowback_enforcement.py (case 4 before activation, activation and the eight
   vaults, case 1 owner-path-no-burn, case 2's claim and fee variants, case 13 M3, case 3 the
   correct spends from the stock node, case 10 garbage coinbases, case 7 bookkeeping; cases 5,
   6, 11, 12 and 15 — kill switch, storage faults, the two reorg cases and the catch-up — are
   the v2 script's own and are not repeated here).
2. ``register_and_arm`` (five attestors), then armed: a claim without a bundle mined by node 1
   => rejected ``yellowback-vault-spend`` (RED-1's bundle clause) by nodes 0, 2-4 (and 6-7), node 5
   follows; DoS 0; a claim paying no residual (the emergency path) => rejected (RED-5); a correct
   emergency claim from node 1's mempool => accepted everywhere with the residual paid; the valve
   still clears after six blocks armed (v2 case 9 re-run).

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer, 6-7 attestor wallets.
"""

from decimal import Decimal

from test_framework.util import assert_equal, assert_greater_than, bytes_to_hex_str, hex_str_to_bytes, sync_blocks
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import (
    build_carrier_tx,
    feed_all,
    outpoint_selector,
    post_notice_raw,
    register_and_arm,
)
from test_framework.yellowback_util import (
    ATTEST_FEE_BPS,
    ATTESTOR_A,
    ATTESTOR_B,
    BPS,
    EMERGENCY_PERSIST,
    ENFORCING,
    OBSERVER,
    POOLS,
    REF_LAG,
    STOCK,
    USER,
    assert_banscore_zero,
    assert_best_hash,
    assert_same_statehash,
    build_vault_spend_raw,
    fee_zat,
    pubkey_to_address,
    wait_yed_healthy,
)
from yellowback_enforcement import CRASH_PRICE, PRICE, YellowbackEnforcementTest, rpc_error, spk

EMERG_X = Decimal('12.00')    # pools: the vault minted at $20 with 500 % becomes 300 %-covered
EMERG_A = Decimal('4.00')     # attestors: pEmerg under EMERGENCY_RATIO_BPS
V3_ENFORCING = ENFORCING + [ATTESTOR_A, ATTESTOR_B]


# Rule: RED-1 RED-4 RED-5 BUNDLE-1 NOT-1 BLK-1 BLK-2 ACT-7 AFEE-1
class YellowbackAttestEnforcementTest(YellowbackEnforcementTest):
    # the attestor wallets join the enforcing half directly (the base topology hangs them off node 1 alone)
    EDGES = YellowbackEnforcementTest.EDGES + [(0, 6), (0, 7)]

    def __init__(self):
        super().__init__()
        self.num_nodes = 8

    # ------------------------------------------------------------------ helpers (the attest script's shapes, compact)

    def attest_fee(self, collateral_zat):
        return fee_zat(collateral_zat) * ATTEST_FEE_BPS // BPS

    def bond_key_address(self, seq):
        return [r for r in self.nodes[USER].yed_listattestors() if int(r['seq']) == seq][0]['bondKeyAddress']

    def carrier_step(self, bundle_hex):
        carrier = build_carrier_tx(self.nodes[USER], hex_str_to_bytes(bundle_hex))
        self.sync_all()
        self.pools_mine(1, 'carrier')
        return carrier

    def vault_bundle(self, vault_txid, prices):
        """Feed node 0's pool at ``prices`` for R = tip - REF_LAG and build the node's bundle for the vault."""
        user = self.nodes[USER]
        ref = user.getblockcount() - REF_LAG
        feed_all(user, prices, cited=ref)
        return ref, user.yed_buildbundle(ref, bytes_to_hex_str(outpoint_selector(vault_txid, 0)))

    def claim_hex(self, vault, ref, built=None, residual=None, expiry=None):
        """A claim of ``vault`` at ``ref``: v2-shaped (no carrier, no attestor fee) when ``built`` is
        None, else with the carrier, the attestor fee to the bundle's first seq and ``residual`` to the
        owner when given. ``expiry=0`` on the adversarial ones (the v2 script's M13 convention)."""
        user = self.nodes[USER]
        live = self.live_vault(vault)
        collateral = int(live['collateralZat'])
        payee = user.yed_getfeepayee(ref, collateral)
        fee = (payee['default']['payoutAddress'], int(payee['feeZat']))
        if built is None:
            return build_vault_spend_raw(user, live, 'claim', [vault['token']], payload=ym.encode_redeem(ref, 1, []),
                                         fee=fee, ref_height=ref, expiry=expiry)
        carrier = self.carrier_step(built['hex'])
        extra = [(self.attest_fee(collateral), spk(user, self.bond_key_address(built['seqs'][0])))]
        if residual:
            extra.append((int(residual), spk(user, pubkey_to_address(hex_str_to_bytes(live['ownerPubKey'])))))
        return build_vault_spend_raw(user, live, 'claim', [vault['token']], payload=ym.encode_redeem(ref, 1, [], attest_fee_vout=2),
                                     fee=fee, ref_height=ref, extra_outputs=extra, charge_extra=True, carrier=carrier, expiry=expiry)

    def assert_rejected_v3(self, blockhash, verdict):
        """Every enforcing node (6-7 included) rejected the block with ``verdict`` at DoS 0; node 5 followed it."""
        self.assert_rejected_everywhere(blockhash, nodes=V3_ENFORCING)
        for i in V3_ENFORCING:
            reason = self.nodes[i].yed_getblockverdict(blockhash)['reason']
            assert reason.startswith(verdict + ':'), 'node %d: %s' % (i, reason)
        sync_blocks([self.nodes[STOCK], self.nodes[OBSERVER]], timeout=60)
        assert_equal(self.nodes[OBSERVER].getbestblockhash(), blockhash)
        assert_banscore_zero([n for n in self.nodes if n is not None])
        self.rejected_hashes.append(blockhash)

    # ------------------------------------------------------------------ run

    def run_test(self):
        for node in self.enforcing_nodes():
            wait_yed_healthy(node)
        assert_equal(self.nodes[USER].yed_getinfo()['attest']['status'], 'UNARMED')

        v2_cases = [
            self.case4_before_activation_accepts,
            self.activate_and_mint,
            self.case1_owner_path_no_burn,
            self.case2_claim_and_fee_variants,
            self.case13_m3_vault_spend_with_mint_payload,
            self.case3_correct_spends_from_the_stock_node,
            self.case10_tag4_garbage_coinbase_never_invalid,
            self.case7_bookkeeping,
        ]
        armed_cases = [
            self.arm,
            self.armed_claim_without_bundle_rejected,
            self.armed_claim_without_residual_rejected_then_correct_accepted,
            self.case9_work_valve,
        ]
        wanted = set(self.options.only.split(',')) if self.options.only else None
        print('=== unarmed_v2_behaviour: the v2 enforcement cases with no registration')
        for case in v2_cases:
            if wanted is None or case.__name__ in wanted or case.__name__ == 'activate_and_mint':
                print('=== %s' % case.__name__)
                case()
        assert_equal(self.nodes[USER].yed_getinfo()['attest']['status'], 'UNARMED')
        for case in armed_cases:
            if wanted is None or case.__name__ in wanted or case.__name__ == 'arm':
                print('=== %s' % case.__name__)
                case()

    # ------------------------------------------------------------------ armed

    def arm(self):
        for i in POOLS:
            self.quote(i, PRICE)
        self.seqs = register_and_arm(self, 5)
        self.pools_mine(REF_LAG, 'ref lag')
        for i in V3_ENFORCING:
            assert_equal(self.nodes[i].yed_getinfo()['attest']['armed'], True)
        assert_equal(self.nodes[OBSERVER].yed_getinfo()['attest']['status'], 'ARMED')
        self.cp('armed')

    def armed_claim_without_bundle_rejected(self):
        """Armed, a claim in v2's shape (no carrier) fails RED-1's bundle clause: MP-1 refuses it on
        every overlay node, node 1 mines it, the block is rejected with red1-bundle-shape at DoS 0 by
        0, 2-4, 6-7, node 5 follows, the pools out-mine and the vault is still ACTIVE."""
# Rule: RED-1
# Rule: BUNDLE-1
# Rule: BLK-1
# Rule: MP-1
        user = self.nodes[USER]
        print('  crashing the price (pools and attestors at $%s) so the vault is underwater' % CRASH_PRICE)
        self.crash_price()
        v = self.vault(6)
        crashed = {seq: Decimal(CRASH_PRICE) for seq in self.seqs}
        ref, built = self.vault_bundle(v['txid'], crashed)
        assert v['txid'] + ':0' in [r['vault'] for r in user.yed_listclaimable()], 'vault 6 is not claimable'
        hex_ = self.claim_hex(v, ref, None, expiry=0)
        check = user.yed_validaterawtransaction(hex_)
        assert_equal((check['blockValid'], check['verdict'], check['wouldBeRejected']), (False, 'red1-bundle-shape', True))
        rpc_error('yellowback-vault-spend', user.sendrawtransaction, hex_)
        self.reset_peer_scores()      # the N1 assertion below measures Yellowback alone (stock tx-expired / bad-prevblk points, see reset_peer_scores)
        blockhash, txid = self.stock_block_with(hex_)
        self.assert_rejected_v3(blockhash, 'red1-bundle-shape')
        assert_equal(self.nodes[OBSERVER].yed_getvault(v['txid'])['status'], 'CLOSED')     # node 5 applied the failing spend
        self.pools_outmine(blockhash)
        for i in V3_ENFORCING + [OBSERVER]:
            assert_equal(self.nodes[i].yed_getvault(v['txid'])['status'], 'ACTIVE')
        assert_same_statehash([self.nodes[i] for i in V3_ENFORCING + [OBSERVER]], 'after the out-mine')
        self.vault6_bundle_ref = ref

    def armed_claim_without_residual_rejected_then_correct_accepted(self):
        """The emergency path on vault 7: pools at $12 (300 %-covered), attestors at $4 (pEmerg
        under EMERGENCY_RATIO): a notice, EMERGENCY_PERSIST blocks, a claim carrying the bundle but no
        residual mined by node 1 => rejected red5-residual (node 5 follows); then the correct claim
        with the residual, from node 1's mempool => accepted everywhere, CLAIMED by clause (b)."""
# Rule: RED-5
# Rule: RED-4
# Rule: NOT-1
# Rule: BLK-1
        user = self.nodes[USER]
        v = self.vault(7)
        for i in POOLS:
            self.quote(i, EMERG_X)
        self.pools_mine(36, 'pools at $%s' % EMERG_X)
        emerg = {seq: EMERG_A for seq in self.seqs}
        ref, built = self.vault_bundle(v['txid'], emerg)
        assert_equal([r['vault'] for r in user.yed_listclaimable()], [])
        carrier = self.carrier_step(built['hex'])
        notice_txid = user.sendrawtransaction(post_notice_raw(user, (v['txid'], 0), ref, carrier))
        self.sync_all()
        self.pools_mine(1, 'notice')
        n = user.yed_getnotice(v['txid'])
        assert_equal((n['found'], n['txid'], n['refHeight']), (True, notice_txid, ref))
        while user.getblockcount() - REF_LAG < ref + EMERGENCY_PERSIST:
            self.pools_mine(1, 'persist')
        rows = [r for r in user.yed_listclaimable() if r['vault'] == v['txid'] + ':0']
        assert_equal([(r['claimPath'], r['noticed']) for r in rows], [('b', True)])
        residual = int(rows[0]['residualZat'])
        assert_greater_than(residual, 100_000)

        print('  a claim carrying the bundle but no residual, mined by node 1')
        ref2, built2 = self.vault_bundle(v['txid'], emerg)
        bad = self.claim_hex(v, ref2, built2, residual=None, expiry=0)
        check = user.yed_validaterawtransaction(bad)
        assert_equal((check['blockValid'], check['verdict']), (False, 'red5-residual'))
        rpc_error('yellowback-vault-spend', user.sendrawtransaction, bad)
        self.reset_peer_scores()      # the out-mine of the previous case's stock block accrues a stock tx-expired point at DoS 10
        blockhash, _txid = self.stock_block_with(bad)
        self.assert_rejected_v3(blockhash, 'red5-residual')
        self.pools_outmine(blockhash)
        for i in V3_ENFORCING + [OBSERVER]:
            assert_equal(self.nodes[i].yed_getvault(v['txid'])['status'], 'ACTIVE')
            assert_equal(self.nodes[i].yed_getnotice(v['txid'])['found'], True)

        print('  the correct claim with the residual, from node 1\'s mempool')
        ref3, built3 = self.vault_bundle(v['txid'], emerg)
        rows = [r for r in user.yed_listclaimable() if r['vault'] == v['txid'] + ':0']
        residual = int(rows[0]['residualZat'])
        good = self.claim_hex(v, ref3, built3, residual=residual)
        check = user.yed_validaterawtransaction(good)
        assert_equal((check['blockValid'], check['verdict'], check['wouldBeRejected']), (True, 'ok', False))
        stock = self.nodes[STOCK]
        txid = stock.sendrawtransaction(good)
        blockhash = stock.generate(1)[0]
        assert txid in stock.getblock(blockhash)['tx']
        self.cp('correct emergency claim mined by the stock node')
        assert_best_hash([n for n in self.nodes if n is not None], 'correct emergency claim')
        for i in V3_ENFORCING + [OBSERVER]:
            assert_equal(self.nodes[i].yed_getvault(v['txid'])['status'], 'CLAIMED')
            info = self.nodes[i].yed_gettxinfo(txid)
            assert_equal((info['verdict'], info['claimPath'], info['residualZat']), ('ok', 'b', residual))
            assert_equal(self.nodes[i].yed_getnotice(v['txid']), {'found': False})
        assert_banscore_zero([n for n in self.nodes if n is not None])
        for i in POOLS:
            self.quote(i, PRICE)


if __name__ == '__main__':
    YellowbackAttestEnforcementTest().main()
