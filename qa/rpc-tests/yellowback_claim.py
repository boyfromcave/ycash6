#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Claims (plan §3.5 CLAIM, §3.8 RED-4, §4.6) on the vault upgrade (upgrade plan U-23):

  - a price crash (every pool quotes $0.01, 64 blocks round-robin) pulls P_claim = max(pMid, pSlow)
    down once two-thirds of the slow window is low quotes; the divergence halt fires meanwhile
    without touching claims (HALT-3 is MINT-4 only);
  - an under-collateralised mint (Z) is an invalid transaction: refused by every Yellowback
    mempool and rejected in a block, no vault;
  - in-term claims (IT-1/IT-2): the V's APP branch is open from the block after the mint, so a
    vault that goes under theta inside its term is claimable at once; node 5's wallet claims V3 in
    term with yed_claim: the vault moves into a claimant intent (CLAIMING), supply down by the
    debt; after CLAIM_DELAY vault_release pays the claimant (CLAIMED);
  - a claim on a healthy vault is refused by the wallet (claim-not-underwater, in term and past
    claimHeight alike) and,
    as a raw transaction, refused by every Yellowback mempool and rejected in a block (RED-4,
    DoS 100: bad-yellowback-vault-claim-not-underwater);
  - the owner still redeems an underwater vault via the owner path (selector 2);
  - red4_underwater_at_r_not_at_h: the rule reads Snapshots[R], not the price at H;
  - assert_model_matches(node, full=True) at the end (P8).
The v2 sweep, sunset and abandonment cases left with the enforcement machinery (upgrade plan §6).

Nodes: 0 user (vault owner), 1 stock, 2-4 pools, 5 observer (the claimant).
"""

from test_framework.util import (
    assert_equal,
    assert_greater_than,
    bytes_to_hex_str,
    hex_str_to_bytes,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_util import (
    CLAIM_DELAY,
    POOLS,
    RESIDUAL_MIN_ZAT,
    REF_LAG,
    STOCK,
    YellowbackTestFramework,
    assert_best_hash,
    assert_same_statehash,
    build_mint_tx,
    build_vault_spend_raw,
    fee_zat,
    mine_block_raw,
    set_quote,
)
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import ArmedModeMixin, armed_raw_claim

OVERLAY = [0, 2, 3, 4, 5]


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


def outpoint_selector(txid, n=0):
    return bytes_to_hex_str(bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little'))


def coin_of(node, cents):
    for c in node.yed_listunspent():
        if c['cents'] == cents and not c['spentUnconfirmed']:
            return c
    raise AssertionError('no %d-cent coin on the node' % cents)


class YellowbackClaimTest(ArmedModeMixin, YellowbackTestFramework):

    def sync_all(self, blocks_only=False):
        """Blocks everywhere; mempools among the overlay nodes only — the stock node keeps the raw
        claim of a healthy vault that every overlay mempool refuses (MP-1), so a six-node mempool
        sync could never converge."""
        for g in self.groups():
            nodes = [self.nodes[i] for i in g if self.nodes[i] is not None]
            sync_blocks(nodes)
            if not blocks_only:
                sync_mempools([self.nodes[i] for i in g if self.nodes[i] is not None and i != STOCK])

    def raw_claim(self, node, vault, burn_cents, ref_height):
        """A claim-path spend from ``node``'s YED with the FEE-W default payee for the vault's selector."""
        coin = coin_of(node, burn_cents)
        payees = node.yed_getfeepayee(ref_height, vault['collateralZat'], outpoint_selector(vault['txid']))
        fee = (payees['default']['payoutAddress'], payees['feeZat'])
        if self.armed:
            # v3: the carrier (mined first) as vin[last], the bundle at R and the attestor fee (AFEE-1)
            return armed_raw_claim(self, node, vault, [(coin['txid'], coin['vout'])], ref_height, self.price_at(node, ref_height, 'pClaim'), fee)
        payload = ym.encode_redeem(ref_height, 1, [])
        return build_vault_spend_raw(node, vault, 'claim', [(coin['txid'], coin['vout'])], payload=payload,
                                     fee=fee, ref_height=ref_height)

    def price(self, usd):
        """Set the same quote on all three pools (framework `quote` takes a node index)."""
        for i in POOLS:
            set_quote(self.nodes[i], usd)

    def run_test(self):
        nodes = self.nodes
        user, stock, claimant = nodes[0], nodes[STOCK], nodes[5]
        self.current_quote = 50

        print('activate at $50; fund the claimant')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        user.sendtoaddress(claimant.getnewaddress(), 5)
        self.sync_all()
        self.mine(POOLS[0])
        self.arm()

# Rule: MINT-1 MINT-5
        print('mint the vaults U (healthy refusals), V (raw claim), W (owner path); Z is an invalid mint')
        mints = {}
        for name in ('U', 'V', 'W'):
            mints[name] = self.mint(user, 10000, 48)
        r = user.yed_getinfo()['height'] - REF_LAG
        z_hex, _ = build_mint_tx(user, 10000, 48, r, self.estimate(user, 10000, 48)['requiredZat'] - 1000)
        z_txid = user.decoderawtransaction(z_hex)['txid']
        self.sync_all()
        self.mine(POOLS[1])
        # U-23: a MINT that fails a rule is an invalid transaction, not a VOID vault
        for i in OVERLAY:
            assert_rpc_error('bad-yellowback-bad-mint-collateral', nodes[i].sendrawtransaction, z_hex)
        result, _ = mine_block_raw(nodes[POOLS[2]], [z_hex])
        assert_equal(result, 'bad-yellowback-bad-mint-collateral')
        self.sync_all(blocks_only=True)
        for name, m in mints.items():
            assert_equal(user.yed_getvault(m['txid'])['status'], 'ACTIVE')
        assert_rpc_error('vault-not-found', user.yed_getvault, z_txid)
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 30000)
        claim_height = user.yed_getvault(mints['U']['txid'])['claimHeight']

        print('the claimant receives 100.50 YED; the vaults stay healthy in term and past claimHeight')
        user.yed_send(claimant.yed_getnewaddress(), 10050)
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 10050)
# Rule: RED-4 IT-2
        assert_greater_than(user.yed_getvault(mints['U']['txid'])['lockHeight'], user.getblockcount())   # in term
        assert_rpc_error('claim-not-underwater', claimant.yed_claim, *self.claim_args(claimant, mints['U']['txid']))
        self.mine_round_robin(POOLS, claim_height - user.getblockcount())
        assert_equal(user.yed_listclaimable(), [])
        assert_rpc_error('claim-not-underwater', claimant.yed_claim, *self.claim_args(claimant, mints['U']['txid']))
        assert_rpc_error('vault-not-found', claimant.yed_claim, z_txid)
        assert_rpc_error('vault-not-found', claimant.yed_claim, '11' * 32)

# Rule: RED-4 MP-1 BLK-1
        print('raw claim of the healthy vault U: every Yellowback mempool refuses it, a block carrying it is rejected')
        r = user.getblockcount()
        vault_u = user.yed_getvault(mints['U']['txid'])
        hex_u = self.raw_claim(claimant, vault_u, 10050, r)
        v = nodes[2].yed_validaterawtransaction(hex_u)
        assert_equal((v['valid'], v['verdict'], v['path'], v['blockValid'], v['wouldBeRejected']), (True, 'vault-claim-not-underwater', 'claim', False, True))
        stock_txid = stock.sendrawtransaction(hex_u)         # the stock node has no YED attestor set: the module is inert there
        assert stock_txid in stock.getrawmempool()
        for i in OVERLAY:
            assert_rpc_error('bad-yellowback-vault-claim-not-underwater', nodes[i].sendrawtransaction, hex_u)
        result, _ = mine_block_raw(nodes[3], [hex_u])
        assert_equal(result, 'bad-yellowback-vault-claim-not-underwater')
        assert_equal(nodes[3].yed_getvault(mints['U']['txid'])['status'], 'ACTIVE')

# Rule: PRICE-1 PRICE-2 HALT-3 RED-4
        print('mint V3 (class C, 145 blocks: it stays in term through the crash) just before the crash, then every pool quotes $0.01 for 64 blocks')
        mint_v3 = self.mint(user, 10000, 145)
        self.sync_all()
        self.mine(POOLS[0])
        v3_claim_height = user.yed_getvault(mint_v3['txid'])['claimHeight']
        self.current_quote = '0.01'
        self.price('0.01')
        self.mine_round_robin(POOLS, 8 + REF_LAG)
        assert 'DIVERGENCE' in user.yed_getstats()['haltMask']
        assert_equal(user.yed_getstats()['mintingAllowed'], False)
        before = user.yed_getprice()
        self.mine_round_robin(POOLS, 64 - 8 - REF_LAG)
        price = user.yed_getprice()
        assert_equal(price['pMid'], 10000)
        assert_equal(price['pSlow'], 10000)
        assert_equal(price['pClaim'], 10000)
        assert_greater_than(before['pClaim'], price['pClaim'])
        claimable = {c['vault']: c for c in user.yed_listclaimable()}
        for name, m in mints.items():
            assert m['txid'] + ':0' in claimable, name
        assert mint_v3['txid'] + ':0' in claimable              # IT-2: V3 is in term and under theta: claimable now
        row = claimable[mints['V']['txid'] + ':0']
        assert_equal((row['mintedCents'], row['pClaim'], row['feeZat']), (10000, 10000, fee_zat(row['collateralZat'])))
        assert_equal(user.yed_getvault(mints['V']['txid'])['claimable'], True)
        assert_equal(nodes[2].yed_getstats()['mintingAllowed'], False)

# Rule: RED-4 IT-1 IT-2
        print('in term (before lockHeight, long before claimHeight) the raw claim of V3 is valid: the APP branch opened at the mint')
        vault_v3 = user.yed_getvault(mint_v3['txid'])
        assert_greater_than(vault_v3['lockHeight'], user.getblockcount())
        assert_greater_than(v3_claim_height, user.getblockcount())
        hex_early = self.raw_claim(claimant, vault_v3, 10050, user.getblockcount())
        early = ym.tx_from_hex(hex_early)
        assert_equal(early.lock_time, vault_v3['refHeight'] + 1)                       # nLockTime = the V's appHeight
        v = nodes[2].yed_validaterawtransaction(hex_early)
        assert_equal((v['valid'], v['verdict'], v['path'], v['blockValid']), (True, 'ok', 'claim', True))

# Rule: XFER-1 RED-2
        print('the floor bites a plain send of the 100.50 YED coin; the claim path burns instead (H2/H4)')
        # Phase 8 H4: yed_claim no longer refuses with change-floor here -- the selector burns a
        # sub-dollar remainder rather than refuse (doc/yellowback-rpc.md, yed_redeem/yed_claim).
        # A plain transfer has no such escape, so the floor is still observable on yed_send.
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 10050)
        est = claimant.yed_estimatesend(10000)
        assert_equal((est['workable'], est['error']), (False, 'change-floor'))
        assert_rpc_error('change-floor', claimant.yed_send, user.yed_getnewaddress(), 10000)
        user.yed_send(claimant.yed_getnewaddress(), 100)
        self.sync_all()
        self.mine(POOLS[1])

# Rule: RED-1 RED-2 RED-3 RED-4 IN-2 IN-3 MP-1 FEE-1
        print('the claimant claims V3 with yed_claim: the vault moves into the claimant intent (CLAIMING)')
        r = user.getblockcount()
        vault_v3 = user.yed_getvault(mint_v3['txid'])
        payees = user.yed_getfeepayee(r, vault_v3['collateralZat'], outpoint_selector(mint_v3['txid']))
        supply_before = nodes[2].yed_getstats()['supplyCents']
        # yed_listclaimable.residualZat is what the builder pays: RED-5's floor applied (0 below RESIDUAL_MIN_ZAT)
        listed = {x['vault']: x for x in claimant.yed_listclaimable()}
        for row in listed.values():
            assert row['residualZat'] == 0 or row['residualZat'] >= RESIDUAL_MIN_ZAT, row
        listed_v3 = listed[mint_v3['txid'] + ':0']
        claimed = self.claim(claimant, mint_v3['txid'])
        assert_equal(listed_v3['residualZat'], claimed['residualZat'])
        assert_equal(claimed['burnedCents'], 10000)
        assert_equal(claimed['feeZat'], payees['feeZat'])
        assert_equal(claimed['payee'], payees['default']['payoutAddress'])
        # U-23: the claimant intent carries the collateral less the RED-5 residual; the fees come from the claimant's YEC
        assert_equal(claimed['collateralOut'], vault_v3['collateralZat'] - claimed['residualZat'])
        assert_equal((claimed['claimPath'], claimed['residualZat'], claimed['pending']), ('a', 0, False))
        raw = claimant.getrawtransaction(claimed['txid'], 1)
        assert_equal(raw['locktime'], vault_v3['refHeight'] + 1)          # IT-1: the APP branch's CLTV, not claimHeight
        assert_greater_than(v3_claim_height, user.getblockcount())        # still in term: an in-term claim
        assert_equal(raw['vin'][0]['txid'], mint_v3['txid'])
        assert_equal(raw['vin'][0]['scriptSig']['hex'], '54')            # OP_4: the V's claim selector
        assert_equal(raw['vin'][-1]['txid'], claimed['carrierTxid'])      # the carrier last (never vin[0])
        assert_equal(raw['vout'][0]['valueZat'], claimed['collateralOut'])
        assert ym.yed_intent_fields(hex_str_to_bytes(raw['vout'][0]['scriptPubKey']['hex'])) is not None
        assert_equal(nodes[2].yed_validaterawtransaction(raw['hex'])['verdict'], 'ok')
        self.sync_all()
        self.mine(POOLS[2])
        claim_block_height = user.getblockcount()
        for i in OVERLAY:
            c = nodes[i].yed_getvault(mint_v3['txid'])
            assert_equal((c['status'], c['burnedCents'], c['unbacked'], c['feePaidZat']), ('CLAIMING', 10000, False, claimed['feeZat']))
            assert_equal([(x['txid'], x['vout'], x['role'], x['releaseHeight']) for x in c['intents']],
                         [(claimed['txid'], 0, 'claimant', claim_block_height + CLAIM_DELAY)])
        assert_equal(nodes[2].yed_getstats()['supplyCents'], supply_before - 10000)
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 150)
        info = nodes[2].yed_gettxinfo(claimed['txid'])
        assert_equal((info['type'], info['path'], info['verdict'], info['burned']), ('redeem', 'claim', 'ok', 10000))
        assert_equal([x['type'] for x in claimant.yed_listtransactions() if x['txid'] == claimed['txid']], ['claim'])
        assert_equal([x['type'] for x in user.yed_listtransactions() if x['txid'] == claimed['txid']], ['claimed'])
        assert_rpc_error('vault-not-active', claimant.yed_claim, mint_v3['txid'])
        assert_rpc_error('vault-not-active', user.yed_redeem, mint_v3['txid'])
        self.checkpoint('claim of V3')

# Rule: RED-1
        print('the release waits CLAIM_DELAY, then vault_release pays the claimant: CLAIMED')
        intent = '%s:0' % claimed['txid']
        assert_rpc_error('matures at height', claimant.vault_release, intent)
        self.mine_round_robin(POOLS, claim_block_height + CLAIM_DELAY - 1 - user.getblockcount())
        yec_before = claimant.getbalance()
        released = claimant.vault_release(intent)
        self.sync_all()
        self.mine(POOLS[0])
        for i in OVERLAY:
            c = nodes[i].yed_getvault(mint_v3['txid'])
            assert_equal(c['status'], 'CLAIMED')
            assert 'intents' not in c
        assert_equal(nodes[2].yed_getstats()['claimedVaults'], 1)
        assert_greater_than(claimant.getbalance(), yec_before + 9)
        assert_equal(nodes[2].yed_gettxinfo(released)['type'], 'claim_release')
        self.checkpoint('release of V3')

# Rule: RED-1 RED-2 RED-3 RED-4
        print('the owner can still redeem the underwater vault W via the owner path')
        redeemed = user.yed_redeem(mints['W']['txid'])
        assert_equal(redeemed['burnedCents'], 10000)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[2].yed_getvault(mints['W']['txid'])['status'], 'CLOSED')
        assert_equal(nodes[2].yed_getvault(mints['W']['txid'])['unbacked'], False)

# Rule: RED-4
        print('red4_underwater_at_r_not_at_h: the claim is built at R, the price recovers by H, the claim is still valid')
        user.yed_send(claimant.yed_getnewaddress(), 10000)
        self.sync_all()
        self.mine(POOLS[1])
        r = user.getblockcount()
        vault_v = user.yed_getvault(mints['V']['txid'])
        assert_equal(vault_v['claimable'], True)
        hex_v = self.raw_claim(claimant, vault_v, 10000, r)
        self.current_quote = 50
        self.price(50)
        self.mine_round_robin(POOLS, 30)
        assert_equal(user.yed_getprice()['pClaim'], 50000000)         # pMid recovered
        assert_equal(user.yed_getvault(mints['V']['txid'])['claimable'], False)
        assert mints['V']['txid'] + ':0' not in {c['vault'] for c in user.yed_listclaimable()}
        assert_rpc_error('claim-not-underwater', claimant.yed_claim, *self.claim_args(claimant, mints['V']['txid']))
        v = nodes[2].yed_validaterawtransaction(hex_v)
        assert_equal((v['verdict'], v['blockValid'], v['wouldBeRejected'], v['mempoolExpiryOk']), ('ok', True, False, True))
        late_txid = nodes[2].sendrawtransaction(hex_v)
        self.sync_all()
        self.mine(POOLS[2])
        c = nodes[2].yed_getvault(mints['V']['txid'])
        assert_equal((c['status'], c['intents'][0]['txid']), ('CLAIMING', late_txid))
        self.mine_round_robin(POOLS, CLAIM_DELAY - 1)
        claimant.vault_release('%s:0' % late_txid)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[2].yed_getvault(mints['V']['txid'])['status'], 'CLAIMED')
        assert_equal(nodes[2].yed_getstats()['claimedVaults'], 2)
        self.checkpoint('claim at R vs H')

        print('the Python model over the whole chain (P8)')
        self.model_check(nodes[0])
        self.sync_all(blocks_only=True)
        assert_best_hash(self.enforcing_nodes(), 'end')
        assert_same_statehash(self.enforcing_nodes(), 'end')


if __name__ == '__main__':
    YellowbackClaimTest().main()
