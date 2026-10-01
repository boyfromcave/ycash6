#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Claims and sweeps (plan §3.5 CLAIM / SWEEP, §3.8 RED-4, §4.6, L10, L12, L13):

  - a price crash (every pool quotes $0.01, 64 blocks round-robin) pulls P_claim = max(pMid, pSlow)
    down once two-thirds of the slow window is low quotes; the divergence halt fires meanwhile
    without touching claims (HALT-3 is MINT-4 only);
  - before claimHeight a claim fails CLTV (sendrawtransaction: non-final); after it node 5's
    wallet claims with yed_claim: vault CLAIMED, supply down by the debt, claimant holds the
    collateral; the change floor from yed_claim;
  - a claim on a healthy vault is refused by the wallet (claim-not-yet, claim-not-underwater) and,
    as a raw transaction broadcast from node 1, refused by every enforcing mempool and rejected in
    a block (RED-4); a VOID vault's claim path is refused by the wallet (vault-not-active);
  - the owner still redeems an underwater vault via the owner path;
  - red4_underwater_at_r_not_at_h: the rule reads Snapshots[R], not the price at H;
  - sweep_refused_when_merely_suspended, sweep_builds_under_abandonment,
    sweep_relayed_by_own_node, sunset_alone_is_not_abandonment,
    sweep_after_sunset_without_successor;
  - assert_model_matches(node, full=True) at the end (P8).

Nodes: 0 user (vault owner; later also a signalling tagger), 1 stock, 2-4 pools, 5 observer
(the claimant).
"""

from test_framework.util import (
    assert_equal,
    assert_greater_than,
    bytes_to_hex_str,
    sync_blocks,
    sync_mempools,
)
from test_framework.yellowback_util import (
    ABANDON_BLOCKS,
    ENFORCEMENT_FLOOR,
    ENFORCEMENT_RESUME,
    POOLS,
    REF_LAG,
    STOCK,
    TOKEN_VALUE,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
    assert_banscore_zero,
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
from test_framework.yellowback_util import CARRIER_VALUE

SWEEP_ACK = 'I understand this leaves YED unbacked'
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

    def set_pools(self, extra):
        for i in POOLS:
            self.restart(i, extra)
        self.price(self.current_quote)

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
        print('mint the vaults U (healthy refusals, sweep), V (raw claim), W (owner path), T (sunset sweep) and a VOID Z')
        mints = {}
        for name in ('U', 'V', 'W', 'T'):
            mints[name] = self.mint(user, 10000, 48)
        r = user.yed_getinfo()['height'] - REF_LAG
        z_hex, _ = build_mint_tx(user, 10000, 48, r, self.estimate(user, 10000, 48)['requiredZat'] - 1000)
        z_txid = user.decoderawtransaction(z_hex)['txid']
        self.sync_all()
        self.mine(POOLS[1])
        # TPL-2 (strict, the daemon default) skips a MINT whose verdict would be VOID, so no
        # node's template will ever carry Z: its block is assembled in Python (6.0 item 4).
        result, _ = mine_block_raw(nodes[POOLS[2]], [z_hex])
        assert result is None, result
        self.sync_all(blocks_only=True)
        for name, m in mints.items():
            assert_equal(user.yed_getvault(m['txid'])['status'], 'ACTIVE')
        assert_equal(user.yed_getvault(z_txid)['status'], 'VOID')
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 40000)
        claim_height = user.yed_getvault(mints['U']['txid'])['claimHeight']

        print('the claimant receives 100.50 YED; the vaults stay healthy until claimHeight')
        user.yed_send(claimant.yed_getnewaddress(), 10050)
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 10050)
# Rule: RED-4
        assert_rpc_error('claim-not-yet', claimant.yed_claim, mints['U']['txid'])
        self.mine_round_robin(POOLS, claim_height - user.getblockcount())
        assert_equal(user.yed_listclaimable(), [])
        assert_rpc_error('claim-not-underwater', claimant.yed_claim, *self.claim_args(claimant, mints['U']['txid']))
        assert_rpc_error('vault-not-active', claimant.yed_claim, z_txid)
        assert_rpc_error('vault-not-found', claimant.yed_claim, '11' * 32)

# Rule: RED-4 MP-1 BLK-1 BLK-2
        print('raw claim of the healthy vault U from node 1: every enforcing node refuses it, a block carrying it is rejected')
        r = user.getblockcount()
        vault_u = user.yed_getvault(mints['U']['txid'])
        hex_u = self.raw_claim(claimant, vault_u, 10050, r)
        v = nodes[2].yed_validaterawtransaction(hex_u)
        assert_equal((v['valid'], v['verdict'], v['path'], v['blockValid'], v['wouldBeRejected']), (True, 'vault-claim-not-underwater', 'claim', False, True))
        stock_txid = stock.sendrawtransaction(hex_u)         # the stock node has no rule against it
        assert stock_txid in stock.getrawmempool()
        for i in OVERLAY:
            assert_rpc_error('yellowback-vault-spend', nodes[i].sendrawtransaction, hex_u)
        result, _ = mine_block_raw(nodes[3], [hex_u])
        assert_equal(result, 'yellowback-vault-spend')
        assert_equal(nodes[3].yed_getinfo()['rejectedBlocks'], 1)
        assert_equal(nodes[3].yed_getvault(mints['U']['txid'])['status'], 'ACTIVE')
        assert_banscore_zero(nodes)

# Rule: PRICE-1 PRICE-2 HALT-3 RED-4
        print('mint V3 just before the crash, then every pool quotes $0.01 for 64 blocks')
        mint_v3 = self.mint(user, 10000, 48)
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
        assert mint_v3['txid'] + ':0' not in claimable          # V3 is not past claimHeight yet
        row = claimable[mints['V']['txid'] + ':0']
        assert_equal((row['mintedCents'], row['pClaim'], row['feeZat']), (10000, 10000, fee_zat(row['collateralZat'])))
        assert_equal(user.yed_getvault(mints['V']['txid'])['claimable'], True)
        assert_equal(nodes[2].yed_getstats()['mintingAllowed'], False)

# Rule: RED-4
        print('before claimHeight the claim of V3 fails CLTV: non-final')
        assert_greater_than(v3_claim_height, user.getblockcount())
        vault_v3 = user.yed_getvault(mint_v3['txid'])
        hex_early = self.raw_claim(claimant, vault_v3, 10050, user.getblockcount())
        assert_rpc_error('non-final', stock.sendrawtransaction, hex_early)
        assert_rpc_error('non-final', claimant.sendrawtransaction, hex_early)
        assert_rpc_error('claim-not-yet', claimant.yed_claim, mint_v3['txid'])
        self.mine_round_robin(POOLS, v3_claim_height - user.getblockcount())

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
        print('the claimant claims V3 with yed_claim')
        r = user.getblockcount()
        vault_v3 = user.yed_getvault(mint_v3['txid'])
        payees = user.yed_getfeepayee(r, vault_v3['collateralZat'], outpoint_selector(mint_v3['txid']))
        yec_before = claimant.getbalance()
        supply_before = nodes[2].yed_getstats()['supplyCents']
        claimed = self.claim(claimant, mint_v3['txid'])
        assert_equal(claimed['burnedCents'], 10000)
        assert_equal(claimed['feeZat'], payees['feeZat'])
        assert_equal(claimed['payee'], payees['default']['payoutAddress'])
        # v3: the carrier's CARRIER_VALUE joins the inputs; armed, the attestor fee leaves (clause (a): no residual)
        assert_equal(claimed['collateralOut'], vault_v3['collateralZat'] + CARRIER_VALUE + 2 * TOKEN_VALUE - YELLOWBACK_FEE - claimed['feeZat']
                     - claimed['attestFeeZat'] - claimed['residualZat'] - TOKEN_VALUE)
        assert_equal((claimed['claimPath'], claimed['residualZat'], claimed['pending']), ('a', 0, False))
        raw = claimant.getrawtransaction(claimed['txid'], 1)
        assert_equal(raw['locktime'], v3_claim_height)
        assert_equal(raw['vin'][0]['txid'], mint_v3['txid'])
        assert_equal(len(raw['vin']), 4)                               # the vault, 1 YED, 100.50 YED, the carrier (never vin[0])
        assert_equal(raw['vin'][3]['txid'], claimed['carrierTxid'])
        assert_equal(len(raw['vout']), 4 + (1 if self.armed else 0))   # collateral, fee, 1.50 YED change, [attestor fee], payload
        assert_equal(nodes[2].yed_validaterawtransaction(raw['hex'])['verdict'], 'ok')
        self.sync_all()
        self.mine(POOLS[2])
        for i in OVERLAY:
            c = nodes[i].yed_getvault(mint_v3['txid'])
            assert_equal((c['status'], c['burnedCents'], c['unbacked'], c['feePaidZat']), ('CLAIMED', 10000, False, claimed['feeZat']))
        assert_equal(nodes[2].yed_getstats()['supplyCents'], supply_before - 10000)
        assert_equal(nodes[2].yed_getstats()['claimedVaults'], 1)
        assert_equal(claimant.yed_getbalance()['confirmedCents'], 150)
        assert_greater_than(claimant.getbalance(), yec_before + 9)
        info = nodes[2].yed_gettxinfo(claimed['txid'])
        assert_equal((info['type'], info['path'], info['verdict'], info['burned']), ('redeem', 'claim', 'ok', 10000))
        assert_equal([x['type'] for x in claimant.yed_listtransactions() if x['txid'] == claimed['txid']], ['claim'])
        assert_equal([x['type'] for x in user.yed_listtransactions() if x['txid'] == claimed['txid']], ['claimed'])
        assert_rpc_error('vault-not-active', claimant.yed_claim, mint_v3['txid'])
        assert_rpc_error('vault-not-active', user.yed_redeem, mint_v3['txid'])
        self.checkpoint('claim of V3')

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
        assert_equal((c['status'], c['closingTxid']), ('CLAIMED', late_txid))
        assert_equal(nodes[2].yed_getstats()['claimedVaults'], 2)
        self.checkpoint('claim at R vs H')

# Rule: ACT-6 ACT-5
        print('sweep_refused_when_merely_suspended: the pools stop signalling for one window')
        self.set_pools(['-yellowbacksignal=0'])
        self.mine_round_robin(POOLS, 64 - ENFORCEMENT_FLOOR + 1)
        act = user.yed_getactivation()
        assert_equal((act['enforcementSuspended'], act['mintHalted'], act['status']), (True, True, 'active'))
        assert_equal(nodes[2].yed_getinfo()['enforcing'], True)      # the node-side conjuncts hold; ACT-5 is off through the bit
        for i in OVERLAY:
            assert_equal(nodes[i].yed_getinfo()['abandoned'], False)
        assert_rpc_error('sweep-not-abandoned', user.yed_sweep, mints['U']['txid'], SWEEP_ACK)
        assert 'sweepBefore' not in user.yed_getvault(mints['U']['txid'])

# Rule: MP-1 TPL-1 RED-1 IN-2
        print('sweep_builds_under_abandonment: ENFORCEMENT set for ABANDON_BLOCKS')
        # the bit was first set at the tip 33 blocks ago and IsAbandoned counts that snapshot too:
        # ABANDON_BLOCKS consecutive snapshots end at H0 + ABANDON_BLOCKS - 1
        self.mine_round_robin(POOLS, ABANDON_BLOCKS - 2)
        assert_equal(user.yed_getinfo()['abandoned'], False)
        self.mine_round_robin(POOLS, 1)
        for i in OVERLAY:
            assert_equal(nodes[i].yed_getinfo()['abandoned'], True)
        vault_u = user.yed_getvault(mints['U']['txid'])
        assert_equal(vault_u['sweepBefore'], vault_u['claimHeight'])
        pos = [p for p in user.yed_listpositions('ACTIVE') if p['txid'] == mints['U']['txid']][0]
        assert_equal((pos['canSweep'], pos['sweepBefore']), (True, vault_u['claimHeight']))
        assert_rpc_error('sweep-acknowledgement-missing', user.yed_sweep, mints['U']['txid'], 'ok')
        assert_rpc_error('vault-not-owned', claimant.yed_sweep, mints['U']['txid'], SWEEP_ACK)
        unbacked_before = nodes[2].yed_getstats()['unbackedCents']
        swept = user.yed_sweep(mints['U']['txid'], SWEEP_ACK)
        assert_equal(swept['unbackedCents'], 10000)
        assert_equal(swept['collateralOut'], vault_u['collateralZat'] - YELLOWBACK_FEE)
        assert_equal(user.decoderawtransaction(swept['hex'])['txid'], swept['txid'])
        decoded = user.decoderawtransaction(swept['hex'])
        assert_equal((len(decoded['vin']), len(decoded['vout'])), (1, 1))
# Rule: MP-1 TPL-1
        print('sweep_relayed_by_own_node (L13)')
        assert swept['txid'] in user.getrawmempool()
        sync_mempools([user, stock, nodes[2]])
        assert swept['txid'] in stock.getrawmempool()
        assert swept['txid'] in nodes[2].getrawmempool()
        assert swept['txid'] in [t['hash'] for t in nodes[2].getblocktemplate()['transactions']]
        assert_equal(nodes[2].yed_validaterawtransaction(swept['hex'])['wouldBeRejected'], False)
        assert_equal(nodes[2].yed_validaterawtransaction(swept['hex'])['blockValid'], False)   # it breaks RED-1 by design
        self.mine(STOCK)
        for i in OVERLAY:
            c = nodes[i].yed_getvault(mints['U']['txid'])
            assert_equal((c['status'], c['unbacked'], c['burnedCents'], c['closingTxid']), ('CLOSED', True, 0, swept['txid']))
            assert_equal(nodes[i].yed_getstats()['unbackedCents'], unbacked_before + 10000)
        assert_equal([x['type'] for x in user.yed_listtransactions() if x['txid'] == swept['txid']], ['sweep'])
        assert_equal([x['unbacked'] for x in user.yed_listtransactions() if x['txid'] == swept['txid']], [True])
        self.checkpoint('sweep under abandonment')

# Rule: ACT-6 MINER-1
        print('sunset_alone_is_not_abandonment (L12): signalling resumes, the pools pass their sunset, node 0 keeps the signal count up')
        self.set_pools(None)
        self.mine_round_robin(POOLS, ENFORCEMENT_RESUME + 1)
        assert_equal(user.yed_getactivation()['enforcementSuspended'], False)
        assert_equal(user.yed_getinfo()['abandoned'], False)
        tip = user.getblockcount()
        self.set_pools(['-yellowbackenforceuntil=%d' % (tip - 1)])
        signaller = user.getnewaddress()
        self.restart(0, ['-yellowbackpayoutaddress=%s' % signaller, '-yellowbacksignal=1'])
        user = nodes[0]
        for i in POOLS:
            info = nodes[i].yed_getinfo()
            assert_equal((info['sunset'], info['enforcing'], info['miner']['signal']), (True, False, False))
        assert_equal(user.yed_getinfo()['miner']['signal'], True)
        self.mine_round_robin([0] + POOLS, 64, shares=[34, 10, 10, 10])
        assert_greater_than(user.yed_getactivation()['signalCount'], ENFORCEMENT_FLOOR - 1)
        for i in POOLS:
            info = nodes[i].yed_getinfo()
            assert_equal((info['sunset'], info['enforcing'], info['abandoned']), (True, False, False))
            assert_equal(nodes[i].yed_getactivation()['enforcementSuspended'], False)
        assert_rpc_error('sweep-not-abandoned', user.yed_sweep, mints['T']['txid'], SWEEP_ACK)

# Rule: ACT-6 MINER-1 RED-1 IN-2
        print('sweep_after_sunset_without_successor: only the pools mine; their tags drop the bit; abandonment follows')
        self.mine_round_robin(POOLS, 64 - ENFORCEMENT_FLOOR + 1 + ABANDON_BLOCKS)
        for i in OVERLAY:
            assert_equal(nodes[i].yed_getinfo()['abandoned'], True, i)
        swept_t = user.yed_sweep(mints['T']['txid'], SWEEP_ACK)
        assert_equal(swept_t['unbackedCents'], 10000)
        sync_mempools([user, nodes[2]])
        self.mine(POOLS[0])
        for i in OVERLAY:
            c = nodes[i].yed_getvault(mints['T']['txid'])
            assert_equal((c['status'], c['unbacked'], c['closingTxid']), ('CLOSED', True, swept_t['txid']))
        assert_equal(nodes[2].yed_getstats()['unbackedCents'], unbacked_before + 20000)
        assert_equal(nodes[2].yed_getstats()['activeVaults'], 0)

        print('the Python model over the whole chain (P8)')
        # node 0 never had a sunset: ENFORCE_UNTIL_HEIGHT is one of the four hashed regtest values,
        # so the pools' state hashes differ from node 0's by design after the sunset restart
        self.model_check(nodes[0])
        self.sync_all(blocks_only=True)
        assert_best_hash(self.enforcing_nodes(), 'end')
        assert_same_statehash([nodes[2], nodes[3], nodes[4]], 'end')
        assert_same_statehash([nodes[0], nodes[5]], 'end')


if __name__ == '__main__':
    YellowbackClaimTest().main()
