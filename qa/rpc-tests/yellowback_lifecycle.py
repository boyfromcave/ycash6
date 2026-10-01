#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The transparent wallet lifecycle on the six-node regtest (plan Phase 6): mint (class A, the
0-conf lock, the reference snapshot vs a later price drop, a 2-block reorg), send (the change
floor, a plain-YEC burn, an under-assigned raw transfer), the one-step owner redemption (the
enforcement fee at an eligible payee, raw redemptions paying outside E(R) or short rejected by
enforcing nodes, a non-default eligible key accepted, FEE-0), the expired-transaction display
(N39), the sweep refusals while enforcement is on (L10), and the Python model over the whole
chain at the end (P8).

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer (a second wallet).
"""

from decimal import Decimal

from test_framework.util import (
    assert_equal,
    assert_greater_than,
    bytes_to_hex_str,
    hex_str_to_bytes,
    sync_mempools,
)
from test_framework.yellowback_util import (
    COIN,
    FEE_MIN,
    PAYEE_WINDOW,
    POOLS,
    REF_LAG,
    REF_WINDOW,
    STOCK,
    TOKEN_VALUE,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
    assert_banscore_zero,
    build_vault_spend_raw,
    fee_zat,
    mine_block_raw,
    pubkey_to_address,
    set_quote,
)
from test_framework import yellowback_model as ym
from test_framework.yellowback_attest import ArmedModeMixin

SWEEP_ACK = 'I understand this leaves YED unbacked'


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


def outpoint_selector(txid, n=0):
    """The FEE-W selector of a vault spend: the serialised COutPoint (section 3.7)."""
    return bytes_to_hex_str(bytes.fromhex(txid)[::-1] + n.to_bytes(4, 'little'))


def coin_of(node, cents):
    for c in node.yed_listunspent():
        if c['cents'] == cents and not c['spentUnconfirmed']:
            return c
    raise AssertionError('no %d-cent coin on the node' % cents)


class YellowbackLifecycleTest(ArmedModeMixin, YellowbackTestFramework):

    def owner_wif(self, node, vault):
        return node.dumpprivkey(pubkey_to_address(hex_str_to_bytes(vault['ownerPubKey'])))

    def raw_redeem(self, node, vault, burn_cents, payee, fee, ref_height, assignments=(), change_script=None):
        coin = coin_of(node, burn_cents)
        extra = [(TOKEN_VALUE, change_script)] if change_script else []
        payload = ym.encode_redeem(ref_height, 1, list(assignments))
        return build_vault_spend_raw(node, vault, 'owner', [(coin['txid'], coin['vout'])], payload=payload,
                                     fee=(payee, fee), ref_height=ref_height, extra_outputs=extra,
                                     owner_wif=self.owner_wif(node, vault))

    def run_test(self):
        nodes = self.nodes
        user, stock, observer = nodes[0], nodes[STOCK], nodes[5]
        pool = nodes[POOLS[0]]

        print('activate at $50 and fill the price windows')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        for node in self.enforcing_nodes():
            assert_equal(node.yed_getstats()['mintingAllowed'], True)
        user.sendtoaddress(observer.getnewaddress(), 30)
        self.sync_all()
        self.mine(POOLS[0])
        self.arm()

# Rule: MINT-1 MINT-2 MINT-3 MINT-5 MINT-8 MINTPOL-1 FEE-1 FEE-W
        print('mint_class_a: 107 YED locked 48 blocks; collateral fixed at the reference snapshot')
        ref = user.yed_getinfo()['height'] - REF_LAG
        est = self.estimate(user, 10700, 48)
        assert_equal(est['termClass'], 'A')
        assert_equal(est['refHeight'], ref)
        # armed, the attestors track xMint (ArmedModeMixin.price_at), so pMint = min(xMint, aMint) = xMint: the estimate stands
        mint_a = self.mint(user, 10700, 48)          # v3: two transactions (the carrier step, W7)
        assert_equal(mint_a['termClass'], 'A')
        assert_equal(mint_a['vault'], mint_a['txid'] + ':0')
        assert_equal(mint_a['collateralZat'], max(est['requiredZat'], 4 * FEE_MIN))
        assert_equal(mint_a['claimHeight'], mint_a['lockHeight'] + 24)
        assert_equal(mint_a['feeZat'], fee_zat(mint_a['collateralZat']))
        assert_equal(mint_a['fundedFrom'], 'transparent')
        # the wallet's default choice is the FEE-W choice for the owner key as selector
        raw = user.getrawtransaction(mint_a['txid'], 1)
        owner_hex = user.yed_decodepayload(raw['vout'][2]['scriptPubKey']['hex'][4:])['ownerPubKey']
        payee = user.yed_getfeepayee(ref, mint_a['collateralZat'], owner_hex)
        assert mint_a['payee'] in payee['eligible']
        assert_equal(mint_a['payee'], payee['default']['payoutAddress'])
        assert_equal(mint_a['feeZat'], payee['feeZat'])
        assert_equal(raw['vout'][3]['scriptPubKey']['addresses'], [mint_a['payee']])
        assert_equal(raw['expiryheight'], ref + REF_WINDOW)
# Rule: MINT-4
        print('zero_conf_lock: the token output is locked before confirmation')
        assert {'txid': mint_a['txid'], 'vout': 1} in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]
        assert_equal(user.yed_getbalance()['unconfirmedCents'], 10700)
        print('ref_snapshot_vs_later_price_drop: pools quote $40 after the mint was built')
        for i in POOLS:
            set_quote(nodes[i], 40)
        self.sync_all()
        self.mine(POOLS[0])
        vault_a = user.yed_getvault(mint_a['txid'])
        assert_equal(vault_a['status'], 'ACTIVE')
        assert_equal(vault_a['refHeight'], ref)
        assert_equal(vault_a['collateralZat'], mint_a['collateralZat'])
        assert_equal(vault_a['feePaidZat'], mint_a['feeZat'])
        assert_equal(user.yed_getbalance()['confirmedCents'], 10700)
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 10700)
        self.checkpoint('mint A')

# Rule: MINT-2 UNDO
        print('two_block_reorg_tolerance: the mint confirms again two blocks later after a reorg')
        self.split_network()
        mint_b = self.mint(user, 10000, 48)           # the carrier's block is the enforcing half's first
        sync_mempools([nodes[0], nodes[2], nodes[3], nodes[4]])
        first = pool.generate(1)[0]
        self.sync_all(blocks_only=True)
        assert_equal(user.yed_getvault(mint_b['txid'])['status'], 'ACTIVE')
        stock.generate(3)                             # carrier + mint block on the enforcing half: three to reorg both
        self.join_network()
        assert_equal(user.getbestblockhash(), stock.getbestblockhash())
        assert user.getblock(first)['confirmations'] < 0
        assert mint_b['txid'] in user.getrawmempool()
        sync_mempools([nodes[i] for i in (0, 2, 3, 4)])   # resurrected on the enforcing half only
        self.mine(POOLS[1])
        vault_b = user.yed_getvault(mint_b['txid'])
        assert_equal(vault_b['status'], 'ACTIVE')
        assert_equal(vault_b['mintHeight'], user.getblockcount())
        self.checkpoint('mint B after reorg')

        print('mint C (user) and mint D (observer)')
        mint_c = self.mint(user, 10000, 48)
        mint_d = self.mint(observer, 10000, 48)
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(user.yed_getvault(mint_c['txid'])['status'], 'ACTIVE')
        assert_equal(nodes[2].yed_getvault(mint_d['txid'])['status'], 'ACTIVE')
        assert_equal(observer.yed_getbalance()['confirmedCents'], 10000)
        assert_equal(len(observer.yed_listpositions()), 1)
        assert_equal(user.yed_getbalance()['confirmedCents'], 30700)

# Rule: XFER-1 XFER-2 XFER-3
        print('send: 1 YED to the observer, 3 YED back')
        sent = user.yed_send(observer.yed_getnewaddress(), 100)
        assert_equal(sent['changeCents'], 9900)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(observer.yed_getbalance()['confirmedCents'], 10100)
        back = observer.yed_send(user.yed_getnewaddress(), 300)
        # H1 (Phase 8): the floor-aware selector prefers one input with valid change to
        # smallest-first accumulation, so the 100-cent coin stays put and the 10000 is spent.
        assert_equal(back['changeCents'], 9700)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getbalance()['confirmedCents'], 30900)
        assert_equal(sorted(c['cents'] for c in user.yed_listunspent()), [300, 9900, 10000, 10700])

# Rule: XFER-1
        print('change_floor: 50 cents under the whole balance is unworkable at any selection (H2)')
        assert_rpc_error('change-floor', user.yed_send, observer.yed_getnewaddress(),
                         user.yed_getbalance()['confirmedCents'] - 50)
        assert_rpc_error('not-a-yellowback-address', user.yed_send, observer.getnewaddress(), 100)
        assert_rpc_error('insufficient-yed', observer.yed_send, user.yed_getnewaddress(), 20000)
        assert_equal(observer.yed_validateaddress(observer.getnewaddress())['reason'], 'not-a-yellowback-address')

# Rule: IN-1 IN-3
        print('plain_yec_burn_recorded: the observer spends its 98 YED output as plain YEC')
        coin = coin_of(observer, 9700)
        raw = observer.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}],
                                            {observer.getnewaddress(): Decimal(TOKEN_VALUE - YELLOWBACK_FEE) / COIN})
        signed_burn = observer.signrawtransaction(raw)['hex']
# Rule: H7
        # Phase 8 H7: sendrawtransaction refuses to destroy this wallet's own YED unless the
        # third argument says so, and yed_unlockcoin is what hands the outpoint back deliberately.
        assert_rpc_error('yed-burn-refused', observer.sendrawtransaction, signed_burn)
        assert_equal(observer.yed_unlockcoin(coin['txid'], coin['vout'], 'I understand this burns YED')['wasYellowbackLocked'], True)
        burn_txid = observer.sendrawtransaction(signed_burn, False, True)
        self.sync_all()
        self.mine(POOLS[2])
        info = nodes[2].yed_gettxinfo(burn_txid)
        assert_equal((info['yedIn'], info['yedOut'], info['burned']), (9700, 0, 9700))
        assert_equal(info['verdict'], 'burned')
        assert_equal(observer.yed_getbalance()['confirmedCents'], 100)   # the 1 YED coin the H1 selector left untouched
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 31000)
        assert_equal([x['type'] for x in observer.yed_listtransactions() if x['txid'] == burn_txid], ['burn'])

# Rule: XFER-2
        print('under_assigned_raw_transfer: 99 YED in, 98 YED assigned, 1 YED burned')
        coin = coin_of(user, 9900)
        dest = user.yed_getnewaddress()
        yec = [u for u in user.listunspent(1) if int(Decimal(str(u['amount'])) * COIN) > 10 * TOKEN_VALUE][0]
        yec_zat = int(Decimal(str(yec['amount'])) * COIN)
        payload = ym.encode_transfer([(0, 9800)])
        vin = [(coin['txid'], coin['vout'], b'', 0xFFFFFFFF), (yec['txid'], yec['vout'], b'', 0xFFFFFFFF)]
        vout = [(TOKEN_VALUE, ym.p2pkh_script(ym.address_key_hash(dest))),
                (0, bytes([ym.OP_RETURN]) + ym.push(payload)),
                (yec_zat - YELLOWBACK_FEE, ym.p2pkh_script(ym.address_key_hash(user.getnewaddress())))]
        raw = ym.serialize_tx_v4(vin, vout, 0, user.getblockcount() + REF_WINDOW)
        under_hex = user.signrawtransaction(bytes_to_hex_str(raw))['hex']
        under_txid = user.decoderawtransaction(under_hex)['txid']
        # TPL-2 (strict, the daemon default) skips a TRANSFER whose verdict would burn, so no
        # node's template will carry this one: the block is assembled in Python (6.0 item 4).
        result, _ = mine_block_raw(nodes[POOLS[0]], [under_hex])
        assert result is None, result
        self.sync_all(blocks_only=True)
        info = nodes[2].yed_gettxinfo(under_txid)
        assert_equal((info['yedIn'], info['yedOut'], info['burned']), (9900, 9800, 100))
        assert_equal(user.yed_getbalance()['confirmedCents'], 30800)
        assert_equal(sorted(c['cents'] for c in user.yed_listunspent()), [300, 9800, 10000, 10700])
        rows = {r['txid']: r for r in user.yed_listtransactions()}
        assert_equal(rows[under_txid]['burned'], 100)
        assert_equal(rows[mint_a['txid']]['type'], 'mint')
        assert_equal(rows[sent['txid']]['type'], 'send')
        assert_equal(rows[back['txid']]['type'], 'receive')
        self.checkpoint('transfers')

# Rule: RED-1
        print('redeem_before_lock_refused')
        assert_rpc_error('vault-locked', user.yed_redeem, mint_b['txid'])
        assert_rpc_error('vault-not-owned', observer.yed_redeem, mint_b['txid'])
        assert_rpc_error('vault-not-found', user.yed_redeem, '00' * 32)
        positions = {p['txid']: p for p in user.yed_listpositions()}
        assert_equal(len(positions), 3)
        assert_equal(positions[mint_b['txid']]['canRedeem'], False)
        assert 'sweepBefore' not in positions[mint_b['txid']]

        print('wait for the locks')
        target = max(mint_a['lockHeight'], mint_b['lockHeight'], mint_c['lockHeight'])
        self.mine_round_robin(POOLS, target - user.getblockcount())
        assert_equal(user.yed_listpositions()[0]['canRedeem'], True)
        r = user.getblockcount()          # the spend's refHeight: the index tip
        vault_a = user.yed_getvault(mint_a['txid'])
        fee = fee_zat(vault_a['collateralZat'])
        payees = user.yed_getfeepayee(r, vault_a['collateralZat'], outpoint_selector(mint_a['txid']))
        assert_greater_than(len(payees['eligible']), 1)
        default = payees['default']['payoutAddress']
        other = [a for a in payees['eligible'] if a != default][0]

# Rule: RED-3 BLK-1 BLK-2
        print('raw_redemption_outside_payee_set_rejected: the fee to a key outside E(R)')
        hex_out = self.raw_redeem(user, vault_a, 10700, stock.getnewaddress(), fee, r)
        assert_equal(nodes[2].yed_validaterawtransaction(hex_out)['verdict'], 'vault-spend-bad-payee')
        assert_equal(nodes[2].yed_validaterawtransaction(hex_out)['wouldBeRejected'], True)
        result, bad = mine_block_raw(nodes[2], [hex_out])
        assert_equal(result, 'yellowback-vault-spend')
        assert_equal(nodes[2].yed_getvault(mint_a['txid'])['status'], 'ACTIVE')
# Rule: RED-3
        print('raw_redemption_short_fee_rejected')
        hex_short = self.raw_redeem(user, vault_a, 10700, default, fee - 1, r)
        assert_equal(nodes[3].yed_validaterawtransaction(hex_short)['verdict'], 'vault-spend-bad-fee')
        result, _ = mine_block_raw(nodes[3], [hex_short])
        assert_equal(result, 'yellowback-vault-spend')
        assert_rpc_error('yellowback-vault-spend', nodes[3].sendrawtransaction, hex_short)
# Rule: RED-1 RED-2 RED-3 MP-1
        print('raw_redemption_non_default_eligible_payee_accepted')
        hex_ok = self.raw_redeem(user, vault_a, 10700, other, fee, r)
        v = nodes[2].yed_validaterawtransaction(hex_ok)
        assert_equal((v['valid'], v['verdict'], v['blockValid'], v['wouldBeRejected']), (True, 'ok', True, False))
        result, good = mine_block_raw(nodes[4], [hex_ok])
        assert_equal(result, None)
        self.sync_all(blocks_only=True)
        closed_a = nodes[2].yed_getvault(mint_a['txid'])
        assert_equal(closed_a['status'], 'CLOSED')
        assert_equal(closed_a['burnedCents'], 10700)
        assert_equal(closed_a['unbacked'], False)
        assert_equal(closed_a['feePaidZat'], fee)
        assert_equal(nodes[2].yed_getinfo()['rejectedBlocks'], 1)
        assert_equal(nodes[3].yed_getinfo()['rejectedBlocks'], 1)
        assert_banscore_zero(nodes)
        assert_equal(user.yed_getbalance()['confirmedCents'], 20100)
        self.checkpoint('raw redemption of A')

# Rule: RED-1 RED-2 RED-3 FEE-1 FEE-W MP-1
        print('one_step_redeem: yed_redeem burns the debt, pays the fee to the default payee')
        r = user.getblockcount()
        vault_b = user.yed_getvault(mint_b['txid'])
        payees = user.yed_getfeepayee(r, vault_b['collateralZat'], outpoint_selector(mint_b['txid']))
        yec_before = user.getbalance()
        redeemed = user.yed_redeem(mint_b['txid'])
        assert_equal(redeemed['burnedCents'], 10000)
        assert_equal(redeemed['feeZat'], payees['feeZat'])
        assert_equal(redeemed['payee'], payees['default']['payoutAddress'])
        assert redeemed['payee'] in payees['eligible']
        assert_greater_than(redeemed['collateralOut'], vault_b['collateralZat'] - COIN)
        raw = user.getrawtransaction(redeemed['txid'], 1)
        assert_equal(raw['vin'][0]['txid'], mint_b['txid'])
        assert_equal(raw['vout'][0]['scriptPubKey']['addresses'], [redeemed['to']])
        assert_equal(raw['vout'][0]['valueZat'], redeemed['collateralOut'])
        assert_equal(raw['vout'][1]['scriptPubKey']['addresses'], [redeemed['payee']])
        assert_equal(raw['vout'][1]['valueZat'], redeemed['feeZat'])
        assert_equal(raw['expiryheight'], r + REF_WINDOW)
        self.sync_all()
        self.mine(POOLS[0])
        closed_b = user.yed_getvault(mint_b['txid'])
        assert_equal((closed_b['status'], closed_b['burnedCents'], closed_b['feePaidZat']), ('CLOSED', 10000, redeemed['feeZat']))
        assert_equal(user.yed_getbalance()['confirmedCents'], 10100)
        assert_greater_than(user.getbalance(), yec_before + 9)
        rows = {r_['txid']: r_ for r_ in user.yed_listtransactions()}
        assert_equal(rows[redeemed['txid']]['type'], 'redeem')
        assert_equal(rows[redeemed['txid']]['payee'], redeemed['payee'])
        assert_rpc_error('vault-not-active', user.yed_redeem, mint_b['txid'])
        self.checkpoint('redeem B')

# Rule: RED-1 MP-1
        print('sweep_refused_while_enforcing')
        assert_equal(user.yed_getinfo()['abandoned'], False)
        assert_rpc_error('sweep-not-abandoned', user.yed_sweep, mint_c['txid'], SWEEP_ACK)
        assert_rpc_error('sweep-acknowledgement-missing', user.yed_sweep, mint_c['txid'], 'yes')
        assert_equal(user.yed_getvault(mint_c['txid'])['status'], 'ACTIVE')
        assert_equal([p['canSweep'] for p in user.yed_listpositions('ACTIVE')], [False])

# Rule: MINT-2
        print('expired_transaction_display: an observer mint left unmined past nExpiryHeight')
        self.split_network()
        expired = self.mint(observer, 10000, 48, miner=STOCK)   # the observer sits on the stock half of the split
        assert expired['txid'] in observer.getrawmempool()
        self.mine_round_robin(POOLS, REF_WINDOW + 1)
        self.join_network()
        self.mine(POOLS[1])
        assert expired['txid'] not in observer.getrawmempool()
        assert_equal(observer.getbestblockhash(), user.getbestblockhash())
        info = observer.yed_gettxinfo(expired['txid'])
        assert_equal(info['expired'], True)
        assert_equal((info['height'], info['verdict'], info['type']), (-1, 'expired', 'mint'))
        row = [x for x in observer.yed_listtransactions() if x['txid'] == expired['txid']][0]
        assert_equal((row['expired'], row['verdict'], row['height'], row['confirmations']), (True, 'expired', -1, 0))
        assert_rpc_error('tx-not-found', nodes[2].yed_gettxinfo, expired['txid'])
        assert_equal(nodes[2].yed_getstats()['activeVaults'], 2)   # C and D; the expired mint left no trace

# Rule: FEE-0 RED-3
        print('fee_0: no pool tagged in the payee window, so the redemption carries no fee output')
        stock.generate(PAYEE_WINDOW + 1)
        self.sync_all(blocks_only=True)
        r = user.getblockcount()
        assert_rpc_error('fee-no-eligible-payee', user.yed_getfeepayee, r, 10 * COIN)
        redeemed_c = user.yed_redeem(mint_c['txid'])
        assert_equal(redeemed_c['feeZat'], 0)
        assert_equal(redeemed_c['payee'], None)
        raw = user.getrawtransaction(redeemed_c['txid'], 1)
        assert_equal(len(raw['vout']), 3)   # collateral, YED change (1 YED), payload
        assert_equal(nodes[2].yed_validaterawtransaction(raw['hex'])['verdict'], 'ok')
        self.sync_all()
        self.mine(POOLS[0])
        closed_c = nodes[2].yed_getvault(mint_c['txid'])
        assert_equal((closed_c['status'], closed_c['burnedCents'], closed_c['feePaidZat']), ('CLOSED', 10000, 0))
        assert_equal(user.yed_getbalance()['confirmedCents'], 100)
        assert_equal(nodes[2].yed_getstats()['activeVaults'], 1)   # D only
        self.checkpoint('FEE-0 redeem of C')

        print('the Python model over the whole chain (P8)')
        self.model_check(nodes[2])
        self.model_check(observer)
        self.checkpoint('end')


if __name__ == '__main__':
    YellowbackLifecycleTest().main()
