#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Sapling funding and destinations (plan §4.6, §3.5, the transaction_builder extension):

  - a mint funded from a ys1… address in one transaction (no transparent inputs, vShieldedSpend,
    positive valueBalance) registers like any other (TX-0: the YEC side is never restricted) and
    debits the shielded balance; the token output is locked before confirmation;
  - a mint funded from one s1… address spends only that address's outputs, and is refused when
    that address cannot cover the collateral;
  - a redemption pays its collateral straight to a ys1… address (vShieldedOutput, negative
    valueBalance): the transparent outputs are YED change at vout[0] (when there is change), the
    payload, then the fee output — feeVout names it wherever it lands: vout[2] with change,
    vout[1] without (N39);
  - bad `from` / `to` values are refused before anything is signed.

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer (a second wallet).
"""

from decimal import Decimal

from test_framework.util import assert_equal, assert_greater_than, wait_and_assert_operationid_status
from test_framework.yellowback_util import (
    COIN,
    POOLS,
    REF_LAG,
    TOKEN_VALUE,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
    fee_zat,
)
from test_framework.yellowback_attest import ArmedModeMixin
from test_framework.yellowback_util import CARRIER_VALUE


def assert_rpc_error(substr, fn, *args):
    try:
        fn(*args)
    except Exception as e:
        assert substr in str(e), 'expected %r in %r' % (substr, str(e))
        return
    raise AssertionError('expected an error containing %r' % substr)


def zat(d):
    return int(Decimal(str(d)) * COIN)


class YellowbackSaplingTest(ArmedModeMixin, YellowbackTestFramework):

    def run_test(self):
        nodes = self.nodes
        user, other = nodes[0], nodes[5]

        print('activate at $50: $100 at 500 % is 10 YEC of collateral')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        assert_equal(user.yed_estimatecollateral(10000, 48)['requiredZat'], 10 * COIN)
        self.arm()

        print('shield 30 YEC into a ys1... address of node 0')
        ys = user.z_getnewaddress('sapling')
        assert ys.startswith('yregtestsapling')
        taddr = user.getnewaddress()
        user.sendtoaddress(taddr, Decimal('30.001'))
        user.sendtoaddress(other.getnewaddress(), 5)
        self.sync_all()
        self.mine(POOLS[0])
        opid = user.z_sendmany(taddr, [{'address': ys, 'amount': Decimal('30')}], 1, Decimal('0.0001'))
        wait_and_assert_operationid_status(user, opid)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.z_getbalance(ys), Decimal('30'))

# Rule: MINT-1 MINT-3 TX-0
        print('mint from the ys1... address in one transaction')
        assert_rpc_error('bad-address', user.yed_mint, 10000, 48, 'nonsense')
        assert_rpc_error('bad-address', user.yed_mint, 10000, 48, user.yed_getnewaddress())
        assert_rpc_error('bad-address', other.yed_mint, 10000, 48, ys)          # no spending key there
        z_before = user.z_getbalance(ys)
        mint1 = self.mint(user, 10000, 48, ys)
        vault1 = mint1['txid']
        assert_equal(mint1['fundedFrom'], 'sapling')
        assert_equal(mint1['collateralZat'], 10 * COIN)                    # armed too: the attestors track xMint, pMint = $50
        assert_equal(mint1['feeZat'], fee_zat(mint1['collateralZat']))
        raw = user.getrawtransaction(vault1, 1)
        assert_equal([v['txid'] for v in raw['vin']], [mint1['carrierTxid']])    # v3: the carrier is the one transparent input
        assert_greater_than(len(raw['vShieldedSpend']), 0)
        assert_equal(len(raw['vShieldedOutput']), 1)                        # change back to ys
        assert_equal(zat(raw['valueBalance']), mint1['collateralZat'] + TOKEN_VALUE + mint1['feeZat'] + mint1['attestFeeZat'] + YELLOWBACK_FEE - CARRIER_VALUE)
        assert_equal(len(raw['vout']), 4 + (1 if self.armed else 0))      # vault, token, payload, fee, [attestor fee]
        carrier = user.getrawtransaction(mint1['carrierTxid'], 1)
        assert_equal(carrier['vin'], [])                                   # the carrier step was funded from ys too
        assert_greater_than(len(carrier['vShieldedSpend']), 0)
        assert_equal(raw['vout'][3]['scriptPubKey']['addresses'], [mint1['payee']])
        assert {'txid': vault1, 'vout': 1} in [{'txid': l['txid'], 'vout': l['vout']} for l in user.listlockunspent()]
        assert_equal(user.yed_getbalance()['unconfirmedCents'], 10000)
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(nodes[2].yed_gettxinfo(vault1)['verdict'], 'ok')
        assert_equal(user.yed_getvault(vault1)['status'], 'ACTIVE')
        assert_equal(user.yed_getbalance()['confirmedCents'], 10000)
        # the carrier step (CARRIER_VALUE + fee) and the mint (outputs + fee - CARRIER_VALUE) both came out of ys
        assert_equal(user.z_getbalance(ys), z_before - Decimal(mint1['collateralZat'] + TOKEN_VALUE + mint1['feeZat'] + mint1['attestFeeZat'] + 2 * YELLOWBACK_FEE) / COIN)

# Rule: MINT-1
        print('mint from one s1... address only')
        t2 = user.getnewaddress()
        t_empty = user.getnewaddress()
        fund = user.sendtoaddress(t2, Decimal('11'))
        self.sync_all()
        self.mine(POOLS[0])
        assert_rpc_error('insufficient-yec', user.yed_mint, *self.mint_args(user, 10000, 48, t_empty))
        mint2 = self.mint(user, 10000, 48, t2)
        vault2 = mint2['txid']
        assert_equal(mint2['fundedFrom'], 'transparent')
        raw2 = user.getrawtransaction(vault2, 1)
        assert_equal(len(raw2['vin']), 2)                                  # t2's coin (the carrier's change back to t2) and the carrier
        assert_equal(raw2['vin'][1]['txid'], mint2['carrierTxid'])
        funding = raw2['vin'][0]
        assert_equal(funding['txid'], mint2['carrierTxid'])
        assert_equal(user.getrawtransaction(funding['txid'], 1)['vout'][funding['vout']]['scriptPubKey']['addresses'], [t2])
        carrier2 = user.getrawtransaction(mint2['carrierTxid'], 1)
        assert_equal(carrier2['vin'][0]['txid'], fund)                     # the carrier step spent t2's coin
        assert_equal(raw2['vShieldedSpend'], [])
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(vault2)['status'], 'ACTIVE')
        assert_equal(user.yed_getbalance()['confirmedCents'], 20000)

        print('arrange the YED coins so vault 1 redeems with change and vault 2 without')
        user.yed_send(other.yed_getnewaddress(), 9900)      # picks one 100 YED coin: 1 YED change
        self.sync_all()
        self.mine(POOLS[2])
        other.yed_send(user.yed_getnewaddress(), 9800)      # 1 YED stays with node 5
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(sorted(c['cents'] for c in user.yed_listunspent()), [100, 9800, 10000])
        # H1 (Phase 8) selects an exact match before anything else, so a wallet holding a 10000-cent
        # coin redeems a 10000-cent debt with no change at all — which would leave this script with
        # two identical no-change shapes instead of the two the N39 note asks for. Consolidate into
        # a single 19900 coin: no subset equals the debt, so the selector takes the one coin and
        # must leave change, and the without-change shape below still arises from an exact match.
        user.yed_send(user.yed_getnewaddress(), 19900)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal([c['cents'] for c in user.yed_listunspent()], [19900])

        print('wait for both vaults to unlock')
        lock = max(mint1['lockHeight'], mint2['lockHeight'])
        self.mine_round_robin(POOLS, lock - user.getblockcount())
        assert_equal([p['canRedeem'] for p in user.yed_listpositions()], [True, True])

        print('bad destinations are refused before signing')
        assert_rpc_error('bad-address', user.yed_redeem, vault1, 'nonsense')
        assert_rpc_error('bad-address', user.yed_redeem, vault1, user.yed_getnewaddress())

# Rule: RED-1 RED-2 RED-3 XFER-1 TX-0
        print('redeem vault 1 straight to the ys1... address, with YED change: fee output at vout[2]')
        z_before = user.z_getbalance(ys)
        red1 = user.yed_redeem(vault1, ys)
        assert_equal(red1['to'], ys)
        assert_equal(red1['burnedCents'], 10000)
        rraw = user.getrawtransaction(red1['txid'], 1)
        assert_equal(len(rraw['vShieldedOutput']), 1)
        assert_equal(rraw['vShieldedSpend'], [])
        assert_equal(rraw['vin'][0]['txid'], vault1)
        assert_equal(len(rraw['vin']), 2)                                  # the vault and the one 199 YED coin (H1: fewest inputs)
        assert_equal(len(rraw['vout']), 3)                                 # YED change, payload, fee
        assert_equal(rraw['vout'][0]['valueZat'], TOKEN_VALUE)
        assert_equal(rraw['vout'][2]['scriptPubKey']['addresses'], [red1['payee']])
        assert_equal(rraw['vout'][2]['valueZat'], red1['feeZat'])
        payload = user.yed_decodepayload(rraw['vout'][1]['scriptPubKey']['hex'][4:])
        assert_equal((payload['type'], payload['feeVout']), ('redeem', 2))
        assert_equal(payload['assignments'], [{'vout': 0, 'cents': 9900}])
        collateral_out = mint1['collateralZat'] + 1 * TOKEN_VALUE - YELLOWBACK_FEE - red1['feeZat'] - TOKEN_VALUE
        assert_equal(red1['collateralOut'], collateral_out)
        assert_equal(zat(rraw['valueBalance']), -collateral_out)
        assert_equal(rraw['locktime'], mint1['lockHeight'])
        assert_equal(nodes[2].yed_validaterawtransaction(rraw['hex'])['verdict'], 'ok')
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(user.yed_getvault(vault1)['status'], 'CLOSED')
        assert_equal(user.z_getbalance(ys), z_before + Decimal(collateral_out) / COIN)
        assert_equal(nodes[2].yed_gettxinfo(red1['txid'])['verdict'], 'ok')
        assert_equal(nodes[2].yed_gettxinfo(red1['txid'])['feeZat'], red1['feeZat'])
        assert_equal(user.yed_getbalance()['confirmedCents'], 9900)

        print('redeem vault 2 to the ys1... address without change: fee output at vout[1]')
        other.yed_send(user.yed_getnewaddress(), 100)
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(sorted(c['cents'] for c in user.yed_listunspent()), [100, 9900])
        z_before = user.z_getbalance(ys)
        red2 = user.yed_redeem(vault2, ys)
        rraw2 = user.getrawtransaction(red2['txid'], 1)
        assert_equal(len(rraw2['vin']), 3)
        assert_equal(len(rraw2['vout']), 2)                                # payload, fee
        assert_equal(rraw2['vout'][1]['scriptPubKey']['addresses'], [red2['payee']])
        payload2 = user.yed_decodepayload(rraw2['vout'][0]['scriptPubKey']['hex'][4:])
        assert_equal((payload2['type'], payload2['feeVout'], payload2['assignments']), ('redeem', 1, []))
        collateral_out2 = mint2['collateralZat'] + 2 * TOKEN_VALUE - YELLOWBACK_FEE - red2['feeZat']
        assert_equal(red2['collateralOut'], collateral_out2)
        assert_equal(zat(rraw2['valueBalance']), -collateral_out2)
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(user.yed_getvault(vault2)['status'], 'CLOSED')
        assert_equal(user.z_getbalance(ys), z_before + Decimal(collateral_out2) / COIN)
        assert_equal(user.yed_getbalance()['confirmedCents'], 0)
        assert_equal(nodes[2].yed_getstats()['supplyCents'], 0)
        self.model_check(nodes[2])
        self.checkpoint('sapling shapes')


if __name__ == '__main__':
    YellowbackSaplingTest().main()
