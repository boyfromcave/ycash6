#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
P-2 (docs/plans/yellowback-ycash6-plan.md §0, Phase 6 "ZIP-317 and mempool-limit interaction
tests"): the wallet's network fee is max(-yellowbackfee, the transaction's ZIP-317 conventional
fee), so no Yellowback transaction has an unpaid action.

Ycash 6.20.0 ships ZIP-317's limits switched off (zip317.h: both default to SIZE_MAX); a node
opts in with -txunpaidactionlimit / -blockunpaidactionlimit. Here they are 0, the strictest, from
the first wallet transaction on (the harness's raw transactions -- the --armed registrations --
pay a flat 1000 zat, so they are mined before node 0 and the pools restart with the limits):

  - node 0 (the user) runs -txunpaidactionlimit=0 -feepolicy=zip317: its own mempool refuses any
    transaction with one unpaid action, so every yed_* transaction it commits proves it paid;
  - the pools run -blockunpaidactionlimit=0: their templates leave out any transaction with an
    unpaid action. A control transaction paying a flat 1000 zat for ten outputs sits in a pool's
    mempool and is never mined, while the carrier, the mint, a transfer and the redemption (all
    with more than two logical actions, so above the old flat 1000 zat) are mined at once;
  - each fee is exactly wallet_network_fee(): the conventional fee with signatures counted at
    their largest, never below the conventional fee of the signed transaction.

getmempoolentry / getrawmempool expose no unpaid-action count in 6.20.0 (only the miner and
AcceptToMemoryPool read CTxMemPoolEntry::GetUnpaidActionCount), so the limits are the observable.

Nodes: 0 user, 1 stock, 2-4 pools, 5 observer.
"""

import time
from decimal import Decimal

from test_framework.util import assert_equal, assert_greater_than
from test_framework.yellowback_util import (
    COIN,
    POOLS,
    REF_LAG,
    TOKEN_VALUE,
    YELLOWBACK_FEE,
    YellowbackTestFramework,
    conventional_fee,
    wallet_network_fee,
)
from test_framework.yellowback_attest import ArmedModeMixin

USER = 0


class YellowbackFeeTest(ArmedModeMixin, YellowbackTestFramework):

    limits = False      # set once the harness's own raw transactions (1000 zat, --armed registrations) are mined

    def node_args(self, i, extra=None):
        args = super().node_args(i, extra)
        if not self.limits:
            return args
        if i in POOLS:
            args += ['-blockunpaidactionlimit=0']
        if i == USER:
            args += ['-txunpaidactionlimit=0', '-feepolicy=zip317']
        return args

    def assert_mined(self, txid, label):
        for node in self.nodes:
            assert txid not in node.getrawmempool(), '%s %s still in a mempool' % (label, txid)
        assert_greater_than(self.nodes[USER].getrawtransaction(txid, 1)['confirmations'], 0)

    def assert_paid(self, raw, label, in_mempool=True, above_floor=True):
        """The fee is wallet_network_fee(raw); while the transaction is in node 0's mempool, the fee
        the mempool computed from the spent coins is that amount exactly."""
        fee = wallet_network_fee(raw)
        if in_mempool:
            assert_equal(int(Decimal(str(self.nodes[USER].getrawmempool(True)[raw['txid']]['fee'])) * COIN), fee)
        print('  %-10s %2d in %2d out %d/%d Sapling: fee %d zat (conventional %d)' % (
            label, len(raw['vin']), len(raw['vout']), len(raw.get('vShieldedSpend', [])),
            len(raw.get('vShieldedOutput', [])), fee, conventional_fee(raw)))
        if above_floor:
            assert_greater_than(fee, YELLOWBACK_FEE)    # more than two logical actions: the old flat fee left actions unpaid
        return fee

    def run_test(self):
        nodes = self.nodes
        user, observer = nodes[USER], nodes[5]
        pool = nodes[POOLS[0]]

        print('activate at $50 and fill the price windows')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.arm()
        self.mine(POOLS[0])

        print('restart node 0 and the pools with the ZIP-317 limits at 0')
        self.limits = True
        for i in [USER] + POOLS:
            self.restart(i)
        self.sync_all()
        user, pool = self.nodes[USER], self.nodes[POOLS[0]]

        print('mint: the carrier and the mint pay the conventional fee; node 0 accepts both, the pools mine both')
        mint = self.mint(user, 10000, 48)                    # the carrier's block is mined by POOLS[0] inside
        carrier = user.getrawtransaction(mint['carrierTxid'], 1)
        assert_greater_than(carrier['confirmations'], 0)
        self.assert_paid(carrier, 'carrier', in_mempool=False, above_floor=False)   # one input, two outputs: the floor (the bundle rides in the mint's input)
        self.assert_paid(user.getrawtransaction(mint['txid'], 1), 'mint')
        self.mine(POOLS[1])
        self.assert_mined(mint['txid'], 'mint')
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')

        print('transfer: yed_send of 25 YED to another address of node 0 (the redemption needs the whole debt back)')
        sent = user.yed_send(user.yed_getnewaddress(), 2500)
        self.sync_all()
        self.assert_paid(user.getrawtransaction(sent['txid'], 1), 'transfer')
        self.mine(POOLS[2])
        self.assert_mined(sent['txid'], 'transfer')

        print('redeem: after the lock, the fee comes out of the collateral')
        self.mine_round_robin(POOLS, 48)
        vault = user.yed_getvault(mint['txid'])
        red = user.yed_redeem(mint['txid'])
        rawr = user.getrawtransaction(red['txid'], 1)
        fee_r = self.assert_paid(rawr, 'redeem')
        yed_in = TOKEN_VALUE * (len(rawr['vin']) - 1)
        change = TOKEN_VALUE if any(o['valueZat'] == TOKEN_VALUE for o in rawr['vout'][1:]) else 0
        assert_equal(red['collateralOut'], vault['collateralZat'] + yed_in - fee_r - red['feeZat'] - change)
        self.sync_all()
        self.mine(POOLS[1])
        self.assert_mined(red['txid'], 'redeem')
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'CLOSED')

        print('control: ten outputs at a flat 1000 zat have unpaid actions; a pool never mines it (node 0 refuses it outright)')
        utxo = [u for u in pool.listunspent(1) if Decimal(str(u['amount'])) > 1][0]
        amount = Decimal(str(utxo['amount']))
        outs = {observer.getnewaddress(): Decimal('0.1') for _ in range(9)}
        outs[pool.getnewaddress()] = amount - Decimal('0.9') - Decimal(YELLOWBACK_FEE) / COIN
        raw = pool.createrawtransaction([{'txid': utxo['txid'], 'vout': utxo['vout']}], outs)
        control = pool.sendrawtransaction(pool.signrawtransaction(raw)['hex'])
        assert_greater_than(conventional_fee(pool.getrawtransaction(control, 1)), YELLOWBACK_FEE)
        for _ in range(60):                                  # relayed to the other pools (not to node 0)
            if all(control in nodes[i].getrawmempool() for i in POOLS):
                break
            time.sleep(0.5)
        for i in POOLS:
            assert control in nodes[i].getrawmempool()
            self.mine(i, blocks_only=True)
            assert control in nodes[i].getrawmempool()
        assert control not in user.getrawmempool()
        self.checkpoint('fee')


if __name__ == '__main__':
    YellowbackFeeTest().main()
