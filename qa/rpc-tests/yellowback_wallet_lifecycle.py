#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""Transparent v2 wallet lifecycle: mint, send, and owner-path redeem."""

from test_framework.util import assert_equal
from test_framework.yellowback_attest import wallet_mint
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    YellowbackTestFramework,
)


class YellowbackWalletLifecycleTest(YellowbackTestFramework):

    def run_test(self):
        nodes = self.nodes
        self.activate(quote_usd=50)
        self.mine(POOLS[0], REF_LAG + 1)

        mint = wallet_mint(self, nodes[0], 10000, 48)   # v3: the carrier step (W7)
        assert_equal(mint['termClass'], 'A')
        assert_equal(mint['fundedFrom'], 'transparent')
        assert mint['feeZat'] > 0
        assert mint['payee'] in self.pool_addresses
        self.sync_all()
        self.mine(POOLS[0])
        assert_equal(nodes[0].yed_getvault(mint['txid'])['status'], 'ACTIVE')
        assert_equal(nodes[0].yed_getbalance()['confirmedCents'], 10000)

        send = nodes[0].yed_send(nodes[0].yed_getnewaddress(), 4000)
        assert_equal(send['changeCents'], 6000)
        self.sync_all()
        self.mine(POOLS[1])
        assert_equal(nodes[0].yed_getbalance()['confirmedCents'], 10000)

        lock_height = mint['lockHeight']
        blocks = lock_height - nodes[0].getblockcount()
        if blocks > 0:
            self.mine_round_robin(POOLS, blocks)
        redeem = nodes[0].yed_redeem(mint['txid'])
        assert_equal(redeem['burnedCents'], 10000)
        assert redeem['feeZat'] > 0
        assert redeem['payee'] in self.pool_addresses
        self.sync_all()
        self.mine(POOLS[2])
        assert_equal(nodes[0].yed_getvault(mint['txid'])['status'], 'CLOSED')
        assert_equal(nodes[0].yed_getbalance()['confirmedCents'], 0)
        self.checkpoint('transparent wallet lifecycle')


if __name__ == '__main__':
    YellowbackWalletLifecycleTest().main()