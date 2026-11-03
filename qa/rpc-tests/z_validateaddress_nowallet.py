#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
z_validateaddress on a -disablewallet node answers instead of crashing.

With the wallet compiled in, z_validateaddress took LOCK2(cs_main, pwalletMain->cs_wallet), and
pwalletMain is null under -disablewallet, so the node died on the call (found by the kogany port's
yewd agent). The address description needs no wallet: the node must describe a transparent and a
Sapling address, with no `ismine`, exactly as the wallet node does apart from that field.
Node 1 has a wallet and supplies the addresses; the two nodes need not be connected.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, start_nodes

WALLET_ARGS = ['-allowdeprecated=getnewaddress', '-allowdeprecated=z_getnewaddress']


class ZValidateAddressNoWalletTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.cache_behavior = 'clean'

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [['-disablewallet'], WALLET_ARGS])
        self.is_network_split = False

    def run_test(self):
        nowallet, wallet = self.nodes
        for addr in (wallet.getnewaddress(), wallet.z_getnewaddress('sapling')):
            mine = wallet.z_validateaddress(addr)
            got = nowallet.z_validateaddress(addr)
            assert_equal(got['isvalid'], True)
            assert_equal(mine['ismine'], True)
            assert 'ismine' not in got, got
            del mine['ismine']
            assert_equal(got, mine)
        assert_equal(nowallet.z_validateaddress('not-an-address')['isvalid'], False)
        assert_equal(nowallet.getblockcount(), 0)   # still alive


if __name__ == '__main__':
    ZValidateAddressNoWalletTest().main()
