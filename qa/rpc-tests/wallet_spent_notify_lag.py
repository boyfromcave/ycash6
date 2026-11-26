#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# Wallets learn of connected blocks asynchronously (ThreadNotifyWallets). Right after a block
# mines one of the wallet's spends, before the wallet is notified, that spend is in neither the
# mempool nor (for the wallet) a block. The wallet must still treat the spent coin as spent:
# listunspent must not list it and coin selection must not pick it (bad-txns-inputs-spent).
# The test calls the wallet straight after generate, without waiting for fullyNotified.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, start_nodes


class WalletSpentNotifyLag(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir, extra_args=[['-allowdeprecated=getnewaddress']])
        self.is_network_split = False

    def stale(self, node):
        return [(u['txid'], u['vout']) for u in node.listunspent()
                if node.gettxout(u['txid'], u['vout'], True) is None]

    def run_test(self):
        node = self.nodes[0]
        node.generate(110)
        self.sync_all()
        for rnd in range(8):
            spent = []
            for _ in range(3):
                txid = node.sendtoaddress(node.getnewaddress(), 1)
                spent += [(i['txid'], i['vout']) for i in node.getrawtransaction(txid, 1)['vin']]
            node.generate(1)
            # no sync: the wallet may not have been notified of the block yet
            listed = {(u['txid'], u['vout']) for u in node.listunspent(0)}
            assert_equal([s for s in spent if s in listed], [])
            assert_equal(self.stale(node), [])
            node.sendtoaddress(node.getnewaddress(), 1)   # coin selection must not pick a spent coin
            self.sync_all()
            assert_equal(self.stale(node), [])


if __name__ == '__main__':
    WalletSpentNotifyLag().main()
