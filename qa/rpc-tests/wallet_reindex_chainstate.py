#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
-reindex-chainstate on a node WITH a wallet (the default), after a clean stop and after an unclean one (SIGKILL after
blocks the block index had not yet written): the node must not stop at the assert in init.cpp
ThreadStartWalletNotifier (`pindexFork != nullptr`: the chainstate is emptied, so the active chain is empty while the
notifier first looks), and the wallet must end up synced: the same balances as before, then a payment received after
the reindex counted too.

    ZCASHD=<ycashd> .venv/bin/python -u qa/rpc-tests/wallet_reindex_chainstate.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
import signal
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    bitcoind_processes,
    connect_nodes_bi,
    start_node,
    stop_node,
    sync_blocks,
)

ARGS = ['-allowdeprecated=getnewaddress']


class WalletReindexChainstateTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = [start_node(i, self.options.tmpdir, ARGS) for i in range(2)]
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def balances(self, i):
        b = self.nodes[i].z_gettotalbalance(1)
        return tuple(Decimal(b[k]) for k in ('transparent', 'private', 'total'))

    def pay(self, amount):
        """node 0 pays node 1 `amount` in a mined block; both nodes see it."""
        self.nodes[0].sendtoaddress(self.addr1, amount)
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

    def restart1(self, kill):
        if kill:
            p = bitcoind_processes.pop(1)
            os.kill(p.pid, signal.SIGKILL)
            p.wait()
        else:
            stop_node(self.nodes[1], 1)
        self.nodes[1] = start_node(1, self.options.tmpdir, ARGS + ['-reindex-chainstate'])
        connect_nodes_bi(self.nodes, 0, 1)
        deadline = time.time() + 120
        while self.nodes[1].getbestblockhash() != self.nodes[0].getbestblockhash():
            assert time.time() < deadline, 'node 1 did not catch up after -reindex-chainstate'
            time.sleep(0.25)

    def check(self, label, expected):
        # the wallet notifier catches up after the chain does
        deadline = time.time() + 60
        while self.balances(1) != expected and time.time() < deadline:
            time.sleep(0.5)
        assert_equal(self.balances(1), expected)
        assert_equal(self.balances(0), self.before0)
        print('    ok   %s: balances unchanged' % label)

    def run_test(self):
        self.addr1 = self.nodes[1].getnewaddress()
        self.pay(Decimal('7'))
        self.before0, before1 = self.balances(0), self.balances(1)

        print('A. a clean stop, then -reindex-chainstate')
        self.restart1(kill=False)
        self.check('after -reindex-chainstate', before1)

        print('B. an unclean stop (SIGKILL), then -reindex-chainstate')
        self.pay(Decimal('3'))
        self.before0, before1 = self.balances(0), self.balances(1)
        self.restart1(kill=True)
        self.check('after the unclean stop and -reindex-chainstate', before1)

        print('C. the wallet still follows the chain')
        self.pay(Decimal('2'))
        t, p, total = self.balances(1)
        assert_equal(t, before1[0] + Decimal('2'))
        print('    ok   a payment after the reindex is counted')
        print('wallet_reindex_chainstate OK')


if __name__ == '__main__':
    WalletReindexChainstateTest().main()
