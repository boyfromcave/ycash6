#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A restore from the recovery phrase on a chain no block extends completes (beta4 item 2b, as yewd: yew #58).

A node whose tip is older than -maxtipage (24 h) stays in initial block download until a new block comes. Before beta4
a wallet restored from its phrase (-mnemonicfile) on such a node scanned the whole chain and still kept
getwalletinfo restore_in_progress true ("the node is in initial block download: the next start scans again"), at every
start, for as long as the chain stayed parked. Now the restore completes once its scan has reached the tip, every
re-pass included, and the node is at its header tip (blocks >= headers) with that tip unchanged: with peers for 60 s on
mainnet and the testnets, at once on regtest.

Here: 20 blocks mined two hours in the past (-mocktime), the node restarted on the real clock with -maxtipage one hour (blocks 20, headers 20,
initial_block_download_complete false, no new block), a new wallet restored from the first wallet's phrase. The marker
clears at that start (the wallet RPCs answer only out of initial block download: one new block, after which the
wallet shows restore_in_progress false, every reward, and no "restart the node" warning), and a later start does not
scan again.

Run: ZCASHD=<ycashd> .venv/bin/python -u qa/rpc-tests/wallet_restore_parked_chain.py --tmpdir=<dir> --portseed=<n>
"""

import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, start_node, start_nodes, stop_node

PARKED = 2 * 60 * 60       # the tip's age: older than -maxtipage, so the node stays in initial block download
MAX_TIP_AGE = 60 * 60     # -maxtipage (24 h by default): one new block (at most 90 min past the median) ends the download


class WalletRestoreParkedChainTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.cache_behavior = 'clean'
        self.setup_clean_chain = True

    def node_args(self, wallet, extra=None):
        return ['-wallet=%s' % wallet, '-exportdir=%s' % os.path.join(self.options.tmpdir, 'export0'),
                '-maxtipage=%d' % MAX_TIP_AGE] + (extra or [])

    def setup_network(self, split=False):
        os.makedirs(os.path.join(self.options.tmpdir, 'export0'), exist_ok=True)
        self.then = int(time.time()) - PARKED
        self.nodes = start_nodes(1, self.options.tmpdir, extra_args=[self.node_args('original.dat', ['-mocktime=%d' % self.then])])
        self.is_network_split = False

    def debug_log(self):
        with open(os.path.join(self.options.tmpdir, 'node0', 'regtest', 'debug.log'), encoding='utf-8') as f:
            return f.read()

    def wait_log(self, logpos, *needles, timeout=30):
        deadline = time.time() + timeout
        while True:
            log = self.debug_log()[logpos:]
            if all(n in log for n in needles) or time.time() > deadline:
                return log
            time.sleep(0.2)

    def wallet_caught_up(self, node, txcount):
        """getwalletinfo once the wallet has seen `txcount` transactions (it follows the tip a moment later)."""
        for _ in range(100):
            info = node.getwalletinfo()
            if info['txcount'] >= txcount:
                return info
            time.sleep(0.1)
        return info

    def restart(self, wallet, extra=None):
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args(wallet, extra))
        return self.nodes[0]

    def run_test(self):
        n0 = self.nodes[0]
        print('20 blocks, two hours ago')
        n0.generate(20)
        assert_equal(n0.getblockcount(), 20)
        original = self.wallet_caught_up(n0, 20)
        assert original['immature_balance'] > 0, original
        export = n0.z_exportwallet('parkedexport')

        print('the node restarts on the real clock: the chain is parked, the node is in initial block download')
        logpos = len(self.debug_log())
        n0 = self.restart('restored.dat', ['-mnemonicfile=%s' % export])
        info = n0.getblockchaininfo()
        assert_equal((info['blocks'], info['headers'], info['initial_block_download_complete']), (20, 20, False))
        log = self.wait_log(logpos, "The restore's scan from height 0 is complete")
        assert "but the node is in initial block download: it completes once the node stays at its header tip" in log, log
        assert ("The restore's scan from height 0 is complete (the node is at its header tip, which no new block has "
                "extended)") in log, log

        print('the restore is complete: wallet RPCs wait for the end of initial block download, which a new block brings')
        n0.generate(1)
        assert_equal(n0.getblockchaininfo()['initial_block_download_complete'], True)
        restored = self.wallet_caught_up(n0, original['txcount'] + 1)
        assert_equal(restored['restore_in_progress'], False)
        assert_equal(restored['txcount'], original['txcount'] + 1)
        assert restored['immature_balance'] > original['immature_balance'], (restored, original)
        assert 'Wallet restore in progress' not in n0.getinfo()['errors']
        assert 'has not completed its scan of older blocks' not in self.debug_log()[logpos:]
        original = restored

        print('a later start does not scan again')
        logpos = len(self.debug_log())
        n0 = self.restart('restored.dat')
        time.sleep(2)
        assert 'has not completed its scan' not in self.debug_log()[logpos:]
        assert_equal(n0.getwalletinfo()['restore_in_progress'], False)
        assert_equal(n0.getwalletinfo()['immature_balance'], original['immature_balance'])


if __name__ == '__main__':
    WalletRestoreParkedChainTest().main()
