#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
-stopatheight=<n> (ported from Bitcoin Core; testnet plan §4.3), the same on both node lines.

The node shuts down cleanly once its active chain reaches <n> and connects no block above it. The
snapshotter relies on that to stop a node at exactly the bundle height H_B.

Node 2 mines its own chain with -stopatheight=3: after block 3 it exits with status 0, and a
restart without the option finds the tip at 3.

Node 0 has -stopatheight=5 and syncs from node 1, which has mined 10 blocks. It receives more
blocks than it may connect, connects up to 5, logs the stop once at height 5 and exits with status 0.
"""

import os

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    bitcoind_processes,
    connect_nodes,
    start_node,
    sync_blocks,
)

STOP_MESSAGE = "-stopatheight: the active chain is at height %d; shutting down"


class StopAtHeightTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)

    def setup_network(self, split=False):
        self.nodes = [
            start_node(0, self.options.tmpdir, ['-stopatheight=5']),
            start_node(1, self.options.tmpdir),
            start_node(2, self.options.tmpdir, ['-stopatheight=3']),
        ]
        self.is_network_split = True    # no connections until the test makes one

    def wait_stopped(self, i):
        proc = bitcoind_processes.pop(i)
        proc.wait(timeout=120)
        assert_equal(proc.returncode, 0)

    def stop_lines(self, i):
        path = os.path.join(self.options.tmpdir, "node%d" % i, "regtest", "debug.log")
        with open(path, encoding="utf8", errors="replace") as f:
            return [line for line in f if "-stopatheight:" in line]

    def run_test(self):
        # Mining: block 3 is connected, then the node stops.
        n2 = self.nodes[2]
        n2.generate(2)
        assert_equal(n2.getblockcount(), 2)
        try:
            n2.generate(1)
        except (JSONRPCException, ConnectionError, BrokenPipeError):
            pass                        # the shutdown may close the RPC connection first
        self.wait_stopped(2)
        lines = self.stop_lines(2)
        assert_equal(len(lines), 1)
        assert STOP_MESSAGE % 3 in lines[0], lines[0]
        self.nodes[2] = start_node(2, self.options.tmpdir)
        assert_equal(self.nodes[2].getblockcount(), 3)

        # Sync: node 0 is offered 10 blocks and connects exactly 5.
        self.nodes[1].generate(10)
        connect_nodes(self.nodes[1], 0)
        self.wait_stopped(0)
        lines = self.stop_lines(0)
        assert_equal(len(lines), 1)
        assert STOP_MESSAGE % 5 in lines[0], lines[0]

        # Without the option the node starts and follows node 1 again.
        self.nodes[0] = start_node(0, self.options.tmpdir)
        connect_nodes(self.nodes[1], 0)
        sync_blocks(self.nodes[0:2])
        assert_equal(self.nodes[0].getblockcount(), 10)


if __name__ == '__main__':
    StopAtHeightTest().main()
