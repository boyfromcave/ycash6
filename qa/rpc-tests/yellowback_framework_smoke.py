#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Smoke test of the v2 test framework itself (plan section 6.0 item 4): six nodes start in the
standard topology, mine, split and join without a restart, survive kill -9 and a restart, and
take a mock clock.  Every node runs as a stock node (``yellowback_enabled = False``) so the
script runs against any ycashd — including the Phase 1 binary, whose regtest ``-yellowback``
still needs the federation genesis arguments — and no ``yed_*`` call is made.

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/yellowback_framework_smoke.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

from test_framework.util import assert_equal, assert_greater_than
from test_framework.yellowback_util import (
    OBSERVER,
    POOLS,
    STOCK,
    USER,
    YellowbackTestFramework,
    assert_best_hash,
    round_robin_schedule,
)


class FrameworkSmokeTest(YellowbackTestFramework):
    yellowback_enabled = False

    def run_test(self):
        nodes = self.nodes
        assert_equal(len(nodes), 6)
        print('topology: every node has the peers the star + 2-3-4 + 0-2 give it')
        expected = {USER: 2, STOCK: 5, 2: 3, 3: 3, 4: 2, OBSERVER: 1}
        for i, n in expected.items():
            assert_equal(len(nodes[i].getpeerinfo()), 2 * n, 'node %d peer count' % i)
        for k, i in enumerate(POOLS):
            assert_equal(nodes[i].validateaddress(self.pool_addresses[k])['ismine'], True)

        print('mine: the stock miner\'s block reaches every node')
        start = nodes[USER].getblockcount()
        self.mine(STOCK, 3)
        assert_best_hash(nodes, 'after stock mining')
        assert_equal(nodes[OBSERVER].getblockcount(), start + 3)

        print('mine_round_robin with shares')
        blocks = self.mine_round_robin(POOLS, 6, shares=[3, 2, 1])
        assert_equal([i for i, _ in blocks], round_robin_schedule(POOLS, 6, [3, 2, 1]))
        assert_equal(sorted(i for i, _ in blocks), [2, 2, 2, 3, 3, 4])
        assert_best_hash(nodes, 'after round robin')
        tip = nodes[0].getbestblockhash()
        assert_equal(nodes[2].getblock(tip)['height'], start + 9)

        print('split_network: {1, 5} away from {0, 2, 3, 4}, no restart')
        self.split_network()
        assert_equal(len(nodes[OBSERVER].getpeerinfo()), 2)      # only node 1
        assert_equal(len(nodes[USER].getpeerinfo()), 2)          # only node 2
        self.mine(STOCK, 2)
        self.mine(2, 3)
        assert_best_hash([nodes[i] for i in (1, 5)], 'stock half')
        assert_best_hash([nodes[i] for i in (0, 2, 3, 4)], 'enforcing half')
        assert nodes[1].getbestblockhash() != nodes[2].getbestblockhash()
        assert_equal(nodes[5].getblockcount(), start + 11)
        assert_equal(nodes[0].getblockcount(), start + 12)

        print('join_network: the longer branch wins everywhere')
        self.join_network()
        assert_best_hash(nodes, 'after join')
        assert_equal(nodes[1].getblockcount(), start + 12)
        assert_equal(nodes[1].getbestblockhash(), tip_of(nodes[2]))

        print('kill9 node 3 and restart it')
        self.kill9(3)
        assert_equal(nodes[3], None)
        self.mine(2, 1)                                          # nodes 0, 1, 2, 4, 5 follow
        self.restart(3)
        self.sync_all()
        assert_best_hash(nodes, 'after restart')
        assert_equal(len(nodes[3].getpeerinfo()), 6)             # 1, 2, 4 both ways

        print('advance_clock: a mined block carries the mock time')
        t = self.advance_clock(3 * 3600)
        h = self.mine(4, 1)[0]
        assert_greater_than(nodes[0].getblock(h)['time'] + 1, t)
        assert_best_hash(nodes, 'after mock time')

        print('checkpoint on stock nodes: best hash only (no yed_* on this binary)')
        self.sync_all()
        assert_best_hash(nodes)
        print('framework smoke OK')


def tip_of(node):
    return node.getbestblockhash()


if __name__ == '__main__':
    FrameworkSmokeTest().main()
