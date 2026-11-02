#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A node started with -lightwalletd alone (no -insightexplorer, no -txindex) connects blocks,
serves the address index lightwalletd reads (getaddresstxids, getaddressbalance) and restarts
without demanding a reindex.

-lightwalletd sets fAddressIndex, and the 6.20.0 pin keeps the address index in the separate
insight explorer database; before this fix that database was opened only for -insightexplorer,
so the first connected block wrote through a null pointer (doc/yellowback-baseline.md, pin
finding 7; reported again by the kogany port). Node 1 is a plain node: the two must agree.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    connect_nodes,
    start_node,
    start_nodes,
    stop_node,
)


class LightwalletdOnlyTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.cache_behavior = 'clean'
        self.lwd_args = ['-experimentalfeatures', '-lightwalletd']

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [self.lwd_args, []])
        connect_nodes(self.nodes[0], 1)
        self.is_network_split = False
        self.sync_all()

    def coinbase_address(self, node, height):
        block = node.getblock(node.getblockhash(height), 2)
        return block['tx'][0]['vout'][0]['scriptPubKey']['addresses'][0]

    def run_test(self):
        lwd, plain = self.nodes
        assert 'lightwalletd' in lwd.getexperimentalfeatures()

        # The defect: the first block the -lightwalletd node connects kills it.
        lwd.generate(1)
        self.sync_all()
        assert_equal(lwd.getblockcount(), 1)
        assert_equal(plain.getblockcount(), 1)

        lwd.generate(9)
        self.sync_all()
        plain.generate(5)   # blocks it receives from a peer are indexed too
        self.sync_all()
        assert_equal(lwd.getblockcount(), 15)

        # The index agrees with the chain: every coinbase that pays the first block's address.
        addr = self.coinbase_address(lwd, 1)
        paid = [h for h in range(1, 16) if self.coinbase_address(lwd, h) == addr]
        expected = [lwd.getblock(lwd.getblockhash(h))['tx'][0] for h in paid]
        assert_equal(lwd.getaddresstxids(addr), expected)
        total = sum(lwd.getblock(lwd.getblockhash(h), 2)['tx'][0]['vout'][0]['valueZat'] for h in paid)
        assert_equal(lwd.getaddressbalance(addr)['balance'], total)

        # The flags persist: a restart with the same flags needs no reindex and keeps indexing.
        stop_node(lwd, 0)
        self.nodes[0] = lwd = start_node(0, self.options.tmpdir, self.lwd_args)
        connect_nodes(lwd, 1)
        lwd.generate(1)
        self.sync_all()
        assert_equal(lwd.getblockcount(), 16)
        assert_equal(plain.getbestblockhash(), lwd.getbestblockhash())
        paid = [h for h in range(1, 17) if self.coinbase_address(lwd, h) == addr]
        assert_equal(lwd.getaddresstxids(addr), [lwd.getblock(lwd.getblockhash(h))['tx'][0] for h in paid])


if __name__ == '__main__':
    LightwalletdOnlyTest().main()
