#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A restart while the node holds an invalidated branch that crosses a network upgrade's activation
block. On this line RewindBlockIndex keeps every entry below BLOCK_VALID_CONSENSUS, which includes
every BLOCK_FAILED_* entry (upstream Ycash 1770fce16, src/main.cpp RewindBlockIndex), so the whole
invalidated branch survives the restart with its marks and reconsiderblock brings it back.

The v4.5.0 line (ycash-dd) has a script of the same name pinning the opposite: there stock
RewindBlockIndex erases the invalidated blocks but keeps the activation block (its branch id is on
disk) with a dangling parent, and CheckBlockIndex aborts ("nNodes == forward.size()").

Cases, each on its own node: Sapling (a stock upgrade, no Yellowback or vault code involved) and
UPGRADE_VAULT; the activation block itself invalidated, and the block below it invalidated.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    nuparams,
    start_node,
    stop_node,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS

ACT = 10                     # the activation height under test
TOP = ACT + 3                # the tip before the invalidation

# start_node passes Overwinter and Sapling at height 1; a later -nuparams for the same branch wins,
# so this moves Sapling to ACT with nothing else scheduled.
SAPLING_ARGS = ['-nuparams=5ba81b19:1', '-nuparams=76b809bb:%d' % ACT]
VAULT_ARGS = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACT)]

# node: (upgrade, arguments, the height invalidated)
CASES = {
    0: ('Sapling', SAPLING_ARGS, ACT - 1),
    1: ('Sapling', SAPLING_ARGS, ACT),
    2: ('Vault', VAULT_ARGS, ACT - 1),
    3: ('Vault', VAULT_ARGS, ACT),
}


class VaultActivationRestartTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = len(CASES)
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = [start_node(i, self.options.tmpdir, CASES[i][1] + ['-checkblockindex=1'])
                      for i in sorted(CASES)]
        self.is_network_split = True          # each node is its own chain

    def run_test(self):
        tips = {}
        for i in sorted(CASES):
            name, _, bad = CASES[i]
            n = self.nodes[i]
            n.generate(TOP)
            assert_equal(n.getblockcount(), TOP)
            tips[i] = n.getbestblockhash()
            n.invalidateblock(n.getblockhash(bad))
            assert_equal(n.getblockcount(), bad - 1)
            stop_node(n, i)

        for i in sorted(CASES):
            name, _, bad = CASES[i]
            where = 'at' if bad == ACT else 'below'
            print('%s: invalidated %s the activation block: the restart is clean and keeps the branch' % (name, where))
            n = self.nodes[i] = start_node(i, self.options.tmpdir, CASES[i][1] + ['-checkblockindex=1'])
            assert_equal(n.getblockcount(), bad - 1)
            invalid = [t for t in n.getchaintips() if t['status'] == 'invalid']
            assert_equal([(t['hash'], t['height']) for t in invalid], [(tips[i], TOP)])
            n.reconsiderblock(self.bad_hash(n, tips[i], bad))
            assert_equal(n.getbestblockhash(), tips[i])
            assert_equal(n.getblockcount(), TOP)

    @staticmethod
    def bad_hash(n, tip, height):
        """The hash at ``height`` on the (invalid) branch ending at ``tip``."""
        h = tip
        while n.getblockheader(h)['height'] > height:
            h = n.getblockheader(h)['previousblockhash']
        return h


if __name__ == '__main__':
    VaultActivationRestartTest().main()
