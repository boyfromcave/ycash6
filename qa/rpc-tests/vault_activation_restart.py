#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
What a restart keeps of the block index, the same on both node lines (byte-identical script,
qa/yellowback-cross-line.manifest).

RewindBlockIndex (src/main.cpp) runs at every start and erases the entries that are not
"sufficiently validated". On both lines (owner decision 2026-10-28) an entry that never ran
ConnectBlock (below BLOCK_VALID_CONSENSUS) is kept unless it has failed (upstream Ycash 1770fce16
plus the workspace upstream report's section 3.2 refinement), and the erase set is closed under
descendants (every entry built on an erased one is erased with it), so a failed branch is erased
whole and its blocks are judged again when they come back, as v4.5.0 always did, and no kept entry
is left under a deleted parent.

The defect this pins as fixed: after `invalidateblock` of a block below a network upgrade's
activation height whose branch contains the activation block, stock v4.5.0 erased the invalidated
blocks but kept the activation block (its branch id is on disk) with a deleted parent, and
CheckBlockIndex aborted ("nNodes == forward.size()"). Every start here runs -checkblockindex.

Nodes 0-3, each its own chain: Sapling (a stock upgrade, no Yellowback or vault code involved)
and UPGRADE_VAULT, the activation block invalidated and the block below it invalidated. The
restart is clean, the invalidated branch is gone (getchaintips shows only the active tip,
reconsiderblock does not know the hash), the node stays at the invalidated tip, and the same
blocks submitted again are judged afresh and connected back to the old tip.

Node 4, the upstream benefit: a never-connected side branch with its data on disk (blocks from
node 0's chain, less work) is kept across the restart; a second one (from node 1's chain) whose
second block is invalidated while off the active chain leaves its later blocks unmarked on disk,
and the restart erases them with it rather than keeping them under a deleted parent.

Nodes 5 and 6, the late upgrader: node 5 runs without the vault upgrade and connects blocks past
its activation height under the old rules; node 6 builds a sibling on node 5's block ACT + 1, which
node 5 stores and never connects (less work). Node 5 then restarts with the upgrade at ACT: the
blocks from ACT up carry a stale branch id and are rewound and erased, and the never-connected
child, which has not failed, goes with its parent instead of being kept under it. The restart is
clean, and node 5 mines across the activation under the new rules.

The no-checkblockindex and -reindex recovery starts of the earlier form are gone with the abort.
"""

from test_framework.authproxy import JSONRPCException
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
SIDE = 4                     # the length of node 4's side branches

# start_node passes Overwinter and Sapling at height 1; a later -nuparams for the same branch wins
# (as in mempool_nu_activation.py), so this moves Sapling to ACT with nothing else scheduled.
SAPLING_ARGS = ['-nuparams=5ba81b19:1', '-nuparams=76b809bb:%d' % ACT]
VAULT_ARGS = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACT)]

# node: (upgrade, arguments, the height invalidated)
CASES = {
    0: ('Sapling', SAPLING_ARGS, ACT - 1),
    1: ('Sapling', SAPLING_ARGS, ACT),
    2: ('Vault', VAULT_ARGS, ACT - 1),
    3: ('Vault', VAULT_ARGS, ACT),
}
SIDE_NODE = 4                # node 0's and node 1's rules, so their blocks are valid here
LATE, PEER = 5, 6            # the late upgrader and the peer that extends its pre-upgrade chain

# Each node's upgrade arguments; LATE's change to VAULT_ARGS at its upgrade restart.
ARGS = {i: CASES[i][1] for i in CASES}
ARGS.update({SIDE_NODE: SAPLING_ARGS, LATE: list(YCASH_UPGRADE_ARGS), PEER: list(YCASH_UPGRADE_ARGS)})


def node_args(i):
    return ARGS[i] + ['-checkblockindex=1']


class VaultActivationRestartTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = len(ARGS)
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)

    def setup_network(self, split=False):
        self.nodes = [start_node(i, self.options.tmpdir, node_args(i))
                      for i in range(self.num_nodes)]
        self.is_network_split = True          # each node is its own chain

    def restart(self, i):
        stop_node(self.nodes[i], i)
        self.nodes[i] = start_node(i, self.options.tmpdir, node_args(i))
        return self.nodes[i]

    @staticmethod
    def raw_chain(n, first, last):
        """(hash, serialized block) at heights first..last of n's active chain."""
        hashes = [n.getblockhash(h) for h in range(first, last + 1)]
        return [(h, n.getblock(h, 0)) for h in hashes]

    @staticmethod
    def tips(n):
        return sorted((t['height'], t['status']) for t in n.getchaintips())

    def run_test(self):
        raw = {}
        for i in sorted(CASES):
            n = self.nodes[i]
            n.generate(TOP)
            assert_equal(n.getblockcount(), TOP)
            raw[i] = self.raw_chain(n, 1, TOP)

        side = self.nodes[SIDE_NODE]
        side.generate(TOP)
        self.check_side_branches(side, raw[0][:SIDE], raw[1][:SIDE])
        self.check_late_upgrader()

        for i in sorted(CASES):
            name, _, bad = CASES[i]
            n = self.nodes[i]
            tip = n.getbestblockhash()
            bad_hash = n.getblockhash(bad)
            n.invalidateblock(bad_hash)
            assert_equal(n.getblockcount(), bad - 1)
            assert_equal(self.tips(n), [(bad - 1, 'active'), (TOP, 'invalid')])

            where = 'at' if bad == ACT else 'below'
            print('%s: invalidated %s the activation block: the restart is clean and erases the branch' % (name, where))
            n = self.restart(i)
            assert_equal(n.getblockcount(), bad - 1)
            assert_equal(self.tips(n), [(bad - 1, 'active')])
            try:
                n.reconsiderblock(bad_hash)
            except JSONRPCException as e:
                assert_equal(e.error['code'], -5)        # Block not found
            else:
                raise AssertionError('%s: the invalidated block survived the restart' % name)

            print('%s: the same blocks submitted again are judged afresh and connect' % name)
            for _, block in raw[i][bad - 1:]:
                assert_equal(n.submitblock(block), None)
            assert_equal(n.getbestblockhash(), tip)
            assert_equal(self.tips(n), [(TOP, 'active')])
            n = self.restart(i)
            assert_equal(n.getbestblockhash(), tip)

    def expect_erased(self, n, hashes, what):
        for h in hashes:
            try:
                n.getblockheader(h)
            except JSONRPCException as e:
                assert_equal(e.error['code'], -5)                       # Block not found
            else:
                raise AssertionError('%s %s survived the restart' % (what, h))

    def check_late_upgrader(self):
        late, peer = self.nodes[LATE], self.nodes[PEER]
        late.generate(TOP)                                  # past ACT, without the vault upgrade
        old = [late.getblockhash(h) for h in range(ACT, TOP + 1)]
        for _, block in self.raw_chain(late, 1, ACT + 1):
            assert_equal(peer.submitblock(block), None)
        child = peer.generate(1)[0]                         # at ACT + 2, on node 5's block ACT + 1
        assert child != old[2], 'node 6 mined node 5\'s own block'
        assert_equal(late.submitblock(peer.getblock(child, 0)), 'inconclusive')   # stored, never connected
        assert_equal(self.tips(late), [(ACT + 2, 'valid-headers'), (TOP, 'active')])

        print('late upgrader: the upgrade restart erases the stale blocks and the never-connected child with them')
        ARGS[LATE] = VAULT_ARGS
        late = self.restart(LATE)
        assert_equal(late.getblockcount(), ACT - 1)
        assert_equal(self.tips(late), [(ACT - 1, 'active')])
        self.expect_erased(late, old + [child], 'late upgrader block')
        late.generate(2)                                    # across the activation, under the new rules
        assert_equal(late.getblockcount(), ACT + 1)
        late = self.restart(LATE)
        assert_equal(late.getblockcount(), ACT + 1)
        assert_equal(self.tips(late), [(ACT + 1, 'active')])

    def check_side_branches(self, n, kept, failed):
        assert kept[0][0] != failed[0][0], 'node 0 and node 1 mined the same first block'
        for _, block in kept + failed:
            assert_equal(n.submitblock(block), 'inconclusive')   # stored, not connected (less work)
        expected = [(SIDE, 'valid-headers'), (SIDE, 'valid-headers'), (TOP, 'active')]
        assert_equal(self.tips(n), expected)

        # Invalidated off the active chain: InvalidateBlock marks that entry only (it walks
        # chainActive), so the blocks above it are unmarked on disk.
        n.invalidateblock(failed[1][0])
        assert_equal(n.getblockcount(), TOP)

        print('side branches: the restart keeps the never-connected branch and erases the failed one whole')
        n = self.restart(SIDE_NODE)
        assert_equal(n.getblockcount(), TOP)
        assert_equal(self.tips(n), [(1, 'valid-headers'), (SIDE, 'valid-headers'), (TOP, 'active')])
        assert_equal(n.getblock(kept[-1][0], 0), kept[-1][1])          # kept with its data
        assert_equal(n.getblockheader(failed[0][0])['height'], 1)
        self.expect_erased(n, [h for h, _ in failed[1:]], 'side branch block')
        for _, block in failed[1:]:
            assert_equal(n.submitblock(block), 'inconclusive')         # judged again, accepted
        assert_equal(self.tips(n), expected)

if __name__ == '__main__':
    VaultActivationRestartTest().main()
