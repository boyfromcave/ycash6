#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A pruned kogany follower at its retention edge (workspace pruning assessment
docs/plans/kogany/research/pruning-assessment.md, KP-2 and section 4.3; decision 4: kogany may
run Zakura's Pruned storage mode with Zakura's floor and no floor at the vault height).

    KOGANY_BIN=<zakurad --features ycash> KOGANY_PRUNED=1 KOGANY_MIRROR_INVALIDATE=1 \\
      ZCASHD=$BIN/ycashd ../../../.venv/bin/python -u kogany_pruned_edge.py --srcdir=$BIN

KOGANY_PRUNE_RETENTION (default 1001, Zakura's regtest floor) is the follower's retention. The
chain:

  - activate Vault and Yellowback with quoting pools, then mint M (a vault and its YED token) and
    send part of it on: their blocks, and the tagged coinbases around them, are the history the
    follower will prune;
  - mine past retention + MAX_BLOCK_REORG_HEIGHT (the finalized tip trails the best tip by up to
    1,000 blocks, and the window counts from the finalized tip) until the follower reports a
    pruneheight above M's block: every sync point on the way compares the tip,
    vault_getinfo.statehash and yed_getstatehash with ycashd's (the harness);
  - the reads a pruned body takes away answer ycashd's pruned refusal on kogany
    (-32603 "Block not available (pruned data)", KP-1), where ycashd (archive) answers: yed_gettag
    by height and by hash, yed_getprice's tag, yed_gettxinfo of M and of its transfer, getblock at
    every verbosity (as a pruned ycashd refuses it); the same reads at or above pruneheight, and
    yed_getvault of M, equal ycashd's;
  - the deepest reorg the follower can take: every ycashd invalidates the block above the
    follower's finalized tip (its fork point is the edge the window is counted from), the pools mine
    a longer branch; the follower follows (the invalidation mirrored) and the three state hashes
    agree; the old branch is reconsidered and abandoned as the shorter one;
  - a restart of the pruned follower (the non-finalized backup reloads): same tip, same state
    hashes, still pruned, the pruneheight not lowered;
  - a last round of blocks, the state hashes once more.

Without KOGANY_BIN the script runs the same chain on ycashd alone (the kogany checks are skipped).
Not in any CI list: the follower needs about 2,100 blocks before it prunes (a nightly candidate).
"""

from test_framework import kogany
from test_framework.authproxy import JSONRPCException
from test_framework.util import assert_equal
from test_framework.yellowback_util import (
    POOLS,
    REF_LAG,
    START_HEIGHT,
    USER,
    YellowbackTestFramework,
    assert_best_hash,
    assert_same_statehash,
)
from test_framework.yellowback_attest import ArmedModeMixin

MAX_BLOCK_REORG_HEIGHT = 1000
PRUNED = 'Block not available (pruned data)'
BATCH = 250


class KoganyPrunedEdgeTest(ArmedModeMixin, YellowbackTestFramework):

    def follower(self):
        mixed = kogany.current()
        return mixed.followers[0] if mixed.active else None

    def pruned_error(self, fn, *args):
        """The error kogany answers for a pruned body: -32603 with ycashd's text."""
        try:
            fn(*args)
        except JSONRPCException as e:
            assert_equal((e.error['code'], e.error['message']), (-32603, PRUNED))
            return
        raise AssertionError('expected the pruned refusal from %s%r' % (getattr(fn, '__name__', fn), args))

    def mine_to(self, height):
        """Batches of ``generate`` on the pools in turn, each batch synced (a harness sync point)."""
        k = 0
        while self.nodes[USER].getblockcount() < height:
            n = min(BATCH, height - self.nodes[USER].getblockcount())
            self.mine(POOLS[k % len(POOLS)], n, blocks_only=True)
            k += 1

    def run_test(self):
        mixed = kogany.current()
        user = self.nodes[USER]
        retention = kogany.pruned_retention() or kogany.REGTEST_PRUNE_FLOOR
        f = self.follower()
        if f is not None:
            assert kogany.pruned_retention() is not None, 'run with KOGANY_PRUNED=1'
            info = f.rpc.getblockchaininfo()
            assert_equal((info['pruned'], info['pruneheight']), (True, 0))   # pruning, nothing pruned yet
        assert_equal(user.getblockchaininfo()['pruned'], False)

        print('activate with quoting pools; mint M and send part of it on')
        self.activate(POOLS, quote_usd=50)
        self.mine_round_robin(POOLS, REF_LAG + 1)
        self.arm()
        mint = self.mint(user, 10000, 48)
        self.sync_all()
        m_block = self.mine(POOLS[1])[0]
        m_height = user.getblock(m_block)['height']
        assert_equal(user.yed_getvault(mint['txid'])['status'], 'ACTIVE')
        sent = user.yed_send(user.yed_getnewaddress(), 2500)
        self.sync_all()
        self.mine(POOLS[2])
        self.checkpoint('after M')
        tagged = [h for h in range(START_HEIGHT, m_height + 1)
                  if user.yed_gettag(str(h)).get('found')]
        assert tagged, 'no tagged coinbase below M'
        print('  M %s at %d; %d tagged coinbases from %d' % (mint['txid'][:16], m_height, len(tagged), START_HEIGHT))

        target = m_height + retention + MAX_BLOCK_REORG_HEIGHT + 50
        print('mine to %d: past M + retention %d + the reorg window' % (target, retention))
        self.mine_to(target)
        self.checkpoint('past the window')

        if f is None:
            print('no kogany follower: the pruned checks are skipped')
            return self.finish()

        info = f.rpc.getblockchaininfo()
        ph = info['pruneheight']
        print('  follower: pruned=%s pruneheight=%d tip=%d' % (info['pruned'], ph, info['blocks']))
        assert ph > m_height, 'the follower kept M\'s block (pruneheight %d, M at %d)' % (ph, m_height)
        finalized = ph + retention - 1          # the window counts from the finalized tip
        assert finalized <= info['blocks'] <= finalized + MAX_BLOCK_REORG_HEIGHT, (finalized, info['blocks'])

        print('reads below pruneheight %d answer the pruned refusal; at and above it they equal ycashd' % ph)
        low = tagged[-1]
        self.pruned_error(f.rpc.yed_gettag, str(low))
        self.pruned_error(f.rpc.yed_gettag, user.getblockhash(low))
        self.pruned_error(f.rpc.yed_getprice, low)
        self.pruned_error(f.rpc.yed_gettxinfo, mint['txid'])
        self.pruned_error(f.rpc.yed_gettxinfo, sent['txid'])
        self.pruned_error(f.rpc.getblock, user.getblockhash(low), 0)
        assert user.yed_gettag(str(low))['found']
        assert_equal(user.yed_gettxinfo(mint['txid'])['height'], m_height)
        self.pruned_error(f.rpc.getblock, m_block, 1)     # ycashd refuses a pruned block at every verbosity
        self.pruned_error(f.rpc.getblock, m_block, 2)
        assert_equal(user.getblock(m_block, 1)['height'], m_height)
        assert_equal(f.rpc.getblock(user.getblockhash(0), 0), user.getblock(user.getblockhash(0), 0))  # genesis
        for h in (ph, ph + 1, user.getblockcount()):
            assert_equal(f.rpc.yed_gettag(str(h)), user.yed_gettag(str(h)))
            bh = user.getblockhash(h)
            assert_equal(f.rpc.getblock(bh, 0), user.getblock(bh, 0))
        if START_HEIGHT < ph:                   # below startHeight ycashd reads no body: no refusal
            assert_equal(f.rpc.yed_gettag(str(START_HEIGHT - 1)), user.yed_gettag(str(START_HEIGHT - 1)))
        assert_equal(f.rpc.yed_getvault(mint['txid']), user.yed_getvault(mint['txid']))

        tip = user.getblockcount()
        depth = tip - finalized
        fork = user.getblockhash(finalized + 1)
        print('the deepest reorg the follower takes: invalidate %d (depth %d, fork point = finalized tip %d)'
              % (finalized + 1, depth, finalized))
        old_tip = user.getbestblockhash()
        for n in self.nodes:
            n.invalidateblock(fork)
        assert_equal(user.getblockcount(), finalized)
        self.refresh_peer_views()               # 6.20.0: peers still point at the invalidated branch
        self.mine_to(tip + 1)
        assert user.getbestblockhash() != old_tip
        self.checkpoint('after the edge reorg')
        assert_equal(f.rpc.getbestblockhash(), user.getbestblockhash())
        for n in self.nodes:
            n.reconsiderblock(fork)             # the old branch comes back as the shorter one
        self.sync_all(blocks_only=True)
        assert_equal(f.rpc.getbestblockhash(), user.getbestblockhash())
        assert_equal(f.rpc.yed_getvault(mint['txid']), user.yed_getvault(mint['txid']))

        print('restart the pruned follower')
        before = f.rpc.getblockchaininfo()['pruneheight']
        f.stop()
        f.start()
        mixed.sync_point([user], 'after the follower restart')
        info = f.rpc.getblockchaininfo()
        assert info['pruned'] and info['pruneheight'] >= before, (info['pruneheight'], before)
        self.pruned_error(f.rpc.yed_gettag, str(low))
        self.finish()

    def finish(self):
        self.mine_to(self.nodes[USER].getblockcount() + 10)
        self.checkpoint('end')
        enforcing = self.enforcing_nodes()
        assert_best_hash(enforcing, 'end')
        assert_same_statehash(enforcing, 'end')
        mixed = kogany.current()
        if mixed.active:
            print('mixed line stats: %s' % mixed.stats)


if __name__ == '__main__':
    KoganyPrunedEdgeTest().main()
