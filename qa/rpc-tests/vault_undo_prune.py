#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The vault set-state database prunes its per-block undo records (audit 07/F-7, 07/F-8).

Connecting block h erases the vault undo record of block h - UNDO_KEEP (4,096, src/vault/db.h) in the
same batch, as the Yellowback index prunes its own: a database holds at most UNDO_KEEP of them.

- One node, UPGRADE_VAULT at ACTIVATION; mine UNDO_KEEP + 4 blocks past it.
- debug.log (-debug=vault) names the pruned undo of the activation block and of the three after it,
  and of no block before activation.
- A disconnect within the horizon (invalidateblock of the tip, reconsiderblock) still works.
- SIGKILL two blocks after a chainstate flush, restart: the database tip is the chain tip again (Reconcile),
  the state hash unchanged; then
  <datadir>/vaults/ deleted: the replay from activation prunes as it goes and reaches the same state.

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_undo_prune.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import os
import shutil
import signal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    bitcoind_processes,
    nuparams,
    start_node,
    start_nodes,
    stop_node,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS

ACTIVATION = 20
UNDO_KEEP = 4096          # src/vault/db.h


class VaultUndoPruneTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.cache_behavior = 'clean'   # the 6.20.0 harness's name for it (ycash6)

    def node_args(self):
        return list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACTIVATION), '-debug=vault']

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir, extra_args=[self.node_args()])
        self.is_network_split = False

    def datadir(self):
        return os.path.join(self.options.tmpdir, 'node0', 'regtest')

    def log(self):
        with open(os.path.join(self.datadir(), 'debug.log'), encoding='utf-8', errors='replace') as f:
            return f.read()

    def restart(self, kill=False, wipe=False):
        if kill:
            p = bitcoind_processes.pop(0)
            os.kill(p.pid, signal.SIGKILL)
            p.wait()
        else:
            stop_node(self.nodes[0], 0)
        if wipe:
            shutil.rmtree(os.path.join(self.datadir(), 'vaults'))
        self.nodes[0] = start_node(0, self.options.tmpdir, self.node_args())

    def assert_db_at_tip(self, label):
        n = self.nodes[0]
        info = n.vault_getinfo()
        assert_equal(info['dbtip']['height'], n.getblockcount())
        assert_equal(info['dbtip']['hash'], n.getbestblockhash())
        print('    ok   %s: the vault database is at the tip (%d)' % (label, info['dbtip']['height']))
        return info['statehash']

    def run_test(self):
        n = self.nodes[0]
        target = ACTIVATION + UNDO_KEEP + 3
        print('mining to %d (UPGRADE_VAULT at %d, UNDO_KEEP %d)' % (target, ACTIVATION, UNDO_KEEP))
        while n.getblockcount() < target:
            n.generate(min(500, target - n.getblockcount()))
        assert_equal(n.vault_getinfo()['active'], True)
        h0 = self.assert_db_at_tip('after mining')

        log = self.log()
        for h in range(ACTIVATION, ACTIVATION + 4):
            line = 'vault: pruned undo of %s at %d' % (n.getblockhash(h), h)
            assert line in log, 'missing "%s" in debug.log' % line
        assert 'vault: pruned undo of %s ' % n.getblockhash(ACTIVATION + 4) not in log
        assert 'vault: pruned undo of %s ' % n.getblockhash(ACTIVATION - 1) not in log
        print('    ok   the undo records of blocks %d..%d were pruned as blocks %d..%d connected'
              % (ACTIVATION, ACTIVATION + 3, ACTIVATION + UNDO_KEEP, target))

        print('a disconnect within the horizon')
        tip = n.getbestblockhash()
        n.invalidateblock(tip)
        assert_equal(n.getblockcount(), target - 1)
        self.assert_db_at_tip('after invalidateblock of the tip')
        n.reconsiderblock(tip)
        assert_equal(n.getbestblockhash(), tip)
        assert_equal(self.assert_db_at_tip('after reconsiderblock'), h0)

        print('restarts')
        n.gettxoutsetinfo()          # flushes the chainstate at the tip ...
        n.generate(2)                # ... and two blocks the chainstate has not flushed when the node is killed
        self.restart(kill=True)
        assert_equal(self.assert_db_at_tip('after SIGKILL'), h0)
        self.restart(wipe=True)
        assert_equal(self.assert_db_at_tip('after deleting vaults/ (replay from activation)'), h0)
        assert 'vault: replaying blocks %d..%d' % (ACTIVATION, self.nodes[0].getblockcount()) in self.log()
        n = self.nodes[0]
        n.generate(1)
        self.assert_db_at_tip('one more block after the replay')
        print('vault_undo_prune OK')


if __name__ == '__main__':
    VaultUndoPruneTest().main()
