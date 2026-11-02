#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
-prune keeps every block from the vault prune floor (pruning assessment, workspace
docs/plans/kogany/research/pruning-assessment.md §2.3, §6a decisions 1-3; PR-2), the same on both
node lines (byte-identical script, qa/yellowback-cross-line.manifest).

The floor is H_V - MIN_BLOCKS_TO_KEEP (288): FindFilesToPrune (src/main.cpp) never deletes a
blk/rev pair holding a block at or above it, because the vault Reconcile (src/vault/node.cpp) and
the YED index replay (src/yellowback/index.cpp) read blocks and undo data from H_V. It replaces
the audit 01/N-1 refusal; the start-up check (src/init.cpp) refuses a pruned datadir that lacks
the data of an active-chain block at or above the floor.

Node 1 mines (archive). Node 0 follows with -prune=550 (the minimum) and no wallet (a wallet's
locator older than the pruned range refuses the start, as stock). Blocks are made
big with one transaction each whose outputs are oversized unspendable scripts (more than
MAX_SCRIPT_SIZE bytes, no OP_RETURN, so no Yellowback or vault parser reads them and no coin is
stored): 128 MiB block files fill in about 70 blocks.

  1..1000          small (regtest prunes nothing at or below nPruneAfterHeight = 1000)
  1001..1400       big
  1401..H_V = 1500 small; the YED attestor set is created at H_V and the nodes restart with it
  1502..1650       big

Then on node 0:
- block files below the floor are gone (blk00000.dat at least), getblock below the floor says
  "pruned data", every block from the floor to the tip is readable, the disk use is above the
  -prune target (the floor binds) and debug.log says so once;
- the vault state hash and the YED state hash equal node 1's (archive);
- SIGKILL with <datadir>/vaults/ deleted (the vault Reconcile replays from H_V), then
  -reindex-yellowback (the YED index replays from H_V): both hashes unchanged, and a plain restart
  passes the start-up check;
- the negative cases: the undo file (rev) of the file holding the floor block removed by hand, the
  start is refused naming the floor height and -reindex (the floor's start-up check); its block file
  (blk) removed as well, the stock check that every blk file is present refuses it too; -reindex
  re-downloads from node 1 and the hashes match.

Nightly (EXTENDED_SCRIPTS): about 1.8 GB of disk and 15-30 minutes.

    ZCASHD=<ycashd> (BITCOIND=<ycashd> on v4.5.0) .venv/bin/python -u qa/rpc-tests/vault_prune_floor.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import hashlib
import os
import shutil
import signal
import struct
import time

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    assert_start_raises_init_error,
    bitcoind_processes,
    connect_nodes_bi,
    nuparams,
    start_node,
    stop_node,
)
from test_framework.yellowback_util import ATTESTOR_SET_SPEC, YCASH_UPGRADE_ARGS, wait_yed_healthy

PRUNE_AFTER = 1000            # regtest nPruneAfterHeight (src/chainparams.cpp)
MIN_BLOCKS_TO_KEEP = 288      # src/main.h
ACT = 1500                    # H_V
FLOOR = ACT - MIN_BLOCKS_TO_KEEP
BIG_BELOW = (PRUNE_AFTER + 1, 1400)
BIG_ABOVE = (ACT + 2, 1650)
PRUNE_MIB = 550               # the minimum -prune target
MAX_SCRIPT_SIZE = 10000       # src/script/script.h: a longer scriptPubKey is unspendable
BIG_OUTPUT_SCRIPT = 10001
BIG_OUTPUTS = 190             # about 1.9 MB per transaction, under the 2 MB block limit
PRUNED, MINER = 0, 1


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def read_compact_size(b, pos):
    n = b[pos]
    if n < 253:
        return n, pos + 1
    if n == 253:
        return struct.unpack_from('<H', b, pos + 1)[0], pos + 3
    if n == 254:
        return struct.unpack_from('<I', b, pos + 1)[0], pos + 5
    return struct.unpack_from('<Q', b, pos + 1)[0], pos + 9


def with_big_outputs(raw_hex):
    """A transparent v4 transaction (createrawtransaction, no outputs) with BIG_OUTPUTS zero-value
    outputs of BIG_OUTPUT_SCRIPT bytes of OP_1 each (unspendable by size, not OP_RETURN)."""
    b = bytes.fromhex(raw_hex)
    pos = 8                                         # header, nVersionGroupId
    nin, pos = read_compact_size(b, pos)
    for _ in range(nin):
        pos += 36
        n, pos = read_compact_size(b, pos)
        pos += n + 4
    head = b[:pos]
    nout, pos = read_compact_size(b, pos)
    assert_equal(nout, 0)
    tail = b[pos:]
    out = struct.pack('<q', 0) + compact_size(BIG_OUTPUT_SCRIPT) + b'\x51' * BIG_OUTPUT_SCRIPT
    return (head + compact_size(BIG_OUTPUTS) + out * BIG_OUTPUTS + tail).hex()


def block_hashes_in_file(path):
    """The hashes of the blocks stored in one blk?????.dat file, in file order."""
    hashes = []
    with open(path, 'rb') as f:
        data = f.read()
    pos = 0
    while pos + 8 <= len(data):
        magic, size = struct.unpack_from('<4sI', data, pos)
        if magic == b'\x00\x00\x00\x00' or size == 0:
            break                                   # the preallocated tail
        block = data[pos + 8:pos + 8 + size]
        n, p = read_compact_size(block, 140)        # version, prev, merkle, commitments, time, bits, nonce
        header = block[:p + n]
        hashes.append(hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex())
        pos += 8 + size
    return hashes


class VaultPruneFloorTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True   # v4.5.0 harness
        self.cache_behavior = 'clean'   # 6.20.0 harness (each harness ignores the other's)
        self.attestor_set = None

    def node_args(self, i, extra=None):
        args = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACT), '-maxreceivebuffer=20000', '-checkblocks=5']
        if self.attestor_set:
            args += ['-yellowbackattestorset=%s' % self.attestor_set, '-yellowbacksigmaref=0']
        if i == PRUNED:
            args += ['-prune=%d' % PRUNE_MIB, '-disablewallet', '-debug=prune']
        return args + list(extra or [])

    def start(self, i, extra=None):
        self.nodes[i] = start_node(i, self.options.tmpdir, self.node_args(i, extra), timewait=900)
        return self.nodes[i]

    def setup_network(self, split=False):
        self.nodes = [None, None]
        self.start(PRUNED)
        self.start(MINER)
        connect_nodes_bi(self.nodes, PRUNED, MINER)
        self.is_network_split = False

    def settle(self):
        """Node 0 restarted: reconnected to node 1, at its tip (a node killed with its chainstate unflushed
        reconnects the rest from its own block files), and its YED index healthy there."""
        connect_nodes_bi(self.nodes, PRUNED, MINER)
        self.sync()
        wait_yed_healthy(self.nodes[PRUNED], timeout=300)

    def stop(self, i):
        stop_node(self.nodes[i], i)
        self.nodes[i] = None

    def kill(self, i):
        p = bitcoind_processes.pop(i)
        os.kill(p.pid, signal.SIGKILL)
        p.wait()
        self.nodes[i] = None

    def restart_both(self):
        self.stop(PRUNED)
        self.stop(MINER)
        self.start(PRUNED)
        self.start(MINER)
        connect_nodes_bi(self.nodes, PRUNED, MINER)
        self.sync()

    def sync(self, timeout=900):
        # By tip hash only: sync_blocks also waits for fullyNotified, which a -disablewallet node never reports.
        deadline = time.time() + timeout
        while len(set(n.getbestblockhash() for n in self.nodes if n is not None)) != 1:
            assert time.time() < deadline, 'block sync failed'
            time.sleep(0.25)

    def blocksdir(self, i=PRUNED):
        return os.path.join(self.options.tmpdir, 'node%d' % i, 'regtest', 'blocks')

    def usage_mib(self):
        d = self.blocksdir()
        return sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d)
                   if f.endswith('.dat')) / (1024.0 * 1024.0)

    def debug_log(self):
        with open(os.path.join(self.options.tmpdir, 'node0', 'regtest', 'debug.log'), encoding='utf-8', errors='replace') as f:
            return f.read()

    def hashes(self, i):
        n = self.nodes[i]
        return (n.vault_getinfo()['statehash'], n.yed_getstatehash()['statehash'])

    def mine_big(self, first, last):
        miner = self.nodes[MINER]
        assert_equal(miner.getblockcount(), first - 1)
        for h in range(first, last + 1):
            # the coinbase of block h - 100 is mature at h; the whole of it is the fee
            cb = miner.getblock(miner.getblockhash(h - 100))['tx'][0]
            raw = miner.createrawtransaction([{'txid': cb, 'vout': 0}], {})
            signed = miner.signrawtransaction(with_big_outputs(raw))
            assert signed['complete'], signed
            miner.sendrawtransaction(signed['hex'], True)
            miner.generate(1)
            if h % 25 == 0:
                print('    big block %d of %d (pruned node at %.0f MiB)' % (h, last, self.usage_mib()))
                self.sync()
        self.sync()

    def run_test(self):
        pruned, miner = self.nodes[PRUNED], self.nodes[MINER]

        print('small blocks to the prune-after height %d' % PRUNE_AFTER)
        for _ in range(PRUNE_AFTER // 100):
            miner.generate(100)
            self.sync()

        print('big blocks %d..%d' % BIG_BELOW)
        self.mine_big(*BIG_BELOW)
        size = len(bytes.fromhex(miner.getblock(miner.getblockhash(BIG_BELOW[1]), 0)))
        assert size > 1900000, size

        print('small blocks to H_V = %d; the YED attestor set; restart with it' % ACT)
        miner.generate(ACT - miner.getblockcount())
        created = miner.set_create(dict(ATTESTOR_SET_SPEC))
        miner.generate(1)
        self.sync()
        self.attestor_set = created['setid']
        self.restart_both()
        wait_yed_healthy(self.nodes[MINER], timeout=120)
        wait_yed_healthy(self.nodes[PRUNED], timeout=120)

        print('big blocks %d..%d' % BIG_ABOVE)
        self.mine_big(*BIG_ABOVE)
        pruned, miner = self.nodes[PRUNED], self.nodes[MINER]
        tip = pruned.getblockcount()
        assert_equal(tip, BIG_ABOVE[1])

        print('the files below the floor %d are gone, every block from it is kept' % FLOOR)
        self.check_floor()
        log = self.debug_log()
        assert 'Prune: prune target below the vault floor: blocks from height %d are kept' % FLOOR in log
        assert self.usage_mib() > PRUNE_MIB, self.usage_mib()
        expected = self.hashes(MINER)
        assert_equal(self.hashes(PRUNED), expected)

        print('SIGKILL with the vault database deleted: Reconcile replays from H_V')
        self.kill(PRUNED)
        shutil.rmtree(os.path.join(self.options.tmpdir, 'node0', 'regtest', 'vaults'))
        self.start(PRUNED)
        self.settle()
        assert_equal(self.hashes(PRUNED), expected)
        assert_equal(self.nodes[PRUNED].vault_getinfo()['dbtip']['height'], tip)

        print('-reindex-yellowback: the YED index replays from H_V')
        self.stop(PRUNED)
        self.start(PRUNED, ['-reindex-yellowback'])
        self.settle()
        assert_equal(self.hashes(PRUNED), expected)

        print('a plain restart passes the start-up check')
        self.stop(PRUNED)
        self.start(PRUNED)
        self.settle()
        assert_equal(self.nodes[PRUNED].getblockcount(), tip)
        assert_equal(self.hashes(PRUNED), expected)
        self.check_floor()

        print('the rev file of the file holding the floor block removed by hand: the start is refused')
        floor_hash = self.nodes[PRUNED].getblockhash(FLOOR)
        self.stop(PRUNED)
        d = self.blocksdir()
        holder = [f for f in sorted(os.listdir(d)) if f.startswith('blk') and f.endswith('.dat')
                  and floor_hash in block_hashes_in_file(os.path.join(d, f))]
        assert_equal(len(holder), 1)
        os.remove(os.path.join(d, 'rev' + holder[0][3:]))
        assert_start_raises_init_error(PRUNED, self.options.tmpdir, self.node_args(PRUNED),
                                       'The block or undo data of block %d is missing, but this pruned node must keep every '
                                       'block from height %d' % (FLOOR, FLOOR))
        if PRUNED in bitcoind_processes:
            del bitcoind_processes[PRUNED]
        print('its blk file removed too: the stock blk-file check refuses the start')
        os.remove(os.path.join(d, holder[0]))
        assert_start_raises_init_error(PRUNED, self.options.tmpdir, self.node_args(PRUNED), 'restart with -reindex')
        if PRUNED in bitcoind_processes:
            del bitcoind_processes[PRUNED]

        print('-reindex re-downloads from the archive node')
        self.start(PRUNED, ['-reindex'])
        self.settle()
        assert_equal(self.hashes(PRUNED), expected)
        self.stop(PRUNED)
        self.start(PRUNED)
        self.settle()
        assert_equal(self.hashes(PRUNED), expected)
        self.check_floor()

    def check_floor(self):
        pruned = self.nodes[PRUNED]
        tip = pruned.getblockcount()
        assert not os.path.exists(os.path.join(self.blocksdir(), 'blk00000.dat'))
        info = pruned.getblockchaininfo()
        assert_equal(info['pruned'], True)
        assert 0 < info['pruneheight'] <= FLOOR, info['pruneheight']
        try:
            pruned.getblock(pruned.getblockhash(1))
        except JSONRPCException as e:
            assert 'pruned data' in e.error['message'], e.error
        else:
            raise AssertionError('block 1 is still on disk')
        for h in range(FLOOR, tip + 1):
            pruned.getblock(pruned.getblockhash(h))


if __name__ == '__main__':
    VaultPruneFloorTest().main()
