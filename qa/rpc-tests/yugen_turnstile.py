#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The Yugen turnstile and the persistent pool state on regtest (spec 0.5.2 §7.9 rule 4, §13.3.2;
review H-3, M-3).

A deposit and a withdrawal made by the Yugen wallet engine (yewd-yugen, YEWD_YUGEN). After each
block the pool balance B (yugen_getinfo, getblockchaininfo and getblock valuePools "yugen") is
checked on both nodes against the transfers: a deposit of v adds v - fee, a withdrawal of v takes
v + fee, so with one wallet B equals the wallet's Yugen balance. Then:

- reorganisation: invalidateblock on the withdrawal block restores B from the undo record,
  reconsiderblock applies it again;
- restart: the state is loaded from <datadir>/regtest/yugen/state.dat with no replay;
- without the file: the state is replayed from blocks to the same B and root.
"""

import json
import os
import subprocess
import tempfile
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, rpc_auth_pair, rpc_port,
    start_node, start_nodes, stop_node, sync_blocks, sync_mempools,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework.yugen_util import yugen_helper

YUGEN_BRANCH_ID = 0x59474E30
HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = '-yugenverifier=' + yugen_helper('YUGEN_LEAFVERIFY', 'yugen-leafverify')
WALLET = yugen_helper('YEWD_YUGEN', 'yewd-yugen')
ARGS = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, 16), nuparams(YUGEN_BRANCH_ID, 32), VERIFIER,
                                   '-debug=yugen']
YUGEN_FEE = 100000 + 155600          # BASE_FEE + LEAF_PROOF_FEE (spec 0.5.2 §2)
ANCHOR_GRID, ANCHOR_MIN_DEPTH = 16, 3


def zat(x):
    return int((Decimal(x) * 100000000).to_integral_value())


class YugenTurnstileTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir, [ARGS] * 2)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False

    def wallet(self, *args):
        u, p = rpc_auth_pair(0)
        cmd = [WALLET, '-network=regtest', '-node=127.0.0.1:%d' % rpc_port(0), '-rpcuser=' + u, '-rpcpassword=' + p,
               '-datadir=' + self.wdir, '-seedfd=3'] + list(args)
        # the engine takes the seed only on an inherited descriptor (N-A5): hex and a newline on fd 3
        r, w = os.pipe()
        os.write(w, ('11' * 32 + '\n').encode())
        os.close(w)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, pass_fds=(3,),
                                 preexec_fn=lambda: os.dup2(r, 3))
        finally:
            os.close(r)
        assert out.returncode == 0, (cmd[-2:], out.stdout, out.stderr[-2000:])
        return json.loads(out.stdout)

    def mine(self, n=1):
        sync_mempools(self.nodes)
        b = self.nodes[0].generate(n)
        sync_blocks(self.nodes)
        return b

    def pool(self, node, h=None):
        if h is None:
            pools = node.getblockchaininfo()['valuePools']
        else:
            pools = node.getblock(node.getblockhash(h))['valuePools']
        y = [p for p in pools if p['id'] == 'yugen']
        assert_equal(len(y), 1)
        assert_equal(pools[-1]['id'], 'yugen')       # appended after the existing pools
        assert_equal([p['id'] for p in pools][:4], ['transparent', 'sprout', 'sapling', 'orchard'])
        return y[0]

    def check(self, want, delta=None):
        """B on both nodes, by every RPC, after the tip block (whose pool delta is `delta`)."""
        for n in self.nodes:
            assert_equal(n.yugen_getinfo()['pool_balance_zat'], want)
            p = self.pool(n)
            assert p['monitored']
            assert_equal(p['chainValueZat'], want)
            b = self.pool(n, n.getblockcount())
            assert_equal(b['chainValueZat'], want)
            if delta is not None:
                assert_equal(b['valueDeltaZat'], delta)
            d = n.yugen_getblockdata(n.getblockcount())
            assert_equal(d['pool_balance_after_zat'], want)

    def ybalance(self):
        return zat(str(self.wallet('getbalance')))

    def run_test(self):
        n0, n1 = self.nodes
        self.wdir = tempfile.mkdtemp(prefix='yewd-yugen-', dir=self.options.tmpdir)
        self.mine(140)
        self.check(0, 0)

        # Deposit.
        dep = self.wallet('depositaddress')
        dep = dep if isinstance(dep, str) else dep['address']
        fund = n0.sendtoaddress(dep, 5)
        self.mine(1)
        self.check(0, 0)
        sh = self.wallet('shield', json.dumps([fund]))
        sh = sh if isinstance(sh, str) else sh['txid']
        hd = self.mine(1)[0]
        assert sh in n0.getblock(hd)['tx']
        b1 = zat(5) - YUGEN_FEE
        self.check(b1, b1)
        hdep = n0.getblockcount()
        while (n0.getblockcount() - ANCHOR_MIN_DEPTH) // ANCHOR_GRID * ANCHOR_GRID <= hdep:
            self.mine(1)
            self.check(b1, 0)
        assert_equal(self.ybalance(), b1)

        # Withdrawal.
        to = n0.getnewaddress()
        r = self.wallet('withdraw', json.dumps([to, 2.0]))
        wd = r if isinstance(r, str) else r['txid']
        hw = self.mine(1)[0]
        assert wd in n0.getblock(hw)['tx']
        b2 = b1 - zat(2) - YUGEN_FEE
        self.check(b2, -(zat(2) + YUGEN_FEE))
        root = n0.yugen_getinfo()['root']

        # Reorganisation: the undo record restores B; the withdrawal returns to the mempool.
        for n in self.nodes:
            n.invalidateblock(hw)
            assert_equal(n.yugen_getinfo()['pool_balance_zat'], b1)
            assert_equal(self.pool(n)['chainValueZat'], b1)
        assert wd in n0.getrawmempool()
        for n in self.nodes:
            n.reconsiderblock(hw)
        sync_blocks(self.nodes)
        self.check(b2, -(zat(2) + YUGEN_FEE))
        assert_equal(n0.yugen_getinfo()['root'], root)

        # A competing branch from node 1: it drops the withdrawal block and mines the withdrawal again
        # in a longer branch; node 0 disconnects the block (undo record) and connects the branch.
        n1.invalidateblock(hw)
        assert_equal(n1.yugen_getinfo()['pool_balance_zat'], b1)
        assert wd in n1.getrawmempool()
        new = n1.generate(2)
        sync_blocks(self.nodes)
        assert_equal(n0.getbestblockhash(), new[-1])
        assert wd in n0.getblock(new[0])['tx']
        self.check(b2, 0)
        tip = n0.getblockcount()

        # Restart: loaded from the state file, no replay.
        stop_node(n0, 0)
        log = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'debug.log')
        with open(log) as f:
            f.seek(0, 2)
            mark = f.tell()
        self.nodes[0] = n0 = start_node(0, self.options.tmpdir, ARGS)
        connect_nodes_bi(self.nodes, 0, 1)
        self.check(b2)
        assert_equal(n0.yugen_getinfo()['root'], root)
        with open(log) as f:
            f.seek(mark)
            text = f.read()
        assert 'yugen: state loaded at height %d' % tip in text, text[-3000:]
        assert 'yugen: replaying' not in text

        # One more block after the restart moves B by nothing and is saved too.
        self.mine(1)
        self.check(b2, 0)

        # Without the file: replayed from blocks to the same state.
        stop_node(n0, 0)
        os.remove(os.path.join(self.options.tmpdir, 'node0', 'regtest', 'yugen', 'state.dat'))
        with open(log) as f:
            f.seek(0, 2)
            mark = f.tell()
        self.nodes[0] = n0 = start_node(0, self.options.tmpdir, ARGS)
        connect_nodes_bi(self.nodes, 0, 1)
        self.check(b2, 0)
        assert_equal(n0.yugen_getinfo()['root'], root)
        with open(log) as f:
            f.seek(mark)
            assert 'yugen: replaying blocks 32 to' in f.read()


if __name__ == '__main__':
    YugenTurnstileTest().main()
