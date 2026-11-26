#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Inventory announces a parent before its child (Yugen -> Sapling relay defect).

A Yugen withdrawal carries ~0.7 MB of leaf proofs, so its feerate is below that of the Sapling
send that spends its transparent output while it is unconfirmed. Announcing by feerate alone sent
the child first; the peer, missing the parent, cannot park a shielded transaction as an orphan,
put it in recentRejects and never fetched it again (until the next block). The fix orders each
trickle by in-mempool ancestor count, then feerate, for Yugen transactions and their in-pool
descendants only (CTxMemPool::YugenRelayDepth; doc/yugen-node.md, review item 6): every other
transaction keeps the stock order.

So the parent is a real Yugen withdrawal made by the wallet engine (yewd-yugen, YEWD_YUGEN; both
wallet proofs) on an isolated node 2, and the child the Sapling send that spends its output there,
as yewd's hop does. Both are handed to node 0 back to back (one trickle), and node 1 must receive
both. Repeated ROUNDS times, each from a freshly anchored note. (Until 2026-11-25 the parent was a
transparent transaction with its fee cut by prioritisetransaction; since review item 6 that chain
is not Yugen-related and is announced in the stock order, so that version failed by design.)

    ZCASHD=<ycashd> YUGEN_LEAFVERIFY=<helper> YEWD_YUGEN=<engine> \
        python3 -u qa/rpc-tests/relay_parent_first.py --tmpdir=<dir> --portseed=<n>
"""

import json
import os
import subprocess
import tempfile
import time
from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, rpc_auth_pair, rpc_port,
    start_nodes, wait_and_assert_operationid_status,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework.yugen_util import yugen_helper

ROUNDS = 2
HOP_FEE = Decimal('0.00001')   # yewd's SAPLING_HOP_FEE
YUGEN_BRANCH_ID = 0x59474E30
VERIFIER = '-yugenverifier=' + yugen_helper('YUGEN_LEAFVERIFY', 'yugen-leafverify')
WALLET = yugen_helper('YEWD_YUGEN', 'yewd-yugen')
ARGS = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, 16), nuparams(YUGEN_BRANCH_ID, 32), VERIFIER,
                                   '-allowdeprecated=getnewaddress', '-allowdeprecated=z_getnewaddress',
                                   '-allowdeprecated=z_getbalance', '-debug=mempool', '-debug=net', '-debug=yugen']
ANCHOR_GRID, ANCHOR_MIN_DEPTH = 16, 3


class RelayParentFirstTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [ARGS] * self.num_nodes)
        connect_nodes_bi(self.nodes, 0, 1)   # node 2 stays isolated: it only builds and mines
        self.is_network_split = False

    def wallet(self, *args):
        """The Yugen wallet engine against node 2; the seed on fd 3 (N-A5)."""
        u, p = rpc_auth_pair(2)
        cmd = [WALLET, '-network=regtest', '-node=127.0.0.1:%d' % rpc_port(2), '-rpcuser=' + u, '-rpcpassword=' + p,
               '-datadir=' + self.wdir, '-seedfd=3'] + list(args)
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
        """Node 2 mines; nodes 0 and 1 take its blocks (recentRejects clears with the tip)."""
        n0, n1, n2 = self.nodes
        hashes = n2.generate(n)
        for h in hashes:
            raw = n2.getblock(h, 0)
            n0.submitblock(raw)
            n1.submitblock(raw)
        assert_equal(n0.getbestblockhash(), hashes[-1])
        assert_equal(n1.getbestblockhash(), hashes[-1])
        return hashes

    def anchor_past(self, h):
        """Mine until a valid anchor height lies after height h (the note at h is spendable)."""
        n2 = self.nodes[2]
        while (n2.getblockcount() - ANCHOR_MIN_DEPTH) // ANCHOR_GRID * ANCHOR_GRID <= h:
            self.mine(1)

    def run_test(self):
        n0, n1, n2 = self.nodes
        self.wdir = tempfile.mkdtemp(prefix='yewd-yugen-', dir=self.options.tmpdir)
        self.mine(140)
        zaddr = n1.z_getnewaddress('sapling')

        # One deposit into the pool; each round withdraws from the anchored change.
        dep = self.wallet('depositaddress')
        dep = dep if isinstance(dep, str) else dep['address']
        fund = n2.sendtoaddress(dep, 10)
        self.mine(1)
        sh = self.wallet('shield', json.dumps([fund]))
        sh = sh if isinstance(sh, str) else sh['txid']
        assert sh in n2.getblock(self.mine(1)[0])['tx']
        self.anchor_past(n2.getblockcount())

        failures = []
        for r in range(ROUNDS):
            hop = n2.getnewaddress()
            w = self.wallet('withdraw', json.dumps([hop, 1.0]))
            ptxid = w if isinstance(w, str) else w['txid']
            assert ptxid in n2.getrawmempool()
            for _ in range(120):   # the wallet takes the parent from the mempool (as yewd waits)
                if Decimal(n2.z_getbalance(hop, 0)) >= 1:
                    break
                time.sleep(0.25)
            opid = n2.z_sendmany(hop, [{'address': zaddr, 'amount': Decimal(1) - HOP_FEE}], 0,
                                 HOP_FEE, 'AllowRevealedSenders')
            ctxid = wait_and_assert_operationid_status(n2, opid)
            phex = n2.getrawtransaction(ptxid)
            chex = n2.getrawtransaction(ctxid)
            pool = n2.getrawmempool(True)
            prate = pool[ptxid]['fee'] / pool[ptxid]['size']
            crate = pool[ctxid]['fee'] / pool[ctxid]['size']
            assert prate < crate, (prate, crate)   # the parent's feerate is below the child's

            # back to back: both wait in node 0's inventory queue for the same trickle
            assert_equal(n0.sendrawtransaction(phex), ptxid)
            assert_equal(n0.sendrawtransaction(chex), ctxid)

            deadline = time.time() + 60
            while time.time() < deadline and ctxid not in n1.getrawmempool():
                time.sleep(0.25)
            got = n1.getrawmempool()
            print('round %d: parent %s child %s' % (r, ptxid in got, ctxid in got))
            if ctxid not in got:
                failures.append(r)

            blk = self.mine(1)[0]
            assert ptxid in n2.getblock(blk)['tx'] and ctxid in n2.getblock(blk)['tx']
            self.anchor_past(n2.getblockcount())
        assert_equal(failures, [])
        print('relay_parent_first OK (%d rounds)' % ROUNDS)


if __name__ == '__main__':
    RelayParentFirstTest().main()
