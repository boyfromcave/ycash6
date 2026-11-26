#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A Yugen leaf transfer end to end on regtest (doc/yugen-node.md N-D3; spec 0.5.1 §7.9).

The transfer is a deposit made by the Yugen wallet engine (yewd-yugen, yew yugen/wallet;
YEWD_YUGEN), with both wallet proofs, against this chain's anchor. Node 0 and node 1 run Yugen at
32; node 2 has Vault but no Yugen height.

- accepted by node 0 (both proofs verified by the helper), relayed to node 1, mined, applied:
  both nodes report the same root, tree size 3 and the transfer in yugen_getblockdata;
- the same transaction is refused before activation (node 2): bad-yugen-tx-before-activation;
- a copy with one byte of proof B flipped is refused: bad-yugen-proof;
- the mined transfer resubmitted is refused: bad-yugen-nullifier-spent.
"""

import json
import os
import subprocess
import tempfile

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, rpc_auth_pair, rpc_port,
    start_nodes, sync_blocks, sync_mempools,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework.yugen_util import yugen_helper

YUGEN_BRANCH_ID = 0x59474E30
HERE = os.path.dirname(os.path.abspath(__file__))
VERIFIER = '-yugenverifier=' + yugen_helper('YUGEN_LEAFVERIFY', 'yugen-leafverify')
WALLET = yugen_helper('YEWD_YUGEN', 'yewd-yugen')
BASE = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, 16), VERIFIER, '-debug=yugen']


class YugenLeafTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        yugen = BASE + [nuparams(YUGEN_BRANCH_ID, 32)]
        # Node 3 has Yugen and no peers: the tampered proof is checked where the nullifier is fresh.
        self.nodes = start_nodes(4, self.options.tmpdir, [yugen, yugen, BASE, yugen])
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

    def refused(self, node, txhex, reason):
        try:
            node.sendrawtransaction(txhex)
        except JSONRPCException as e:
            assert reason in e.error['message'], e.error['message']
            return
        raise AssertionError('accepted: expected ' + reason)

    def run_test(self):
        n0, n1, n2, n3 = self.nodes
        self.wdir = tempfile.mkdtemp(prefix='yewd-yugen-', dir=self.options.tmpdir)
        n0.generate(140)
        n2.generate(140)
        sync_blocks([n0, n1])

        dep = self.wallet('depositaddress')
        dep = dep if isinstance(dep, str) else dep['address']
        fund = n0.sendtoaddress(dep, 5)
        n0.generate(1)
        sync_blocks([n0, n1])
        # Node 3 (no peers) gets node 0's chain, funding included: the proofs are checked after the
        # inputs (review M-1), so the tampered copy needs its input there.
        for hh in range(1, n0.getblockcount() + 1):
            n3.submitblock(n0.getblock(n0.getblockhash(hh), 0))
        assert_equal(n3.getbestblockhash(), n0.getbestblockhash())

        shielded = self.wallet('shield', json.dumps([fund]))
        txid = shielded if isinstance(shielded, str) else shielded['txid']
        sync_mempools([n0, n1])
        assert txid in n1.getrawmempool()
        txhex = n0.getrawtransaction(txid)

        # Before activation (node 2 has no Yugen height).
        self.refused(n2, txhex, 'bad-yugen-tx-before-activation')
        # One byte of proof B flipped (the last byte of the transaction is proof B's).
        tampered = txhex[:-2] + '%02x' % (int(txhex[-2:], 16) ^ 1)
        self.refused(n3, tampered, 'bad-yugen-proof')

        tip = n0.generate(1)[0]
        sync_blocks([n0, n1])
        h = n0.getblockcount()
        assert txid in n0.getblock(tip)['tx']
        d0, d1 = n0.yugen_getblockdata(h), n1.yugen_getblockdata(h)
        assert_equal(d0, d1)
        assert_equal([t['txid'] for t in d0['transfers']], [txid])
        assert_equal(n0.yugen_getinfo()['tree_size'], 3)
        assert_equal(n0.yugen_getinfo()['root'], n1.yugen_getinfo()['root'])
        nf1 = d0['transfers'][0]['transfer'][8:72]
        assert_equal(n0.gettransferstatus(nf1), {'state': 'mined', 'height': h})

        # Spent nullifiers.
        self.refused(n0, txhex, 'bad-yugen-nullifier-spent')

        # Restart rebuilds the same state from blocks.
        root = n0.yugen_getinfo()['root']
        self.stop_nodes_and_restart_0()
        assert_equal(self.nodes[0].yugen_getinfo()['root'], root)

    def stop_nodes_and_restart_0(self):
        from test_framework.util import stop_node, start_node
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir, BASE + [nuparams(YUGEN_BRANCH_ID, 32)])


if __name__ == '__main__':
    YugenLeafTest().main()
