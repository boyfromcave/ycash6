#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A Yugen bundle supersedes the pool leaf transfers it carries (lead decision (a); mempool policy,
no consensus change).

TEST-ONLY bundle proofs (-yugenteststubproofs, as yugen_bundle.py); the leaf is a real private
send by the Yugen wallet engine (yewd-yugen, YEWD_YUGEN) with both wallet proofs.

- a bundle carrying a different spend of the leaf's nullifiers (one commitment byte changed) is
  refused: bad-yugen-nullifier-in-mempool;
- a bundle carrying the leaf (plus one random transfer) is accepted by submitbundle; the leaf
  leaves the mempool, node 1 drops it too, and the next block holds the bundle, not the leaf;
- the wallet sees its transfer confirmed: nothing pending afterwards.
"""

import json
import os
import struct
import subprocess
import tempfile

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal, connect_nodes_bi, rpc_auth_pair, rpc_port, start_nodes, sync_blocks, sync_mempools,
)
from yugen_bundle import ARGS, HELPER, WALLET, YUGEN_BRANCH_ID, ACT, bundle_tx


def read_compact(b, o):
    n = b[o]
    if n < 253:
        return n, o + 1
    k = {253: 2, 254: 4, 255: 8}[n]
    return int.from_bytes(b[o + 1:o + 1 + k], 'little'), o + 1 + k


def leaf_transfer(raw):
    """The transfer bytes of a leaf transaction with no transparent or shielded parts."""
    b = bytes.fromhex(raw)
    o = 8
    nin, o = read_compact(b, o)
    nout, o = read_compact(b, o)
    assert (nin, nout) == (0, 0), 'leaf with transparent parts'
    o += 4 + 4 + 8
    assert b[o:o + 3] == b'\x00\x00\x00', 'leaf with shielded parts'
    n, o = read_compact(b, o + 3)
    return b[o:o + n]


class YugenBundleSupersedeTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir, [ARGS, ARGS])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False

    def helper(self, *args):
        out = subprocess.run([HELPER] + list(args), capture_output=True, text=True, timeout=600)
        assert out.returncode == 0, out.stdout + out.stderr
        return out.stdout.strip()

    def wallet(self, *args):
        u, p = rpc_auth_pair(0)
        # the engine takes the seed only on an inherited descriptor (N-A5): hex and a newline on fd 3
        r, w = os.pipe()
        os.write(w, ('44' * 32 + '\n').encode())
        os.close(w)
        try:
            out = subprocess.run([WALLET, '-network=regtest', '-node=127.0.0.1:%d' % rpc_port(0), '-rpcuser=' + u,
                                  '-rpcpassword=' + p, '-datadir=' + self.wdir, '-seedfd=3'] + list(args),
                                 capture_output=True, text=True, timeout=1800, pass_fds=(3,),
                                 preexec_fn=lambda: os.dup2(r, 3))
        finally:
            os.close(r)
        assert out.returncode == 0, (args[:1], out.stdout, out.stderr[-2000:])
        return json.loads(out.stdout)

    def make(self, node, n, seed, slot, transfers):
        h = node.getblockcount() + 1
        ha = (h - 1) // 16 * 16
        while (ha // 16) & 0xff != slot:
            ha -= 16
        a = node.yugen_getanchor(ha)
        req = {'anchor': {'slot': slot, 'anchor_root': a['root'], 'reg_root': self.reg, 'block_hash': a['block_hash']},
               'n': n, 'seed': seed, 'payee': '', 'branch_id': YUGEN_BRANCH_ID, 'network': 2,
               'height': h, 'activation': ACT, 'transfers': [t.hex() for t in transfers]}
        path = os.path.join(self.options.tmpdir, 'tb.json')
        with open(path, 'w') as f:
            json.dump(req, f)
        b, pa, pb = self.helper('testbundle', path).split()
        return bundle_tx(bytes.fromhex(b)), [pa, pb]

    def run_test(self):
        n0, n1 = self.nodes
        self.reg = self.helper('regroot')
        self.wdir = tempfile.mkdtemp(prefix='yewd-yugen-', dir=self.options.tmpdir)
        n0.generate(140)
        # the wallet learns of blocks on its notification thread: wait for it before spending
        sync_blocks([n0, n1])
        dep = self.wallet('depositaddress')
        dep = dep if isinstance(dep, str) else dep['address']
        fund = n0.sendtoaddress(dep, 5)
        n0.generate(1)
        self.wallet('shield', json.dumps([fund]))
        n0.generate(20)
        sync_blocks([n0, n1])
        to = self.wallet('newaddress')
        to = to if isinstance(to, str) else to['address']
        sent = self.wallet('send', json.dumps([to, 1.0]))
        leaf = sent if isinstance(sent, str) else sent['txid']
        sync_mempools([n0, n1])
        assert leaf in n0.getrawmempool() and leaf in n1.getrawmempool()
        print('wallet before:', self.wallet('getbalances'))
        t = leaf_transfer(n0.getrawtransaction(leaf))

        # A different spend of the same nullifiers: refused as before.
        other = bytearray(t)
        other[4 + 64 + 5] ^= 1   # a commitment byte
        txhex, proofs = self.make(n0, 1, 7, t[1], [bytes(other)])
        try:
            n0.submitbundle({'tx': txhex, 'proofs': proofs})
            raise AssertionError('accepted a different spend')
        except JSONRPCException as e:
            assert 'bad-yugen-nullifier-in-mempool' in e.error['message'], e.error['message']
        assert leaf in n0.getrawmempool()

        # The bundle carrying the leaf supersedes it.
        txhex, proofs = self.make(n0, 1, 8, t[1], [t])
        r = n0.submitbundle({'tx': txhex, 'proofs': proofs})
        assert_equal(r['transfers'], 2)
        assert r['accepted']
        # The identical bundle again (a retry): accepted, same txid; the different spend still refused.
        assert_equal(n0.submitbundle({'tx': txhex, 'proofs': proofs}), r)
        bad, badp = self.make(n0, 1, 7, t[1], [bytes(other)])
        try:
            n0.submitbundle({'tx': bad, 'proofs': badp})
            raise AssertionError('accepted a conflicting bundle')
        except JSONRPCException as e:
            assert 'bad-yugen-nullifier-in-mempool' in e.error['message'], e.error['message']
        mp = n0.getrawmempool()
        assert r['txid'] in mp and leaf not in mp, mp
        tip = n0.generate(1)[0]
        sync_blocks([n0, n1])
        blk = n0.getblock(tip)
        assert r['txid'] in blk['tx'] and leaf not in blk['tx'], blk['tx']
        assert leaf not in n1.getrawmempool()
        d = n0.yugen_getblockdata(blk['height'])
        assert_equal(d['bundles'][0]['applied'], 2)
        # The wallet finds its transfer in the bundle: the notes become spendable as after a leaf.
        n0.generate(20)
        print('wallet getbalance:', self.wallet('getbalance'))
        bal = self.wallet('getbalances')
        print('wallet after:', bal)
        assert_equal(bal['outgoing_pending'], 0)
        assert_equal(bal['pending'], 0)
        assert bal['spendable'] > 4.99, bal

if __name__ == '__main__':
    YugenBundleSupersedeTest().main()
