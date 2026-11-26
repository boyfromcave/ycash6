#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Fields outside the txid never decide a verdict on a transaction or a block (doc/yugen-node.md N-D8).

A Yugen transaction's kind (leaf or bundle) is read from its transfer bytes, which the txid
commits to; its proof fields and a block's proof sidecar are not covered by the txid or the block
hash, so a relay can change them. Each case below gives a victim node the altered copy first and the
honest one second; the honest one must be taken.

TEST-ONLY PROOFS for the bundle (-yugenteststubproofs, as yugen_bundle.py); the leaf is a real
deposit made by the Yugen wallet engine (YEWD_YUGEN) with both wallet proofs.

- sidecar before activation: bytes appended to a pre-Yugen block are ignored, as upstream ignores
  trailing bytes: the block is taken and re-served without them;
- leaf, mempool: the leaf with both proofs emptied, sent over P2P, does not keep the honest leaf
  (same txid and wtxid) out of the mempool (a guard: a mempool refusal is already corruption-possible
  on this line, so the N-D7 gate kept it out of recentRejects before N-D8 too);
- leaf, block: the block with that leaf's proofs emptied is refused without marking the block
  invalid; the honest block is then connected;
- bundle, mempool: the bundle with a proof byte added inline does not enter recentRejects (the node
  still asks for the txid; a guard, as for the leaf);
- bundle, block: the block whose bundle has a proof byte added inline is refused without marking
  it invalid; the honest block is then connected;
- bundle, block, review H-1: the block whose sidecar proof B is swapped for 900 KB of junk (above a
  leaf's LEAF_PROOF_MAX_B) is refused without marking it invalid; the honest block is then connected;
- sidecar, review C-2: a block with no bundle and a junk sidecar entry, then the honest copy: the
  honest block is taken, and the node never serves the junk with it;
- mempool, review M-3: a leaf whose proof fails only because the node's anchor block differs (a
  node on another chain) costs its relaying peer nothing (DoS 0).
"""

import json
import os
import subprocess
import tempfile
import time

from test_framework.authproxy import JSONRPCException
from test_framework.mininode import CInv, NetworkThread, NodeConn, msg_inv, mininode_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port, rpc_auth_pair, rpc_port, start_nodes
from tx_expiry_helper import TestNode
from yugen_bundle import ARGS, WALLET, YugenBundleTest, bundle_tx

PROTO = 270200


class msg_rawtx(object):
    """A `tx` message carrying bytes as given (the framework cannot parse the Yugen group)."""
    command = b"tx"

    def __init__(self, raw):
        self.raw = raw

    def serialize(self):
        return self.raw

    def __repr__(self):
        return "msg_rawtx(%d bytes)" % len(self.raw)


class Probe(TestNode):
    def __init__(self):
        super().__init__()
        self.getdata = []

    def on_getdata(self, conn, message):
        self.getdata.extend(message.inv)


def compact_read(b, o):
    c = b[o]
    if c < 253:
        return c, o + 1
    k = {253: 2, 254: 4, 255: 8}[c]
    return int.from_bytes(b[o + 1:o + 1 + k], 'little'), o + 1 + k


def strip_leaf_proofs(txhex):
    """The Yugen leaf with both proof fields emptied (v4 layout, no Sapling or Sprout parts)."""
    b = bytes.fromhex(txhex)
    o = 8                                   # header, version group
    n, o = compact_read(b, o)
    for _ in range(n):                      # vin
        o += 36
        k, o = compact_read(b, o)
        o += k + 4
    n, o = compact_read(b, o)
    for _ in range(n):                      # vout
        o += 8
        k, o = compact_read(b, o)
        o += k
    o += 4 + 4 + 8                          # lock time, expiry, Sapling value balance
    for _ in range(3):                      # spends, outputs, joinsplits: all empty
        n, o = compact_read(b, o)
        assert n == 0
    k, o = compact_read(b, o)               # transfer
    o += k
    pa = o
    k, o = compact_read(b, o)
    assert k > 0
    o += k
    k, o = compact_read(b, o)
    assert k > 0
    o += k
    assert o == len(b)
    return (b[:pa] + b'\x00\x00').hex()


def leaf_anchor(txhex):
    """The anchor height of a wallet engine leaf: nExpiryHeight - ANCHOR_WINDOW (doc/yugen-node.md N-D9)."""
    b = bytes.fromhex(txhex)
    o = 8
    n, o = compact_read(b, o)
    for _ in range(n):
        o += 36
        k, o = compact_read(b, o)
        o += k + 4
    n, o = compact_read(b, o)
    for _ in range(n):
        o += 8
        k, o = compact_read(b, o)
        o += k
    return int.from_bytes(b[o + 4:o + 8], 'little') - 96


def compact(n):
    return bytes([n]) if n < 253 else b'\xfd' + n.to_bytes(2, 'little') if n < 0x10000 else b'\xfe' + n.to_bytes(4, 'little')


def replace_once(hay, old, new):
    assert_equal(hay.count(old), 1)
    return hay.replace(old, new)


class YugenStripTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 5
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        # No node links: node 0 builds the chain, nodes 1 to 4 are fed by hand (node 4 forks).
        self.nodes = start_nodes(5, self.options.tmpdir, [ARGS] * 5)
        self.is_network_split = False

    helper = YugenBundleTest.helper
    make = YugenBundleTest.make

    def wallet(self, *args):
        u, p = rpc_auth_pair(0)
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

    def feed(self, node, upto):
        n0 = self.nodes[0]
        for h in range(node.getblockcount() + 1, upto + 1):
            r = node.submitblock(n0.getblock(n0.getblockhash(h), 0))
            assert r in (None, 'duplicate'), (h, r)
        assert_equal(node.getblockhash(upto), n0.getblockhash(upto))

    def check(self, name, ok, detail=''):
        print('    %s %s %s' % ('ok  ' if ok else 'FAIL', name, detail))
        self.results.append((name, ok))

    def bad_then_good(self, node, bad, good, blockhash):
        r1 = node.submitblock(bad)
        r2 = node.submitblock(good)
        return node.getbestblockhash() == blockhash, 'altered: %r, honest: %r' % (r1, r2)

    def wait(self, cond, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if cond():
                return True
            time.sleep(0.2)
        return False

    def run_test(self):
        n0, n1, n2, n3, n4 = self.nodes
        self.results = []
        self.wdir = tempfile.mkdtemp(prefix='yewd-yugen-', dir=self.options.tmpdir)
        self.reg = self.helper('regroot')

        # 1. A proof sidecar before activation (height 20 < 32).
        n0.generate(20)
        self.feed(n1, 19)
        good = n0.getblock(n0.getblockhash(20), 0)
        sidecar = '01' + '11' * 32 + '02' + '01aa' + '01bb'
        r = n1.submitblock(good + sidecar)
        ok = r is None and n1.getbestblockhash() == n0.getblockhash(20) and n1.getblock(n0.getblockhash(20), 0) == good
        self.check('sidecar bytes before activation ignored, block re-served without them', ok, 'submitblock: %r' % r)
        try:
            r = n1.submitblock(n0.getblock(n0.getblockhash(19), 0) + 'ff')   # not even a sidecar: still ignored
        except JSONRPCException as e:
            r = e.error['message']
        self.check('trailing bytes before activation ignored', r == 'duplicate', 'submitblock: %r' % r)

        # 2. One real deposit: a leaf with both wallet proofs, in node 0's pool.
        n0.generate(120)
        # the wallet learns of blocks asynchronously (no peer sync here to wait on)
        assert self.wait(lambda: n0.getbalance() > 5, timeout=60)
        dep = self.wallet('depositaddress')
        dep = dep if isinstance(dep, str) else dep['address']
        fund = n0.sendtoaddress(dep, 5)
        n0.generate(1)
        r = self.wallet('shield', json.dumps([fund]))
        leaf = r if isinstance(r, str) else r['txid']
        leafhex = n0.getrawtransaction(leaf)
        stripped = strip_leaf_proofs(leafhex)
        top = n0.getblockcount()
        for node in (n1, n2, n3):
            self.feed(node, top)
        # Node 4 (review M-3) leaves node 0's chain at the leaf's anchor block: the same pool state
        # (no Yugen output yet), another anchor block hash, so the leaf's proofs cannot verify there.
        ha = leaf_anchor(leafhex)
        self.feed(n4, ha - 1)
        n4.generate(top - ha)                       # its own blocks from ha; the funding tx is final above its lock time
        n4.sendrawtransaction(n0.getrawtransaction(fund))
        n4.generate(1)
        assert_equal(n4.getblockcount(), top)
        assert n4.getblockhash(ha) != n0.getblockhash(ha)
        assert fund in n4.getblock(n4.getbestblockhash())['tx']

        # 3. Mempool, leaf: the stripped copy over P2P, then the honest one from another peer.
        probes = [Probe() for _ in range(4)]
        for p in probes:
            p.add_connection(NodeConn('127.0.0.1', p2p_port(2), n2, p, 'regtest', PROTO))
        fork_probe = Probe()
        fork_probe.add_connection(NodeConn('127.0.0.1', p2p_port(4), n4, fork_probe, 'regtest', PROTO))
        probes_all = probes + [fork_probe]
        NetworkThread().start()
        for p in probes_all:
            p.wait_for_verack()
        probes[0].send_message(msg_rawtx(bytes.fromhex(stripped)))
        probes[1].sync_with_ping()
        probes[1].send_message(msg_rawtx(bytes.fromhex(leafhex)))
        ok = self.wait(lambda: leaf in n2.getrawmempool(), timeout=120)
        self.check('mempool: stripped leaf does not keep the honest leaf out', ok)

        # Review M-3: the honest leaf on node 4's fork fails its proof only for the node's anchor block.
        fork_probe.send_message(msg_rawtx(bytes.fromhex(leafhex)))
        try:
            fork_probe.sync_with_ping(timeout=120)   # the tx is judged before the ping is answered
        except BaseException:
            pass                                     # disconnected: banned
        time.sleep(1)
        peers = n4.getpeerinfo()
        ok = leaf not in n4.getrawmempool() and len(peers) == 1 and peers[0].get('banscore', 0) == 0
        self.check('mempool: a proof failing for the node\'s own anchor costs the peer nothing', ok, repr(
            [(p.get('addr'), p.get('banscore')) for p in peers]))

        # 4. Block, leaf: the block with the stripped leaf, then the honest block.
        blk_a = n0.generate(1)[0]
        assert leaf in n0.getblock(blk_a)['tx']
        good = n0.getblock(blk_a, 0)
        ok, detail = self.bad_then_good(n1, replace_once(good, leafhex, stripped), good, blk_a)
        self.check('block: stripped leaf does not invalidate the honest block', ok, detail)
        for node in (n2, n3):
            self.feed(node, n0.getblockcount())

        # 5. A stub bundle (the deposit funds its fees), mined by node 0.
        payee = n0.validateaddress(n0.getnewaddress())['scriptPubKey']
        b, pa, pb = self.make(n0, 3, 7, payee)
        txhex = bundle_tx(b)
        txid = n0.submitbundle({'tx': txhex, 'proofs': [pa, pb]})['txid']
        padded = txhex[:-4] + '01ab00'      # proof A = one byte inline, proof B empty

        # Mempool, bundle: the padded copy over P2P, then an announcement of the txid from another peer.
        probes[2].send_message(msg_rawtx(bytes.fromhex(padded)))
        probes[3].sync_with_ping()
        with mininode_lock:
            probes[3].getdata = []
        probes[3].send_message(msg_inv([CInv(1, int(txid, 16))]))
        asked = self.wait(lambda: any(i.hash == int(txid, 16) for i in probes[3].getdata), timeout=20)
        self.check('mempool: padded bundle is not in recentRejects', asked)

        # 6. Block, bundle: the block with the padded bundle, then the honest block (sidecar included).
        blk_b = n0.generate(1)[0]
        assert txid in n0.getblock(blk_b)['tx']
        good = n0.getblock(blk_b, 0)
        ok, detail = self.bad_then_good(n3, replace_once(good, txhex, padded), good, blk_b)
        self.check('block: padded bundle does not invalidate the honest block', ok, detail)

        # 7. Review H-1: the same block with proof B swapped for 900 KB of junk in its sidecar.
        self.feed(n1, n0.getblockcount() - 1)
        junk = 'ee' * 900000
        swapped = replace_once(good, compact(len(pb) // 2).hex() + pb, compact(len(junk) // 2).hex() + junk)
        ok, detail = self.bad_then_good(n1, swapped, good, blk_b)
        self.check('block: a swapped proof B does not invalidate the honest block', ok, detail)

        # 8. Review C-2 (node 2): a block with no bundle, a junk sidecar entry, then the honest copy.
        blk_c = n0.generate(1)[0]
        good = n0.getblock(blk_c, 0)
        assert_equal(len(n0.getblock(blk_c)['tx']), 1)   # the coinbase only: no bundle
        self.feed(n2, n0.getblockcount() - 1)
        ok, detail = self.bad_then_good(n2, good + sidecar, good, blk_c)
        served = n2.getblock(blk_c, 0)
        self.check('sidecar: a junk entry is dropped and never served with the honest block',
                   ok and served == good, detail + ' served %d extra bytes' % ((len(served) - len(good)) // 2))

        failed = [n for n, ok in self.results if not ok]
        assert not failed, 'failed: %s' % failed


if __name__ == '__main__':
    YugenStripTest().main()
