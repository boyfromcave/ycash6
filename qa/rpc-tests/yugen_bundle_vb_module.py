#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
N-D12 on regtest: a bundle's deposit of a coin the YED module tracks is an S2 skip, decided from the module's
state after the parent, and only a node whose module can answer decides it (doc/yugen-node.md N-D12).

TEST-ONLY PROOFS, as yugen_bundle_vb.py. Node 0 runs the YED module (an attestor set), node 1 does not (its
module is inert: on regtest the set is a node parameter, 01/V-7; on a public network it is a chain parameter).

- YED goes live on node 0; a token is minted to a P2PKH holder key of node 0's wallet.
- A bundle deposits the token coin with a BROKEN signature, beside a withdrawal. A node whose module tracks
  the coin skips the deposit and never verifies it (§15.5), so the block carrying the bundle is valid there.
  The block is assembled here: node 1 mines the same bundle with a good signature (its module tracks nothing),
  then the bundle is swapped for the broken one, the coinbase gives up the skipped transfer's fee, and the
  header is solved again.
- Node 0's index made unhealthy (-yellowbacktestfault=storage:mempool; the node runs on): the block arrives
  and node 0 stops with a node failure. The module could not answer, so the block is not marked invalid
  (before the fix the deposit was applied and failed the block: BLOCK_FAILED_VALID, for good).
- Restarted, node 0 connects the block (the deposit skipped, the token coin unspent), and `verifychain 4`
  re-connects it with the recorded skip (before the fix it re-decided the skip and reported the block
  unconnectable).

    BITCOIND=<ycashd> ../.venv/bin/python -u qa/rpc-tests/yugen_bundle_vb_module.py --srcdir=<src> --tmpdir=<dir>
"""

import hashlib
import struct
import tempfile
import time
from io import BytesIO

from hashlib import blake2b

from test_framework.equihash import gbp_basic, gbp_validate, hash_nonce, zcash_person
from test_framework.mininode import CBlockHeader, uint256_from_compact
from test_framework.util import (
    assert_equal, bitcoind_processes, connect_nodes_bi, start_node, start_nodes, stop_node, sync_blocks,
)
from test_framework.vault import ecdsa_sign_der
from test_framework.yellowback_model import base58check_decode
from test_framework.yellowback_util import (
    ACTIVATION_BLOCKS, ATTESTOR_SET_SPEC, REF_LAG, mint_to_fresh_holder, set_quote,
)

from yugen_bundle import ARGS, YUGEN_BRANCH_ID, bundle_tx, compact
from yugen_bundle_vb import FEE, YugenBundleVbTest, dep_sighash, push, vout


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def merkle_root(hashes):
    while len(hashes) > 1:
        if len(hashes) % 2:
            hashes.append(hashes[-1])
        hashes = [dsha(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
    return hashes[0]


def read_compact(b, i):
    n = b[i]
    if n < 253:
        return n, i + 1
    w = {253: 2, 254: 4, 255: 8}[n]
    return int.from_bytes(b[i + 1:i + 1 + w], 'little'), i + 1 + w


class YugenBundleVbModuleTest(YugenBundleVbTest):
    def setup_network(self, split=False):
        self.nodes = start_nodes(2, self.options.tmpdir, [ARGS, ARGS])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False

    def args0(self, extra=()):
        return list(ARGS) + self.yed_args + list(extra)

    def restart0(self, extra=(), connect=True, stderr=None):
        self.nodes[0] = start_node(0, self.options.tmpdir, self.args0(extra), stderr=stderr)
        if connect:
            connect_nodes_bi(self.nodes, 0, 1)

    def activate_yed_on_node0(self):
        """U-22 on node 0 only: the set created and mined, node 0 restarted with it, quoting and mining the
        activation run (node 1 follows the chain with an inert module)."""
        n0, n1 = self.nodes
        setid = n0.set_create(dict(ATTESTOR_SET_SPEC))['setid']
        self.sync_mempool_and_mine(n0)
        self.yed_args = ['-yellowbackattestorset=%s' % setid, '-yellowbacksigmaref=0',
                         '-yellowbackpayoutaddress=%s' % n0.getnewaddress()]
        stop_node(n0, 0)
        self.restart0()
        n0 = self.nodes[0]
        set_quote(n0, 50)
        for _ in range(ACTIVATION_BLOCKS + REF_LAG + 1):
            n0.generate(1)
        sync_blocks(self.nodes)
        assert_equal(n0.yed_getactivation()['status'], 'active')

    def sync_mempool_and_mine(self, node):
        time.sleep(1)
        node.generate(1)
        sync_blocks(self.nodes)

    def token_bundle(self, node, coin, payee, seed, break_sig):
        """A deposit of the whole token coin (no change) and a 1-YEC withdrawal to `payee`."""
        txid, n, script, secret, value = coin
        records = [{'vb': -value, 'vout': vout([]),
                    'vin': [{'txid': bytes.fromhex(txid)[::-1].hex(), 'index': n, 'script_sig': ''}]},
                   {'vb': 100000000, 'vout': vout([(100000000, payee)])}]
        _, _, _, hashes = self.make_vb(node, records, seed)
        d = dep_sighash(YUGEN_BRANCH_ID, 2, hashes[0], [(bytes.fromhex(txid)[::-1], n)], 0, value, script)
        sig = ecdsa_sign_der(secret, d) + b'\x01'
        if break_sig:
            sig = sig[:-2] + bytes([sig[-2] ^ 1]) + sig[-1:]
        records[0]['vin'][0]['script_sig'] = (push(sig) + push(self.pubkey(secret))).hex()
        b, pa, pb, _ = self.make_vb(node, records, seed)
        return bundle_tx(b), pa, pb

    def assemble(self, good_block_hex, good_tx, bad_tx, bad_proofs, fee_given_up):
        """The block node 1 mined, with `good_tx` swapped for `bad_tx`, the coinbase's first output lowered by
        `fee_given_up`, the merkle root and the sidecar redone, the header solved again."""
        raw = bytes.fromhex(good_block_hex)
        hdr = CBlockHeader()
        hdr.deserialize(BytesIO(raw))
        body = raw[len(hdr.serialize()):]
        ntx, i = read_compact(body, 0)
        assert_equal(ntx, 2)
        good, bad = bytes.fromhex(good_tx), bytes.fromhex(bad_tx)
        rest = body[i:]
        cb_len = rest.index(good)
        cb = bytearray(rest[:cb_len])
        # v4 coinbase: version, group id, one input (36-byte prevout, script, sequence), then the outputs.
        j = 8
        nin, j = read_compact(cb, j)
        assert_equal(nin, 1)
        j += 36
        sl, j = read_compact(cb, j)
        j += sl + 4
        _, j = read_compact(cb, j)
        v = struct.unpack('<q', cb[j:j + 8])[0]
        cb[j:j + 8] = struct.pack('<q', v - fee_given_up)
        cb = bytes(cb)
        hdr.hashMerkleRoot = int.from_bytes(merkle_root([dsha(cb), dsha(bad)]), 'little')
        hdr.sha256 = None
        self.solve(hdr)
        sidecar = compact(1) + dsha(bad)
        sidecar += compact(len(bad_proofs)) + b''.join(compact(len(p)) + p for p in (bytes.fromhex(x) for x in bad_proofs))
        out = hdr.serialize() + compact(2) + cb + bad + sidecar
        hdr.rehash()
        return out.hex(), hdr.hash

    @staticmethod
    def solve(hdr, n=48, k=5):
        """mininode CBlock.solve on a bare header (the merkle root kept as set)."""
        target = uint256_from_compact(hdr.nBits)
        digest = blake2b(digest_size=(512 // n) * n // 8, person=zcash_person(n, k))
        digest.update(hdr.serialize()[:108])
        hdr.nNonce = 0
        while True:
            curr = digest.copy()
            hash_nonce(curr, hdr.nNonce)
            for soln in gbp_basic(curr, n, k):
                assert gbp_validate(curr, soln, n, k)
                hdr.nSolution = soln
                hdr.rehash()
                if hdr.sha256 <= target:
                    return
            hdr.nNonce += 1

    def run_test(self):
        n0, n1 = self.nodes
        self.results = []
        self.reg = self.helper('regroot')
        n0.generate(140)
        sync_blocks(self.nodes)
        self.fund_pool(n0, n1, 5)
        self.activate_yed_on_node0()
        n0, n1 = self.nodes

        _, (ttxid, tvout), holder = mint_to_fresh_holder(self.nodes, 0, 0)
        sync_blocks(self.nodes)
        out = n0.getrawtransaction(ttxid, 1)['vout'][tvout]
        value = int(round(out['value'] * 100000000)) if 'valueZat' not in out else out['valueZat']
        script = bytes.fromhex(out['scriptPubKey']['hex'])
        secret = base58check_decode(n0.dumpprivkey(holder))[1:33]
        token = (ttxid, tvout, script, secret, value)
        payee = bytes.fromhex(n0.validateaddress(n0.getnewaddress())['scriptPubKey'])
        assert n0.yed_listunspent(), 'node 0 holds the token'

        # Node 1 (module inert) mines the bundle with a good signature; node 0 never takes that block.
        good_tx, pa, pb = self.token_bundle(n1, token, payee, 61, False)
        bad_tx, qa, qb = self.token_bundle(n1, token, payee, 61, True)
        tip0 = n0.getbestblockhash()
        n0.setban('127.0.0.1', 'add', 3600)
        n1.submitbundle({'tx': good_tx, 'proofs': [pa, pb]})
        h = n1.generate(1)[0]
        good_block = n1.getblock(h, 0)
        assert_equal(n0.getbestblockhash(), tip0)
        block, bhash = self.assemble(good_block, good_tx, bad_tx, [qa, qb], FEE)

        # 1. Node 0's index unhealthy, the node running on: the block stops the node, it is not invalid.
        stop_node(n0, 0)
        # The node's expected "fatal internal error" goes to a captured stderr: the runner fails a test
        # whose stderr is not empty.
        abort_stderr = tempfile.SpooledTemporaryFile(max_size=2**16)
        self.restart0(['-yellowbacktestfault=storage:mempool'], connect=False, stderr=abort_stderr)   # node 1 stays banned
        n0 = self.nodes[0]
        try:
            n0.sendtoaddress(n0.getnewaddress(), 1)
        except Exception:
            pass
        assert not n0.yed_getinfo().get('healthy', True), n0.yed_getinfo()
        try:
            n0.submitblock(block)
        except Exception:
            pass
        bitcoind_processes[0].wait(timeout=120)   # AbortNode shuts the node down
        del bitcoind_processes[0]
        abort_stderr.seek(0)
        abort_msg = abort_stderr.read().decode('utf-8')
        abort_stderr.close()
        self.check('unhealthy index: the block stops the node (a node failure)', 'fatal internal error' in abort_msg, abort_msg.strip())
        self.restart0(connect=False)
        n0 = self.nodes[0]
        tips = {t['hash']: t['status'] for t in n0.getchaintips()}
        self.check('unhealthy index: the block is not marked invalid', tips.get(bhash) != 'invalid', str(tips.get(bhash)))

        # 2. Healthy again: the block connects with the deposit skipped.
        if n0.getbestblockhash() != bhash:
            n0.submitblock(block)
        self.check('the block connects on node 0', n0.getbestblockhash() == bhash, n0.getbestblockhash())
        self.check('the tracked deposit was skipped: the token coin is unspent', n0.gettxout(ttxid, tvout) is not None)

        # 3. A level-4 re-verification re-connects it with the recorded skip.
        ok = n0.verifychain(4, 0)
        self.check('verifychain 4 over the block with the skipped deposit', ok is True, str(ok))

        failed = [n for n, ok in self.results if not ok]
        assert not failed, 'failed: %s' % failed


if __name__ == '__main__':
    YugenBundleVbModuleTest().main()
