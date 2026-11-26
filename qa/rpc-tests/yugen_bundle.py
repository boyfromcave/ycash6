#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Yugen bundles on regtest (doc/yugen-node.md N-D4, N-D5; spec 0.5.1 §15, §16.2, §13.3.12).

TEST-ONLY PROOFS: both nodes run with -yugenteststubproofs (regtest only; startup refuses it
elsewhere). A stub proof is a tag and the bundle statement `bstmt`; the helper still runs rule B1,
recomputes every transfer hash, leaf digest and `bstmt` (B3, B4) and checks the proof hashes the
transaction commits to (B5). The real verifiers (System A in the helper, System B through
b2verify) are not exercised here. The transfers are random bytes that decode (§7.1), built by the
helper's test-only `testbundle` against this chain's anchor.

- the pool is funded first by one real deposit (yewd-yugen, YEWD_YUGEN): the stub transfers spend
  no deposited note, so without it the turnstile (spec §13.3.2, B >= 0) refuses their fees
  (bad-yugen-turnstile, checked);
- a bundle of 5 transfers (two sub-bundles under one merge) is accepted by submitbundle;
- getblocktemplate lists its two proofs and `weightlimit`;
- it is mined: the coinbase ends with the record run (the claimed root record's script), the tree
  grows by 10 commitments, and node 1 accepts the block with its proof sidecar over the network;
- refused: a flipped proof byte (bad-yugen-bundle-proof), a flipped anchor root
  (bad-yugen-bundle-anchor-root), the mined bundle again (bad-yugen-nullifier-spent);
- a helper that hangs (review H-1, M-2): node 1 restarted with a helper that sleeps on `bundle`
  and -yugenverifytimeout=2 does not take node 0's next bundle block, and does not mark it
  invalid: restarted with the real helper it syncs to it;
- mempool eviction (review H-2): node 0 holds bundle X; node 1 mines bundle Y sharing four of X's
  nullifiers; after the block X is gone from node 0's mempool and node 0 mines again;
- a mempool candidate, a template and a block trial never run the root helper (review M-4): node 0's
  helper logs its commands;
- a bundle whose proof B is above LEAF_PROOF_MAX_B (a leaf's limit) but within PROOF_BYTES_MAX is
  accepted, mined and taken by node 1 (review C-1);
- -yugenmempoolverifytimeout bounds a mempool candidate's helper run, not a block's (review M-2);
- a helper that exits 1 (a Rust main returning Err) on its first bundle is a failure, not a verdict:
  node 1 does not mark the block invalid, fetches it again and connects it without a restart
  (reviews H-1, H-2).
"""

import json
import os
import struct
import subprocess
import tempfile

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID, assert_equal, connect_nodes_bi, nuparams, rpc_auth_pair, rpc_port, start_nodes,
    sync_blocks, sync_mempools,
)
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS
from test_framework.yugen_util import yugen_helper

YUGEN_BRANCH_ID = 0x59474E30
ACT = 32
HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = yugen_helper('YUGEN_LEAFVERIFY', 'yugen-leafverify')
WALLET = yugen_helper('YEWD_YUGEN', 'yewd-yugen')
ARGS = list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, 16), nuparams(YUGEN_BRANCH_ID, ACT),
                                   '-yugenverifier=' + HELPER, '-yugenteststubproofs', '-debug=yugen']


def compact(n):
    return bytes([n]) if n < 253 else b'\xfd' + struct.pack('<H', n) if n < 0x10000 else b'\xfe' + struct.pack('<I', n)


def bundle_expiry(bundle):
    """Spec 0.5.4 (§15.1, as §7.9 rule 1a): h_a + ANCHOR_WINDOW for the first anchor table entry; on these
    regtest chains (below height 4096) the entry's anchor height is its slot times the 16-block grid."""
    return bundle[2] * 16 + 96


def bundle_tx(bundle, expiry=None):
    """v4 layout under the Yugen group, no transparent or shielded parts, lock time 0, the spec 0.5.4
    expiry, the bundle, two empty proof fields."""
    e = bundle_expiry(bundle) if expiry is None else expiry
    return (struct.pack('<I', 4 | 0x80000000) + struct.pack('<I', 0x59474E47) + b'\x00\x00' + b'\x00' * 4 +
            struct.pack('<I', e) + b'\x00' * 8 + b'\x00\x00\x00' + compact(len(bundle)) + bundle + b'\x00\x00').hex()


class YugenBundleTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def wrapper(self, name, body):
        path = os.path.join(self.options.tmpdir, name)
        with open(path, 'w') as f:
            f.write('#!/bin/sh\n' + body + 'exec "%s" "$@"\n' % HELPER)
        os.chmod(path, 0o755)
        return path

    def check(self, name, ok, detail=''):
        print('    %s %s %s' % ('ok  ' if ok else 'FAIL', name, detail))
        self.results.append((name, ok))

    def helper_calls(self, cmd):
        with open(self.calls) as f:
            return sum(1 for l in f if l.strip() == cmd)

    def setup_network(self, split=False):
        # Node 0's helper logs each command (review M-4: no root runs for trials).
        self.calls = os.path.join(self.options.tmpdir, 'helper-calls.log')
        open(self.calls, 'w').close()
        logging = self.wrapper('log-helper.sh', 'echo "$1" >> "%s"\n' % self.calls)
        args0 = [a for a in ARGS if not a.startswith('-yugenverifier=')] + ['-yugenverifier=' + logging]
        self.nodes = start_nodes(2, self.options.tmpdir, [args0, ARGS])
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False

    def helper(self, *args):
        out = subprocess.run([HELPER] + list(args), capture_output=True, text=True, timeout=600)
        assert out.returncode == 0, out.stdout + out.stderr
        return out.stdout.strip()

    def fund_pool(self, n0, n1, amount):
        """One deposit by the Yugen wallet engine, mined: B = amount - fee."""
        wdir = tempfile.mkdtemp(prefix='yewd-yugen-', dir=self.options.tmpdir)
        u, p = rpc_auth_pair(0)

        def wallet(*args):
            # the engine takes the seed only on an inherited descriptor (N-A5): hex and a newline on fd 3
            r, w = os.pipe()
            os.write(w, ('33' * 32 + '\n').encode())
            os.close(w)
            try:
                out = subprocess.run([WALLET, '-network=regtest', '-node=127.0.0.1:%d' % rpc_port(0), '-rpcuser=' + u,
                                      '-rpcpassword=' + p, '-datadir=' + wdir, '-seedfd=3'] + list(args),
                                     capture_output=True, text=True, timeout=1800, pass_fds=(3,),
                                     preexec_fn=lambda: os.dup2(r, 3))
            finally:
                os.close(r)
            assert out.returncode == 0, (args[:1], out.stdout, out.stderr[-2000:])
            return json.loads(out.stdout)
        dep = wallet('depositaddress')
        dep = dep if isinstance(dep, str) else dep['address']
        fund = n0.sendtoaddress(dep, amount)
        n0.generate(1)
        wallet('shield', json.dumps([fund]))
        sync_mempools([n0, n1])
        n0.generate(1)
        sync_blocks([n0, n1])

    def make(self, node, n, seed, payee='', pad_b=0):
        h = node.getblockcount() + 1
        ha = (h - 1) // 16 * 16
        a = node.yugen_getanchor(ha)
        req = {'anchor': {'slot': (ha // 16) & 0xff, 'anchor_root': a['root'], 'reg_root': self.reg,
                          'block_hash': a['block_hash']},
               'n': n, 'seed': seed, 'payee': payee, 'branch_id': YUGEN_BRANCH_ID, 'network': 2,
               'height': h, 'activation': ACT, 'pad_b': pad_b}
        path = os.path.join(self.options.tmpdir, 'tb.json')
        with open(path, 'w') as f:
            json.dump(req, f)
        b, pa, pb = self.helper('testbundle', path).split()
        return bytes.fromhex(b), pa, pb

    def refused(self, node, txhex, proofs, reason):
        try:
            node.submitbundle({'tx': txhex, 'proofs': proofs})
        except JSONRPCException as e:
            assert reason in e.error['message'], e.error['message']
            return
        raise AssertionError('accepted: expected ' + reason)

    def run_test(self):
        n0, n1 = self.nodes
        self.results = []
        self.reg = self.helper('regroot')
        n0.generate(140)
        sync_blocks([n0, n1])

        payee = n0.validateaddress(n0.getnewaddress())['scriptPubKey']
        # B = 0: the stub transfers' fees are not backed by any deposit.
        b0, pa0, pb0 = self.make(n0, 2, 99, payee)
        self.refused(n0, bundle_tx(b0), [pa0, pb0], 'bad-yugen-turnstile')
        self.fund_pool(n0, n1, 5)
        b1 = n0.yugen_getinfo()['pool_balance_zat']
        assert b1 > 0

        b, pa, pb = self.make(n0, 5, 1, payee)
        txhex = bundle_tx(b)

        # Tampered: one proof byte, one byte of the anchor root (offset 2 + slot byte).
        self.refused(n0, txhex, [pa[:-2] + '%02x' % (int(pa[-2:], 16) ^ 1), pb], 'bad-yugen-bundle-proof')
        bad = bytearray(b)
        bad[3] ^= 1
        self.refused(n0, bundle_tx(bytes(bad)), [pa, pb], 'bad-yugen-bundle-anchor-root')

        roots = self.helper_calls('root')
        r = n0.submitbundle({'tx': txhex, 'proofs': [pa, pb]})
        txid = r['txid']
        assert_equal(r['transfers'], 5)
        assert txid in n0.getrawmempool()

        t = n0.getblocktemplate()
        # Review M-4: the mempool trial, the template's record run and its block trial ran no root.
        self.check('M-4: no root helper run for a mempool candidate or a template', self.helper_calls('root') == roots,
                   '%d root runs' % (self.helper_calls('root') - roots))
        assert_equal(t['weightlimit'], 4000000)
        entry = [e for e in t['transactions'] if e['hash'] == txid][0]
        assert_equal(entry['proofs'], [pa, pb])
        assert_equal(entry['weight'], len(txhex) // 2 + (len(pa) + len(pb)) // 2)

        size0 = n0.yugen_getinfo()['tree_size']
        tip = n0.generate(1)[0]
        sync_blocks([n0, n1])   # node 1 takes the block with its sidecar from the network
        blk = n0.getblock(tip)
        assert txid in blk['tx']
        assert_equal(n0.yugen_getinfo()['tree_size'], size0 + 10)
        assert_equal(n0.yugen_getinfo()['root'], n1.yugen_getinfo()['root'])
        cb = n0.getrawtransaction(blk['tx'][0], 1)
        last = cb['vout'][-1]
        assert_equal(last['scriptPubKey']['hex'], payee)
        assert last['valueZat'] > 0, last
        assert_equal(len(n0.yugen_getblockdata(blk['height'])['transfers']), 5)
        # The turnstile: B fell by the five transfers' fees, which the miner was paid.
        d = n0.yugen_getblockdata(blk['height'])
        assert d['pool_balance_after_zat'] < d['pool_balance_before_zat'] == b1
        # B-RPC-2: the block's bundle, its statement (the stub proofs end with bstmt) and sizes.
        assert_equal(len(d['bundles']), 1)
        bd = d['bundles'][0]
        assert_equal(bd['txid'], txid)
        assert_equal(bd['stmt'], pa[-64:])
        assert_equal(bd['stmt'], pb[-64:])
        assert_equal(bd['proof_hash_a'], b[-64:-32].hex())
        assert_equal(bd['proof_hash_b'], b[-32:].hex())
        assert_equal((bd['transfers'], bd['applied']), (5, 5))
        assert_equal(bd['transfer_indexes'], [0, 1, 2, 3, 4])
        assert_equal(len(bd['nf1']), 5)
        assert_equal((bd['proof_a_bytes'], bd['proof_b_bytes']), (len(pa) // 2, len(pb) // 2))
        assert_equal(bd['fee_zat'], b1 - d['pool_balance_after_zat'])
        assert_equal(bd['skipped_fee_zat'], 0)
        assert_equal(n1.yugen_getblockdata(blk['height'])['bundles'], d['bundles'])
        assert_equal(n0.yugen_getblockdata(blk['height'] - 1)['bundles'], [])

        # The mined bundle again: its nullifiers are spent.
        self.refused(n0, txhex, [pa, pb], 'bad-yugen-nullifier-spent')

        # Eviction (review H-2): X (seed 2, 5 transfers) on node 0; Y (seed 2, the first 4) mined by node 1.
        bx, pax, pbx = self.make(n0, 5, 2)
        by, pay, pby = self.make(n1, 4, 2)
        x = n0.submitbundle({'tx': bundle_tx(bx), 'proofs': [pax, pbx]})['txid']
        y = n1.submitbundle({'tx': bundle_tx(by), 'proofs': [pay, pby]})['txid']
        assert x in n0.getrawmempool() and y in n1.getrawmempool()
        n1.generate(1)
        sync_blocks([n0, n1])
        assert x not in n0.getrawmempool(), 'conflicting bundle not evicted'
        n0.generate(1)
        sync_blocks([n0, n1])

        # Review C-1: proof B above a leaf's LEAF_PROOF_MAX_B (817,736) is within a bundle's PROOF_BYTES_MAX.
        b, pa, pb = self.make(n0, 2, 8, pad_b=900000)
        assert len(pb) // 2 > 817736
        try:
            big = n0.submitbundle({'tx': bundle_tx(b), 'proofs': [pa, pb]})['txid']
            tip = n0.generate(1)[0]
            sync_blocks([n0, n1])
            self.check('C-1: proof B above LEAF_PROOF_MAX_B accepted, mined and synced', big in n1.getblock(tip)['tx'])
        except JSONRPCException as e:
            self.check('C-1: proof B above LEAF_PROOF_MAX_B accepted, mined and synced', False, e.error['message'])

        # Review H-1, M-2: a verifier that hangs is a node failure, never a verdict on the block.
        from test_framework.util import start_node, stop_node, wait_bitcoinds
        import time
        hang = os.path.join(self.options.tmpdir, 'hang.sh')
        with open(hang, 'w') as f:
            f.write('#!/bin/sh\ncase "$1" in bundle|verify) sleep 30; exit 0;; esac\nexec "%s" "$@"\n' % HELPER)
        os.chmod(hang, 0o755)
        stop_node(n1, 1)
        hang_args = [a for a in ARGS if not a.startswith('-yugenverifier=')] + ['-yugenverifier=' + hang, '-yugenverifytimeout=2']
        self.nodes[1] = n1 = start_node(1, self.options.tmpdir, hang_args)
        connect_nodes_bi(self.nodes, 0, 1)
        b, pa, pb = self.make(n0, 3, 3)
        n0.submitbundle({'tx': bundle_tx(b), 'proofs': [pa, pb]})
        tip = n0.generate(1)[0]
        time.sleep(8)
        assert n1.getbestblockhash() != tip
        assert not [c for c in n1.getchaintips() if c['hash'] == tip and c['status'] == 'invalid'], n1.getchaintips()
        stop_node(n1, 1)
        self.nodes[1] = n1 = start_node(1, self.options.tmpdir, ARGS)
        connect_nodes_bi(self.nodes, 0, 1)
        n0.generate(1)
        sync_blocks([n0, n1])
        assert_equal(n1.getblock(tip)['confirmations'], 2)

        # Review M-2: a mempool candidate's helper run has its own, short deadline.
        stop_node(n1, 1)
        slow_args = [a for a in ARGS if not a.startswith('-yugenverifier=')] + [
            '-yugenverifier=' + hang, '-yugenverifytimeout=600', '-yugenmempoolverifytimeout=2']
        self.nodes[1] = n1 = start_node(1, self.options.tmpdir, slow_args)
        b, pa, pb = self.make(n1, 2, 4)
        t0 = time.time()
        try:
            n1.submitbundle({'tx': bundle_tx(b), 'proofs': [pa, pb]})
            msg = 'accepted'
        except JSONRPCException as e:
            msg = e.error['message']
        took = time.time() - t0
        self.check('M-2: a mempool helper run stops at -yugenmempoolverifytimeout',
                   'yugen-verifier-failed' in msg and took < 15, '%s after %.0f s' % (msg, took))

        # Reviews H-1, H-2: exit 1 (what a Rust main returning Err exits with) on the first bundle is a
        # failure. The block is not marked invalid; its body is reset, fetched again and connected.
        stop_node(n1, 1)
        once = os.path.join(self.options.tmpdir, 'failed-once')
        fail1 = self.wrapper('fail-once.sh', 'if [ "$1" = bundle ] && [ ! -e "%s" ]; then touch "%s"; exit 1; fi\n' % (once, once))
        self.nodes[1] = n1 = start_node(1, self.options.tmpdir,
                                        [a for a in ARGS if not a.startswith('-yugenverifier=')] + ['-yugenverifier=' + fail1])
        connect_nodes_bi(self.nodes, 0, 1)
        sync_blocks([n0, n1])
        b, pa, pb = self.make(n0, 3, 6)
        n0.submitbundle({'tx': bundle_tx(b), 'proofs': [pa, pb]})
        tip = n0.generate(1)[0]
        deadline = time.time() + 90
        while time.time() < deadline and n1.getbestblockhash() != tip:
            time.sleep(0.5)
        assert os.path.exists(once), 'the failing helper was not run'
        invalid = [c for c in n1.getchaintips() if c['hash'] == tip and c['status'] == 'invalid']
        self.check('H-1/H-2: helper exit 1 is a failure; the block is fetched again and connected',
                   not invalid and n1.getbestblockhash() == tip, 'invalid tip' if invalid else '')

        failed = [n for n, ok in self.results if not ok]
        assert not failed, 'failed: %s' % failed


if __name__ == '__main__':
    YugenBundleTest().main()
