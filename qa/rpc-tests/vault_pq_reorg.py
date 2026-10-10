#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
A reorg below Falcon's height evicts Falcon spends (quantum spec R-A2; review F-1).

Falcon (OP_CHECKPQSIG scheme 0x02) activates at ``pqFalconHeight`` with no branch-ID change, so the
branch-ID eviction of a reorg does not reach a Falcon spend: ``vault::RecheckMempool`` re-runs the
inputs of every mempool transaction with an OP_CHECKPQSIG at the next height's flags when a reorg
drops the next block below Falcon's height, and evicts failures with their descendants.

- Before: a Falcon spend for the block below Falcon's height is refused ("scheme unknown or not
  active"); for the block at it, accepted, with a P2PKH child, and in getblocktemplate.
- invalidateblock of the tip below Falcon's height: both are evicted, getblocktemplate has no
  Falcon transaction, and the node keeps mining (two blocks).
- reconsiderblock: the old chain is back, the spend is accepted again and mined at Falcon's height.
- A mined Falcon spend resurrected by a reorg stays while the next block is at Falcon's height
  and is evicted one block lower; re-mining over the height includes it again.

There is no Python Falcon signer (test_framework/pq.py), so the test builds a small signer from the
tree's own vendored PQClean code (src/crypto/pq/falcon, the wallet's signer) with the C compiler
(``$CC``, default ``cc``) and calls it through ctypes; the framework's independent Python verifier
checks every signature.

    ZCASHD=<ycashd> ../.venv/bin/python -u qa/rpc-tests/vault_pq_reorg.py --srcdir=<src> --tmpdir=<dir> --portseed=<n>
"""

import ctypes
import os
import subprocess
import sys

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    VAULT_BRANCH_ID,
    assert_equal,
    assert_start_raises_init_error,
    nuparams,
    signing_branch_id,
    start_nodes,
    stop_node,
)
from test_framework import pq
from test_framework import vault as v
from test_framework.yellowback_util import YCASH_UPGRADE_ARGS, wif_to_secret

ACTIVATION = 115          # UPGRADE_VAULT
FALCON = 130              # -pqfalconheight (below regtest's first halving, 150)
VALUE = 100000000
FEE = 30000
CHILD_FEE = 10000
FALCON_SOURCES = ['codec.c', 'common.c', 'fft.c', 'fips202.c', 'fpr.c', 'keygen.c', 'rng.c',
                  'sign.c', 'vrfy.c', 'ycash_falcon_sign.c', 'ycash_falcon_verify.c']


def build_falcon_signer(tmpdir):
    src = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        '..', '..', 'src', 'crypto', 'pq', 'falcon'))
    out = os.path.join(tmpdir, 'libfalconsigner' + ('.dylib' if sys.platform == 'darwin' else '.so'))
    cc = os.environ.get('CC', 'cc').split()
    subprocess.check_call(cc + ['-O2', '-shared', '-fPIC', '-o', out] +
                          [os.path.join(src, f) for f in FALCON_SOURCES])
    return ctypes.CDLL(out)


class FalconSigner:
    def __init__(self, lib, seed48):
        self.lib = lib
        pk = ctypes.create_string_buffer(pq.FALCON_PK_BYTES)
        sk = ctypes.create_string_buffer(1281)
        assert_equal(lib.ycash_falcon512_keygen_from_seed(pk, sk, seed48, ctypes.c_size_t(len(seed48))), 0)
        self.pk, self.sk = pk.raw, sk.raw

    def sign(self, msg32):
        sig = ctypes.create_string_buffer(pq.FALCON_SIG_BYTES)
        assert_equal(self.lib.ycash_falcon512_sign(sig, msg32, ctypes.c_size_t(32), self.sk,
                                                   os.urandom(40), os.urandom(48)), 0)
        assert pq.verify(pq.SCHEME_FN_DSA_512, self.pk, sig.raw, msg32)   # the independent verifier
        return sig.raw


class VaultPQReorgTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.cache_behavior = 'clean'   # 6.20.0 harness: replaces setup_clean_chain

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir, extra_args=[
            list(YCASH_UPGRADE_ARGS) + [nuparams(VAULT_BRANCH_ID, ACTIVATION),
                                        '-pqfalconheight=%d' % FALCON, '-debug=vault']])
        self.is_network_split = False

    def mempool(self):
        return set(self.node.getrawmempool())

    def template_txids(self):
        t = self.node.getblocktemplate()
        return t['height'], set(x['hash'] for x in t['transactions'])

    def fund(self, spk):
        """A confirmed VALUE output paying ``spk``, from a mature coinbase signed in Python."""
        n = self.node
        cb = n.getblock(n.getblockhash(self.next_coinbase), 2)['tx'][0]
        self.next_coinbase += 1
        out = cb['vout'][0]
        secret = wif_to_secret(n.dumpprivkey(out['scriptPubKey']['addresses'][0]))
        amt = int(out['valueZat'])
        tx = v.make_tx([(cb['txid'], 0, 0xffffffff)],
                       [(VALUE, spk), (amt - VALUE - FEE, bytes.fromhex(out['scriptPubKey']['hex']))])
        v.sign_p2pkh_input(tx, 0, secret, amt, signing_branch_id(n))
        txid = n.sendrawtransaction(v.tx_hex(tx))
        n.generate(1)
        assert_equal(n.getrawtransaction(txid, 1)['confirmations'], 1)
        return txid

    def falcon_spend(self, txid):
        """Spend output 0 of ``txid`` (the Falcon TX_PQPKH) to a wallet P2PKH: (hex, address)."""
        n = self.node
        spk = pq.pqpkh_script(pq.SCHEME_FN_DSA_512, pq.key_hash(pq.SCHEME_FN_DSA_512, self.falcon.pk))
        address = n.getnewaddress()
        tx = v.make_tx([(txid, 0, 0xffffffff)], [(VALUE - FEE, v.node_spk(n, address))])
        msg = pq.pq_sighash(tx, 0, spk, VALUE, signing_branch_id(n))
        tx.vin[0].scriptSig = pq.pq_scriptsig(self.falcon.pk, self.falcon.sign(msg) + bytes([pq.SIGHASH_ALL]))
        return v.tx_hex(tx), address

    def send_pair(self, txid):
        """Send a Falcon spend of ``txid`` and a P2PKH child of it: (parent txid, child txid)."""
        n = self.node
        parent, address = self.falcon_spend(txid)
        ptxid = n.sendrawtransaction(parent)
        child = v.make_tx([(ptxid, 0, 0xffffffff)], [(VALUE - FEE - CHILD_FEE, v.node_spk(n))])
        v.sign_p2pkh_input(child, 0, wif_to_secret(n.dumpprivkey(address)), VALUE - FEE, signing_branch_id(n))
        ctxid = n.sendrawtransaction(v.tx_hex(child))
        return ptxid, ctxid

    def run_test(self):
        self.node = n = self.nodes[0]
        self.next_coinbase = 10
        self.falcon = FalconSigner(build_falcon_signer(self.options.tmpdir), bytes(range(48)))

        n.generate(120)
        f1 = self.fund(pq.pqpkh_script(pq.SCHEME_FN_DSA_512, pq.key_hash(pq.SCHEME_FN_DSA_512, self.falcon.pk)))
        f2 = self.fund(pq.pqpkh_script(pq.SCHEME_FN_DSA_512, pq.key_hash(pq.SCHEME_FN_DSA_512, self.falcon.pk)))

        print('A. a Falcon spend is refused below Falcon\'s height, accepted for the block at it')
        n.generate(FALCON - 2 - n.getblockcount())
        assert_equal(n.getblockcount() + 1, FALCON - 1)
        parent, _ = self.falcon_spend(f1)
        try:
            n.sendrawtransaction(parent)
            raise AssertionError('a Falcon spend for the block below Falcon\'s height was accepted')
        except JSONRPCException as e:
            assert 'scheme unknown or not active' in e.error['message'], e.error['message']
        n.generate(1)
        assert_equal(n.getblockcount() + 1, FALCON)
        ptxid, ctxid = self.send_pair(f1)
        assert_equal(self.mempool(), {ptxid, ctxid})
        height, txids = self.template_txids()
        assert_equal(height, FALCON)
        assert_equal(txids, {ptxid, ctxid})
        old_tip = n.getbestblockhash()

        print('B. invalidateblock below Falcon\'s height evicts the spend and its child; mining goes on')
        n.invalidateblock(old_tip)
        assert_equal(n.getblockcount() + 1, FALCON - 1)
        assert_equal(self.mempool(), set())
        height, txids = self.template_txids()
        assert_equal((height, txids), (FALCON - 1, set()))
        blocks = n.generate(2)
        assert_equal(n.getblockcount(), FALCON)
        for h in blocks:
            assert_equal(len(n.getblock(h)['tx']), 1)

        print('C. reconsiderblock: the old chain, the spend accepted again and mined at Falcon\'s height')
        # the two new blocks are on the longer chain: invalidate them so the old tip returns
        n.invalidateblock(blocks[0])
        n.reconsiderblock(old_tip)
        assert_equal(n.getbestblockhash(), old_tip)
        assert_equal(n.getblockcount() + 1, FALCON)
        ptxid, ctxid = self.send_pair(f1)
        mined = n.generate(1)[0]
        assert_equal(n.getblockcount(), FALCON)
        assert_equal(set(n.getblock(mined)['tx'][1:]), {ptxid, ctxid})
        assert_equal(self.mempool(), set())

        print('D. a mined Falcon spend resurrected by a reorg is evicted one block below Falcon\'s height')
        n.invalidateblock(mined)
        assert_equal(self.mempool(), {ptxid, ctxid})     # next block is at Falcon's height: it stays
        n.invalidateblock(old_tip)
        assert_equal(self.mempool(), set())
        assert_equal(self.template_txids(), (FALCON - 1, set()))
        n.generate(1)
        assert_equal(n.getblockcount() + 1, FALCON)
        ptxid2, ctxid2 = self.send_pair(f2)
        ptxid, ctxid = self.send_pair(f1)
        mined = n.generate(1)[0]
        assert_equal(n.getblockcount(), FALCON)
        assert_equal(set(n.getblock(mined)['tx'][1:]), {ptxid, ctxid, ptxid2, ctxid2})
        n.generate(1)
        assert_equal(n.getblockcount(), FALCON + 1)

        print('E. -pqfalconheight must be a decimal block height (review F-4)')
        stop_node(n, 0)
        for bad in ['abc', '12x', '', '-1', '2147483648']:
            assert_start_raises_init_error(0, self.options.tmpdir, ['-pqfalconheight=' + bad],
                                           '-pqfalconheight must be a block height')
        self.setup_network()
        assert_equal(self.nodes[0].getblockcount(), FALCON + 1)


if __name__ == '__main__':
    VaultPQReorgTest().main()
