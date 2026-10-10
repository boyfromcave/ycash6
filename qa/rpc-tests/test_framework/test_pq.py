#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for pq.py that need no node (docs/plans/yellowback-quantum-plan.md §4.1-§4.3, §4.7).

    cd qa/rpc-tests && python3 -m unittest test_framework.test_pq -v

Covers: SLH-DSA-SHA2-128s against a NIST ACVP subset (keyGen, sigGen, sigVer;
``data/pq_conformance.json``), FN-DSA-512 padded verification against PQClean's KAT and test
vectors plus rejections, the script helpers (key hash, canonical chunking, the scriptSig push
sequence, ``TX_PQPKH``), the transaction signer, and -- once it exists -- the library's golden
vector ``src/test/data/pq_vectors.json`` reproduced byte for byte.
"""

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from test_framework import pq                           # noqa: E402
from test_framework import vault as v                   # noqa: E402
from test_framework import script as sc                 # noqa: E402

HERE = os.path.dirname(os.path.realpath(__file__))
CONFORMANCE = os.path.join(HERE, 'data', 'pq_conformance.json')
GOLDEN = os.path.join(HERE, '..', '..', '..', 'src', 'test', 'data', 'pq_vectors.json')
H = bytes.fromhex


def _load(path):
    with open(path) as f:
        return json.load(f)


class SlhDsaAcvp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load(CONFORMANCE)['slhdsa']

    def test_keygen(self):
        for t in self.data['keyGen']:
            sk, pk = pq.slh_keygen_internal(H(t['skSeed']), H(t['skPrf']), H(t['pkSeed']))
            self.assertEqual(sk, H(t['sk']), t['tcId'])
            self.assertEqual(pk, H(t['pk']), t['tcId'])
            pk2, sk2 = pq.slh_keygen(H(t['skSeed']) + H(t['skPrf']) + H(t['pkSeed']))
            self.assertEqual((pk2, sk2), (pk, sk))

    def test_siggen(self):
        for t in self.data['sigGen']:
            m, sk = H(t['message']), H(t['sk'])
            ar = None if t['deterministic'] else H(t['additionalRandomness'])
            if t['interface'] == 'internal':
                sig = pq.slh_sign_internal(m, sk, ar)
                self.assertTrue(pq.slh_verify_internal(m, sig, H(t['pk'])))
            else:
                sig = pq.slh_sign(sk, m, H(t['context']), ar)
                self.assertTrue(pq.slh_verify(H(t['pk']), m, sig, H(t['context'])))
            self.assertEqual(sig, H(t['signature']), t['tcId'])

    def test_sigver(self):
        for t in self.data['sigVer']:
            got = pq.slh_verify(H(t['pk']), H(t['message']), H(t['signature']), H(t['context']))
            self.assertEqual(got, t['testPassed'], (t['tcId'], t['reason']))

    def test_pure_empty_context_is_the_node_scheme(self):
        t = self.data['keyGen'][0]
        pk, sk = pq.slh_keygen(H(t['skSeed']) + H(t['skPrf']) + H(t['pkSeed']))
        msg = hashlib.sha256(b'sighash').digest()
        sig = pq.sign(pq.SCHEME_SLH_DSA_SHA2_128S, sk, msg)
        self.assertEqual(len(sig), pq.sig_size(pq.SCHEME_SLH_DSA_SHA2_128S))
        self.assertEqual(sig, pq.slh_sign_internal(b'\x00\x00' + msg, sk))    # M' = 0 || 0 || M
        self.assertTrue(pq.verify(pq.SCHEME_SLH_DSA_SHA2_128S, pk, sig, msg))
        self.assertFalse(pq.verify(pq.SCHEME_SLH_DSA_SHA2_128S, pk, sig, msg[::-1]))
        self.assertFalse(pq.verify(pq.SCHEME_SLH_DSA_SHA2_128S, pk, sig[:-1], msg))
        self.assertFalse(pq.verify(pq.SCHEME_SLH_DSA_SHA2_128S, pk + b'\x00', sig, msg))
        self.assertFalse(pq.slh_verify(pk, msg, sig, b'ctx'))
        bad = bytearray(sig)
        bad[-1] ^= 1
        self.assertFalse(pq.verify(pq.SCHEME_SLH_DSA_SHA2_128S, pk, bytes(bad), msg))
        self.assertFalse(pq.verify(0x03, pk, sig, msg))
        self.assertEqual(pq.slh_sign(sk, msg, processes=2), sig)       # the process-pool path agrees


class FalconPadded512(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load(CONFORMANCE)['falcon']

    def test_vectors_verify(self):
        for t in self.data:
            pk, m, sig = H(t['pk']), H(t['message']), H(t['signature'])
            self.assertEqual(len(pk), 897)
            self.assertEqual(len(sig), 666)
            self.assertTrue(pq.falcon_verify(pk, m, sig), t['source'])

    def test_rejections(self):
        t = self.data[0]
        pk, m, sig = H(t['pk']), H(t['message']), H(t['signature'])
        self.assertFalse(pq.falcon_verify(pk, m + b'\x00', sig))                # other message
        for i in (0, 1, 40, 41, 100, 300):                                        # header, nonce, body
            bad = bytearray(sig)
            bad[i] ^= 0x01
            self.assertFalse(pq.falcon_verify(pk, m, bytes(bad)), i)
        bad = bytearray(sig)
        bad[-1] |= 0x01                                                           # padding must be zero
        self.assertFalse(pq.falcon_verify(pk, m, bytes(bad)))
        self.assertFalse(pq.falcon_verify(pk, m, sig[:-1]))                       # exact size
        self.assertFalse(pq.falcon_verify(pk, m, sig + b'\x00'))
        badpk = bytearray(pk)
        badpk[0] = 0x0a                                                           # wrong logn header
        self.assertFalse(pq.falcon_verify(bytes(badpk), m, sig))
        badpk = bytearray(pk)
        badpk[1], badpk[2] = 0xff, 0xff                                           # coefficient >= q
        self.assertFalse(pq.falcon_verify(bytes(badpk), m, sig))
        other = H(self.data[-1]['pk'])
        self.assertFalse(pq.falcon_verify(other, m, sig))                         # other key
        self.assertFalse(pq.verify(pq.SCHEME_FN_DSA_512, pk, sig + b'\x00', m))
        self.assertTrue(pq.verify(pq.SCHEME_FN_DSA_512, pk, sig, m))

    def test_no_python_signer(self):
        with self.assertRaises(NotImplementedError):
            pq.sign(pq.SCHEME_FN_DSA_512, b'', b'\x00' * 32)


class ScriptHelpers(unittest.TestCase):
    def test_registry(self):
        self.assertEqual(sc.OP_CHECKPQSIG, 0xc2)
        self.assertEqual(pq.pubkey_size(1), 32)
        self.assertEqual(pq.pubkey_size(2), 897)
        self.assertEqual(pq.sig_size(1), 7856)
        self.assertEqual(pq.sig_size(2), 666)
        self.assertEqual(pq.sig_size(3), 0)
        self.assertEqual(pq.SLH_SIG_BYTES, 7856)

    def test_key_hash_and_pqpkh(self):
        pk = bytes(range(32))
        kh = pq.key_hash(1, pk)
        self.assertEqual(kh, hashlib.sha256(b'\x01' + pk).digest())
        spk = pq.pqpkh_script(1, kh)
        self.assertEqual(len(spk), 35)
        self.assertEqual(spk, b'\x20' + kh + b'\x51\xc2')
        self.assertEqual(spk, bytes(sc.CScript([kh, 1, sc.OP_CHECKPQSIG])))        # CScript << int64_t
        self.assertEqual(spk, v.push(kh) + v.push_int(1) + bytes([sc.OP_CHECKPQSIG]))
        self.assertEqual(pq.parse_pqpkh(spk), (1, kh))
        spk2 = pq.pqpkh_script_of(2, b'\x09' * 897)
        self.assertEqual(spk2[-2:], bytes([0x52, 0xc2]))
        self.assertEqual(pq.parse_pqpkh(spk2)[0], 2)
        self.assertIsNone(pq.parse_pqpkh(b'\x20' + kh + b'\x01\x01\xc2'))             # 36-byte 01 01 form is not PQPKH
        self.assertIsNone(pq.parse_pqpkh(b'\x20' + kh + b'\x53\xc2'))

    def test_chunking(self):
        for n, sizes in ((7857, [520] * 15 + [57]), (897, [520, 377]), (667, [520, 147]),
                         (32, [32]), (520, [520]), (521, [520, 1])):
            self.assertEqual([len(c) for c in pq.chunk(b'\xab' * n)], sizes)

    def test_scriptsig_order(self):
        pk, sig = b'\x01' * 897, b'\x02' * 666 + b'\x01'
        pushes = pq.pq_scriptsig_pushes(pk, sig)
        self.assertEqual([len(x) for x in pushes], [520, 147, 1, 520, 377, 1])
        self.assertEqual(pushes[2], b'\x02')
        self.assertEqual(pushes[5], b'\x02')
        ss = pq.pq_scriptsig(pk, sig, extra=v.push_int(2))
        self.assertEqual(ss, pq.pq_scriptsig_from_pushes(pushes, v.push_int(2)))
        vals = v.push_values(ss)
        self.assertEqual(vals[:-1], pushes)
        self.assertEqual(vals[-1], b'\x02')
        self.assertEqual(len(ss), 1578)                 # Falcon OWNER scriptSig (spec §1.5)
        slh = pq.pq_scriptsig(b'\x03' * 32, b'\x04' * 7857, extra=v.push_int(2))
        self.assertEqual(len(slh), 7939)                # SLH-DSA OWNER scriptSig (spec §1.5)
        self.assertEqual([op for op, _ in v.get_ops(slh)][15:], [0x39, 0x60, 0x20, 0x51, 0x52])
        ops = v.get_ops(ss)
        self.assertEqual(ops[2][0], v.OP_2)            # s as OP_n, minimal
        self.assertEqual(ops[0][0], v.OP_PUSHDATA2)     # 520-byte chunk

    def test_sign_input(self):
        pk, sk = pq.slh_keygen(bytes(range(48)))
        spk = pq.pqpkh_script_of(1, pk)
        tx = v.make_tx([('11' * 32, 0, 0xffffffff)], [(9000, spk)])
        pushes = pq.pq_sign_input(tx, 0, spk, 10000, v.VAULT_BRANCH_ID, sk)
        self.assertEqual(len(pushes), 16 + 1 + 1 + 1)
        sig = b''.join(pushes[:16])
        self.assertEqual(sig[-1], pq.SIGHASH_ALL)
        self.assertEqual(b''.join(pushes[17:18]), pk)
        msg = sc.SignatureHash(sc.CScript(spk), tx, 0, sc.SIGHASH_ALL, 10000, v.VAULT_BRANCH_ID)[0]
        self.assertEqual(msg, v.template_sighash(tx, 0, spk, 10000))
        self.assertTrue(pq.verify(1, pk, sig[:-1], msg))
        self.assertFalse(pq.verify(1, pk, sig[:-1],
                                   pq.pq_sighash(tx, 0, spk, 10001, v.VAULT_BRANCH_ID)))
        tx.vin[0].scriptSig = pq.pq_scriptsig_from_pushes(pushes)
        self.assertLessEqual(len(tx.vin[0].scriptSig), 9000)          # MAX_STANDARD_PQ_SCRIPTSIG


@unittest.skipUnless(os.path.exists(GOLDEN), 'src/test/data/pq_vectors.json not on this branch yet')
class GoldenVectors(unittest.TestCase):
    """The library's golden vector (plan §4.7), reproduced byte for byte."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load(GOLDEN)
        assert cls.data['format'] == 'ycash-pq-vectors-1'

    def test_keys(self):
        for k in self.data['keys']:
            scheme, pk, msg, sig = k['scheme'], H(k['pk']), H(k['msg']), H(k['sig'])
            self.assertEqual(pq.key_hash(scheme, pk), H(k['keyhash']), k['label'])
            self.assertEqual(len(pk), pq.pubkey_size(scheme))
            self.assertEqual(len(sig), pq.sig_size(scheme))
            if scheme == pq.SCHEME_SLH_DSA_SHA2_128S:
                pk2, sk = pq.keygen(scheme, H(k['seed']))
                self.assertEqual(pk2, pk, k['label'])
                self.assertEqual(pq.sign(scheme, sk, msg), sig, k['label'])       # deterministic: byte for byte
            self.assertTrue(pq.verify(scheme, pk, sig, msg), k['label'])
            self.assertFalse(pq.verify(scheme, pk, sig, msg[::-1]), k['label'])

    def test_spends(self):
        keys = self.data['keys']
        for sp in self.data['spends']:
            k = keys[sp['key']]
            scheme, pk = sp['scheme'], H(k['pk'])
            self.assertEqual(k['scheme'], scheme)
            self.assertEqual(pq.pqpkh_script(scheme, pq.key_hash(scheme, pk)), H(sp['scriptPubKey']))
            sig = H(k['sig']) + bytes([sp['hashtype']])
            pushes = pq.pq_scriptsig_pushes(pk, sig)
            self.assertEqual(pushes[sp['sigChunks']], bytes([sp['sigChunks']]))
            self.assertEqual(pushes[-1], bytes([sp['pkChunks']]))
            ss = pq.pq_scriptsig(pk, sig)
            self.assertEqual(len(ss), sp['scriptSigSize'])
            self.assertEqual(ss, H(sp['scriptSig']))
            self.assertEqual(pq.pq_scriptsig_from_pushes(pushes), ss)


if __name__ == '__main__':
    unittest.main()
