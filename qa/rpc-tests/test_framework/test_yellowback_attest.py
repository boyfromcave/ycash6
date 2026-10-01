#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for yellowback_attest.py that need no node (plan v3 section 6.0 item 4, R18).

    ../.venv/bin/python -m unittest qa/rpc-tests/test_framework/test_yellowback_attest.py

Everything is pure Python; the one OpenSSL cross-check skips when libcrypto is not loadable.
"""

import hashlib
import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from test_framework import yellowback_attest as ya         # noqa: E402
from test_framework import yellowback_model as ym          # noqa: E402
from test_framework import yellowback_util as yu           # noqa: E402

N = ya._N
HALF_N = N // 2
BH_ONE = '00' * 31 + '01'          # display hex: internal bytes are 01 00 .. 00
VECTORS = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..', 'src', 'test', 'data',
                       'yellowback_attest_vectors.json')


class KeyTests(unittest.TestCase):
    def test_fixed_wifs_follow_the_pool_convention(self):
        for i, wif in enumerate(ya.ATTESTOR_WIFS):
            self.assertEqual(yu.wif_to_secret(wif), hashlib.sha256(b'yellowback-regtest-attestor-%d' % i).digest())
        for i, wif in enumerate(ya.BOND_WIFS):
            self.assertEqual(yu.wif_to_secret(wif), hashlib.sha256(b'yellowback-regtest-bond-%d' % i).digest())
        self.assertEqual(len(set(ya.ATTESTOR_WIFS + ya.BOND_WIFS)), 10)

    def test_attestor_keys(self):
        keys = ya.attestor_keys(5)
        self.assertEqual(len(keys), 5)
        for secret, pk in keys:
            self.assertEqual(len(secret), 32)
            self.assertEqual(pk, yu.secret_to_pubkey(secret).hex())
            self.assertTrue(ym.is_valid_compressed_pubkey(bytes.fromhex(pk)))
        self.assertEqual(keys[0][1], '0219ce7f2f737be07548a7243c605b76a09e039942f58ef91fe52771bf1f88767b')


class SignerTests(unittest.TestCase):
    def test_rfc6979_known_vector(self):
        # The widely published secp256k1 vector: key 1, message "Satoshi Nakamoto" (SHA-256).
        r, s = ya.ecdsa_sign_raw((1).to_bytes(32, 'big'), hashlib.sha256(b'Satoshi Nakamoto').digest())
        self.assertEqual('%064x' % r, '934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8')
        self.assertGreater(s, HALF_N)                       # raw s is high; the published DER is low-S
        r, s = ya.ecdsa_sign((1).to_bytes(32, 'big'), hashlib.sha256(b'Satoshi Nakamoto').digest())
        self.assertEqual('%064x' % s, '2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5')

    def test_message_layout(self):
        preimage = (b'YBATTEST1' + bytes([0x01, 0x00]) + bytes([0x40, 0x42, 0x0f, 0x00])
                    + bytes([0x64, 0x00, 0x00, 0x00]) + b'\x01' + b'\x00' * 31)
        self.assertEqual(len(preimage), 9 + 2 + 4 + 4 + 32)
        self.assertEqual(ya.attest_message(1, 1_000_000, 100, BH_ONE), hashlib.sha256(preimage).digest())
        # the internal bytes are what mininode.ser_uint256 produces for the RPC hex
        from test_framework.mininode import ser_uint256
        self.assertEqual(ya.blockhash_internal(BH_ONE), ser_uint256(int(BH_ONE, 16)))
        self.assertEqual(ya.attest_message(1, 1_000_000, 100, BH_ONE),
                         hashlib.sha256(ya.ATTEST_PREFIX + struct.pack('<HII', 1, 1_000_000, 100)
                                        + ser_uint256(int(BH_ONE, 16))).digest())

    def check_vector(self, secret, seq, price, cited, expected_hex, raw_was_high):
        pk = bytes.fromhex(ya.attestor_keys(1)[0][1])
        r, s_raw = ya.ecdsa_sign_raw(secret, ya.attest_message(seq, price, cited, BH_ONE))
        self.assertEqual(s_raw > HALF_N, raw_was_high)
        att = ya.sign_attestation(secret, seq, price, cited, BH_ONE)
        self.assertEqual(att.hex(), expected_hex)
        self.assertEqual(len(att), 74)
        self.assertEqual(ya.parse_attestation(att)[:3], (seq, price, cited))
        self.assertEqual(ya.parse_attestation(att)[3], r)
        self.assertEqual(ya.parse_attestation(att)[4], N - s_raw if raw_was_high else s_raw)
        self.assertTrue(ya.is_low_s(att))
        self.assertTrue(ya.verify_attestation(pk, att, BH_ONE))
        # the same signature with s un-normalised verifies mathematically but is not low-S
        high = att[:42] + (N - ya.parse_attestation(att)[4]).to_bytes(32, 'big')
        self.assertFalse(ya.is_low_s(high))
        self.assertFalse(ya.verify_attestation(pk, high, BH_ONE))
        self.assertTrue(ya.ecdsa_verify(pk, ya.attest_message(seq, price, cited, BH_ONE), r, N - ya.parse_attestation(att)[4]))
        # wrong block hash, wrong key, tampered price
        self.assertFalse(ya.verify_attestation(pk, att, '00' * 31 + '02'))
        self.assertFalse(ya.verify_attestation(bytes.fromhex(ya.attestor_keys(2)[1][1]), att, BH_ONE))
        self.assertFalse(ya.verify_attestation(pk, att[:2] + struct.pack('<I', price + 1) + att[6:], BH_ONE))
        return att

    def test_known_answer_low_s_branch(self):
        # Rule: BUNDLE-1
        secret = ya.attestor_keys(1)[0][0]
        self.check_vector(secret, 1, 1_000_000, 2,
                          '010040420f0002000000e19633f18fff3550d9122e47e26a2b32b41243698326c46d551c26e1678a65fc'
                          '7508078cdf808abe6b64ec29ffc2e5eb3c53ca62457a088dee6e4336fb664f6f', raw_was_high=False)

    def test_known_answer_normalised_branch(self):
        # Rule: BUNDLE-1
        secret = ya.attestor_keys(1)[0][0]
        self.check_vector(secret, 1, 1_000_000, 1,
                          '010040420f0001000000622d6ba87603895c2f2ac9703b48b5966c82c2246942ebd2868707d3e74c808d'
                          '3fc680a587458d70e33fc7dda023934b027fcc00b4136b0a23e65b1336fe6aeb', raw_was_high=True)

    def test_deterministic(self):
        secret = ya.attestor_keys(1)[0][0]
        a = ya.sign_attestation(secret, 7, 123_456, 50, BH_ONE)
        self.assertEqual(a, ya.sign_attestation(secret, 7, 123_456, 50, BH_ONE))

    def test_openssl_cross_check(self):
        try:
            from test_framework.key import CECKey     # noqa: F401
        except OSError:
            self.skipTest('libcrypto not loadable')
        secret, pk = ya.attestor_keys(1)[0]
        for cited in (1, 2, 3):
            att = ya.sign_attestation(secret, 1, 1_000_000, cited, BH_ONE)
            self.assertTrue(ya.verify_attestation(bytes.fromhex(pk), att, BH_ONE, backend='openssl'))
            self.assertFalse(ya.verify_attestation(bytes.fromhex(pk), att, '00' * 31 + '09', backend='openssl'))
        # and OpenSSL's own (random-nonce) signature is accepted after the same normalisation
        key = CECKey()
        key.set_secretbytes(secret)
        key.set_compressed(True)
        msg = ya.attest_message(1, 1_000_000, 1, BH_ONE)
        r, s = ya.der_decode(key.sign(msg))
        if s > HALF_N:
            s = N - s
        att = struct.pack('<HII', 1, 1_000_000, 1) + ya.compact_sig(r, s)
        self.assertTrue(ya.verify_attestation(bytes.fromhex(pk), att, BH_ONE))

    def test_der_round_trip(self):
        r, s = ya.ecdsa_sign(ya.attestor_keys(1)[0][0], b'\x11' * 32)
        der = ya.der_encode(r, s)
        self.assertEqual(ya.der_decode(der), (r, s))
        self.assertEqual(yu._low_s(der), der)          # already low-S: the util helper leaves it alone
        self.assertEqual(ya.der_encode(0x80 << 248, 1)[3], 33)   # high bit gets the leading zero


class EncoderTests(unittest.TestCase):
    def setUp(self):
        self.hot = bytes.fromhex(ya.attestor_keys(1)[0][1])
        self.bond = bytes.fromhex(ya.bond_keys(1)[0][1])
        self.att = ya.sign_attestation(ya.attestor_keys(1)[0][0], 1, 1_000_000, 2, BH_ONE)

    def test_payload_sizes(self):
        mint = ya.encode_mint_v3(0, 10_000, 250, 200, self.hot, 3, 4)
        self.assertEqual(len(mint), 52)
        self.assertEqual(mint[:4], b'YB\x03\x01')
        self.assertEqual(mint[-2:], b'\x03\x04')
        self.assertEqual(mint, ym.encode_mint(0, 10_000, 250, 200, self.hot, 3, 4))
        self.assertEqual(mint[4:51], ym.encode_mint(0, 10_000, 250, 200, self.hot, 3)[4:51])
        reg = ya.encode_attestor_register(self.hot, self.bond, 301, 5)
        self.assertEqual(len(reg), 75)
        self.assertEqual(reg[:4], b'YB\x03\x05')
        self.assertEqual(reg[4:37], self.hot)
        self.assertEqual(reg[37:70], self.bond)
        self.assertEqual(reg[70:75], struct.pack('<I', 301) + b'\x05')
        notice = ya.encode_claim_notice('ab' * 31 + 'cd', 0, 200)
        self.assertEqual(len(notice), 41)
        self.assertEqual(notice[:4], b'YB\x03\x06')
        self.assertEqual(notice[4:36], bytes.fromhex('ab' * 31 + 'cd')[::-1])
        self.assertEqual(notice[36:41], b'\x00' + struct.pack('<I', 200))
        self.assertEqual(ya.encode_equivocation(), b'YB\x03\x07')
        self.assertEqual(len(ya.encode_equivocation()), 4)
        revive = ya.encode_revive(self.att)
        self.assertEqual(len(revive), 78)
        self.assertEqual(revive, b'YB\x03\x08' + self.att)
        self.assertEqual(len(ya.encode_redeem_v3(200, 1, 0xFF, [(2, 500)])), 16)
        self.assertEqual(len(ya.encode_redeem_v3(200, 1, 2, [(3, 1)] * 13)), 76)
        self.assertEqual(ya.encode_transfer_v3([(1, 5)]), b'YB\x03\x02\x01\x01' + struct.pack('<I', 5))

    def test_bundle_codec(self):
        atts = [ya.sign_attestation(s, i + 1, 1_000_000 + i, 2, BH_ONE) for i, (s, _pk) in enumerate(ya.attestor_keys(5))]
        atts.append(ya.sign_attestation(ya.attestor_keys(1)[0][0], 9, 1, 2, BH_ONE))
        b = ya.encode_bundle(atts)
        self.assertEqual(len(b), 448)
        self.assertEqual(b[:4], b'YA\x01\x06')
        self.assertEqual(ya.decode_bundle(b), atts)
        with self.assertRaises(AssertionError):
            ya.encode_bundle(atts + [atts[0]])
        self.assertIsNone(ya.decode_bundle(b[:-1]))
        self.assertIsNone(ya.decode_bundle(b'YA\x02\x00'))
        self.assertEqual(ya.decode_bundle(b'YA\x01\x00'), [])

    def test_scripts(self):
        h = hashlib.sha256(b'bundle').digest()
        cs = ya.carrier_script(self.hot, h)
        self.assertEqual(len(cs), 71)               # the plan says 72; the bytes say 71
        self.assertEqual(cs, bytes([0x7c, 0xa8, 32]) + h + bytes([0x88, 33]) + self.hot + bytes([0xac]))
        self.assertEqual(ya.parse_carrier_script(cs), (self.hot, h))
        self.assertIsNone(ya.parse_carrier_script(cs[:-1] + b'\xad'))
        bs = ya.bond_script(self.bond, 301)
        self.assertEqual(bs, ym.push_int(301) + bytes([0xb1, 0x75, 33]) + self.bond + bytes([0xac]))
        ss = ya.carrier_scriptsig(b'x' * 448, b'y' * 71, cs)
        self.assertEqual(ss, b'\x4d\xc0\x01' + b'x' * 448 + b'\x47' + b'y' * 71 + b'\x47' + cs)
        self.assertEqual(ya.p2sh_script(cs), ym.p2sh_script(cs))


class SelectionTests(unittest.TestCase):
    def seed(self, bh, selector, i):
        return int.from_bytes(hashlib.sha256(bytes.fromhex(bh)[::-1] + selector + b'S' + bytes([i])).digest(), 'little')

    def manual(self, bh, selector, pool, rounds):
        pool = sorted(pool)
        out = []
        for i in range(rounds):
            total = sum(w for _s, w in pool)
            pick = self.seed(bh, selector, i) % total
            cum = 0
            for j, (s, w) in enumerate(pool):
                cum += w
                if cum > pick:
                    out.append(pool.pop(j)[0])
                    break
        return out

    def test_hand_worked(self):
        bh = 'ab' * 32
        pool = [(3, 3), (1, 1), (2, 2)]
        # round 0: seed mod 6 == 1; cumulative 1 (seq 1) does not exceed 1, 3 (seq 2) does
        self.assertEqual(self.seed(bh, b'', 0) % 6, 1)
        got = ya.select_attestors(bh, b'', pool)
        self.assertEqual(got[0], 2)
        self.assertEqual(got, self.manual(bh, b'', pool, 3))
        self.assertEqual(len(got), yu.M_SELECT + yu.K_SLACK)
        sel = ya.outpoint_selector('11' * 32, 1)
        self.assertEqual(sel, b'\x11' * 32 + b'\x01\x00\x00\x00')
        self.assertEqual(ya.select_attestors(bh, sel, pool), self.manual(bh, sel, pool, 3))
        self.assertNotEqual(ya.select_attestors(bh, sel, pool), got)   # the selector matters
        self.assertEqual(ya.select_attestors(bh, b'', pool, 1, 0), got[:1])

    def test_little_endian_seed(self):
        # UintToArith256 reads the digest little-endian; a big-endian reading picks differently here
        bh = 'ab' * 32
        digest = hashlib.sha256(bytes.fromhex(bh)[::-1] + b'S\x00').digest()
        self.assertNotEqual(int.from_bytes(digest, 'little') % 6, int.from_bytes(digest, 'big') % 6)

    def test_256_bit_modulus(self):
        # Rule: BUNDLE-1
        W = 1 << 70                    # three bonds well past 2^64 each
        bh = '01' * 32
        seed = self.seed(bh, b'', 0)
        self.assertEqual((seed % (3 * W)) // W, 2)                        # exact: seq 3
        self.assertEqual(((seed & ((1 << 64) - 1)) % (3 * W)) // W, 0)    # a 64-bit pick: seq 1
        got = ya.select_attestors(bh, b'', [(1, W), (2, W), (3, W)])
        self.assertEqual(got[0], 3)
        self.assertEqual(got, self.manual(bh, b'', [(1, W), (2, W), (3, W)], 3))

    def test_short_and_zero_pools(self):
        self.assertEqual(ya.select_attestors('ab' * 32, b'', [(5, 1)]), [5])
        self.assertEqual(ya.select_attestors('ab' * 32, b'', []), [])
        self.assertEqual(ya.select_attestors('ab' * 32, b'', [(9, 0), (4, 0), (6, 0), (1, 0)]), [1, 4, 6])
        self.assertEqual(ya.select_attestors('ab' * 32, b'', [(9, 0), (4, 5)]), [4, 9])

    def test_bond_weight(self):
        self.assertEqual(ya.bond_weight(10 * yu.COIN, 0), 0)
        self.assertEqual(ya.bond_weight(10 * yu.COIN, 3), 30 * yu.COIN)
        self.assertEqual(ya.bond_weight(10 * yu.COIN, 1000), 640 * yu.COIN)
        self.assertEqual(ya.bond_weight(10 * yu.COIN, -3), 0)
        self.assertEqual(ya.age_origin(100, 'UNARMED', None), 100)
        self.assertEqual(ya.age_origin(100, 'TRIGGERED', 90), 90)
        self.assertEqual(ya.age_origin(90 + yu.FOUNDING_WINDOW + 1, 'ARMED', 90), 90 + yu.FOUNDING_WINDOW + 1)


class QuantileTests(unittest.TestCase):
    def test_exact_thresholds(self):
        pairs = [(100, 1), (200, 1), (300, 1)]
        self.assertEqual(ya.weighted_quantile(pairs, yu.Q_LOW_BPS), 100)     # ceil(0.9999) = 1
        self.assertEqual(ya.weighted_quantile(pairs, yu.Q_HIGH_BPS), 300)    # ceil(2.0001) = 3
        self.assertEqual(ya.weighted_quantile(pairs, 5000), 200)             # ceil(1.5) = 2
        # cumulative weight exactly at the threshold counts
        self.assertEqual(ya.weighted_quantile([(100, 1), (200, 1)], 5000), 100)
        self.assertEqual(ya.weighted_quantile([(100, 1), (200, 3)], 2500), 100)
        self.assertEqual(ya.weighted_quantile([(100, 1), (200, 3)], 2501), 200)
        self.assertEqual(ya.weighted_quantile([(300, 5), (100, 1)], 10_000), 300)
        self.assertIsNone(ya.weighted_quantile([], 5000))
        self.assertIsNone(ya.weighted_quantile([(1, 0)], 5000))

    def test_ties_by_seq_and_stat(self):
        rows = [(200, 1, 2), (200, 1, 1), (100, 1, 3)]
        self.assertEqual(ya.weighted_quantile(rows, yu.Q_LOW_BPS), 100)
        self.assertEqual(ya.bundle_stat([((1, 200), 1), ((2, 100), 1), ((3, 300), 1)]), (100, 300))
        self.assertIsNone(ya.bundle_stat([((1, 200), 1)]))
        att = ya.sign_attestation(ya.attestor_keys(1)[0][0], 1, 1_000_000, 2, BH_ONE)
        att2 = ya.sign_attestation(ya.attestor_keys(2)[1][0], 2, 2_000_000, 2, BH_ONE)
        self.assertEqual(ya.bundle_stat([(att, 3), (att2, 1)]), (1_000_000, 1_000_000))
        self.assertEqual(ya.bundle_stat([(att, 1), (att2, 3)]), (2_000_000, 2_000_000))


class FakeNode(object):
    def __init__(self, utxos, height=200):
        self.utxos, self.height = utxos, height
        self.secret = hashlib.sha256(b'fake-owner').digest()
        self.pubkey = yu.secret_to_pubkey(self.secret)
        self.address = yu.pubkey_to_address(self.pubkey)
        self.sent = []

    def getnewaddress(self):
        return self.address

    def validateaddress(self, addr):
        return {'pubkey': self.pubkey.hex(), 'isvalid': True, 'ismine': addr == self.address}

    def listunspent(self, minconf=1):
        return list(self.utxos)

    def signrawtransaction(self, hex_):
        return {'hex': hex_, 'complete': True}

    def sendrawtransaction(self, hex_):
        self.sent.append(hex_)
        return ym.tx_from_hex(hex_).txid

    def getblockcount(self):
        return self.height

    def dumpprivkey(self, addr):
        assert addr == self.address
        return yu.secret_to_wif(self.secret)


def utxo(seed, vout, yec):
    txid = hashlib.sha256(seed).digest()[::-1].hex()
    return {'txid': txid, 'vout': vout, 'amount': yec, 'scriptPubKey': ym.p2pkh_script(hashlib.sha256(seed).digest()[:20]).hex()}


class BuilderTests(unittest.TestCase):
    def node(self):
        return FakeNode([utxo(b'a', 0, 30), utxo(b'b', 1, 5)])

    def test_register_layout(self):
        node = self.node()
        hot, bond = ya.attestor_keys(1)[0][1], ya.bond_keys(1)[0][1]
        hex_, locktime = ya.build_register_tx(node, hot, bond, 10 * yu.COIN, 200, flags=2)
        self.assertEqual(locktime, 200 + 1 + 200)
        tx = ym.tx_from_hex(hex_)
        self.assertEqual(len(tx.vout), 3)
        self.assertEqual(tx.vout[0].value, 10 * yu.COIN)
        self.assertEqual(tx.vout[0].script, ym.p2sh_script(ya.bond_script(bytes.fromhex(bond), locktime)))
        payload = ym.script_single_push(tx.vout[1].script)
        self.assertEqual(payload, ya.encode_attestor_register(bytes.fromhex(hot), bytes.fromhex(bond), locktime, 2))
        self.assertEqual(tx.vout[2].value, 30 * yu.COIN - 10 * yu.COIN - yu.YELLOWBACK_FEE)
        self.assertEqual(tx.expiry_height, 0)

    def test_carrier_round_trip(self):
        node = self.node()
        atts = [ya.sign_attestation(s, i + 1, 1_000_000, 2, BH_ONE) for i, (s, _pk) in enumerate(ya.attestor_keys(2))]
        bundle = ya.encode_bundle(atts)
        carrier = ya.build_carrier_tx(node, bundle)
        self.assertEqual(len(node.sent), 1)
        ctx = ym.tx_from_hex(carrier['hex'])
        self.assertEqual(carrier['txid'], ctx.txid)
        self.assertEqual(ctx.vout[0].value, yu.CARRIER_VALUE)
        self.assertEqual(ctx.vout[0].script, ym.p2sh_script(carrier['redeem']))
        self.assertEqual(ya.parse_carrier_script(carrier['redeem']), (node.pubkey, hashlib.sha256(bundle).digest()))
        # a notice spending it: funding input first, the carrier last, signed here
        hex_ = ya.post_notice_raw(node, ('cd' * 32, 0), 190, carrier)
        tx = ym.tx_from_hex(hex_)
        self.assertEqual(len(tx.vin), 2)
        self.assertEqual((tx.vin[1].prev_txid, tx.vin[1].prev_n), (carrier['txid'], 0))
        pushes = ym.parse_pushes(tx.vin[1].script_sig)
        self.assertEqual(len(pushes), 3)
        self.assertEqual(pushes[0], bundle)
        self.assertEqual(pushes[2], carrier['redeem'])
        self.assertEqual(pushes[1][-1], 0x01)                      # SIGHASH_ALL
        r, s = ya.der_decode(pushes[1][:-1])
        self.assertLessEqual(s, HALF_N)
        from io import BytesIO
        from test_framework.mininode import CTransaction
        from test_framework.script import CScript, SIGHASH_ALL, SignatureHash
        ctx2 = CTransaction()
        ctx2.deserialize(BytesIO(bytes.fromhex(hex_)))
        sighash = SignatureHash(CScript(carrier['redeem']), ctx2, 1, SIGHASH_ALL, yu.CARRIER_VALUE, yu.SIGNING_BRANCH_ID)[0]
        self.assertTrue(ya.ecdsa_verify(node.pubkey, sighash, r, s))
        self.assertEqual(ym.script_single_push(tx.vout[0].script), ya.encode_claim_notice('cd' * 32, 0, 190))
        self.assertEqual(tx.vout[1].value, 30 * yu.COIN + yu.CARRIER_VALUE - yu.YELLOWBACK_FEE)
        self.assertEqual(tx.expiry_height, 190 + yu.REF_WINDOW)

    def test_mint_v3_layout(self):
        node = self.node()
        bundle = ya.encode_bundle([ya.sign_attestation(ya.attestor_keys(1)[0][0], 1, 1_000_000, 2, BH_ONE)])
        carrier = ya.build_carrier_tx(node, bundle, send=False)
        collateral = 20 * yu.COIN
        pool_addr = yu.address_of(yu.POOL_WIFS[0])
        bond_addr = yu.pubkey_to_address(bytes.fromhex(ya.bond_keys(1)[0][1]))
        hex_, owner = ya.build_mint_tx_v3(node, 10_000, 48, 190, collateral, fee_addr=pool_addr, carrier=carrier,
                                          attest_fee=(bond_addr, 12_500_000))
        tx = ym.tx_from_hex(hex_)
        self.assertEqual(len(tx.vout), 6)
        p = ym.script_single_push(tx.vout[2].script)
        self.assertEqual(len(p), 52)
        self.assertEqual(p[:4], b'YB\x03\x01')
        self.assertEqual(p[-2:], b'\x03\x04')
        self.assertEqual(tx.vout[3].value, yu.fee_zat(collateral))
        self.assertEqual(tx.vout[4].value, 12_500_000)
        self.assertEqual(tx.vout[4].script, ym.p2pkh_script(ym.hash160(bytes.fromhex(ya.bond_keys(1)[0][1]))))
        self.assertEqual(tx.vin[-1].prev_txid, carrier['txid'])
        self.assertEqual(ym.parse_pushes(tx.vin[-1].script_sig)[0], bundle)
        self.assertEqual(tx.vout[5].value, 30 * yu.COIN + yu.CARRIER_VALUE - collateral - yu.TOKEN_VALUE
                         - yu.fee_zat(collateral) - 12_500_000 - yu.YELLOWBACK_FEE)
        # without carrier and fees: the v2 layout with a v3 payload
        hex2, _o = ya.build_mint_tx_v3(self.node(), 10_000, 48, 190, collateral)
        tx2 = ym.tx_from_hex(hex2)
        self.assertEqual(len(tx2.vout), 4)
        self.assertEqual(ym.script_single_push(tx2.vout[2].script)[-2:], b'\xff\xff')

    def test_equivocation_and_revive(self):
        node = self.node()
        s = ya.attestor_keys(1)[0][0]
        a, b = ya.sign_attestation(s, 1, 1_000_000, 2, BH_ONE), ya.sign_attestation(s, 1, 2_000_000, 2, BH_ONE)
        carrier = ya.build_carrier_tx(node, ya.encode_bundle([a, b]), send=False)
        tx = ym.tx_from_hex(ya.equivocation_raw(node, carrier))
        self.assertEqual(ym.script_single_push(tx.vout[0].script), b'YB\x03\x07')
        self.assertEqual(ym.parse_pushes(tx.vin[-1].script_sig)[0], ya.encode_bundle([a, b]))
        with self.assertRaises(AssertionError):
            ya.equivocation_raw(node, ya.build_carrier_tx(node, ya.encode_bundle([a]), send=False))
        tx = ym.tx_from_hex(ya.revive_raw(node, a))
        self.assertEqual(len(tx.vin), 1)
        self.assertEqual(ym.script_single_push(tx.vout[0].script), b'YB\x03\x08' + a)


class VectorFileTests(unittest.TestCase):
    """Every valid vector of src/test/data/yellowback_attest_vectors.json (the crypto chunk's
    file, read by yellowback_attest_tests.cpp) is reproduced byte for byte: RFC 6979 makes the
    signature a function of the key and the message alone."""

    def test_reproduce_vectors(self):
        if not os.path.exists(VECTORS):
            self.skipTest('no vectors file at %s' % VECTORS)
        with open(VECTORS) as f:
            data = json.load(f)
        vectors = data['vectors'] if isinstance(data, dict) and 'vectors' in data else data
        checked = 0
        for v in vectors:
            if not v.get('valid', True):
                continue
            secret = bytes.fromhex(v['secret']) if 'secret' in v else yu.wif_to_secret(v['wif'])
            att = ya.sign_attestation(secret, int(v['seq']), int(v['price']), int(v['citedHeight']), v['blockHash'])
            self.assertEqual(att.hex(), v['attestation'], v)
            if 'pubkey' in v:
                self.assertTrue(ya.verify_attestation(bytes.fromhex(v['pubkey']), att, v['blockHash']))
            checked += 1
        self.assertGreater(checked, 0)


if __name__ == '__main__':
    unittest.main()
