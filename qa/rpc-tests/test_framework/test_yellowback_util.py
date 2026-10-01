#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for yellowback_util.py that need no node (plan section 6.0 item 4).

    cd qa/rpc-tests && DYLD_LIBRARY_PATH="$(brew --prefix openssl@3)/lib" \\
        ../../../.venv/bin/python -m unittest test_framework.test_yellowback_util

The owner-path signature case loads libcrypto through the framework's key.py (hence the
DYLD_LIBRARY_PATH on macOS); the rest is pure Python.
"""

import hashlib
import os
import sys
import unittest
from io import BytesIO

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from test_framework import yellowback_model as ym          # noqa: E402
from test_framework import yellowback_util as yu           # noqa: E402
from test_framework.util import bytes_to_hex_str           # noqa: E402

COIN = 10 ** 8


class FakeNode(object):
    """Just enough of the RPC surface for build_mint_tx / build_vault_spend_raw."""

    def __init__(self, utxos, height=200):
        self.utxos = utxos
        self.height = height
        self.secret = hashlib.sha256(b'fake-owner').digest()
        self.pubkey = yu.secret_to_pubkey(self.secret)
        self.address = yu.pubkey_to_address(self.pubkey)
        self.signed = []

    def getnewaddress(self):
        return self.address

    def validateaddress(self, addr):
        return {'pubkey': self.pubkey.hex(), 'isvalid': True, 'ismine': addr == self.address}

    def listunspent(self, minconf=1):
        return list(self.utxos)

    def signrawtransaction(self, hex_):
        self.signed.append(hex_)
        return {'hex': hex_, 'complete': True}

    def getblockcount(self):
        return self.height

    def dumpprivkey(self, addr):
        assert addr == self.address
        return yu.secret_to_wif(self.secret)


def utxo(txid_seed, vout, yec, spk=None):
    txid = hashlib.sha256(txid_seed).digest()[::-1].hex()
    if spk is None:
        spk = ym.p2pkh_script(hashlib.sha256(txid_seed).digest()[:20])
    return {'txid': txid, 'vout': vout, 'amount': yec, 'scriptPubKey': spk.hex()}


class WifTests(unittest.TestCase):
    def test_pool_wifs_round_trip(self):
        for i, wif in enumerate(yu.POOL_WIFS):
            secret = yu.wif_to_secret(wif)
            self.assertEqual(secret, hashlib.sha256(b'yellowback-regtest-pool-%d' % i).digest())
            self.assertEqual(yu.secret_to_wif(secret), wif)
            addr = yu.address_of(wif)
            self.assertTrue(addr.startswith('sm'), addr)   # regtest 0x1C95
            self.assertEqual(ym.address_key_hash(addr), ym.hash160(yu.secret_to_pubkey(secret)))

    def test_bad_checksum_rejected(self):
        wif = yu.POOL_WIFS[0]
        bad = wif[:-1] + ('1' if wif[-1] != '1' else '2')
        with self.assertRaises(AssertionError):
            yu.wif_to_secret(bad)

    def test_pubkey_matches_libcrypto(self):
        try:
            from test_framework.key import CECKey
        except OSError:
            self.skipTest('libcrypto not loadable (set DYLD_LIBRARY_PATH)')
        secret = yu.wif_to_secret(yu.POOL_WIFS[1])
        k = CECKey()
        k.set_secretbytes(secret)
        k.set_compressed(True)
        self.assertEqual(k.get_pubkey(), yu.secret_to_pubkey(secret))


class MintLayoutTests(unittest.TestCase):
    def build(self, fee_addr):
        node = FakeNode([utxo(b'a', 0, 30), utxo(b'b', 1, 5), utxo(b'tok', 0, 0.0001),
                         utxo(b'vault', 0, 20, ym.p2sh_script(b'\x51'))])
        collateral = 20 * COIN + 123
        hex_, owner = yu.build_mint_tx(node, 10_000, 48, 190, collateral, fee_addr=fee_addr)
        return node, collateral, ym.tx_from_hex(hex_), owner

    def test_layout_with_fee(self):
        node, collateral, tx, owner = self.build(yu.address_of(yu.POOL_WIFS[0]))
        self.assertEqual(owner, node.pubkey.hex())
        # funded from the 30 YEC coin alone (largest first); never the token or the P2SH coin
        self.assertEqual(len(tx.vin), 1)
        self.assertEqual(tx.vin[0].prev_txid, node.utxos[0]['txid'])
        self.assertEqual(len(tx.vout), 5)
        lock_height, claim_height = 190 + 48, 190 + 48 + yu.GRACE
        self.assertEqual(tx.vout[0].value, collateral)
        self.assertEqual(tx.vout[0].script, ym.p2sh_script(ym.vault_script(lock_height, node.pubkey, claim_height)))
        self.assertEqual(tx.vout[1].value, yu.TOKEN_VALUE)
        self.assertEqual(tx.vout[1].script, ym.p2pkh_script(ym.hash160(node.pubkey)))
        self.assertEqual(tx.vout[2].value, 0)
        p = ym.decode_payload(ym.script_single_push(tx.vout[2].script))
        self.assertEqual(p.type, ym.PAYLOAD_MINT)
        self.assertEqual((p.cents, p.lock_height, p.ref_height, p.fee_vout, p.term_class), (10_000, lock_height, 190, 3, 0))
        self.assertEqual(p.owner_pubkey, node.pubkey)
        fee = yu.fee_zat(collateral)
        self.assertEqual(fee, yu.FEE_MIN)   # 20 YEC * 25 bps < 0.5 YEC floor
        self.assertEqual(tx.vout[3].value, fee)
        self.assertEqual(tx.vout[3].script, ym.p2pkh_script(ym.address_key_hash(yu.address_of(yu.POOL_WIFS[0]))))
        self.assertEqual(tx.vout[4].value, 30 * COIN - collateral - yu.TOKEN_VALUE - fee - yu.YELLOWBACK_FEE)
        self.assertEqual(tx.expiry_height, 190 + yu.REF_WINDOW)
        self.assertEqual(tx.lock_time, 0)
        self.assertEqual(len(node.signed), 1)

    def test_layout_without_fee(self):
        node, collateral, tx, owner = self.build(None)
        self.assertEqual(len(tx.vout), 4)
        p = ym.decode_payload(ym.script_single_push(tx.vout[2].script))
        self.assertEqual(p.fee_vout, yu.FEE_VOUT_NONE)
        self.assertEqual(tx.vout[3].value, 30 * COIN - collateral - yu.TOKEN_VALUE - yu.YELLOWBACK_FEE)

    def test_class_follows_lock_blocks(self):
        self.assertEqual([yu.term_class_of(b) for b in (47, 48, 96, 97, 144, 145, 240, 241)],
                         [None, 'A', 'A', 'B', 'B', 'C', 'C', None])
        node = FakeNode([utxo(b'a', 0, 30)])
        with self.assertRaises(AssertionError):
            yu.build_mint_tx(node, 10_000, 47, 190, COIN)
        hex_, _ = yu.build_mint_tx(node, 10_000, 47, 190, COIN, term_class='A')   # adversarial: built anyway
        self.assertEqual(ym.decode_payload(ym.script_single_push(ym.tx_from_hex(hex_).vout[2].script)).lock_height, 237)

    def test_vault_from_mint(self):
        node = FakeNode([utxo(b'a', 0, 30)])
        hex_, owner = yu.build_mint_tx(node, 10_000, 48, 190, COIN)
        v = yu.vault_from_mint(hex_, 48, 190, owner)
        self.assertEqual((v['vout'], v['collateralZat'], v['lockHeight'], v['claimHeight'], v['refHeight']),
                         (0, COIN, 238, 262, 190))
        self.assertEqual(v['txid'], ym.tx_from_hex(hex_).txid)
        self.assertEqual(v['ownerAddress'], node.address)


class VaultSpendTests(unittest.TestCase):
    def setUp(self):
        self.node = FakeNode([utxo(b'a', 0, 30)], height=300)
        hex_, owner = yu.build_mint_tx(self.node, 10_000, 48, 190, 20 * COIN)
        self.vault = yu.vault_from_mint(hex_, 48, 190, owner)
        self.script = ym.vault_script(self.vault['lockHeight'], self.node.pubkey, self.vault['claimHeight'])

    def _key(self):
        try:
            from test_framework.key import CECKey
        except OSError:
            self.skipTest('libcrypto not loadable (set DYLD_LIBRARY_PATH)')
        return CECKey

    def test_owner_path_signature_verifies(self):
        # Rule: RED-1
        CECKey = self._key()
        from test_framework.mininode import CTransaction
        from test_framework.script import CScript, SIGHASH_ALL, SignatureHash
        signed_before = len(self.node.signed)
        hex_ = yu.build_vault_spend_raw(self.node, self.vault, 'owner', [], ref_height=298)
        tx = CTransaction()
        tx.deserialize(BytesIO(bytes.fromhex(hex_)))
        self.assertEqual(len(tx.vin), 1)
        self.assertEqual(tx.vin[0].nSequence, 0xFFFFFFFE)
        self.assertEqual(tx.nLockTime, self.vault['lockHeight'])
        self.assertEqual(tx.nExpiryHeight, 298 + yu.REF_WINDOW)
        pushes = ym.parse_pushes(tx.vin[0].scriptSig)
        self.assertEqual(len(pushes), 3)
        sig, selector, script = pushes
        self.assertEqual(script, self.script)
        self.assertEqual(ym.spend_path(tx.vin[0].scriptSig), 'owner')
        self.assertEqual(sig[-1], SIGHASH_ALL)
        sighash = SignatureHash(CScript(self.script), tx, 0, SIGHASH_ALL, 20 * COIN, yu.SIGNING_BRANCH_ID)[0]
        k = CECKey()
        k.set_pubkey(self.node.pubkey)
        self.assertTrue(k.verify(sighash, sig[:-1]))
        # a different amount or branch id is a different message
        other = SignatureHash(CScript(self.script), tx, 0, SIGHASH_ALL, 20 * COIN - 1, yu.SIGNING_BRANCH_ID)[0]
        self.assertFalse(k.verify(other, sig[:-1]))
        other = SignatureHash(CScript(self.script), tx, 0, SIGHASH_ALL, 20 * COIN, yu.YCASH_HEARTWOOD_BRANCH_ID)[0]
        self.assertFalse(k.verify(other, sig[:-1]))
        # low-S
        s = int.from_bytes(sig[6 + sig[3]:6 + sig[3] + sig[5 + sig[3]]], 'big')
        self.assertLessEqual(s, yu._SECP256K1_N // 2)
        # one output: the collateral less the network fee, to the node's address
        self.assertEqual(len(tx.vout), 1)
        self.assertEqual(tx.vout[0].nValue, 20 * COIN - yu.YELLOWBACK_FEE)
        self.assertEqual(bytes(tx.vout[0].scriptPubKey), ym.p2pkh_script(ym.hash160(self.node.pubkey)))
        self.assertEqual(len(self.node.signed), signed_before)  # no burn: signrawtransaction not called

    def test_owner_wif_bypasses_node(self):
        self._key()
        hex_ = yu.build_vault_spend_raw(None, self.vault, 'owner', [], expiry=0, to=self.node.address,
                                        owner_wif=yu.secret_to_wif(self.node.secret))
        tx = ym.tx_from_hex(hex_)
        self.assertEqual(tx.expiry_height, 0)
        self.assertEqual(ym.spend_path(tx.vin[0].script_sig), 'owner')

    def test_claim_path_is_unsigned_and_uses_claim_height(self):
        # Rule: RED-4
        payload = ym.encode_redeem(298, 1, [])
        hex_ = yu.build_vault_spend_raw(self.node, self.vault, 'claim', ['%s:1' % self.vault['txid'], (self.vault['txid'], 5)],
                                        payload=payload, fee=(yu.address_of(yu.POOL_WIFS[2]), 3 * yu.FEE_MIN), ref_height=298)
        tx = ym.tx_from_hex(hex_)
        self.assertEqual(tx.lock_time, self.vault['claimHeight'])
        self.assertEqual(tx.expiry_height, 298 + yu.REF_WINDOW)
        self.assertEqual([i.sequence for i in tx.vin], [0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF])
        self.assertEqual(tx.vin[0].script_sig, bytes([ym.OP_0]) + ym.push(self.script))
        self.assertEqual(ym.spend_path(tx.vin[0].script_sig), 'claim')
        self.assertEqual([(i.prev_txid, i.prev_n) for i in tx.vin[1:]], [(self.vault['txid'], 1), (self.vault['txid'], 5)])
        self.assertEqual(len(tx.vout), 3)
        self.assertEqual(tx.vout[0].value, 20 * COIN + 2 * yu.TOKEN_VALUE - yu.YELLOWBACK_FEE - 3 * yu.FEE_MIN)
        self.assertEqual(tx.vout[1].value, 3 * yu.FEE_MIN)
        self.assertEqual(tx.vout[1].script, ym.p2pkh_script(ym.address_key_hash(yu.address_of(yu.POOL_WIFS[2]))))
        self.assertEqual(ym.script_single_push(tx.vout[2].script), payload)
        self.assertEqual(len(self.node.signed), 2)   # the mint, then the burn inputs of the spend

    def test_selector_override(self):
        # Rule: RED-4 (K4: CastToBool selectors)
        hex_ = yu.build_vault_spend_raw(self.node, self.vault, 'claim', [], selector=b'\x01\x80', expiry=0)
        self.assertEqual(ym.spend_path(ym.tx_from_hex(hex_).vin[0].script_sig), 'claim')


class RoundRobinTests(unittest.TestCase):
    def test_equal_shares(self):
        self.assertEqual(yu.round_robin_schedule([2, 3, 4], 7), [2, 3, 4, 2, 3, 4, 2])

    def test_weighted_counts_sum_exactly(self):
        for n in (1, 7, 20, 64, 129):
            for shares in ([45, 55], [3, 2, 1], [40, 20, 20, 20], [1, 0], [60, 40]):
                pools = list(range(len(shares)))
                sched = yu.round_robin_schedule(pools, n, shares)
                self.assertEqual(len(sched), n)
                counts = [sched.count(p) for p in pools]
                total = sum(shares)
                for p in pools:
                    self.assertIn(counts[p], (n * shares[p] // total, -(-n * shares[p] // total)), (n, shares, counts))
                self.assertEqual(sum(counts), n)

    def test_45_percent_stock_over_64(self):
        # the activation test: node 1 at 45 % over a signal window leaves ~35 signals
        sched = yu.round_robin_schedule([2, 3, 4, 1], 64, [55 / 3, 55 / 3, 55 / 3, 45])
        self.assertEqual(sched.count(1), 29)
        self.assertEqual(64 - sched.count(1), 35)

    def test_interleaving_is_smooth(self):
        sched = yu.round_robin_schedule(['a', 'b'], 10, [1, 4])
        self.assertEqual(sched.count('a'), 2)
        # no prefix of length k has more 'a' than ceil(k/5)
        for k in range(1, 11):
            self.assertLessEqual(sched[:k].count('a'), -(-k // 5))

    def test_bad_shares(self):
        with self.assertRaises(AssertionError):
            yu.round_robin_schedule([1, 2], 4, [0, 0])
        with self.assertRaises(AssertionError):
            yu.round_robin_schedule([1, 2], 4, [1])


class ArgsTests(unittest.TestCase):
    def test_node_args(self):
        args = yu.yellowback_node_args()
        self.assertEqual(len([a for a in args if a.startswith('-nuparams=')]), 4)   # + 2 from start_node = 6
        self.assertIn('-nuparams=19bd2d2f:1', args)
        self.assertEqual(args[-4:], ['-experimentalfeatures', '-yellowback', '-yellowbackstartheight=1', '-yellowbacksigmaref=0'])
        self.assertNotIn('-yellowback', yu.yellowback_node_args(yellowback=False))
        self.assertNotIn('-yellowbacksigmaref=0', yu.yellowback_node_args(sigma_ref=None))
        p = yu.pool_args('smX', ['-debug=yellowback'])
        self.assertIn('-yellowbackpayoutaddress=smX', p)
        self.assertIn('-yellowbacksignal=1', p)
        self.assertEqual(p[-1], '-debug=yellowback')
        self.assertIn('-yellowbackenforce=0', yu.observer_args())

    def test_constants_match_model(self):
        p = ym.Params.regtest(1)
        self.assertEqual((p.p_fast_window, p.p_mid_window, p.p_slow_window), (yu.P_FAST_WINDOW, yu.P_MID_WINDOW, yu.P_SLOW_WINDOW))
        self.assertEqual((p.min_fill_fast, p.min_fill_mid, p.min_fill_slow), yu.MIN_FILL)
        self.assertEqual((p.signal_window, p.activation_threshold, p.participation_floor, p.activation_delay),
                         (yu.SIGNAL_WINDOW, yu.ACTIVATION_THRESHOLD, yu.PARTICIPATION_FLOOR, yu.ACTIVATION_DELAY))
        self.assertEqual((p.enforcement_floor, p.enforcement_resume, p.valve_blocks, p.abandon_blocks),
                         (yu.ENFORCEMENT_FLOOR, yu.ENFORCEMENT_RESUME, yu.VALVE_BLOCKS, yu.ABANDON_BLOCKS))
        self.assertEqual((p.grace, p.payee_window, p.fee_min, p.fee_bps, p.ref_window, p.ref_lag),
                         (yu.GRACE, yu.PAYEE_WINDOW, yu.FEE_MIN, yu.FEE_BPS, yu.REF_WINDOW, yu.REF_LAG))
        self.assertEqual((p.token_value, p.yellowback_fee, p.min_mint, p.max_mint), (yu.TOKEN_VALUE, yu.YELLOWBACK_FEE, yu.MIN_MINT, yu.MAX_MINT))
        for i, name in enumerate('ABC'):
            self.assertEqual((p.class_min[i], p.class_max[i], p.base_ratio_bps[i]), yu.CLASS_RANGES[name])
        self.assertEqual(yu.ACTIVATION_BLOCKS, 129)

    def test_usd_to_micro(self):
        self.assertEqual(yu.usd_to_micro('0.05'), 50_000)
        self.assertEqual(yu.usd_to_micro(1), 1_000_000)
        self.assertEqual(yu.usd_to_micro(0.1), 100_000)


class LedgerTests(unittest.TestCase):
    def test_format(self):
        rows = [{'node': 0, 'height': 5, 'blockhash': 'ab', 'statehash': 'cd'}, {'node': 1, 'height': 5, 'blockhash': 'ab', 'statehash': None}]
        out = yu.format_ledger('H0', rows)
        self.assertIn('| H0 | node |', out)
        self.assertIn('| | 1 | 5 | ab | - |', out)
        self.assertEqual(bytes_to_hex_str(b'\x01'), '01')


if __name__ == '__main__':
    unittest.main()
