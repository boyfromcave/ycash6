#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for vault.py that need no node (docs/plans/yellowback-upgrade-plan.md §15).

    .venv/bin/python -m unittest qa/rpc-tests/test_framework/test_vault.py

Covers: recoverable signatures, template and act round trips and their rejections, selector
parsing, the golden vector being reproducible, and VaultModel scenarios (lifecycle, BIP68 /
cancel boundary, dormancy, rate epochs, equivocation, removal, wind-down, undo).
"""

import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from test_framework import vault as v                   # noqa: E402
from test_framework import gen_vault_vectors as gvv     # noqa: E402

N = v._N
VECTORS = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..', 'src', 'test', 'data',
                       'vault_vectors.json')

ADMIT = v.fixed_secret('vault-test-admit')
OWNER = v.fixed_secret('vault-test-owner')
MEMBERS = [v.fixed_secret('vault-test-member-%d' % i) for i in range(6)]
MKEYS = [v.pubkey_of(s) for s in MEMBERS]
SET_A = bytes(range(32))
SET_B = bytes(range(32, 64))


def vparams(**kw):
    d = dict(tag=b'WYEC', set_id=SET_A, cancel_set_id=SET_B, delay=144, owner_height=1000, app_height=0,
             owner_key=v.pubkey_of(OWNER))
    d.update(kw)
    return v.VaultParams(**d)


class SignatureTests(unittest.TestCase):
    def test_round_trip_and_header(self):
        flipped = set()
        for i in range(24):
            sk, msg = MEMBERS[i % 6], v.sha256(b'msg %d' % i)
            r, s, rec, fl = v.ecdsa_sign_rec(sk, msg)
            flipped.add(fl)
            self.assertLessEqual(s, N // 2)
            sig = v.sign_recoverable(sk, msg)
            self.assertEqual(len(sig), 65)
            self.assertIn(sig[0], (31, 32, 33, 34))
            self.assertEqual(sig[0], 31 + rec)
            self.assertEqual(v.recover_compact(sig, msg), MKEYS[i % 6])
            self.assertNotEqual(v.recover_compact(sig, v.sha256(b'other')), MKEYS[i % 6])
        self.assertEqual(flipped, {True, False}, 'both low-S branches exercised')

    def test_strict_rejections(self):
        msg = v.sha256(b'strict')
        sig = v.sign_recoverable(MEMBERS[0], msg)
        r, s = sig[1:33], int.from_bytes(sig[33:], 'big')
        high = bytes([31 + ((sig[0] - 31) ^ 1)]) + r + (N - s).to_bytes(32, 'big')     # same key, high S
        self.assertIsNone(v.recover_compact(high, msg))
        self.assertEqual(v.recover_compact(high, msg, strict=False), MKEYS[0])
        uncompressed = bytes([sig[0] - 4]) + sig[1:]                       # header 27..30
        self.assertIsNone(v.recover_compact(uncompressed, msg))
        loose = v.recover_compact(uncompressed, msg, strict=False)       # CPubKey::RecoverCompact: uncompressed
        self.assertEqual((len(loose), loose[0]), (65, 4))
        self.assertEqual(bytes([2 + (loose[64] & 1)]) + loose[1:33], MKEYS[0])
        self.assertIsNone(v.recover_compact(bytes([35]) + sig[1:], msg))
        self.assertIsNone(v.recover_compact(sig[:64], msg))
        self.assertIsNone(v.recover_compact(sig[:1] + bytes(32) + sig[33:], msg))   # r = 0
        self.assertIsNone(v.recover_compact(sig[:33] + bytes(32), msg))            # s = 0

    def test_matches_attest_signer(self):
        """Two RFC 6979 implementations in the tree agree (the other is the one whose vectors
        libsecp256k1 already reproduces in yellowback_attest_tests)."""
        from test_framework import yellowback_attest as ya
        for i in range(8):
            msg = v.sha256(b'x%d' % i)
            r, s, _rec, _f = v.ecdsa_sign_rec(MEMBERS[i % 6], msg)
            self.assertEqual((r, s), ya.ecdsa_sign(MEMBERS[i % 6], msg))

    def test_der(self):
        msg = v.sha256(b'der')
        der = v.ecdsa_sign_der(OWNER, msg)
        self.assertTrue(v.ecdsa_verify_der(v.pubkey_of(OWNER), msg, der))
        self.assertFalse(v.ecdsa_verify_der(MKEYS[0], msg, der))

    def test_messages(self):
        po_txid = '%064x' % 0xabcdef
        sh = v.sha256(b'sighash')
        m = v.set_sig_msg(SET_A, 1, po_txid, 7, sh)
        pre = b'YcashSetSig' + SET_A + b'\x01' + bytes.fromhex(po_txid)[::-1] + struct.pack('<I', 7) + sh
        self.assertEqual(len(pre), 11 + 32 + 1 + 36 + 32)
        self.assertEqual(m, v.sha256d(pre))
        p = v.encode_act(v.act_set_winddown(SET_A))
        self.assertEqual(v.act_msg(p, po_txid, 7),
                         v.sha256d(b'YcashSetAct' + p + bytes.fromhex(po_txid)[::-1] + struct.pack('<I', 7)))


class TemplateTests(unittest.TestCase):
    def test_vault_round_trip_edges(self):
        for delay in (1, 16, 17, 127, 128, 255, 256, 32767, 32768, 65535):
            for oh in (1, 16, 17, 499999999):
                for ah in (0, 1, 499999999):
                    p = vparams(delay=delay, owner_height=oh, app_height=ah)
                    self.assertEqual(v.parse_vault(v.vault_script(p)), p)
        self.assertEqual(v.vault_script(vparams(delay=16))[38], v.OP_16)
        self.assertEqual(v.vault_script(vparams(app_height=0))[-7:],
                         bytes([v.OP_4, v.OP_EQUALVERIFY, v.OP_0, v.OP_CHECKLOCKTIMEVERIFY]) + bytes([v.OP_ENDIF] * 3))

    def test_vault_rejections(self):
        good = vparams()
        spk = v.vault_script(good)
        for bad in (dict(delay=0), dict(delay=65536), dict(owner_height=0), dict(owner_height=500000000),
                    dict(app_height=500000000), dict(app_height=-1), dict(delay=-1)):
            p = vparams(**bad)
            self.assertIsNone(v.parse_vault(v.vault_script_unchecked(p)), bad)
            with self.assertRaises(v.VaultError):
                v.vault_script(p)
        # non-minimal delay: 144 = 0x90 needs 0x9000; write 5 as a data push instead of OP_5
        p5 = vparams(delay=5)
        s5 = v.vault_script(p5)
        i = 4 + 1 + 32 + 1
        self.assertEqual(s5[i], v.OP_1 + 4)
        self.assertIsNone(v.parse_vault(s5[:i] + b'\x01\x05' + s5[i + 1:]))
        # padded number (0x9000 -> 0x900000)
        j = s5.find(bytes([0x02, 0xe8, 0x03]))        # ownerHeight 1000
        self.assertGreater(j, 0)
        self.assertIsNone(v.parse_vault(s5[:j] + bytes([0x03, 0xe8, 0x03, 0x00]) + s5[j + 3:]))
        # PUSHDATA1 for a 32-byte push
        self.assertIsNone(v.parse_vault(spk[:5] + bytes([v.OP_PUSHDATA1]) + spk[5:]))
        # bad keys
        off_curve = b'\x02' + bytes(31) + b'\x07'
        while v.is_valid_point(off_curve):
            off_curve = off_curve[:-1] + bytes([off_curve[-1] + 1])
        # A-2: "compressed" is the prefix only; an off-curve key parses (it can never sign)
        self.assertEqual(v.parse_vault(v.vault_script(vparams(owner_key=off_curve))), vparams(owner_key=off_curve))
        self.assertIsNone(v.parse_vault(v.vault_script_unchecked(vparams(owner_key=b'\x04' + v.pubkey_of(OWNER)[1:]))))
        # the two setId / ownerKey copies must agree
        k = spk.rfind(SET_A)
        self.assertIsNone(v.parse_vault(spk[:k] + SET_B + spk[k + 32:]))
        # trailing / truncated
        self.assertIsNone(v.parse_vault(spk + b'\x61'))
        self.assertIsNone(v.parse_vault(spk[:-1]))
        self.assertIsNone(v.parse_vault(b''))

    def test_intent(self):
        vp = vparams(delay=10)
        ip = v.intent_for(vp, v.p2pkh_script_of_pubkey(MKEYS[0]))
        spk = v.intent_script(ip)
        self.assertEqual(v.parse_intent(spk), ip)
        self.assertEqual(ip.vault_hash, v.sha256(v.vault_script(vp)))
        self.assertIsNone(v.parse_vault(spk))
        self.assertIsNone(v.parse_intent(v.vault_script(vp)))
        for d in (0, 65536):
            ip.delay = d
            self.assertIsNone(v.parse_intent(v.intent_script_unchecked(ip)))
        ip.delay = 10
        self.assertIsNone(v.parse_intent(spk + b'\x00'))

    def test_bond(self):
        for lt in (1, 16, 17, 1000, 499999999):
            red = v.bond_script(MKEYS[0], lt)
            self.assertEqual(v.parse_bond(red), (MKEYS[0], lt))
        red = v.bond_script(MKEYS[0], 5)
        self.assertIsNone(v.parse_bond(b'\x01\x05' + red[1:]))
        self.assertEqual(len(v.bond_spk(MKEYS[0], 5)), 23)

    def test_selectors(self):
        sigs = [bytes([31]) + bytes(64)] * 2
        self.assertEqual(v.parse_selector(v.vault_unlock_scriptsig(sigs)), (1, sigs))
        self.assertEqual(v.parse_selector(v.vault_owner_scriptsig(b'\x30\x01')), (2, [b'\x30\x01']))
        self.assertEqual(v.parse_selector(v.vault_owner_released_scriptsig(b'\x30')), (3, [b'\x30']))
        self.assertEqual(v.parse_selector(v.vault_app_scriptsig()), (4, []))
        self.assertEqual(v.parse_selector(v.intent_release_scriptsig(), 'I'), (1, []))
        self.assertEqual(v.parse_selector(v.intent_cancel_scriptsig(sigs), 'I'), (2, sigs))
        self.assertIsNone(v.parse_selector(v.vault_app_scriptsig(), 'I'))       # OP_4 is not an I selector
        self.assertIsNone(v.parse_selector(bytes([0x55])))                      # OP_5
        self.assertIsNone(v.parse_selector(b'\x01\x01'))                        # selector as data
        self.assertIsNone(v.parse_selector(b''))
        self.assertIsNone(v.parse_selector(bytes([v.OP_0])))
        self.assertIsNone(v.parse_selector(bytes([v.OP_DUP, v.OP_1])))          # not push-only
        self.assertIsNone(v.parse_selector(bytes([v.OP_1NEGATE])))


class ActTests(unittest.TestCase):
    def _all(self):
        return [
            v.act_set_create(5, 3, 1, 4, v.pubkey_of(ADMIT), flags=1, rate_limit_bps=2500, rate_window=144,
                             liveness_window=1008, bond_min=-1 + 2 * v.COIN, bond_lock_min=2016, maturity=6),
            v.act_set_join(SET_A, MKEYS[0], 499999999, 3),
            v.act_set_heartbeat(SET_A, MKEYS[1]),
            v.act_set_remove(SET_A, MKEYS[2], 1),
            v.equivocation_proof(SET_A, MEMBERS[3], '%064x' % 5, 2, 1, v.sha256(b'a'), 2, v.sha256(b'b')),
            v.act_set_winddown(SET_A),
        ]

    def test_round_trip(self):
        for a in self._all():
            p = v.encode_act(a)
            self.assertEqual(p[:3], b'YV\x01')
            self.assertEqual(len(p), 4 + v.ACT_BODY_SIZE[a['type']])
            d = v.decode_act(p)
            for k, val in a.items():
                self.assertEqual(d[k], val, k)
            self.assertEqual(v.encode_act(d), p)
            sigs = [v.sign_recoverable(MEMBERS[0], v.sha256(p))]
            spk = v.act_script(p, sigs)
            self.assertLessEqual(len(spk), v.ACT_MAX_SCRIPT)
            p2, d2, s2 = v.parse_act_script(spk)
            self.assertEqual((p2, s2), (p, sigs))

    def test_equivocation_key(self):
        a = self._all()[4]
        self.assertEqual(v.equivocation_key(a), MKEYS[3])
        same = dict(a, roleB=a['roleA'], sighashB=a['sighashA'], sigB=a['sigA'])
        with self.assertRaises(v.VaultError):
            v.equivocation_key(same)
        other = dict(a, sigB=v.equivocation_proof(SET_A, MEMBERS[4], '%064x' % 5, 2, 1, v.sha256(b'a'), 2,
                                                  v.sha256(b'b'))['sigB'])
        with self.assertRaises(v.VaultError):
            v.equivocation_key(other)

    def test_rejections(self):
        create = self._all()[0]
        p = v.encode_act(create)
        bad_payloads = [
            b'YV', b'YV\x01', b'Yv\x01\x01' + p[4:], b'YV\x02' + p[3:], b'YV\x01\x00' + p[4:], b'YV\x01\x07' + p[4:],
            p[:-1], p + b'\x00',
        ]
        for b in bad_payloads:
            with self.assertRaises(v.VaultError, msg=b.hex()):
                v.decode_act(b)
        for bad in (dict(seats=0), dict(seats=16), dict(unlockThreshold=0), dict(cancelThreshold=6),
                    dict(slashThreshold=6), dict(flags=2), dict(flags=0x81), dict(rateLimitBps=10001),
                    dict(rateWindow=0), dict(rateWindow=1048577), dict(livenessWindow=0),
                    dict(livenessWindow=1048577), dict(bondMin=0), dict(bondMin=-5), dict(bondMin=v.MAX_MONEY + 1),
                    dict(admitKey='04' + create['admitKey'][2:])):
            with self.assertRaises(v.VaultError, msg=str(bad)):
                v.decode_act(v.encode_act(dict(create, **bad), check=False))
        for edge in (dict(seats=15, unlockThreshold=15, cancelThreshold=15, slashThreshold=15),
                     dict(rateLimitBps=10000), dict(rateLimitBps=0), dict(rateWindow=1048576), dict(bondMin=1),
                     dict(bondMin=v.MAX_MONEY)):
            v.decode_act(v.encode_act(dict(create, **edge)))
        join = self._all()[1]
        with self.assertRaises(v.VaultError):
            v.decode_act(v.encode_act(dict(join, bondLocktime=500000000), check=False))
        rem = self._all()[3]
        with self.assertRaises(v.VaultError):
            v.decode_act(v.encode_act(dict(rem, burn=2), check=False))
        eqv = self._all()[4]
        for bad in (dict(roleA=0), dict(roleB=3), dict(sigA='1b' + eqv['sigA'][2:])):
            with self.assertRaises(v.VaultError, msg=str(bad)):
                v.decode_act(v.encode_act(dict(eqv, **bad), check=False))

    def test_act_script_rejections(self):
        p = v.encode_act(v.act_set_winddown(SET_A))
        sig = v.sign_recoverable(MEMBERS[0], v.sha256(p))
        self.assertIsNone(v.parse_act_script(b'\x6a\x04abcd'))
        self.assertIsNone(v.parse_act_script(v.push(p)))                       # not OP_RETURN
        with self.assertRaises(v.VaultError):
            v.parse_act_script(bytes([v.OP_RETURN, v.OP_PUSHDATA1, len(p)]) + p)  # non-minimal push
        with self.assertRaises(v.VaultError):
            v.parse_act_script(v.act_script(p, [sig[:64]]))
        with self.assertRaises(v.VaultError):
            v.parse_act_script(v.act_script(p) + bytes([v.OP_1]))
        with self.assertRaises(v.VaultError):
            v.parse_act_script(v.act_script(p[:-1]))


# ---------------------------------------------------------------------------
# Model scenarios

class Chain(object):
    """A VaultModel plus a supply of fake funding coins (P2PKH, not script-checked)."""

    def __init__(self, activation=100, **set_kw):
        self.m = v.VaultModel(activation_height=activation)
        self.n = 0
        self.dest = v.p2pkh_script_of_pubkey(v.pubkey_of(v.fixed_secret('vault-test-dest')))

    @property
    def h(self):
        return self.m.tip + 1

    def coin(self, value=10 * v.COIN):
        self.n += 1
        txid = '%064x' % (0xf00d0000 + self.n)
        self.m.add_coin(txid, 0, value, self.dest, 1)
        return [(txid, 0, v.SEQUENCE_FINAL)]

    def block(self, *txs):
        r = self.m.connect_block(self.h, list(txs))
        assert r is None, r
        return r

    def reject(self, tx):
        r = self.m.connect_block(self.h, [tx])
        assert r is not None, 'expected a rejection'
        return r[1]

    def mine_to(self, h):
        while self.h < h:
            self.block()

    def create_set(self, **kw):
        d = dict(seats=5, unlock_threshold=2, cancel_threshold=1, slash_threshold=2, admit_key=v.pubkey_of(ADMIT),
                 rate_window=1000, liveness_window=50, bond_min=v.COIN, bond_lock_min=100, maturity=5)
        d.update(kw)
        tx, _p = v.build_set_create_tx(self.coin(), v.act_set_create(**d))
        self.block(tx)
        return v.txid_internal(v.tx_txid(tx))

    def join_tx(self, sid, i, admit=None, locktime=None):
        lt = self.h + 200 if locktime is None else locktime
        tx, _p = v.build_set_join_tx(self.coin(), sid, MEMBERS[i], v.COIN, lt, [ADMIT] if admit is None else admit)
        return tx

    def join(self, sid, idxs):
        self.block(*[self.join_tx(sid, i) for i in idxs])

    def lock(self, vp, amount=10 * v.COIN):
        tx = v.build_lock_tx(self.coin(amount + v.VAULT_FEE), vp, amount)
        self.block(tx)
        return (v.tx_txid(tx), 0), amount

    def setup(self, members=(0, 1, 2), **kw):
        sid = self.create_set(**kw)
        self.join(sid, members)
        s = self.m.get_set(sid)
        self.mine_to(self.h + s.p['maturity'])
        return sid


class ModelTests(unittest.TestCase):
    def test_lifecycle_release(self):
        c = Chain()
        sid = c.setup()
        s = c.m.get_set(sid)
        self.assertEqual(len(s.current(c.h)), 3)
        self.assertFalse(c.m.is_released(sid, c.h))
        vp = vparams(set_id=sid, cancel_set_id=sid, delay=10)
        out, val = c.lock(vp)
        self.assertEqual(s.locked_value, val)
        tx = v.build_unlock_tx(out, vp, val, [(c.dest, val)], fee_vin=c.coin(), member_secrets=MEMBERS[:2])
        c.block(tx)
        self.assertEqual(c.m.get_set(sid).locked_value, 0)
        ip = v.intent_for(vp, c.dest)
        iout = (v.tx_txid(tx), 0)
        coin_h = c.m.tip
        # BIP68 / CSV boundary: release valid from coinHeight + delay
        c.mine_to(coin_h + 9)
        rel = v.build_release_tx(iout, ip, val, c.dest, fee_vin=c.coin())
        self.assertEqual(c.h, coin_h + 9)
        self.assertEqual(c.reject(rel), 'bad-txns-vault-timelock')
        c.block()
        self.assertEqual(c.h, coin_h + 10)
        c.block(rel)

    def test_unlock_needs_threshold_of_current_members(self):
        c = Chain()
        sid = c.setup()
        vp = vparams(set_id=sid, cancel_set_id=sid, delay=10)
        out, val = c.lock(vp)
        one = v.build_unlock_tx(out, vp, val, [(c.dest, val)], fee_vin=c.coin(), member_secrets=MEMBERS[:1])
        self.assertEqual(c.reject(one), 'script-setsig')
        dup = v.build_unlock_tx(out, vp, val, [(c.dest, val)], fee_vin=c.coin(), member_secrets=[MEMBERS[0]] * 2)
        self.assertEqual(c.reject(dup), 'script-setsig')
        outsider = v.build_unlock_tx(out, vp, val, [(c.dest, val)], fee_vin=c.coin(),
                                     member_secrets=[MEMBERS[0], MEMBERS[5]])
        self.assertEqual(c.reject(outsider), 'script-setsig')
        wrong_branch = v.build_unlock_tx(out, vp, val, [(c.dest, val)], fee_vin=c.coin(),
                                         member_secrets=MEMBERS[:2], branch_id=0x76B809BB)
        self.assertEqual(c.reject(wrong_branch), 'script-setsig')
        leak = v.build_unlock_tx(out, vp, val, [(c.dest, val - 1)], fee_vin=c.coin(),
                                 change=(1, c.dest), member_secrets=MEMBERS[:2])
        self.assertEqual(c.reject(leak), 'bad-vault-covenant')

    def test_cancel_boundary(self):
        c = Chain()
        sid = c.setup()
        vp = vparams(set_id=sid, cancel_set_id=sid, delay=10)
        out, val = c.lock(vp)
        tx = v.build_unlock_tx(out, vp, val, [(c.dest, val)], fee_vin=c.coin(), member_secrets=MEMBERS[:2])
        c.block(tx)
        coin_h = c.m.tip
        ip = v.intent_for(vp, c.dest)
        iout = (v.tx_txid(tx), 0)
        c.mine_to(coin_h + 10)            # h - coinHeight = delay: too late
        late = v.build_cancel_tx(iout, ip, val, vp, fee_vin=c.coin(), member_secrets=MEMBERS[:1])
        self.assertEqual(c.m.check_tx(late), 'bad-vault-cancel-late')
        c.m.disconnect_block()            # back to h - coinHeight = delay - 1
        self.assertEqual(c.h, coin_h + 9)
        ok = v.build_cancel_tx(iout, ip, val, vp, fee_vin=c.coin(), member_secrets=MEMBERS[:1])
        c.block(ok)
        self.assertEqual(c.m.get_set(sid).locked_value, val)
        self.assertIsNotNone(v.parse_vault(c.m.coins[(v.tx_txid(ok), 0)].spk))

    def test_intent_only_from_covenant(self):
        c = Chain()
        sid = c.setup()
        vp = vparams(set_id=sid, cancel_set_id=sid)
        ip = v.intent_for(vp, c.dest)
        tx = v.make_tx(c.coin(), [(v.COIN, v.intent_script(ip))])
        self.assertEqual(c.reject(tx), 'bad-vault-intent-create')

    def test_vault_needs_set_from_earlier_block(self):
        c = Chain()
        create, _p = v.build_set_create_tx(c.coin(), v.act_set_create(3, 2, 1, 2, v.pubkey_of(ADMIT)))
        sid = v.txid_internal(v.tx_txid(create))
        lock = v.build_lock_tx(c.coin(), vparams(set_id=sid, cancel_set_id=sid), v.COIN)
        self.assertEqual(c.m.connect_block(c.h, [create, lock]), (1, 'bad-vault-unknown-set'))
        c.block(create)
        c.block(lock)
        bad = v.build_lock_tx(c.coin(), vparams(set_id=sid, cancel_set_id=SET_B), v.COIN)
        self.assertEqual(c.reject(bad), 'bad-vault-unknown-set')

    def test_one_template_input(self):
        c = Chain()
        sid = c.setup()
        vp = vparams(set_id=sid, cancel_set_id=sid, owner_height=50)
        o1, val = c.lock(vp)
        o2, _ = c.lock(vp)
        tx = v.make_tx([(o1[0], o1[1], 0xFFFFFFFE), (o2[0], o2[1], 0xFFFFFFFE)], [(2 * val - v.VAULT_FEE, c.dest)],
                       lock_time=60)
        self.assertEqual(c.reject(tx), 'bad-vault-template-count')

    def test_dormancy_owner_released(self):
        c = Chain()
        sid = c.setup(liveness_window=20, cancel_threshold=2)
        s = c.m.get_set(sid)
        vp = vparams(set_id=sid, cancel_set_id=sid, owner_height=499999999)
        out, val = c.lock(vp)
        # member 0 heartbeats, members 1 and 2 do not
        mature = s.members[MKEYS[0]].join_height + 5
        c.mine_to(mature + 15)
        hb, _p = v.build_set_heartbeat_tx(c.coin(), sid, MEMBERS[0])
        c.block(hb)
        hb_h = c.m.tip
        spend = v.build_owner_spend_tx(out, v.vault_script(vp), val, OWNER, c.dest, v.SEL_OWNER_RELEASED)
        # live while two current members acted in the window: lastAct(1, 2) = mature
        c.mine_to(mature + 20)
        self.assertFalse(c.m.is_dormant(sid, c.h))
        self.assertEqual(c.reject(spend), 'script-notreleased')
        c.block()
        self.assertEqual(c.h, mature + 21)
        self.assertTrue(c.m.is_dormant(sid, c.h))
        self.assertTrue(c.m.get_set(sid).members[MKEYS[0]].last_act == hb_h)
        c.block(spend)
        self.assertEqual(c.m.get_set(sid).locked_value, 0)

    def test_heartbeat_rules(self):
        c = Chain()
        sid = c.create_set()
        c.join(sid, [0])
        hb, _p = v.build_set_heartbeat_tx(c.coin(), sid, MEMBERS[0])
        self.assertEqual(c.reject(hb), 'bad-vault-act-heartbeat')     # not yet mature
        c.mine_to(c.h + 5)
        hb, _p = v.build_set_heartbeat_tx(c.coin(), sid, MEMBERS[0])
        c.block(hb)
        wrong, _p = v.build_act_tx(c.coin(), v.act_set_heartbeat(sid, MKEYS[0]), [MEMBERS[1]])
        self.assertEqual(c.reject(wrong), 'bad-vault-act-heartbeat')

    def test_rate_limit_epoch_boundary(self):
        c = Chain(activation=100)
        sid = c.setup(rate_limit_bps=5000, rate_window=50)
        vp = vparams(set_id=sid, cancel_set_id=sid)
        out, val = c.lock(vp)
        s = c.m.get_set(sid)
        self.assertEqual(s.epoch_basis, 0)             # the creation epoch's basis is 0: nothing unlocks
        u = v.build_unlock_tx(out, vp, val, [(c.dest, v.COIN)], relock_value=val - v.COIN, fee_vin=c.coin(),
                              member_secrets=MEMBERS[:2])
        self.assertEqual(c.reject(u), 'bad-vault-rate')
        c.mine_to(150)                                  # epoch 3: basis = 10 YEC-worth, cap 5
        u = v.build_unlock_tx(out, vp, val, [(c.dest, 4 * v.COIN)], relock_value=6 * v.COIN, fee_vin=c.coin(),
                              member_secrets=MEMBERS[:2])
        c.block(u)
        s = c.m.get_set(sid)
        self.assertEqual((s.epoch, s.epoch_basis, s.epoch_used, s.locked_value), (3, val, 4 * v.COIN, 6 * v.COIN))
        out2 = (v.tx_txid(u), 1)
        u2 = v.build_unlock_tx(out2, vp, 6 * v.COIN, [(c.dest, 2 * v.COIN)], relock_value=4 * v.COIN,
                               fee_vin=c.coin(), member_secrets=MEMBERS[:2])
        self.assertEqual(c.reject(u2), 'bad-vault-rate')                     # 4 + 2 > 5
        u1 = v.build_unlock_tx(out2, vp, 6 * v.COIN, [(c.dest, v.COIN)], relock_value=5 * v.COIN,
                               fee_vin=c.coin(), member_secrets=MEMBERS[:2])
        self.assertIsNone(c.m.check_tx(u1))                                 # 4 + 1 = 5: exactly the cap
        c.mine_to(199)
        self.assertEqual(c.reject(u2), 'bad-vault-rate')                     # still epoch 3 at h = 199
        c.block()                                                            # h = 200: epoch 4, basis 6, cap 3
        u2b = v.build_unlock_tx(out2, vp, 6 * v.COIN, [(c.dest, 2 * v.COIN)], relock_value=4 * v.COIN,
                                fee_vin=c.coin(), member_secrets=MEMBERS[:2])
        c.block(u2b)
        s = c.m.get_set(sid)
        self.assertEqual((s.epoch, s.epoch_basis, s.epoch_used), (4, 6 * v.COIN, 2 * v.COIN))

    def test_equivocation(self):
        c = Chain()
        sid = c.setup()
        s = c.m.get_set(sid)
        bond = s.members[MKEYS[1]].bond_outpoint
        proof = v.equivocation_proof(sid, MEMBERS[1], '%064x' % 99, 0, 1, v.sha256(b'A'), 1, v.sha256(b'B'))
        tx, _p = v.build_set_equivocation_tx(c.coin(), proof)
        c.block(tx)
        m = c.m.get_set(sid).members[MKEYS[1]]
        self.assertEqual((m.status, m.bond_frozen), (v.MEMBER_EJECTED, True))
        # a second proof against the same member: bond already frozen
        again, _p = v.build_set_equivocation_tx(c.coin(), proof)
        self.assertEqual(c.reject(again), 'bad-vault-act-equivocation')
        # the frozen bond cannot be spent, even after its locktime
        c.mine_to(m.bond_locktime + 1)
        spend = v.build_bond_spend_tx(bond, MEMBERS[1], m.bond_value, m.bond_locktime, c.dest)
        self.assertEqual(c.reject(spend), 'bad-vault-bond-frozen')
        # an outsider's "proof" convicts nobody
        p2 = v.equivocation_proof(sid, MEMBERS[5], '%064x' % 99, 0, 1, v.sha256(b'A'), 2, v.sha256(b'A'))
        t2, _p = v.build_set_equivocation_tx(c.coin(), p2)
        self.assertEqual(c.reject(t2), 'bad-vault-act-equivocation')

    def test_remove_and_withdraw(self):
        c = Chain()
        sid = c.setup(members=(0, 1, 2, 3))
        s = c.m.get_set(sid)
        # removal needs slashThreshold (2) current members other than the target
        bad, _p = v.build_set_remove_tx(c.coin(), sid, MKEYS[0], [MEMBERS[0], MEMBERS[1]])
        self.assertEqual(c.reject(bad), 'bad-vault-act-sig')
        rm, _p = v.build_set_remove_tx(c.coin(), sid, MKEYS[0], [MEMBERS[1], MEMBERS[2]], burn=0)
        burn, _p = v.build_set_remove_tx(c.coin(), sid, MKEYS[3], [MEMBERS[1], MEMBERS[2]], burn=1)
        c.block(rm, burn)
        s = c.m.get_set(sid)
        m0, m3, m1 = s.members[MKEYS[0]], s.members[MKEYS[3]], s.members[MKEYS[1]]
        self.assertEqual((m0.status, m0.bond_frozen), (v.MEMBER_REMOVED, False))
        self.assertEqual((m3.status, m3.bond_frozen), (v.MEMBER_REMOVED, True))
        again, _p = v.build_set_remove_tx(c.coin(), sid, MKEYS[0], [MEMBERS[1], MEMBERS[2]])
        self.assertEqual(c.reject(again), 'bad-vault-act-remove')
        c.mine_to(max(m0.bond_locktime, m1.bond_locktime) + 1)
        c.block(v.build_bond_spend_tx(m0.bond_outpoint, MEMBERS[0], m0.bond_value, m0.bond_locktime, c.dest))
        self.assertEqual(c.reject(v.build_bond_spend_tx(m3.bond_outpoint, MEMBERS[3], m3.bond_value,
                                                        m3.bond_locktime, c.dest)), 'bad-vault-bond-frozen')
        c.block(v.build_bond_spend_tx(m1.bond_outpoint, MEMBERS[1], m1.bond_value, m1.bond_locktime, c.dest))
        self.assertEqual(c.m.get_set(sid).members[MKEYS[1]].status, v.MEMBER_WITHDRAWN)
        # a burned member rejoins with a fresh bond: the old bond stays frozen
        c.block(c.join_tx(sid, 3))            # one current member left (< slashThreshold): admitKey admits
        self.assertEqual(c.m.get_set(sid).members[MKEYS[3]].status, v.MEMBER_ACTIVE)
        self.assertEqual(c.reject(v.build_bond_spend_tx(m3.bond_outpoint, MEMBERS[3], m3.bond_value,
                                                        m3.bond_locktime, c.dest)), 'bad-vault-bond-frozen')

    def test_join_admission_and_seats(self):
        c = Chain()
        sid = c.setup(members=(0, 1), seats=3)
        # two current members = slashThreshold: admission now needs them, not the admitKey
        self.assertEqual(c.reject(c.join_tx(sid, 2)), 'bad-vault-act-sig')
        c.block(c.join_tx(sid, 2, admit=[MEMBERS[0], MEMBERS[1]]))
        self.assertEqual(c.reject(c.join_tx(sid, 3, admit=[MEMBERS[0], MEMBERS[1]])), 'bad-vault-act-join')  # seats
        self.assertEqual(c.reject(c.join_tx(sid, 0, admit=[MEMBERS[1], MEMBERS[2]])), 'bad-vault-act-join')
        low = c.join_tx(sid, 4, admit=[MEMBERS[0], MEMBERS[1]], locktime=c.h + 99)
        self.assertIn(c.m.check_tx(low), ('bad-vault-act-join', 'bad-vault-act-bond'))

    def test_open_set_join(self):
        c = Chain()
        sid = c.create_set(flags=v.SET_FLAG_OPEN)
        c.block(c.join_tx(sid, 0, admit=[]))
        self.assertEqual(c.reject(c.join_tx(sid, 1, admit=[ADMIT])), 'bad-vault-act-sig')

    def test_winddown(self):
        c = Chain()
        sid = c.setup(liveness_window=30)
        hb = [v.build_set_heartbeat_tx(c.coin(), sid, MEMBERS[i])[0] for i in range(3)]
        c.block(*hb)
        one, _p = v.build_set_winddown_tx(c.coin(), sid, [MEMBERS[0]])
        self.assertEqual(c.reject(one), 'bad-vault-act-sig')
        wd, _p = v.build_set_winddown_tx(c.coin(), sid, [MEMBERS[0], MEMBERS[1]])
        c.block(wd)
        wd_h = c.m.tip
        self.assertEqual(c.reject(c.join_tx(sid, 4)), 'bad-vault-act-join')
        again, _p = v.build_set_winddown_tx(c.coin(), sid, [MEMBERS[0], MEMBERS[1]])
        self.assertEqual(c.reject(again), 'bad-vault-act-winddown')
        # keep members live with heartbeats; release comes from the wind-down alone
        c.mine_to(wd_h + 20)
        c.block(*[v.build_set_heartbeat_tx(c.coin(), sid, MEMBERS[i])[0] for i in range(3)])
        c.mine_to(wd_h + 29)
        self.assertFalse(c.m.is_released(sid, c.h))
        c.block()
        self.assertEqual(c.h, wd_h + 30)
        self.assertTrue(c.m.is_released(sid, c.h))
        self.assertFalse(c.m.is_dormant(sid, wd_h + 30))

    def test_owner_branch_and_app(self):
        c = Chain()
        sid = c.setup()
        vp = vparams(set_id=sid, cancel_set_id=sid, owner_height=c.h + 5, app_height=c.h + 3)
        out, val = c.lock(vp)
        early = v.build_owner_spend_tx(out, v.vault_script(vp), val, OWNER, c.dest, v.SEL_OWNER,
                                       lock_time=vp.owner_height)
        self.assertEqual(c.reject(early), 'bad-txns-nonfinal')
        wrong_key = v.build_owner_spend_tx(out, v.vault_script(vp), val, MEMBERS[0], c.dest, v.SEL_OWNER,
                                           lock_time=vp.owner_height)
        app = v.build_app_tx(out, vp, val, [(c.dest, val)], fee_vin=c.coin())
        self.assertEqual(c.m.check_tx(app), 'bad-txns-nonfinal')
        c.mine_to(vp.app_height + 1)
        self.assertIsNone(c.m.check_tx(app))
        c.mine_to(vp.owner_height + 1)
        self.assertEqual(c.reject(wrong_key), 'script-ownersig')
        c.block(early)
        disabled = vparams(set_id=sid, cancel_set_id=sid, app_height=0)
        o2, v2 = c.lock(disabled)
        self.assertEqual(c.reject(v.build_app_tx(o2, disabled, v2, [(c.dest, v2)], fee_vin=c.coin())),
                         'bad-vault-app-disabled')

    def test_two_acts_and_time_lock(self):
        c = Chain()
        sid = c.create_set()
        p = v.encode_act(v.act_set_winddown(sid))
        tx = v.make_tx(c.coin(), [(0, v.act_script(p)), (0, v.act_script(p))])
        self.assertEqual(c.reject(tx), 'bad-vault-act-count')
        tl = v.make_tx([(c.coin()[0][0], 0, v.SEQUENCE_TYPE_FLAG | 5)], [(v.COIN, c.dest)])
        self.assertEqual(c.reject(tl), 'bad-txns-vault-timelock')

    def test_undo(self):
        c = Chain()
        sid = c.setup()
        before = json.dumps(c.m.set_info(sid), sort_keys=True)
        tip = c.m.tip
        c.block(*[v.build_set_heartbeat_tx(c.coin(), sid, MEMBERS[i])[0] for i in range(2)])
        self.assertNotEqual(json.dumps(c.m.set_info(sid, tip + 1), sort_keys=True), before)
        c.m.disconnect_block()
        self.assertEqual(c.m.tip, tip)
        self.assertEqual(json.dumps(c.m.set_info(sid), sort_keys=True), before)

    def test_unknown_set_is_released(self):
        self.assertTrue(v.VaultModel().is_released(SET_B, 10))


class VectorTests(unittest.TestCase):
    def test_vectors_reproducible(self):
        doc = gvv.build()
        self.assertEqual(gvv.dumps(gvv.build()), gvv.dumps(doc))
        if os.path.exists(VECTORS):
            with open(VECTORS) as f:
                self.assertEqual(f.read(), gvv.dumps(doc), 'vault_vectors.json is stale: run gen_vault_vectors.py')


if __name__ == '__main__':
    unittest.main()
