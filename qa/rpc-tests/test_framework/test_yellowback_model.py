#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for yellowback_model.py -- plain unittest, no node.

Run from qa/rpc-tests:

    ../../../../.venv/bin/python -m unittest test_framework.test_yellowback_model -v

or from this directory:

    ../../../../.venv/bin/python test_yellowback_model.py -v

Regenerate the golden vector (after a deliberate protocol or serialisation change only):

    ../../../../.venv/bin/python test_yellowback_model.py --write-golden

Every test case is tagged ``# Rule: <ID>`` on the line before it (plan N36).
"""

import json
import os
import sys
import unittest

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from test_framework import yellowback_model as ym
    from test_framework import yellowback_attest as ya
else:
    from . import yellowback_model as ym
    from . import yellowback_attest as ya

from decimal import Decimal  # noqa: E402  (used by the getblock-2 dict test)

GOLDEN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yellowback_golden.json')

# The pinned state hash of the golden sequence (regtest params {1, 0, 0, 0, 3, scriptsig}).  The C++ unit test
# ``statehash_golden_vector`` replays yellowback_golden.json and must produce this hex.
GOLDEN_STATE_HASH = 'abe131e0cd68cd438449ce22969c7b331930ca3b9e4324ed9d841e90a340a4fe'

# secp256k1 generator, compressed: a valid owner key that needs no library
G_PUBKEY = bytes.fromhex('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
G2_PUBKEY = bytes.fromhex('02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5')  # 2G
BAD_PUBKEY = b'\x02' + b'\x00' * 32   # x = 0: 7 is not a square mod p

KEY1 = ym.hash160(b'yellowback-golden-miner-1')
KEY2 = ym.hash160(b'yellowback-golden-miner-2')
KEY3 = ym.hash160(b'yellowback-golden-miner-3')
MINERS = [KEY1, KEY2, KEY3]
OWNER_KEYHASH = ym.hash160(b'owner')
SIG71 = bytes(range(1, 72))          # a placeholder signature push; the model verifies no signature
# The framework's fixed regtest attestor / bond keys (yellowback_attest.py): [(secret32, pubkey33)]
ATTESTORS = [(sec, bytes.fromhex(pub)) for sec, pub in ya.attestor_keys(5)]
BONDS = [(sec, bytes.fromhex(pub)) for sec, pub in ya.bond_keys(5)]


def outpoint_hex(i):
    return ym.sha256(b'funding-%d' % i)[::-1].hex()


class Chain(object):
    """A synthetic chain: builds coinbases and real (serialised, hashed) v4 transactions."""

    def __init__(self, params, issued_before_start=0):
        self.params = params
        self.model = ym.YellowbackModel(params, issued_before_start)
        self.height = 0
        self.blocks = []       # golden document rows
        self.funding = 0

    def block_hash(self, h):
        return ym.sha256(b'golden-block-%d' % h)[::-1].hex()

    def coinbase(self, h, scriptsig):
        raw = ym.serialize_tx_v4([(None, 0xFFFFFFFF, scriptsig, 0xFFFFFFFF)],
                                 [(ym.regtest_subsidy(h), ym.p2pkh_script(KEY1))])
        return raw

    def mine(self, tag=None, txs=(), extranonce=b'', raw_scriptsig=None):
        """Mine the next block.  ``tag`` = (flags, price, mask, key) or None; ``txs`` = raw hex list."""
        self.height += 1
        h = self.height
        if raw_scriptsig is not None:
            ss = raw_scriptsig
        else:
            ss = ym.height_prefix(h) + extranonce
            if tag is not None:
                ss += ym.tag_push(*tag)
        cb = self.coinbase(h, ss)
        subsidy = ym.regtest_subsidy(h)
        raws = [cb.hex()] + list(txs)
        parsed = [ym.tx_from_hex(x) for x in raws]
        verdict = self.model.feed_block(h, self.block_hash(h), ss.hex(), subsidy, parsed[1:])
        self.blocks.append({'height': h, 'hash': self.block_hash(h), 'subsidyZat': subsidy, 'txs': raws})
        return verdict

    def mine_n(self, n, price_fn=None, signal=True, key_fn=None):
        for _ in range(n):
            h = self.height + 1
            key = MINERS[h % 3] if key_fn is None else key_fn(h)
            price = 0 if price_fn is None else price_fn(h)
            self.mine((1 if signal else 0, price, 0, key))

    def fund_input(self):
        self.funding += 1
        return (outpoint_hex(self.funding), 0, b'', 0xFFFFFFFF)

    # -- transaction builders (section 3.5 shapes) --------------------------

    def carrier_input(self, bundle):
        """A carrier-shaped input (section 3.4) whose redeem script commits to ``bundle``; the model
        verifies no script, so the signature push is a placeholder."""
        redeem = ya.carrier_script(G2_PUBKEY, ym.sha256(bundle))
        t, n, _ss, seq = self.fund_input()
        return (t, n, ya.carrier_scriptsig(bundle, SIG71, redeem), seq)

    def mint_tx(self, cents, lock_blocks, ref_height, collateral, fee_key=None, fee_value=None,
                owner=G_PUBKEY, term_class=0, yed_inputs=(), fee_vout=None, vout0_script=None,
                opret_at=2, lock_height=None, carrier=None, attest_fee=None):
        """``carrier`` = a bundle (bytes) carried by an extra input; ``attest_fee`` = (bond key hash, zat)
        paid at vout 4 (after the pool fee) and named by attestFeeVout."""
        lock = ref_height + lock_blocks if lock_height is None else lock_height
        script = ym.vault_script(lock, owner, lock + self.params.grace)
        vin = [self.fund_input()] + [(t, n, b'', 0xFFFFFFFF) for t, n in yed_inputs]
        if carrier is not None:
            vin.append(self.carrier_input(carrier))
        if fee_vout is None:
            fee_vout = 3 if fee_key is not None else ym.FEE_VOUT_NONE
        attest_fee_vout = 4 if attest_fee is not None else ym.FEE_VOUT_NONE
        payload = ym.encode_mint(term_class, cents, lock, ref_height, owner, fee_vout, attest_fee_vout)
        vout0 = ym.p2sh_script(script) if vout0_script is None else vout0_script
        vouts = [(collateral, vout0), (self.params.token_value, ym.p2pkh_script(OWNER_KEYHASH))]
        opret = (0, bytes([ym.OP_RETURN]) + ym.push(payload))
        if opret_at == 2:
            vouts.append(opret)
        elif opret_at == 1:
            vouts.insert(1, opret)
        if fee_key is not None:
            if fee_value is None:
                fee_value = ym.fee_zat(collateral, self.params.fee_min, self.params.fee_bps)
            vouts.append((fee_value, ym.p2pkh_script(fee_key)))
        if attest_fee is not None:
            vouts.append((attest_fee[1], ym.p2pkh_script(attest_fee[0])))
        return ym.serialize_tx_v4(vin, vouts, 0, ref_height + self.params.ref_window).hex()

    def transfer_tx(self, yed_inputs, assignments, opret_index=None):
        """assignments = [(vout, cents)]; token outputs at each assigned vout, OP_RETURN after them."""
        vin = [(t, n, b'', 0xFFFFFFFF) for t, n in yed_inputs] + [self.fund_input()]
        n_out = (max([v for v, _ in assignments]) + 1) if assignments else 0
        vouts = [(self.params.token_value, ym.p2pkh_script(OWNER_KEYHASH)) for _ in range(n_out)]
        opret = (0, bytes([ym.OP_RETURN]) + ym.push(ym.encode_transfer(assignments)))
        if opret_index is None:
            vouts.append(opret)
        else:
            vouts.insert(opret_index, opret)
        return ym.serialize_tx_v4(vin, vouts).hex()

    def spend_tx(self, vault_op, vault_script, path, yed_inputs, ref_height, fee_key, fee_value,
                 assignments=(), payload=None, collateral_out=10 ** 9, selector=None, script_sig=None,
                 extra_vaults=(), fee_vout=1, first_input=None, carrier=None, attest_fee=None, residual=None):
        """A vault spend: vin[0] = vault (owner: <sig> OP_1 <script>; claim: OP_0 <script>),
        vin[1..] = YED inputs, then the carrier input when ``carrier`` (a bundle) is given; vout[0] =
        collateral, vout[1] = fee, vout[2] = OP_RETURN, vout[3..] = assigned token outputs, then the
        attestor fee (``attest_fee`` = (bond key hash, zat)) and the residual (``residual`` = (owner key
        hash, zat)) when given."""
        if script_sig is None:
            if selector is None:
                selector = bytes([ym.OP_1]) if path == 'owner' else bytes([ym.OP_0])
            script_sig = (ym.push(SIG71) if path == 'owner' else b'') + selector + ym.push(vault_script)
        vin = [(vault_op[0], vault_op[1], script_sig, 0xFFFFFFFE)]
        if first_input is not None:
            vin.insert(0, first_input)
        vin += [(t, n, b'', 0xFFFFFFFF) for t, n in yed_inputs]
        vin += [(t, n, b'\x00' + ym.push(vault_script), 0xFFFFFFFE) for t, n in extra_vaults]
        if carrier is not None:
            vin.append(self.carrier_input(carrier))
        vouts = [(collateral_out, ym.p2pkh_script(OWNER_KEYHASH))]
        vouts.append((fee_value, ym.p2pkh_script(fee_key)) if fee_key is not None else (1000, ym.p2pkh_script(OWNER_KEYHASH)))
        attest_fee_vout = 3 + len(assignments) if attest_fee is not None else ym.FEE_VOUT_NONE
        if payload is None:
            payload = ym.encode_redeem(ref_height, fee_vout, list(assignments), attest_fee_vout)
        if payload != b'':
            vouts.append((0, bytes([ym.OP_RETURN]) + ym.push(payload)))
        for _ in assignments:
            vouts.append((self.params.token_value, ym.p2pkh_script(OWNER_KEYHASH)))
        if attest_fee is not None:
            vouts.append((attest_fee[1], ym.p2pkh_script(attest_fee[0])))
        if residual is not None:
            vouts.append((residual[1], ym.p2pkh_script(residual[0])))
        return ym.serialize_tx_v4(vin, vouts, 0, ref_height + self.params.ref_window).hex()

    # -- v3 builders (section 3.5) -------------------------------------------

    def register_tx(self, hot_pubkey, bond_pubkey, bond_locktime, bond_zat, flags=0):
        vin = [self.fund_input()]
        vouts = [(bond_zat, ym.p2sh_script(ya.bond_script(bond_pubkey, bond_locktime))),
                 (0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_attestor_register(hot_pubkey, bond_pubkey, bond_locktime, flags))),
                 (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts).hex()

    def notice_tx(self, vault_op, ref_height, bundle):
        vin = [self.fund_input(), self.carrier_input(bundle)]
        vouts = [(0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_claim_notice(vault_op[0], vault_op[1], ref_height))),
                 (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts, 0, ref_height + self.params.ref_window).hex()

    def equivocation_tx(self, att_a, att_b):
        vin = [self.carrier_input(ya.encode_bundle([att_a, att_b]))]
        vouts = [(0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_equivocation())), (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts).hex()

    def revive_tx(self, att74):
        vin = [self.fund_input()]
        vouts = [(0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_revive(att74))), (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts).hex()

    def bond_spend_tx(self, bond_op, bond_script, lock_time):
        vin = [(bond_op[0], bond_op[1], ym.push(SIG71) + ym.push(bond_script), 0xFFFFFFFE)]
        return ym.serialize_tx_v4(vin, [(10 ** 9 - 1000, ym.p2pkh_script(OWNER_KEYHASH))], lock_time).hex()

    def bundle_for(self, ref_height, selector, prices, cited=None, skip=()):
        """The bundle for (R, selector) signed with the fixed regtest attestor keys: every selected seq
        not in ``skip`` signs ``prices[seq]`` (or ``prices['*']``) citing ``cited`` (default R)."""
        selected = self.model.selected(ref_height, selector)
        cited = ref_height if cited is None else cited
        atts = []
        for seq in selected:
            if seq in skip:
                continue
            price = prices.get(seq, prices.get('*'))
            atts.append(ya.sign_attestation(ATTESTORS[seq][0], seq, price, cited, self.block_hash(cited)))
        return ya.encode_bundle(atts), selected


def txid_of(raw_hex):
    return ym.tx_from_hex(raw_hex).txid


def activated_chain(params=None, **kw):
    """A chain whose activation is ACTIVE at 128 and whose windows are full (quotes at 50,000)."""
    params = params or ym.Params.regtest(1)
    c = Chain(params, **kw)
    c.mine_n(135, price_fn=lambda h: 50_000)
    assert c.model.activation.status == ym.ACTIVE
    return c


def collateral_for(c, cents, ref_height, term_class=0, p_mint=None):
    s = c.model.snapshot(ref_height)
    req = ym.required_zat(cents, ym.min_ratio_bps(c.params.base_ratio_bps[term_class], s.sigma_mult_bps),
                          s.p_mint if p_mint is None else p_mint)
    return ym.ceil_div(req, 1000) * 1000


# ===========================================================================
# section 3.2  Tag decoder

class TagTests(unittest.TestCase):
    P = ym.Params.regtest(1)

    def ss(self, h, body, extra=b''):
        return ym.height_prefix(h) + extra + body

    # Rule: TAG-1
    def test_tag_after_height_prefix(self):
        t = ym.find_tag(self.ss(17, ym.tag_push(1, 50_000, 3, KEY1)), 17, self.P)
        self.assertEqual(t, ym.Tag(1, 1, 50_000, 3, KEY1))
        self.assertTrue(t.signal and t.is_quote)

    # Rule: TAG-1
    def test_tag_after_extranonce_bytes(self):
        ss = self.ss(300, ym.tag_push(0, 50_000, 0, KEY2), extra=b'\x08' + b'\xaa' * 8)
        self.assertEqual(ym.find_tag(ss, 300, self.P).payout_key, KEY2)

    # Rule: TAG-1
    def test_tag1_magic_without_push_opcode_is_no_tag(self):
        ss = ym.height_prefix(20) + ym.encode_tag(1, 50_000, 0, KEY1)   # magic, no 0x24
        self.assertIsNone(ym.find_tag(ss, 20, self.P))

    # Rule: TAG-1
    def test_pattern_inside_height_prefix_is_skipped(self):
        # a height push whose bytes happen to be the pattern is not scanned; here the whole tag lies in the prefix region
        ss = ym.tag_push(1, 50_000, 0, KEY1)
        self.assertIsNone(ym.find_tag(ss, 0x24594544, self.P))
        # and below the prefix length there is no tag at all
        self.assertIsNone(ym.find_tag(b'\x01', 300, self.P))

    # Rule: TAG-1
    def test_short_body_is_no_tag(self):
        ss = self.ss(30, ym.tag_push(1, 50_000, 0, KEY1)[:-1])
        self.assertIsNone(ym.find_tag(ss, 30, self.P))

    # Rule: TAG-2
    def test_invalid_version_flags_price(self):
        self.assertIsNone(ym.find_tag(self.ss(5, ym.tag_push(1, 50_000, 0, KEY1, version=2)), 5, self.P))
        self.assertIsNone(ym.find_tag(self.ss(5, ym.tag_push(0x02, 50_000, 0, KEY1)), 5, self.P))
        self.assertIsNone(ym.find_tag(self.ss(5, ym.tag_push(1, 99, 0, KEY1)), 5, self.P))
        self.assertIsNone(ym.find_tag(self.ss(5, ym.tag_push(1, 100_000_001, 0, KEY1)), 5, self.P))
        self.assertIsNotNone(ym.find_tag(self.ss(5, ym.tag_push(1, 100, 0, KEY1)), 5, self.P))
        self.assertIsNotNone(ym.find_tag(self.ss(5, ym.tag_push(1, 100_000_000, 0, KEY1)), 5, self.P))

    # Rule: TAG-3
    def test_kinds(self):
        q = ym.find_tag(self.ss(5, ym.tag_push(0, 777, 0, KEY1)), 5, self.P)
        s = ym.find_tag(self.ss(5, ym.tag_push(1, 0, 0, KEY1)), 5, self.P)
        self.assertEqual((q.kind, q.signal), ('quote', False))
        self.assertEqual((s.kind, s.signal), ('signal', True))

    # Rule: TAG-5
    def test_first_occurrence_decides(self):
        bad = ym.tag_push(0x04, 50_000, 0, KEY1)      # reserved flag: TAG-2 fails
        good = ym.tag_push(1, 50_000, 0, KEY2)
        self.assertIsNone(ym.find_tag(self.ss(40, bad + good), 40, self.P))
        first = ym.find_tag(self.ss(40, good + bad), 40, self.P)
        self.assertEqual(first.payout_key, KEY2)


# ===========================================================================
# section 3.3  Payload codec

class PayloadTests(unittest.TestCase):

    # Rule: MINT-1
    def test_mint_roundtrip(self):
        b = ym.encode_mint(1, 12_345, 500, 460, G_PUBKEY, 3, 4)
        self.assertEqual(len(b), 52)
        p = ym.decode_payload(b)
        self.assertEqual((p.type, p.term_class, p.cents, p.lock_height, p.ref_height, p.owner_pubkey, p.fee_vout, p.attest_fee_vout),
                         (ym.PAYLOAD_MINT, 1, 12_345, 500, 460, G_PUBKEY, 3, 4))
        self.assertEqual(ym.decode_payload(ym.encode_mint(1, 12_345, 500, 460, G_PUBKEY, 3)).attest_fee_vout, 0xFF)

    # Rule: XFER-1
    def test_transfer_and_redeem_roundtrip(self):
        t = ym.decode_payload(ym.encode_transfer([(0, 100), (1, 200)]))
        self.assertEqual((t.type, t.assignments), (ym.PAYLOAD_TRANSFER, [(0, 100), (1, 200)]))
        r = ym.decode_payload(ym.encode_redeem(99, 0xFF, [(3, 5)], 2))
        self.assertEqual((r.type, r.ref_height, r.fee_vout, r.attest_fee_vout, r.assignments), (ym.PAYLOAD_REDEEM, 99, 0xFF, 2, [(3, 5)]))
        self.assertEqual(len(ym.encode_transfer([(0, 1)] * 1)), 10)
        self.assertEqual(len(ym.encode_redeem(1, 1, [])), 11)

    # Rule: MINT-1
    def test_v3_types_decode_by_name(self):
        # The four v3 types decode (shape only; no rule reads them until A1) and round-trip their fields.
        reg = ym.decode_payload(b'YB\x03\x05' + G_PUBKEY + G2_PUBKEY + (301).to_bytes(4, 'little') + b'\x05')
        self.assertEqual((reg.type_name, reg.attestor_pubkey, reg.bond_pubkey, reg.bond_locktime, reg.flags),
                         ('ATTESTOR_REGISTER', G_PUBKEY, G2_PUBKEY, 301, 5))
        txid = 'ab' * 31 + 'cd'
        notice = ym.decode_payload(b'YB\x03\x06' + bytes.fromhex(txid)[::-1] + b'\x02' + (200).to_bytes(4, 'little'))
        self.assertEqual((notice.type_name, notice.vault_txid, notice.vault_vout, notice.ref_height), ('CLAIM_NOTICE', txid, 2, 200))
        self.assertEqual(ym.decode_payload(b'YB\x03\x07').type_name, 'EQUIVOCATION')
        self.assertIsNone(ym.decode_payload(b'YB\x03\x07\x00'))
        rev = ym.decode_payload(b'YB\x03\x08' + (7).to_bytes(2, 'little') + (1_000_000).to_bytes(4, 'little') + (9).to_bytes(4, 'little') + b'\x11' * 64)
        self.assertEqual((rev.type_name, rev.seq, rev.price_micro_usd, rev.cited_height, rev.sig), ('ATTESTOR_REVIVE', 7, 1_000_000, 9, b'\x11' * 64))
        for t in (ym.PAYLOAD_ATTESTOR_REGISTER, ym.PAYLOAD_CLAIM_NOTICE, ym.PAYLOAD_ATTESTOR_REVIVE):
            self.assertIsNone(ym.decode_payload(bytes([0x59, 0x42, 3, t]) + b'\x00' * 10))
        self.assertIsNone(ym.decode_payload(b'YB\x03\x04'))
        self.assertIsNone(ym.decode_payload(b'YB\x03\x09' + b'\x00'))

    # Rule: MINT-1
    def test_malformed(self):
        good = ym.encode_mint(0, 10_000, 100, 50, G_PUBKEY, 0xFF)
        self.assertIsNone(ym.decode_payload(good[:-1]))                 # short
        self.assertIsNone(ym.decode_payload(good + b'\x00'))            # trailing
        self.assertIsNone(ym.decode_payload(b'YA' + good[2:]))          # magic
        self.assertIsNone(ym.decode_payload(b'YB\x01' + good[3:]))      # version 1 ignored (V23)
        self.assertIsNone(ym.decode_payload(b'YB\x02' + good[3:]))      # version 2 ignored (V23)
        self.assertIsNone(ym.decode_payload(b'YB\x04' + good[3:]))      # later version ignored
        self.assertIsNone(ym.decode_payload(b'YB\x03\x10' + good[4:]))  # retired type
        self.assertIsNone(ym.decode_payload(b'YB\x03\x20'))             # other family, short
        self.assertIsNone(ym.decode_payload(b'YB\x03'))                 # < 4 bytes
        self.assertIsNone(ym.decode_payload(b'YB\x03\x02' + b'\x0f' + b'\x00' * 75 + b'\x00'))  # 81 bytes
        self.assertIsNone(ym.decode_payload(ym.encode_transfer([(0, 0)])))          # cents == 0
        self.assertIsNone(ym.decode_payload(ym.encode_transfer([(0, 1), (0, 2)])))  # duplicate vout
        self.assertIsNone(ym.decode_payload(ym.encode_transfer([(5, 1)]), n_vout=3))          # out of range
        self.assertIsNone(ym.decode_payload(ym.encode_transfer([(1, 1)]), n_vout=3, opret_index=1))  # the OP_RETURN
        self.assertIsNotNone(ym.decode_payload(ym.encode_transfer([(2, 1)]), n_vout=3, opret_index=1))

    # Rule: MINT-1
    def test_tx_payload_shape(self):
        pl = ym.encode_transfer([(0, 100)])
        token = ym.p2pkh_script(KEY1)
        self.assertIsNotNone(ym.tx_payload([token, bytes([ym.OP_RETURN]) + ym.push(pl)])[0])
        # two OP_RETURN outputs => non-Yellowback
        self.assertIsNone(ym.tx_payload([token, bytes([ym.OP_RETURN]) + ym.push(pl), bytes([ym.OP_RETURN])])[0])
        # two pushes after OP_RETURN => not the shape
        self.assertIsNone(ym.tx_payload([token, bytes([ym.OP_RETURN]) + ym.push(pl) + ym.push(b'x')])[0])
        # bare OP_RETURN
        self.assertIsNone(ym.tx_payload([token, bytes([ym.OP_RETURN])])[0])
        # PUSHDATA1 encoding of the same payload is accepted (GetOp semantics)
        self.assertIsNotNone(ym.tx_payload([token, bytes([ym.OP_RETURN, ym.OP_PUSHDATA1, len(pl)]) + pl])[0])
        # 80-byte payload of a reserved family: non-Yellowback; 80 bytes of a TRANSFER: accepted
        t15 = ym.encode_transfer([(i, 1) for i in range(15)])
        self.assertEqual(len(t15), 80)
        self.assertIsNotNone(ym.tx_payload([token] * 16 + [bytes([ym.OP_RETURN, ym.OP_PUSHDATA1, 80]) + t15])[0])


# ===========================================================================
# section 3.4  Scripts and path detection

class ScriptTests(unittest.TestCase):

    # Rule: RED-1
    def test_vault_script_shape(self):
        s = ym.vault_script(182, G_PUBKEY, 206)
        self.assertEqual(len(s), 51 - 2)   # regtest heights fit in 2 bytes: 49 bytes
        s = ym.vault_script(1_000_000, G_PUBKEY, 1_034_560)
        self.assertEqual(len(s), 51)
        self.assertEqual(s[0], ym.OP_IF)
        self.assertEqual(s[-1], ym.OP_ENDIF)
        self.assertTrue(ym.is_p2sh(ym.p2sh_script(s)))

    # Rule: RED-4
    def test_path_detection(self):
        vs = ym.vault_script(182, G_PUBKEY, 206)
        self.assertEqual(ym.spend_path(ym.push(SIG71) + bytes([ym.OP_1]) + ym.push(vs)), 'owner')
        self.assertEqual(ym.spend_path(bytes([ym.OP_0]) + ym.push(vs)), 'claim')
        self.assertEqual(ym.spend_path(ym.push(SIG71) + bytes([0x52]) + ym.push(vs)), 'owner')       # OP_2 (K4)
        self.assertEqual(ym.spend_path(ym.push(SIG71) + ym.push(b'\x01') + ym.push(vs)), 'owner')      # non-minimal 1
        self.assertEqual(ym.spend_path(ym.push(SIG71) + ym.push(b'\x80') + ym.push(vs)), 'claim')      # negative zero
        self.assertEqual(ym.spend_path(ym.push(SIG71) + ym.push(b'\x00\x80') + ym.push(vs)), 'claim')
        self.assertEqual(ym.spend_path(ym.push(SIG71) + ym.push(b'\x00\x01') + ym.push(vs)), 'owner')

    # Rule: RED-1
    def test_not_push_only_or_too_few_pushes(self):
        vs = ym.vault_script(182, G_PUBKEY, 206)
        self.assertIsNone(ym.spend_path(ym.push(vs)))                          # one push
        self.assertIsNone(ym.spend_path(b''))
        self.assertIsNone(ym.spend_path(bytes([ym.OP_1, ym.OP_DUP]) + ym.push(vs)))   # OP_DUP is not a push
        self.assertIsNone(ym.spend_path(ym.push(SIG71) + bytes([ym.OP_1, 0x30])))    # truncated push


# ===========================================================================
# section 3.7  Arithmetic

class ArithmeticTests(unittest.TestCase):

    # Rule: PRICE-1
    def test_lower_median(self):
        self.assertIsNone(ym.lower_median([]))
        self.assertEqual(ym.lower_median([5]), 5)
        self.assertEqual(ym.lower_median([3, 1]), 1)
        self.assertEqual(ym.lower_median([1, 2, 3, 4]), 2)
        self.assertEqual(ym.lower_median([4, 3, 2, 1, 5]), 3)
        self.assertEqual(ym.lower_median([7, 7, 1, 9, 9, 9]), 7)

    # Rule: MINT-5
    def test_required_collateral_worked_example(self):
        # $100 at 300 % and $0.05/YEC -> 6e11 zat = 6,000 YEC (section 3.7)
        self.assertEqual(ym.required_zat(10_000, 30_000, 50_000), 6 * 10 ** 11)
        self.assertEqual(ym.min_ratio_bps(50_000, 30_000), 150_000)
        # worst case: class A at the cap and PRICE_MIN is unsatisfiable (K14)
        self.assertIsNone(ym.required_zat(1_000_000, 150_000, 100))
        self.assertIsNone(ym.required_zat(10_000, 30_000, None))
        # rounding up
        self.assertEqual(ym.required_zat(10_000, 50_000, 30_001), ym.ceil_div(10_000 * 50_000 * ym.COIN, 30_001))

    # Rule: RED-4
    def test_underwater_worked_example(self):
        # 6,000 YEC backing $100 is underwater once pClaim <= 18,333 (section 3.7)
        self.assertTrue(ym.is_underwater(6 * 10 ** 11, 18_333, 10_000, 11_000))
        self.assertFalse(ym.is_underwater(6 * 10 ** 11, 18_334, 10_000, 11_000))
        self.assertFalse(ym.is_underwater(6 * 10 ** 11, None, 10_000, 11_000))

    # Rule: FEE-1
    def test_fee(self):
        self.assertEqual(ym.fee_zat(10 ** 9, 50_000_000, 25), 50_000_000)
        self.assertEqual(ym.fee_zat(10 ** 12, 50_000_000, 25), 2_500_000_000)

    # Rule: HALT-2
    def test_global_ratio_and_cap(self):
        self.assertIsNone(ym.global_ratio_bps(10 ** 12, 50_000, 0))
        self.assertIsNone(ym.global_ratio_bps(10 ** 12, None, 10_000))
        self.assertEqual(ym.global_ratio_bps(10 ** 12, 50_000, 10_000), 50_000)
        self.assertEqual(ym.cap_cents(10 ** 12, 50_000), 50_000)           # 10,000 YEC * $0.05 = $500
        self.assertEqual(ym.supply_cap_cents(10 ** 12, 50_000, 1_500), 7_500)
        self.assertIsNone(ym.supply_cap_cents(10 ** 12, 50_000, 0))
        self.assertIsNone(ym.supply_cap_cents(10 ** 12, None, 1_500))

    # Rule: SIGMA-1
    def test_sigma_undefined_sample_is_cap(self):
        s = [50_000] * 9
        self.assertEqual(ym.sigma_mult_bps(s, 10_000, 8_760, 30_000), 10_000)
        s[4] = None
        self.assertEqual(ym.sigma_mult_bps(s, 10_000, 8_760, 30_000), 30_000)
        self.assertEqual(ym.sigma_mult_bps([None] * 9, 10_000, 8_760, 30_000), 30_000)
        # sigmaRefBps == 0 fixes the multiplier at 1x even with undefined samples (regtest)
        self.assertEqual(ym.sigma_mult_bps([None] * 9, 0, 8_760, 30_000), 10_000)

    # Rule: SIGMA-1
    def test_sigma_worked_example(self):
        # s = [1100, 1000, 1100, 1000, 1100, 1000, 1100, 1000, 1100]: 8 returns
        s = [1100, 1000] * 4 + [1100]
        # r_k = |s_k - s_{k+1}| * 1e4 / s_{k+1}: 1000 when s_{k+1} = 1000, 909 when s_{k+1} = 1100
        rs = [1000, 909] * 4
        var = sum(r * r for r in rs) // 8
        annual = ym.isqrt(var * 8_760)
        expect = min(30_000, max(10_000, annual * 10_000 // 10_000))
        self.assertEqual(ym.sigma_mult_bps(s, 10_000, 8_760, 30_000), expect)
        self.assertEqual(expect, 30_000)  # such swings pin the cap
        # a mild series: 1% steps, 42 returns, annualised below the reference -> 1x
        mild = [100_000 + (k % 2) * 1000 for k in range(43)]
        self.assertEqual(ym.sigma_mult_bps(mild, 10_000, 8_760, 30_000), 10_000)
        # sigmaRef scaling: the same series against a tiny reference reaches the cap
        self.assertEqual(ym.sigma_mult_bps(mild, 1, 8_760, 30_000), 30_000)


# ===========================================================================
# section 3.7 / 3.8  Snapshots: medians, fill, activation, halts, judgement

class SnapshotTests(unittest.TestCase):

    def chain(self, start=1):
        return Chain(ym.Params.regtest(start))

    # Rule: PRICE-1
    def test_fast_fill_boundary(self):
        p = ym.Params.regtest(1)
        self.assertEqual((p.min_fill_fast, p.min_fill_mid, p.min_fill_slow), (4, 16, 43))
        c = self.chain()
        c.mine_n(3, price_fn=lambda h: 1000 + h)      # 3 quotes = ceil(8/2) - 1
        self.assertIsNone(c.model.snapshots[3].p_fast)
        c.mine_n(1, price_fn=lambda h: 1000 + h)      # 4 quotes = ceil(8/2)
        self.assertEqual(c.model.snapshots[4].p_fast, ym.lower_median([1001, 1002, 1003, 1004]))
        self.assertEqual(c.model.snapshots[4].p_fast, 1002)
        self.assertIsNone(c.model.snapshots[4].p_mid)
        self.assertIsNone(c.model.snapshots[4].p_mint)

    # Rule: PRICE-1
    def test_mid_and_slow_fill_boundary(self):
        c = self.chain()
        c.mine_n(15, price_fn=lambda h: 500)
        self.assertIsNone(c.model.snapshots[15].p_mid)
        c.mine_n(1, price_fn=lambda h: 500)
        self.assertEqual(c.model.snapshots[16].p_mid, 500)
        c.mine_n(26, price_fn=lambda h: 500)          # 42 quotes
        self.assertIsNone(c.model.snapshots[42].p_slow)
        c.mine_n(1, price_fn=lambda h: 500)           # 43 = ceil(2*64/3)
        self.assertEqual(c.model.snapshots[43].p_slow, 500)
        self.assertEqual(c.model.snapshots[43].p_mint, 500)
        self.assertEqual(c.model.snapshots[43].p_claim, 500)

    # Rule: PRICE-1
    def test_window_is_half_open_and_signal_only_does_not_fill(self):
        c = self.chain()
        c.mine_n(4, price_fn=lambda h: 100 + h)        # quotes at 1..4
        c.mine_n(4, price_fn=lambda h: 0)              # signal-only at 5..8: pFast over (0, 8] still has 4 quotes
        self.assertEqual(c.model.snapshots[8].p_fast, 102)
        c.mine_n(1, price_fn=lambda h: 0)              # (1, 9]: quote at 1 drops out -> 3 quotes
        self.assertIsNone(c.model.snapshots[9].p_fast)

    # Rule: PRICE-2
    def test_pmint_pclaim(self):
        c = self.chain()
        c.mine_n(43, price_fn=lambda h: 500)
        c.mine_n(8, price_fn=lambda h: 300)            # fast window now all 300, mid mixes, slow mostly 500
        s = c.model.snapshots[51]
        self.assertEqual(s.p_fast, 300)
        self.assertEqual(s.p_mint, min(s.p_fast, s.p_mid, s.p_slow))
        self.assertEqual(s.p_claim, max(s.p_mid, s.p_slow))
        self.assertEqual(s.p_claim, 500)

    # Rule: ACT-2
    def test_lock_in_at_exactly_the_threshold(self):
        c = self.chain()
        # 47 signals in the first 64 blocks: no lock-in at 64
        c.mine_n(47, signal=True)
        c.mine_n(17, signal=False)
        self.assertEqual(c.model.snapshots[64].signal_count, 47)
        self.assertEqual(c.model.activation.status, ym.SIGNALING)
        # block 65: window (1, 65] holds 46 + 1 = 47 -> still no; block 66 with signals 2..47 + 65, 66 = 48
        c.mine_n(1, signal=True)
        self.assertEqual(c.model.snapshots[65].signal_count, 47)
        self.assertEqual(c.model.activation.status, ym.SIGNALING)
        c.mine_n(1, signal=True)
        self.assertEqual(c.model.snapshots[66].signal_count, 47)   # signal at 1 and 2 dropped out
        c2 = self.chain()
        c2.mine_n(48, signal=True)
        c2.mine_n(15, signal=False)
        self.assertEqual(c2.model.activation.status, ym.SIGNALING)  # H = 63 < START + 64 - 1
        c2.mine_n(1, signal=False)
        self.assertEqual(c2.model.activation.status, ym.LOCKED_IN)
        self.assertEqual((c2.model.activation.lock_in_height, c2.model.activation.activate_height), (64, 128))
        self.assertEqual(c2.model.snapshots[64].activation.status, ym.LOCKED_IN)

    # Rule: ACT-2
    def test_lock_in_needs_start_plus_window(self):
        c = Chain(ym.Params.regtest(10))
        c.mine_n(9)                                    # below START: ignored, no snapshots
        self.assertEqual(c.model.snapshots, {})
        c.mine_n(63, signal=True)                      # heights 10..72
        self.assertEqual(c.model.activation.status, ym.SIGNALING)
        c.mine_n(1, signal=True)                       # 73 = 10 + 64 - 1
        self.assertEqual(c.model.activation.status, ym.LOCKED_IN)
        self.assertEqual(c.model.activation.lock_in_height, 73)

    # Rule: ACT-3
    def test_activation_at_activate_height_even_if_signalling_collapsed(self):
        c = self.chain()
        c.mine_n(64, signal=True)
        self.assertEqual(c.model.activation.status, ym.LOCKED_IN)
        c.mine_n(63, signal=False)
        self.assertEqual(c.model.activation.status, ym.LOCKED_IN)
        c.mine_n(1, signal=False)
        self.assertEqual(c.model.activation.status, ym.ACTIVE)
        s = c.model.snapshots[128]
        self.assertTrue(s.halt_mask & ym.HALT_PARTICIPATION)
        self.assertTrue(s.halt_mask & ym.HALT_ENFORCEMENT)
        self.assertFalse(s.halt_mask & ym.HALT_NOT_ACTIVE)
        self.assertFalse(c.model.enforcement_on(129))

    # Rule: ACT-4
    def test_participation_hysteresis(self):
        c = self.chain()
        c.mine_n(128, signal=True)
        self.assertEqual(c.model.activation.status, ym.ACTIVE)
        self.assertEqual(c.model.snapshots[128].halt_mask & ym.HALT_PARTICIPATION, 0)
        # drop to exactly the floor (39 of 64): the bit stays clear
        c.mine_n(25, signal=False)                     # window (65, 129]..(89, 153]: 39 signals at 153
        self.assertEqual(c.model.snapshots[153].signal_count, 39)
        self.assertEqual(c.model.snapshots[153].halt_mask & ym.HALT_PARTICIPATION, 0)
        c.mine_n(1, signal=False)                      # 38 < 39: set
        self.assertEqual(c.model.snapshots[154].signal_count, 38)
        self.assertTrue(c.model.snapshots[154].halt_mask & ym.HALT_PARTICIPATION)
        # recover: each new signal replaces one leaving the window, so the count stays 38 until the
        # old signals are all out; at 201 the window (137, 201] holds 47: still set (hysteresis, K15); 48 clears
        c.mine_n(47, signal=True)
        self.assertEqual(c.model.snapshots[201].signal_count, 47)
        self.assertTrue(c.model.snapshots[201].halt_mask & ym.HALT_PARTICIPATION)
        self.assertTrue(c.model.snapshots[180].halt_mask & ym.HALT_PARTICIPATION)
        c.mine_n(1, signal=True)
        self.assertEqual(c.model.snapshots[202].signal_count, 48)
        self.assertEqual(c.model.snapshots[202].halt_mask & ym.HALT_PARTICIPATION, 0)

    # Rule: ACT-6
    def test_enforcement_hysteresis(self):
        c = self.chain()
        c.mine_n(128, signal=True)
        c.mine_n(32, signal=False)                     # count 32 = ENFORCEMENT_FLOOR: clear
        self.assertEqual(c.model.snapshots[160].signal_count, 32)
        self.assertEqual(c.model.snapshots[160].halt_mask & ym.HALT_ENFORCEMENT, 0)
        self.assertTrue(c.model.snapshots[160].halt_mask & ym.HALT_PARTICIPATION)
        self.assertTrue(c.model.enforcement_on(161))
        c.mine_n(1, signal=False)                      # 31 < 32: set
        self.assertTrue(c.model.snapshots[161].halt_mask & ym.HALT_ENFORCEMENT)
        self.assertFalse(c.model.enforcement_on(162))
        c.mine_n(38, signal=True)                      # (135, 199] holds 38 < ENFORCEMENT_RESUME 39: persists
        self.assertEqual(c.model.snapshots[199].signal_count, 38)
        self.assertTrue(c.model.snapshots[199].halt_mask & ym.HALT_ENFORCEMENT)
        self.assertFalse(c.model.enforcement_on(200))
        c.mine_n(1, signal=True)                       # 39: clears; PARTICIPATION (needs 48) stays
        self.assertEqual(c.model.snapshots[200].signal_count, 39)
        self.assertEqual(c.model.snapshots[200].halt_mask & ym.HALT_ENFORCEMENT, 0)
        self.assertTrue(c.model.snapshots[200].halt_mask & ym.HALT_PARTICIPATION)
        self.assertTrue(c.model.enforcement_on(201))

    # Rule: ACT-5
    def test_enforcement_sunset(self):
        c = Chain(ym.Params.regtest(1, enforce_until=130))
        c.mine_n(131, signal=True)
        self.assertTrue(c.model.enforcement_on(130))
        self.assertFalse(c.model.enforcement_on(131))
        self.assertFalse(c.model.enforcement_on(1))    # Snapshots[0] is virtual

    # Rule: HALT-1
    def test_halts_no_price_and_not_active(self):
        c = self.chain()
        c.mine_n(1, signal=True)
        self.assertEqual(c.model.snapshots[1].halt_mask, ym.HALT_NOT_ACTIVE | ym.HALT_NO_PRICE)
        self.assertEqual(c.model.snapshots[1].halt_names(), ['NOT_ACTIVE', 'NO_PRICE'])

    # Rule: HALT-3
    def test_divergence(self):
        c = activated_chain()
        # pFast falls 25 % below pMid
        c.mine_n(8, price_fn=lambda h: 37_000)
        s = c.model.snapshots[c.height]
        self.assertEqual(s.p_fast, 37_000)
        self.assertEqual(s.p_mid, 50_000)
        self.assertTrue(s.halt_mask & ym.HALT_DIVERGENCE)
        self.assertEqual(s.halt_mask & ym.HALT_NO_PRICE, 0)
        # exactly 80 % is not a divergence (strict <)
        c2 = activated_chain()
        c2.mine_n(8, price_fn=lambda h: 40_000)
        self.assertEqual(c2.model.snapshots[c2.height].halt_mask & ym.HALT_DIVERGENCE, 0)

    # Rule: REG-4
    def test_judgement(self):
        c = self.chain()
        prices = {1: 1000, 2: 1000, 3: 1000, 4: 1000, 5: 1000, 6: 1300, 7: 1000, 8: 1000, 9: 1000, 10: 1040}
        c.mine_n(10, price_fn=lambda h: prices[h])
        # tag at t = 6 judged when H = 10: peers in [2, 9] except 6 -> 7 quotes at 1000; dev = 3000 bps
        j = c.model.judgements[6]
        self.assertEqual((j.evaluated, j.in_band, j.penalized), (True, False, True))
        j = c.model.judgements[5]
        self.assertEqual((j.evaluated, j.in_band, j.penalized), (True, True, False))
        c.mine_n(4, price_fn=lambda h: 1000)
        j = c.model.judgements[10]                     # dev = 400 bps: out of band, not penalised
        self.assertEqual((j.evaluated, j.in_band, j.penalized), (True, False, False))
        # too few peers: written, not evaluated
        c3 = self.chain()
        c3.mine_n(1, price_fn=lambda h: 1000)
        c3.mine_n(2, price_fn=lambda h: 0)
        c3.mine_n(2, price_fn=lambda h: 1000)          # t = 1 judged at 5: peers at 4, 5 only
        self.assertFalse(c3.model.judgements[1].evaluated)
        self.assertNotIn(2, c3.model.judgements)       # a signal-only tag is never judged

    # Rule: FEE-2
    def test_eligible_payees(self):
        c = self.chain()
        c.mine_n(12, price_fn=lambda h: 500, key_fn=lambda h: MINERS[h % 3])
        e = c.model.eligible_payees(12)                # (2, 12]: heights 3..12
        self.assertEqual(e, [MINERS[3 % 3], MINERS[4 % 3], MINERS[5 % 3]])
        c.mine_n(10, price_fn=lambda h: 0, key_fn=lambda h: MINERS[0])
        self.assertEqual(c.model.eligible_payees(22), [])   # signal-only tags register nothing

    # Rule: SNAP
    def test_issued_zat(self):
        c = self.chain()
        c.mine_n(3)
        self.assertEqual(c.model.snapshots[3].issued_zat, sum(ym.regtest_subsidy(h) for h in (1, 2, 3)))
        c2 = Chain(ym.Params.regtest(1), issued_before_start=ym.regtest_subsidy(0))
        c2.mine_n(1)
        self.assertEqual(c2.model.snapshots[1].issued_zat, ym.regtest_subsidy(0) + ym.regtest_subsidy(1))

    # Rule: SNAP
    def test_below_start_is_ignored_and_virtual_snapshot(self):
        m = ym.YellowbackModel(ym.Params.regtest(5))
        v = m.snapshot(4)
        self.assertTrue(v.virtual)
        self.assertEqual(v.halt_mask, ym.HALT_NOT_ACTIVE | ym.HALT_NO_PRICE)
        self.assertIsNone(v.p_mint)
        self.assertEqual(v.activation.status, ym.SIGNALING)
        self.assertIsNone(m.snapshot(5))
        self.assertIsNone(m.feed_block(3, '00' * 32, ym.height_prefix(3).hex(), 1, []))
        self.assertEqual(m.tags, {})


# ===========================================================================
# section 3.8  Money rules

class MintTests(unittest.TestCase):

    def setUp(self):
        self.c = activated_chain()

    def mint(self, **kw):
        c = self.c
        ref = kw.pop('ref_height', c.height - 1)
        cents = kw.pop('cents', 10_000)
        lock_blocks = kw.pop('lock_blocks', 48)
        coll = kw.pop('collateral', None)
        if coll is None:
            tc = kw.get('term_class', 0)
            coll = collateral_for(c, cents if 10_000 <= cents <= 1_000_000 else 10_000, ref, tc if tc in (0, 1, 2) else 0)
        fee_key = kw.pop('fee_key', KEY1)
        raw = c.mint_tx(cents, lock_blocks, ref, coll, fee_key=fee_key, **kw)
        c.mine((1, 50_000, 0, KEY2), [raw])
        return txid_of(raw)

    def assertVoid(self, txid, reason):
        v = self.c.model.vaults[(txid, 0)]
        self.assertEqual(v.status, ym.V_VOID)
        self.assertEqual(v.void_reason, reason)
        self.assertEqual(self.c.model.txlog[txid].verdict, reason)
        self.assertEqual(self.c.model.txlog[txid].yed_out, 0)
        self.assertNotIn((txid, 1), self.c.model.tokens)
        self.assertEqual(self.c.model.totals.supply_cents, 0)

    # Rule: MINT-1
    def test_valid_mint(self):
        c = self.c
        ref = c.height - 1
        coll = collateral_for(c, 10_000, ref)
        txid = self.mint()
        m = c.model
        v = m.vaults[(txid, 0)]
        self.assertEqual(v.status, ym.V_ACTIVE)
        self.assertEqual((v.minted_cents, v.collateral_zat, v.lock_height, v.claim_height, v.ref_height, v.mint_height),
                         (10_000, coll, ref + 48, ref + 48 + 24, ref, c.height))
        self.assertEqual(v.fee_paid_zat, ym.fee_zat(coll, 50_000_000, 25))
        self.assertEqual(m.tokens[(txid, 1)].cents, 10_000)
        self.assertEqual(m.totals.supply_cents, 10_000)
        self.assertEqual(m.totals.collateral_zat, coll)
        self.assertEqual(m.totals.active_vaults, 1)
        rec = m.txlog[txid]
        self.assertEqual((rec.type, rec.verdict, rec.yed_in, rec.yed_out, rec.burned, rec.fee_zat, rec.payee),
                         ('MINT', 'ok', 0, 10_000, 0, v.fee_paid_zat, KEY1))
        self.assertEqual(rec.assigned, [(1, 10_000)])
        s = m.snapshots[c.height]
        self.assertEqual(s.supply_cents, 10_000)
        self.assertEqual(s.global_ratio_bps, ym.global_ratio_bps(coll, s.p_mint, 10_000))
        self.assertGreaterEqual(s.global_ratio_bps, 50_000)

    # Rule: IN-3
    def test_mint_with_yed_inputs_burns_them(self):
        c = self.c
        t1 = self.mint()
        # a second mint that spends the first mint's 10,000-cent token: yedIn = 10,000 is burned, cents are issued (N19)
        t2 = self.mint(yed_inputs=[(t1, 1)])
        rec = c.model.txlog[t2]
        self.assertEqual((rec.yed_in, rec.yed_out, rec.burned, rec.verdict), (10_000, 10_000, 10_000, 'ok'))
        self.assertEqual(c.model.totals.supply_cents, 10_000)          # 10,000 + 10,000 - 10,000
        self.assertNotIn((t1, 1), c.model.tokens)
        self.assertIn((t2, 1), c.model.tokens)
        self.assertEqual(rec.spent_tokens, [(t1, 1)])
        # a VOID mint with YED inputs burns them too
        t3 = self.mint(cents=5_000, yed_inputs=[(t2, 1)])
        rec = c.model.txlog[t3]
        self.assertEqual((rec.yed_in, rec.yed_out, rec.burned, rec.verdict), (10_000, 0, 10_000, 'bad-mint-amount'))
        self.assertEqual(c.model.totals.supply_cents, 0)

    # Rule: MINT-2
    def test_mint2_verdicts(self):
        self.assertVoid(self.mint(term_class=3), 'bad-mint-class')
        self.assertVoid(self.mint(cents=9_999), 'bad-mint-amount')
        self.assertVoid(self.mint(cents=1_000_001), 'bad-mint-amount')
        self.assertVoid(self.mint(lock_height=ym.LOCKTIME_THRESHOLD - 24), 'bad-mint-lock-height')
        self.assertVoid(self.mint(ref_height=self.c.height + 1, collateral=10 ** 12), 'bad-mint-ref-height')   # ref = H
        self.assertVoid(self.mint(ref_height=self.c.height - 40), 'bad-mint-ref-height')          # ref = H - 41
        self.assertVoid(self.mint(lock_blocks=47), 'bad-mint-lock-height')
        self.assertVoid(self.mint(lock_blocks=97), 'bad-mint-lock-height')
        self.assertVoid(self.mint(lock_blocks=96, term_class=1), 'bad-mint-lock-height')         # class B is (96, 144]
        self.assertVoid(self.mint(lock_blocks=0), 'bad-mint-lock-height')

    # Rule: MINT-2
    def test_mint2_ref_below_start(self):
        c = Chain(ym.Params.regtest(140))
        c.mine_n(139)
        c.mine_n(135, price_fn=lambda h: 50_000)
        # H = 275, ref = 139 < START (and outside the window) -> bad-mint-ref-height; H - 40 = 235 >= START
        raw = c.mint_tx(10_000, 48, 139, 10 ** 12, fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.model.vaults[(txid_of(raw), 0)].void_reason, 'bad-mint-ref-height')

    # Rule: MINT-3
    def test_mint3_verdicts(self):
        c = self.c
        ref = c.height - 1
        # fewer than three outputs: a P2SH vout[0] and the OP_RETURN only
        lock = ref + 48
        script = ym.vault_script(lock, G_PUBKEY, lock + 24)
        pl = ym.encode_mint(0, 10_000, lock, ref, G_PUBKEY, 0xFF)
        raw = ym.serialize_tx_v4([c.fund_input()], [(10 ** 12, ym.p2sh_script(script)), (0, bytes([ym.OP_RETURN]) + ym.push(pl))]).hex()
        c.mine((1, 50_000, 0, KEY2), [raw])
        self.assertVoid(txid_of(raw), 'bad-mint-outputs')
        self.assertVoid(self.mint(owner=BAD_PUBKEY), 'bad-mint-owner-key')
        self.assertVoid(self.mint(vout0_script=ym.p2sh_script(b'\x51')), 'bad-mint-vault-script')
        # a non-P2SH vout[0] creates no vault at all
        raw = c.mint_tx(10_000, 48, c.height - 1, 10 ** 12, fee_key=KEY1, vout0_script=ym.p2pkh_script(KEY1))
        c.mine((1, 50_000, 0, KEY2), [raw])
        self.assertNotIn((txid_of(raw), 0), c.model.vaults)
        self.assertNotIn(txid_of(raw), c.model.txlog)

    # Rule: MINT-4
    def test_mint4_not_active(self):
        c = Chain(ym.Params.regtest(1))
        c.mine_n(100, price_fn=lambda h: 50_000)       # LOCKED_IN, not yet ACTIVE
        raw = c.mint_tx(10_000, 48, 99, 10 ** 12, fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.model.vaults[(txid_of(raw), 0)].void_reason, 'mint-not-active')

    # Rule: MINT-4
    def test_mint4_halts(self):
        c = self.c
        c.mine_n(8, price_fn=lambda h: 37_000)         # DIVERGENCE at the tip
        self.assertVoid(self.mint(), 'mint-halted-divergence')
        c2 = activated_chain()
        c2.mine_n(9, price_fn=lambda h: 0)             # 9 signal-only: pFast (4 quotes needed) undefined
        self.assertTrue(c2.model.snapshots[c2.height].halt_mask & ym.HALT_NO_PRICE)
        raw = c2.mint_tx(10_000, 48, c2.height - 1, 10 ** 12, fee_key=KEY1)
        c2.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c2.model.vaults[(txid_of(raw), 0)].void_reason, 'mint-halted-no-price')
        c3 = activated_chain()
        c3.mine_n(30, signal=False, price_fn=lambda h: 50_000)   # 34 signals < 39
        self.assertTrue(c3.model.snapshots[c3.height].halt_mask & ym.HALT_PARTICIPATION)
        raw = c3.mint_tx(10_000, 48, c3.height - 1, 10 ** 12, fee_key=KEY1)
        c3.mine((0, 50_000, 0, KEY1), [raw])
        self.assertEqual(c3.model.vaults[(txid_of(raw), 0)].void_reason, 'mint-halted-participation')

    # Rule: HALT-2
    def test_mint4_global_ratio(self):
        c = self.c
        self.mint()                                    # 10,000 cents backed at 500 %
        c.mine_n(64, price_fn=lambda h: 9_000)         # price / 5.5: ratio ~ 9,000 bps < 25,000; slow window fully refilled
        s = c.model.snapshots[c.height]
        self.assertTrue(s.halt_mask & ym.HALT_GLOBAL_RATIO)
        self.assertEqual(s.halt_mask & ym.HALT_DIVERGENCE, 0)
        # W16: the halt stops the classes below the recapitalisation floor (class C, 300 %) ...
        raw = c.mint_tx(10_000, 145, c.height - 1, 10 ** 13, fee_key=KEY1, term_class=2)
        c.mine((1, 9_000, 0, KEY1), [raw])
        self.assertEqual(c.model.vaults[(txid_of(raw), 0)].void_reason, 'mint-halted-global-ratio')
        # ... and lets class A (500 %) through, which is what repairs the ratio
        self.assertTrue(c.model.snapshots[c.height].halt_mask & ym.HALT_GLOBAL_RATIO)
        raw = c.mint_tx(10_000, 48, c.height - 1, 10 ** 13, fee_key=KEY1)
        c.mine((1, 9_000, 0, KEY1), [raw])
        self.assertEqual(c.model.vaults[(txid_of(raw), 0)].void_reason, '')

    # Rule: MINT-5
    def test_mint5_collateral(self):
        c = self.c
        ref = c.height - 1
        coll = collateral_for(c, 10_000, ref)
        req = ym.required_zat(10_000, 50_000, c.model.snapshot(ref).p_mint)
        self.assertVoid(self.mint(collateral=req - 1), 'bad-mint-collateral')
        t = self.mint(collateral=req)
        self.assertEqual(c.model.vaults[(t, 0)].status, ym.V_ACTIVE)
        self.assertLessEqual(req, coll)
        # the 4 * FEE_MIN floor (2 YEC) can never bind with the section 3.1 parameters: MIN_MINT at
        # PRICE_MAX and the lowest ratio (class C, 1x) still needs 3 YEC
        self.assertGreater(ym.required_zat(10_000, 30_000, 100_000_000), 4 * 50_000_000)

    # Rule: MINT-5
    def test_mint5_unsatisfiable(self):
        c = activated_chain(ym.Params.regtest(1, sigma_ref_bps=10_000))   # sigma at the cap (undefined samples)
        c.mine_n(64, price_fn=lambda h: 100)           # PRICE_MIN
        s = c.model.snapshot(c.height - 1)
        self.assertEqual(s.sigma_mult_bps, 30_000)
        raw = c.mint_tx(1_000_000, 48, c.height - 1, ym.MAX_MONEY, fee_key=KEY1)
        c.mine((1, 100, 0, KEY1), [raw])
        self.assertEqual(c.model.vaults[(txid_of(raw), 0)].void_reason, 'mint-unsatisfiable')

    # Rule: MINT-6
    def test_mint6_supply_cap(self):
        c = activated_chain(ym.Params.regtest(1, supply_cap_bps=1_500))
        s = c.model.snapshot(c.height - 1)
        cap = ym.supply_cap_cents(s.issued_zat, s.p_mint, 1_500)
        self.assertIsNotNone(cap)
        # issued ~ 135 blocks * 6.25 YEC ~ 843 YEC * $0.05 = $42 -> cap = 15 % of that ~ 632 cents < MIN_MINT
        self.assertLess(cap, 10_000)
        raw = c.mint_tx(10_000, 48, c.height - 1, 10 ** 12, fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.model.vaults[(txid_of(raw), 0)].void_reason, 'mint-supply-cap')

    # Rule: MINT-7
    def test_mint7_token_output_is_opreturn(self):
        self.assertVoid(self.mint(opret_at=1, fee_vout=3), 'bad-mint-token-output')

    # Rule: MINT-8
    def test_mint8_fee(self):
        c = self.c
        self.assertVoid(self.mint(fee_key=None), 'bad-mint-fee')                          # 0xFF with E non-empty
        self.assertVoid(self.mint(fee_key=KEY1, fee_vout=7), 'bad-mint-fee')              # out of range
        self.assertVoid(self.mint(fee_key=KEY1, fee_vout=0), 'bad-mint-fee')              # the vault
        self.assertVoid(self.mint(fee_key=KEY1, fee_vout=1), 'bad-mint-fee')              # the token
        self.assertVoid(self.mint(fee_key=KEY1, fee_vout=2), 'bad-mint-fee')              # the OP_RETURN
        self.assertVoid(self.mint(fee_key=OWNER_KEYHASH), 'bad-mint-fee')                 # not in E(R)
        coll = collateral_for(c, 10_000, c.height - 1)
        self.assertVoid(self.mint(fee_key=KEY1, fee_value=ym.fee_zat(coll, 50_000_000, 25) - 1), 'bad-mint-fee')
        # FEE-0 (no quote tag in (R - 10, R]) can never reach MINT-8 on regtest: PAYEE_WINDOW (10) covers
        # P_FAST_WINDOW (8), so an empty E(R) implies an undefined pFast and MINT-4's NO_PRICE halt
        c.mine_n(12, price_fn=lambda h: 0)
        raw = c.mint_tx(10_000, 48, c.height - 1, coll, fee_key=None, fee_vout=9)
        c.mine((1, 0, 0, KEY1), [raw])
        self.assertEqual(c.model.eligible_payees(c.height - 2), [])
        self.assertVoid(txid_of(raw), 'mint-halted-no-price')


class TransferTests(unittest.TestCase):

    def setUp(self):
        self.c = activated_chain()
        self.raw = self.c.mint_tx(10_000, 48, self.c.height - 1, collateral_for(self.c, 10_000, self.c.height - 1), fee_key=KEY1)
        self.c.mine((1, 50_000, 0, KEY2), [self.raw])
        self.t = txid_of(self.raw)

    # Rule: XFER-1
    def test_valid_transfer_and_remainder_burn(self):
        c = self.c
        raw = c.transfer_tx([(self.t, 1)], [(0, 6_000), (1, 4_000)])
        c.mine((1, 50_000, 0, KEY2), [raw])
        tx = txid_of(raw)
        rec = c.model.txlog[tx]
        self.assertEqual((rec.type, rec.verdict, rec.yed_in, rec.yed_out, rec.burned), ('TRANSFER', 'ok', 10_000, 10_000, 0))
        self.assertEqual(c.model.tokens[(tx, 0)].cents, 6_000)
        self.assertEqual(c.model.tokens[(tx, 1)].cents, 4_000)
        self.assertNotIn((self.t, 1), c.model.tokens)
        raw = c.transfer_tx([(tx, 1)], [(0, 1_000)])
        c.mine((1, 50_000, 0, KEY2), [raw])
        rec = c.model.txlog[txid_of(raw)]
        self.assertEqual((rec.verdict, rec.yed_out, rec.burned), ('burned', 1_000, 3_000))
        self.assertEqual(c.model.totals.supply_cents, 7_000)

    # Rule: XFER-1
    def test_bad_assignment(self):
        c = self.c
        raw = c.transfer_tx([(self.t, 1)], [(0, 99)])
        c.mine((1, 50_000, 0, KEY2), [raw])
        rec = c.model.txlog[txid_of(raw)]
        self.assertEqual((rec.verdict, rec.yed_out, rec.burned), ('bad-transfer-assignment', 0, 10_000))
        self.assertEqual(c.model.totals.supply_cents, 0)

    # Rule: XFER-2
    def test_over_assigned(self):
        c = self.c
        raw = c.transfer_tx([(self.t, 1)], [(0, 10_001)])
        c.mine((1, 50_000, 0, KEY2), [raw])
        rec = c.model.txlog[txid_of(raw)]
        self.assertEqual((rec.verdict, rec.yed_out, rec.burned), ('transfer-over-assigned', 0, 10_000))
        self.assertEqual(c.model.tokens, {})

    # Rule: XFER-3
    def test_no_yed_input(self):
        c = self.c
        raw = c.transfer_tx([], [(0, 500)])
        c.mine((1, 50_000, 0, KEY2), [raw])
        self.assertNotIn(txid_of(raw), c.model.txlog)  # touches nothing: no TxLog (N7)
        raw = c.transfer_tx([], [])
        c.mine((1, 50_000, 0, KEY2), [raw])
        self.assertNotIn(txid_of(raw), c.model.txlog)

    # Rule: IN-1
    def test_non_yellowback_tx_burns_tokens(self):
        c = self.c
        raw = ym.serialize_tx_v4([(self.t, 1, b'', 0xFFFFFFFF)], [(5000, ym.p2pkh_script(KEY1))]).hex()
        c.mine((1, 50_000, 0, KEY2), [raw])
        rec = c.model.txlog[txid_of(raw)]
        self.assertEqual((rec.type, rec.verdict, rec.yed_in, rec.yed_out, rec.burned), ('NONE', 'burned', 10_000, 0, 10_000))
        self.assertEqual(c.model.totals.supply_cents, 0)

    # Rule: TX-0
    def test_coinbase_payload_creates_nothing(self):
        c = self.c
        # a coinbase carrying a TRANSFER payload: fed as a coinbase, skipped entirely
        pl = ym.encode_transfer([(0, 500)])
        cb = ym.tx_from_hex(ym.serialize_tx_v4([(None, 0xFFFFFFFF, ym.height_prefix(c.height + 1), 0xFFFFFFFF)],
                                               [(1000, ym.p2pkh_script(KEY1)), (0, bytes([ym.OP_RETURN]) + ym.push(pl))]).hex())
        m = c.model
        m.feed_block(c.height + 1, '11' * 32, ym.height_prefix(c.height + 1).hex(), 1, [cb])
        self.assertNotIn(cb.txid, m.txlog)
        self.assertEqual(len(m.tokens), 1)


class RedeemTests(unittest.TestCase):

    def setUp(self):
        self.c = activated_chain()
        c = self.c
        self.ref = c.height - 1
        self.coll = collateral_for(c, 10_000, self.ref)
        raw = c.mint_tx(10_000, 48, self.ref, self.coll, fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY2), [raw])
        self.vault = (txid_of(raw), 0)
        self.token = (txid_of(raw), 1)
        self.lock = self.ref + 48
        self.script = ym.vault_script(self.lock, G_PUBKEY, self.lock + 24)
        # a second vault whose token funds the burn tests
        raw2 = c.mint_tx(10_000, 48, c.height - 1, collateral_for(c, 10_000, c.height - 1), fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY2), [raw2])
        self.vault2 = (txid_of(raw2), 0)
        self.token2 = (txid_of(raw2), 1)
        self.fee = ym.fee_zat(self.coll, 50_000_000, 25)
        while c.height < self.lock:
            c.mine_n(1, price_fn=lambda h: 50_000)

    def spend(self, path='owner', yed=None, assignments=(), fee_key=KEY1, fee_value=None, **kw):
        c = self.c
        yed = [self.token, self.token2] if yed is None else yed
        ref = kw.pop('ref_height', c.height - 1)
        raw = c.spend_tx(self.vault, self.script, path, yed, ref, fee_key,
                         self.fee if fee_value is None else fee_value, assignments, **kw)
        verdict = c.mine((1, 50_000, 0, KEY2), [raw])
        return txid_of(raw), verdict

    def assertFails(self, result, reason):
        txid, verdict = result
        rec = self.c.model.txlog[txid]
        self.assertEqual(rec.verdict, reason)
        self.assertEqual(rec.type, 'REDEEM')
        self.assertTrue(verdict.block_invalid)
        self.assertTrue(verdict.enforcement_on)
        self.assertTrue(verdict.rejected)
        self.assertEqual(verdict.reason, '%s:%s' % (reason, txid))
        v = self.c.model.vaults[self.vault]
        self.assertEqual(v.status, ym.V_CLOSED)
        self.assertEqual(rec.yed_out, 0)
        self.assertEqual(rec.burned, rec.yed_in)
        self.assertEqual(v.burned_cents, rec.yed_in)
        self.assertEqual(v.unbacked, rec.yed_in < 10_000)
        self.assertEqual(self.c.model.totals.unbacked_cents, max(0, 10_000 - rec.yed_in))
        self.assertEqual(self.c.model.totals.collateral_zat, self.c.model.vaults[self.vault2].collateral_zat)

    # Rule: RED-1
    def test_owner_redeem_ok(self):
        c = self.c
        txid, verdict = self.spend(assignments=[(3, 10_000)])
        self.assertFalse(verdict.block_invalid)
        rec = c.model.txlog[txid]
        self.assertEqual((rec.type, rec.path, rec.verdict, rec.yed_in, rec.yed_out, rec.burned, rec.fee_zat, rec.payee),
                         ('REDEEM', 'owner', 'ok', 20_000, 10_000, 10_000, self.fee, KEY1))
        v = c.model.vaults[self.vault]
        self.assertEqual((v.status, v.close_height, v.closing_txid, v.burned_cents, v.fee_paid_zat, v.unbacked),
                         (ym.V_CLOSED, c.height, txid, 10_000, self.fee, False))
        self.assertEqual(c.model.tokens[(txid, 3)].cents, 10_000)
        self.assertEqual(c.model.totals.supply_cents, 10_000)
        self.assertEqual(c.model.totals.active_vaults, 1)
        self.assertEqual(c.model.totals.closed_vaults, 1)
        self.assertEqual(c.model.totals.collateral_zat, c.model.vaults[self.vault2].collateral_zat)
        self.assertEqual(rec.closed_vaults, [self.vault])
        self.assertEqual(sorted(rec.spent_tokens), sorted([self.token, self.token2]))

    # Rule: RED-1
    def test_red1_malformed(self):
        self.assertFails(self.spend(payload=b''), 'vault-spend-malformed')                            # no payload (a sweep)
        self.setUp()
        self.assertFails(self.spend(payload=ym.encode_transfer([(3, 100)])), 'vault-spend-malformed')  # M3: TRANSFER payload
        self.setUp()
        self.assertFails(self.spend(script_sig=ym.push(self.script)), 'vault-spend-malformed')        # one push
        self.setUp()
        self.assertFails(self.spend(ref_height=self.c.height + 1), 'vault-spend-malformed')          # ref = H
        self.setUp()
        self.assertFails(self.spend(ref_height=self.c.height - 40), 'vault-spend-malformed')         # ref = H - 41
        self.setUp()
        self.assertFails(self.spend(assignments=[(3, 99)]), 'vault-spend-malformed')                  # XFER-1 bound
        self.setUp()
        self.assertFails(self.spend(first_input=self.c.fund_input()), 'vault-spend-malformed')       # vault not at vin[0]

    # Rule: RED-1
    def test_red1_two_active_vaults(self):
        c = self.c
        raw = c.spend_tx(self.vault, self.script, 'owner', [self.token, self.token2], c.height - 1, KEY1, self.fee,
                         [], extra_vaults=[self.vault2])
        c.mine((1, 50_000, 0, KEY2), [raw])
        rec = c.model.txlog[txid_of(raw)]
        self.assertEqual(rec.verdict, 'vault-spend-malformed')
        self.assertEqual(c.model.vaults[self.vault].status, ym.V_CLOSED)
        self.assertEqual(c.model.vaults[self.vault2].status, ym.V_CLOSED)
        self.assertEqual(c.model.totals.unbacked_cents, 0)        # 20,000 burned covers both
        self.assertEqual(c.model.totals.collateral_zat, 0)
        self.assertEqual(sorted(rec.closed_vaults), sorted([self.vault, self.vault2]))

    # Rule: M3
    def test_m3_mint_payload_on_vault_spend(self):
        c = self.c
        lock = c.height - 1 + 48
        pl = ym.encode_mint(0, 10_000, lock, c.height - 1, G2_PUBKEY, 0xFF)
        txid, verdict = self.spend(payload=pl)
        self.assertFails((txid, verdict), 'vault-spend-malformed')
        self.assertNotIn((txid, 0), c.model.vaults)             # no MINT rule ran
        self.assertEqual(c.model.txlog[txid].type, 'REDEEM')

    # Rule: RED-2
    def test_red2_burn(self):
        self.assertFails(self.spend(yed=[]), 'vault-spend-missing-burn')
        self.setUp()
        self.assertFails(self.spend(yed=[self.token], assignments=[(3, 10_000)]), 'vault-spend-missing-burn')
        self.setUp()
        self.assertFails(self.spend(yed=[self.token, self.token2], assignments=[(3, 10_001)]), 'vault-spend-short-burn')
        self.setUp()
        txid, verdict = self.spend(yed=[self.token, self.token2], assignments=[(3, 10_000)])
        self.assertFalse(verdict.block_invalid)
        self.setUp()
        txid, verdict = self.spend(yed=[self.token, self.token2], assignments=[])   # over-burn is allowed
        self.assertFalse(verdict.block_invalid)
        self.assertEqual(self.c.model.txlog[txid].burned, 20_000)
        self.assertEqual(self.c.model.totals.supply_cents, 0)

    # Rule: RED-3
    def test_red3_fee(self):
        self.assertFails(self.spend(fee_key=None), 'vault-spend-bad-payee')                     # P2PKH not in E(R)
        self.setUp()
        self.assertFails(self.spend(fee_key=OWNER_KEYHASH), 'vault-spend-bad-payee')
        self.setUp()
        self.assertFails(self.spend(fee_value=self.fee - 1), 'vault-spend-bad-fee')
        self.setUp()
        self.assertFails(self.spend(fee_vout=0xFF), 'vault-spend-bad-fee')
        self.setUp()
        self.assertFails(self.spend(fee_vout=2), 'vault-spend-bad-fee')                          # the OP_RETURN
        self.setUp()
        self.assertFails(self.spend(fee_vout=3, assignments=[(3, 1000)]), 'vault-spend-bad-fee')  # an assigned vout
        self.setUp()
        self.assertFails(self.spend(fee_vout=9), 'vault-spend-bad-fee')
        # K23: the fee may be the collateral destination
        self.setUp()
        c = self.c
        raw2 = ym.serialize_tx_v4(
            [(self.vault[0], 0, ym.push(SIG71) + bytes([ym.OP_1]) + ym.push(self.script), 0xFFFFFFFE),
             (self.token[0], 1, b'', 0xFFFFFFFF), (self.token2[0], 1, b'', 0xFFFFFFFF)],
            [(self.coll, ym.p2pkh_script(KEY1)), (0, bytes([ym.OP_RETURN]) + ym.push(ym.encode_redeem(c.height - 1, 0, [])))]).hex()
        verdict = c.mine((1, 50_000, 0, KEY2), [raw2])
        self.assertFalse(verdict.block_invalid)
        self.assertEqual(c.model.txlog[txid_of(raw2)].fee_zat, self.coll)
        # FEE-0 on a redeem: no quote tags in (R - 10, R]
        self.setUp()
        c = self.c
        c.mine_n(12, price_fn=lambda h: 0)
        txid, verdict = self.spend(fee_key=None, fee_vout=0xFF)
        self.assertFalse(verdict.block_invalid)
        self.assertEqual(c.model.vaults[self.vault].fee_paid_zat, 0)     # the close rewrote the mint's fee
        self.assertEqual(c.model.txlog[txid].fee_zat, 0)

    # Rule: RED-4
    def test_red4_claim(self):
        c = self.c
        while c.height < self.lock + 24:
            c.mine_n(1, price_fn=lambda h: 50_000)
        # not underwater at 50,000: claim fails
        self.assertFails(self.spend(path='claim'), 'vault-claim-not-underwater')
        # underwater: pClaim = max(pMid, pSlow) must fall below 11,000 with this collateral
        self.setUp()
        c = self.c
        while c.height < self.lock + 24:
            c.mine_n(1, price_fn=lambda h: 50_000)
        c.mine_n(64, price_fn=lambda h: 9_000)
        s = c.model.snapshot(c.height - 1)
        self.assertTrue(ym.is_underwater(self.coll, s.p_claim, 10_000, 11_000))
        txid, verdict = self.spend(path='claim', assignments=[(3, 10_000)])
        self.assertFalse(verdict.block_invalid)
        v = c.model.vaults[self.vault]
        self.assertEqual((v.status, v.burned_cents), (ym.V_CLAIMED, 10_000))
        self.assertEqual(c.model.txlog[txid].path, 'claim')
        self.assertEqual(c.model.totals.claimed_vaults, 1)
        # claim at a reference height whose pClaim is undefined: not underwater (M1)
        self.setUp()
        c = self.c
        while c.height < self.lock + 24:
            c.mine_n(1, price_fn=lambda h: 50_000)
        c.mine_n(64, price_fn=lambda h: 9_000)
        c.mine_n(12, price_fn=lambda h: 0)             # pMid over 24 with 12 quotes < 16: undefined
        self.assertIsNone(c.model.snapshot(c.height - 1).p_claim)
        self.assertFails(self.spend(path='claim', fee_vout=0xFF, fee_key=None), 'vault-claim-not-underwater')

    # Rule: ACT-5
    def test_block_valid_when_not_enforcing(self):
        c = Chain(ym.Params.regtest(1, enforce_until=150))
        c.mine_n(135, price_fn=lambda h: 50_000)
        ref = c.height - 1
        raw = c.mint_tx(10_000, 48, ref, collateral_for(c, 10_000, ref), fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY2), [raw])
        vault = (txid_of(raw), 0)
        script = ym.vault_script(ref + 48, G_PUBKEY, ref + 72)
        c.mine_n(60, price_fn=lambda h: 50_000)        # past the sunset at 150
        raw = c.spend_tx(vault, script, 'owner', [], c.height - 1, KEY1, 10 ** 9, payload=b'')
        verdict = c.mine((1, 50_000, 0, KEY2), [raw])
        self.assertTrue(verdict.block_invalid)
        self.assertFalse(verdict.enforcement_on)
        self.assertFalse(verdict.rejected)
        self.assertTrue(c.model.vaults[vault].unbacked)
        self.assertEqual(c.model.totals.unbacked_cents, 10_000)

    # Rule: IN-2
    def test_void_vault_spend_is_ordinary(self):
        c = self.c
        raw = c.mint_tx(5_000, 48, c.height - 1, 10 ** 12, fee_key=KEY1)     # VOID
        c.mine((1, 50_000, 0, KEY2), [raw])
        vault = (txid_of(raw), 0)
        self.assertEqual(c.model.totals.void_vaults, 1)
        script = ym.vault_script(c.height - 2 + 48, G_PUBKEY, c.height - 2 + 72)
        raw = c.spend_tx(vault, script, 'owner', [], c.height - 1, None, 0, payload=b'')
        verdict = c.mine((1, 50_000, 0, KEY2), [raw])
        self.assertFalse(verdict.block_invalid)
        v = c.model.vaults[vault]
        self.assertEqual((v.status, v.unbacked, v.burned_cents, v.closing_txid), (ym.V_CLOSED, False, 0, txid_of(raw)))
        self.assertEqual((c.model.totals.void_vaults, c.model.totals.closed_vaults), (0, 1))
        rec = c.model.txlog[txid_of(raw)]
        self.assertEqual((rec.type, rec.verdict, rec.closed_vaults), ('NONE', 'ok', [vault]))


# ===========================================================================
# section 3.6  State hash and the golden vector

GOLDEN_BLOCKS = 440


def build_golden():
    """The fixed synthetic sequence: regtest params {1, 0, 0, 0, 3, scriptsig}; 440 blocks; the v2
    lifecycle to 224, then the v3 one: four registrations, arming, a mint with a bundle, a VOID mint
    without one, a price fall, a notice and an emergency claim with a residual, dormancy, an
    equivocation, a revival and two bond spends."""
    params = ym.Params.regtest(1, 0, 0, 0)
    c = Chain(params)
    price = lambda h: (50_000 + (h % 5) * 100) if h <= 149 else (9_000 + (h % 3) * 10) if h <= 251 else (2_000 + (h % 3) * 5)  # noqa: E731
    key = lambda h: MINERS[h % 3]  # noqa: E731
    txs_at = {}
    v3 = {}     # heights and choices the v3 tail makes as it goes (deterministic; recorded for the tests)
    while c.height < GOLDEN_BLOCKS:
        h = c.height + 1
        txs = []
        if h == 136:
            ref = 134
            txs_at['mint1'] = c.mint_tx(10_000, 48, ref, collateral_for(c, 10_000, ref), fee_key=KEY1)
            txs.append(txs_at['mint1'])
        elif h == 137:
            txs_at['mint2'] = c.mint_tx(5_000, 48, 135, 10 ** 12, fee_key=KEY2)      # VOID: bad-mint-amount
            txs.append(txs_at['mint2'])
        elif h == 140:
            txs_at['xfer1'] = c.transfer_tx([(txid_of(txs_at['mint1']), 1)], [(0, 6_000), (1, 4_000)])
            txs.append(txs_at['xfer1'])
        elif h == 141:
            txs_at['mint3'] = c.mint_tx(10_000, 48, 139, collateral_for(c, 10_000, 139), fee_key=KEY3)
            txs.append(txs_at['mint3'])
        elif h == 142:
            txs_at['mint4'] = c.mint_tx(10_000, 48, 140, collateral_for(c, 10_000, 140), fee_key=KEY1)
            txs.append(txs_at['mint4'])
        elif h == 145:
            txs_at['xfer2'] = c.transfer_tx([(txid_of(txs_at['xfer1']), 1)], [(0, 5_000)])   # over-assigned: burns 4,000
            txs.append(txs_at['xfer2'])
        elif h == 185:
            v = c.model.vaults[(txid_of(txs_at['mint1']), 0)]
            script = ym.vault_script(v.lock_height, G_PUBKEY, v.claim_height)
            txs_at['redeem1'] = c.spend_tx((txid_of(txs_at['mint1']), 0), script, 'owner',
                                           [(txid_of(txs_at['xfer1']), 0), (txid_of(txs_at['mint4']), 1)], 183,
                                           KEY2, ym.fee_zat(v.collateral_zat, params.fee_min, params.fee_bps),
                                           [(3, 6_000)], collateral_out=v.collateral_zat - 10 ** 9)
            txs.append(txs_at['redeem1'])
        elif h == 215:
            v = c.model.vaults[(txid_of(txs_at['mint3']), 0)]
            script = ym.vault_script(v.lock_height, G_PUBKEY, v.claim_height)
            txs_at['claim3'] = c.spend_tx((txid_of(txs_at['mint3']), 0), script, 'claim',
                                          [(txid_of(txs_at['mint3']), 1), (txid_of(txs_at['redeem1']), 3)], 213,
                                          KEY3, ym.fee_zat(v.collateral_zat, params.fee_min, params.fee_bps),
                                          [(3, 6_000)], collateral_out=v.collateral_zat - 10 ** 9)
            txs.append(txs_at['claim3'])
        elif h == 217:
            v = c.model.vaults[(txid_of(txs_at['mint4']), 0)]
            script = ym.vault_script(v.lock_height, G_PUBKEY, v.claim_height)
            txs_at['sweep4'] = c.spend_tx((txid_of(txs_at['mint4']), 0), script, 'owner', [], 215, None, 0,
                                          payload=b'', collateral_out=v.collateral_zat - 1000)
            txs.append(txs_at['sweep4'])
        # ---- the v3 tail
        elif 225 <= h <= 228:                                   # REG-A1: seq 0..3, 10 YEC bonds, locktime H + 200
            i = h - 225
            txs_at['reg%d' % i] = c.register_tx(ATTESTORS[i][1], BONDS[i][1], h + 200, 10 * ym.COIN, flags=i)
            txs.append(txs_at['reg%d' % i])
        elif h == 230:                                          # burn the last 6,000 cents so the global ratio is undefined again
            txs_at['burn'] = c.transfer_tx([(txid_of(txs_at['claim3']), 3)], [])
            txs.append(txs_at['burn'])
        elif h == 250:                                          # MINT-9: a mint with a bundle at R = 248 (ARMED at 243)
            ref = 248
            bundle, sel = c.bundle_for(ref, b'', {'*': 9_000})
            x = c.model.snapshot(ref).p_mint
            collateral = collateral_for(c, 10_000, ref, p_mint=min(x, 9_000))
            fee = ym.fee_zat(collateral, params.fee_min, params.fee_bps)
            payee = sel[0]
            txs_at['mint5'] = c.mint_tx(10_000, 48, ref, collateral, fee_key=KEY1, carrier=bundle,
                                        attest_fee=(ym.hash160(BONDS[payee][1]), ym.attest_fee_zat(fee, params.attest_fee_bps)))
            txs.append(txs_at['mint5'])
            v3['mint5_selected'] = sel
        elif h == 251:                                          # MINT-9: the same shape without a carrier => VOID mint9-no-bundle
            ref = 249
            txs_at['mint6'] = c.mint_tx(10_000, 48, ref, collateral_for(c, 10_000, ref), fee_key=KEY2)
            txs.append(txs_at['mint6'])
        elif h == 290:                                          # NOT-1 at R = 288: attestors at 1,850, pools at ~2,000
            ref = 288
            vault = (txid_of(txs_at['mint5']), 0)
            sel = c.model.selected(ref, ya.outpoint_selector(*vault))
            v3['lazy'] = sel[0]                                 # the attestor that stops signing (dormancy)
            bundle, _ = c.bundle_for(ref, ya.outpoint_selector(*vault), {'*': 1_850}, skip=(v3['lazy'],))
            txs_at['notice5'] = c.notice_tx(vault, ref, bundle)
            txs.append(txs_at['notice5'])
        elif h >= 298 and 'claim5' not in txs_at:               # RED-4(b) + RED-5 at the first R >= 296 that selects the lazy attestor
            ref = h - 2
            vault = (txid_of(txs_at['mint5']), 0)
            selector = ya.outpoint_selector(*vault)
            sel = c.model.selected(ref, selector)
            if v3['lazy'] in sel:
                v = c.model.vaults[vault]
                script = ym.vault_script(v.lock_height, G_PUBKEY, v.claim_height)
                bundle, _ = c.bundle_for(ref, selector, {'*': 1_850}, skip=(v3['lazy'],))
                fee = ym.fee_zat(v.collateral_zat, params.fee_min, params.fee_bps)
                p_claim = max(c.model.snapshot(ref).p_claim, 1_850)
                residual = ym.residual_zat(v.collateral_zat, ym.claimant_max_zat(v.minted_cents, ym.BPS, p_claim))
                payee = [q for q in sel if q != v3['lazy']][0]
                txs_at['claim5'] = c.spend_tx(vault, script, 'claim', [(txid_of(txs_at['mint5']), 1)], ref, KEY3, fee,
                                              carrier=bundle, collateral_out=v.collateral_zat - residual - fee - 10 ** 8,
                                              attest_fee=(ym.hash160(BONDS[payee][1]), ym.attest_fee_zat(fee, params.attest_fee_bps)),
                                              residual=(ym.hash160(G_PUBKEY), residual))
                txs.append(txs_at['claim5'])
                v3['claim_height'] = h
                v3['residual'] = residual
                v3['dormancy_height'] = h + (-h) % 4            # the first DORMANCY_CHECK multiple at or after the claim
        elif 'claim_height' in v3 and h == v3['dormancy_height'] + 2:   # EQV-1: two prices for one block hash
            e = min(q for q in range(4) if q != v3['lazy'])
            v3['ejected'] = e
            a = ya.sign_attestation(ATTESTORS[e][0], e, 2_000, h - 1, c.block_hash(h - 1))
            b = ya.sign_attestation(ATTESTORS[e][0], e, 2_100, h - 1, c.block_hash(h - 1))
            txs_at['eqv'] = c.equivocation_tx(a, b)
            txs.append(txs_at['eqv'])
        elif 'claim_height' in v3 and h == v3['dormancy_height'] + 4:   # REV-1: the dormant attestor signs again
            lazy = v3['lazy']
            txs_at['revive'] = c.revive_tx(ya.sign_attestation(ATTESTORS[lazy][0], lazy, 2_000, h - 1, c.block_hash(h - 1)))
            txs.append(txs_at['revive'])
        elif h == GOLDEN_BLOCKS:                                # IN-2: two bond spends (one WITHDRAWN, the EJECTED one stays EJECTED)
            e = v3['ejected']
            w = max(q for q in range(4) if q not in (v3['lazy'], e))
            v3['withdrawn'] = w
            for name, q in (('spend_e', e), ('spend_w', w)):
                rec = c.model.attestors[q]
                txs_at[name] = c.bond_spend_tx(rec.bond_outpoint, ya.bond_script(BONDS[q][1], rec.bond_locktime), rec.bond_locktime)
                txs.append(txs_at[name])
        if h == 5:
            c.mine(None, txs)                                          # untagged
        elif h == 9:
            c.mine((1, 0, 0, key(h)), txs)                             # signal-only
        elif h == 13:
            c.mine((0x03, price(h), 0, key(h)), txs)                   # reserved flag: invalid == no tag
        elif h == 17:
            c.mine((1, price(h), 0x0007, key(h)), txs, extranonce=b'\x08' + b'\xee' * 8)
        elif h == 21:
            c.mine((0, price(h), 1, key(h)), txs)                      # quote without the signal bit
        else:
            c.mine((1, price(h), 0, key(h)), txs)
    c.v3 = v3
    return c, txs_at


def golden_document(c):
    return {
        'description': 'Yellowback v3 state-hash golden vector: regtest params {startHeight 1, sigmaRefBps 0, '
                       'supplyCapBps 0, enforceUntil 0, attestArmMin 3, bundleCarrier 0 (scriptsig)}; payload version 3; '
                       '%d synthetic blocks (see test_yellowback_model.build_golden): the v2 lifecycle to 224, then '
                       'registrations, arming, a mint with a bundle, a VOID mint without one, a notice and an emergency '
                       'claim with a residual, dormancy, an equivocation, a revival and two bond spends. '
                       'txs[0] of every block is the coinbase; the model reads its scriptSig only. '
                       'Block 217 fails BLK-1 (vault-spend-malformed) with enforcement on; it is applied anyway.' % GOLDEN_BLOCKS,
        'params': {'startHeight': 1, 'sigmaRefBps': 0, 'supplyCapBps': 0, 'enforceUntil': 0,
                   'attestArmMin': 3, 'bundleCarrier': ym.CARRIER_SCRIPTSIG},
        'stateHash': c.model.state_hash(),
        'tip': {'height': c.height, 'hash': c.block_hash(c.height)},
        'totals': c.model.totals.as_dict(),
        'blocks': c.blocks,
    }


class StateHashTests(unittest.TestCase):

    # Rule: N18
    def test_preimage_layout(self):
        m = ym.YellowbackModel(ym.Params.regtest(7, 1, 2, 3))
        pre = m.state_hash_preimage()
        # T + i32 0 + zero hash + u32 3 + "regtest"; C + SIGNALING; G totals; P params; N + u16 0; M + UNARMED
        self.assertEqual(pre[:1], b'T')
        self.assertEqual(pre[1:5], b'\x00\x00\x00\x00')
        self.assertEqual(pre[5:37], bytes(32))
        self.assertEqual(pre[37:41], b'\x03\x00\x00\x00')
        self.assertEqual(pre[41:49], b'\x07regtest')
        self.assertEqual(pre[49:59], b'C' + b'\x00' + bytes(8))
        self.assertEqual(pre[59:60], b'G')
        self.assertEqual(pre[60:100], bytes(40))
        # P: the four v2 i32 fields, then v3's attestArmMin u32 (3) and bundleCarrier u8 (0 = scriptsig) (M13)
        self.assertEqual(pre[100:122], b'P' + b'\x07\x00\x00\x00' + b'\x01\x00\x00\x00' + b'\x02\x00\x00\x00' + b'\x03\x00\x00\x00'
                         + b'\x03\x00\x00\x00' + b'\x00')
        # v3 (section 3.6): AttestorSeq (N + u16 next) and Attest (M + status u8 + i32 triggerHeight + i32 armHeight) always present
        self.assertEqual(pre[122:125], b'N\x00\x00')
        self.assertEqual(pre[125:], b'M' + bytes(9))
        m2 = ym.YellowbackModel(ym.Params.regtest(7, 1, 2, 3, attest_arm_min=0, bundle_carrier=ym.CARRIER_EITHER))
        self.assertEqual(m2.state_hash_preimage()[117:122], b'\x00\x00\x00\x00' + b'\x02')
        self.assertNotEqual(m2.state_hash(), m.state_hash())
        self.assertEqual(m.state_hash(), ym.sha256(pre).hex())

    # Rule: N18
    def test_tag_and_snapshot_records(self):
        c = Chain(ym.Params.regtest(1))
        c.mine((1, 50_000, 0x0102, KEY1))
        pre = c.model.state_hash_preimage()
        i = 49                                                        # right after the 49-byte Tip record
        self.assertEqual(pre[i:i + 5], b'Q\x00\x00\x00\x01')
        self.assertEqual(pre[i + 5:i + 25], KEY1)
        self.assertEqual(pre[i + 25:i + 33], (50_000).to_bytes(8, 'little'))
        self.assertEqual(pre[i + 33:i + 36], b'\x01\x02\x01')
        j = 49 + 36 + 10 + 41                                         # Tip, Tags[1], Activation, Totals
        self.assertEqual(pre[j:j + 5], b'S\x00\x00\x00\x01')
        rec = pre[j + 5:]
        self.assertEqual(rec[:32], bytes.fromhex(c.block_hash(1))[::-1])
        self.assertEqual(rec[32:34], b'\x01\x01')                     # tagged, quote
        self.assertEqual(rec[34:38], b'\x01\x00\x00\x00')             # signalCount
        self.assertEqual(rec[38:47], b'\x00' + bytes(8))              # activation
        self.assertEqual(rec[47:87], bytes(40))                       # five undefined prices as 0
        self.assertEqual(rec[87:91], (10_000).to_bytes(4, 'little'))  # sigmaMultBps
        self.assertEqual(rec[91:99], ym.regtest_subsidy(1).to_bytes(8, 'little'))
        self.assertEqual(rec[99:115], bytes(16))                      # supply, collateral
        self.assertEqual(rec[115:123], bytes(8))                      # globalRatio undefined
        self.assertEqual(rec[123:127], b'\x03\x00\x00\x00')           # NOT_ACTIVE | NO_PRICE
        self.assertEqual(rec[127:136], bytes(9))                      # v3: attest UNARMED/0/0
        self.assertEqual(rec[136:139], b'\x00\x00\x00')               # seated, pinnedKeys, pinnedSeqs empty
        self.assertEqual(rec[139:140], b'P')

    # Rule: N18
    def test_golden_vector(self):
        c, txs_at = build_golden()
        m = c.model
        # sanity on the sequence itself
        self.assertEqual(m.activation.status, ym.ACTIVE)
        self.assertEqual((m.activation.lock_in_height, m.activation.activate_height), (64, 128))
        self.assertNotIn(5, m.tags)
        self.assertNotIn(13, m.tags)
        self.assertIn(17, m.tags)
        self.assertFalse(m.tags[9].is_quote)
        self.assertEqual(m.vaults[(txid_of(txs_at['mint1']), 0)].status, ym.V_CLOSED)
        self.assertEqual(m.vaults[(txid_of(txs_at['mint2']), 0)].void_reason, 'bad-mint-amount')
        self.assertEqual(m.vaults[(txid_of(txs_at['mint3']), 0)].status, ym.V_CLAIMED)
        v4 = m.vaults[(txid_of(txs_at['mint4']), 0)]
        self.assertEqual((v4.status, v4.unbacked), (ym.V_CLOSED, True))
        self.assertEqual(m.txlog[txid_of(txs_at['xfer2'])].verdict, 'transfer-over-assigned')
        self.assertEqual(m.txlog[txid_of(txs_at['redeem1'])].verdict, 'ok')
        self.assertEqual(m.txlog[txid_of(txs_at['claim3'])].verdict, 'ok')
        self.assertEqual(m.txlog[txid_of(txs_at['sweep4'])].verdict, 'vault-spend-malformed')
        self.assertTrue(m.blocks[217].rejected)
        self.assertEqual([h for h, b in m.blocks.items() if b.block_invalid], [217])
        self.assertEqual(m.totals.as_dict(), {'supplyCents': 0, 'collateralZat': 0, 'activeVaults': 0,
                                              'voidVaults': 2, 'closedVaults': 2, 'claimedVaults': 2,
                                              'unbackedCents': 10_000})
        self.assertTrue(m.snapshots[224].halt_mask & ym.HALT_DIVERGENCE == 0)   # windows refilled at ~9,000
        # the v3 tail (v3 plan section 3.8): arming, a bundled mint, a bundle-less VOID mint, notice + emergency claim
        # with a residual, dormancy, ejection, revival, bond spends
        v3 = c.v3
        self.assertEqual((m.attest.status, m.attest.trigger_height, m.attest.arm_height), (ym.ARMED, 235, 243))
        self.assertEqual(m.snapshots[242].attest.status, ym.TRIGGERED)
        self.assertEqual(m.snapshots[243].attest.status, ym.ARMED)
        self.assertEqual(sorted(m.attestors), [0, 1, 2, 3])
        self.assertEqual(m.snapshots[248].seated, [0, 1, 2, 3])
        mint5 = m.txlog[txid_of(txs_at['mint5'])]
        self.assertEqual((mint5.verdict, mint5.a_mint, sorted(mint5.bundle_seqs), mint5.attest_payee), ('ok', 9_000, sorted(v3['mint5_selected']), v3['mint5_selected'][0]))
        self.assertEqual(m.vaults[(txid_of(txs_at['mint6']), 0)].void_reason, 'mint9-no-bundle')
        self.assertEqual(m.txlog[txid_of(txs_at['notice5'])].notice, True)
        self.assertEqual(m.bundle_log[290].a_claim, 1_850)
        claim5 = m.txlog[txid_of(txs_at['claim5'])]
        self.assertEqual((claim5.verdict, claim5.claim_path, claim5.residual_zat), ('ok', 'b', v3['residual']))
        self.assertTrue(claim5.residual_zat >= ym.Params.REGTEST_ATTEST['residual_min_zat'])
        self.assertEqual(m.vaults[(txid_of(txs_at['mint5']), 0)].status, ym.V_CLAIMED)
        self.assertEqual(m.notices, {})                                        # deleted when the vault left ACTIVE
        lazy, e, w = v3['lazy'], v3['ejected'], v3['withdrawn']
        self.assertEqual(m.snapshots[v3['dormancy_height']].attest.status, ym.ARMED)
        self.assertEqual(m.txlog[txid_of(txs_at['revive'])].attestor_seq, lazy)
        self.assertEqual(m.attestors[lazy].status, ym.A_ELIGIBLE)
        self.assertEqual(m.attestors[lazy].status_height, v3['dormancy_height'] + 4)
        self.assertEqual(m.attestors[e].status, ym.A_EJECTED)
        self.assertEqual(m.attestors[e].bond_spent_height, GOLDEN_BLOCKS)     # spent, still EJECTED
        self.assertEqual((m.attestors[w].status, m.attestors[w].status_height), (ym.A_WITHDRAWN, GOLDEN_BLOCKS))
        # the pinned hash, the file on disk and a replay from the file all agree
        self.assertEqual(m.state_hash(), GOLDEN_STATE_HASH)
        with open(GOLDEN_PATH) as f:
            doc = json.load(f)
        self.assertEqual(doc['stateHash'], GOLDEN_STATE_HASH)
        self.assertEqual(doc['blocks'], c.blocks)
        replayed = ym.replay_golden(doc)
        self.assertEqual(replayed.state_hash(), GOLDEN_STATE_HASH)
        self.assertEqual(replayed.state_hash_preimage(), m.state_hash_preimage())

    # Rule: N18
    def test_hash_changes_with_params(self):
        c1 = Chain(ym.Params.regtest(1, 0, 0, 0))
        c2 = Chain(ym.Params.regtest(1, 0, 0, 999))
        c1.mine_n(3)
        c2.mine_n(3)
        self.assertNotEqual(c1.model.state_hash(), c2.model.state_hash())
        # only P.enforceUntil differs: everything before it and the 18 bytes after it (attestArmMin, bundleCarrier, N, M) agree
        self.assertEqual(c1.model.state_hash_preimage()[:-22], c2.model.state_hash_preimage()[:-22])
        self.assertEqual(c1.model.state_hash_preimage()[-18:], c2.model.state_hash_preimage()[-18:])


class JsonFeedTests(unittest.TestCase):

    # Rule: SNAP
    def test_feed_block_json_shape(self):
        m = ym.YellowbackModel(ym.Params.regtest(1))
        ss = ym.height_prefix(1) + ym.tag_push(1, 50_000, 0, KEY1)
        blk = {'height': 1, 'hash': 'ab' * 32, 'tx': [
            {'txid': 'cd' * 32, 'vin': [{'coinbase': ss.hex(), 'sequence': 4294967295}],
             'vout': [{'value': Decimal('6.25'), 'n': 0, 'scriptPubKey': {'hex': ym.p2pkh_script(KEY1).hex()}}]},
            {'txid': 'ef' * 32, 'vin': [{'txid': '01' * 32, 'vout': 0, 'scriptSig': {'hex': ''}, 'sequence': 4294967295}],
             'vout': [{'valueZat': 1000, 'n': 0, 'scriptPubKey': {'hex': ym.p2pkh_script(KEY2).hex()}}]},
        ]}
        m.feed_block_json(blk, ym.regtest_subsidy(1))
        self.assertEqual(m.tags[1].payout_key, KEY1)
        self.assertEqual(m.snapshots[1].block_hash, 'ab' * 32)
        self.assertEqual(ym.tx_from_json(blk['tx'][0]).vout[0].value, 625_000_000)
        self.assertEqual(m.stats()['height'], 1)
        self.assertEqual(m.txinfo('ef' * 32), None)

    # Rule: SNAP
    def test_params_from_getinfo(self):
        p = ym.params_from_getinfo({'network': 'regtest', 'params': {'startHeight': 5, 'sigmaRefBps': 10_000,
                                                                     'supplyCapBps': 1_500, 'enforceUntilHeight': 0}})
        self.assertEqual((p.start_height, p.sigma_ref_bps, p.supply_cap_bps, p.enforce_until), (5, 10_000, 1_500, 0))
        self.assertEqual(p.p_slow_window, 64)


def write_golden():
    c, _ = build_golden()
    doc = golden_document(c)
    with open(GOLDEN_PATH, 'w') as f:
        json.dump(doc, f, indent=1)
        f.write('\n')
    print('wrote %s: %d blocks, stateHash %s' % (GOLDEN_PATH, len(doc['blocks']), doc['stateHash']))


if __name__ == '__main__':
    if '--write-golden' in sys.argv:
        write_golden()
    else:
        unittest.main()
