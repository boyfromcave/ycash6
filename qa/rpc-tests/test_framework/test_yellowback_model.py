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

Regenerate the golden vector (after a deliberate protocol or serialisation change only, in a commit of its own:
doc/yellowback-testing.md, "The golden vector"):

    ../../../../.venv/bin/python test_yellowback_model.py --write-golden

Check that the committed golden is exactly what the model and build_golden produce (byte for byte, the whole
document; CI's python job, audit 03/T-1):

    ../../../../.venv/bin/python test_yellowback_model.py --check-golden

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
    from test_framework import vault as va
else:
    from . import yellowback_model as ym
    from . import yellowback_attest as ya
    from . import vault as va

from decimal import Decimal  # noqa: E402  (used by the getblock-2 dict test)

GOLDEN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yellowback_golden.json')

# The golden sequence's state hash is the committed file's ``stateHash`` (audit 03/T-4: one artifact, no third copy
# here).  The reviewer-recomputed pin is the C++ ``GOLDEN_HASH`` in src/test/yellowback_state_tests.cpp, whose
# ``statehash_golden_vector`` replays yellowback_golden.json; test_golden_vector asserts the model reproduces both.


def cpp_golden_hash():
    """The C++ pin (``GOLDEN_HASH`` in src/test/yellowback_state_tests.cpp), read from the source."""
    import re
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'src', 'test', 'yellowback_state_tests.cpp')
    with open(path) as f:
        m = re.search(r'^const std::string GOLDEN_HASH = "([0-9a-f]{64})";', f.read(), re.M)
    return m.group(1)

# secp256k1 generator, compressed: a valid owner key that needs no library
G_PUBKEY = bytes.fromhex('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')
G2_PUBKEY = bytes.fromhex('02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5')  # 2G
BAD_PUBKEY = b'\x02' + b'\x00' * 32   # x = 0: 7 is not a square mod p
# Post-quantum owner ids (quantum spec section 3.1): scheme 0x01 (SLH-DSA) || a 32-byte key hash; the model checks no signature
G_OWNER = bytes([0x01]) + ym.sha256(b'yellowback-golden-owner-1')
G2_OWNER = bytes([0x01]) + ym.sha256(b'yellowback-golden-owner-2')
BAD_OWNER = bytes([0x03]) + bytes(32)  # an unregistered scheme

KEY1 = ym.hash160(b'yellowback-golden-miner-1')
KEY2 = ym.hash160(b'yellowback-golden-miner-2')
KEY3 = ym.hash160(b'yellowback-golden-miner-3')
MINERS = [KEY1, KEY2, KEY3]
OWNER_KEYHASH = ym.hash160(b'owner')
SIG71 = bytes(range(1, 72))          # a placeholder signature push; the model verifies no signature
# The framework's fixed regtest attestor / bond keys (yellowback_attest.py): [(secret32, pubkey33)]
ATTESTORS = [(sec, bytes.fromhex(pub)) for sec, pub in ya.attestor_keys(5)]
# P4-b: an attestor's bond is keyed by its member key (the set's bond B), so the "bond keys" are the attestor keys
BONDS = ATTESTORS


def attestor_set_create(liveness_window=1_000_000, maturity=8, seats=15, unlock_threshold=1, cancel_threshold=1):
    """P4-b: the attestor set's SET_CREATE (open, 1/1/1 thresholds by default), from a fixed input; its txid is the set id."""
    act = va.act_set_create(seats, unlock_threshold, cancel_threshold, 1, G2_PUBKEY, flags=va.SET_FLAG_OPEN, rate_window=1000,
                            liveness_window=liveness_window, bond_min=1, bond_lock_min=0, maturity=maturity)
    vin = [(ym.sha256(b'yellowback-attestor-set')[::-1].hex(), 0, b'', 0xFFFFFFFF)]
    return ym.serialize_tx_v4(vin, [(0, va.act_script(va.encode_act(act)))]).hex()


def attestor_set_id(**kw):
    return ym.tx_from_hex(attestor_set_create(**kw)).txid


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
        self.refused = {}      # U-21: txid -> the verdict that made it invalid (its block was rejected and mined again without it)
        self.refused_logs = {}  # txid -> the model's TxLogRecord of the refused evaluation
        self.side = False       # rejected(): fund inputs come from a separate namespace
        self.side_funding = 0

    def block_hash(self, h):
        return ym.sha256(b'golden-block-%d' % h)[::-1].hex()

    def coinbase(self, h, scriptsig):
        raw = ym.serialize_tx_v4([(None, 0xFFFFFFFF, scriptsig, 0xFFFFFFFF)],
                                 [(ym.regtest_subsidy(h), ym.p2pkh_script(KEY1))])
        return raw

    def mine(self, tag=None, txs=(), extranonce=b'', raw_scriptsig=None):
        """Mine the next block.  ``tag`` = (flags, price, mask, key) or None; ``txs`` = raw hex list.
        U-21: a block with an invalid transaction is rejected (recorded in the document as ``invalid``)
        and the height is mined again without that transaction, as a miner's template filter would.
        Returns the first verdict (the rejected block's when there was one)."""
        h = self.height + 1
        if raw_scriptsig is not None:
            ss = raw_scriptsig
        else:
            ss = ym.height_prefix(h) + extranonce
            if tag is not None:
                ss += ym.tag_push(*tag)
        cb = self.coinbase(h, ss)
        subsidy = ym.regtest_subsidy(h)
        txs = list(txs)
        first = None
        while True:
            raws = [cb.hex()] + txs
            parsed = [ym.tx_from_hex(x) for x in raws]
            verdict = self.model.feed_block(h, self.block_hash(h), ss.hex(), subsidy, parsed)
            row = {'height': h, 'hash': self.block_hash(h), 'subsidyZat': subsidy, 'txs': raws}
            if verdict is not None and verdict.block_invalid:
                row['invalid'] = True
                self.blocks.append(row)
                bad = verdict.reason.split(':', 1)[1]
                self.refused[bad] = verdict.verdict
                self.refused_logs[bad] = self.model.last_failed
                first = first or verdict
                txs = [x for x in txs if txid_of(x) != bad]
                continue
            self.blocks.append(row)
            self.height = h
            return first or verdict

    def void_reason(self, txid):
        """What v2 called the VOID reason: the verdict that made the mint invalid ('' for an ACTIVE vault)."""
        return self.refused.get(txid, '')

    def mine_n(self, n, price_fn=None, signal=True, key_fn=None):
        for _ in range(n):
            h = self.height + 1
            key = MINERS[h % 3] if key_fn is None else key_fn(h)
            price = 0 if price_fn is None else price_fn(h)
            self.mine((1 if signal else 0, price, 0, key))

    def fund_input(self):
        if self.side:
            self.side_funding += 1
            return (ym.sha256(b'rejected-funding-%d' % self.side_funding)[::-1].hex(), 0, b'', 0xFFFFFFFF)
        self.funding += 1
        return (outpoint_hex(self.funding), 0, b'', 0xFFFFFFFF)

    def rejected(self, build):
        """Build a transaction the module must refuse (U-21) with fund and carrier inputs from a separate namespace,
        so adding it to a block leaves every accepted transaction -- and so the state hash -- byte-identical."""
        self.side = True
        try:
            return build()
        finally:
            self.side = False

    # -- transaction builders (section 3.5 shapes) --------------------------

    def carrier_input(self, bundle):
        """A carrier-shaped input (section 3.4) whose redeem script commits to ``bundle``; the model
        verifies no script, so the signature push is a placeholder."""
        redeem = ya.carrier_script(G2_PUBKEY, ym.sha256(bundle))
        t, n, _ss, seq = self.fund_input()
        return (t, n, ya.carrier_scriptsig(bundle, SIG71, redeem), seq)

    def mint_tx(self, cents, lock_blocks, ref_height, collateral, fee_key=None, fee_value=None,
                owner=G_OWNER, term_class=0, yed_inputs=(), fee_vout=None, vout0_script=None,
                opret_at=2, lock_height=None, carrier=None, attest_fee=None, token_script=None, p_mint=None):
        """``carrier`` = a bundle (bytes) carried by an extra input; ``attest_fee`` = (bond key hash, zat)
        paid at vout 4 (after the pool fee) and named by attestFeeVout. The default fee is FEE-1' at ``p_mint``
        (default the snapshot's xMint at ``ref_height``; an ARMED mint passes min(xMint, aMint))."""
        lock = ref_height + lock_blocks if lock_height is None else lock_height
        vin = [self.fund_input()] + [(t, n, b'', 0xFFFFFFFF) for t, n in yed_inputs]
        if carrier is not None:
            vin.append(self.carrier_input(carrier))
        if fee_vout is None:
            fee_vout = 3 if fee_key is not None else ym.FEE_VOUT_NONE
        attest_fee_vout = 4 if attest_fee is not None else ym.FEE_VOUT_NONE
        payload = ym.encode_mint(term_class, cents, lock, ref_height, owner, fee_vout, attest_fee_vout)
        if vout0_script is None:                                   # U-23: the V template (a P2PKH placeholder if it cannot be built)
            vout0_script = ym.yed_vault_script(self.params, owner, ref_height) or ym.p2pkh_script(OWNER_KEYHASH)
        vout0 = vout0_script
        vouts = [(collateral, vout0), (self.params.token_value, token_script or ym.p2pkh_script(OWNER_KEYHASH))]
        opret = (0, bytes([ym.OP_RETURN]) + ym.push(payload))
        if opret_at == 2:
            vouts.append(opret)
        elif opret_at == 1:
            vouts.insert(1, opret)
        if fee_key is not None:
            if fee_value is None:
                fee_value = self.mint_fee(cents, ref_height, p_mint)
            vouts.append((fee_value, ym.p2pkh_script(fee_key)))
        if attest_fee is not None:
            vouts.append((attest_fee[1], ym.p2pkh_script(attest_fee[0])))
        return ym.serialize_tx_v4(vin, vouts, 0, ref_height + self.params.ref_window).hex()

    def mint_fee(self, cents, ref_height, p_mint=None):
        """FEE-1': the protocol fee of a mint of ``cents`` at ``p_mint`` (default the snapshot's xMint at ``ref_height``); 0 without a price."""
        if p_mint is None:
            s = self.model.snapshot(ref_height)
            p_mint = None if (s is None or s.virtual) else s.p_mint
        fee = ym.protocol_fee_zat(cents, p_mint, self.params)
        return 0 if fee is None else fee

    def vault_fee(self, vault_op, height=None, owner=True):
        """RED-3' (and IT-9' for an owner spend mined at ``height`` below lockHeight): the fee a spend of the vault pays."""
        v = self.model.vaults[vault_op]
        fee = ym.protocol_fee_zat(v.minted_cents, v.p_mint, self.params)
        if owner and height is not None and height < v.lock_height:
            fee += ym.early_redeem_fee_zat(v.minted_cents, self.params.early_redeem_fee_bps[v.term_class], v.p_mint)
        return fee

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
        """A vault spend (U-23): vin[0] = vault (owner: <sig> OP_2; claim: OP_4; ``selector`` = the
        selector byte(s) to use instead), vin[1..] = YED inputs, then (claim) a fee input, then the carrier
        input when ``carrier`` (a bundle) is given; vout[0] = collateral (owner) or the claimant's intent
        paying OWNER_KEYHASH of the vault's value less the residual (claim), vout[1] = fee, vout[2] =
        OP_RETURN, vout[3..] = assigned token outputs, then the attestor fee (``attest_fee`` = (bond key
        hash, zat)) and the residual (``residual`` = (owner key hash, zat); the owner's intent on a claim).
        ``vault_script`` is unused since the V is rebuilt from the model's record (kept for the call sites)."""
        v = self.model.vaults.get(vault_op)
        claim = path == 'claim'
        if script_sig is None:
            if selector is None:
                selector = bytes([ym.OP_2]) if path == 'owner' else bytes([ym.OP_4])
            script_sig = (ym.push(SIG71) if path == 'owner' else b'') + selector
        vin = [(vault_op[0], vault_op[1], script_sig, 0xFFFFFFFE)]
        if first_input is not None:
            vin.insert(0, first_input)
        vin += [(t, n, b'', 0xFFFFFFFF) for t, n in yed_inputs]
        vin += [(t, n, ym.push(SIG71) + bytes([ym.OP_2]), 0xFFFFFFFE) for t, n in extra_vaults]
        if claim:
            vin.append(self.fund_input())
        if carrier is not None:
            vin.append(self.carrier_input(carrier))
        if claim and v is not None:
            res = residual[1] if residual is not None else 0
            vouts = [(v.collateral_zat - res, ym.yed_intent_script(self.params, v.owner_pubkey, v.owner_height, v.app_height, ym.p2pkh_script(OWNER_KEYHASH)))]
        else:
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
            spk = ym.p2pkh_script(residual[0]) if len(residual[0]) == 20 else residual[0]   # a key hash or a script (PQPKH, F-3)
            if claim and v is not None:
                spk = ym.yed_intent_script(self.params, v.owner_pubkey, v.owner_height, v.app_height, spk)
            vouts.append((residual[1], spk))
        return ym.serialize_tx_v4(vin, vouts, 0, ref_height + self.params.ref_window).hex()

    def release_tx(self, intent_op, value, recipient_spk=None):
        """U-23: the RELEASE of a claim intent (selector 1, nSequence = CLAIM_DELAY) paying its recipient; a fee input."""
        vin = [(intent_op[0], intent_op[1], bytes([ym.OP_1]), self.params.claim_delay), self.fund_input()]
        return ym.serialize_tx_v4(vin, [(value, recipient_spk or ym.p2pkh_script(OWNER_KEYHASH))]).hex()

    def cancel_tx(self, intent_op, vault_op_of_record, value, vouts=None, selector=ym.OP_2, refund=False, cosigns=None):
        """U-23: the attestor CANCEL of a claimant intent (selector 2; the set signatures are placeholders the model
        does not verify) re-creating the byte-identical vault at vout[0]; a fee input.  ``refund``: CAN-1's refund output
        at vout[1] (``self.refund_out(intent_op)``).  ``vouts`` = [(value, script)] replaces the outputs (the re-lock
        is ``self.relock(vault_op_of_record, value)``); ``selector`` the last opcode.  ``cosigns`` (CAN-2 + C4b): "YC"
        entries [(price, sig65)] carried by a carrier input, with the CANCEL_COSIGN marker as the last output."""
        if vouts is None:
            vouts = [self.relock(vault_op_of_record, value)] + ([self.refund_out(intent_op)] if refund else [])
        vin = [(intent_op[0], intent_op[1], ym.push(bytes(65)) + bytes([selector]), 0xFFFFFFFF), self.fund_input()]
        if cosigns:
            vin.append(self.carrier_input(ya.encode_cancel_cosigns(cosigns)))
            vouts = list(vouts) + [(0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_cancel_cosign()))]
        return ym.serialize_tx_v4(vin, vouts).hex()

    def cosign(self, intent_op, seq, price, ref=None, block_hash=None, member=None):
        """CAN-2 + C4b: member ``seq``'s (ATTESTORS[seq], or ``member``) co-signature of the cancel of ``intent_op``: its
        price statement at ``ref`` (default the intent's claim_ref_height)."""
        if ref is None:
            ref = self.model.intents[intent_op].claim_ref_height
        secret = (member or ATTESTORS[seq])[0]
        return ya.sign_cancel_cosign(secret, self.params.attestor_set_internal, intent_op[0], intent_op[1], ref, price,
                                     block_hash or self.block_hash(ref))

    def cancel_evidence_tx(self, att74, intent_op, entry):
        """C4b: an EQUIVOCATION whose carrier holds a regular attestation and a cancel statement ("YX")."""
        vin = [self.carrier_input(ya.encode_cancel_evidence(att74, intent_op[0], intent_op[1], entry[0], entry[1]))]
        vouts = [(0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_equivocation())), (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts).hex()

    def refund_out(self, intent_op):
        """CAN-1 (03/H-1): the refund output a cancel of the claimant intent carries -- a token carrier paying the
        holder the claim's burn came from (the intent's refund_script)."""
        return (self.params.token_value, self.model.intents[intent_op].refund_script)

    def relock(self, vault_op_of_record, value):
        """The output a cancel re-creates: the claimed vault's byte-identical V of ``value``."""
        v = self.model.vaults[vault_op_of_record]
        return (value, ym.yed_vault_script_at(self.params, v.owner_pubkey, v.owner_height, v.app_height))

    # -- v3 builders (section 3.5) -------------------------------------------

    def legacy_register_tx(self, hot_pubkey, bond_pubkey, bond_locktime, bond_zat, flags=0):
        """The v3 ATTESTOR_REGISTER payload (invalid since P4-b)."""
        vin = [self.fund_input()]
        vouts = [(bond_zat, ym.p2sh_script(ya.bond_script(bond_pubkey, bond_locktime))),
                 (0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_attestor_register(hot_pubkey, bond_pubkey, bond_locktime, flags))),
                 (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts).hex()

    def act_tx(self, act, signer_secrets=(), before=()):
        """A ``YV`` act transaction (P4-b): a funding input, ``before`` outputs, the act signed over actMsg, change."""
        vin = [self.fund_input()]
        payload = va.encode_act(act)
        msg = va.act_msg(payload, vin[0][0], vin[0][1])
        sigs = [va.sign_recoverable(sec, msg) for sec in signer_secrets]
        vouts = list(before) + [(0, va.act_script(payload, sigs)), (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts).hex()

    def register_tx(self, member, bond_locktime, bond_zat):
        """P4-b: ``member`` = (secret32, pubkey33) joins the attestor set: vout[0] its bond, vout[1] the SET_JOIN."""
        act = va.act_set_join(self.params.attestor_set_internal, member[1], bond_locktime, 0)
        return self.act_tx(act, [member[0]], [(bond_zat, ym.p2sh_script(ya.bond_script(member[1], bond_locktime)))])

    def heartbeat_tx(self, member):
        return self.act_tx(va.act_set_heartbeat(self.params.attestor_set_internal, member[1]), [member[0]])

    def remove_tx(self, target_pubkey, signer, burn=0):
        return self.act_tx(va.act_set_remove(self.params.attestor_set_internal, target_pubkey, burn), [signer[0]])

    def notice_tx(self, vault_op, ref_height, bundle):
        vin = [self.fund_input(), self.carrier_input(bundle)]
        vouts = [(0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_claim_notice(vault_op[0], vault_op[1], ref_height))),
                 (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts, 0, ref_height + self.params.ref_window).hex()

    def equivocation_tx(self, att_a, att_b):
        vin = [self.carrier_input(ya.encode_bundle([att_a, att_b]))]
        vouts = [(0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_equivocation())), (1000, ym.p2pkh_script(OWNER_KEYHASH))]
        return ym.serialize_tx_v4(vin, vouts).hex()

    def legacy_revive_tx(self, att74):
        """The v3 ATTESTOR_REVIVE payload (invalid since P4-b)."""
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
    """A chain whose windows are full (quotes at 50,000) at 135 (the module is active from START, U-22;
    135 blocks keeps v2's heights, when activation took 128)."""
    params = params or ym.Params.regtest(1)
    c = Chain(params, **kw)
    c.mine_n(135, price_fn=lambda h: 50_000)
    assert c.model.snapshots[135].halt_mask == 0
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
        self.assertIsNone(ym.find_tag(self.ss(5, ym.tag_push(1, 4_294_967_296, 0, KEY1)), 5, self.P))   # PRICE_MAX + 1 (D-Q-22)
        self.assertIsNotNone(ym.find_tag(self.ss(5, ym.tag_push(1, 100, 0, KEY1)), 5, self.P))
        self.assertIsNotNone(ym.find_tag(self.ss(5, ym.tag_push(1, 100_000_001, 0, KEY1)), 5, self.P))  # above the old $100 bound
        self.assertIsNotNone(ym.find_tag(self.ss(5, ym.tag_push(1, 4_294_967_295, 0, KEY1)), 5, self.P))  # PRICE_MAX

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
        b = ym.encode_mint(1, 12_345, 500, 460, G_OWNER, 3, 4)
        self.assertEqual(len(b), 52)
        p = ym.decode_payload(b)
        self.assertEqual((p.type, p.term_class, p.cents, p.lock_height, p.ref_height, p.owner_pubkey, p.fee_vout, p.attest_fee_vout),
                         (ym.PAYLOAD_MINT, 1, 12_345, 500, 460, G_OWNER, 3, 4))
        self.assertEqual(ym.decode_payload(ym.encode_mint(1, 12_345, 500, 460, G_OWNER, 3)).attest_fee_vout, 0xFF)

    # Rule: MINT-1
    def test_mint_is_version_4_other_types_version_3(self):
        # quantum spec header C-1: the MINT alone is payload version 4; a v3 MINT and a v4 TRANSFER are non-Yellowback
        b = ym.encode_mint(1, 12_345, 500, 460, G_OWNER, 3, 4)
        self.assertEqual(b[2], 4)
        self.assertEqual(b[17], 0x01)
        self.assertEqual(b[18:50], G_OWNER[1:])
        self.assertIsNone(ym.decode_payload(b[:2] + b'\x03' + b[3:]))
        t = ym.encode_transfer([(0, 100)])
        self.assertEqual(t[2], 3)
        self.assertIsNone(ym.decode_payload(t[:2] + b'\x04' + t[3:]))
        self.assertEqual(ym.encode_redeem(1, 1, [])[2], 3)

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
        good = ym.encode_mint(0, 10_000, 100, 50, G_OWNER, 0xFF)
        self.assertIsNone(ym.decode_payload(good[:-1]))                 # short
        self.assertIsNone(ym.decode_payload(good + b'\x00'))            # trailing
        self.assertIsNone(ym.decode_payload(b'YA' + good[2:]))          # magic
        self.assertIsNone(ym.decode_payload(b'YB\x01' + good[3:]))      # version 1 ignored (V23)
        self.assertIsNone(ym.decode_payload(b'YB\x02' + good[3:]))      # version 2 ignored (V23)
        self.assertIsNone(ym.decode_payload(b'YB\x05' + good[3:]))      # later version ignored
        self.assertIsNone(ym.decode_payload(b'YB\x03' + good[3:]))      # a v3 MINT ignored (quantum spec C-1)
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

    # Rule: FEE-1'
    def test_fee(self):
        p = ym.Params.regtest(1)
        # the bands (D-Q-23): $100 pays the $1 floor, $1,000 $10, $10,000 $55, $100,000 $145; cent-bps, ceil to the cent
        self.assertEqual(ym.protocol_fee_units(10_000, p), 1_000_000)
        self.assertEqual(ym.protocol_fee_units(100_000, p), 10_000_000)
        self.assertEqual(ym.protocol_fee_units(100_001, p), 10_000_050)
        self.assertEqual(ym.protocol_fee_units(1_000_000, p), 55_000_000)
        self.assertEqual(ym.protocol_fee_units(1_000_001, p), 55_000_010)
        self.assertEqual(ym.protocol_fee_units(10_000_000, p), 145_000_000)
        self.assertEqual(ym.protocol_fee_units(0, p), 0)
        self.assertEqual(ym.protocol_fee_cents(100_001, p), 1_001)
        # zat = ceil(units x COIN / pMint): the fees spec §1.3 worked values
        self.assertEqual(ym.protocol_fee_zat(10_000, 100, p), 10 ** 12)
        self.assertEqual(ym.protocol_fee_zat(10_000, 18_000, p), 5_555_555_556)
        self.assertEqual(ym.protocol_fee_zat(10_000, 4_294_967_295, p), 23_284)
        self.assertEqual(ym.protocol_fee_zat(10_000_000, 18_000, p), 805_555_555_556)
        self.assertEqual(ym.protocol_fee_zat(10_000_000, 100, p), 145 * 10 ** 12)
        self.assertIsNone(ym.protocol_fee_zat(10_000, None, p))
        self.assertIsNone(ym.protocol_fee_zat(10_000, 0, p))
        # IT-9': bps of the debt at pMint, ceil, no floor
        self.assertEqual(ym.early_redeem_fee_zat(10_000, 500, 50_000), 10 ** 10)
        self.assertEqual(ym.early_redeem_fee_zat(10_000_000, 500, 18_000), 27_777_777_777_778)
        self.assertEqual(ym.early_redeem_fee_zat(10_000, 0, 50_000), 0)
        self.assertEqual(ym.early_redeem_fee_zat(10_000, 500, None), 0)
        self.assertEqual(ym.early_redeem_fee_zat(10_000_000, 500, 100), ym.MAX_MONEY)

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

    # Rule: HALT-1
    def test_halts_no_price_and_not_active(self):
        # the module is active from START (U-22): NOT_ACTIVE marks only the virtual snapshot below it
        c = self.chain()
        c.mine_n(1, signal=True)
        self.assertEqual(c.model.snapshots[1].halt_mask, ym.HALT_NO_PRICE)
        self.assertEqual(c.model.snapshots[1].halt_names(), ['NO_PRICE'])
        self.assertEqual(c.model.snapshot(0).halt_names(), ['NOT_ACTIVE', 'NO_PRICE'])
        # non-signal tags halt nothing any more (v2's PARTICIPATION / ENFORCEMENT halts)
        c2 = activated_chain()
        c2.mine_n(40, signal=False, price_fn=lambda h: 50_000)
        self.assertEqual(c2.model.snapshots[c2.height].halt_mask, 0)

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
            coll = collateral_for(c, cents if 10_000 <= cents <= 10_000_000 else 10_000, ref, tc if tc in (0, 1, 2) else 0)
        fee_key = kw.pop('fee_key', KEY1)
        raw = c.mint_tx(cents, lock_blocks, ref, coll, fee_key=fee_key, **kw)
        c.mine((1, 50_000, 0, KEY2), [raw])
        return txid_of(raw)

    def assertVoid(self, txid, reason):
        """U-21, section 15.10: a failing mint is an invalid transaction (v2 registered a VOID vault): its block
        was rejected, nothing of it is in the state."""
        self.assertEqual(self.c.refused.get(txid), reason)
        self.assertNotIn((txid, 0), self.c.model.vaults)
        self.assertNotIn(txid, self.c.model.txlog)
        self.assertEqual(self.c.refused_logs[txid].yed_out, 0)
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
        self.assertEqual(v.p_mint, c.model.snapshot(ref).p_mint)                      # FEE-1': the mint price is stored
        self.assertEqual(v.fee_paid_zat, ym.protocol_fee_zat(10_000, v.p_mint, c.params))
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
        self.assertGreaterEqual(s.global_ratio_bps, 30_000)      # class A's 300 % (D-IT-4)

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
        # an invalid mint with YED inputs burns nothing: it is never applied (U-21)
        t3 = self.mint(cents=5_000, yed_inputs=[(t2, 1)])
        self.assertEqual(c.refused[t3], 'bad-mint-amount')
        self.assertIn((t2, 1), c.model.tokens)
        self.assertEqual(c.model.totals.supply_cents, 10_000)

    # Rule: MINT-2
    def test_mint2_verdicts(self):
        self.assertVoid(self.mint(term_class=3), 'bad-mint-class')
        self.assertVoid(self.mint(cents=9_999), 'bad-mint-amount')
        self.assertVoid(self.mint(cents=10_000_001), 'bad-mint-amount')      # D-Q-24: $100,000 + one cent
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
        self.assertEqual(c.void_reason(txid_of(raw)), 'bad-mint-ref-height')

    # Rule: MINT-3
    # Rule: TOK-PQ
    def test_mint3_falcon_owner_and_tokpq(self):
        # quantum spec R-A2, A-5, F-7: a Falcon owner and the holder rule bind from the Falcon height only
        c = self.c
        falcon_owner = bytes([ym.PQ_SCHEME_FALCON]) + ym.sha256(b'falcon-owner')
        falcon_holder = ym.pqpkh_script(bytes([ym.PQ_SCHEME_FALCON]) + ym.sha256(b'falcon-holder'))
        self.assertEqual(len(falcon_holder), 35)
        self.assertEqual(ym.pqpkh_owner(falcon_holder)[0], 2)
        c.params.pq_falcon_height = c.height + 3
        self.assertVoid(self.mint(owner=falcon_owner), 'bad-mint-owner-key')          # below the height
        ok = self.mint(token_script=ym.pqpkh_script(G_OWNER))                            # any holder below it
        self.assertIn((ok, 0), c.model.vaults)
        while c.height + 1 < c.params.pq_falcon_height:
            c.mine((1, 50_000, 0, KEY2), [])
        bad = self.mint()                                                                # P2PKH token at the height
        self.assertEqual(c.refused.get(bad), 'bad-yed-holder')
        good = self.mint(owner=falcon_owner, token_script=falcon_holder)
        self.assertIn((good, 0), c.model.vaults)
        self.assertIn((good, 1), c.model.tokens)
        # D-Q-19: a hybrid channel token holds from the Falcon height iff its client is a Falcon key
        ch = ym.pqchannel_script(bytes([2]) + ym.sha256(b'channel-client'), G2_PUBKEY, 1000)
        self.assertEqual(ym.pqchannel_client(ch)[0], 2)
        self.assertEqual(len(ch), 114)
        self.assertIn((self.mint(token_script=ch), 0), c.model.vaults)
        slh_ch = ym.pqchannel_script(G_OWNER, G2_PUBKEY, 1000)
        self.assertEqual(c.refused.get(self.mint(token_script=slh_ch)), 'bad-yed-holder')
        self.assertIsNone(ym.pqchannel_client(slh_ch[:-1]))

    # Rule: MINT-3
    def test_mint3_verdicts(self):
        c = self.c
        ref = c.height - 1
        # fewer than three outputs: the V at vout[0] and the OP_RETURN only
        lock = ref + 48
        pl = ym.encode_mint(0, 10_000, lock, ref, G_OWNER, 0xFF)
        raw = ym.serialize_tx_v4([c.fund_input()], [(10 ** 12, ym.yed_vault_script(c.params, G_OWNER, ref)),
                                                    (0, bytes([ym.OP_RETURN]) + ym.push(pl))]).hex()
        c.mine((1, 50_000, 0, KEY2), [raw])
        self.assertVoid(txid_of(raw), 'bad-mint-outputs')
        self.assertVoid(self.mint(owner=BAD_OWNER), 'bad-mint-owner-key')
        self.assertVoid(self.mint(vout0_script=ym.p2sh_script(b'\x51')), 'bad-mint-vault-script')
        # U-23: v2's P2SH vault is refused for new mints, and so is a P2PKH vout[0]
        self.assertVoid(self.mint(vout0_script=ym.p2sh_script(ym.vault_script(c.height - 1 + 48, G_PUBKEY, c.height - 1 + 72))),
                        'bad-mint-vault-script')
        self.assertVoid(self.mint(vout0_script=ym.p2pkh_script(KEY1)), 'bad-mint-vault-script')
        # a V under another set is not the YED vault
        other = ym.Params.regtest(1, attestor_set='77' * 32)
        self.assertVoid(self.mint(vout0_script=ym.yed_vault_script(other, G_OWNER, c.height - 1)), 'bad-mint-vault-script')
        # IT-1: the pre-plan shape (ownerHeight = lockHeight, appHeight = lockHeight + GRACE) is refused for a new mint
        self.assertVoid(self.mint(vout0_script=ym.yed_vault_script_at(c.params, G_OWNER, c.height - 1 + 48, c.height - 1 + 48 + c.params.grace)),
                        'bad-mint-vault-script')

    # Rule: MINT-4
    def test_mint4_not_active(self):
        # active from START (U-22): a mint at the first fully priced height goes through; before the windows fill, no price
        c = Chain(ym.Params.regtest(1))
        c.mine_n(20, price_fn=lambda h: 50_000)
        raw = c.mint_tx(10_000, 48, 19, 10 ** 12, fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), 'mint-halted-no-price')
        c.mine_n(80, price_fn=lambda h: 50_000)
        raw = c.mint_tx(10_000, 48, c.height - 1, 10 ** 12, fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.model.vaults[(txid_of(raw), 0)].status, ym.V_ACTIVE)

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
        self.assertEqual(c2.void_reason(txid_of(raw)), 'mint-halted-no-price')

    # Rule: HALT-2
    def test_mint4_global_ratio(self):
        c = self.c
        self.mint()                                    # 10,000 cents backed at 300 % (class A)
        c.mine_n(64, price_fn=lambda h: 9_000)         # price / 5.5: ratio ~ 5,400 bps < 25,000; slow window fully refilled
        s = c.model.snapshots[c.height]
        self.assertTrue(s.halt_mask & ym.HALT_GLOBAL_RATIO)
        self.assertEqual(s.halt_mask & ym.HALT_DIVERGENCE, 0)
        # W16 / IT-5: the halt stops the classes whose base ratio is below the recapitalisation floor (A 300 %, B 400 %) ...
        raw = c.mint_tx(10_000, 48, c.height - 1, 10 ** 13, fee_key=KEY1)
        c.mine((1, 9_000, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), 'mint-halted-global-ratio')
        raw = c.mint_tx(10_000, 97, c.height - 1, 10 ** 13, fee_key=KEY1, term_class=1)
        c.mine((1, 9_000, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), 'mint-halted-global-ratio')
        # ... and lets class C (500 %, the floor) through, which is what repairs the ratio
        self.assertTrue(c.model.snapshots[c.height].halt_mask & ym.HALT_GLOBAL_RATIO)
        raw = c.mint_tx(10_000, 145, c.height - 1, 10 ** 13, fee_key=KEY1, term_class=2)
        c.mine((1, 9_000, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), '')

    # Rule: MINT-5
    def test_mint5_collateral(self):
        c = self.c
        ref = c.height - 1
        coll = collateral_for(c, 10_000, ref)
        req = ym.required_zat(10_000, c.params.base_ratio_bps[0], c.model.snapshot(ref).p_mint)
        self.assertVoid(self.mint(collateral=req - 1), 'bad-mint-collateral')
        t = self.mint(collateral=req)
        self.assertEqual(c.model.vaults[(t, 0)].status, ym.V_ACTIVE)
        self.assertLessEqual(req, coll)
        # MINT-5' (D-Q-23): the 4 * FEE_MIN floor (2 YEC) is gone; at PRICE_MAX ($4,294.97, D-Q-22) MIN_MINT at
        # 300 % needs 0.07 YEC and that is the collateral (every fee is <= 2 % of it, fees spec §1.6)
        self.assertEqual(ym.required_zat(10_000, 30_000, 4_294_967_295), 6_984_920)

    # Rule: MINT-5
    def test_mint5_unsatisfiable(self):
        # D-IT-5 pins the multiplier at 1 (sigma_mult_max_bps 10,000) even at a 10,000 reference with undefined samples
        c = activated_chain(ym.Params.regtest(1, sigma_ref_bps=10_000))
        c.mine_n(64, price_fn=lambda h: 100)           # PRICE_MIN
        s = c.model.snapshot(c.height - 1)
        self.assertEqual(s.sigma_mult_bps, 10_000)
        raw = c.mint_tx(1_000_000, 48, c.height - 1, ym.MAX_MONEY, fee_key=KEY1)
        c.mine((1, 100, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), 'mint-unsatisfiable')

    # Rule: MINT-6
    def test_mint6_supply_cap(self):
        c = activated_chain(ym.Params.regtest(1, supply_cap_bps=1_500))
        s = c.model.snapshot(c.height - 1)
        cap = ym.supply_cap_cents(s.issued_zat, s.p_mint, 1_500)
        self.assertIsNotNone(cap)
        # issued ~ 135 blocks * 6.25 YEC ~ 843 YEC * $0.05 = $42 -> cap = 15 % of that ~ 632 cents < MIN_MINT
        self.assertLess(cap, 10_000)
        # W20 / IT-5: over the cap only a mint whose class base ratio reaches RECAP_RATIO_BPS (500 %) is
        # accepted. Class A (300 %, lock 48) is refused; class C (500 %, lock 145) goes through and supply
        # ends above the cap.
        raw = c.mint_tx(10_000, 48, c.height - 1, 10 ** 12, fee_key=KEY1)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), 'mint-supply-cap')
        raw = c.mint_tx(10_000, 145, c.height - 1, 10 ** 12, fee_key=KEY1, term_class=2)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), '')
        self.assertGreater(c.model.totals.supply_cents, cap)

    # Rule: MINT-6b
    def test_mint6b_vault_share(self):
        # D-Q-23a: one mint's debt <= max(max_vault_share_bps of the cap, vault_share_floor_cents); silent without a cap.
        # D-Q-25: the cap's base is the circulating supply, here 50,000 YEC below the start plus the chain's blocks.
        p = ym.Params.regtest(1, supply_cap_bps=10_000)
        p.vault_share_floor_cents = 10_000
        c = activated_chain(p, issued_before_start=50_000 * ym.COIN)
        self.assertEqual(ym.max_vault_cents(None, 1_000, 1_000_000), None)
        self.assertEqual(ym.max_vault_cents(100_000_000, 1_000, 1_000_000), 10_000_000)
        self.assertEqual(ym.max_vault_cents(5_000_000, 1_000, 1_000_000), 1_000_000)
        self.assertEqual(ym.max_vault_cents(100_000_000, 0, 1_000_000), None)

        def max_vault(ref):
            s = c.model.snapshot(ref)
            return ym.max_vault_cents(ym.supply_cap_cents(s.issued_zat, s.p_mint, 10_000), p.max_vault_share_bps, p.vault_share_floor_cents)
        ref = c.height - 1
        self.assertTrue(10_000 < max_vault(ref) < p.max_mint)
        raw = c.mint_tx(max_vault(ref), 145, ref, collateral_for(c, max_vault(ref), ref, 2), fee_key=KEY1, term_class=2)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), '')
        ref = c.height - 1
        raw = c.mint_tx(max_vault(ref) + 1, 145, ref, collateral_for(c, max_vault(ref) + 1, ref, 2), fee_key=KEY1, term_class=2)
        c.mine((1, 50_000, 0, KEY1), [raw])
        self.assertEqual(c.void_reason(txid_of(raw)), 'mint-vault-share')

    # Rule: D-Q-30
    def test_dq28_bond_min_from_collateral(self):
        m, r = ym.Params.mainnet(1), ym.Params.regtest(1)
        f = ym.bond_min_from_collateral_zat
        for coll, yec in ((0, 10_000), (-1, 10_000), (900_000, 10_000), (1_800_000, 10_000), (3_600_000, 20_000), (10_000_000, 20_000)):
            self.assertEqual(f(coll * ym.COIN, m), yec * ym.COIN)
        self.assertEqual(f(1_800_000 * ym.COIN + 1, m), 10_000 * ym.COIN + 1)
        self.assertEqual(f(3_600_000 * ym.COIN - 180, m), 20_000 * ym.COIN - 1)
        self.assertEqual(f(0, r), 5 * ym.COIN)
        self.assertEqual(f(700 * ym.COIN, r), 7 * ym.COIN)
        self.assertEqual(f(1_300 * ym.COIN, r), 10 * ym.COIN)

    # Rule: D-Q-30: the model's SNAP mirrors yellowback_state_tests dq28_bond_min_from_collateral
    def test_dq28_bond_min_from_snapshot_collateral(self):
        c = activated_chain(ym.Params.regtest(1, 0, 0, attestor_set_id(), attest_arm_min=0), )
        tag = lambda: (1, 50_000, 0, MINERS[(c.height + 1) % 3])  # noqa: E731
        self.assertEqual(c.model.bond_min_zat(c.height + 1), 5 * ym.COIN)
        c.mine(tag(), [attestor_set_create()])
        # seats re-review: a join below the minimum at its block is invalid (never recorded)
        below = c.register_tx(ATTESTORS[0], c.height + 1 + 200, 5 * ym.COIN - 1)
        c.mine(tag(), [below, c.register_tx(ATTESTORS[1], c.height + 1 + 200, 5 * ym.COIN)])
        self.assertEqual(c.refused[txid_of(below)], 'attestor-bond-below-min')
        ref = c.height - 1
        raw = c.mint_tx(10_000, 48, ref, collateral_for(c, 10_000, ref), fee_key=KEY1)     # $100 at 300 % and $0.05 = 6,000 YEC
        c.mine(tag(), [raw])
        self.assertEqual(c.model.snapshots[c.height].collateral_zat, collateral_for(c, 10_000, ref))
        self.assertEqual(c.model.bond_min_zat(c.height + 1), 10 * ym.COIN)                # far above 1,000 YEC: the cap
        late = c.register_tx(ATTESTORS[2], c.height + 1 + 200, 5 * ym.COIN)
        c.mine(tag(), [late])
        self.assertEqual(c.refused[txid_of(late)], 'attestor-bond-below-min')
        c.mine_n(c.params.bond_maturity, price_fn=lambda h: 50_000)
        self.assertEqual(sorted(c.model.attestors), [0])
        self.assertEqual(c.model.attestors[0].status, ym.A_ELIGIBLE)     # judged at its own snapshot, before the mint

    # Rule: RED-5'
    def test_red5_residual_threshold(self):
        p = ym.Params.regtest(1)
        self.assertEqual(ym.residual_min_zat(18_000, p), 2_666_666_667)        # $0.48 at $0.018 (ceil)
        self.assertEqual(ym.residual_min_zat(50_000, p), 960_000_000)
        self.assertEqual(ym.residual_min_zat(480_000_000, p), 100_000)          # exactly the floor
        self.assertEqual(ym.residual_min_zat(4_294_967_295, p), 100_000)        # below the floor: the floor
        self.assertEqual(ym.residual_min_zat(None, p), 100_000)
        self.assertEqual(ym.residual_min_zat(100, p), 480_000_000_000)

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
        self.assertVoid(self.mint(fee_key=KEY1, fee_value=c.mint_fee(10_000, c.height - 1) - 1), 'bad-mint-fee')
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
        self.fee = c.vault_fee(self.vault)         # RED-3': spent at or after lockHeight below, no early fee
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
        """U-21: the failing spend is an invalid transaction; its block is rejected and nothing changes (v2
        closed the vault, unbacked when the burn fell short)."""
        txid, verdict = result
        rec = self.c.refused_logs[txid]
        self.assertEqual(rec.verdict, reason)
        self.assertEqual(rec.type, 'REDEEM')
        self.assertTrue(verdict.block_invalid)
        self.assertTrue(verdict.rejected)
        self.assertEqual(verdict.reason, '%s:%s' % (reason, txid))
        self.assertNotIn(txid, self.c.model.txlog)
        v = self.c.model.vaults[self.vault]
        self.assertEqual(v.status, ym.V_ACTIVE)
        self.assertEqual(rec.yed_out, 0)
        self.assertEqual(v.burned_cents, 0)
        self.assertFalse(v.unbacked)
        self.assertEqual(self.c.model.totals.unbacked_cents, 0)
        self.assertEqual(self.c.model.totals.collateral_zat, self.coll + self.c.model.vaults[self.vault2].collateral_zat)

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
        self.assertFails(self.spend(script_sig=ym.push(self.script)), 'vault-spend-malformed')        # no selector
        self.setUp()
        self.assertFails(self.spend(selector=bytes([ym.OP_1])), 'vault-spend-malformed')              # a set unlock is never a YED path
        self.setUp()
        self.assertFails(self.spend(selector=ym.push(b'\x02')), 'vault-spend-malformed')               # a non-minimal 2
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
        self.assertEqual(c.refused[txid_of(raw)], 'vault-spend-malformed')
        self.assertEqual(c.model.vaults[self.vault].status, ym.V_ACTIVE)
        self.assertEqual(c.model.vaults[self.vault2].status, ym.V_ACTIVE)

    # Rule: M3
    def test_m3_mint_payload_on_vault_spend(self):
        c = self.c
        lock = c.height - 1 + 48
        pl = ym.encode_mint(0, 10_000, lock, c.height - 1, G2_OWNER, 0xFF)
        txid, verdict = self.spend(payload=pl)
        self.assertFails((txid, verdict), 'vault-spend-malformed')
        self.assertNotIn((txid, 0), c.model.vaults)             # no MINT rule ran
        self.assertEqual(c.refused_logs[txid].type, 'REDEEM')

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
            [(self.vault[0], 0, ym.push(SIG71) + bytes([ym.OP_2]), 0xFFFFFFFE),
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
        self.assertEqual((v.status, v.burned_cents), (ym.V_CLAIMING, 10_000))       # U-23: until the release
        self.assertEqual(c.model.txlog[txid].path, 'claim')
        self.assertEqual(c.model.intents, {(txid, 0): c.model.intents[(txid, 0)]})
        self.assertEqual(c.model.intents[(txid, 0)].role, ym.I_CLAIMANT)
        self.assertEqual(c.model.totals.claimed_vaults, 0)
        rel = c.release_tx((txid, 0), self.coll)
        self.assertFalse(c.mine((1, 9_000, 0, KEY2), [rel]).block_invalid)
        self.assertEqual(c.model.vaults[self.vault].status, ym.V_CLAIMED)
        self.assertEqual(c.model.txlog[txid_of(rel)].type, 'CLAIM_RELEASE')
        self.assertEqual(c.model.intents, {})
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

class CancelTests(unittest.TestCase):
    """U-23/U-24/I-2 and CAN-1: the attestor cancel of a claim intent -- the model twins of yellowback_state_tests'
    intent_cancel_* cases (audit 03/T-2, 03/H-1)."""

    HONEST = 50_000     # the co-signers' price ($0.05: the vault at 300 %, not claimable)

    def setUp(self):
        # ATTEST_ARM_MIN 10: the four members (CAN-2 co-signers) never arm the chain, so the claim stays unarmed path (a)
        self.c = c = activated_chain(ym.Params.regtest(1, 0, 0, attestor_set_id(), attest_arm_min=10))
        c.mine((1, 50_000, 0, KEY2), [attestor_set_create()])
        for i in range(4):
            c.mine((1, 50_000, 0, KEY2), [c.register_tx(ATTESTORS[i], c.height + 1, 10 * ym.COIN)])
        c.mine_n(c.params.bond_maturity, price_fn=lambda h: 50_000)
        self.assertEqual(sorted(c.model.attestors), [0, 1, 2, 3])
        ref = c.height - 1
        self.coll = collateral_for(c, 10_000, ref)
        raw = c.mint_tx(10_000, 48, ref, self.coll, fee_key=KEY1)
        raw2 = c.mint_tx(10_000, 48, ref, self.coll, fee_key=KEY1, token_script=ym.p2pkh_script(KEY3))
        c.mine((1, 50_000, 0, KEY2), [raw, raw2])
        self.vault = (txid_of(raw), 0)
        self.token = (txid_of(raw), 1)
        self.spare = (txid_of(raw2), 1)          # another holder's 10,000 cents
        self.holder = ym.p2pkh_script(OWNER_KEYHASH)
        c.mine_n(64, price_fn=lambda h: 9_000)
        self.before = ym.Totals()
        for k in self.before.__slots__:
            setattr(self.before, k, getattr(c.model.totals, k))
        claim = c.spend_tx(self.vault, None, 'claim', [self.token], c.height - 1, KEY1, c.vault_fee(self.vault, owner=False))
        self.assertFalse(c.mine((1, 9_000, 0, KEY2), [claim]).block_invalid)
        self.claim = txid_of(claim)
        self.intent = (self.claim, 0)
        self.assertEqual(c.model.vaults[self.vault].status, ym.V_CLAIMING)
        self.after_claim = c.model.totals.supply_cents

    def mine(self, raw):
        """Returns the verdict that refused ``raw`` ('' when it was applied)."""
        self.c.mine((1, 9_000, 0, KEY2), [raw])
        return self.c.refused.get(txid_of(raw), '')

    def cancel(self, vouts=None, seqs=(0,), price=None, **kw):
        """The cancel, by default co-signed by member 0 at HONEST (CAN-2's first cancel)."""
        if 'cosigns' not in kw:
            kw['cosigns'] = [self.c.cosign(self.intent, s, price or self.HONEST) for s in seqs]
        return self.c.cancel_tx(self.intent, self.vault, self.coll, vouts=vouts, refund=True, **kw)

    # Rule: U-23
    # Rule: U-24
    # Rule: CAN-1
    # Rule: I-2
    # Rule: IT-6
    def test_cancel_recreates_the_vault_at_vout0(self):
        c, m = self.c, self.c.model
        self.assertEqual(self.after_claim, self.before.supply_cents - 10_000)
        raw = self.cancel()
        self.assertEqual(self.mine(raw), '')
        txid = txid_of(raw)
        self.assertNotIn(self.vault, m.vaults)
        v = m.vaults[(txid, 0)]
        self.assertEqual((v.status, v.minted_cents, v.burned_cents, v.collateral_zat, v.close_height, v.closing_txid),
                         (ym.V_ACTIVE, 10_000, 0, self.coll, 0, None))
        rec = m.txlog[txid]
        self.assertEqual((rec.type, rec.verdict, rec.closed_vaults, rec.reopened_vaults, rec.burned, rec.assigned, rec.yed_out),
                         ('CLAIM_CANCEL', 'ok', [self.vault], [(txid, 0)], 0, [(1, 10_000)], 10_000))
        self.assertEqual(m.intents, {})
        t = m.totals
        self.assertEqual((t.active_vaults, t.claimed_vaults, t.collateral_zat),
                         (self.before.active_vaults, self.before.claimed_vaults, self.before.collateral_zat))
        # CAN-1 (03/H-1, 03/M-1): the claim's burn is re-issued to the holder it came from and supply is back
        tok = m.tokens[(txid, 1)]
        self.assertEqual((tok.cents, tok.script_pub_key, tok.n_value), (10_000, self.holder, c.params.token_value))
        self.assertEqual(t.supply_cents, self.before.supply_cents)
        self.assertEqual(t.supply_cents, self.after_claim + 10_000)

    # Rule: CAN-1
    def test_claim_records_the_refund_holder(self):
        ir = self.c.model.intents[self.intent]
        self.assertEqual((ir.role, ir.refund_script), (ym.I_CLAIMANT, self.holder))

    # Rule: CAN-1
    def test_cancel_without_the_refund_invalid(self):
        c = self.c
        relock = c.relock(self.vault, self.coll)
        for vouts in ([relock],                                                    # no refund output
                      [relock, (c.params.token_value, ym.p2pkh_script(KEY3))],      # to another script
                      [relock, (0, self.holder)]):                                 # a zero carrier
            self.assertEqual(self.mine(self.cancel(vouts=vouts)), 'intent-cancel-no-refund')
        # the refund at vout 0 displaces the re-lock: the re-lock rule speaks first
        self.assertEqual(self.mine(self.cancel(vouts=[c.refund_out(self.intent), relock])), 'intent-cancel-no-vault')
        self.assertEqual(c.model.vaults[self.vault].status, ym.V_CLAIMING)
        self.assertEqual(c.model.totals.supply_cents, self.after_claim)

    # Rule: CAN-1
    def test_refund_at_the_lowest_holder_output(self):
        c, m = self.c, self.c.model
        relock = c.relock(self.vault, self.coll)
        raw = self.cancel(vouts=[relock, (777, ym.p2pkh_script(KEY3)), (5_000, self.holder), (6_000, self.holder)])
        self.assertEqual(self.mine(raw), '')
        self.assertEqual(m.tokens[(txid_of(raw), 2)].cents, 10_000)
        self.assertNotIn((txid_of(raw), 3), m.tokens)

    # Rule: CAN-1
    # Rule: IN-3
    def test_cancel_yed_inputs_still_burn(self):
        """A cancel's YED inputs burn as any non-Yellowback spend's do; the refund is re-issued, not carried."""
        c, m = self.c, self.c.model
        vouts = [c.relock(self.vault, self.coll), c.refund_out(self.intent)]
        vin = [(self.intent[0], self.intent[1], ym.push(bytes(65)) + bytes([ym.OP_2]), 0xFFFFFFFF), c.fund_input(),
               (self.spare[0], self.spare[1], b'', 0xFFFFFFFF), c.carrier_input(ya.encode_cancel_cosigns([c.cosign(self.intent, 0, self.HONEST)]))]
        vouts = vouts + [(0, bytes([ym.OP_RETURN]) + ym.push(ya.encode_cancel_cosign()))]
        raw = ym.serialize_tx_v4(vin, vouts).hex()
        self.assertEqual(self.mine(raw), '')
        rec = m.txlog[txid_of(raw)]
        self.assertEqual((rec.yed_in, rec.yed_out, rec.burned), (10_000, 10_000, 10_000))
        self.assertEqual(m.totals.supply_cents, self.after_claim + 10_000 - 10_000)

    # Rule: CAN-1
    # Rule: XFER-1
    def test_refund_spendable(self):
        c, m = self.c, self.c.model
        raw = self.cancel()
        self.assertEqual(self.mine(raw), '')
        xfer = c.transfer_tx([(txid_of(raw), 1)], [(0, 10_000)])
        self.assertEqual(self.mine(xfer), '')
        self.assertNotIn((txid_of(raw), 1), m.tokens)
        self.assertEqual(m.tokens[(txid_of(xfer), 0)].cents, 10_000)
        self.assertEqual(m.txlog[txid_of(xfer)].verdict, 'ok')

    # Rule: U-23
    # Rule: U-24
    def test_cancel_of_residual_invalid(self):
        c = self.c
        c.model.intents[self.intent].role = ym.I_RESIDUAL      # the owner's residual intent (role flipped for the unit)
        self.assertEqual(self.mine(self.cancel()), 'intent-cancel-residual')
        self.assertIn(self.intent, c.model.intents)

    # Rule: U-23
    # Rule: I-2
    def test_cancel_relock_shapes_invalid(self):
        c = self.c
        relock = c.relock(self.vault, self.coll)
        refund = c.refund_out(self.intent)
        change = (1000, ym.p2pkh_script(OWNER_KEYHASH))
        other = ym.yed_vault_script_at(c.params, G2_OWNER, c.model.vaults[self.vault].owner_height, c.model.vaults[self.vault].app_height)
        for vouts in ([change, relock, refund], [relock, (1000, relock[1]), refund], [(self.coll, ym.p2pkh_script(OWNER_KEYHASH)), refund],
                      [(self.coll, other), refund]):
            self.assertEqual(self.mine(self.cancel(vouts=vouts)), 'intent-cancel-no-vault')
        self.assertEqual(c.model.vaults[self.vault].status, ym.V_CLAIMING)

    # Rule: U-23
    def test_cancel_payload_or_selector3_malformed(self):
        c = self.c
        payload = (0, bytes([ym.OP_RETURN]) + ym.push(ym.encode_transfer([])))
        self.assertEqual(self.mine(self.cancel(vouts=[c.relock(self.vault, self.coll), c.refund_out(self.intent), payload], cosigns=None)),
                         'intent-spend-malformed')
        self.assertEqual(self.mine(self.cancel(selector=ym.OP_3)), 'intent-spend-malformed')

    # Rule: U-23
    # Rule: NOT-1
    def test_cancel_erases_the_notice(self):
        c = self.c
        c.model.notices[self.vault] = ym.NoticeRecord(c.height, c.height - 2, 9_000)    # forced in at the CLAIMING outpoint
        raw = self.cancel()
        self.assertEqual(self.mine(raw), '')
        self.assertEqual(c.model.notices, {})

    # Rule: U-23
    # Rule: UNDO
    def test_cancel_refused_leaves_the_state(self):
        c = self.c
        raw = self.cancel(vouts=[(1000, ym.p2pkh_script(OWNER_KEYHASH)), c.relock(self.vault, self.coll)])
        self.assertEqual(self.mine(raw), 'intent-cancel-no-vault')
        # U-21: only the re-mined (empty) block moved the state: the CLAIMING record and the intent are untouched
        self.assertEqual(c.model.vaults[self.vault].status, ym.V_CLAIMING)
        self.assertIn(self.intent, c.model.intents)
        self.assertEqual(c.model.txlog.get(txid_of(raw)), None)


class CancelLimitTests(CancelTests):
    """The per-vault cancel limit (cancel-limit design, owner 2026-10-13): CAN-2's schedule and quiet reset, the CAN-2 +
    C4b co-signature refusals, CAN-3's held residual and C4b's EQV-1 statement slash -- the model twins of
    yellowback_state_tests' cancel_limit_* / cancel_cosign_* / cancel_statement_* cases."""

    def reclaim(self, pos):
        """Claim ``pos`` again with the refund token at pos:1 (under theta at $0.009); returns the new claimant intent."""
        c = self.c
        ref = c.height - 1
        payee = sorted(c.model.eligible_payees(ref))[0]
        claim = c.spend_tx(pos, None, 'claim', [(pos[0], 1)], ref, payee, c.vault_fee(pos, owner=False))
        self.assertEqual(self.mine(claim), '')
        self.assertEqual(c.model.vaults[pos].status, ym.V_CLAIMING)
        return (txid_of(claim), 0)

    def cancel_of(self, intent, pos, seqs, price=None):
        c = self.c
        return c.cancel_tx(intent, pos, self.coll, vouts=[c.relock(pos, self.coll), c.refund_out(intent)],
                           cosigns=[c.cosign(intent, s, price or self.HONEST) for s in seqs])

    # Rule: CAN-2
    def test_escalation_schedule_and_cap(self):
        c, m = self.c, self.c.model
        self.assertEqual((c.params.cancel_signers_max, c.params.cancel_quiet), (3, 40))
        pos, intent = self.vault, self.intent
        minted = m.vaults[pos]
        for rnd in range(1, 6):
            if rnd > 1:
                intent = self.reclaim(pos)
            need = min(rnd, c.params.cancel_signers_max)
            self.assertEqual(m.cancels_required(m.vaults[pos], c.height + 1), need)
            if need > 1:
                self.assertEqual(self.mine(self.cancel_of(intent, pos, range(need - 1))), 'intent-cancel-cosign')
            raw = self.cancel_of(intent, pos, range(need))
            self.assertEqual(self.mine(raw), '')
            pos = (txid_of(raw), 0)
            v = m.vaults[pos]
            self.assertEqual((v.status, v.cancel_count, v.last_cancel_height, v.mint_height, v.p_mint),
                             (ym.V_ACTIVE, rnd, c.height, minted.mint_height, minted.p_mint))
            self.assertEqual(m.txlog[pos[0]].bundle_seqs, list(range(need)))

    # Rule: CAN-2
    def test_quiet_resets_the_schedule(self):
        c, m = self.c, self.c.model
        raw = self.cancel()
        self.assertEqual(self.mine(raw), '')
        first, pos = c.height, (txid_of(raw), 0)
        while c.height + 2 < first + c.params.cancel_quiet - 1:
            c.mine_n(1, price_fn=lambda h: 9_000)
        intent = self.reclaim(pos)
        self.assertEqual(c.height + 1, first + c.params.cancel_quiet - 1)
        self.assertEqual(m.cancels_required(m.vaults[pos], c.height + 1), 2)
        self.assertEqual(self.mine(self.cancel_of(intent, pos, [0])), 'intent-cancel-cosign')
        self.assertEqual(m.cancels_required(m.vaults[pos], c.height + 1), 1)
        raw = self.cancel_of(intent, pos, [1])
        self.assertEqual(self.mine(raw), '')
        self.assertEqual(m.vaults[(txid_of(raw), 0)].cancel_count, 1)

    # Rule: CAN-2
    # Rule: C4b
    def test_cosign_refusals(self):
        c, m = self.c, self.c.model
        relock, refund = c.relock(self.vault, self.coll), c.refund_out(self.intent)
        bad = 'intent-cancel-cosign'
        self.assertEqual(self.mine(self.cancel(cosigns=None)), bad)                          # no statement at all
        no_marker = c.cancel_tx(self.intent, self.vault, self.coll, refund=True, cosigns=None,
                                vouts=None)
        self.assertEqual(self.mine(no_marker), bad)
        other = c.cosign(self.intent, 4, self.HONEST)                                          # ATTESTORS[4] never joined
        self.assertEqual(self.mine(self.cancel(cosigns=[other])), bad)
        self.assertEqual(self.mine(self.cancel(cosigns=[c.cosign((self.claim, 1), 0, self.HONEST, ref=m.intents[self.intent].claim_ref_height)])), bad)
        self.assertEqual(self.mine(self.cancel(cosigns=[c.cosign(self.intent, 0, self.HONEST, ref=m.intents[self.intent].claim_ref_height - 1)])), bad)
        self.assertEqual(self.mine(self.cancel(cosigns=[c.cosign(self.intent, 0, self.HONEST, block_hash='01' * 32)])), bad)
        v = m.vaults[self.vault]
        edge = next(p for p in range(1, 10 ** 6) if not ym.is_underwater(v.collateral_zat, p, v.minted_cents, c.params.claim_threshold_bps))
        self.assertEqual(self.mine(self.cancel(price=9_000)), bad)                            # a claimable statement
        self.assertEqual(self.mine(self.cancel(price=edge - 1)), bad)
        self.assertEqual(self.mine(self.cancel(price=99)), bad)                               # under PRICE_MIN
        self.assertEqual(self.mine(self.cancel(cosigns=[other, c.cosign(self.intent, 0, 9_000)])), bad)   # nothing valid
        self.assertEqual(m.vaults[self.vault].status, ym.V_CLAIMING)
        raw = self.cancel(seqs=(0, 2, 3), price=edge)                                        # extras valid; the boundary holds
        self.assertEqual(self.mine(raw), '')
        self.assertEqual(m.txlog[txid_of(raw)].bundle_seqs, [0, 2, 3])

    # Rule: CAN-3
    # Rule: NOT-1
    def test_residual_held_while_claimable_by_path_b(self):
        """Round 2: healthy at the snapshot price, but a persisted notice on the position under EMERGENCY_RATIO holds it."""
        c, m = self.c, self.c.model
        res = self.fake_residual()
        raw = self.cancel()
        self.assertEqual(self.mine(raw), '')
        pos = (txid_of(raw), 0)
        c.mine_n(64, price_fn=lambda h: 50_000)
        m.notices[pos] = ym.NoticeRecord(c.height - 4, c.height - c.params.emergency_persist, 1_000)
        self.assertEqual(self.mine(c.release_tx(res, 1000)), 'intent-residual-held')
        m.notices[pos] = ym.NoticeRecord(c.height, c.height, 1_000)       # not yet persisted at H - 1
        self.assertEqual(self.mine(c.release_tx(res, 1000)), '')

    # Rule: CAN-2
    def test_counts_distinct_valid_entries(self):
        """Round 2 (review M-2): invalid, non-current and repeated entries are ignored; enough distinct valid ones hold."""
        c, m = self.c, self.c.model
        raw = self.cancel()
        self.assertEqual(self.mine(raw), '')
        pos = (txid_of(raw), 0)
        intent = self.reclaim(pos)                               # two needed now
        cs = lambda seq, price=None: c.cosign(intent, seq, price or self.HONEST)  # noqa: E731
        other = c.cosign(intent, 0, self.HONEST, member=ATTESTORS[4])            # never joined
        vouts = [c.relock(pos, self.coll), c.refund_out(intent)]
        self.assertEqual(self.mine(c.cancel_tx(intent, pos, self.coll, vouts=vouts, cosigns=[cs(0), cs(0)])), 'intent-cancel-cosign')
        self.assertEqual(self.mine(c.cancel_tx(intent, pos, self.coll, vouts=vouts, cosigns=[cs(0), other])), 'intent-cancel-cosign')
        raw = c.cancel_tx(intent, pos, self.coll, vouts=vouts, cosigns=[cs(0), other, cs(2, 9_000), cs(0), cs(1)])
        self.assertEqual(self.mine(raw), '')
        self.assertEqual(m.txlog[txid_of(raw)].bundle_seqs, [0, 1])
        self.assertEqual(m.vaults[(txid_of(raw), 0)].cancel_count, 2)

    def fake_residual(self):
        """A residual intent of this fixture's claim (the claim had none due: injected into the model for the unit,
        as test_cancel_of_residual_invalid flips a role); returns its outpoint."""
        m = self.c.model
        ir = m.intents[self.intent]
        op = (self.claim, 1)
        m.intents[op] = ym.IntentRec(self.vault, ym.I_RESIDUAL, ir.height, b'', ir.claim_ref_height)
        return op

    # Rule: CAN-3
    def test_residual_held_until_quiet(self):
        c, m = self.c, self.c.model
        res = self.fake_residual()
        raw = self.cancel()
        self.assertEqual(self.mine(raw), '')
        cancelled, pos = c.height, (txid_of(raw), 0)
        self.assertEqual(m.intents[res].held_by, pos)
        self.assertEqual(self.mine(c.release_tx(res, 1000)), 'intent-residual-held')
        while c.height + 2 < cancelled + c.params.cancel_quiet:
            c.mine_n(1, price_fn=lambda h: 9_000)
        self.assertEqual(self.mine(c.release_tx(res, 1000)), 'intent-residual-held')
        # round 2: past CANCEL_QUIET the position (300 % at $0.05) is claimable at $0.009: still held
        self.assertTrue(m.claimable_at_snapshot(m.vaults[pos], pos, c.height + 1))
        self.assertEqual(self.mine(c.release_tx(res, 1000)), 'intent-residual-held')
        c.mine_n(64, price_fn=lambda h: 50_000)                 # the price recovers for a slow window
        self.assertFalse(m.claimable_at_snapshot(m.vaults[pos], pos, c.height + 1))
        self.assertEqual(self.mine(c.release_tx(res, 1000)), '')
        self.assertNotIn(res, m.intents)

    # Rule: CAN-3
    def test_residual_follows_the_position_and_is_freed_by_a_close(self):
        c, m = self.c, self.c.model
        res = self.fake_residual()
        raw = self.cancel()
        self.assertEqual(self.mine(raw), '')
        pos = (txid_of(raw), 0)
        intent = self.reclaim(pos)
        self.assertEqual(self.mine(c.release_tx(res, 1000)), 'intent-residual-held')     # CLAIMING
        raw2 = self.cancel_of(intent, pos, [0, 1])
        self.assertEqual(self.mine(raw2), '')
        pos2 = (txid_of(raw2), 0)
        self.assertEqual(m.intents[res].held_by, pos2)
        self.assertEqual(self.mine(c.release_tx(res, 1000)), 'intent-residual-held')
        redeem = c.spend_tx(pos2, None, 'owner', [(pos2[0], 1)], c.height - 1, sorted(m.eligible_payees(c.height - 1))[0], c.vault_fee(pos2))
        self.assertEqual(self.mine(redeem), '')
        self.assertEqual(m.vaults[pos2].status, ym.V_CLOSED)
        self.assertEqual(self.mine(c.release_tx(res, 1000)), '')

    # Rule: C4b
    # Rule: EQV-1
    def test_statement_slashed_and_honest_never(self):
        c, m = self.c, self.c.model
        ref = m.intents[self.intent].claim_ref_height
        entry1 = c.cosign(self.intent, 1, self.HONEST)
        entry0 = c.cosign(self.intent, 0, self.HONEST)
        self.assertEqual(self.mine(self.cancel(cosigns=[entry0, entry1])), '')
        # member 0 attested the same price at the claim's refHeight: no evidence; member 1 attested $0.009: slashed
        same = ya.sign_attestation(ATTESTORS[0][0], 0, self.HONEST, ref, c.block_hash(ref))
        self.assertIsNone(m.equivocation_evidence(ym.tx_from_hex(c.cancel_evidence_tx(same, self.intent, entry0))))
        other = ya.sign_attestation(ATTESTORS[2][0], 2, 9_000, ref, c.block_hash(ref))     # another member's attestation
        lying = ya.sign_attestation(ATTESTORS[1][0], 1, 9_000, ref, c.block_hash(ref))
        raws = [c.cancel_evidence_tx(same, self.intent, entry0), c.cancel_evidence_tx(other, self.intent, entry0)]
        c.mine((1, 9_000, 0, KEY2), raws)
        for seq in (0, 2):
            self.assertNotEqual(m.attestors[seq].status, ym.A_EJECTED)
            self.assertFalse(m.attestors[seq].bond_frozen)
        eqv = c.cancel_evidence_tx(lying, self.intent, entry1)
        c.mine((1, 9_000, 0, KEY2), [eqv])
        self.assertEqual((m.attestors[1].status, m.attestors[1].bond_frozen), (ym.A_EJECTED, True))
        self.assertEqual((m.txlog[txid_of(eqv)].type, m.txlog[txid_of(eqv)].attestor_seq), ('EQUIVOCATION', 1))


class AttestorSetThresholdTests(unittest.TestCase):

    # Rule: P4-b
    # Rule: I-3
    def test_adopted_only_with_threshold_one(self):
        """03/I-3: the mirror adopts the attestor set only with cancelThreshold = unlockThreshold = 1."""
        for kw, adopted in (({}, True), ({'cancel_threshold': 2}, False), ({'unlock_threshold': 2}, False)):
            c = Chain(ym.Params.regtest(1, 0, 0, attestor_set_id(**kw)))
            c.mine((1, 50_000, 0, KEY1), [attestor_set_create(**kw)])
            self.assertEqual(c.model.attestor_set_rec is not None, adopted, kw)


# ===========================================================================
# section 3.6  State hash and the golden vector

GOLDEN_BLOCKS = 440


def golden_rejected(claim_height):
    """The golden's rejected blocks in order, (height, verdict) -- the vector's manifest (doc/yellowback-testing.md); the
    C++ statehash_golden_vector carries the same list.  claim_height is where build_golden's emergency claim landed."""
    return [(137, 'bad-mint-amount'), (141, 'bad-mint-collateral'), (146, 'yed-template-output'), (150, 'bad-redeem-early-fee'),
            (185, 'vault-spend-short-burn'), (217, 'vault-spend-malformed'), (231, 'attestor-register-retired'),
            (251, 'mint9-no-bundle'), (252, 'mint9-bundle-sig'), (253, 'mint9-bundle-member'), (292, 'liveness-unheld'),
            (claim_height, 'red5-residual'), (claim_height + 1, 'intent-cancel-no-vault'), (claim_height + 1, 'intent-cancel-no-refund'),
            (claim_height + 1, 'intent-cancel-cosign'), (claim_height + 9, 'intent-cancel-residual'), (claim_height + 11, 'intent-residual-held'),
            (claim_height + 41, 'intent-residual-held'),
            (GOLDEN_FALCON + 2, 'bad-yed-holder'), (GOLDEN_FALCON + 3, 'bad-yed-holder')]
GOLDEN_LIVENESS = 150          # P4-b: the golden attestor set's livenessWindow (joins at 225..228 lapse at ~377)
GOLDEN_HEARTBEAT = 370
GOLDEN_RELEASE_CHECK = 41      # CAN-3 round 2: the held residual's release attempt after CANCEL_QUIET (claim + 1 + 40)
GOLDEN_FALCON = 400            # TOK-PQ binds from here (pqFalconHeight; not hashed): only the golden's TOK-PQ refusals come after it


def build_golden():
    """The fixed synthetic sequence: regtest params {1, 0, 0, TEST_SET, 3, scriptsig}; 440 blocks; the v2
    lifecycle to 224 on the vault upgrade's V vaults, then the v3 one: four registrations, arming, a
    mint with a bundle, a price fall, a notice and an emergency claim into a claimant and a residual
    intent, an attestor cancel of the claimant intent (the vault back, the burn kept), the residual's
    release, dormancy, an equivocation, a revival, a member's own exit and two bond spends; the cancel refunds the
    claim's burn (CAN-1) and a second, non-held notice at 293 leaves no BundleLog row (R12 hardened).  Seventeen blocks
    are rejected and mined again without the offending transaction (U-21), one per consensus verdict the vector covers
    (audit 03/T-1; golden_rejected() lists them): the original four -- 137 (a mint of $50), 217 (an owner spend with no
    payload), 231 (a v3 ATTESTOR_REGISTER) and 251 (an armed mint without a bundle) -- and, each built by
    Chain.rejected() so the accepted chain is unchanged, an over-mint at required - 1 (141), a YED V output no rule
    created (146), an early owner redeem without the early fee (150), a short burn (185), a bundle with a bad
    signature (252), a bundle drawn for another selector replayed on a mint (253), a non-held notice carrying a fresh
    attestation (292), a claim short of its residual (the claim height), a cancel that re-locks at vout 1 and one
    without the refund (claim + 1), a cancel of the owner's residual intent (claim + 9), and from the Falcon height
    (GOLDEN_FALCON) a TRANSFER and a REDEEM-type change of the refunded YED to a P2PKH (TOK-PQ).  The per-vault cancel
    limit (cancel-limit design, owner 2026-10-13; twenty rejected blocks): the cancel carries two CANCEL_COSIGN
    statements (CAN-2 + C4b), a cancel whose statement says the vault was claimable is refused (claim + 1,
    intent-cancel-cosign), the residual's release after CLAIM_DELAY is held (claim + 11, intent-residual-held, CAN-3)
    and, round 2, still at claim + 1 + CANCEL_QUIET (the re-created position is claimable at the snapshot), so the
    residual stays held to the end, and at GOLDEN_BLOCKS - 1 EQV-1 ejects the attestor whose statement
    contradicts its claim5 attestation (C4b)."""
    params = ym.Params.regtest(1, 0, 0, attestor_set_id(liveness_window=GOLDEN_LIVENESS))
    params.pq_falcon_height = GOLDEN_FALCON
    c = Chain(params)
    # IT-2 keeps the v3 tail on RED-4's path (b): at 300 % collateral minted at $0.009 the vault sits at ~127 %
    # when the pools quote $0.0038 (not under theta 125 %) and at 100 % at the attestors' $0.003 (under 105 %).
    price = lambda h: (50_000 + (h % 5) * 100) if h <= 149 else (9_000 + (h % 3) * 10) if h <= 251 else (3_800 + (h % 3) * 5)  # noqa: E731
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
            txs_at['mint2'] = c.mint_tx(5_000, 48, 135, 10 ** 12, fee_key=KEY2)      # invalid: bad-mint-amount (block 137 rejected)
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
                                           KEY2, c.vault_fee((txid_of(txs_at['mint1']), 0), h),
                                           [(3, 6_000)], collateral_out=v.collateral_zat - 10 ** 9)
            txs.append(txs_at['redeem1'])
        elif h == 215:
            v = c.model.vaults[(txid_of(txs_at['mint3']), 0)]
            script = ym.vault_script(v.lock_height, G_PUBKEY, v.claim_height)
            txs_at['claim3'] = c.spend_tx((txid_of(txs_at['mint3']), 0), script, 'claim',
                                          [(txid_of(txs_at['mint3']), 1), (txid_of(txs_at['redeem1']), 3)], 213,
                                          KEY3, c.vault_fee((txid_of(txs_at['mint3']), 0), owner=False),
                                          [(3, 6_000)], collateral_out=v.collateral_zat - 10 ** 9)
            txs.append(txs_at['claim3'])
        elif h == 217:
            v = c.model.vaults[(txid_of(txs_at['mint4']), 0)]
            script = ym.vault_script(v.lock_height, G_PUBKEY, v.claim_height)
            txs_at['sweep4'] = c.spend_tx((txid_of(txs_at['mint4']), 0), script, 'owner', [], 215, None, 0,
                                          payload=b'', collateral_out=v.collateral_zat - 1000)
            txs.append(txs_at['sweep4'])
        # ---- the v3 tail
        elif h == 224:                                          # P4-b: the attestor set's SET_CREATE (its txid is attestorSetId)
            txs_at['setcreate'] = attestor_set_create(liveness_window=GOLDEN_LIVENESS)
            txs.append(txs_at['setcreate'])
        elif h == 231:                                          # P4-b: a v3 ATTESTOR_REGISTER is invalid (block 231 rejected)
            txs_at['legacyreg'] = c.legacy_register_tx(ATTESTORS[4][1], ATTESTORS[4][1], h + 200, 10 * ym.COIN)
            txs.append(txs_at['legacyreg'])
        elif h == 229:                                          # U-23: the claimant's intent of claim3 released after CLAIM_DELAY
            v = c.model.vaults[(txid_of(txs_at['mint3']), 0)]
            txs_at['release3'] = c.release_tx((txid_of(txs_at['claim3']), 0), v.collateral_zat)
            txs.append(txs_at['release3'])
        elif 225 <= h <= 228:                                   # P4-b: SET_JOIN of seq 0..3, 10 YEC bonds, locktime H + 200
            i = h - 225
            txs_at['reg%d' % i] = c.register_tx(ATTESTORS[i], h + 200, 10 * ym.COIN)
            txs.append(txs_at['reg%d' % i])
        elif h == 230:                                          # burn the last 6,000 cents so the global ratio is undefined again
            txs_at['burn'] = c.transfer_tx([(txid_of(txs_at['claim3']), 3)], [])
            txs.append(txs_at['burn'])
        elif h == 250:                                          # MINT-9: a mint with a bundle at R = 248 (ARMED at 243)
            ref = 248
            bundle, sel = c.bundle_for(ref, b'', {'*': 9_000})
            x = c.model.snapshot(ref).p_mint
            collateral = collateral_for(c, 10_000, ref, p_mint=min(x, 9_000))
            fee = c.mint_fee(10_000, ref, p_mint=min(x, 9_000))          # FEE-1' at min(xMint, aMint)
            payee = sel[0]
            txs_at['mint5'] = c.mint_tx(10_000, 48, ref, collateral, fee_key=KEY1, carrier=bundle, p_mint=min(x, 9_000),
                                        attest_fee=(ym.hash160(BONDS[payee][1]), ym.attest_fee_zat(fee, params.attest_fee_bps)))
            txs.append(txs_at['mint5'])
            v3['mint5_selected'] = sel
        elif h == 251:                                          # MINT-9: the same shape without a carrier => invalid mint9-no-bundle (block 251 rejected)
            ref = 249
            txs_at['mint6'] = c.mint_tx(10_000, 48, ref, collateral_for(c, 10_000, ref), fee_key=KEY2)
            txs.append(txs_at['mint6'])
        elif h == 290:                                          # NOT-1 at R = 288: attestors at 3,000, pools at ~3,800
            ref = 288
            vault = (txid_of(txs_at['mint5']), 0)
            sel = c.model.selected(ref, ya.outpoint_selector(*vault))
            v3['lazy'] = sel[0]                                 # the attestor that stops signing (dormancy)
            bundle, _ = c.bundle_for(ref, ya.outpoint_selector(*vault), {'*': 3_000}, skip=(v3['lazy'],))
            txs_at['notice5'] = c.notice_tx(vault, ref, bundle)
            txs.append(txs_at['notice5'])
        elif h == 293:                                          # R12 hardened (03/M-2): a notice that does not hold (notice5 stands)
            vault = (txid_of(txs_at['mint5']), 0)                # with notice5's bundle (cited 288, already credited): valid, no BundleLog row
            sel = c.model.selected(288, ya.outpoint_selector(*vault))
            bundle, _ = c.bundle_for(288, ya.outpoint_selector(*vault), {'*': 3_000}, skip=(sel[0],))
            txs_at['notice5b'] = c.notice_tx(vault, 288, bundle)
            txs.append(txs_at['notice5b'])
        elif h >= 298 and 'claim5' not in txs_at:               # RED-4(b) + RED-5 at the first R >= 296 that selects the lazy attestor
            ref = h - 2
            vault = (txid_of(txs_at['mint5']), 0)
            selector = ya.outpoint_selector(*vault)
            sel = c.model.selected(ref, selector)
            if v3['lazy'] in sel:
                v = c.model.vaults[vault]
                script = ym.vault_script(v.lock_height, G_PUBKEY, v.claim_height)
                bundle, _ = c.bundle_for(ref, selector, {'*': 3_000}, skip=(v3['lazy'],))
                fee = c.vault_fee(vault, owner=False)                        # RED-3': the claimant pays the redeem fee at the vault's pMint
                p_claim = max(c.model.snapshot(ref).p_claim, 3_000)
                residual = ym.residual_zat(v.collateral_zat, ym.claimant_max_zat(v.minted_cents, ym.BPS, p_claim))
                payee = [q for q in sel if q != v3['lazy']][0]
                txs_at['claim5'] = c.spend_tx(vault, script, 'claim', [(txid_of(txs_at['mint5']), 1)], ref, KEY3, fee,
                                              carrier=bundle, collateral_out=v.collateral_zat - residual - fee - 10 ** 8,
                                              attest_fee=(ym.hash160(BONDS[payee][1]), ym.attest_fee_zat(fee, params.attest_fee_bps)),
                                              residual=(ym.pqpkh_script(G_OWNER), residual))
                txs.append(txs_at['claim5'])
                v3['claim_height'] = h
                v3['claim_ref'] = ref
                v3['residual'] = residual
                v3['dormancy_height'] = h + (-h) % 4            # the first DORMANCY_CHECK multiple at or after the claim
        elif 'claim_height' in v3 and h == v3['claim_height'] + 1:      # U-23/U-24: an attestor cancels the claimant intent
            vault = (txid_of(txs_at['mint5']), 0)
            v = c.model.vaults[vault]
            intent = (txid_of(txs_at['claim5']), 0)
            # CAN-2 + C4b: the first cancel needs one co-signer; the lazy attestor (it signed no bundle at R) and, as an
            # extra, the attestor that signed claim5's bundle at $0.003 both state $0.009 (300 %, not claimable) -- the
            # second statement is slashable (EQV-1 at GOLDEN_BLOCKS - 1)
            v3['liar'] = sorted(q for q in range(4) if q != v3['lazy'])[1]
            v3['statement'] = c.cosign(intent, v3['liar'], 9_000)
            txs_at['cancel5'] = c.cancel_tx(intent, vault, v.collateral_zat - v3['residual'], refund=True,   # CAN-1
                                            cosigns=[c.cosign(intent, v3['lazy'], 9_000), v3['statement']])
            txs.append(txs_at['cancel5'])
        elif 'claim_height' in v3 and h == v3['dormancy_height'] + 2:   # EQV-1: two prices for one block hash
            e = min(q for q in range(4) if q != v3['lazy'])
            v3['ejected'] = e
            a = ya.sign_attestation(ATTESTORS[e][0], e, 2_000, h - 1, c.block_hash(h - 1))
            b = ya.sign_attestation(ATTESTORS[e][0], e, 2_100, h - 1, c.block_hash(h - 1))
            txs_at['eqv'] = c.equivocation_tx(a, b)
            txs.append(txs_at['eqv'])
        elif 'claim_height' in v3 and h == v3['dormancy_height'] + 4:   # REV-1 (P4-b): the dormant attestor's SET_HEARTBEAT
            lazy = v3['lazy']
            txs_at['revive'] = c.heartbeat_tx(ATTESTORS[lazy])
            txs.append(txs_at['revive'])
        elif h == GOLDEN_HEARTBEAT:                             # P4-b: one heartbeat keeps w live; the fourth goes DORMANT (set dormancy)
            e = v3['ejected']
            w = max(q for q in range(4) if q not in (v3['lazy'], e))
            txs_at['heartbeat_w'] = c.heartbeat_tx(ATTESTORS[w])
            txs.append(txs_at['heartbeat_w'])
        elif h == GOLDEN_BLOCKS - params.bond_maturity:        # the bond exit delay: w leaves by its own SET_REMOVE (WITHDRAWN)
            e = v3['ejected']
            w = max(q for q in range(4) if q not in (v3['lazy'], e))
            v3['withdrawn'] = w
            v3['exit_height'] = h
            txs_at['leave_w'] = c.remove_tx(ATTESTORS[w][1], ATTESTORS[w])
            txs.append(txs_at['leave_w'])
        elif h == GOLDEN_BLOCKS - 1:                            # C4b: the liar's cancel statement ($0.009) against its claim5 attestation ($0.003)
            R = v3['claim_ref']
            liar = v3['liar']
            att = ya.sign_attestation(ATTESTORS[liar][0], liar, 3_000, R, c.block_hash(R))
            txs_at['eqv_statement'] = c.cancel_evidence_tx(att, (txid_of(txs_at['claim5']), 0), v3['statement'])
            txs.append(txs_at['eqv_statement'])
        elif h == GOLDEN_BLOCKS:                                # IN-2: two bond spends (w's at exit + BOND_MATURITY; the EJECTED one stays EJECTED)
            e, w = v3['ejected'], v3['withdrawn']
            for name, q in (('spend_e', e), ('spend_w', w)):
                rec = c.model.attestors[q]
                txs_at[name] = c.bond_spend_tx(rec.bond_outpoint, ya.bond_script(BONDS[q][1], rec.bond_locktime), rec.bond_locktime)
                txs.append(txs_at[name])
        # ---- audit 03/T-1: one rejected block per verdict, the refused transaction first in its block
        bad = []
        if h == 141:                                            # MINT-5: collateral one zat below the requirement
            s141 = c.model.snapshot(139)
            req = ym.required_zat(10_000, ym.min_ratio_bps(params.base_ratio_bps[0], s141.sigma_mult_bps), s141.p_mint)
            bad.append(c.rejected(lambda: c.mint_tx(10_000, 48, 139, req - 1, fee_key=KEY3)))
        elif h == 146:                                          # U-23: a YED V output that no mint, claim or cancel created
            bad.append(c.rejected(lambda: ym.serialize_tx_v4([c.fund_input()], [(10 ** 9, ym.yed_vault_script(params, G_OWNER, 144))]).hex()))
        elif h == 150:                                          # IT-9': an owner redeem before lockHeight paying only the protocol fee
            op4 = (txid_of(txs_at['mint4']), 0)
            v = c.model.vaults[op4]
            payee = c.model.eligible_payees(148)[0]
            bad.append(c.rejected(lambda: c.spend_tx(op4, None, 'owner', [(txid_of(txs_at['mint4']), 1)], 148, payee,
                                                     c.vault_fee(op4), [], collateral_out=v.collateral_zat - 10 ** 9)))
        elif h == 185:                                          # RED-2: 6,000 cents burned for a 10,000-cent debt
            op1 = (txid_of(txs_at['mint1']), 0)
            v = c.model.vaults[op1]
            bad.append(c.rejected(lambda: c.spend_tx(op1, None, 'owner', [(txid_of(txs_at['xfer1']), 0)], 183, KEY2,
                                                     c.vault_fee(op1, h), [], collateral_out=v.collateral_zat - 10 ** 9)))
        elif h in (252, 253):                                   # BUNDLE-1: a bad signature (252); a vault selector's bundle replayed on a mint (253)
            ref = h - 2
            x = c.model.snapshot(ref).p_mint
            if h == 252:
                bundle, sel = c.bundle_for(ref, b'', {'*': 9_000})
                atts = ya.decode_bundle(bundle)
                seq0 = sel[0]
                atts[0] = ya.sign_attestation(ATTESTORS[seq0][0], seq0, 9_000, ref, c.block_hash(ref - 1))   # signs the wrong block hash
                bundle = ya.encode_bundle(atts)
            else:                                               # the bundle mint5's vault would get as a claim selector, replayed on a mint
                bundle, sel = c.bundle_for(ref, ya.outpoint_selector(txid_of(txs_at['mint5']), 0), {'*': 9_000})
            fee = c.mint_fee(10_000, ref, p_mint=min(x, 9_000))
            bad.append(c.rejected(lambda: c.mint_tx(10_000, 48, ref, collateral_for(c, 10_000, ref, p_mint=min(x, 9_000)), fee_key=KEY1,
                                                    carrier=bundle, p_mint=min(x, 9_000),
                                                    attest_fee=(ym.hash160(BONDS[sel[0]][1]), ym.attest_fee_zat(fee, params.attest_fee_bps)))))
        elif h == 292:                                          # liveness: a notice that does not hold (one stands) with a fresh attestation
            vault = (txid_of(txs_at['mint5']), 0)
            bundle, _ = c.bundle_for(290, ya.outpoint_selector(*vault), {'*': 3_000})
            bad.append(c.rejected(lambda: c.notice_tx(vault, 290, bundle)))
        elif 'claim5' in txs_at and txs_at['claim5'] in txs:    # RED-5: the same claim one zat short of the residual
            vault = (txid_of(txs_at['mint5']), 0)
            v = c.model.vaults[vault]
            ref = h - 2
            selector = ya.outpoint_selector(*vault)
            sel = c.model.selected(ref, selector)
            bundle, _ = c.bundle_for(ref, selector, {'*': 3_000}, skip=(v3['lazy'],))
            fee = c.vault_fee(vault, owner=False)
            payee = [q for q in sel if q != v3['lazy']][0]
            bad.append(c.rejected(lambda: c.spend_tx(vault, None, 'claim', [(txid_of(txs_at['mint5']), 1)], ref, KEY3, fee,
                                                     carrier=bundle, collateral_out=v.collateral_zat - v3['residual'] - fee - 10 ** 8,
                                                     attest_fee=(ym.hash160(BONDS[payee][1]), ym.attest_fee_zat(fee, params.attest_fee_bps)),
                                                     residual=(ym.pqpkh_script(G_OWNER), v3['residual'] - 1))))
        elif 'claim_height' in v3 and h == v3['claim_height'] + 1:     # I-2 / U-23: the cancel's re-lock at vout 1; CAN-1: no refund
            vault = (txid_of(txs_at['mint5']), 0)
            value = c.model.vaults[vault].collateral_zat - v3['residual']
            intent = (txid_of(txs_at['claim5']), 0)
            bad.append(c.rejected(lambda: c.cancel_tx(intent, vault, value, vouts=[(1000, ym.p2pkh_script(OWNER_KEYHASH)), c.relock(vault, value),
                                                                                    c.refund_out(intent)])))
            bad.append(c.rejected(lambda: c.cancel_tx(intent, vault, value)))
            # CAN-2 + C4b: a cancel whose one statement says the vault was claimable ($0.003: 100 %)
            bad.append(c.rejected(lambda: c.cancel_tx(intent, vault, value, refund=True, cosigns=[c.cosign(intent, v3['lazy'], 3_000)])))
        elif 'claim_height' in v3 and h == v3['claim_height'] + 9:     # U-23: the owner's residual intent is never cancelled
            claim5 = txid_of(txs_at['claim5'])
            res = [op for op, r in c.model.intents.items() if op[0] == claim5 and r.role == ym.I_RESIDUAL][0]
            bad.append(c.rejected(lambda: c.cancel_tx(res, (txid_of(txs_at['cancel5']), 0), v3['residual'])))
        elif 'claim_height' in v3 and h == v3['claim_height'] + 11:    # CAN-3: the residual's release after CLAIM_DELAY is held
            claim5 = txid_of(txs_at['claim5'])
            res = [op for op, r in c.model.intents.items() if op[0] == claim5 and r.role == ym.I_RESIDUAL][0]
            bad.append(c.rejected(lambda: c.release_tx(res, v3['residual'], ym.pqpkh_script(G_OWNER))))
            v3['residual_vout'] = res[1]
        elif 'claim_height' in v3 and h == v3['claim_height'] + 1 + params.cancel_quiet:   # CAN-3 round 2: CANCEL_QUIET has
            # passed, but the re-created position (~100 % at the claim's pClaim) is claimable at the pools' ~$0.0038: still held
            claim5 = txid_of(txs_at['claim5'])
            res = [op for op, r in c.model.intents.items() if op[0] == claim5 and r.role == ym.I_RESIDUAL][0]
            bad.append(c.rejected(lambda: c.release_tx(res, v3['residual'], ym.pqpkh_script(G_OWNER))))
        elif h == GOLDEN_FALCON + 2:                            # TOK-PQ: a TRANSFER of the CAN-1 refund to a P2PKH after the Falcon height
            refund = (txid_of(txs_at['cancel5']), 1)
            bad.append(c.rejected(lambda: c.transfer_tx([refund], [(0, 10_000)])))
        elif h == GOLDEN_FALCON + 3:                            # TOK-PQ: a REDEEM-type transfer whose change goes to a P2PKH
            refund = (txid_of(txs_at['cancel5']), 1)
            def change_tx():
                vin = [(refund[0], refund[1], b'', 0xFFFFFFFF), c.fund_input()]
                vouts = [(params.token_value, ym.p2pkh_script(OWNER_KEYHASH)),
                         (0, bytes([ym.OP_RETURN]) + ym.push(ym.encode_redeem(h - 1, ym.FEE_VOUT_NONE, [(0, 4_000)])))]
                return ym.serialize_tx_v4(vin, vouts).hex()
            bad.append(c.rejected(change_tx))
        txs = bad + txs
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
    set_id = c.params.attestor_set
    return {
        'description': 'Yellowback state-hash golden vector on the vault upgrade, P4-b: regtest params {startHeight 1, sigmaRefBps 0, '
                       'supplyCapBps 0, attestorSetId %s (the txid of the SET_CREATE at 224; livenessWindow %d, maturity 1), '
                       'attestArmMin 3, bundleCarrier 0 (scriptsig), mintRequiresArmed false, pqFalconHeight %d (not hashed: TOK-PQ binds from it)}; '
                       'SCHEMA_VERSION 14 (in-term claims: the V ownerHeight = appHeight = refHeight + 1, 300/400/500 %% tiers, theta 125 %%; '
                       'CAN-1: a cancelled claim refunds its burn; the per-vault cancel limit: CAN-2 escalating co-signed cancels, '
                       'C4b slashable cancel statements, CAN-3 the held residual); payload version 3, MINT version 4 with post-quantum (SLH-DSA) owners (quantum spec C-1, section 3); '
                       '%d synthetic heights (see test_yellowback_model.build_golden): the v2 lifecycle to 224 on V vaults '
                       '(a claim into an intent and its release), then the attestor set (SET_CREATE), four SET_JOINs, arming, '
                       'a mint with a bundle, a notice, a second notice that does not hold (no BundleLog row, R12 hardened), an emergency '
                       'claim into a claimant and a residual intent, an attestor cancel of the claimant intent refunding the burn '
                       '(CAN-1) co-signed by two members (CAN-2 + C4b), the residual held past CANCEL_QUIET while the position stays claimable (CAN-3, round 2), S15 dormancy, an equivocation (EQV-1: ejected, bond '
                       'frozen), a revival by SET_HEARTBEAT, a heartbeat that keeps one attestor live while the other stays live by its attestation (seats review B2, '
                       'the set\'s member dormancy), a member\'s own exit (SET_REMOVE, burn 0), an EQV-1 ejection on a cancel statement (C4b) '
                       'and two bond spends (the leaver\'s at exit + BOND_MATURITY). '
                       'txs[0] of every block is the coinbase. Blocks flagged "invalid" (%s; one per verdict, audit 03/T-1) are '
                       'rejected and not applied (U-21); the next entry is the same height mined again without the offending '
                       'transaction.'
                       % (set_id, GOLDEN_LIVENESS, GOLDEN_FALCON, GOLDEN_BLOCKS,
                          ', '.join('%d %s' % hv for hv in golden_rejected(c.v3['claim_height']))),
        'params': {'startHeight': 1, 'sigmaRefBps': 0, 'supplyCapBps': 0, 'attestorSetId': set_id,
                   'attestArmMin': 3, 'bundleCarrier': ym.CARRIER_SCRIPTSIG, 'mintRequiresArmed': False,
                   'pqFalconHeight': GOLDEN_FALCON},
        'stateHash': c.model.state_hash(),
        'tip': {'height': c.height, 'hash': c.block_hash(c.height)},
        'totals': c.model.totals.as_dict(),
        'blocks': c.blocks,
    }


class SeatTests(unittest.TestCase):
    """Seat ranking and eviction (owner 2026-10-11), mirroring yellowback_math_tests seat_weight_log_tenure_factor and
    yellowback_state_tests seat_eviction_victim_rule / seat_eviction_mirror / p4b_slashed_key_barred_remove_winddown_refused."""

    def test_log2_and_factor(self):
        self.assertEqual([ym.log2_q16(x) for x in (0, 1, 2, 3, 1024, 2**64 - 1)], [0, 0, 65536, 103872, 10 << 16, (63 << 16) | 0xFFFF])
        u, cap = 1152, 420480
        self.assertEqual([ym.seat_age_factor_q16(a, u, cap) for a in (0, -10, 1152, 8064, 210240, cap, 3 * cap)],
                         [65536, 65536, 72462, 86314, 117619, 124518, 124518])
        self.assertEqual(ym.seat_weight(8000 * ym.COIN, 8064, u, cap) // 65536, 1053637695312)
        p = ym.Params.regtest(1, 0, 0, '5e' * 32)
        self.assertEqual((p.seat_age_unit, p.seat_age_cap, p.seat_margin_bps, p.evict_margin_bps, p.attestor_seats),
                         (1152, 420480, 500, 500, 15))

    def test_eviction_victim(self):
        p = ym.Params.regtest(1, 0, 0, '5e' * 32)
        H, LW, C = 100000, 1000, ym.COIN
        k = lambda i: bytes([2]) + bytes([i]) * 32  # noqa: E731
        m = [(k(0), 20 * C, H - 8064, H), (k(1), 8 * C, H - 8064, H), (k(2), 8 * C, H - 10, H)]
        self.assertIsNone(ym.eviction_victim(m, H, 8 * C, LW, p))
        self.assertEqual(ym.eviction_victim(m, H, 9 * C, LW, p), k(2))
        self.assertIsNone(ym.eviction_victim(m, H, 8 * C * 105 // 100, LW, p))
        self.assertIsNotNone(ym.eviction_victim([(k(0), 6 * C, H - 8064, H)], H, 9 * C, LW, p))
        self.assertIsNone(ym.eviction_victim([(k(0), 6 * C, H - 420480, H)], H, 9 * C, LW, p))
        self.assertIsNotNone(ym.eviction_victim([(k(0), 8000 * C, H - 10 * 420480, H)], H, 20000 * C, LW, p))
        m.append((k(3), 1000 * C, H - 420480, H - LW - 1))
        self.assertEqual(ym.eviction_victim(m, H, p.bond_min_floor_zat, LW, p), k(3))
        self.assertIsNone(ym.eviction_victim(m, H, p.bond_min_floor_zat - 1, LW, p))   # seats review B2: no dust eviction
        m[3] = (k(3), 1000 * C, H - 420480, H - LW)
        self.assertIsNone(ym.eviction_victim(m, H, p.bond_min_floor_zat, LW, p))
        self.assertEqual(ym.eviction_victim([(k(6), 8 * C, H - 50, H), (k(5), 8 * C, H - 50, H)], H, 100 * C, LW, p), k(5))

    def test_mirror_evicts_and_refuses_remove(self):
        secrets = [ym.sha256(b'seat-test-%d' % i) for i in range(17)]
        keys = [(sec, bytes(ya.yu.secret_to_pubkey(sec))) for sec in secrets]
        c = Chain(ym.Params.regtest(1, 0, 0, attestor_set_id()))
        tag = lambda: (1, 50000, 0, MINERS[(c.height + 1) % 3])  # noqa: E731
        c.mine_n(135)
        c.mine(tag(), [attestor_set_create()])
        for i in range(15):
            c.mine(tag(), [c.register_tx(keys[i], c.height + 1 + 200, 10 * ym.COIN)])
        # SET_REMOVE of the attestor set: invalid (the block is mined again without it)
        c.mine(tag(), [c.remove_tx(keys[3][1], keys[1])])
        self.assertEqual(c.model.last_failed.verdict, 'attestor-set-act')
        self.assertNotEqual(c.model.attestors[3].status, ym.A_EJECTED)
        # 11 YEC evicts the youngest 10-YEC member (seq 14)
        c.mine(tag(), [c.register_tx(keys[15], c.height + 1 + 200, 11 * ym.COIN)])
        r = c.model.attestors[14]
        self.assertEqual((r.status, r.status_height, bool(r.flags & ym.ATTESTOR_FLAG_EVICTED), r.bond_frozen, r.bond_spent_height),
                         (ym.A_WITHDRAWN, c.height, True, False, 0))
        self.assertEqual(c.model.attestors[15].status, ym.A_PENDING)
        self.assertTrue(all(c.model.attestors[s].status != ym.A_WITHDRAWN for s in range(14)))


class StateHashTests(unittest.TestCase):

    # Rule: N18
    def test_preimage_layout(self):
        s = '0102030405060708' * 4                                   # an attestor set id (display hex)
        m = ym.YellowbackModel(ym.Params.regtest(7, 1, 2, s))
        pre = m.state_hash_preimage()
        # T + i32 0 + zero hash + u32 6 + "regtest"; G totals; P params; N + u16 0; M + UNARMED (no C: ACT-1..6 are gone)
        self.assertEqual(pre[:1], b'T')
        self.assertEqual(pre[1:5], b'\x00\x00\x00\x00')
        self.assertEqual(pre[5:37], bytes(32))
        self.assertEqual(pre[37:41], b'\x0e\x00\x00\x00')        # SCHEMA_VERSION 14 (the cancel limit: CAN-2, C4b, CAN-3)
        self.assertEqual(pre[41:49], b'\x07regtest')
        self.assertEqual(pre[49:50], b'G')
        self.assertEqual(pre[50:90], bytes(40))
        # P: startHeight, sigmaRefBps, supplyCapBps (i32), attestorSetId (32 internal bytes), v3's attestArmMin
        # u32 (3) and bundleCarrier u8 (0 = scriptsig), H-1's mintRequiresArmed u8 (0) (M13)
        self.assertEqual(pre[90:141], b'P' + b'\x07\x00\x00\x00' + b'\x01\x00\x00\x00' + b'\x02\x00\x00\x00'
                         + bytes.fromhex(s)[::-1] + b'\x03\x00\x00\x00' + b'\x00' + b'\x00')
        # v3 (section 3.6): AttestorSeq (N + u16 next) and Attest (M + status u8 + i32 triggerHeight + i32 armHeight) always present
        self.assertEqual(pre[141:144], b'N\x00\x00')
        self.assertEqual(pre[144:], b'M' + bytes(9))
        m2 = ym.YellowbackModel(ym.Params.regtest(7, 1, 2, s, attest_arm_min=0, bundle_carrier=ym.CARRIER_EITHER))
        self.assertEqual(m2.state_hash_preimage()[135:141], b'\x00\x00\x00\x00' + b'\x02' + b'\x00')
        self.assertNotEqual(m2.state_hash(), m.state_hash())
        m3 = ym.YellowbackModel(ym.Params.regtest(7, 1, 2, s, mint_requires_armed=True))
        self.assertEqual(m3.state_hash_preimage()[140:141], b'\x01')
        self.assertNotEqual(m3.state_hash(), m.state_hash())
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
        j = 49 + 36 + 41                                              # Tip, Tags[1], Totals
        self.assertEqual(pre[j:j + 5], b'S\x00\x00\x00\x01')
        rec = pre[j + 5:]
        self.assertEqual(rec[:32], bytes.fromhex(c.block_hash(1))[::-1])
        self.assertEqual(rec[32:34], b'\x01\x01')                     # tagged, quote (signalCount and activation are gone)
        self.assertEqual(rec[34:74], bytes(40))                       # five undefined prices as 0
        self.assertEqual(rec[74:78], (10_000).to_bytes(4, 'little'))  # sigmaMultBps
        self.assertEqual(rec[78:86], ym.regtest_subsidy(1).to_bytes(8, 'little'))
        self.assertEqual(rec[86:102], bytes(16))                      # supply, collateral
        self.assertEqual(rec[102:110], bytes(8))                      # globalRatio undefined
        self.assertEqual(rec[110:114], b'\x02\x00\x00\x00')           # NO_PRICE (active from START, U-22)
        self.assertEqual(rec[114:123], bytes(9))                      # v3: attest UNARMED/0/0
        self.assertEqual(rec[123:126], b'\x00\x00\x00')               # seated, pinnedKeys, pinnedSeqs empty
        self.assertEqual(rec[126:127], b'P')

    # Rule: N18
    def test_golden_vector(self):
        c, txs_at = build_golden()
        m = c.model
        # sanity on the sequence itself
        self.assertNotIn(5, m.tags)
        self.assertNotIn(13, m.tags)
        self.assertIn(17, m.tags)
        self.assertFalse(m.tags[9].is_quote)
        self.assertEqual(m.vaults[(txid_of(txs_at['mint1']), 0)].status, ym.V_CLOSED)
        # U-21: one rejected block per verdict (audit 03/T-1), none applied; the same heights mined again without the
        # offending transaction (the C++ statehash_golden_vector's `expected` map is this list)
        v3 = c.v3
        rejected = golden_rejected(v3['claim_height'])
        self.assertEqual([(v.height, v.verdict) for v in m.rejected], rejected)
        self.assertGreaterEqual(len(set(v for _h, v in rejected)), 18)               # one block per verdict (TOK-PQ: two shapes)
        self.assertTrue(all(v.rejected for v in m.rejected))
        self.assertEqual([b['height'] for b in c.blocks if b.get('invalid')], [h for h, _v in rejected])
        self.assertEqual(len(c.blocks), GOLDEN_BLOCKS + len(rejected))
        self.assertEqual(c.refused[txid_of(txs_at['legacyreg'])], 'attestor-register-retired')   # P4-b
        self.assertNotIn((txid_of(txs_at['mint2']), 0), m.vaults)                      # no VOID vault (section 15.10)
        self.assertEqual(c.refused[txid_of(txs_at['mint2'])], 'bad-mint-amount')
        # U-23: claim3 left its vault CLAIMING; the release of its intent at 229 closed it
        self.assertEqual(m.vaults[(txid_of(txs_at['mint3']), 0)].status, ym.V_CLAIMED)
        self.assertEqual(m.txlog[txid_of(txs_at['release3'])].type, 'CLAIM_RELEASE')
        v4 = m.vaults[(txid_of(txs_at['mint4']), 0)]
        self.assertEqual((v4.status, v4.unbacked), (ym.V_ACTIVE, False))               # the sweep was refused
        self.assertEqual(m.txlog[txid_of(txs_at['xfer2'])].verdict, 'transfer-over-assigned')
        self.assertEqual(m.txlog[txid_of(txs_at['redeem1'])].verdict, 'ok')
        self.assertEqual(m.txlog[txid_of(txs_at['claim3'])].verdict, 'ok')
        self.assertEqual(c.refused[txid_of(txs_at['sweep4'])], 'vault-spend-malformed')
        self.assertNotIn(txid_of(txs_at['sweep4']), m.txlog)
        self.assertEqual(m.totals.as_dict(), {'supplyCents': 10_000, 'collateralZat': 3_225_730_455_562, 'activeVaults': 2,   # 300 % collateral (D-IT-4; the set id moved with its maturity); CAN-1's refund still held
                                              'voidVaults': 0, 'closedVaults': 1, 'claimedVaults': 1,
                                              'unbackedCents': 0})
        self.assertTrue(m.snapshots[224].halt_mask & ym.HALT_DIVERGENCE == 0)   # windows refilled at ~9,000
        # the v3 tail (v3 plan section 3.8): arming, a bundled mint, a bundle-less VOID mint, notice + emergency claim
        # with a residual, dormancy, ejection, revival, bond spends
        v3 = c.v3
        self.assertEqual((m.attest.status, m.attest.trigger_height, m.attest.arm_height), (ym.ARMED, 235, 243))
        self.assertEqual(m.snapshots[242].attest.status, ym.TRIGGERED)
        self.assertEqual(m.snapshots[243].attest.status, ym.ARMED)
        self.assertEqual(sorted(m.attestors), [0, 1, 2, 3])
        self.assertEqual(m.snapshots[248].seated, [0, 1, 2, 3])
        # P4-b: the AttestorSet record from the SET_CREATE at 224; the joins are its members' mirrors
        z = m.attestor_set_rec
        self.assertEqual((z.create_height, z.seats, z.maturity, z.liveness_window), (224, 15, 8, GOLDEN_LIVENESS))
        self.assertEqual(m.txlog[txid_of(txs_at['setcreate'])].type, 'ATTESTOR_SET_ACT')
        for i in range(4):
            r = m.attestors[i]
            self.assertEqual((r.attestor_pubkey, r.bond_pubkey, r.register_height), (ATTESTORS[i][1], ATTESTORS[i][1], 225 + i))
            self.assertEqual(r.bond_outpoint, (txid_of(txs_at['reg%d' % i]), 0))
            self.assertEqual(m.txlog[txid_of(txs_at['reg%d' % i])].type, 'ATTESTOR_REGISTER')
        mint5 = m.txlog[txid_of(txs_at['mint5'])]
        self.assertEqual((mint5.verdict, mint5.a_mint, sorted(mint5.bundle_seqs), mint5.attest_payee), ('ok', 9_000, sorted(v3['mint5_selected']), v3['mint5_selected'][0]))
        self.assertEqual(c.refused[txid_of(txs_at['mint6'])], 'mint9-no-bundle')
        self.assertEqual(m.txlog[txid_of(txs_at['notice5'])].notice, True)
        self.assertEqual(m.bundle_log[290].a_claim, 3_000)
        claim5 = m.txlog[txid_of(txs_at['claim5'])]
        self.assertEqual((claim5.verdict, claim5.claim_path, claim5.residual_zat), ('ok', 'b', v3['residual']))
        self.assertTrue(claim5.residual_zat >= ym.Params.REGTEST_ATTEST['residual_min_zat'])
        # U-23/U-24: the attestor cancel re-created the vault at (cancel5, 0): the same position, ACTIVE, its
        # collateral the claimant intent's value; CAN-1 (03/H-1): the claim's 10,000-cent burn was refunded at (cancel5, 1)
        # to the holder it came from, and supply credited
        self.assertNotIn((txid_of(txs_at['mint5']), 0), m.vaults)
        cancel = m.txlog[txid_of(txs_at['cancel5'])]
        self.assertEqual(cancel.type, 'CLAIM_CANCEL')
        self.assertEqual(cancel.closed_vaults, [(txid_of(txs_at['mint5']), 0)])
        self.assertEqual(cancel.reopened_vaults, [(txid_of(txs_at['cancel5']), 0)])
        v5 = m.vaults[(txid_of(txs_at['cancel5']), 0)]
        self.assertEqual((v5.status, v5.minted_cents, v5.mint_height, v5.burned_cents), (ym.V_ACTIVE, 10_000, 250, 0))
        # FEE-1': the re-created record keeps the mint price (min(xMint(248), the bundle's 9,000)): every later fee strikes at it
        self.assertEqual(v5.p_mint, min(m.snapshots[248].p_mint, 9_000))
        self.assertEqual(v5.p_mint, 9_000)
        self.assertEqual(claim5.burned, 10_000)
        self.assertEqual((cancel.assigned, cancel.yed_out, cancel.burned), ([(1, 10_000)], 10_000, 0))
        # CAN-2 + C4b: the first cancel needed one co-signer; it carried two statements (the lazy attestor's and the liar's)
        self.assertEqual(cancel.bundle_seqs, [v3['lazy'], v3['liar']])
        self.assertEqual((v5.cancel_count, v5.last_cancel_height), (1, v3['claim_height'] + 1))
        refund = m.tokens[(txid_of(txs_at['cancel5']), 1)]
        self.assertEqual((refund.cents, refund.script_pub_key), (10_000, ym.p2pkh_script(OWNER_KEYHASH)))
        # R12 hardened (03/M-2): the notice at 293 did not hold (notice5 stands) and its verified bundle left no row
        self.assertNotIn(293, m.bundle_log)
        self.assertNotIn(txid_of(txs_at['notice5b']), m.txlog)
        # CAN-3: the residual was held at claim + 11, and (round 2) still at claim + 1 + CANCEL_QUIET because the re-created
        # position is claimable at the snapshot; it stays held to the end
        res = (txid_of(txs_at['claim5']), v3['residual_vout'])
        self.assertEqual((m.intents[res].role, m.intents[res].held_by), (ym.I_RESIDUAL, (txid_of(txs_at['cancel5']), 0)))
        self.assertEqual(GOLDEN_RELEASE_CHECK, v3['claim_height'] + 1 + c.params.cancel_quiet - v3['claim_height'])
        self.assertEqual(list(m.intents), [res])
        self.assertEqual(m.notices, {})                                        # deleted when the vault left ACTIVE
        lazy, e, w = v3['lazy'], v3['ejected'], v3['withdrawn']
        self.assertEqual(m.snapshots[v3['dormancy_height']].attest.status, ym.ARMED)
        self.assertEqual(m.txlog[txid_of(txs_at['revive'])].attestor_seq, lazy)
        self.assertEqual(m.attestors[lazy].status, ym.A_ELIGIBLE)
        self.assertEqual(m.attestors[lazy].status_height, v3['dormancy_height'] + 4)
        self.assertEqual(m.attestors[e].status, ym.A_EJECTED)
        self.assertTrue(m.attestors[e].bond_frozen)                            # P4-b: EQV-1 freezes the bond
        self.assertEqual(m.attestors[e].bond_spent_height, GOLDEN_BLOCKS)     # spent, still EJECTED (the model reads no bond freeze: the primitive refuses that spend)
        self.assertEqual(v3['exit_height'], GOLDEN_BLOCKS - 8)                 # the bond exit delay: spent at exit + BOND_MATURITY
        self.assertEqual((m.attestors[w].status, m.attestors[w].status_height), (ym.A_WITHDRAWN, v3['exit_height']))
        self.assertEqual(m.attestors[w].bond_spent_height, GOLDEN_BLOCKS)
        self.assertEqual(m.attestors[w].last_act, GOLDEN_HEARTBEAT)
        # seats review B2: the fourth attestor never heartbeat, but its attestation in claim5's bundle (citing R =
        # claim height - 2) is liveness: lastAct is that cited height and it stays ELIGIBLE (it was DORMANT at
        # join + 8 + livenessWindow + 1 before attestations counted)
        r4 = [q for q in range(4) if q not in (lazy, e, w)][0]
        self.assertEqual(m.attestors[r4].last_act, v3['claim_height'] - 2)
        # C4b: the same attestor co-signed cancel5 stating $0.009 at R while its claim5 attestation said $0.003; EQV-1 took
        # the statement as one side at GOLDEN_BLOCKS - 1: EJECTED, bond frozen
        self.assertEqual(r4, v3['liar'])
        self.assertEqual((m.attestors[r4].status, m.attestors[r4].status_height, m.attestors[r4].bond_frozen), (ym.A_EJECTED, GOLDEN_BLOCKS - 1, True))
        eqv2 = m.txlog[txid_of(txs_at['eqv_statement'])]
        self.assertEqual((eqv2.type, eqv2.attestor_seq), ('EQUIVOCATION', r4))
        # the file on disk, the C++ pin, the model and a replay from the file all agree
        with open(GOLDEN_PATH) as f:
            doc = json.load(f)
        self.assertEqual(m.state_hash(), doc['stateHash'])
        self.assertEqual(doc['stateHash'], cpp_golden_hash())
        self.assertEqual(doc['blocks'], c.blocks)
        replayed = ym.replay_golden(doc)
        self.assertEqual(replayed.state_hash(), doc['stateHash'])
        self.assertEqual(replayed.state_hash_preimage(), m.state_hash_preimage())

    # Rule: N18
    def test_hash_changes_with_params(self):
        c1 = Chain(ym.Params.regtest(1, 0, 0, '11' * 32))
        c2 = Chain(ym.Params.regtest(1, 0, 0, '22' * 32))
        c1.mine_n(3)
        c2.mine_n(3)
        self.assertNotEqual(c1.model.state_hash(), c2.model.state_hash())
        # only P.attestorSetId differs: everything before it and the 19 bytes after it (attestArmMin, bundleCarrier,
        # mintRequiresArmed, N, M) agree
        self.assertEqual(c1.model.state_hash_preimage()[:-51], c2.model.state_hash_preimage()[:-51])
        self.assertEqual(c1.model.state_hash_preimage()[-19:], c2.model.state_hash_preimage()[-19:])


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
                                                                     'supplyCapBps': 1_500, 'attestorSetId': 'ab' * 32}})
        self.assertEqual((p.start_height, p.sigma_ref_bps, p.supply_cap_bps, p.attestor_set), (5, 10_000, 1_500, 'ab' * 32))
        self.assertEqual(p.claim_delay, 10)
        self.assertEqual(p.p_slow_window, 64)


# ---------------------------------------------------------------------------
# The post-quantum cross-implementation vectors (reviews A m-2, B M-1 of Q4): yellowback_pq_vectors.json, replayed
# by the C++ unit tests (pq_channel_tests: the scripts; yellowback_state_tests: the chain) and by this model, and
# later by ycash6.  Regenerate with --write-pq-vectors.

PQ_VECTORS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yellowback_pq_vectors.json')
PQ_FALCON_HEIGHT = 150
_P_SECP = 2 ** 256 - 2 ** 32 - 977
_SERVER_PK = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')   # G


def _push_num_raw(n):
    """A script-number push as a channel's refundHeight is written (OP_n for 1..16)."""
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    out = bytearray()
    v = n
    while v:
        out.append(v & 0xff)
        v >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes([len(out)]) + bytes(out)


def _raw_channel(scheme_byte, h, pk, refund_push):
    return (bytes([ym.OP_IF, 0x20]) + h + bytes([scheme_byte, ym.OP_CHECKPQSIG, ym.OP_VERIFY, 0x21]) + pk
            + bytes([ym.OP_CHECKSIG, ym.OP_ELSE]) + refund_push + bytes([ym.OP_CHECKLOCKTIMEVERIFY, ym.OP_DROP, 0x20]) + h
            + bytes([scheme_byte, ym.OP_CHECKPQSIG, ym.OP_ENDIF]))


def pq_script_cases():
    """The channel / PQPKH matcher cases of reviewer B's differential (wt/scratch/q45-review-b, 364 cases): every
    refund encoding and scheme byte, non-minimal refunds, slot mismatches, server keys off the curve, 240 seeded
    single-byte mutations, truncation and extension, PQPKH near misses."""
    import random
    rnd = random.Random(4545)
    hh = ym.sha256(b'client')
    cases = []
    for sch in (0, 1, 2, 3, 16):
        for refund in (1, 2, 16, 17, 127, 128, 255, 256, 32767, 32768, 8388607, 8388608, 499999999, 500000000, 2 ** 31 - 1, 2 ** 31):
            cases.append(('chan sch=%d refund=%d' % (sch, refund), _raw_channel(0x50 + sch if sch else 0, hh, _SERVER_PK, _push_num_raw(refund))))
    base = _raw_channel(0x52, hh, _SERVER_PK, _push_num_raw(1000))
    for enc in (b'\x01\x05', b'\x03\xe8\x03\x00', b'\x02\x10\x00', b'\x01\x81', b'\x01\x00', b'\x00', b'\x4f',
                b'\x4c\x02\xe8\x03', b'\x05\x00\x65\xcd\x1d\x00', b'\x04\xff\xff\xff\x7f', b'\x04\x00\x65\xcd\x1d', b'\x04\xff\x64\xcd\x1d'):
        cases.append(('chan refund-enc %s' % enc.hex(), base[:73] + enc + base[76:]))
    cases.append(('chan slot hash differs', base[:-35] + bytes([0x20]) + ym.sha256(b'other') + base[-3:]))
    cases.append(('chan slot scheme differs', base[:-3] + bytes([0x51]) + base[-2:]))
    for name, pk in (('pk 04', b'\x04' + _SERVER_PK[1:]), ('pk x>=p', b'\x02' + (_P_SECP + 1).to_bytes(32, 'big')),
                     ('pk off-curve', b'\x02' + (5).to_bytes(32, 'big')), ('pk 03 G', b'\x03' + _SERVER_PK[1:]),
                     ('pk x=p', b'\x02' + _P_SECP.to_bytes(32, 'big'))):
        cases.append(('chan ' + name, base[:38] + pk + base[71:]))
    for i in rnd.sample(range(len(base)), 40):
        for b in (0x00, 0x51, 0x52, 0xb2, 0x61, 0xff):
            if base[i] != b:
                cases.append(('chan mut[%d]=%02x' % (i, b), base[:i] + bytes([b]) + base[i + 1:]))
    cases.append(('chan +byte', base + b'\x61'))
    cases.append(('chan -byte', base[:-1]))
    cases.append(('chan OP_NOTIF', bytes([0x64]) + base[1:]))
    for n in range(1, 17):
        cases.append(('chan off-curve-x=%d' % n, base[:38] + b'\x02' + n.to_bytes(32, 'big') + base[71:]))
    for sb in (0x00, 0x50, 0x51, 0x52, 0x53, 0x60):
        cases.append(('pqpkh scheme %02x' % sb, bytes([0x20]) + hh + bytes([sb, 0xc2])))
    cases.append(('pqpkh pushdata1', bytes([0x4c, 0x20]) + hh + bytes([0x52, 0xc2])))
    cases.append(('pqpkh 01 02 scheme', bytes([0x20]) + hh + bytes([0x01, 0x02, 0xc2])))
    rows = []
    for name, spk in cases:
        ch = ym.pqchannel_client(spk)
        pk = ym.pqpkh_owner(spk)
        kind = 'pqchannel' if ch is not None else 'pqpubkeyhash' if pk is not None else 'other'
        holder = (ch or pk or b'').hex()
        rows.append({'name': name, 'hex': spk.hex(), 'type': kind, 'holder': holder})
    return rows


def build_pq_chain():
    """A chain across PQ_FALCON_HEIGHT: Falcon owner mints, P2PKH / SLH / Falcon / channel holders on both sides
    of F, an off-curve server key, the yedIn = 0 TRANSFER and an over-assignment (both unaffected by TOK-PQ)."""
    params = ym.Params.regtest(1)
    params.pq_falcon_height = PQ_FALCON_HEIGHT
    c = activated_chain(params)
    expected = []
    falcon_owner = bytes([2]) + ym.sha256(b'pq-vectors-falcon-owner')
    falcon_h = ym.pqpkh_script(bytes([2]) + ym.sha256(b'pq-vectors-falcon-holder'))
    slh_h = ym.pqpkh_script(bytes([1]) + ym.sha256(b'pq-vectors-slh-holder'))
    p2pkh = ym.p2pkh_script(OWNER_KEYHASH)
    chan_falcon = ym.pqchannel_script(bytes([2]) + ym.sha256(b'pq-vectors-chan-falcon'), _SERVER_PK, 1000)
    chan_slh = ym.pqchannel_script(bytes([1]) + ym.sha256(b'pq-vectors-chan-slh'), _SERVER_PK, 1000)
    off_curve = _raw_channel(0x52, ym.sha256(b'pq-vectors-off-curve'), b'\x02' + (5).to_bytes(32, 'big'), _push_num_raw(1000))
    assert ym.pqchannel_client(off_curve) is None

    def step(raws, want=None):
        """Mine ``raws`` in the next block; ``want`` = the verdict that must refuse the (single) transaction."""
        h = c.height + 1
        before = dict(c.refused)
        c.mine((1, 50_000, 0, KEY2), raws)
        new = {k: v for k, v in c.refused.items() if k not in before}
        if want is None:
            assert not new, new
        else:
            assert list(new.values()) == [want], (h, new, want)
            expected.append({'height': h, 'verdict': want})
        return [txid_of(x) for x in raws]

    def mint(owner=G_OWNER, token=None, want=None):
        ref = c.height - 1
        raw = c.mint_tx(10_000, 48, ref, collateral_for(c, 10_000, ref), fee_key=KEY1, owner=owner, token_script=token)
        return step([raw], want)[0]

    def transfer(inputs, outs, want=None):
        vin = [(t, n, b'', 0xFFFFFFFF) for t, n in inputs] + [c.fund_input()]
        vouts = [(c.params.token_value, spk) for spk, _ in outs]
        vouts.append((0, bytes([ym.OP_RETURN]) + ym.push(ym.encode_transfer([(i, cents) for i, (_, cents) in enumerate(outs)]))))
        return step([ym.serialize_tx_v4(vin, vouts).hex()], want)[0]

    # below F
    a = mint(token=p2pkh)
    mint(owner=falcon_owner, token=falcon_h, want='bad-mint-owner-key')
    b = mint(token=slh_h)
    mint(token=chan_slh)
    mint(token=chan_falcon)
    mint(token=off_curve)                                   # no shape rule below F: any script holds YED
    e = transfer([(a, 1)], [(p2pkh, 3000), (falcon_h, 3000), (chan_falcon, 4000)])
    while c.height + 1 < PQ_FALCON_HEIGHT:
        c.mine_n(1, price_fn=lambda h: 50_000)
    # from F
    mint(token=p2pkh, want='bad-yed-holder')
    g = mint(owner=falcon_owner, token=falcon_h)
    mint(token=slh_h, want='bad-yed-holder')
    mint(token=chan_slh, want='bad-yed-holder')
    mint(token=chan_falcon)
    mint(token=off_curve, want='bad-yed-holder')
    transfer([(b, 1)], [(falcon_h, 10_000)])                 # a pre-F SLH token spent to a Falcon holder
    transfer([], [(p2pkh, 1_000)])                          # yedIn = 0: no YED moves, TOK-PQ unaffected
    transfer([(e, 0)], [(p2pkh, 5_000)])                    # over-assigned: XFER-2 burns, TOK-PQ unaffected
    transfer([(g, 1)], [(p2pkh, 10_000)], want='bad-yed-holder')
    transfer([(g, 1)], [(chan_falcon, 6_000), (falcon_h, 4_000)])
    c.mine_n(2, price_fn=lambda h: 50_000)
    return c, expected


def pq_vectors_document():
    c, expected = build_pq_chain()
    return {
        'description': 'Post-quantum cross-implementation vectors (quantum spec D-Q-19, F-7, R-A2; Q4 reviews A m-2, B M-1). '
                       '"scripts": TX_PQCHANNEL / TX_PQPKH matcher cases (reviewer B\'s differential): type pqchannel | '
                       'pqpubkeyhash | other and the YED holder (scheme || hash, HolderKey) or "". "chain": regtest params '
                       '{startHeight 1, the TEST_SET attestor set, pqFalconHeight %d}; synthetic blocks as yellowback_golden.json '
                       '(txs[0] the coinbase; "invalid" blocks are rejected with the listed verdict and mined again without the '
                       'transaction): Falcon owners and P2PKH / SLH / Falcon / channel / off-curve-server holders on both sides of '
                       'the Falcon height, a pre-F token spent after it, the yedIn = 0 TRANSFER and an over-assignment (unaffected '
                       'by TOK-PQ). Regenerate: test_yellowback_model.py --write-pq-vectors.' % PQ_FALCON_HEIGHT,
        'scripts': pq_script_cases(),
        'chain': {
            'params': {'startHeight': 1, 'sigmaRefBps': 0, 'supplyCapBps': 0, 'attestorSetId': c.params.attestor_set,
                       'attestArmMin': 3, 'bundleCarrier': ym.CARRIER_SCRIPTSIG, 'mintRequiresArmed': False,
                       'pqFalconHeight': PQ_FALCON_HEIGHT},
            'invalid': expected,
            'stateHash': c.model.state_hash(),
            'tip': {'height': c.height, 'hash': c.block_hash(c.height)},
            'totals': c.model.totals.as_dict(),
            'blocks': c.blocks,
        },
    }


def write_pq_vectors():
    doc = pq_vectors_document()
    with open(PQ_VECTORS_PATH, 'w') as f:
        json.dump(doc, f, indent=1)
        f.write('\n')
    print('wrote %s: %d scripts, %d blocks, stateHash %s' % (PQ_VECTORS_PATH, len(doc['scripts']), len(doc['chain']['blocks']),
                                                            doc['chain']['stateHash']))


class PQVectorTests(unittest.TestCase):

    # Rule: TOK-PQ
    # Rule: MINT-3
    def test_pq_vectors_pinned(self):
        """The model regenerates yellowback_pq_vectors.json byte for byte (the C++ suites replay the same file)."""
        with open(PQ_VECTORS_PATH) as f:
            pinned = json.load(f)
        self.assertEqual(pq_vectors_document(), pinned)
        self.assertEqual(len(pinned['scripts']), 364)


def golden_text():
    """The golden document exactly as --write-golden writes it."""
    c, _ = build_golden()
    doc = golden_document(c)
    return json.dumps(doc, indent=1) + '\n', doc


def write_golden():
    text, doc = golden_text()
    with open(GOLDEN_PATH, 'w') as f:
        f.write(text)
    print('wrote %s: %d blocks, stateHash %s' % (GOLDEN_PATH, len(doc['blocks']), doc['stateHash']))
    print('sha256 of the file: %s' % ym.sha256(text.encode()).hex())


def check_golden():
    """Rebuild the golden sequence and compare the whole document with the committed file, byte for byte (audit
    03/T-1: stronger than the stateHash pin -- a hand "fix" of the hash, or of any block, fails here).  Exit 1 on
    any difference."""
    text, doc = golden_text()
    with open(GOLDEN_PATH) as f:
        committed = f.read()
    if committed == text:
        print('golden OK: %s is the model\'s output byte for byte (%d blocks, stateHash %s, sha256 %s)'
              % (GOLDEN_PATH, len(doc['blocks']), doc['stateHash'], ym.sha256(text.encode()).hex()))
        return 0
    import difflib
    diff = list(difflib.unified_diff(committed.splitlines(), text.splitlines(), 'committed', 'rebuilt', lineterm='', n=1))
    print('golden STALE: %s differs from the model\'s output (%d diff lines; first 40):' % (GOLDEN_PATH, len(diff)))
    print('\n'.join(diff[:40]))
    return 1


if __name__ == '__main__':
    if '--write-golden' in sys.argv:
        write_golden()
    elif '--check-golden' in sys.argv:
        sys.exit(check_golden())
    elif '--write-pq-vectors' in sys.argv:
        write_pq_vectors()
    else:
        unittest.main()
