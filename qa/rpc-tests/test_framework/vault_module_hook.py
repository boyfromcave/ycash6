#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The YED module's liveness hook for the Python ``VaultModel`` (vault.py, ``liveness_hook``): an
independent port of ``yellowback::Module::Liveness`` (src/yellowback/module.cpp) and the
``AttestationLiveness`` it calls (src/yellowback/state.cpp), so the model can witness the set
state of a node that runs the module (07/F-4).

    hook = yed_liveness_hook(params, block_hash_at)
    model = VaultModel(activation_height, liveness_hook=hook)

``params`` is the YED model's ``Params`` (``yellowback_model.params_from_getinfo``), its
``attestor_set`` the governed set's display hex. ``block_hash_at(h)`` returns the display hex of
the block at height h on the chain being replayed (the C++ hook's ``ctx.blockHashAt``), or None.

The hook, for a non-coinbase transaction at height h (C++ order):
  1. the governed set exists in the model and has the shape the module adopts (``AdoptedSet``):
     OPEN, ``seats == ATTESTOR_SEATS``, ``maturity == BOND_MATURITY``,
     ``livenessWindow >= ATTESTOR_LIVENESS_MIN``;
  2. the transaction is a MINT, CLAIM_NOTICE or REDEEM whose refHeight R is below h and within
     REF_WINDOW of it, carrying one scriptSig bundle carrier (REDEEM: not on vin 0) whose bundle
     hashes to the carrier's commitment and holds M_SELECT..BUNDLE_MAX attestations;
  3. every attestation's seq names a live member: the member whose ``join_ordinal == seq + 1``,
     ACTIVE, its bond unfrozen and in the bond index; distinct seqs; each cited height fresh
     (R - ATTEST_MAX_AGE < cited <= R, cited >= START_HEIGHT), each price in range, each
     signature valid under the member key over blockHash(cited);
  4. then (governed set, member key, cited) for each attestation whose cited height exceeds the
     member's lastAct. Any failure credits nobody. VaultModel applies the result as
     ``ApplyEjectionsOf`` does (cited < h, cited > lastAct, ACTIVE, unfrozen).

The module's equivocation ejections (``Module::Ejections``) are not ported: a chain that carries
an attestor equivocation diverges from this witness on the ejected member's status.
"""

from . import vault as v
from . import yellowback_model as ym


def set_id_internal(display_hex):
    return bytes.fromhex(display_hex)[::-1]


def adopted_set(params, vmodel):
    """AdoptedSet (module.cpp): the governed set when it has the shape the module adopts, else None."""
    if not params.attestor_set:
        return None
    s = vmodel.get_set(set_id_internal(params.attestor_set))
    if s is None or not s.p['flags'] & v.SET_FLAG_OPEN or s.p['seats'] != params.attestor_seats \
            or s.p['maturity'] != params.bond_maturity or s.p['livenessWindow'] < params.attestor_liveness_min:
        return None
    return s


def live_member(vmodel, s, seq):
    """(key33, last_act) of the member whose join ordinal is seq + 1 when it is ACTIVE with an unfrozen bond in
    the bond index, else None (module.cpp liveMember)."""
    for m in s.members.values():
        if m.join_ordinal != seq + 1:
            continue
        if m.status != v.MEMBER_ACTIVE or m.bond_frozen:
            return None
        b = vmodel.bonds.get(m.bond_outpoint)
        if b is None or b[2]:
            return None
        return (m.key, m.last_act)
    return None


def attestation_liveness(tx_hex, params, height, member_of, block_hash_at):
    """AttestationLiveness (state.cpp) over a raw transaction: [(seq, cited)] for the signers whose cited height
    exceeds their lastAct, or [] on any failure. ``member_of(seq)`` -> (key33, last_act) or None."""
    from . import yellowback_attest as ya
    p = params
    tx = ym.tx_from_hex(tx_hex)
    payload, _opret = ym.tx_payload([o.script for o in tx.vout])
    if payload is None or payload.type not in (ym.PAYLOAD_MINT, ym.PAYLOAD_CLAIM_NOTICE, ym.PAYLOAD_REDEEM):
        return []
    if p.bundle_carrier == ym.CARRIER_OP_RETURN:
        return []
    found, _why = ym.YellowbackModel(p)._find_carrier(tx, payload.type == ym.PAYLOAD_REDEEM)
    if found is None:
        return []
    _i, pushes = found
    _pk, commitment = ya.parse_carrier_script(pushes[2])
    if ym.sha256(pushes[0]) != commitment:
        return []
    atts = ya.decode_bundle(pushes[0])
    if atts is None or not atts or not (p.m_select <= len(atts) <= p.bundle_max):
        return []
    parsed = [ya.parse_attestation(a) for a in atts]
    seqs = [x[0] for x in parsed]
    members = {}
    for seq in seqs:
        m = member_of(seq)
        if m is None:
            return []
        members[seq] = m
    if len(set(seqs)) != len(seqs):
        return []
    R = payload.ref_height
    if R < 0 or R >= height or height - R > p.ref_window:
        return []
    for _seq, price, cited, _r, _s in parsed:
        if not (R - p.attest_max_age < cited <= R) or cited < p.start_height:
            return []
        if not (p.price_min <= price <= p.price_max):
            return []
    for att, (seq, _price, cited, _r, _s) in zip(atts, parsed):
        bh = block_hash_at(cited)
        if bh is None or not ya.verify_attestation(members[seq][0], att, bh):
            return []
    return [(seq, cited) for seq, _price, cited, _r, _s in parsed if cited > members[seq][1]]


def yed_liveness_hook(params, block_hash_at):
    """VaultModel's liveness_hook: Module::Liveness with the YED parameters ``params``."""
    def hook(tx, h, vmodel):
        s = adopted_set(params, vmodel)
        if s is None:
            return []
        credits = attestation_liveness(v.tx_hex(tx), params, h, lambda seq: live_member(vmodel, s, seq), block_hash_at)
        out = []
        for seq, cited in credits:
            key, _last = live_member(vmodel, s, seq)
            out.append((s.set_id, key, cited))
        return out
    return hook


# ---------------------------------------------------------------------------
# The two-model witness over a live chain (07/F-4): one VaultModel with the hook (a module node's set state), one
# without (a stock node's), replayed from the activation height and compared with set_getinfo.

def replay_models(node, params):
    """(model_with_hook, model_without, tip, credits): both VaultModels over ``node``'s chain from UPGRADE_VAULT's
    activation to its tip, and the number of (member, height) credits the hook returned on the way. Scripts are not
    re-checked (the node did); every set rule is. Raises AssertionError naming the first block the models refuse."""
    from io import BytesIO
    from .mininode import CBlock
    act = node.vault_getinfo()['activationheight']
    assert act >= 0, 'UPGRADE_VAULT is not scheduled'
    tip = node.getblockcount()
    hashes = {h: node.getblockhash(h) for h in range(0, tip + 1)}
    hook = yed_liveness_hook(params, hashes.get)
    credits = []

    def counting(tx, h, vmodel):
        out = hook(tx, h, vmodel)
        credits.extend(out)
        return out
    with_hook = v.VaultModel(activation_height=act, check_scripts=False, liveness_hook=counting)
    without = v.VaultModel(activation_height=act, check_scripts=False)
    for h in range(act, tip + 1):
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(node.getblock(hashes[h], 0))))
        for name, model in (('with the module hook', with_hook), ('without a module', without)):
            r = model.connect_block(h, block.vtx)
            assert r is None, 'the VaultModel %s refuses block %d (%s), tx %d: %s' % (name, h, hashes[h], r[0], r[1])
    return with_hook, without, tip, len(credits)


def _zat(yec):
    from decimal import Decimal
    return int((Decimal(str(yec)) * v.COIN).to_integral_value())


def compare_set_state(node, model, h):
    """Every set the node lists, and every member of each, against ``model`` at height ``h``: the set fields the model
    keeps and every member field but the node's ``wallet``. Returns the number of members compared; raises
    AssertionError naming the first difference."""
    rpc_sets = sorted(s['setid'] for s in node.set_list())
    model_sets = sorted(v.txid_display(sid) for sid in model.sets)
    assert rpc_sets == model_sets, 'sets: node %s, model %s' % (rpc_sets, model_sets)
    n = 0
    for sid_hex in rpc_sets:
        r = node.set_getinfo(sid_hex, h)
        m = model.set_info(set_id_internal(sid_hex), h)
        for rk, mk, conv in (('createheight', 'createHeight', int), ('winddownheight', 'windDownHeight', int),
                             ('lockedvalue', 'lockedValue', _zat), ('current', 'current', int),
                             ('dormant', 'dormant', bool), ('released', 'released', bool)):
            assert conv(r[rk]) == m[mk], 'set %s %s: node %r, model %r (height %d)' % (sid_hex[:16], rk, r[rk], m[mk], h)
        rm = {x['key']: x for x in r['memberlist']}
        mm = {x['memberKey']: x for x in m['members']}
        assert sorted(rm) == sorted(mm), 'set %s members: node %s, model %s' % (sid_hex[:16], sorted(rm), sorted(mm))
        for key, x in mm.items():
            y = rm[key]
            got = (y['status'].upper(), int(y['joinheight']), int(y['lastact']), y['bondoutpoint'], _zat(y['bondvalue']),
                   int(y['bondlocktime']), bool(y['bondfrozen']))
            want = (x['status'], x['joinHeight'], x['lastAct'], '%s:%d' % (x['bondOutpoint']['txid'], x['bondOutpoint']['vout']),
                    x['bondValue'], x['bondLocktime'], x['bondFrozen'])
            assert got == want, 'set %s member %s: node %r, model %r (status, joinheight, lastact, bondoutpoint, bondvalue, ' \
                                'bondlocktime, bondfrozen; height %d)' % (sid_hex[:16], key[:16], got, want, h)
            n += 1
    return n
