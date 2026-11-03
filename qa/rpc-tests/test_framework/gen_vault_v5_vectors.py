#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
DORMANT. Writes src/test/data/vault_v5_dormant_vectors.json: the vault signing messages as they
would be under a v5 (ZIP-225 / ZIP-244) transaction, the dormant section of the vault spec
(workspace docs/spec/vault-signing-message-v5.md, kogany plan K-21, option D). No Ycash network
allows a v5 transaction under Vault (upgrade plan U-26); these vectors pin the message a later
upgrade would switch on, and are NOT part of qa/yellowback-cross-line.manifest (ycash6 only).

    .venv/bin/python qa/rpc-tests/test_framework/gen_vault_v5_vectors.py           # write
    .venv/bin/python qa/rpc-tests/test_framework/gen_vault_v5_vectors.py --check   # compare only

Before it emits anything the generator replays the upstream ZIP-244 vectors
(src/test/data/zip0244.json, = librustzcash zcash_primitives tests/data.rs zip_0244) through
test_framework/zip244.py and refuses to write if any digest differs.
src/test/vault_v5_dormant_tests.cpp replays the output through the node's own ZIP-244 path
(SignatureHash -> SIGVERSION_ZIP244 -> Rust sighash_v5.rs) on hand-built transactions; no node
configuration schedules Vault and NU5 together.

The messages (spec §2): the v5 transaction carries its branch id; every digest below is computed
with nConsensusBranchId = BRANCH_ID (Ycash's reserved NU5 id, kogany K-7):

    set signature  msg = SHA256d("YcashSetSig" || setId || role || prevout || S(ALL|ANYONECANPAY, nIn))
    owner (PQ)     msg = S(ALL, nIn)
    act            actMsg = SHA256d("YcashSetAct" || P || vin[0].prevout)      unchanged
    S(t, i)        the ZIP-244 signature digest for transparent input i under hash type t; it needs
                   the amount and scriptPubKey of EVERY spent output (prevOutputs[] below)

JSON schema (hex everywhere; ids, txids and digests in internal byte order = uint256::begin()
unless the key ends in "Display"; a prevout is the 36-byte COutPoint serialisation):

    _comment, _status, _schema   text
    branchId, versionGroupId     ints (0xf919a198, 0x26a7270a)
    upstream                     {source, vectors, checked}: the ZIP-244 self-check that ran
    keys[]                       {label, secret, pubkey}
    pqOwner                      {seed, pk, owner {scheme, hash}}
    spends[]                     set-signed template inputs: {name, kind, tx, txid, txidDisplay, authDigest,
                                 nIn, prevOutputs [{amount, scriptPubKey}], hashType (0x81), sighash,
                                 v4Sighash (the same spend as a v4 tx under VAULT_BRANCH_ID, ZIP-243),
                                 setId, role, setSigMsg, signers, sigs, scriptSig,
                                 feeReplaced {tx, txid, prevOutputs, sighash}: the fee input swapped for
                                 another of a different value; sighash and setSigMsg are unchanged}
    ownerSpends[]                {name, kind, tx, txid, authDigest, nIn, prevOutputs, hashType (0x01),
                                 sighash, selector, scriptSig,
                                 feeAmountChanged {prevOutputs, sighash}: same tx, the fee input's spent
                                 amount claimed differently; the owner's ALL digest changes (S.2c)}
    acts[]                       {name, tx, txid, payload, prevout, actMsg, actMsgV4 (== actMsg), sigs}
    setCreate                    {tx, setIdV5 (the ZIP-244 txid), setIdV4 (SHA256d of the same act as a v4 tx)}
"""

import json
import os
import sys

if __name__ == '__main__':
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from test_framework import vault as v                      # noqa: E402
from test_framework import zip244                          # noqa: E402
from test_framework import test_zip244                     # noqa: E402
from test_framework.mininode import (                      # noqa: E402
    CTransaction, OrchardBundle, SaplingBundle, ZIP225_VERSION_GROUP_ID,
)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..'))
OUT = os.path.join(ROOT, 'src', 'test', 'data', 'vault_v5_dormant_vectors.json')

BRANCH_ID = 0xF919A198          # Ycash's reserved NU5 branch id (src/consensus/upgrades.cpp; kogany K-7)
LABELS = ['admit', 'member-0', 'member-1', 'member-2', 'fee', 'fee-alt', 'recipient']


def _h(b):
    return bytes(b).hex()


def _txid(label):
    return v.sha256(b'vault-v5-vectors-txid-' + label.encode())[::-1].hex()


def upstream_check():
    """Replays every upstream ZIP-244 vector; raises on the first mismatch."""
    rows = test_zip244.load_vectors()
    checked = 0
    for row in rows:
        tx, raw = test_zip244.parse_tx(row[0])
        assert tx.serialize() == raw
        assert test_zip244.display(zip244.txid_digest(tx)) == row[1], 'upstream txid'
        assert test_zip244.display(zip244.auth_digest(tx)) == row[2], 'upstream auth digest'
        t_in = test_zip244.t_inputs_of(row)
        assert test_zip244.display(zip244.signature_digest(tx, t_in, 0x01, None)) == row[6], 'upstream shielded'
        checked += 1
        if row[5] is None:
            continue
        for col, ht in test_zip244.HASH_TYPES:
            if row[col] is not None:
                got = zip244.signature_digest(tx, t_in, ht, t_in[row[5]])
                assert test_zip244.display(got) == row[col], 'upstream sighash 0x%02x' % ht
                checked += 1
    return {'source': 'src/test/data/zip0244.json (zcash-test-vectors zip_0244.py; '
                      'librustzcash zcash_primitives/src/transaction/tests/data.rs zip_0244)',
            'vectors': len(rows), 'checked': checked}


def to_v5(tx4):
    """The same transparent transaction as a ZIP-225 v5 transaction: no Sapling, no Orchard."""
    tx = CTransaction()
    tx.fOverwintered = True
    tx.nVersion = 5
    tx.nVersionGroupId = ZIP225_VERSION_GROUP_ID
    tx.nConsensusBranchId = BRANCH_ID
    tx.vin = [type(i)(i.prevout, i.scriptSig, i.nSequence) for i in tx4.vin]
    tx.vout = list(tx4.vout)
    tx.nLockTime = tx4.nLockTime
    tx.nExpiryHeight = tx4.nExpiryHeight
    tx.saplingBundle = SaplingBundle()
    tx.orchardBundle = OrchardBundle()
    return tx


def t_inputs(prev):
    return [zip244.TransparentInput(i, spk, amt) for i, (amt, spk) in enumerate(prev)]


def sighash5(tx, prev, n_in, hashtype):
    ti = t_inputs(prev)
    return zip244.signature_digest(tx, ti, hashtype, ti[n_in])


def txid5(tx):
    return zip244.txid_digest(tx)


def _prev_json(prev):
    return [{'amount': a, 'scriptPubKey': _h(s)} for a, s in prev]


def _sign_fee(tx, prev, n_in, secret):
    """A P2PKH fee input signed under ZIP-244 SIGHASH_ALL (a complete transaction; not a vault message)."""
    sh = sighash5(tx, prev, n_in, v.SIGHASH_ALL)
    sig = v.ecdsa_sign_der(secret, sh) + bytes([v.SIGHASH_ALL])
    tx.vin[n_in].scriptSig = v.push(sig) + v.push(v.pubkey_of(secret))


def build():
    K = {lab: v.fixed_secret('vault-v5-vectors-' + lab) for lab in LABELS}
    P = {lab: v.pubkey_of(s) for lab, s in K.items()}
    seed = v.sha256(b'vault-v5-vectors-pq-owner') + v.sha256(b'vault-v5-vectors-pq-owner\x01')[:16]
    pq_pk, pq_sk = v.pq.slh_keygen(seed)
    OWNER = v.pq_owner_id(v.pq.SCHEME_SLH_DSA_SHA2_128S, pq_pk)
    set_a = v.txid_internal(_txid('set-a'))
    set_b = v.txid_internal(_txid('set-b'))
    recipient = v.p2pkh_script_of_pubkey(P['recipient'])
    fee_spk = v.p2pkh_script_of_pubkey(P['fee'])
    fee_alt_spk = v.p2pkh_script_of_pubkey(P['fee-alt'])
    fee_value = v.COIN // 10
    fee_alt_value = v.COIN // 4

    doc = {
        '_comment': 'DORMANT: generated by qa/rpc-tests/test_framework/gen_vault_v5_vectors.py; do not edit. '
                    'Spec: workspace docs/spec/vault-signing-message-v5.md. Not in qa/yellowback-cross-line.manifest.',
        '_status': 'dormant: no network admits a v5 transaction under Vault (upgrade plan U-26); switched on only '
                   'by a later upgrade that adopts NU5 on Ycash (kogany plan K-21, option D)',
        '_schema': 'hex everywhere; ids/txids/digests internal byte order unless the key ends in Display; '
                   'prevout = txid internal || n u32 LE',
        'branchId': BRANCH_ID,
        'versionGroupId': ZIP225_VERSION_GROUP_ID,
        'upstream': upstream_check(),
        'keys': [{'label': lab, 'secret': _h(K[lab]), 'pubkey': _h(P[lab])} for lab in LABELS],
        'pqOwner': {'seed': _h(seed), 'pk': _h(pq_pk), 'owner': {'scheme': OWNER[0], 'hash': _h(OWNER[1:])}},
    }

    vp = v.VaultParams(tag=b'WYEC', set_id=set_a, cancel_set_id=set_b, delay=10, owner_height=1000,
                       app_height=0, owner=OWNER)
    v_spk = v.vault_script(vp)
    ip = v.intent_for(vp, recipient)
    i_spk = v.intent_script(ip)
    value = 25 * v.COIN
    fee_in = (_txid('fee-utxo'), 1, v.SEQUENCE_FINAL)
    fee_alt_in = (_txid('fee-alt-utxo'), 3, v.SEQUENCE_FINAL)

    # --- set-signed spends (OP_CHECKSETSIG, ALL|ANYONECANPAY)
    def set_spend(name, kind, tx4, spk, amount, set_id, role, signers, scriptsig_of):
        prev = [(amount, spk), (fee_value, fee_spk)]
        tx = to_v5(tx4)
        sh = sighash5(tx, prev, 0, v.SET_SIGHASH)
        txid_hex, n = v.prevout_of(tx, 0)
        msg = v.set_sig_msg(set_id, role, txid_hex, n, sh)
        sigs = [v.sign_recoverable(K[s], msg) for s in signers]
        assert [v.recover_compact(s, msg) for s in sigs] == [P[s] for s in signers]
        tx.vin[0].scriptSig = scriptsig_of(sigs)
        _sign_fee(tx, prev, 1, K['fee'])
        tid = txid5(tx)
        # v4 contrast: the same spend under ZIP-243 and the vault branch
        sh4 = v.set_sighash(tx4, 0, spk, amount)
        assert sh4 != sh
        # Fee replacement: another fee input, another value; the set's digest must not move (01/V-2).
        tx_r = to_v5(tx4)
        tx_r.vin[1] = type(tx_r.vin[1])(tx_r.vin[1].prevout, b'', tx_r.vin[1].nSequence)
        from test_framework.mininode import COutPoint
        tx_r.vin[1].prevout = COutPoint(int(fee_alt_in[0], 16), fee_alt_in[1])
        prev_r = [(amount, spk), (fee_alt_value, fee_alt_spk)]
        sh_r = sighash5(tx_r, prev_r, 0, v.SET_SIGHASH)
        assert sh_r == sh, 'ANYONECANPAY must not commit to the fee input'
        tx_r.vin[0].scriptSig = scriptsig_of(sigs)
        _sign_fee(tx_r, prev_r, 1, K['fee-alt'])
        assert txid5(tx_r) != tid
        return {'name': name, 'kind': kind, 'tx': v.tx_hex(tx), 'txid': _h(tid), 'txidDisplay': tid[::-1].hex(),
                'authDigest': _h(zip244.auth_digest(tx)), 'nIn': 0, 'prevOutputs': _prev_json(prev),
                'hashType': v.SET_SIGHASH, 'sighash': _h(sh), 'v4Sighash': _h(sh4), 'setId': _h(set_id),
                'role': role, 'setSigMsg': _h(msg), 'signers': signers, 'sigs': [_h(s) for s in sigs],
                'scriptSig': _h(tx.vin[0].scriptSig),
                'feeReplaced': {'tx': v.tx_hex(tx_r), 'txid': _h(txid5(tx_r)), 'prevOutputs': _prev_json(prev_r),
                                'sighash': _h(sh_r)}}

    signers = ['member-0', 'member-1']
    utx = v.build_unlock_tx((_txid('vault-utxo'), 0), vp, value, [(recipient, 20 * v.COIN)],
                            relock_value=5 * v.COIN, fee_vin=[fee_in], change=(fee_value - v.VAULT_FEE, fee_spk))
    ctx = v.build_cancel_tx((_txid('intent-utxo'), 0), ip, 20 * v.COIN, vp, fee_vin=[fee_in],
                            change=(fee_value - v.VAULT_FEE, fee_spk))
    doc['spends'] = [
        set_spend('unlock', 'V', utx, v_spk, value, set_a, v.ROLE_UNLOCK, signers, v.vault_unlock_scriptsig),
        set_spend('cancel', 'I', ctx, i_spk, 20 * v.COIN, set_b, v.ROLE_CANCEL, ['member-2'],
                  v.intent_cancel_scriptsig),
    ]

    # --- owner spends (OP_CHECKPQSIG, SIGHASH_ALL): the V's OWNER branch, with a fee input
    def owner_spend(name, kind, spk, amount, outpoint, selector, lock_time, seq):
        tx4 = v.make_tx([(outpoint[0], outpoint[1], seq), fee_in], [(amount, recipient)], lock_time)
        tx = to_v5(tx4)
        prev = [(amount, spk), (fee_value, fee_spk)]
        sh = sighash5(tx, prev, 0, v.SIGHASH_ALL)
        sig = v.pq.slh_sign(pq_sk, sh)
        assert v.pq.slh_verify(pq_pk, sh, sig)
        pushes = v.pq.pq_scriptsig_pushes(pq_pk, sig + bytes([v.SIGHASH_ALL]))
        if kind == 'V':
            tx.vin[0].scriptSig = (v.vault_owner_scriptsig(pushes) if selector == v.SEL_OWNER
                                   else v.vault_owner_released_scriptsig(pushes))
        else:
            tx.vin[0].scriptSig = v.intent_owner_released_scriptsig(pushes)
        assert v.parse_selector(tx.vin[0].scriptSig, kind)[0] == selector
        _sign_fee(tx, prev, 1, K['fee'])
        prev_x = [(amount, spk), (fee_value + 1, fee_spk)]
        sh_x = sighash5(tx, prev_x, 0, v.SIGHASH_ALL)
        assert sh_x != sh, 'ALL commits to every spent amount (S.2c)'
        return {'name': name, 'kind': kind, 'tx': v.tx_hex(tx), 'txid': _h(txid5(tx)),
                'authDigest': _h(zip244.auth_digest(tx)), 'nIn': 0, 'prevOutputs': _prev_json(prev),
                'hashType': v.SIGHASH_ALL, 'sighash': _h(sh), 'selector': selector,
                'scriptSig': _h(tx.vin[0].scriptSig),
                'feeAmountChanged': {'prevOutputs': _prev_json(prev_x), 'sighash': _h(sh_x)}}

    doc['ownerSpends'] = [
        owner_spend('owner-selector-2', 'V', v_spk, value, (_txid('owner-vault-utxo'), 0), v.SEL_OWNER, 1000,
                    v.SEQUENCE_FINAL - 1),
        owner_spend('owner-released-selector-3-intent', 'I', i_spk, 20 * v.COIN, (_txid('owner-intent-utxo'), 1),
                    v.SEL_OWNER_RELEASED, 0, v.SEQUENCE_FINAL),
    ]

    # --- acts: actMsg binds P and vin[0].prevout only, so it is the same under v4 and v5
    acts = []
    hb_vin = [(_txid('heartbeat-utxo'), 0, v.SEQUENCE_FINAL)]
    tx4, p = v.build_set_heartbeat_tx(hb_vin, set_a, K['member-0'])
    tx = to_v5(tx4)
    txid_hex, n = v.prevout_of(tx, 0)
    am = v.act_msg(p, txid_hex, n)
    _, _, sigs = v.parse_act_script(tx.vout[0].scriptPubKey)
    acts.append({'name': 'heartbeat', 'tx': v.tx_hex(tx), 'txid': _h(txid5(tx)), 'payload': _h(p),
                 'prevout': _h(v.ser_prevout(txid_hex, n)), 'actMsg': _h(am), 'actMsgV4': _h(am),
                 'sigs': [_h(s) for s in sigs]})
    doc['acts'] = acts

    # --- SET_CREATE: setId is the creating transaction's txid, so a v5 SET_CREATE gets a ZIP-244 setId
    create = v.act_set_create(seats=3, unlock_threshold=2, cancel_threshold=1, slash_threshold=2,
                              admit_key=P['admit'])
    ctx4, _p = v.build_set_create_tx([(_txid('create-utxo'), 0, v.SEQUENCE_FINAL)], create)
    ctx5 = to_v5(ctx4)
    doc['setCreate'] = {'tx': v.tx_hex(ctx5), 'setIdV5': _h(txid5(ctx5)),
                        'setIdV4': _h(v.sha256d(ctx4.serialize()))}
    return doc


def dumps(doc):
    return json.dumps(doc, indent=1, sort_keys=False) + '\n'


def main():
    text = dumps(build())
    if '--check' in sys.argv[1:]:
        with open(OUT) as f:
            if f.read() != text:
                print('vault_v5_dormant_vectors.json is stale; rerun without --check')
                return 1
        print('vault_v5_dormant_vectors.json up to date')
        return 0
    with open(OUT, 'w') as f:
        f.write(text)
    print('wrote', OUT)
    return 0


if __name__ == '__main__':
    sys.exit(main())
