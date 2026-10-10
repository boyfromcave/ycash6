#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Writes src/test/data/vault_vectors.json, the golden vector of the vault primitive
(docs/plans/yellowback-upgrade-plan.md §15.9), deterministically from fixed private keys.
src/test/vault_vectors_tests.cpp replays it against the C++; the file must be byte-identical
on both node lines (ycash-dd and ycash6).

    .venv/bin/python qa/rpc-tests/test_framework/gen_vault_vectors.py           # write
    .venv/bin/python qa/rpc-tests/test_framework/gen_vault_vectors.py --check   # compare only

JSON schema (top-level keys; every byte string is lowercase hex; ids, txids, set ids and
hashes are the **internal** byte order = uint256::begin()..end() unless the key ends in
"Display"; a prevout is the 36-byte COutPoint serialisation, txid internal || n u32 LE):

    _comment, _schema        text
    branchId                 int, 0x6d5b7a31 (signatures in "spends" use it)
    opcodes                  {"CHECKSEQUENCEVERIFY": 178, "CHECKSETSIG": 192, "CHECKSETDORMANT": 193}
    keys[]                   {label, secret (32), pubkey (33, compressed)}
    pqOwner                  {label, seed (48), pk (32), owner {scheme, hash}}: the SLH-DSA-SHA2-128s
                              owner every vault and intent below names (quantum plan §4.3)
    vaults[]                 {name, params {tag, setId, cancelSetId, delay, ownerHeight, appHeight,
                              owner {scheme, hash}}, script}   ParseVault(script) == params,
                                                               BuildVault(params) == script
    vaultsInvalid[]          {name, script, reason}           ParseVault(script) fails
    intents[]                {name, params {tag, recipientHash, vaultHash, delay, cancelSetId, setId,
                              owner {scheme, hash}}, script, recipientScript?, vaultScript?}
    intentsInvalid[]         {name, script, reason}
    bonds[]                  {memberKey, locktime, redeem, spk (P2SH of redeem)}
    selectors[]              {kind "V"|"I", scriptSig, selector, nArgs}
    selectorsInvalid[]       {kind, scriptSig, reason}
    acts[]                   {name, type, fields (decoded, as decode_act), payload, prevout, actMsg,
                              signers [key labels], sigs [65], recovered [33], script (the OP_RETURN),
                              convicts? (SET_EQUIVOCATION: the key both signatures recover to)}
    actsInvalid[]            {name, payload, reason, stage}   stage "decode": magic / version / type /
                              size, DecodePayload fails; stage "field": a context-free field rule of
                              15.5 (CREATE ranges and flags, bondLocktime, burn, roles, signature
                              header) -- Python rejects it at decode, C++ may at rule time
    actScriptsInvalid[]      {name, script, reason}           the act output is malformed
    setSigMsgs[]             {setId, role, prevout, sighash, msg}
    signatures[]             {label, secret, pubkey, msg, sig, lowSFlipped}
                              sig == CKey::SignCompact(uint256(msg)); RecoverSetSig(msg, sig) == pubkey
    signaturesInvalid[]      {name, msg, sig, reason, nonStrictRecovers (pubkey or null)}
                              RecoverSetSig (strict: header 31..34, low S) fails
    spends[]                 {name, tx (final hex), nIn, scriptCode, amount, branchId, sighash,
                              setId, role, setSigMsg, signers, sigs, scriptSig}
                              SignatureHash(scriptCode, tx, nIn, SIGHASH_ALL, amount, branchId) == sighash
    ownerSpends[]            {name, tx (final hex), nIn, scriptCode, amount, branchId, sighash, selector,
                              scriptSig}  the pqOwner's SLH-DSA spend of a V's OWNER branch (selector 2):
                              VerifyScript(scriptSig, scriptCode) under the vault flags passes

"reason" strings are informative (the Python codes); a C++ test asserts only rejection.
"""

import json
import os
import sys

if __name__ == '__main__':
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from test_framework import vault as v    # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..'))
OUT = os.path.join(ROOT, 'src', 'test', 'data', 'vault_vectors.json')

LABELS = ['admit', 'ec-legacy', 'member-0', 'member-1', 'member-2', 'member-3', 'member-4', 'outsider']


def _keys():
    return {lab: v.fixed_secret('vault-vectors-' + lab) for lab in LABELS}


def _h(b):
    return bytes(b).hex()


def _txid(label):
    """A fixed txid (display hex) from a label."""
    return v.sha256(b'vault-vectors-txid-' + label.encode())[::-1].hex()


def _pq_owner():
    """The vectors' SLH-DSA owner: (seed48, pk, sk, owner33)."""
    seed = v.sha256(b'vault-vectors-pq-owner') + v.sha256(b'vault-vectors-pq-owner\x01')[:16]
    pk, sk = v.pq.slh_keygen(seed)
    return seed, pk, sk, v.pq_owner_id(v.pq.SCHEME_SLH_DSA_SHA2_128S, pk)


# The Falcon (FN-DSA-512) owner. Python has no Falcon signer (test_framework/pq.py verifies only), so its
# public key and its one signature are recorded here, made by the node's library: pq::KeyGen(2, FALCON_SEED)
# and pq::SignWithEntropy(2, sk, sighash, FALCON_ENTROPY) over the 'owner-falcon-selector-2' spend's sighash.
# src/test/vault_vectors_tests.cpp recomputes both byte for byte (and prints them on a mismatch, which is how
# to refresh them if that spend's transaction ever changes); build() checks them with pq.falcon_verify.
FALCON_SEED = v.sha256(b'vault-vectors-falcon-owner') + v.sha256(b'vault-vectors-falcon-owner\x01')[:16]
FALCON_ENTROPY = b''.join(v.sha256(b'vault-vectors-falcon-entropy-%d' % i) for i in range(3))[:88]
FALCON_PK = bytes.fromhex(
    '0953f1c292034d8b58c86212f5e9e3a9dd0ff5dd9262bb32d7a347d43815dc4f700e10670b204ab92c2e9b12988019da41c341c227f492d0b502c02f426a8d6705900739c88fb49670b5729a9a97517528346f2b6269d042404cdb3da5ba3689d660eb57780b7844cff90ddee3f6ee838942dec610de194f316daec721dd3c7ae967f8411ffb08d6d103ff59330244e7552e6f4c75647f7613898159d82b1a7b1b537626a2da4f6507bde94d63b008358d6ef9fb7782e2a54910010cafd107b5610736e2813adacbb426497c51da12f1661c4b6528e77422eac6ba3e71367fd5e26e19b1c316217e4bb0d798c52fdb7dd47091e82ba082d111a49c048636d1edd1cf804e128c03778f9615bc02d9390c4a610d9c2ee99968bba0c07db5ba0c484339b2c500cf2a2638b8001dc8b4858ecc23d6cf5f6ae928017e596c6dcd7f58d14e322eece711566d1309c01eb7a24b4101916f310dd5856972e421596cccaa6e67f0634b55428eb7f68f5a205292c326b5e576603c48ab63aa19bb7409dab097b60e55c5ba6cad4f9f306be0b74aae7ce419a1c56e21285a22eb2454f394886a938fd96735ce7597994c386732f5aadf0f541155a1a64321fd82a82ba6220f230e362c25855d105abdb191a7c376440ce8d7d02e0620c0bb14469087027aefb31395a80cc8ed887592a7bac5d349cea3867b487f22dc9f1d5dedbbd69e06ef227962741d2a898f5aab34c9da2d77d13db292c9345a122197031f7e18e6f902faad7f02c211e05063877f20f4d69aea644ea6fc03a8436e84cc9ce92ec8409539eedbd2822a65794757eccb3c339969f916c72c80048a63471524215876c1b09ef0419933a7619d3b273854681245283a985d9037127e89256dd60d9367b62264b7f0156b212075b7b8043d107484a3e494838b7e04c33c03be0208b12b4127b034cd26a336d9026c168674c7934c569ca0045601a67e6594935695ce320af420c5a9147bad1d503353ce0424be36ba6e17ad7407b101def929f999603899028924d4123f95e318aaa00b72903fb7e412432368356a887d367619c728cd1be4e9d8253a201655f899c7b68cb6d29960b1239d6aa15515802a7e0834d8eec0a4bc3bb256e81e62a18947e2d14053f2e10563d73727a88e44939093a84dbf911de42d95b211d10884c024a180e2bac4494b3c67c560dba0a688398b1dcfcfa0754f262fce4b3019aadbac90b99158c789c6280326503f55ecdc1c583457f85bd666')
FALCON_SIG = bytes.fromhex(
    '39483d45c94913cb62ab183868acfe76358b48890a02b8fd7a589924166f2699fdbf249c3a16deda2b27399238d4448d2bacc1aa894a6a6f953cd4451c1e577ff7ba8faeced9f2446353ea458290db7019273f0b6f894f68f197b7f68af53224c08316fdfd90dc4cddc8240a0b206d2c5845b54895de21262b17962179ce9f09d4a7e3c8247108ae5b368c89bd86b6c902c6ad1deaac691589bb3611549b6e8cc7e7a495c9e6cc12b73c57281e79ba2a7ad0f9491fc3a1fa5672833cb70c32b1924071e819104a27df32739270e314be7409ac7ce19098b286f3b42bb6dbf1fa55d31424afcd7db909fd7e13dabc92efe4aecb2159b110528513676b26ba8c55a32102ddfd6987ab1ec105c9888848fcfbc38a4bb30810b34db69846d2d8fbb4c8ea3427f6c469dd302a02bd7a4108d41700d7759158a70283eff3b2581d735663ac9d360bacb364ca2bd2922739f21b418b7959b5a086eb2addc20b33f6307e2756a1e790b22f434e697dd05482bb44aa52597ebe6520b4c4b6cbb863163d79a869d945b2cb90bb7b6251f1e166149fc51d28d8ee1beebd798ab769a60d8128ada9db3817d63ffa60b210c348693a9bb824f6b16e44168d031b4b844751eda23a8de1d96415a65e2d69450d8167edb6525109c42fed25fdb92b30cc246a6e916ed4e69603098dabd08556d1139db4473e34a0c31f18ef9bfc9dcef366a1e9b8cfac6c4a129b4918867debe127eecfda096e127419928a52526aaa80d2684f2b5338a3741d5d54f8657697a9065bf7c94273ef54179995c57ba5301e7227e15f7064ab8a41d8efb3059ebdf0e444e91f36ee43daf1a7b414c2b1d9f224b1255f80a0f939bc9a845ac05f308caebb5f739e52d27b94e73d67baef39daaf132b2b4c7ebb15bd91c7f7492e508fff10000000000000000000000000')


def build():
    K = _keys()
    P = {lab: v.pubkey_of(s) for lab, s in K.items()}
    pq_seed, pq_pk, pq_sk, OWNER = _pq_owner()
    set_a = v.txid_internal(_txid('set-a'))
    set_b = v.txid_internal(_txid('set-b'))
    doc = {
        '_comment': 'Generated by qa/rpc-tests/test_framework/gen_vault_vectors.py; do not edit. '
                    'Schema in that file and in qa/rpc-tests/test_framework/VAULT_VECTORS.md.',
        '_schema': 'hex everywhere; ids/hashes internal byte order (uint256::begin()); prevout = txid internal || n u32 LE; '
                   'integers in act bodies little-endian; script numbers minimal (CScript << int64_t).',
        'branchId': v.VAULT_BRANCH_ID,
        'opcodes': {'CHECKSEQUENCEVERIFY': v.OP_CHECKSEQUENCEVERIFY, 'CHECKSETSIG': v.OP_CHECKSETSIG,
                    'CHECKSETDORMANT': v.OP_CHECKSETDORMANT},
        'keys': [{'label': lab, 'secret': _h(K[lab]), 'pubkey': _h(P[lab])} for lab in LABELS],
        'pqOwner': {'label': 'pq-owner', 'seed': _h(pq_seed), 'pk': _h(pq_pk),
                    'owner': {'scheme': OWNER[0], 'hash': _h(OWNER[1:])}},
        'falconOwner': {'label': 'falcon-owner', 'seed': _h(FALCON_SEED), 'pk': _h(FALCON_PK),
                        'owner': {'scheme': 2, 'hash': _h(v.pq.key_hash(2, FALCON_PK))}},
    }
    FOWNER = v.pq_owner_id(v.pq.SCHEME_FN_DSA_512, FALCON_PK)

    # --- vaults
    def vp(**kw):
        d = dict(tag=b'WYEC', set_id=set_a, cancel_set_id=set_b, delay=144, owner_height=1000, app_height=0,
                 owner=OWNER)
        d.update(kw)
        return v.VaultParams(**d)

    off_curve = b'\x02' + bytes(31) + b'\x07'
    while v.is_valid_point(off_curve):
        off_curve = off_curve[:-1] + bytes([off_curve[-1] + 1])
    vault_cases = [
        ('bridge-default', vp()),
        ('delay-1-opcode', vp(delay=1)),
        ('delay-16-opcode', vp(delay=16)),
        ('delay-17-push', vp(delay=17)),
        ('delay-128-two-bytes', vp(delay=128)),
        ('delay-max', vp(delay=65535)),
        ('owner-height-1', vp(owner_height=1)),
        ('owner-height-max', vp(owner_height=499999999)),
        ('app-enabled', vp(tag=b'YED\x00', set_id=set_a, cancel_set_id=set_a, app_height=1288)),
        ('app-height-max', vp(app_height=499999999)),
        ('tag-zero', vp(tag=bytes(4))),
        ('owner-falcon-scheme-2', vp(owner=FOWNER)),      # A-1: a template whatever the Falcon flag
    ]
    doc['vaults'] = [{'name': n, 'params': p.to_json(), 'script': _h(v.vault_script(p))} for n, p in vault_cases]

    base = v.vault_script(vp(delay=5))
    i_delay = 4 + 1 + 32 + 1
    good = v.vault_script(vp())
    k_set = good.rfind(set_a)
    j_oh = base.find(bytes([0x02, 0xe8, 0x03]))
    inv = [
        ('delay-0', v.vault_script_unchecked(vp(delay=0)), 'delay out of range'),
        ('delay-65536', v.vault_script_unchecked(vp(delay=65536)), 'delay out of range'),
        ('delay-negative', v.vault_script_unchecked(vp(delay=-1)), 'delay out of range'),
        ('delay-5-as-data-push', base[:i_delay] + b'\x01\x05' + base[i_delay + 1:], 'non-minimal number'),
        ('owner-height-padded', base[:j_oh] + bytes([0x03, 0xe8, 0x03, 0x00]) + base[j_oh + 3:], 'non-minimal number'),
        ('owner-height-0', v.vault_script_unchecked(vp(owner_height=0)), 'ownerHeight out of range'),
        ('owner-height-500000000', v.vault_script_unchecked(vp(owner_height=500000000)), 'ownerHeight out of range'),
        ('app-height-500000000', v.vault_script_unchecked(vp(app_height=500000000)), 'appHeight out of range'),
        ('owner-scheme-0', v.vault_script_unchecked(vp(owner=b'\x00' + OWNER[1:])), 'owner scheme'),
        ('owner-scheme-3', v.vault_script_unchecked(vp(owner=b'\x03' + OWNER[1:])), 'owner scheme'),
        ('owner-scheme-16', v.vault_script_unchecked(vp(owner=b'\x10' + OWNER[1:])), 'owner scheme'),
        ('owner-scheme-as-data-push', good.replace(bytes([v.OP_1, v.OP_CHECKPQSIG]), bytes([1, 1, v.OP_CHECKPQSIG])),
         'non-minimal number'),
        ('owner-schemes-differ', good[:good.rfind(bytes([v.OP_1, v.OP_CHECKPQSIG]))] + bytes([v.OP_2, v.OP_CHECKPQSIG])
         + good[good.rfind(bytes([v.OP_1, v.OP_CHECKPQSIG])) + 2:], 'owner copies'),
        ('owner-hashes-differ', good[:good.rfind(OWNER[1:])] + bytes(32) + good[good.rfind(OWNER[1:]) + 32:],
         'owner copies'),
        ('owner-ec-key-checksig', good.replace(v.owner_slot(OWNER), v.push(P['ec-legacy']) + bytes([v.OP_CHECKSIG])),
         'the secp256k1 owner shape is not a template'),
        ('setid-copies-differ', good[:k_set] + set_b + good[k_set + 32:], 'shape'),
        ('pushdata1-for-32-bytes', good[:5] + bytes([v.OP_PUSHDATA1]) + good[5:], 'non-minimal push'),
        ('trailing-op', good + bytes([v.OP_1]), 'shape'),
        ('truncated', good[:-1], 'shape'),
        ('empty', b'', 'shape'),
        ('tag-5-bytes', bytes([5]) + b'WYECX' + good[5:], 'shape'),
    ]
    for n, s, _r in inv:
        assert v.parse_vault(s) is None, n
    doc['vaultsInvalid'] = [{'name': n, 'script': _h(s), 'reason': r} for n, s, r in inv]

    # --- intents
    recipient = v.p2pkh_script_of_pubkey(P['member-4'])
    intents = []
    for n, p in [('bridge-default', vp()), ('delay-1', vp(delay=1)), ('app-enabled', vault_cases[8][1]),
                 ('owner-falcon-scheme-2', vp(owner=FOWNER))]:
        ip = v.intent_for(p, recipient)
        intents.append({'name': n, 'params': ip.to_json(), 'script': _h(v.intent_script(ip)),
                        'recipientScript': _h(recipient), 'vaultScript': _h(v.vault_script(p))})
    doc['intents'] = intents
    ip0 = v.intent_for(vp(), recipient)
    igood = v.intent_script(ip0)
    ibad = [
        ('delay-0', v.intent_script_unchecked(v.IntentParams(ip0.tag, ip0.recipient_hash, ip0.vault_hash, 0,
                                                             ip0.cancel_set_id, ip0.set_id, ip0.owner)), 'delay'),
        ('delay-65536', v.intent_script_unchecked(v.IntentParams(ip0.tag, ip0.recipient_hash, ip0.vault_hash, 65536,
                                                                 ip0.cancel_set_id, ip0.set_id, ip0.owner)), 'delay'),
        ('trailing-byte', igood + b'\x00', 'shape'),
        ('vault-is-not-intent', v.vault_script(vp()), 'shape'),
        ('role-1-in-cancel-branch', igood.replace(bytes([v.OP_2, v.OP_CHECKSETSIG]), bytes([v.OP_1, v.OP_CHECKSETSIG])),
         'shape'),
        ('owner-scheme-3', igood.replace(bytes([v.OP_1, v.OP_CHECKPQSIG]), bytes([v.OP_3, v.OP_CHECKPQSIG])), 'owner scheme'),
        ('owner-ec-key-checksig', igood.replace(v.owner_slot(OWNER), v.push(P['ec-legacy']) + bytes([v.OP_CHECKSIG])),
         'the secp256k1 owner shape is not a template'),
        ('owner-scheme-as-data-push', igood.replace(bytes([v.OP_1, v.OP_CHECKPQSIG]), bytes([1, 1, v.OP_CHECKPQSIG])),
         'non-minimal number'),
        ('owner-scheme-0', igood.replace(bytes([v.OP_1, v.OP_CHECKPQSIG]), bytes([v.OP_0, v.OP_CHECKPQSIG])),
         'owner scheme'),
        ('owner-hash-31-bytes', igood.replace(v.owner_slot(OWNER), v.push(OWNER[1:32]) + bytes([v.OP_1, v.OP_CHECKPQSIG])),
         'owner hash size'),
        ('owner-hash-33-bytes', igood.replace(v.owner_slot(OWNER), v.push(OWNER[1:] + b'\x00') + bytes([v.OP_1, v.OP_CHECKPQSIG])),
         'owner hash size'),
    ]
    for n, s, _r in ibad:
        assert v.parse_intent(s) is None, n
    doc['intentsInvalid'] = [{'name': n, 'script': _h(s), 'reason': r} for n, s, r in ibad]

    # --- bonds
    doc['bonds'] = [{'memberKey': _h(P['member-0']), 'locktime': lt, 'redeem': _h(v.bond_script(P['member-0'], lt)),
                     'spk': _h(v.bond_spk(P['member-0'], lt))} for lt in (16, 1300, 499999999)]

    # --- selectors
    s65 = bytes([31]) + bytes(64)
    # an owner scriptSig shape: SLH-DSA chunking, <sig 15x520 + 57> <16> <pk 32> <1> (quantum plan §4.2)
    pq_args = v.pq.pq_scriptsig_pushes(bytes(32), bytes(v.pq.SIG_SIZE[1]) + b'\x01')
    sel = [
        ('V', v.vault_unlock_scriptsig([s65, s65]), 1, 2),
        ('V', v.vault_owner_scriptsig(pq_args), 2, 19),
        ('V', v.vault_owner_released_scriptsig(pq_args), 3, 19),
        ('V', v.vault_app_scriptsig(), 4, 0),
        ('I', v.intent_release_scriptsig(), 1, 0),
        ('I', v.intent_cancel_scriptsig([s65]), 2, 1),
        ('I', v.intent_owner_released_scriptsig(pq_args), 3, 19),
    ]
    for kind, ss, s_, n in sel:
        assert v.parse_selector(ss, kind) == (s_, v.push_values(ss)[:-1]) and n == len(v.push_values(ss)) - 1
    doc['selectors'] = [{'kind': k, 'scriptSig': _h(ss), 'selector': s_, 'nArgs': n} for k, ss, s_, n in sel]
    sel_bad = [
        ('V', bytes([0x55]), 'OP_5 is not a selector'),
        ('I', bytes([v.OP_4]), 'OP_4 is not an intent selector'),
        ('V', b'\x01\x01', 'selector pushed as data'),
        ('V', b'', 'empty'),
        ('V', bytes([v.OP_0]), 'OP_0'),
        ('V', bytes([v.OP_1NEGATE]), 'OP_1NEGATE'),
        ('V', bytes([v.OP_DUP, v.OP_1]), 'not push-only'),
        ('V', b'\x02\xaa', 'truncated push'),
    ]
    for kind, ss, _r in sel_bad:
        assert v.parse_selector(ss, kind) is None
    doc['selectorsInvalid'] = [{'kind': k, 'scriptSig': _h(ss), 'reason': r} for k, ss, r in sel_bad]

    # --- acts
    prevout_txid, prevout_n = _txid('act-funding'), 3
    po36 = v.ser_prevout(prevout_txid, prevout_n)
    sighash_a, sighash_b = v.sha256(b'vault-vectors-sighash-a'), v.sha256(b'vault-vectors-sighash-b')
    eqv = v.equivocation_proof(set_a, K['member-2'], _txid('contested'), 1, v.ROLE_UNLOCK, sighash_a,
                               v.ROLE_CANCEL, sighash_b)
    act_cases = [
        ('set-create', v.act_set_create(7, 5, 1, 5, P['admit'], flags=0, rate_limit_bps=1000, rate_window=1008,
                                        liveness_window=4032, bond_min=50 * v.COIN, bond_lock_min=8064, maturity=144),
         []),
        ('set-create-open-max', v.act_set_create(15, 15, 15, 15, P['admit'], flags=v.SET_FLAG_OPEN,
                                                 rate_limit_bps=10000, rate_window=1048576, liveness_window=1,
                                                 bond_min=21000000 * v.COIN, bond_lock_min=0xFFFFFFFF,
                                                 maturity=0xFFFFFFFF), []),
        ('set-join-admit', v.act_set_join(set_a, P['member-0'], 2000, 0), ['member-0', 'admit']),
        ('set-join-members', v.act_set_join(set_a, P['member-3'], 499999999, 2),
         ['member-3', 'member-0', 'member-1']),
        ('set-heartbeat', v.act_set_heartbeat(set_a, P['member-1']), ['member-1']),
        ('set-remove-return', v.act_set_remove(set_a, P['member-4'], 0), ['member-0', 'member-1']),
        ('set-remove-burn', v.act_set_remove(set_a, P['member-4'], 1), ['member-0', 'member-1']),
        ('set-equivocation', eqv, []),
        ('set-winddown', v.act_set_winddown(set_a), ['member-0', 'member-1', 'member-2']),
        ('set-create-admit-key-off-curve-accepted', v.act_set_create(1, 1, 1, 1, off_curve), []),   # A-2
        ('set-join-member-key-off-curve-accepted', v.act_set_join(set_a, off_curve, 2000, 0), []),   # A-2
    ]
    acts = []
    for n, a, signers in act_cases:
        p = v.encode_act(a)
        msg = v.act_msg(p, prevout_txid, prevout_n)
        sigs = [v.sign_recoverable(K[s], msg) for s in signers]
        rec = [v.recover_compact(s, msg) for s in sigs]
        assert rec == [P[s] for s in signers]
        script = v.act_script(p, sigs)
        assert len(script) <= v.ACT_MAX_SCRIPT and v.parse_act_script(script)[0] == p
        fields = v.decode_act(p)
        fields.pop('name')
        e = {'name': n, 'type': a['type'], 'fields': fields, 'payload': _h(p), 'prevout': _h(po36),
             'actMsg': _h(msg), 'signers': signers, 'sigs': [_h(s) for s in sigs], 'recovered': [_h(r) for r in rec],
             'script': _h(script)}
        if a['type'] == v.ACT_SET_EQUIVOCATION:
            e['convicts'] = _h(v.equivocation_key(a))
            assert e['convicts'] == _h(P['member-2'])
        acts.append(e)
    doc['acts'] = acts

    cp = v.encode_act(act_cases[0][1])
    create = act_cases[0][1]

    def bad_create(**kw):
        return v.encode_act(dict(create, **kw), check=False)
    join = act_cases[2][1]
    rem = act_cases[5][1]
    act_bad = [
        ('too-short', b'YV\x01', 'size'),
        ('bad-magic', b'YW' + cp[2:], 'magic'),
        ('version-0', b'YV\x00' + cp[3:], 'version'),
        ('version-2', b'YV\x02' + cp[3:], 'version'),
        ('type-0', b'YV\x01\x00' + cp[4:], 'type'),
        ('type-7', b'YV\x01\x07' + cp[4:], 'type'),
        ('create-truncated', cp[:-1], 'size'),
        ('create-trailing-byte', cp + b'\x00', 'size'),
        ('winddown-trailing-byte', v.encode_act(v.act_set_winddown(set_a)) + b'\x00', 'size'),
        ('seats-0', bad_create(seats=0, unlockThreshold=0, cancelThreshold=0, slashThreshold=0), 'seats'),
        ('seats-16', bad_create(seats=16), 'seats'),
        ('unlock-threshold-0', bad_create(unlockThreshold=0), 'threshold'),
        ('cancel-threshold-gt-seats', bad_create(cancelThreshold=8), 'threshold'),
        ('slash-threshold-gt-seats', bad_create(slashThreshold=8), 'threshold'),
        ('flags-bit1', bad_create(flags=2), 'flags'),
        ('rate-10001', bad_create(rateLimitBps=10001), 'rate'),
        ('rate-window-0', bad_create(rateWindow=0), 'window'),
        ('rate-window-1048577', bad_create(rateWindow=1048577), 'window'),
        ('liveness-window-0', bad_create(livenessWindow=0), 'window'),
        ('liveness-window-1048577', bad_create(livenessWindow=1048577), 'window'),
        ('bond-min-0', bad_create(bondMin=0), 'bondMin'),
        ('bond-min-negative', bad_create(bondMin=-1), 'bondMin'),
        ('bond-min-above-max-money', bad_create(bondMin=v.MAX_MONEY + 1), 'bondMin'),   # D-1
        ('admit-key-04', bad_create(admitKey='04' + create['admitKey'][2:]), 'key'),
        ('join-locktime-500000000', v.encode_act(dict(join, bondLocktime=500000000), check=False), 'locktime'),
        ('remove-burn-2', v.encode_act(dict(rem, burn=2), check=False), 'burn'),
        ('equivocation-role-0', v.encode_act(dict(eqv, roleA=0), check=False), 'role'),
        ('equivocation-role-3', v.encode_act(dict(eqv, roleB=3), check=False), 'role'),
        ('equivocation-sig-header-27', v.encode_act(dict(eqv, sigA='1b' + eqv['sigA'][2:]), check=False), 'sig header'),
    ]
    for n, p, _r in act_bad:
        try:
            v.decode_act(p)
            raise AssertionError('decoded ' + n)
        except v.VaultError:
            pass
    structural = ('size', 'magic', 'version', 'type')
    doc['actsInvalid'] = [{'name': n, 'payload': _h(p), 'reason': r, 'stage': 'decode' if r in structural else 'field'}
                          for n, p, r in act_bad]

    wd = v.encode_act(v.act_set_winddown(set_a))
    wsig = v.sign_recoverable(K['member-0'], v.act_msg(wd, prevout_txid, prevout_n))
    sc_bad = [
        ('pushdata1-for-short-payload', bytes([v.OP_RETURN, v.OP_PUSHDATA1, len(wd)]) + wd, 'non-minimal push'),
        ('sig-64-bytes', v.act_script(wd, [wsig[:64]]), 'signature size'),
        ('opcode-after-payload', v.act_script(wd) + bytes([v.OP_1]), 'non-push'),
        ('payload-undecodable', v.act_script(wd[:-1]), 'body'),
    ]
    for n, s, _r in sc_bad:
        try:
            v.parse_act_script(s)
            raise AssertionError(n)
        except v.VaultError:
            pass
    doc['actScriptsInvalid'] = [{'name': n, 'script': _h(s), 'reason': r} for n, s, r in sc_bad]

    # --- set-signature messages
    msgs = []
    for sid, role, txl, n, sh in [(set_a, 1, 'vault-1', 0, sighash_a), (set_a, 2, 'intent-1', 1, sighash_b),
                                  (set_b, 1, 'vault-2', 0xFFFFFFFF, sighash_a)]:
        po = v.ser_prevout(_txid(txl), n)
        msgs.append({'setId': _h(sid), 'role': role, 'prevout': _h(po), 'sighash': _h(sh),
                     'msg': _h(v.set_sig_msg_raw(sid, role, po, sh))})
    doc['setSigMsgs'] = msgs

    # --- signatures (include both low-S branches)
    sigs, seen = [], set()
    i = 0
    while len(sigs) < 8 or seen != {True, False}:
        lab = LABELS[i % len(LABELS)]
        msg = v.sha256(b'vault-vectors-msg-%d' % i)
        _r, _s, _rec, fl = v.ecdsa_sign_rec(K[lab], msg)
        seen.add(fl)
        if len(sigs) < 8 or fl not in {e['lowSFlipped'] for e in sigs}:
            sig = v.sign_recoverable(K[lab], msg)
            assert v.recover_compact(sig, msg) == P[lab]
            sigs.append({'label': lab, 'secret': _h(K[lab]), 'pubkey': _h(P[lab]), 'msg': _h(msg), 'sig': _h(sig),
                         'lowSFlipped': fl})
        i += 1
    doc['signatures'] = sigs
    base_sig = bytes.fromhex(sigs[0]['sig'])
    base_msg = bytes.fromhex(sigs[0]['msg'])
    r_, s_ = base_sig[1:33], int.from_bytes(base_sig[33:], 'big')
    sig_bad = [
        ('high-s', bytes([31 + ((base_sig[0] - 31) ^ 1)]) + r_ + (v._N - s_).to_bytes(32, 'big'), 'high S'),
        ('header-27-uncompressed', bytes([base_sig[0] - 4]) + base_sig[1:], 'header'),
        ('header-35', bytes([35]) + base_sig[1:], 'header'),
        ('header-30', bytes([30]) + base_sig[1:], 'header'),
        ('r-zero', base_sig[:1] + bytes(32) + base_sig[33:], 'r = 0'),
        ('s-zero', base_sig[:33] + bytes(32), 's = 0'),
        ('r-ge-n', base_sig[:1] + v._N.to_bytes(32, 'big') + base_sig[33:], 'r >= n'),
    ]
    out = []
    for n, s, r in sig_bad:
        assert v.recover_compact(s, base_msg) is None, n
        ns = v.recover_compact(s, base_msg, strict=False)
        out.append({'name': n, 'msg': _h(base_msg), 'sig': _h(s), 'reason': r,
                    'nonStrictRecovers': None if ns is None else _h(ns)})
    doc['signaturesInvalid'] = out

    # --- spends: full transactions, ZIP-243 sighash under the vault branch id, set signatures
    spends = []
    vp_u = vp(delay=10)
    v_out = (_txid('vault-utxo'), 0)
    fee_in = [(_txid('fee-utxo'), 1, v.SEQUENCE_FINAL)]
    value = 25 * v.COIN
    signers = ['member-0', 'member-1']
    utx = v.build_unlock_tx(v_out, vp_u, value, [(recipient, 20 * v.COIN)], relock_value=5 * v.COIN,
                            fee_vin=fee_in, change=(v.COIN, recipient), member_secrets=[K[s] for s in signers])
    v_spk = v.vault_script(vp_u)
    spends.append(_spend('unlock', utx, 0, v_spk, value, set_a, v.ROLE_UNLOCK, signers, K, P))
    i_spk = v.intent_script(v.intent_for(vp_u, recipient))
    ctx = v.build_cancel_tx((_txid('intent-utxo'), 0), v.intent_for(vp_u, recipient), 20 * v.COIN, vp_u,
                            fee_vin=fee_in, member_secrets=[K['member-2']])
    spends.append(_spend('cancel', ctx, 0, i_spk, 20 * v.COIN, set_b, v.ROLE_CANCEL, ['member-2'], K, P))
    doc['spends'] = spends

    # --- owner spends: the SLH-DSA owner signs a V's OWNER branch (selector 2), verified by the C++ interpreter
    owner_spends = []
    vp_o = vp(delay=10, owner_height=1000)
    o_spk = v.vault_script(vp_o)
    otx = v.build_owner_spend_tx((_txid('owner-vault-utxo'), 0), o_spk, value, pq_sk, recipient, v.SEL_OWNER,
                                 lock_time=1000)
    sh = v.template_sighash(otx, 0, o_spk, value)
    assert v.parse_selector(otx.vin[0].scriptSig, 'V')[0] == v.SEL_OWNER
    owner_spends.append(_owner_spend('owner-selector-2', 'V', otx, o_spk, value, v.SEL_OWNER, 'script'))
    # OWNER-RELEASED (selector 3) on V and on I: OP_CHECKSETDORMANT reads the set state, so the C++ replay
    # checks the template, the sighash and the signature itself (pq::Verify), not the whole script.
    otx3 = v.build_owner_spend_tx((_txid('owner-released-vault-utxo'), 0), o_spk, value, pq_sk, recipient,
                                  v.SEL_OWNER_RELEASED)
    owner_spends.append(_owner_spend('owner-released-selector-3-vault', 'V', otx3, o_spk, value, v.SEL_OWNER_RELEASED,
                                     'signature'))
    i_o = v.intent_script(v.intent_for(vp_o, recipient))
    itx3 = v.build_owner_spend_tx((_txid('owner-released-intent-utxo'), 1), i_o, 20 * v.COIN, pq_sk, recipient,
                                  v.SEL_OWNER_RELEASED)
    owner_spends.append(_owner_spend('owner-released-selector-3-intent', 'I', itx3, i_o, 20 * v.COIN,
                                     v.SEL_OWNER_RELEASED, 'signature'))
    # The Falcon owner (selector 2), signed by the node's library (FALCON_SIG above); valid only with
    # SCRIPT_VERIFY_PQ_FALCON.
    vp_f = vp(delay=10, owner_height=1000, owner=FOWNER)
    f_spk = v.vault_script(vp_f)
    ftx = v.make_tx([(_txid('owner-falcon-vault-utxo'), 0, v.SEQUENCE_FINAL - 1)], [(value - v.VAULT_FEE, recipient)], 1000)
    fsh = v.template_sighash(ftx, 0, f_spk, value)
    assert v.pq.falcon_verify(FALCON_PK, fsh, FALCON_SIG), \
        'FALCON_SIG does not verify over %s: refresh it (vault_vectors_tests prints the signature)' % fsh.hex()
    ftx.vin[0].scriptSig = v.vault_owner_scriptsig(
        v.pq.pq_scriptsig_pushes(FALCON_PK, FALCON_SIG + bytes([v.SIGHASH_ALL])))
    fe = _owner_spend('owner-falcon-selector-2', 'V', ftx, f_spk, value, v.SEL_OWNER, 'script')
    fe['falconEntropy'] = _h(FALCON_ENTROPY)
    owner_spends.append(fe)
    doc['ownerSpends'] = owner_spends
    return doc


def _owner_spend(name, kind, tx, spk, amount, selector, verify):
    sh = v.template_sighash(tx, 0, spk, amount)
    assert v.parse_selector(tx.vin[0].scriptSig, kind)[0] == selector
    return {'name': name, 'kind': kind, 'tx': v.tx_hex(tx), 'nIn': 0, 'scriptCode': _h(spk), 'amount': amount,
            'branchId': v.VAULT_BRANCH_ID, 'sighash': _h(sh), 'selector': selector, 'verify': verify,
            'scriptSig': _h(tx.vin[0].scriptSig)}


def _spend(name, tx, n_in, spk, amount, set_id, role, signers, K, P):
    sh = v.template_sighash(tx, n_in, spk, amount)
    txid, n = v.prevout_of(tx, n_in)
    msg = v.set_sig_msg(set_id, role, txid, n, sh)
    sigs = [v.sign_recoverable(K[s], msg) for s in signers]
    sel = v.parse_selector(tx.vin[n_in].scriptSig, 'V' if role == v.ROLE_UNLOCK else 'I')
    assert sel[1] == sigs
    assert [v.recover_compact(s, msg) for s in sigs] == [P[s] for s in signers]
    return {'name': name, 'tx': v.tx_hex(tx), 'nIn': n_in, 'scriptCode': _h(spk), 'amount': amount,
            'branchId': v.VAULT_BRANCH_ID, 'sighash': _h(sh), 'setId': _h(set_id), 'role': role,
            'setSigMsg': _h(msg), 'signers': signers, 'sigs': [_h(s) for s in sigs],
            'scriptSig': _h(tx.vin[n_in].scriptSig)}


def dumps(doc):
    return json.dumps(doc, indent=1, sort_keys=False) + '\n'


def main():
    text = dumps(build())
    if '--check' in sys.argv[1:]:
        with open(OUT) as f:
            if f.read() != text:
                print('vault_vectors.json is stale; rerun without --check')
                return 1
        print('vault_vectors.json up to date')
        return 0
    with open(OUT, 'w') as f:
        f.write(text)
    print('wrote', OUT)
    return 0


if __name__ == '__main__':
    sys.exit(main())
