#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Seed corpus for the Vault fuzz target (upgrade plan §15.3, §15.5).

    src/fuzzing/Vault/input/*.bin   u16 LE n ‖ spk (n bytes) ‖ scriptSig   (grammar: src/test/vault_fuzz_harness.h)

and the C++ table embedded in src/test/vault_fuzz_tests.cpp between the BEGIN/END GENERATED
CORPUS markers, so `make check` replays every seed (and every file under
src/fuzzing/Vault/crashes/) without a fuzzing build.

The seeds are built with qa/rpc-tests/test_framework/vault.py, the pure-Python primitive the
golden vector src/test/data/vault_vectors.json cross-checks against the C++, so a seed's shape
is the specification's, not this file's.

    gen_vault_corpus.py            print the C++ table
    gen_vault_corpus.py --write    write input/*.bin and update the C++ file (fuzz-*.bin, the
                                   weekly job's merged finds, are kept and never checked)
    gen_vault_corpus.py --check    exit 1 unless input/ and the C++ file match (CI)

Run from anywhere; no third-party modules.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "qa", "rpc-tests"))
from test_framework import vault as v   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT = os.path.join(os.path.dirname(HERE), "fuzzing", "Vault", "input")
CRASHES = os.path.join(os.path.dirname(HERE), "fuzzing", "Vault", "crashes")
CPP = os.path.join(HERE, "vault_fuzz_tests.cpp")
BEGIN = "// BEGIN GENERATED CORPUS (src/test/gen_vault_corpus.py; do not edit by hand)"
END = "// END GENERATED CORPUS"
FOUND_PREFIX = "fuzz-"

SECRETS = [v.fixed_secret("vault-fuzz-%d" % i) for i in range(3)]
KEYS = [v.pubkey_of(s) for s in SECRETS]
# the V / I owner: a post-quantum key id, scheme 1 (SLH-DSA) || 32-byte key hash (quantum plan §4.3)
OWNER = bytes([1]) + v.sha256(b"vault-fuzz-owner")
SET_A = bytes(range(32))
SET_B = bytes(range(32, 64))
PREVOUT_TXID = "11" * 32
SIGHASH = bytes([0x5A]) * 32


def seed(spk, script_sig=b""):
    return struct.pack("<H", len(spk)) + bytes(spk) + bytes(script_sig)


def vp(tag=b"TEST", delay=10, owner_height=1000, app_height=0, set_id=SET_A, cancel=SET_A, key=OWNER):
    return v.VaultParams(tag, set_id, cancel, delay, owner_height, app_height, key)


def set_sig(i, role=v.ROLE_UNLOCK):
    return v.sign_recoverable(SECRETS[i], v.set_sig_msg(SET_A, role, PREVOUT_TXID, 0, SIGHASH))


def act(a, signers=()):
    p = v.encode_act(a)
    return p, v.act_script(p, [v.sign_recoverable(SECRETS[i], v.act_msg(p, PREVOUT_TXID, 0)) for i in signers])


def corpus():
    V = v.vault_script(vp())
    V_yed = v.vault_script(vp(tag=b"YED\x00", delay=10, owner_height=500, app_height=524))
    I = v.intent_script(v.intent_for(vp(), v.p2pkh_script_of_pubkey(KEYS[1])))
    I_yed = v.intent_script(v.intent_for(vp(tag=b"YED\x00", owner_height=500, app_height=524), v.p2pkh_script_of_pubkey(KEYS[2])))
    bond = v.bond_script(KEYS[1], 5000)
    create_p, create = act(v.act_set_create(3, 2, 1, 2, KEYS[0], rate_limit_bps=500))
    _, join = act(v.act_set_join(SET_A, KEYS[1], 5000), signers=(1, 0))
    hb_p, hb = act(v.act_set_heartbeat(SET_A, KEYS[1]), signers=(1,))
    _, remove = act(v.act_set_remove(SET_A, KEYS[2], burn=1), signers=(0, 1))
    _, winddown = act(v.act_set_winddown(SET_A), signers=(0, 1))
    po = v.ser_prevout(PREVOUT_TXID, 0)
    _, equiv = act(v.act_set_equivocation(SET_A, po, 1, SIGHASH, set_sig(0), 1, bytes([0xA5]) * 32,
                                          v.sign_recoverable(SECRETS[0], v.set_sig_msg(SET_A, 1, PREVOUT_TXID, 0, bytes([0xA5]) * 32))))
    sigs2 = [set_sig(0), set_sig(1)]
    # an owner scriptSig's shape: <sig> <1> <pk:32> <1> (one chunk each; the interpreter checks the sizes)
    fake_sig = [bytes([0x30]) + bytes(70) + bytes([0x01]), bytes([1]), bytes(32), bytes([1])]
    return [
        # templates (V, I) and their range edges
        ("vault", seed(V)),
        ("vault_yed", seed(V_yed)),
        ("vault_bridge", seed(v.vault_script(vp(tag=b"WYEC", owner_height=499999999)))),
        ("vault_delay_16", seed(v.vault_script(vp(delay=16)))),
        ("vault_delay_max", seed(v.vault_script(vp(delay=65535)))),
        ("vault_two_sets", seed(v.vault_script(vp(cancel=SET_B, app_height=2000)))),
        ("vault_nonminimal_delay", seed(v.nonminimal_delay_vault(vp()))),
        ("vault_delay_zero", seed(v.vault_script_unchecked(vp(delay=0)))),
        ("vault_unregistered_scheme", seed(v.vault_script_unchecked(vp(key=bytes([0x03]) + bytes(32))))),
        ("vault_trailing", seed(V + bytes([v.OP_DROP]))),
        ("vault_truncated", seed(V[:-1])),
        ("intent", seed(I)),
        ("intent_yed", seed(I_yed)),
        ("intent_delay_zero", seed(v.intent_script_unchecked(v.intent_for(vp(), b"\x51")).replace(b"\x5a\xb2", b"\x00\xb2"))),
        ("bond", seed(bond)),
        ("bond_max_locktime", seed(v.bond_script(KEYS[2], 499999999))),
        ("bond_p2sh", seed(v.bond_spk(KEYS[1], 5000))),
        # acts and bare payloads
        ("act_create", seed(create)),
        ("act_join", seed(join)),
        ("act_heartbeat", seed(hb)),
        ("act_remove_burn", seed(remove)),
        ("act_equivocation", seed(equiv)),
        ("act_winddown", seed(winddown)),
        ("act_bad_version", seed(v.act_script(b"YV\x02" + create_p[3:]))),
        ("act_unknown_type", seed(v.act_script(b"YV\x01\x07" + bytes(32)))),
        ("act_short_sig", seed(hb + v.push(bytes(64)))),
        ("act_nonminimal_push", seed(bytes([v.OP_RETURN, v.OP_PUSHDATA2]) + struct.pack("<H", len(hb_p)) + hb_p)),
        ("payload_create", seed(create_p)),
        ("payload_heartbeat", seed(hb_p)),
        # template spends (spk ‖ scriptSig)
        ("spend_vault_unlock", seed(V, v.vault_unlock_scriptsig(sigs2))),
        ("spend_vault_owner", seed(V, v.vault_owner_scriptsig(fake_sig))),
        ("spend_vault_owner_released", seed(V, v.vault_owner_released_scriptsig(fake_sig))),
        ("spend_vault_app", seed(V_yed, v.vault_app_scriptsig())),
        ("spend_intent_release", seed(I, v.intent_release_scriptsig())),
        ("spend_intent_cancel", seed(I_yed, v.intent_cancel_scriptsig([set_sig(0, v.ROLE_CANCEL)]))),
        ("spend_intent_owner_released", seed(I, v.intent_owner_released_scriptsig(fake_sig))),
        ("spend_intent_selector_4", seed(I, v.vault_app_scriptsig())),
        ("spend_selector_5", seed(V, bytes([v.OP_1 + 4]))),
        ("spend_not_push_only", seed(V, bytes([v.OP_DROP, v.OP_1]))),
        ("spend_selector_as_data", seed(V, v.push(b"\x01"))),
        ("spend_non_template", seed(v.p2pkh_script_of_pubkey(KEYS[0]), v.vault_app_scriptsig())),
        ("empty", b""),
        ("one_byte", b"\x6a"),
        ("length_past_end", struct.pack("<H", 0xFFFF) + V),
    ]


def crashes():
    if not os.path.isdir(CRASHES):
        return []
    out = []
    for name in sorted(os.listdir(CRASHES)):
        p = os.path.join(CRASHES, name)
        if name.startswith(".") or not os.path.isfile(p):
            continue
        with open(p, "rb") as f:
            out.append((name, f.read()))
    return out


def cpp_table(var, entries):
    lines = ["static const std::vector<std::pair<std::string, std::string>> %s = {" % var]
    for name, data in entries:
        lines.append('    {"%s", "%s"},' % (name, data.hex()))
    lines.append("};")
    return "\n".join(lines)


def cpp_block():
    seeds = corpus()
    names = [n for n, _ in seeds]
    assert len(names) == len(set(names)), "duplicate seed name"
    return "\n".join([BEGIN, cpp_table("VAULT_CORPUS", seeds), cpp_table("VAULT_CRASHES", crashes()), END]) + "\n"


def splice(text, block):
    a = text.find(BEGIN)
    b = text.find(END)
    if a < 0 or b < 0:
        raise SystemExit("markers not found in %s" % CPP)
    return text[:a] + block + text[b + len(END) + 1:]


def write_all():
    os.makedirs(INPUT, exist_ok=True)
    want = {n + ".bin": d for n, d in corpus()}
    for name in os.listdir(INPUT):
        if name.endswith(".bin") and name not in want and not name.startswith(FOUND_PREFIX):
            os.remove(os.path.join(INPUT, name))
    for name, data in want.items():
        with open(os.path.join(INPUT, name), "wb") as f:
            f.write(data)
    with open(CPP) as f:
        text = f.read()
    with open(CPP, "w") as f:
        f.write(splice(text, cpp_block()))
    print("Vault: %d seeds" % len(want))


def check_all():
    ok = True
    want = {n + ".bin": d for n, d in corpus()}
    have = {n for n in os.listdir(INPUT) if n.endswith(".bin") and not n.startswith(FOUND_PREFIX)} if os.path.isdir(INPUT) else set()
    for name in sorted(set(want) | have):
        p = os.path.join(INPUT, name)
        if name not in want:
            print("Vault: unexpected file %s" % name)
            ok = False
        elif not os.path.exists(p):
            print("Vault: missing %s" % name)
            ok = False
        else:
            with open(p, "rb") as f:
                if f.read() != want[name]:
                    print("Vault: %s differs" % name)
                    ok = False
    with open(CPP) as f:
        text = f.read()
    if splice(text, cpp_block()) != text:
        print("%s: embedded corpus table is stale (run --write)" % CPP)
        ok = False
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.write:
        write_all()
        return 0
    if args.check:
        if check_all():
            print("vault corpus ok")
            return 0
        return 1
    sys.stdout.write(cpp_block())
    return 0


if __name__ == "__main__":
    sys.exit(main())
