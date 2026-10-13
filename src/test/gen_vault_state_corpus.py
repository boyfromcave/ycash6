#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Seed corpus for the VaultState fuzz target (the vault primitive's state rules, upgrade plan §15.4-§15.6).

    src/fuzzing/VaultState/input/*.bin   base header ‖ items   (grammar: src/test/vault_state_fuzz_harness.h)

and the C++ table embedded in src/test/vault_fuzz_tests.cpp between the BEGIN/END GENERATED
VAULT STATE CORPUS markers, so `make check` replays every seed (and every file under
src/fuzzing/VaultState/crashes/) without a fuzzing build.

    gen_vault_state_corpus.py            print the C++ table
    gen_vault_state_corpus.py --write    write input/*.bin and update the C++ file (fuzz-*.bin kept, never checked)
    gen_vault_state_corpus.py --check    exit 1 unless input/ and the C++ file match (CI)

Run from anywhere; no third-party modules.
"""
import argparse
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT = os.path.join(os.path.dirname(HERE), "fuzzing", "VaultState", "input")
CRASHES = os.path.join(os.path.dirname(HERE), "fuzzing", "VaultState", "crashes")
CPP = os.path.join(HERE, "vault_fuzz_tests.cpp")
BEGIN = "// BEGIN GENERATED VAULT STATE CORPUS (src/test/gen_vault_state_corpus.py; do not edit by hand)"
END = "// END GENERATED VAULT STATE CORPUS"
FOUND_PREFIX = "fuzz-"

COIN = 100000000
NEXT, CREATE, JOIN, HEARTBEAT, WINDDOWN, REMOVE, LOCK, SPEND, BOND, EQUIV = range(10)
# SPEND output mask bits (PAY_RECIPIENT spending a V: another V of the set)
INTENT, RELOCK, PLAIN, PAY_RECIPIENT, PAY_BACK, SECOND_TEMPLATE, FEE = 1, 2, 4, 8, 16, 32, 64


def header(seats=5, ut=2, ct=1, st=2, bps=0, window=49, maturity=2, delay=5):
    """The base set (seats 2 + b % 6, thresholds 1 + b % seats) and the base V's delay (1 + b)."""
    return bytes([seats - 2, ut - 1, ct - 1, st - 1, bps // 40, window, maturity, delay - 1])


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def nxt(d=0):
    return bytes([NEXT, d])


def create(seats, ut, ct, st, bps=0, rw=10, lw=50, open_=True, stray_sig=False, maturity=2):
    return bytes([CREATE, seats, ut, ct, st, bps // 50, rw, lw, (1 if open_ else 0) | (2 if stray_sig else 0) | (maturity << 4)])


def join(set_=0, key=2, cosigners=0, bond_zat=1000, ahead=10, admit=False, bad_vout=False, wrong_prevout=False):
    return bytes([JOIN, set_, key, cosigners]) + u16(bond_zat // 10) + bytes([ahead, (1 if admit else 0) | (2 if bad_vout else 0) | (4 if wrong_prevout else 0)])


def heartbeat(set_=0, key=0, signer=None):
    return bytes([HEARTBEAT, set_, key, key if signer is None else signer])


def winddown(set_=0, signers=0b11):
    return bytes([WINDDOWN, set_, signers])


def remove(set_=0, target=1, burn=0, signers=0b11):
    return bytes([REMOVE, set_, target, burn, signers])


def lock(tag=0, set_=0, delay=5, app_height=0, value=2 * COIN, second=False, malformed=False, other_cancel_set=None):
    flags = tag | (4 if second else 0) | (8 if malformed else 0)
    if other_cancel_set is not None:
        flags |= 16 | (other_cancel_set << 5)
    return bytes([LOCK, flags, set_]) + u16(delay) + bytes([app_height]) + u32(value)


def spend(coin=0, selector=1, mask=INTENT | RELOCK, value=COIN, recipient=0):
    return bytes([SPEND, coin, selector, mask | (0x80 if recipient else 0)]) + u32(value)


def bond(coin=0, fee=False):
    return bytes([BOND, coin, 1 if fee else 0])


def equiv(set_=0, key=0, roles=0, same=False, other_key=False):
    return bytes([EQUIV, set_, key, roles, (1 if same else 0) | (2 if other_key else 0)])


def corpus():
    H = header()
    s = []
    s.append(("base_only", H))
    s.append(("empty", b""))
    s.append(("one_byte", b"\x07"))
    # set acts
    s.append(("join_heartbeat", H + join(key=2) + nxt(3) + heartbeat(key=2)))
    s.append(("heartbeat_immature", H + join(key=2) + heartbeat(key=2)))
    s.append(("heartbeat_other_signer", H + heartbeat(key=0, signer=1)))
    s.append(("join_wrong_prevout", H + join(key=3, wrong_prevout=True)))
    s.append(("join_bad_vout", H + join(key=3, bad_vout=True)))
    s.append(("join_bond_below_min", H + join(key=3, bond_zat=10)))
    s.append(("join_twice", H + join(key=3) + join(key=3)))
    s.append(("join_seats_full", header(seats=2) + join(key=3)))
    s.append(("create_then_join", H + create(3, 2, 1, 2, maturity=1) + nxt(0) + join(set_=1, key=4)))
    s.append(("create_invalid", H + create(0, 1, 1, 1) + create(3, 4, 1, 1) + create(3, 1, 1, 1, rw=0)))
    s.append(("create_stray_sig", H + create(3, 2, 1, 2, stray_sig=True)))
    s.append(("create_closed_join", H + create(3, 2, 1, 2, open_=False) + nxt(0) + join(set_=1, key=4) + join(set_=1, key=5, admit=True)))
    s.append(("winddown", H + winddown() + nxt(0) + join(key=3) + winddown()))
    s.append(("winddown_short", H + winddown(signers=0b1)))
    s.append(("remove_burn", H + remove(target=1, burn=1, signers=0b11)))
    s.append(("remove_self", H + remove(target=1, burn=0, signers=0b10)))
    s.append(("remove_burn_2", H + remove(target=1, burn=2)))
    s.append(("equivocation", H + equiv(key=0) + equiv(key=0)))
    s.append(("equivocation_same", H + equiv(key=1, same=True)))
    s.append(("equivocation_other_key", H + equiv(key=1, other_key=True)))
    s.append(("equivocation_nonmember", H + equiv(key=5)))
    # bonds
    s.append(("bond_locked", H + bond(0)))
    s.append(("bond_exit", H + remove(target=1, burn=0, signers=0b10) + nxt(3) + bond(1, fee=True)))
    s.append(("bond_frozen", H + equiv(key=0) + nxt(9) + bond(0)))
    # V and I
    s.append(("lock", H + lock()))
    s.append(("lock_two", H + lock(second=True)))
    s.append(("lock_yed", H + lock(tag=1)))
    s.append(("lock_other_tag", H + lock(tag=3)))
    s.append(("lock_malformed", H + lock(malformed=True, value=8)))
    s.append(("lock_byte_flipped", H + lock(malformed=True, value=7)))
    s.append(("lock_cancel_set", H + create(3, 2, 1, 2) + nxt(0) + lock(other_cancel_set=1)))
    s.append(("lock_new_set_same_block", H + create(3, 2, 1, 2) + lock(set_=1)))
    s.append(("lock_delay_zero", H + lock(delay=0)))
    s.append(("unlock_release", H + spend(0, 1, INTENT | RELOCK, 3 * COIN) + nxt(5) + spend(0, 1, PAY_RECIPIENT, 0)))
    s.append(("unlock_cancel", H + spend(0, 1, INTENT | RELOCK, 3 * COIN) + spend(0, 2, PAY_BACK, 0)))
    s.append(("unlock_cancel_late", H + spend(0, 1, INTENT | RELOCK, 3 * COIN) + nxt(9) + spend(0, 2, PAY_BACK, 0)))
    s.append(("unlock_whole", H + spend(0, 1, INTENT, 10 * COIN) + nxt(2) + spend(0, 3, PLAIN, 0)))
    # after an unlock the template list is [intent, relocked V]: coin 1 is the V
    s.append(("unlock_short", H + spend(0, 1, INTENT | RELOCK, 3 * COIN) + spend(1, 1, INTENT, COIN)))
    s.append(("unlock_value", H + spend(0, 1, INTENT, COIN)))
    s.append(("unlock_other_v", H + spend(0, 1, INTENT | RELOCK | PAY_RECIPIENT, COIN)))
    s.append(("owner_spend_other_v", H + spend(0, 2, PAY_RECIPIENT, 4 * COIN)))
    s.append(("unlock_plain_out", H + spend(0, 1, INTENT | PLAIN, 10 * COIN)))
    s.append(("unlock_two_templates", H + lock() + spend(0, 1, INTENT | RELOCK | SECOND_TEMPLATE, COIN)))
    s.append(("unlock_fee_input", H + spend(0, 1, INTENT | RELOCK | FEE, COIN)))
    s.append(("unlock_over_value", H + spend(0, 1, INTENT | RELOCK, 0xFFFFFFFF)))   # the relock clamps to 0
    s.append(("rate_limit", header(bps=1000) + spend(0, 1, INTENT | RELOCK, 3 * COIN) + spend(0, 1, INTENT | RELOCK, COIN // 2)))
    s.append(("rate_limit_epoch", header(bps=1000, window=4) + spend(0, 1, INTENT | RELOCK, COIN // 2) + nxt(9)
                                  + spend(1, 1, INTENT | RELOCK, COIN // 2)))
    s.append(("owner_spend", H + spend(0, 2, PLAIN, 0)))
    s.append(("released_spend", H + spend(0, 3, PLAIN | FEE, 0)))
    s.append(("selector_0_5", H + spend(0, 0, PLAIN, 0) + spend(0, 5, PLAIN, 0)))
    s.append(("app_without_height", H + spend(0, 4, INTENT | RELOCK, COIN)))
    s.append(("app_branch", H + lock(app_height=9) + nxt(0) + spend(1, 4, INTENT | RELOCK, COIN)))
    s.append(("intent_without_unlock", H + spend(0, 2, INTENT, COIN)))
    s.append(("intent_selector_4", H + spend(0, 1, INTENT | RELOCK, 3 * COIN) + spend(0, 4, PAY_RECIPIENT, 0)))
    s.append(("intent_released", H + spend(0, 1, INTENT | RELOCK, 3 * COIN) + nxt(1) + spend(0, 3, PLAIN, 0)))
    s.append(("release_unpaid", H + spend(0, 1, INTENT | RELOCK, 3 * COIN) + nxt(5) + spend(0, 1, PLAIN, 0)))
    s.append(("long_walk", H + join(key=2) + spend(0, 1, INTENT | RELOCK, 2 * COIN) + nxt(4) + heartbeat(key=2)
                           + spend(0, 1, PAY_RECIPIENT, 0) + lock(value=COIN) + nxt(1) + remove(target=2, signers=0b11)
                           + spend(0, 1, INTENT | RELOCK, COIN // 4) + nxt(20) + winddown() + nxt(60) + spend(0, 3, PLAIN, 0)))
    return s


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
    return "\n".join([BEGIN, cpp_table("VAULT_STATE_CORPUS", seeds), cpp_table("VAULT_STATE_CRASHES", crashes()), END]) + "\n"


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
    print("VaultState: %d seeds" % len(want))


def check_all():
    ok = True
    want = {n + ".bin": d for n, d in corpus()}
    have = {n for n in os.listdir(INPUT) if n.endswith(".bin") and not n.startswith(FOUND_PREFIX)} if os.path.isdir(INPUT) else set()
    for name in sorted(set(want) | have):
        p = os.path.join(INPUT, name)
        if name not in want:
            print("VaultState: unexpected file %s" % name)
            ok = False
        elif not os.path.exists(p):
            print("VaultState: missing %s" % name)
            ok = False
        else:
            with open(p, "rb") as f:
                if f.read() != want[name]:
                    print("VaultState: %s differs" % name)
                    ok = False
    with open(CPP) as f:
        text = f.read()
    if splice(text, cpp_block()) != text:
        print("%s: embedded vault state corpus table is stale (run --write)" % CPP)
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
            print("vault state corpus ok")
            return 0
        return 1
    sys.stdout.write(cpp_block())
    return 0


if __name__ == "__main__":
    sys.exit(main())
