#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Seed corpus for the PQScript fuzz target (OP_CHECKPQSIG, quantum plan §4.2).

    src/fuzzing/PQScript/input/*.bin   flags ‖ scheme ‖ items   (grammar: src/test/pq_fuzz_harness.h)

and the C++ table embedded in src/test/vault_fuzz_tests.cpp between the BEGIN/END GENERATED
PQ CORPUS markers, so `make check` replays every seed (and every file under
src/fuzzing/PQScript/crashes/) without a fuzzing build.

    gen_pq_corpus.py            print the C++ table
    gen_pq_corpus.py --write    write input/*.bin and update the C++ file (fuzz-*.bin kept, never checked)
    gen_pq_corpus.py --check    exit 1 unless input/ and the C++ file match (CI)

Run from anywhere; no third-party modules.
"""
import argparse
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INPUT = os.path.join(os.path.dirname(HERE), "fuzzing", "PQScript", "input")
CRASHES = os.path.join(os.path.dirname(HERE), "fuzzing", "PQScript", "crashes")
CPP = os.path.join(HERE, "vault_fuzz_tests.cpp")
BEGIN = "// BEGIN GENERATED PQ CORPUS (src/test/gen_pq_corpus.py; do not edit by hand)"
END = "// END GENERATED PQ CORPUS"
FOUND_PREFIX = "fuzz-"

STRICTENC, FALCON, VAULT, HASH_RIGHT, ANSWER, TWICE = 0x01, 0x02, 0x04, 0x08, 0x40, 0x80
KH31, KH33, KH0 = 0x10, 0x20, 0x30
SLH, FN = 1, 2
PK = {SLH: 32, FN: 897}
SIG = {SLH: 7856 + 1, FN: 666 + 1}   # with the hashtype byte


def elem(n, fill=0):
    return struct.pack("<H", n) + bytes([fill])


def num(v):
    return struct.pack("<H", 0x8000 | v) + b"\x00"


def chunks(n, fill, last_fill=None):
    """Canonical chunks of an n-byte field; the last chunk's fill sets the hashtype byte."""
    out, k = [], 0
    while n > 0:
        c = min(520, n)
        out.append(elem(c, fill + k))
        n -= c
        k += 1
    return out


def seq(n, fill):
    c = chunks(n, fill)
    return b"".join(c) + num(len(c))


def seed(flags, scheme, items):
    return bytes([flags, scheme]) + b"".join(items)


def good(scheme, flags):
    return seed(flags | VAULT | HASH_RIGHT, scheme, [seq(SIG[scheme], 0x22), seq(PK[scheme], 0x11)])


def corpus():
    s = []
    s.append(("slh_good_true", good(SLH, ANSWER)))
    s.append(("slh_good_false", good(SLH, 0)))
    s.append(("slh_good_strict", good(SLH, STRICTENC | ANSWER)))
    s.append(("falcon_good", good(FN, FALCON | ANSWER)))
    s.append(("falcon_without_flag", good(FN, ANSWER)))
    s.append(("slh_no_vault", seed(HASH_RIGHT | ANSWER, SLH, [seq(SIG[SLH], 0x22), seq(PK[SLH], 0x11)])))
    s.append(("slh_wrong_hash", seed(VAULT | ANSWER, SLH, [seq(SIG[SLH], 0x22), seq(PK[SLH], 0x11)])))
    s.append(("slh_kh31", good(SLH, KH31 | ANSWER)))
    s.append(("slh_kh33", good(SLH, KH33)))
    s.append(("slh_kh0", good(SLH, KH0)))
    for name, b in (("scheme_0", 0), ("scheme_3", 3), ("scheme_ff_empty", 0xff), ("scheme_81", 0x81)):
        s.append((name, seed(VAULT | HASH_RIGHT, b, [seq(SIG[SLH], 0x22), seq(PK[SLH], 0x11)])))
    # p and s out of range or not minimal
    s.append(("slh_p0", seed(VAULT | HASH_RIGHT, SLH, [seq(SIG[SLH], 0x22), elem(32, 0x11), num(0)])))
    s.append(("slh_p2", seed(VAULT | HASH_RIGHT, SLH, [seq(SIG[SLH], 0x22), elem(16), elem(16), num(2)])))
    s.append(("slh_p_nonminimal", seed(VAULT | HASH_RIGHT, SLH, [seq(SIG[SLH], 0x22), elem(32, 0x11), elem(2, 0x01)])))
    s.append(("slh_s17", seed(VAULT | HASH_RIGHT, SLH, chunks(SIG[SLH] - 1, 0x22) + [elem(1, 1), num(17), seq(PK[SLH], 0x11)])))
    s.append(("slh_s15_short", seed(VAULT | HASH_RIGHT, SLH, chunks(7800, 0x22) + [num(15), seq(PK[SLH], 0x11)])))
    s.append(("falcon_short_nonlast", seed(VAULT | FALCON | HASH_RIGHT | ANSWER, FN,
                                           [seq(SIG[FN], 0x22), elem(519), elem(378), num(2)])))
    s.append(("falcon_oversize_last", seed(VAULT | FALCON | HASH_RIGHT, FN,
                                           [seq(SIG[FN], 0x22), elem(520), elem(600), num(2)])))
    s.append(("falcon_single_whole_key", seed(VAULT | FALCON | HASH_RIGHT, FN,
                                              [seq(SIG[FN], 0x22), elem(897, 0x11), num(1)])))
    s.append(("falcon_sig_long", seed(VAULT | FALCON | HASH_RIGHT, FN, [elem(520), elem(148), num(2), seq(PK[FN], 0x11)])))
    s.append(("falcon_missing_chunks", seed(VAULT | FALCON | HASH_RIGHT, FN, [elem(147), num(2), seq(PK[FN], 0x11)])))
    # hashtypes: fill so the last byte (index 56 of the last 57-byte chunk) is 0x00 / 0x84 / 0x83
    for name, ht in (("slh_ht_00", 0x00), ("slh_ht_84", 0x84), ("slh_ht_83", 0x83)):
        items = chunks(SIG[SLH] - 57, 0x22) + [elem(57, (ht - 56) & 0xff), num(16), seq(PK[SLH], 0x11)]
        s.append((name, seed(VAULT | HASH_RIGHT | STRICTENC | ANSWER, SLH, items)))
    # two faults, the earlier in the frozen order (QUANTUM-SPEC A-7) wins: the signature's chunking
    # before the key's size
    s.append(("falcon_order_sigchunk_pksize", seed(VAULT | FALCON | HASH_RIGHT, FN,
                                                   [elem(519), elem(148), num(2), elem(520), elem(378), num(2)])))
    s.append(("extra_below", seed(VAULT | HASH_RIGHT | ANSWER, SLH, [elem(3, 7), seq(SIG[SLH], 0x22), seq(PK[SLH], 0x11)])))
    # R-B1: a second executed OP_CHECKPQSIG is PQ_COUNT; a first that fails reports its own error
    s.append(("slh_twice", good(SLH, ANSWER | TWICE)))
    s.append(("falcon_twice_false", good(FN, FALCON | TWICE)))
    s.append(("twice_no_vault", seed(TWICE, SLH, [])))
    s.append(("twice_first_fails", seed(VAULT | TWICE, 3, [])))
    s.append(("empty_stack", bytes([VAULT, SLH])))
    s.append(("one_byte", bytes([VAULT])))
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
    return "\n".join([BEGIN, cpp_table("PQ_CORPUS", seeds), cpp_table("PQ_CRASHES", crashes()), END]) + "\n"


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
    print("PQScript: %d seeds" % len(want))


def check_all():
    ok = True
    want = {n + ".bin": d for n, d in corpus()}
    have = {n for n in os.listdir(INPUT) if n.endswith(".bin") and not n.startswith(FOUND_PREFIX)} if os.path.isdir(INPUT) else set()
    for name in sorted(set(want) | have):
        p = os.path.join(INPUT, name)
        if name not in want:
            print("PQScript: unexpected file %s" % name)
            ok = False
        elif not os.path.exists(p):
            print("PQScript: missing %s" % name)
            ok = False
        else:
            with open(p, "rb") as f:
                if f.read() != want[name]:
                    print("PQScript: %s differs" % name)
                    ok = False
    with open(CPP) as f:
        text = f.read()
    if splice(text, cpp_block()) != text:
        print("%s: embedded PQ corpus table is stale (run --write)" % CPP)
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
            print("pq corpus ok")
            return 0
        return 1
    sys.stdout.write(cpp_block())
    return 0


if __name__ == "__main__":
    sys.exit(main())
