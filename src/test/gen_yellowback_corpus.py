#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""Seed corpora for the Yellowback fuzz targets (plan §7 "Fuzzing", N34).

One deterministic generator owns five corpora:

    src/fuzzing/YellowbackTag/input/*.bin       LE32(nHeight) ‖ coinbase scriptSig
    src/fuzzing/YellowbackPayload/input/*.bin   OP_RETURN payload bytes (version 3)
    src/fuzzing/YellowbackScript/input/*.bin    vault scripts and vault scriptSigs
    src/fuzzing/YellowbackEvaluate/input/*.bin  the prefix grammar of src/test/yellowback_fuzz_harness.h ‖ a CBlock
    src/fuzzing/YellowbackPayee/input/*.bin     the FEE-W grammar of the same header

and the C++ tables embedded in src/test/yellowback_fuzz_tests.cpp between the
BEGIN/END GENERATED CORPUS markers, so `make check` replays every seed (and
every file under src/fuzzing/<Target>/crashes/, a found-and-fixed crash)
without a fuzzing build or a path.

    gen_yellowback_corpus.py            print the C++ tables
    gen_yellowback_corpus.py --write    write input/*.bin and update the C++ file
    gen_yellowback_corpus.py --check    exit 1 unless input/ and the C++ file match (CI); also checks that
                                        src/test/data/yellowback_golden.json equals the qa/ copy the model pins

Run from anywhere; paths are relative to this file. No third-party modules.
"""
import argparse
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                                "qa", "rpc-tests"))
from test_framework.yellowback_model import ripemd160 as _yb_ripemd160   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
FUZZ_DIR = os.path.join(SRC, "fuzzing")
CPP = os.path.join(HERE, "yellowback_fuzz_tests.cpp")
TARGETS = ("YellowbackTag", "YellowbackPayload", "YellowbackScript", "YellowbackEvaluate", "YellowbackPayee")
GOLDEN_SRC = os.path.join(HERE, "data", "yellowback_golden.json")
GOLDEN_QA = os.path.join(os.path.dirname(SRC), "qa", "rpc-tests", "test_framework", "yellowback_golden.json")
BEGIN = "// BEGIN GENERATED CORPUS (src/test/gen_yellowback_corpus.py; do not edit by hand)"
END = "// END GENERATED CORPUS"

# ---------------------------------------------------------------- script helpers (ref/ycash/src/script/script.h)
OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_1NEGATE, OP_1, OP_16 = 0x00, 0x4C, 0x4D, 0x4F, 0x51, 0x60
OP_IF, OP_ELSE, OP_ENDIF, OP_DROP, OP_DUP, OP_RETURN = 0x63, 0x67, 0x68, 0x75, 0x76, 0x6A
OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CLTV = 0xAC, 0xAD, 0xAE, 0xB1
OP_TRUE = OP_1

# A fixed syntactically valid compressed key (also used by the unit tests).
KEY = bytes.fromhex("02cb81cc0269783ebd9e6484b5495343036874a407856f230a8ee0384986759e70")
UNCOMPRESSED_KEY = bytes([0x04]) + bytes(64)
FAKE_SIG = bytes([0x30, 0x45, 0x02, 0x21]) + bytes(range(1, 34)) + bytes([0x02, 0x20]) + bytes(range(34, 66)) + bytes([0x01])
assert len(FAKE_SIG) == 72
TAG_MAGIC = b"YED!"
LOCKTIME_THRESHOLD = 500000000


def scriptnum(n):
    """Minimal CScriptNum serialisation (CScriptNum::serialize)."""
    if n == 0:
        return b""
    neg = n < 0
    a = abs(n)
    out = bytearray()
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def push(data):
    """CScript::operator<<(vector): the minimal push for data (never OP_N)."""
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data


def push_num(n):
    """CScript::operator<<(int64_t): OP_0 / OP_1..OP_16 / OP_1NEGATE / a minimal CScriptNum push."""
    if n == 0:
        return bytes([OP_0])
    if n == -1:
        return bytes([OP_1NEGATE])
    if 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    return push(scriptnum(n))


def op(*ops):
    return bytes(ops)


def rnd(seed, n):
    """Deterministic pseudo-random bytes (no `random` module: the corpus must not drift)."""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(("yellowback-corpus/%s/%d" % (seed, counter)).encode()).digest()
        counter += 1
    return out[:n]


# ---------------------------------------------------------------- tag (§3.2)
def tag(price=50000, flags=0x01, version=1, source=0x0007, key=bytes([0xAB]) * 20):
    return TAG_MAGIC + bytes([version, flags]) + struct.pack("<Q", price) + struct.pack("<H", source) + key


def tag_push(*a, **kw):
    return push(tag(*a, **kw))


def tag_seed(height, script_sig):
    return struct.pack("<I", height) + script_sig


def tag_corpus():
    h = 1234567
    pre = push_num(h)
    ex8 = bytes.fromhex("0011223344556677")
    seeds = [
        ("after_height", tag_seed(h, pre + tag_push())),
        ("after_extranonce", tag_seed(h, pre + ex8 + tag_push())),
        ("after_pool_text", tag_seed(h, pre + b"/YcashPool/" + tag_push() + ex8)),
        ("magic_without_push_opcode", tag_seed(h, pre + tag())),
        ("first_occurrence_short_then_full", tag_seed(h, pre + bytes([0x24]) + TAG_MAGIC + b"\x01\x00" + tag_push())),
        ("two_tags", tag_seed(h, pre + tag_push() + tag_push(60000))),
        ("bad_version", tag_seed(h, pre + tag_push(version=0))),
        ("reserved_flag_bit", tag_seed(h, pre + tag_push(flags=0x03))),
        ("price_below_min", tag_seed(h, pre + tag_push(price=99))),
        ("price_above_max", tag_seed(h, pre + tag_push(price=100000001))),
        ("signal_only", tag_seed(h, pre + tag_push(price=0))),
        ("wrong_height", tag_seed(h + 1, pre + tag_push())),
        ("no_prefix", tag_seed(h, tag_push())),
        ("truncated_by_one", tag_seed(h, pre + tag_push()[:-1])),
        ("pushdata1_tag", tag_seed(h, pre + bytes([OP_PUSHDATA1, 0x24]) + tag())),
        ("empty", tag_seed(h, b"")),
        ("height_only", tag_seed(h, pre)),
        ("all_0x24", tag_seed(h, pre + bytes([0x24]) * 60)),
        ("height_1", tag_seed(1, push_num(1) + ex8 + tag_push())),
        ("height_16", tag_seed(16, push_num(16) + ex8 + tag_push())),
        ("height_17", tag_seed(17, push_num(17) + ex8 + tag_push())),
        ("height_65535", tag_seed(65535, push_num(65535) + ex8 + tag_push())),
        ("height_16777215", tag_seed(16777215, push_num(16777215) + ex8 + tag_push())),
        ("height_16777216", tag_seed(16777216, push_num(16777216) + ex8 + tag_push())),
        ("height_0_genesis_shape", tag_seed(0, push_num(0) + tag_push())),
        ("height_negative_bits", tag_seed(0xFFFFFFFF, pre + tag_push())),
    ]
    # Ten pool-shaped coinbase scriptSigs (synthetic: no mainnet node was available
    # when this corpus was made; the shapes are those real pools use — height push,
    # nTime/extranonce1/extranonce2 as raw bytes, pool text as a push or raw, and
    # Ycash's own IncrementExtraNonce layout `<height> <CScriptNum extranonce>`).
    pools = [
        ("pool_internal_miner", 1000000, push_num(1000000) + push_num(3)),                                    # miner.cpp:720 shape
        ("pool_internal_miner_big_nonce", 1000001, push_num(1000001) + push_num(0x123456)),
        ("pool_raw_en1_en2", 1100000, push_num(1100000) + bytes.fromhex("deadbeef") + bytes.fromhex("0000000000000001")),
        ("pool_text_push_then_raw", 1200000, push_num(1200000) + push(b"/ViaBTC/Mined by yecuser/") + rnd("en3", 8)),
        ("pool_ntime_en_text", 1300000, push_num(1300000) + struct.pack("<I", 1790000000) + rnd("en5", 8) + push(b"/2miners/")),
        ("pool_slush_shape", 1400000, push_num(1400000) + struct.pack("<I", 1790000001) + rnd("en6", 4) + rnd("en6b", 4) + b"/slush/"),
        ("pool_mph_shape", 1500000, push_num(1500000) + b"/ycash.miningpoolhub.com/" + rnd("en7", 8)),
        ("pool_padding_then_en", 1600000, push_num(1600000) + b"\x00\x00" + rnd("en8", 12)),
        ("pool_max_100_bytes", 1700000, None),                                                              # filled below
        ("pool_magic_in_extranonce", 1800000, push_num(1800000) + rnd("en10", 8) + TAG_MAGIC + rnd("en10b", 20)),
    ]
    out = []
    for name, height, sig in pools:
        if sig is None:
            sig = push_num(height) + push(b"/A very long pool tagline padding out the coinbase/")
            sig += rnd("en9", 100 - len(sig))
            assert len(sig) == 100
        out.append((name, tag_seed(height, sig)))
        # The same coinbase with a tag inserted after the height push.
        pre_len = len(push_num(height))
        tagged = sig[:pre_len] + tag_push() + sig[pre_len:]
        if len(tagged) > 100:
            tagged = tagged[:100]
        out.append((name + "_tagged", tag_seed(height, tagged)))
    seeds += out
    seeds.append(("random1", rnd("tag-random1", 40)))
    seeds.append(("random2", rnd("tag-random2", 104)))
    return seeds


# ---------------------------------------------------------------- payload (v3 plan §3.3)
PAYLOAD_VERSION = 3
KEY2 = bytes.fromhex("03a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90")
SIG64 = bytes(range(64))
TXID = bytes([0xAA]) * 32


def hdr(t, version=PAYLOAD_VERSION):
    return bytes([0x59, 0x42, version, t])


def mint(term=0, cents=10000, lock=1000, ref=950, key=KEY, fee=3, attest_fee=0xFF, version=PAYLOAD_VERSION):
    return hdr(1, version) + bytes([term]) + struct.pack("<III", cents, lock, ref) + key + bytes([fee, attest_fee])


def mint_v2(term=0, cents=10000, lock=1000, ref=950, key=KEY, fee=3):
    """The v2 encoding (51 bytes): non-Yellowback under v3 (V23)."""
    return hdr(1, 2) + bytes([term]) + struct.pack("<III", cents, lock, ref) + key + bytes([fee])


def transfer(assignments, version=PAYLOAD_VERSION):
    body = bytes([len(assignments)])
    for v, c in assignments:
        body += bytes([v]) + struct.pack("<I", c)
    return hdr(2, version) + body


def redeem(ref, fee, assignments, attest_fee=0xFF):
    body = struct.pack("<I", ref) + bytes([fee, attest_fee, len(assignments)])
    for v, c in assignments:
        body += bytes([v]) + struct.pack("<I", c)
    return hdr(3) + body


def redeem_v2(ref, fee, assignments):
    """The v2 encoding (10 + 5n): non-Yellowback under v3 (V23)."""
    body = struct.pack("<I", ref) + bytes([fee, len(assignments)])
    for v, c in assignments:
        body += bytes([v]) + struct.pack("<I", c)
    return hdr(3, 2) + body


def register(attestor=KEY, bond=KEY2, locktime=420480, flags=0):
    return hdr(5) + attestor + bond + struct.pack("<I", locktime) + bytes([flags])


def notice(txid=TXID, vout=2, ref=950):
    return hdr(6) + txid + bytes([vout]) + struct.pack("<I", ref)


def equivocation():
    return hdr(7)


def revive(seq=1, price=50000, cited=949, sig=SIG64):
    return hdr(8) + struct.pack("<HII", seq, price, cited) + sig


def payload_corpus():
    fifteen = [(i, 100 + i) for i in range(15)]
    thirteen = fifteen[:13]
    return [
        ("mint", mint()),
        ("mint_feevout_none", mint(term=2, cents=1000000, lock=0xFFFFFFFF, ref=0, fee=0xFF)),
        ("mint_attest_fee", mint(fee=3, attest_fee=4)),
        ("mint_key_prefix_03", mint(key=bytes([0x03]) + KEY[1:])),
        ("transfer_empty", transfer([])),
        ("transfer_one", transfer([(1, 100)])),
        ("transfer_15", transfer(fifteen)),
        ("redeem_empty", redeem(950, 0xFF, [])),
        ("redeem_one", redeem(950, 3, [(1, 12345)], attest_fee=4)),
        ("redeem_13", redeem(0xFFFFFFFF, 0, thirteen, attest_fee=1)),
        ("register", register()),
        ("register_key_prefix_04", register(attestor=bytes([0x04]) + KEY[1:], flags=0xFF)),
        ("notice", notice()),
        ("notice_vout_ff", notice(vout=0xFF, ref=0xFFFFFFFF)),
        ("equivocation", equivocation()),
        ("revive", revive()),
        ("revive_max", revive(seq=0xFFFF, price=0xFFFFFFFF, cited=0xFFFFFFFF, sig=bytes([0xFF]) * 64)),
        ("bad_magic", b"\x59\x44" + mint()[2:]),
        ("version1_mint", hdr(1, 1) + bytes([0]) + struct.pack("<III", 10000, 1000, 950) + KEY),   # v1: non-Yellowback (V23)
        ("version2_mint", mint_v2()),                                                               # v2: non-Yellowback (W14)
        ("version2_transfer", transfer([(1, 100)], version=2)),
        ("version2_redeem", redeem_v2(950, 3, [(1, 12345)])),
        ("version2_header_v3_body", mint(version=2)),
        ("version4", mint(version=4)),
        ("unknown_type_04", hdr(4) + b"\x01\x00\x00\x00"),
        ("unknown_type_09", hdr(9) + b"\x00"),
        ("retired_type_10", hdr(0x10) + struct.pack("<Q", 50000)),
        ("reserved_type_20", hdr(0x20) + b"\x00"),
        ("short", b"\x59\x42\x03"),
        ("mint_short", mint()[:-2]),
        ("mint_no_attest_feevout", mint()[:-1]),        # the v2 length under the v3 header
        ("mint_no_feevout", mint()[:-2]),               # the v1 length
        ("mint_trailing", mint() + b"\x00"),
        ("mint_uncompressed_key", hdr(1) + bytes([0]) + struct.pack("<III", 10000, 1000, 950) + UNCOMPRESSED_KEY[:33] + b"\x03\xff"),
        ("transfer_dup", transfer([(1, 1), (1, 2)])),
        ("transfer_zero", transfer([(1, 0)])),
        ("transfer_16", transfer([(i, 1) for i in range(16)])),
        ("redeem_14", redeem(1, 0xFF, [(i, 1) for i in range(14)])),
        ("redeem_short", redeem(950, 0xFF, [(1, 12345)])[:-1]),
        ("redeem_v2_head", hdr(3) + struct.pack("<I", 950) + bytes([0xFF, 0])),   # the v2 head (no attestFeeVout) under the v3 header
        ("register_short", register()[:-1]),
        ("register_trailing", register() + b"\x00"),
        ("notice_short", notice()[:-1]),
        ("notice_trailing", notice() + b"\x00"),
        ("equivocation_byte", equivocation() + b"\x00"),
        ("revive_short", revive()[:-1]),
        ("revive_trailing", revive() + b"\x00"),
        ("long81", hdr(2) + bytes(77)),
        ("random1", rnd("payload-random1", 40)),
        ("random2", rnd("payload-random2", 80)),
        ("empty", b""),
    ]


# ---------------------------------------------------------------- script (§3.4)
def vault(lock=120000, claim=120000 + 34560, key=KEY, checksig=OP_CHECKSIG, endif=True, lock_bytes=None):
    s = op(OP_IF)
    s += push(lock_bytes) if lock_bytes is not None else push_num(lock)
    s += op(OP_CLTV, OP_DROP) + push(key) + op(checksig)
    s += op(OP_ELSE) + push_num(claim) + op(OP_CLTV, OP_DROP, OP_TRUE)
    if endif:
        s += op(OP_ENDIF)
    return s


def owner_sig(script, sig=FAKE_SIG, selector=op(OP_1)):
    return push(sig) + selector + push(script)


def claim_sig(script, selector=op(OP_0)):
    return selector + push(script)


def script_corpus():
    v = vault()
    return [
        ("vault", v),
        ("vault_4byte_heights", vault(9000000, 9000000 + 34560)),
        ("vault_mixed_widths", vault(8388607, 8388607 + 34560)),
        ("vault_opn_heights", vault(1, 2)),
        ("vault_2byte_heights", vault(17, 18)),
        ("vault_threshold_minus_one", vault(LOCKTIME_THRESHOLD - 2, LOCKTIME_THRESHOLD - 1)),
        ("vault_nonminimal_lock", vault(lock_bytes=bytes.fromhex("c0d40100"))),
        ("vault_claim_le_lock", vault(120000, 120000)),
        ("vault_time_locked", vault(LOCKTIME_THRESHOLD, LOCKTIME_THRESHOLD + 1)),
        ("vault_uncompressed_key", vault(key=UNCOMPRESSED_KEY)),
        ("vault_missing_endif", vault(endif=False)),
        ("vault_checksigverify", vault(checksig=OP_CHECKSIGVERIFY)),
        ("vault_trailing", v + op(OP_DROP)),
        ("scriptsig_owner", owner_sig(v)),
        ("scriptsig_claim", claim_sig(v)),
        ("scriptsig_owner_op2", owner_sig(v, selector=op(OP_1 + 1))),
        ("scriptsig_owner_nonminimal_1", owner_sig(v, selector=bytes([0x01, 0x01]))),
        ("scriptsig_claim_negzero", claim_sig(v, selector=bytes([0x01, 0x80]))),
        ("scriptsig_claim_with_sig", owner_sig(v, selector=op(OP_0))),
        ("scriptsig_one_push", push(v)),
        ("scriptsig_not_push_only", op(OP_1) + push(v) + op(OP_DROP)),
        ("scriptsig_four_pushes", push(FAKE_SIG) + push(FAKE_SIG) + op(OP_1) + push(v)),
        ("scriptsig_pushdata1_script", push(FAKE_SIG) + op(OP_1) + bytes([OP_PUSHDATA1, len(v)]) + v),
        ("pushdata2", bytes([OP_PUSHDATA2]) + struct.pack("<H", 256) + bytes(256)),
        ("pushdata_truncated", bytes([OP_PUSHDATA1, 0x50, 0x01, 0x02])),
        ("v1_vault", push_num(120000) + op(OP_CLTV, OP_DROP) + push(KEY) + op(OP_CHECKSIGVERIFY, OP_1) + push(KEY) + op(OP_1, OP_CHECKMULTISIG)),
        ("p2pkh", op(OP_DUP, 0xA9) + push(bytes(20)) + op(0x88, OP_CHECKSIG)),
        ("random1", rnd("script-random1", 60)),
        ("random2", rnd("script-random2", 400)),
        ("empty", b""),
    ]


# ---------------------------------------------------------------- evaluate (§3.8; grammar in yellowback_fuzz_harness.h)
SAPLING_VERSION = 4
SAPLING_GROUP = 0x892F2085
START = 1
GRACE = 24


def compact(n):
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def tx_v4(vin, vout, lock_time=0, expiry=0):
    """A transparent-only Sapling (v4) transaction: vin [(txid32, n, scriptSig, seq)], vout [(value, script)]."""
    r = struct.pack("<I", (1 << 31) | SAPLING_VERSION) + struct.pack("<I", SAPLING_GROUP) + compact(len(vin))
    for txid, n, ss, seq in vin:
        r += txid + struct.pack("<I", n) + compact(len(ss)) + ss + struct.pack("<I", seq)
    r += compact(len(vout))
    for val, spk in vout:
        r += struct.pack("<q", val) + compact(len(spk)) + spk
    r += struct.pack("<II", lock_time, expiry) + struct.pack("<q", 0) + compact(0) + compact(0) + compact(0)
    return r


def block(txs):
    """CBlock: the Zcash header (version, prev, merkle, light-client root, time, bits, 32-byte nonce, solution) and vtx."""
    return struct.pack("<I", 4) + bytes(32) * 3 + struct.pack("<II", 1700000000, 0x207fffff) + bytes(32) + compact(0) + compact(len(txs)) + b"".join(txs)


def coinbase(height, tag_bytes=b""):
    return tx_v4([(bytes(32), 0xFFFFFFFF, push_num(height) + tag_bytes, 0xFFFFFFFF)], [(625000000, p2pkh(bytes(20)))])


def p2pkh(key_hash):
    return op(OP_DUP, 0xA9) + push(key_hash) + op(0x88, OP_CHECKSIG)


def _ripemd160(b):
    """RIPEMD-160, without depending on OpenSSL providing it.

    OpenSSL 3 moved RIPEMD-160 into the legacy provider and most Linux
    distributions ship it disabled, so hashlib.new("ripemd160") raises
    UnsupportedDigestmodError on a stock CI runner while working on the
    developer's macOS host — the corpus would then be generated but never
    checkable in CI. The pure-Python implementation the functional-test model
    already carries is single-sourced here so the two can never disagree about
    a script hash; it is byte-identical to OpenSSL's (checked against the
    algorithm's reference vectors in the model's own tests).
    """
    return _yb_ripemd160(b)


def p2sh(redeem):
    h = _ripemd160(hashlib.sha256(redeem).digest())
    return op(0xA9) + push(h) + op(0x87)


def opret(data):
    return op(OP_RETURN) + push(data)


def fill(b):
    return bytes([b]) * 32


def key20(i):
    return bytes([i]) * 20


def ev_tag(dh, price, key_idx, flags=1, mask=7):
    return bytes([dh, flags]) + struct.pack("<QH", price, mask) + bytes([key_idx])


def ev_vault(status, term, lock, collateral, minted, ref):
    return bytes([status, term]) + struct.pack("<Iqqi", lock, collateral, minted, ref)


def ev_token(cents):
    return struct.pack("<q", cents)


def ev_prev(status=2, mask=0, p_fast=50000, p_mid=50000, p_slow=50000, sigma=10000, issued=10 ** 11):
    return bytes([status]) + struct.pack("<Iqqqiq", mask, p_fast, p_mid, p_slow, sigma, issued)


def ev_act(status=2, lock_in=64, activate=128):
    return bytes([status]) + struct.pack("<ii", lock_in, activate)


def ev_input(tags, vaults, tokens, prev, act, hsel, blk):
    return (bytes([len(tags)]) + b"".join(tags) + bytes([len(vaults)]) + b"".join(vaults)
            + bytes([len(tokens)]) + b"".join(tokens) + prev + act + bytes([hsel]) + blk)


def evaluate_corpus():
    # H = START - 2 + (hsel % 75) on regtest (VOL_WINDOW 64): hsel 10 => H = 9 with the seeded Snapshots[8].
    H = 9
    hsel = H - (START - 2)
    quotes = [ev_tag(dh, 50000 + dh * 10, dh % 3) for dh in range(0, 9)]          # tags at 1..9 (E(R) non-empty)
    vault_script = vault(lock=100, claim=100 + GRACE)
    active = ev_vault(0, 0, 100, 10 ** 12, 10000, 5)                               # Vaults[fill(1):0] ACTIVE
    void = ev_vault(1, 0, 100, 10 ** 12, 5000, 5)                                  # Vaults[fill(2):0] VOID
    tokens = [ev_token(10000), ev_token(6000)]                                     # Tokens[fill(0x80):0], [fill(0x81):0]
    cb = coinbase(H, tag_push())
    fee = p2pkh(key20(8 % 3))                                                      # the key quoted at R = 8
    mint_pl = mint(term=0, cents=10000, lock=8 + 48, ref=8, key=KEY, fee=3)
    mint_tx = tx_v4([(fill(0x50), 0, b"", 0xFFFFFFFF)],
                    [(10 ** 12, p2sh(vault(lock=56, claim=56 + GRACE))), (10000, p2pkh(KEY[1:21])), (0, opret(mint_pl)), (2500000000, fee)])
    owner_sig = push(FAKE_SIG) + op(OP_1) + push(vault_script)
    claim_sig_ = op(OP_0) + push(vault_script)
    redeem_pl = redeem(8, 1, [])
    redeem_tx = tx_v4([(fill(1), 0, owner_sig, 0xFFFFFFFE), (fill(0x80), 0, b"", 0xFFFFFFFF)],
                      [(10 ** 12 - 1000, p2pkh(bytes(20))), (2500000000, fee), (0, opret(redeem_pl))], lock_time=100)
    claim_tx = tx_v4([(fill(1), 0, claim_sig_, 0xFFFFFFFE), (fill(0x80), 0, b"", 0xFFFFFFFF)],
                     [(10 ** 12 - 1000, p2pkh(bytes(20))), (2500000000, fee), (0, opret(redeem_pl))], lock_time=124)
    short_tx = tx_v4([(fill(1), 0, owner_sig, 0xFFFFFFFE), (fill(0x81), 0, b"", 0xFFFFFFFF)],
                     [(10 ** 12 - 1000, p2pkh(bytes(20))), (2500000000, fee), (0, opret(redeem_pl))], lock_time=100)
    sweep_tx = tx_v4([(fill(1), 0, owner_sig, 0xFFFFFFFE)], [(10 ** 12 - 1000, p2pkh(bytes(20)))], lock_time=100)
    void_spend = tx_v4([(fill(2), 0, claim_sig_, 0xFFFFFFFE)], [(10 ** 12 - 1000, p2pkh(bytes(20)))])
    xfer_tx = tx_v4([(fill(0x80), 0, b"", 0xFFFFFFFF)], [(10000, p2pkh(key20(1))), (10000, p2pkh(key20(2))), (0, opret(transfer([(0, 6000), (1, 4000)])))])
    over_tx = tx_v4([(fill(0x81), 0, b"", 0xFFFFFFFF)], [(10000, p2pkh(key20(1))), (0, opret(transfer([(0, 9000)])))])
    plain_tx = tx_v4([(fill(0x60), 0, b"", 0xFFFFFFFF)], [(1000, p2pkh(key20(5)))])
    garbage_tx = tx_v4([(fill(0x61), 0, b"", 0xFFFFFFFF)], [(0, opret(rnd("garbage", 80)))])
    # v3 (v3 plan §3.3-3.5): carriers and the four attestation payload types. The seeded view holds no
    # attestors and is unarmed, so every rule is exercised on its refusal path; the fuzzer mutates from here.
    bond_script = push_num(H + 200) + op(OP_CLTV, OP_DROP) + push(KEY2) + op(OP_CHECKSIG)
    bundle = b"YA\x01\x02" + bytes(range(74)) + bytes(range(74, 148))
    carrier_script = op(0x7C, 0xA8) + push(hashlib.sha256(bundle).digest()) + op(0x88) + push(KEY) + op(OP_CHECKSIG)
    carrier_sig = push(bundle) + push(FAKE_SIG) + push(carrier_script)
    bad_carrier_sig = push(bundle[:-1]) + push(FAKE_SIG) + push(carrier_script)          # hash mismatch
    register_tx = tx_v4([(fill(0x62), 0, b"", 0xFFFFFFFF)],
                        [(10 ** 9, p2sh(bond_script)), (0, opret(register(KEY, KEY2, H + 200))), (1000, p2pkh(key20(5)))])
    register_bare_tx = tx_v4([(fill(0x62), 0, b"", 0xFFFFFFFF)],
                             [(10 ** 9, bond_script), (0, opret(register(KEY, KEY2, H + 200)))])
    mint_carrier_tx = tx_v4([(fill(0x50), 0, b"", 0xFFFFFFFF), (fill(0x63), 0, carrier_sig, 0xFFFFFFFF)],
                            [(10 ** 12, p2sh(vault(lock=56, claim=56 + GRACE))), (10000, p2pkh(KEY[1:21])),
                             (0, opret(mint(term=0, cents=10000, lock=8 + 48, ref=8, key=KEY, fee=3, attest_fee=4))),
                             (2500000000, fee), (625000000, p2pkh(KEY2[1:21]))])
    mint_two_carriers_tx = tx_v4([(fill(0x50), 0, b"", 0xFFFFFFFF), (fill(0x63), 0, carrier_sig, 0xFFFFFFFF), (fill(0x64), 0, carrier_sig, 0xFFFFFFFF)],
                                 [(10 ** 12, p2sh(vault(lock=56, claim=56 + GRACE))), (10000, p2pkh(KEY[1:21])),
                                  (0, opret(mint_pl))])
    claim_carrier_tx = tx_v4([(fill(1), 0, claim_sig_, 0xFFFFFFFE), (fill(0x80), 0, b"", 0xFFFFFFFF), (fill(0x65), 0, carrier_sig, 0xFFFFFFFF)],
                             [(10 ** 12 - 1000, p2pkh(bytes(20))), (2500000000, fee), (0, opret(redeem(8, 1, [], attest_fee=3))),
                              (625000000, p2pkh(KEY2[1:21])), (10 ** 9, p2pkh(KEY[1:21]))], lock_time=124)
    notice_tx = tx_v4([(fill(0x66), 0, b"", 0xFFFFFFFF), (fill(0x67), 0, carrier_sig, 0xFFFFFFFF)],
                      [(0, opret(notice(fill(1), 0, 8))), (1000, p2pkh(key20(5)))])
    notice_bad_hash_tx = tx_v4([(fill(0x66), 0, b"", 0xFFFFFFFF), (fill(0x67), 0, bad_carrier_sig, 0xFFFFFFFF)],
                               [(0, opret(notice(fill(1), 0, 8))), (1000, p2pkh(key20(5)))])
    equivocation_tx = tx_v4([(fill(0x68), 0, carrier_sig, 0xFFFFFFFF)], [(0, opret(equivocation())), (1000, p2pkh(key20(5)))])
    revive_tx = tx_v4([(fill(0x69), 0, b"", 0xFFFFFFFF)], [(0, opret(revive(seq=0, price=50000, cited=8))), (1000, p2pkh(key20(5)))])
    bond_spend_tx = tx_v4([(fill(0x6A), 0, push(FAKE_SIG) + push(bond_script), 0xFFFFFFFE)], [(10 ** 9 - 1000, p2pkh(key20(5)))], lock_time=H + 200)
    base = dict(tags=quotes, vaults=[active, void], tokens=tokens, prev=ev_prev(), act=ev_act(), hsel=hsel)

    def mk(name, blk=None, **kw):
        a = dict(base)
        a.update(kw)
        return (name, ev_input(a["tags"], a["vaults"], a["tokens"], a["prev"], a["act"], a["hsel"], blk if blk is not None else block([cb])))

    seeds = [
        mk("empty_block"),
        mk("no_state", tags=[], vaults=[], tokens=[]),
        mk("untagged_coinbase", blk=block([coinbase(H)])),
        mk("mint_ok", blk=block([cb, mint_tx])),
        mk("mint_void_not_active", blk=block([cb, mint_tx]), prev=ev_prev(status=0, mask=1)),
        mk("mint_and_xfer_chained", blk=block([cb, mint_tx, xfer_tx])),
        mk("redeem_owner_ok", blk=block([cb, redeem_tx])),
        mk("redeem_short_burn", blk=block([cb, short_tx])),
        mk("claim_not_underwater", blk=block([cb, claim_tx])),
        mk("claim_underwater", blk=block([cb, claim_tx]), prev=ev_prev(p_fast=9000, p_mid=9000, p_slow=9000)),
        mk("sweep_no_payload", blk=block([cb, sweep_tx])),
        mk("sweep_enforcement_suspended", blk=block([cb, sweep_tx]), prev=ev_prev(mask=0x24)),
        mk("void_vault_spend", blk=block([cb, void_spend])),
        mk("transfer_ok", blk=block([cb, xfer_tx])),
        mk("transfer_over_assigned", blk=block([cb, over_tx])),
        mk("plain_and_garbage", blk=block([cb, plain_tx, garbage_tx])),
        mk("everything", blk=block([cb, mint_tx, xfer_tx, redeem_tx, void_spend, plain_tx])),
        mk("below_start", hsel=0),                                                  # H = START - 2: ignored
        mk("at_start", hsel=2, tags=[], vaults=[], tokens=[]),                      # H = START: virtual Snapshots[H - 1]
        mk("first_sigma_sample", hsel=64 + 2 + 0),                                  # H = START + VOL_WINDOW
        mk("top_of_range", hsel=74),                                                # H = START + VOL_WINDOW + 8
        mk("hsel_wraps", hsel=255),
        mk("no_coinbase_first", blk=block([plain_tx])),
        mk("register", blk=block([cb, register_tx])),
        mk("register_bare_bond", blk=block([cb, register_bare_tx])),
        mk("register_twice", blk=block([cb, register_tx, register_tx])),
        mk("mint_with_carrier", blk=block([cb, mint_carrier_tx])),
        mk("mint_two_carriers", blk=block([cb, mint_two_carriers_tx])),
        mk("claim_with_carrier", blk=block([cb, claim_carrier_tx]), prev=ev_prev(p_fast=9000, p_mid=9000, p_slow=9000)),
        mk("notice", blk=block([cb, notice_tx])),
        mk("notice_bad_hash", blk=block([cb, notice_bad_hash_tx])),
        mk("equivocation", blk=block([cb, equivocation_tx])),
        mk("revive", blk=block([cb, revive_tx])),
        mk("bond_spend_shape", blk=block([cb, bond_spend_tx])),
        mk("everything_v3", blk=block([cb, register_tx, mint_carrier_tx, notice_tx, equivocation_tx, revive_tx, claim_carrier_tx, bond_spend_tx])),
        mk("max_tags_and_vaults", tags=[ev_tag(i, 100 + i, i % 5, flags=i & 1) for i in range(64)],
           vaults=[ev_vault(i % 4, i % 3, 60 + i, 10 ** 12, 10000, 5) for i in range(16)], tokens=[ev_token(100 + i) for i in range(16)]),
        mk("inconsistent_totals_seed", tokens=[ev_token(-5)]),
        mk("truncated_block", blk=block([cb])[:40]),                                 # discarded
        mk("empty_rest", blk=b""),                                                   # discarded
        ("random1", rnd("evaluate-random1", 300)),
        ("random2", rnd("evaluate-random2", 900)),
        ("empty", b""),
    ]
    return seeds


# ---------------------------------------------------------------- payee (§3.7 FEE-W)
def pt(dh, price, key_idx, jb):
    return bytes([dh]) + struct.pack("<Q", price) + bytes([key_idx, jb])


def payee_input(tags, rsel, selector, penalty=12, window=24, tilt=10000, pref=0xFF):
    return (bytes([len(tags)]) + b"".join(tags) + bytes([rsel, len(selector)]) + selector
            + bytes([penalty, window]) + struct.pack("<H", tilt) + bytes([pref]))


def payee_corpus():
    judged = [pt(dh, 50000, dh % 2, 0b0111 if dh % 2 == 0 else 0b0011) for dh in range(0, 60)]   # A in band, B not
    penalised_b = [pt(dh, 50000, dh % 2, 0b0111 if dh % 2 == 0 else 0b1011) for dh in range(0, 60)]
    all_penalised = [pt(dh, 50000, dh % 2, 0b1011) for dh in range(0, 60)]
    unjudged = [pt(dh, 50000, dh % 3, 0) for dh in range(0, 60)]
    sel = KEY
    return [
        ("no_tags", payee_input([], 10, sel)),
        ("one_quote", payee_input([pt(5, 50000, 0, 0)], 10, sel)),
        ("signal_only", payee_input([pt(5, 0, 0, 0)], 10, sel)),                    # price 0: not a quote, E(R) empty
        ("window_edge_in", payee_input([pt(0, 50000, 0, 0)], 9, sel)),
        ("window_edge_out", payee_input([pt(0, 50000, 0, 0)], 10, sel)),
        ("two_pools_judged", payee_input(judged, 59, sel)),
        ("two_pools_tilt0", payee_input(judged, 59, sel, tilt=0)),
        ("two_pools_max_tilt", payee_input(judged, 59, sel, tilt=65535)),
        ("penalised_skipped", payee_input(penalised_b, 59, sel)),
        ("all_penalised_fallback", payee_input(all_penalised, 59, sel)),
        ("penalty_zero", payee_input(all_penalised, 59, sel, penalty=0)),
        ("window_zero", payee_input(judged, 59, sel, window=0)),
        ("unjudged", payee_input(unjudged, 59, sel)),
        ("preferred_in_set", payee_input(judged, 59, sel, pref=1)),
        ("preferred_not_in_set", payee_input(judged, 59, sel, pref=7)),
        ("empty_selector", payee_input(judged, 59, b"")),
        ("long_selector", payee_input(judged, 59, rnd("sel", 200))),
        ("outpoint_selector", payee_input(judged, 59, rnd("op", 36))),
        ("r_before_tags", payee_input(judged, 0, sel)),
        ("r_far_after", payee_input(judged, 255, sel)),
        ("max_tags", payee_input([pt(i, 100 + i, i % 8, i & 15) for i in range(64)], 63, sel)),
        ("random1", rnd("payee-random1", 200)),
        ("random2", rnd("payee-random2", 600)),
        ("empty", b""),
    ]


CORPORA = {
    "YellowbackTag": tag_corpus,
    "YellowbackPayload": payload_corpus,
    "YellowbackScript": script_corpus,
    "YellowbackEvaluate": evaluate_corpus,
    "YellowbackPayee": payee_corpus,
}


# ---------------------------------------------------------------- files and the C++ table
def crashes(target):
    d = os.path.join(FUZZ_DIR, target, "crashes")
    if not os.path.isdir(d):
        return []
    out = []
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
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
    parts = [BEGIN]
    for target in TARGETS:
        seeds = CORPORA[target]()
        names = [n for n, _ in seeds]
        assert len(names) == len(set(names)), "duplicate seed name in %s" % target
        assert len(seeds) >= 20, "%s needs >= 20 seeds" % target
        upper = target.replace("Yellowback", "").upper()
        parts.append(cpp_table("%s_CORPUS" % upper, seeds))
        parts.append(cpp_table("%s_CRASHES" % upper, crashes(target)))
    parts.append(END)
    return "\n".join(parts) + "\n"


def splice(text, block):
    a = text.find(BEGIN)
    b = text.find(END)
    if a < 0 or b < 0:
        raise SystemExit("markers not found in %s" % CPP)
    b += len(END) + 1
    return text[:a] + block + text[b:]


def expected_files(target):
    return {name + ".bin": data for name, data in CORPORA[target]()}


def write_all():
    for target in TARGETS:
        d = os.path.join(FUZZ_DIR, target, "input")
        os.makedirs(d, exist_ok=True)
        want = expected_files(target)
        for name in os.listdir(d):
            if name.endswith(".bin") and name not in want:
                os.remove(os.path.join(d, name))
        for name, data in want.items():
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
    with open(CPP) as f:
        text = f.read()
    with open(CPP, "w") as f:
        f.write(splice(text, cpp_block()))


def check_all():
    ok = True
    for target in TARGETS:
        d = os.path.join(FUZZ_DIR, target, "input")
        want = expected_files(target)
        have = {n for n in os.listdir(d) if n.endswith(".bin")} if os.path.isdir(d) else set()
        for name in sorted(set(want) | have):
            p = os.path.join(d, name)
            if name not in want:
                print("%s: unexpected file %s" % (target, name))
                ok = False
            elif not os.path.exists(p):
                print("%s: missing %s" % (target, name))
                ok = False
            else:
                with open(p, "rb") as f:
                    if f.read() != want[name]:
                        print("%s: %s differs" % (target, name))
                        ok = False
        if len(have) < 20:
            print("%s: only %d corpus files (need >= 20)" % (target, len(have)))
            ok = False
    with open(CPP) as f:
        text = f.read()
    if splice(text, cpp_block()) != text:
        print("%s: embedded corpus table is stale (run --write)" % CPP)
        ok = False
    # The golden vector the C++ statehash_golden_vector replays is a copy of the model's (N18, N23).
    try:
        with open(GOLDEN_SRC, "rb") as a, open(GOLDEN_QA, "rb") as b:
            if a.read() != b.read():
                print("%s differs from %s (copy the qa/ file over)" % (GOLDEN_SRC, GOLDEN_QA))
                ok = False
    except OSError as e:
        print("golden vector: %s" % e)
        ok = False
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--write", action="store_true", help="write input/*.bin and update the C++ tables")
    g.add_argument("--check", action="store_true", help="verify input/*.bin and the C++ tables; exit 1 on drift")
    args = ap.parse_args()
    if args.write:
        write_all()
        for target in TARGETS:
            print("%s: %d seeds" % (target, len(CORPORA[target]())))
        return 0
    if args.check:
        if check_all():
            print("corpus ok")
            return 0
        return 1
    sys.stdout.write(cpp_block())
    return 0


if __name__ == "__main__":
    sys.exit(main())
