#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""
Known-answer vectors for Yellowback price attestations (v3 plan §3.8
BUNDLE-1, R13, W3) and the seed corpus of src/fuzzing/YellowbackBundle.

Writes
    src/test/data/yellowback_attest_vectors.json      (loaded by yellowback_attest_tests.cpp)
    src/fuzzing/YellowbackBundle/input/*.bin          (replayed by the fuzz target)

Standard library only, so the numbers do not depend on OpenSSL's random k:
secp256k1 arithmetic and RFC 6979 deterministic nonces are written out below.
The Python framework (test_framework/yellowback_attest.py) and the Rust agent
must reproduce every `sig` here from the same `secret` and `message`.

Byte layout (all little-endian, no length prefixes):
    message     = SHA256(b"YBATTEST1" || seq u16 || price u32 || citedHeight u32 || blockHash 32)
                  blockHash = the 32 internal bytes of the node's uint256 (bytes.fromhex(hex)[::-1]
                  of the displayed hash; the vectors give both forms)
    attestation = seq u16 || price u32 || citedHeight u32 || sig 64      (74 bytes)
    sig         = r (32, big-endian) || s (32, big-endian), s <= n/2      (compact, low-S)
    bundle      = b"YA" || 0x01 || count u8 || count x attestation        (<= 448 bytes for 6)

Run from the repository root with the workspace venv:
    .venv/bin/python src/test/gen_yellowback_attest_vectors.py
"""
import hashlib
import hmac
import json
import os
import struct
import sys

# --- secp256k1 ------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _inv(a, m):
    return pow(a, m - 2, m)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * _inv(2 * p[1], P) % P
    else:
        lam = (q[1] - p[1]) * _inv(q[0] - p[0], P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)


def _mul(k, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def pubkey(secret):
    x, y = _mul(secret, G)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def rfc6979_k(secret, msg32):
    """RFC 6979 §3.2 with HMAC-SHA256, no extra data (what libsecp256k1's default nonce function does with ndata = NULL)."""
    x = secret.to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + msg32, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            return t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_compact(secret, msg32):
    """Compact r||s, low-S. Returns (sig64, high_s_variant64)."""
    z = int.from_bytes(msg32, "big")
    while True:
        k = rfc6979_k(secret, msg32)
        r = _mul(k, G)[0] % N
        s = _inv(k, N) * (z + r * secret) % N
        if r != 0 and s != 0:
            break
        msg32 = hashlib.sha256(msg32).digest()   # unreachable in practice
    low = s if s <= N // 2 else N - s
    high = N - low
    enc = lambda a, b: a.to_bytes(32, "big") + b.to_bytes(32, "big")
    return enc(r, low), enc(r, high)


# --- attestation layout ----------------------------------------------------------
PREFIX = b"YBATTEST1"


def attest_message(seq, price, cited_height, block_hash_internal):
    assert len(block_hash_internal) == 32
    return hashlib.sha256(PREFIX + struct.pack("<HII", seq, price, cited_height) + block_hash_internal).digest()


def encode_attestation(seq, price, cited_height, sig64):
    return struct.pack("<HII", seq, price, cited_height) + sig64


def encode_bundle(atts):
    return b"YA" + bytes([1, len(atts)]) + b"".join(atts)


def block_hash_internal(height):
    """A deterministic stand-in for blockHash(height): SHA256(b"yellowback-attest-vector-block" || height LE32)."""
    return hashlib.sha256(b"yellowback-attest-vector-block" + struct.pack("<I", height)).digest()


def displayed(internal):
    return internal[::-1].hex()


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # src/test -> repo
    keys = []
    for i in range(6):
        secret = int.from_bytes(hashlib.sha256(b"yellowback-attest-vector-key-%d" % i).digest(), "big") % N
        keys.append({"seq": i, "secret": secret.to_bytes(32, "big").hex(), "pubkey": pubkey(secret).hex(), "_secret": secret})

    # Eight valid attestations: one per key for seq 0..5 (a full BUNDLE_MAX bundle of distinct attestors,
    # prices around $0.10), then a second, later one for seq 0 and seq 1 (the "dup" and pool-replacement cases).
    plan = [(0, 100_000, 1000), (1, 101_000, 1000), (2, 99_500, 1001),
            (3, 100_500, 1002), (4, 100_000, 1003), (5, 102_000, 1003),
            (0, 100_200, 1002), (1, 100_900, 1003)]
    valid = []
    for seq, price, h in plan:
        bh = block_hash_internal(h)
        msg = attest_message(seq, price, h, bh)
        low, high = sign_compact(keys[seq]["_secret"], msg)
        valid.append({
            "seq": seq, "priceMicroUsd": price, "citedHeight": h,
            "blockHash": displayed(bh), "blockHashInternal": bh.hex(),
            "message": msg.hex(), "sig": low.hex(), "sigHighS": high.hex(),
            "pubkey": keys[seq]["pubkey"],
            "attestation": encode_attestation(seq, price, h, low).hex(),
        })

    # The invalid cases derive from valid[0].
    v0 = valid[0]
    wrong_bh = block_hash_internal(4242)
    invalid = [
        {"name": "high_s", "why": "same r, s' = n - s: a second encoding of a valid signature (R17)",
         "seq": v0["seq"], "priceMicroUsd": v0["priceMicroUsd"], "citedHeight": v0["citedHeight"],
         "blockHashInternal": v0["blockHashInternal"], "pubkey": v0["pubkey"], "sig": v0["sigHighS"]},
        {"name": "wrong_block_hash", "why": "the message binds blockHash(citedHeight)",
         "seq": v0["seq"], "priceMicroUsd": v0["priceMicroUsd"], "citedHeight": v0["citedHeight"],
         "blockHashInternal": wrong_bh.hex(), "pubkey": v0["pubkey"], "sig": v0["sig"]},
        {"name": "wrong_key", "why": "signed by seq 0, verified under seq 1's key",
         "seq": v0["seq"], "priceMicroUsd": v0["priceMicroUsd"], "citedHeight": v0["citedHeight"],
         "blockHashInternal": v0["blockHashInternal"], "pubkey": keys[1]["pubkey"], "sig": v0["sig"]},
        {"name": "wrong_price", "why": "price is in the message",
         "seq": v0["seq"], "priceMicroUsd": v0["priceMicroUsd"] + 1, "citedHeight": v0["citedHeight"],
         "blockHashInternal": v0["blockHashInternal"], "pubkey": v0["pubkey"], "sig": v0["sig"]},
        {"name": "wrong_seq", "why": "seq is in the message",
         "seq": v0["seq"] + 1, "priceMicroUsd": v0["priceMicroUsd"], "citedHeight": v0["citedHeight"],
         "blockHashInternal": v0["blockHashInternal"], "pubkey": v0["pubkey"], "sig": v0["sig"]},
    ]

    bundle6 = encode_bundle([bytes.fromhex(a["attestation"]) for a in valid[:6]])
    assert len(bundle6) == 448

    # The flat list the Python framework's reader (test_framework/yellowback_attest.py) consumes:
    # {secret, seq, price, citedHeight, blockHash (display hex), attestation, pubkey, valid}. Every valid row
    # above, the invalid rows (skipped by the Python test, attestation carried as the bytes under test),
    # and the two regtest known-answer rows the framework fixes: attestor secret sha256(b"yellowback-regtest-attestor-0"),
    # seq 1, price 1000000, blockHash 00..01 (display), citedHeight 2 (already low-S) and 1 (needed s = n - s).
    vectors = []
    for a in valid:
        vectors.append({"secret": keys[a["seq"]]["secret"], "seq": a["seq"], "price": a["priceMicroUsd"],
                        "citedHeight": a["citedHeight"], "blockHash": a["blockHash"],
                        "attestation": a["attestation"], "pubkey": a["pubkey"], "valid": True})
    for a in invalid:
        vectors.append({"name": a["name"], "seq": a["seq"], "price": a["priceMicroUsd"], "citedHeight": a["citedHeight"],
                        "blockHash": displayed(bytes.fromhex(a["blockHashInternal"])),
                        "attestation": encode_attestation(a["seq"], a["priceMicroUsd"], a["citedHeight"], bytes.fromhex(a["sig"])).hex(),
                        "pubkey": a["pubkey"], "valid": False})
    regtest_secret = int.from_bytes(hashlib.sha256(b"yellowback-regtest-attestor-0").digest(), "big") % N
    regtest_pub = pubkey(regtest_secret)
    assert regtest_pub.hex() == "0219ce7f2f737be07548a7243c605b76a09e039942f58ef91fe52771bf1f88767b", regtest_pub.hex()
    bh_display = "00" * 31 + "01"
    bh_internal = bytes.fromhex(bh_display)[::-1]
    for cited in (2, 1):
        msg = attest_message(1, 1_000_000, cited, bh_internal)
        low, _high = sign_compact(regtest_secret, msg)
        vectors.append({"secret": regtest_secret.to_bytes(32, "big").hex(), "seq": 1, "price": 1_000_000,
                        "citedHeight": cited, "blockHash": bh_display,
                        "attestation": encode_attestation(1, 1_000_000, cited, low).hex(),
                        "pubkey": regtest_pub.hex(), "valid": True, "name": "regtest-attestor-0-h%d" % cited})

    doc = {
        "_comment": "Generated by src/test/gen_yellowback_attest_vectors.py; do not edit. Layout in that file's docstring.",
        "prefix": PREFIX.decode(),
        "keys": [{k: v for k, v in key.items() if not k.startswith("_")} for key in keys],
        "valid": valid,
        "invalid": invalid,
        "bundle6": bundle6.hex(),
        "vectors": vectors,
    }
    out = os.path.join(root, "src", "test", "data", "yellowback_attest_vectors.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print("wrote", out)

    corpus = os.path.join(root, "src", "fuzzing", "YellowbackBundle", "input")
    os.makedirs(corpus, exist_ok=True)
    files = {
        "empty.bin": b"",
        "bundle6.bin": b"\x00" + bundle6,
        "bundle_dup.bin": b"\x00" + encode_bundle([bytes.fromhex(a["attestation"]) for a in (valid[0], valid[6])]),
        "bundle2_opreturn.bin": b"\x01" + encode_bundle([bytes.fromhex(a["attestation"]) for a in valid[:2]]),
        "count7.bin": b"\x00" + b"YA\x01\x07" + b"\x00" * (74 * 7),
        "bad_magic.bin": b"\x00" + b"YB\x01\x00",
        "short.bin": b"\x00" + b"YA\x01\x01" + b"\x00" * 73,
        "two_carriers.bin": b"\x02" + bundle6[:78],
    }
    for name, data in files.items():
        with open(os.path.join(corpus, name), "wb") as f:
            f.write(data)
    print("wrote", len(files), "corpus files under", corpus)


if __name__ == "__main__":
    sys.exit(main())
