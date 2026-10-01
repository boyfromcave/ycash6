#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Yellowback v3 (price attestation) helpers for the functional tests: plan v3 section 6.0 item 4.

What lives here (and nowhere else in Python):

- the attestation message and signature (plan v3 section 3.8, BUNDLE-1): ``attest_message``,
  ``sign_attestation`` (74 bytes), ``verify_attestation``, ``is_low_s``, ``parse_attestation``;
- the fixed regtest key sets ``ATTESTOR_WIFS`` / ``BOND_WIFS`` and ``attestor_keys(n)``;
- the v3 payload encoders (section 3.3), the bundle codec (section 8.2 of the proposal) and
  the carrier / bond scripts (section 3.4);
- the raw transaction builders: ``build_register_tx``, ``build_carrier_tx``, ``spend_carrier``,
  ``build_mint_tx_v3``, ``post_notice_raw``, ``equivocation_raw``, ``revive_raw``;
- the second implementation of W9 selection (``select_attestors``), ``bond_weight``,
  ``weighted_quantile``, ``bundle_stat``;
- the node drivers ``feed``, ``feed_all``, ``build_bundle``, ``register_and_arm``,
  ``assert_void_reason`` — written against the section 4.5 RPC names, which arrive in Phase A2.

**Signing is pure Python and deterministic (RFC 6979, SHA-256).**  The plan (section 6.0 item
4) suggested the framework's ``CECKey.sign``; that is OpenSSL's ``ECDSA_sign``, which draws a
*random* nonce, so no known-answer vector could ever be reproduced from it, and the vectors file
``src/test/data/yellowback_attest_vectors.json`` that ``yellowback_attest_tests.cpp`` reads
must be reproducible by this module, by ``libsecp256k1`` (``secp256k1_ecdsa_sign`` with its
default RFC 6979 nonce function) and by the Rust agent (the ``secp256k1`` crate, likewise
RFC 6979).  All three therefore agree byte for byte on every vector.  The low-S normalisation
(``s = n - s`` when ``s > n/2``) is still applied after signing, exactly as the plan describes
for the DER path, and both branches have a known-answer test.  ``CECKey`` is used only as an
independent verifier (``verify_attestation(..., backend='openssl')``), so nothing here needs
libcrypto unless a test asks for the cross-check.

The block hash argument of every function is the RPC hex (the reversed display form); the
message uses the 32 *internal* bytes, ``bytes.fromhex(hex)[::-1]`` — the same bytes
``mininode.ser_uint256(int(hex, 16))`` produces and ``uint256::begin()..end()`` exposes.
"""

import hashlib
import hmac
import struct
from io import BytesIO

from .util import assert_equal, bytes_to_hex_str, hex_str_to_bytes
from . import yellowback_model as ym
from . import yellowback_util as yu
from .yellowback_util import (
    ATTEST_ARM_DELAY, ATTEST_ARM_MIN, BOND_MATURITY, BOND_MIN_LOCK, BOND_MIN_ZAT,
    BUNDLE_MAX, CARRIER_VALUE, K_SLACK, M_SELECT, N_SLOTS, Q_HIGH_BPS, Q_LOW_BPS, REF_LAG, REF_WINDOW,
    SIGNING_BRANCH_ID, TOKEN_VALUE, YELLOWBACK_FEE, ATTESTOR_A, ATTESTOR_B, USER, POOLS,
    FEE_VOUT_NONE, GRACE, PAYLOAD_VERSION_V3, AGE_CAP, FOUNDING_WINDOW,
)

__all__ = [
    'ATTEST_PREFIX', 'ATTESTATION_SIZE', 'BUNDLE_MAGIC', 'BUNDLE_VERSION',
    'PAYLOAD_ATTESTOR_REGISTER', 'PAYLOAD_CLAIM_NOTICE', 'PAYLOAD_EQUIVOCATION', 'PAYLOAD_ATTESTOR_REVIVE',
    'attest_message', 'sign_attestation', 'verify_attestation', 'is_low_s', 'parse_attestation',
    'ATTESTOR_WIFS', 'BOND_WIFS', 'attestor_keys', 'bond_keys', 'hot_wif_for',
    'bond_script', 'carrier_script', 'p2sh_script', 'carrier_scriptsig', 'parse_carrier_script',
    'encode_mint_v3', 'encode_transfer_v3', 'encode_redeem_v3', 'encode_attestor_register',
    'encode_claim_notice', 'encode_equivocation', 'encode_revive', 'encode_bundle', 'decode_bundle',
    'outpoint_selector', 'select_attestors', 'bond_weight', 'weighted_quantile', 'bundle_stat',
    'build_register_tx', 'build_carrier_tx', 'spend_carrier', 'build_mint_tx_v3',
    'post_notice_raw', 'equivocation_raw', 'revive_raw', 'withdraw_bond_raw', 'bond_secret_for',
    'feed', 'feed_all', 'build_bundle', 'register_and_arm', 'assert_void_reason', 'hot_secret_for', 'send_and_lock',
    # A3: the wallet's two-step flow and the offline registry (stand-ins for the A2 node RPCs)
    'has_rpc', 'two_step', 'two_step_pending', 'wait_for_spender', 'wallet_mint', 'wallet_claim', 'wallet_notice',
    'wallet_report_equivocation', 'register_wallet_attestor', 'note_attestor_status', 'offline_selection',
    'offline_bundle', 'offline_bundle_hex', 'arming_state', 'REGISTRY', 'armed_raw_claim', 'armed_raw_mint', 'attest_fee_zat',
    'ArmedModeMixin', 'attested_micro', 'model_check',
]

# ---------------------------------------------------------------------------
# Constants

ATTEST_PREFIX = b'YBATTEST1'          # 9 ASCII bytes, no length prefix (R13)
ATTESTATION_SIZE = 74                 # seq u16 | price u32 | citedHeight u32 | sig 64
BUNDLE_MAGIC = b'YA'
BUNDLE_VERSION = 1
BUNDLE_HEADER = 4                     # "YA" | version | count
CARRIER_SCRIPT_SIZE = 71                 # 2 + (1 + 32) + 1 + (1 + 33) + 1; the plan's "72 bytes" miscounts
MAX_SCRIPT_ELEMENT_SIZE = 520

PAYLOAD_MINT = ym.PAYLOAD_MINT
PAYLOAD_TRANSFER = ym.PAYLOAD_TRANSFER
PAYLOAD_REDEEM = ym.PAYLOAD_REDEEM
PAYLOAD_ATTESTOR_REGISTER = 0x05
PAYLOAD_CLAIM_NOTICE = 0x06
PAYLOAD_EQUIVOCATION = 0x07
PAYLOAD_ATTESTOR_REVIVE = 0x08

OP_SWAP = 0x7c
OP_SHA256 = 0xa8

_N = yu._SECP256K1_N
_P = yu._SECP256K1_P
_G = yu._SECP256K1_G


# ---------------------------------------------------------------------------
# secp256k1 ECDSA in pure Python: RFC 6979 nonces, low-S, compact (r || s) encoding

def _ec_mul(k, point):
    r, a = None, point
    while k:
        if k & 1:
            r = yu._ec_add(r, a)
        a = yu._ec_add(a, a)
        k >>= 1
    return r


def _decompress(pubkey33):
    if len(pubkey33) != 33 or pubkey33[0] not in (2, 3):
        return None
    x = int.from_bytes(pubkey33[1:], 'big')
    if x >= _P:
        return None
    y = pow((x * x * x + 7) % _P, (_P + 1) // 4, _P)
    if (y * y - (x * x * x + 7)) % _P != 0:
        return None
    if (y & 1) != (pubkey33[0] & 1):
        y = _P - y
    return (x, y)


def _rfc6979_k(secret32, msg32):
    """RFC 6979 section 3.2 with HMAC-SHA256 over secp256k1's order (q = n, qlen = 256)."""
    x = int.from_bytes(secret32, 'big')
    h1 = int.from_bytes(msg32, 'big') % _N       # bits2int then mod q (both 256 bits)
    v = b'\x01' * 32
    k = b'\x00' * 32
    seed = secret32 + h1.to_bytes(32, 'big')
    k = hmac.new(k, v + b'\x00' + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    assert 0 < x < _N
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, 'big')
        if 0 < t < _N:
            # RFC 6979 does not check r, s != 0 here; libsecp256k1 retries in that case, and the
            # caller does too (ecdsa_sign_raw).
            yield t
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign_raw(secret32, msg32):
    """``(r, s)`` before low-S normalisation, deterministic (RFC 6979)."""
    x = int.from_bytes(secret32, 'big')
    z = int.from_bytes(msg32, 'big')
    for k in _rfc6979_k(secret32, msg32):
        px, _py = _ec_mul(k, _G)
        r = px % _N
        if r == 0:
            continue
        s = pow(k, _N - 2, _N) * (z + r * x) % _N
        if s == 0:
            continue
        return r, s


def ecdsa_sign(secret32, msg32):
    """``(r, s)`` with ``s <= n/2`` (the section 3.8 low-S requirement)."""
    r, s = ecdsa_sign_raw(secret32, msg32)
    if s > _N // 2:
        s = _N - s
    return r, s


def ecdsa_verify(pubkey33, msg32, r, s):
    """Textbook verification; accepts any ``s`` in range (low-S is the caller's check)."""
    q = _decompress(pubkey33)
    if q is None or not (0 < r < _N and 0 < s < _N):
        return False
    z = int.from_bytes(msg32, 'big')
    w = pow(s, _N - 2, _N)
    u1, u2 = z * w % _N, r * w % _N
    point = yu._ec_add(_ec_mul(u1, _G), _ec_mul(u2, q))
    return point is not None and point[0] % _N == r


def der_encode(r, s):
    def _int(v):
        b = v.to_bytes((v.bit_length() + 7) // 8, 'big') or b'\x00'
        if b[0] & 0x80:
            b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = _int(r) + _int(s)
    return b'\x30' + bytes([len(body)]) + body


def der_decode(der):
    assert der[0] == 0x30 and der[2] == 0x02, 'not a DER ECDSA signature'
    rlen = der[3]
    r = int.from_bytes(der[4:4 + rlen], 'big')
    assert der[4 + rlen] == 0x02
    slen = der[5 + rlen]
    s = int.from_bytes(der[6 + rlen:6 + rlen + slen], 'big')
    return r, s


def compact_sig(r, s):
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


# ---------------------------------------------------------------------------
# The attestation (section 3.8 BUNDLE-1; proposal section 4)

def blockhash_internal(blockhash_hex):
    """The 32 internal bytes of a block hash given as RPC hex (``uint256::begin()..end()``)."""
    b = bytes.fromhex(blockhash_hex)
    assert_equal(len(b), 32)
    return b[::-1]


def attest_message(seq, price_micro_usd, cited_height, blockhash_hex):
    """``SHA256("YBATTEST1" || seq LE16 || price LE32 || citedHeight LE32 || blockHash internal 32)``."""
    return hashlib.sha256(ATTEST_PREFIX + struct.pack('<HII', seq, price_micro_usd, cited_height)
                          + blockhash_internal(blockhash_hex)).digest()


def sign_attestation(hot_secret32, seq, price_micro_usd, cited_height, blockhash_hex):
    """The 74-byte attestation: ``seq LE16 || price LE32 || citedHeight LE32 || r || s`` with a
    low-S compact signature under ``hot_secret32`` (deterministic; see the module docstring)."""
    assert_equal(len(hot_secret32), 32)
    msg = attest_message(seq, price_micro_usd, cited_height, blockhash_hex)
    r, s = ecdsa_sign(hot_secret32, msg)
    att = struct.pack('<HII', seq, price_micro_usd, cited_height) + compact_sig(r, s)
    assert_equal(len(att), ATTESTATION_SIZE)
    return att


def parse_attestation(att74):
    """``(seq, price, citedHeight, r, s)``; raises on a wrong length."""
    assert_equal(len(att74), ATTESTATION_SIZE)
    seq, price, cited = struct.unpack('<HII', att74[:10])
    return seq, price, cited, int.from_bytes(att74[10:42], 'big'), int.from_bytes(att74[42:74], 'big')


def is_low_s(att74):
    return parse_attestation(att74)[4] <= _N // 2


def verify_attestation(pubkey33, att74, blockhash_hex, backend='python'):
    """True iff the signature is low-S and verifies under ``pubkey33`` over the message for
    ``blockhash_hex`` (the hash of ``citedHeight``).  ``backend='openssl'`` re-encodes to DER and
    asks the framework's ``CECKey`` instead (an independent check; needs libcrypto)."""
    if len(att74) != ATTESTATION_SIZE:
        return False
    seq, price, cited, r, s = parse_attestation(att74)
    if s > _N // 2:
        return False
    msg = attest_message(seq, price, cited, blockhash_hex)
    if backend == 'openssl':
        from .key import CECKey
        key = CECKey()
        key.set_pubkey(bytes(pubkey33))
        return key.verify(msg, der_encode(r, s))
    return ecdsa_verify(bytes(pubkey33), msg, r, s)


# ---------------------------------------------------------------------------
# Fixed regtest keys (secrets are sha256(b'yellowback-regtest-attestor-<i>') /
# sha256(b'yellowback-regtest-bond-<i>'), the POOL_WIFS convention; fixed so the golden vectors
# and yellowback_attest_vectors.json are reproducible)

ATTESTOR_WIFS = [
    'cN1YspvpHoYxFePhqsmA3P33t3N3BQ6TQsgKeh4g6RXvLadakcBg',
    'cV3a1PqGVQE5xGwXKf8PeJAZKofjWvaZwwoAzAPoa11uEnj4SE37',
    'cVwoSEL1WM8dw7SebJMpUgkMeHt2BpJSGQGtyMTuy94BW9teDtYg',
    'cSU3B3SviB5gyqfZMiq9XuzDZMNf2c9zZdYeBcWyWFdrMpRX7fE4',
    'cNSVSiZdLPftiXdLLdFnQ8XXu5pdPUj15Xr72QqNLhEPNr2dWV9V',
]
BOND_WIFS = [
    'cVaWtZtPA4zvLE49z12M47sWD3smxzRvXNeSPLbZwQSm3tQH6u1B',
    'cRXr8Gswr9uVg665Bak7Qs32XzyCPpVGtpT7x4CrzzNvQYbuqSju',
    'cRudaMUEyq8Jf8Wg9z5BsNaGouunnD1x18fw3tDRRsCkRZKsZhTi',
    'cUjxLZVCMgUfTUHjkM7Rh2NR83HafDSdc4LAr59SQeNewFERieoN',
    'cQnkLT2YP7vJmRbDCJFyfEoJiU9BhwG51n8sb93K9ym78XaK2fef',
]


def attestor_keys(n=5):
    """``[(hot_secret32, compressed_pubkey_hex)]`` for attestors ``0..n-1``."""
    out = []
    for wif in ATTESTOR_WIFS[:n]:
        secret = yu.wif_to_secret(wif)
        out.append((secret, bytes_to_hex_str(yu.secret_to_pubkey(secret))))
    return out


def bond_keys(n=5):
    """``[(bond_secret32, compressed_pubkey_hex)]`` for attestors ``0..n-1``."""
    out = []
    for wif in BOND_WIFS[:n]:
        secret = yu.wif_to_secret(wif)
        out.append((secret, bytes_to_hex_str(yu.secret_to_pubkey(secret))))
    return out


# ---------------------------------------------------------------------------
# Scripts (section 3.4)

def bond_script(pubkey33, locktime):
    """``<L> OP_CHECKLOCKTIMEVERIFY OP_DROP <k 33> OP_CHECKSIG``."""
    assert_equal(len(pubkey33), 33)
    return (ym.push_int(locktime) + bytes([ym.OP_CHECKLOCKTIMEVERIFY, ym.OP_DROP])
            + ym.push(bytes(pubkey33)) + bytes([ym.OP_CHECKSIG]))


def carrier_script(pubkey33, bundle_sha256):
    """``OP_SWAP OP_SHA256 <h 32> OP_EQUALVERIFY <pk 33> OP_CHECKSIG`` (71 bytes)."""
    assert_equal(len(pubkey33), 33)
    assert_equal(len(bundle_sha256), 32)
    s = (bytes([OP_SWAP, OP_SHA256]) + ym.push(bytes(bundle_sha256)) + bytes([ym.OP_EQUALVERIFY])
         + ym.push(bytes(pubkey33)) + bytes([ym.OP_CHECKSIG]))
    assert_equal(len(s), CARRIER_SCRIPT_SIZE)
    return s


def parse_carrier_script(script):
    """``(pubkey33, hash32)`` if ``script`` matches ``carrier_script(.,.)`` exactly, else None."""
    if len(script) != CARRIER_SCRIPT_SIZE:
        return None
    h, pk = script[3:35], script[37:70]
    if script != carrier_script(pk, h):
        return None
    return pk, h


p2sh_script = ym.p2sh_script


def carrier_scriptsig(bundle, sig, redeem):
    """``<bundle> <sig> <carrierScript>``, three canonical pushes."""
    assert len(bundle) <= MAX_SCRIPT_ELEMENT_SIZE
    return ym.push(bytes(bundle)) + ym.push(bytes(sig)) + ym.push(bytes(redeem))


# ---------------------------------------------------------------------------
# Payloads, version 3 (section 3.3)

def _v3(type_, body):
    out = ym.PAYLOAD_MAGIC + bytes([PAYLOAD_VERSION_V3, type_]) + body
    assert len(out) <= ym.MAX_PAYLOAD
    return out


def encode_mint_v3(term_class, cents, lock_height, ref_height, owner_pubkey, fee_vout, attest_fee_vout=FEE_VOUT_NONE):
    """52 bytes."""
    assert_equal(len(owner_pubkey), 33)
    return _v3(PAYLOAD_MINT, bytes([term_class & 0xFF]) + struct.pack('<III', cents, lock_height, ref_height)
               + bytes(owner_pubkey) + bytes([fee_vout & 0xFF, attest_fee_vout & 0xFF]))


def encode_transfer_v3(assignments):
    body = ym.encode_transfer(assignments)[4:]
    return _v3(PAYLOAD_TRANSFER, body)


def encode_redeem_v3(ref_height, fee_vout, attest_fee_vout, assignments):
    """11 + 5 * count bytes."""
    body = struct.pack('<I', ref_height) + bytes([fee_vout & 0xFF, attest_fee_vout & 0xFF, len(assignments)])
    for vout, cents in assignments:
        body += bytes([vout & 0xFF]) + struct.pack('<I', cents)
    return _v3(PAYLOAD_REDEEM, body)


def encode_attestor_register(hot_pubkey33, bond_pubkey33, bond_locktime, flags=0):
    """75 bytes."""
    assert_equal(len(hot_pubkey33), 33)
    assert_equal(len(bond_pubkey33), 33)
    return _v3(PAYLOAD_ATTESTOR_REGISTER, bytes(hot_pubkey33) + bytes(bond_pubkey33)
               + struct.pack('<I', bond_locktime) + bytes([flags & 0xFF]))


def encode_claim_notice(vault_txid_hex, vault_vout, ref_height):
    """41 bytes; the txid as its 32 internal bytes (the ``COutPoint`` serialisation, R13)."""
    return _v3(PAYLOAD_CLAIM_NOTICE, bytes.fromhex(vault_txid_hex)[::-1] + bytes([vault_vout & 0xFF])
               + struct.pack('<I', ref_height))


def encode_equivocation():
    """4 bytes: the header alone."""
    return _v3(PAYLOAD_EQUIVOCATION, b'')


def encode_revive(att74):
    """78 bytes: the header and one attestation."""
    assert_equal(len(att74), ATTESTATION_SIZE)
    return _v3(PAYLOAD_ATTESTOR_REVIVE, bytes(att74))


def encode_bundle(atts):
    """``"YA" || 0x01 || count || count x attestation``; refuses more than ``BUNDLE_MAX``."""
    atts = [bytes(a) for a in atts]
    assert len(atts) <= BUNDLE_MAX, 'a bundle holds at most %d attestations' % BUNDLE_MAX
    for a in atts:
        assert_equal(len(a), ATTESTATION_SIZE)
    return BUNDLE_MAGIC + bytes([BUNDLE_VERSION, len(atts)]) + b''.join(atts)


def decode_bundle(bundle):
    """The attestations of a well-formed bundle, or None."""
    if len(bundle) < BUNDLE_HEADER or bundle[:2] != BUNDLE_MAGIC or bundle[2] != BUNDLE_VERSION:
        return None
    count = bundle[3]
    if len(bundle) != BUNDLE_HEADER + count * ATTESTATION_SIZE:
        return None
    return [bundle[BUNDLE_HEADER + i * ATTESTATION_SIZE:BUNDLE_HEADER + (i + 1) * ATTESTATION_SIZE] for i in range(count)]


# ---------------------------------------------------------------------------
# Derived quantities (section 3.7): weight, W9 selection, quantiles

def outpoint_selector(txid_hex, vout):
    """The 36-byte serialised ``COutPoint``: txid internal 32 bytes || vout LE u32 (R13)."""
    return bytes.fromhex(txid_hex)[::-1] + struct.pack('<I', vout)


def bond_weight(bond_zat, age_blocks, age_cap=AGE_CAP):
    """``bondZat * clamp(age, 0, AGE_CAP)``."""
    return int(bond_zat) * ym.clamp(int(age_blocks), 0, age_cap)


def age_origin(register_height, attest_status, trigger_height, founding_window=FOUNDING_WINDOW):
    """``triggerHeight`` for a founding-cohort registrant once the layer is triggered, else
    ``registerHeight`` (section 3.7)."""
    if attest_status != 'UNARMED' and trigger_height is not None and register_height <= trigger_height + founding_window:
        return trigger_height
    return register_height


def select_attestors(blockhash_hex, selector, pool, m_select=M_SELECT, k_slack=K_SLACK):
    """W9: ``pool`` is ``[(seq, weight)]`` (order irrelevant; weights are Python ints, so the
    arithmetic is exact at any width — the C++ uses ``arith_uint256``, R10).

    For round ``i``: ``seed_i = UintToArith256(SHA256(blockHash internal 32 || selector || "S" ||
    u8 i))``.  ``UintToArith256`` reads the 32 digest bytes as a **little-endian** integer
    (``arith_uint256`` stores base-2^32 limbs least significant first, and ``uint256``'s bytes
    are copied limb for limb), hence ``int.from_bytes(..., 'little')`` here — not ``'big'``.
    ``pick = seed_i mod sum(weight)``; chosen = the first ``seq`` in ascending order whose
    cumulative weight exceeds ``pick``; removed; repeat for ``m_select + k_slack`` rounds while
    the pool is non-empty.  A zero total (every remaining weight 0) falls back to ascending
    ``seq`` order for the remaining rounds (the plan states this for the initial pool; applying
    it to a pool that becomes all-zero mid-way keeps the function total)."""
    bh = blockhash_internal(blockhash_hex)
    remaining = sorted((int(seq), int(w)) for seq, w in pool)
    chosen = []
    for i in range(m_select + k_slack):
        if not remaining:
            break
        total = sum(w for _s, w in remaining)
        if total == 0:
            seq, _w = remaining.pop(0)
            chosen.append(seq)
            continue
        seed = int.from_bytes(hashlib.sha256(bh + bytes(selector) + b'S' + bytes([i])).digest(), 'little')
        pick = seed % total
        cumulative = 0
        for j, (seq, w) in enumerate(remaining):
            cumulative += w
            if cumulative > pick:
                chosen.append(seq)
                remaining.pop(j)
                break
    return chosen


def weighted_quantile(pairs, q_bps):
    """``pairs``: ``[(price, weight)]`` or ``[(price, weight, seq)]``.  Sort by price (ties by
    seq); the price at which the cumulative weight first reaches ``ceil(q_bps * total / 10^4)``.
    None for an empty list or a zero total."""
    rows = sorted((tuple(p) + (0,))[:3] for p in pairs)
    total = sum(w for _p, w, _s in rows)
    if not rows or total == 0:
        return None
    threshold = ym.ceil_div(q_bps * total, ym.BPS)
    cumulative = 0
    for price, w, _seq in rows:
        cumulative += w
        if cumulative >= threshold:
            return price
    return rows[-1][0]


def bundle_stat(atts_with_weights, q_low_bps=Q_LOW_BPS, q_high_bps=Q_HIGH_BPS, m_select=M_SELECT):
    """``(aMint, aClaim)`` over ``[(att74 | (seq, price), weight)]``; None when fewer than
    ``m_select`` attestations."""
    rows = []
    for item, w in atts_with_weights:
        if isinstance(item, (bytes, bytearray)):
            seq, price, _c, _r, _s = parse_attestation(bytes(item))
        else:
            seq, price = item
        rows.append((price, int(w), seq))
    if len(rows) < m_select:
        return None
    return weighted_quantile(rows, q_low_bps), weighted_quantile(rows, q_high_bps)


# ---------------------------------------------------------------------------
# Raw builders (section 3.5).  ``node`` needs listunspent / getnewaddress / signrawtransaction
# (and sendrawtransaction / getblockcount where stated); the FakeNode of the unit tests suffices.

def _fund(node, vout, needed, extra_vin=(), lock_time=0, expiry=0, extra_in_value=0):
    """Funding inputs for ``needed`` zat of outputs plus the network fee, ``extra_vin``
    (``[(txid, n, sequence)]``, e.g. a carrier) appended after them, change last.  Returns the
    hex after ``signrawtransaction`` (``complete`` is False while a carrier input is unsigned)."""
    needed_total = needed + YELLOWBACK_FEE - extra_in_value
    utxos, total = yu._select_funding(node, max(needed_total, 0))
    change = total - needed_total
    vout = list(vout)
    if change > 0:
        vout.append((change, yu._spk_of_address(node.getnewaddress())))
    vin = [(u['txid'], u['vout'], b'', 0xFFFFFFFF) for u in utxos]
    vin += [(t, n, b'', seq) for t, n, seq in extra_vin]
    raw = ym.serialize_tx_v4(vin, vout, lock_time, expiry)
    return node.signrawtransaction(bytes_to_hex_str(raw))['hex'], len(utxos)


def send_and_lock(node, hex_):
    """``sendrawtransaction`` then ``lockunspent`` the inputs: ``_select_funding`` reads
    ``listunspent(1)``, which knows nothing of the mempool, so two hand-built transactions in one
    block would otherwise spend the same coin (the second is a silent mempool conflict).  The
    locks fall away with the next restart; nothing else reads them."""
    txid = node.sendrawtransaction(hex_)
    vin = node.decoderawtransaction(hex_)['vin']
    node.lockunspent(False, [{'txid': i['txid'], 'vout': int(i['vout'])} for i in vin if 'txid' in i])
    return txid


def build_register_tx(node, hot_pubkey, bond_pubkey, bond_zat=BOND_MIN_ZAT, lock_blocks=BOND_MIN_LOCK, flags=0,
                      locktime=None, expiry=0):
    """The ATTESTOR_REGISTER of section 3.5: ``vout[0]`` the bond (P2SH of ``bond_script``),
    ``vout[1]`` the payload, change.  ``locktime`` defaults to ``getblockcount() + 1 +
    lock_blocks`` (REG-A1 wants ``bondLocktime >= H + BOND_MIN_LOCK`` at the mining height
    ``H``).  Pubkeys as hex or bytes.  Returns ``(hex, locktime)``."""
    hot = hex_str_to_bytes(hot_pubkey) if isinstance(hot_pubkey, str) else bytes(hot_pubkey)
    bond = hex_str_to_bytes(bond_pubkey) if isinstance(bond_pubkey, str) else bytes(bond_pubkey)
    if locktime is None:
        locktime = node.getblockcount() + 1 + lock_blocks
    payload = encode_attestor_register(hot, bond, locktime, flags)
    vout = [
        (int(bond_zat), ym.p2sh_script(bond_script(bond, locktime))),
        (0, bytes([ym.OP_RETURN]) + ym.push(payload)),
    ]
    hex_, _n = _fund(node, vout, int(bond_zat), expiry=expiry)
    return hex_, locktime


def build_carrier_tx(node, bundle, carrier_pubkey=None, carrier_wif=None, send=True, expiry=0):
    """The carrier step (W7/R2): one output ``P2SH(carrier_script(pk, SHA256(bundle)))`` of
    ``CARRIER_VALUE``, change; broadcast with ``sendrawtransaction`` unless ``send=False``.
    ``carrier_pubkey`` defaults to a fresh key of ``node`` (so ``dumpprivkey`` can sign the
    spend); pass ``carrier_wif`` for a key the node does not hold.  Returns the carrier dict
    ``{txid, vout, outpoint, pubkey, redeem, bundle, hash, hex, wif}`` that ``spend_carrier``
    and the builders take."""
    bundle = bytes(bundle)
    if carrier_pubkey is None:
        if carrier_wif is not None:
            carrier_pubkey = bytes_to_hex_str(yu.secret_to_pubkey(yu.wif_to_secret(carrier_wif)))
        else:
            carrier_pubkey = yu.node_pubkey(node)
    pk = hex_str_to_bytes(carrier_pubkey) if isinstance(carrier_pubkey, str) else bytes(carrier_pubkey)
    h = hashlib.sha256(bundle).digest()
    redeem = carrier_script(pk, h)
    hex_, _n = _fund(node, [(CARRIER_VALUE, ym.p2sh_script(redeem))], CARRIER_VALUE, expiry=expiry)
    txid = node.sendrawtransaction(hex_) if send else ym.tx_from_hex(hex_).txid
    return {'txid': txid, 'vout': 0, 'outpoint': (txid, 0), 'pubkey': bytes_to_hex_str(pk), 'redeem': redeem,
            'bundle': bundle, 'hash': bytes_to_hex_str(h), 'hex': hex_, 'wif': carrier_wif}


def spend_carrier(node, raw_hex, vin_index, carrier, carrier_wif=None, branch_id=SIGNING_BRANCH_ID, bundle=None):
    """Sign input ``vin_index`` of ``raw_hex`` as the carrier: ZIP-243 ``SignatureHash`` with
    ``scriptCode`` = the redeem script and ``amount = CARRIER_VALUE`` (exactly as
    ``build_vault_spend_raw`` signs the owner path), low-S DER + SIGHASH_ALL, scriptSig
    ``<bundle> <sig> <carrierScript>``.  ``bundle`` overrides the carrier's (the malleation
    case, R2).  Returns the hex."""
    from .mininode import CTransaction
    from .script import CScript, SIGHASH_ALL, SignatureHash
    wif = carrier_wif or carrier.get('wif') or node.dumpprivkey(yu.pubkey_to_address(hex_str_to_bytes(carrier['pubkey'])))
    secret = yu.wif_to_secret(wif)
    assert_equal(bytes_to_hex_str(yu.secret_to_pubkey(secret)), carrier['pubkey'])
    tx = CTransaction()
    tx.deserialize(BytesIO(hex_str_to_bytes(raw_hex)))
    redeem = bytes(carrier['redeem'])
    sighash = SignatureHash(CScript(redeem), tx, vin_index, SIGHASH_ALL, CARRIER_VALUE, branch_id)[0]
    r, s = ecdsa_sign(secret, sighash)
    sig = der_encode(r, s) + bytes([SIGHASH_ALL])
    tx.vin[vin_index].scriptSig = carrier_scriptsig(carrier['bundle'] if bundle is None else bundle, sig, redeem)
    return bytes_to_hex_str(tx.serialize())


def _carrier_vin(carrier):
    return (carrier['txid'], int(carrier['vout']), 0xFFFFFFFF)


def build_mint_tx_v3(node, cents, lock_blocks, ref_height, collateral_zat, fee_addr=None, carrier=None,
                     attest_fee=None, owner_pubkey=None, fee_zat_override=None, term_class=None, expiry=None,
                     carrier_wif=None):
    """``build_mint_tx`` with the v3 shape: vault ``vout[0]``, token ``vout[1]``, payload
    ``vout[2]`` (version 3), pool fee ``vout[3]`` when ``fee_addr``, attestor fee (``attest_fee
    = (address, zat)``, ``P2PKH(bondPubKey)`` of a selected attestor) next, change last; the
    carrier input (``carrier`` from ``build_carrier_tx``, confirmed) as ``vin[last]``, signed
    here.  Returns ``(hex, owner_pubkey_hex)``."""
    if owner_pubkey is None:
        owner_pubkey = yu.node_pubkey(node)
    owner = hex_str_to_bytes(owner_pubkey)
    if term_class is None:
        term_class = yu.term_class_of(lock_blocks)
        assert term_class is not None, 'lock_blocks %d is outside every class' % lock_blocks
    class_index = 'ABC'.index(term_class) if isinstance(term_class, str) else int(term_class)
    lock_height = ref_height + lock_blocks
    vault = ym.vault_script(lock_height, owner, lock_height + GRACE)
    vout = [
        (collateral_zat, ym.p2sh_script(vault)),
        (TOKEN_VALUE, ym.p2pkh_script(ym.hash160(owner))),
        None,   # the payload, once the vout indices are known
    ]
    needed = collateral_zat + TOKEN_VALUE
    fee_vout = FEE_VOUT_NONE
    if fee_addr:
        enforcement_fee = yu.fee_zat(collateral_zat) if fee_zat_override is None else fee_zat_override
        fee_vout = len(vout)
        vout.append((enforcement_fee, yu._spk_of_address(fee_addr)))
        needed += enforcement_fee
    attest_fee_vout = FEE_VOUT_NONE
    if attest_fee:
        attest_fee_vout = len(vout)
        vout.append((int(attest_fee[1]), yu._spk_of_address(attest_fee[0])))
        needed += int(attest_fee[1])
    payload = encode_mint_v3(class_index, cents, lock_height, ref_height, owner, fee_vout, attest_fee_vout)
    vout[2] = (0, bytes([ym.OP_RETURN]) + ym.push(payload))
    extra_vin = [_carrier_vin(carrier)] if carrier else []
    hex_, n_funding = _fund(node, vout, needed, extra_vin, expiry=ref_height + REF_WINDOW if expiry is None else expiry,
                            extra_in_value=CARRIER_VALUE if carrier else 0)
    if carrier:
        hex_ = spend_carrier(node, hex_, n_funding, carrier, carrier_wif)
    return hex_, owner_pubkey


def post_notice_raw(node, vault, ref_height, carrier, carrier_wif=None, expiry=None):
    """CLAIM_NOTICE (section 3.5): funding inputs plus the carrier; outputs the payload and
    change.  ``vault`` is ``(txid, vout)``, ``'txid:n'`` or a dict with ``txid``/``vout``."""
    txid, n = yu._outpoint(vault)
    payload = encode_claim_notice(txid, n, ref_height)
    vout = [(0, bytes([ym.OP_RETURN]) + ym.push(payload))]
    hex_, n_funding = _fund(node, vout, 0, [_carrier_vin(carrier)],
                            expiry=ref_height + REF_WINDOW if expiry is None else expiry, extra_in_value=CARRIER_VALUE)
    return spend_carrier(node, hex_, n_funding, carrier, carrier_wif)


def equivocation_raw(node, carrier, carrier_wif=None, expiry=0):
    """EQUIVOCATION: ``carrier`` (from ``build_carrier_tx(node, encode_bundle([a, b]))``,
    confirmed) plus funding; outputs the empty-bodied payload ``0x07`` and change."""
    atts = decode_bundle(carrier['bundle'])
    assert atts is not None and len(atts) == 2, 'an equivocation carrier holds exactly two attestations'
    vout = [(0, bytes([ym.OP_RETURN]) + ym.push(encode_equivocation()))]
    hex_, n_funding = _fund(node, vout, 0, [_carrier_vin(carrier)], expiry=expiry, extra_in_value=CARRIER_VALUE)
    return spend_carrier(node, hex_, n_funding, carrier, carrier_wif)


def revive_raw(node, att74, expiry=0):
    """ATTESTOR_REVIVE: payload ``0x08`` carrying one attestation; funded from ``node``; no
    carrier.  Returns the hex."""
    vout = [(0, bytes([ym.OP_RETURN]) + ym.push(encode_revive(att74)))]
    hex_, _n = _fund(node, vout, 0, expiry=expiry)
    return hex_


def withdraw_bond_raw(node, rec, bond_secret32, to=None, branch_id=SIGNING_BRANCH_ID, lock_time=None):
    """The bond spend (section 3.5 ``yed_withdrawbond``'s shape, built here): ``vin[0]`` the
    bond outpoint with scriptSig ``<sig> <bondScript>`` signed by ``bond_secret32`` over the
    ZIP-243 sighash (``scriptCode`` = the bond script, ``amount = bondZat``), ``nSequence
    0xFFFFFFFE``, ``nLockTime = bondLocktime`` (CLTV); one output of ``bondZat -
    YELLOWBACK_FEE`` to ``to`` (default a fresh address of ``node``).  ``rec`` is a
    ``yed_listattestors`` row.  Returns the hex; the caller mines it at or past the locktime."""
    from .mininode import CTransaction
    from .script import CScript, SIGHASH_ALL, SignatureHash
    bond_pub = yu.secret_to_pubkey(bond_secret32)
    locktime = int(rec['bondLocktime'])
    redeem = bond_script(bond_pub, locktime)
    value = int(rec['bondZat']) - YELLOWBACK_FEE
    dest = to or node.getnewaddress()
    vin = [(rec['bondOutpoint']['txid'], int(rec['bondOutpoint']['vout']), b'', 0xFFFFFFFE)]
    raw = ym.serialize_tx_v4(vin, [(value, yu._spk_of_address(dest))], locktime if lock_time is None else lock_time, 0)
    tx = CTransaction()
    tx.deserialize(BytesIO(raw))
    sighash = SignatureHash(CScript(redeem), tx, 0, SIGHASH_ALL, int(rec['bondZat']), branch_id)[0]
    r, s = ecdsa_sign(bond_secret32, sighash)
    sig = der_encode(r, s) + bytes([SIGHASH_ALL])
    tx.vin[0].scriptSig = ym.push(sig) + ym.push(redeem)
    return bytes_to_hex_str(tx.serialize())


def bond_secret_for(rec):
    """The fixed bond secret of a ``yed_listattestors`` row registered with the fixed key set."""
    hot_by_pubkey = {pk: i for i, (_s, pk) in enumerate(attestor_keys(len(ATTESTOR_WIFS)))}
    i = hot_by_pubkey.get(rec['attestorPubKey'])
    assert i is not None, 'seq %s was not registered with a fixed key' % rec.get('seq')
    return bond_keys(len(BOND_WIFS))[i][0]


# ---------------------------------------------------------------------------
# Node drivers, against the section 4.5 RPC surface (Phase A2+; untestable until then)

_SEQ_SECRETS = {}     # seq -> hot secret, filled by register_and_arm / hot_secret_for


def hot_secret_for(node, seq):
    """The hot secret of attestor ``seq``: from the cache, else by matching
    ``yed_listattestors`` against the fixed key set."""
    if seq not in _SEQ_SECRETS:
        by_pubkey = {pk: secret for secret, pk in attestor_keys(len(ATTESTOR_WIFS))}
        for rec in node.yed_listattestors():
            pk = rec['attestorPubKey']
            if pk in by_pubkey:
                _SEQ_SECRETS[int(rec['seq'])] = by_pubkey[pk]
    assert seq in _SEQ_SECRETS, 'no fixed regtest key registered as seq %d' % seq
    return _SEQ_SECRETS[seq]


def hot_wif_for(node, seq):
    """The WIF of attestor ``seq``'s hot key. Never ``ATTESTOR_WIFS[seq]``: register_and_arm puts
    its registrations in one block, and the block's transaction order, not the key index, decides
    which fixed key became which seq (the intermittent failures of 2026-09-24)."""
    secret = hot_secret_for(node, seq)
    for wif in ATTESTOR_WIFS:
        if yu.wif_to_secret(wif) == secret:
            return wif
    raise AssertionError('seq %d has no fixed hot key' % seq)


def feed(node, seq, price_usd, cited=None, secret=None):
    """Sign one attestation for ``seq`` at ``price_usd`` (decimal dollars) citing ``cited``
    (default ``tip - REF_LAG``) and ``yed_addattestation`` it on ``node``.  Returns
    ``(hex, result)``."""
    if cited is None:
        cited = node.getblockcount() - REF_LAG
    secret = secret or hot_secret_for(node, seq)
    att = sign_attestation(secret, seq, yu.usd_to_micro(price_usd), cited, node.getblockhash(cited))
    hex_ = bytes_to_hex_str(att)
    return hex_, node.yed_addattestation(hex_)


def feed_all(node, prices, cited=None):
    """``feed`` for every ``seq -> usd`` in ``prices``; returns ``{seq: (hex, result)}``."""
    return {seq: feed(node, seq, usd, cited) for seq, usd in prices.items()}


def selection_pool(node, ref_height):
    """``[(seq, weight)]`` of ``Snapshots[R].seated \\ pinnedSeqs`` from ``yed_listattestors(R)``
    (its ``seated``/``pinned`` flags and ``weight`` field, section 4.5)."""
    return [(int(r['seq']), int(r['weight'])) for r in node.yed_listattestors(ref_height)
            if r.get('seated') and not r.get('pinned')]


def build_bundle(node, ref_height, selector, prices, cited=None, check=True):
    """The bundle for ``(R, selector)`` signed in Python: ``select_attestors`` over
    ``selection_pool`` (the second implementation of W9), each selected ``seq`` signed at
    ``prices[seq]`` (usd; a ``seq`` missing from ``prices`` is left out) citing ``cited``
    (default ``R``).  With ``check`` the selected set is asserted equal to
    ``yed_getselection``'s.  Returns ``(bundle_bytes, selected_seqs)``."""
    blockhash = node.getblockhash(ref_height)
    selected = select_attestors(blockhash, selector, selection_pool(node, ref_height))
    if check:
        got = sorted(int(s['seq']) for s in node.yed_getselection(ref_height, bytes_to_hex_str(selector))['selected'])
        assert_equal(got, sorted(selected))
    cited = ref_height if cited is None else cited
    atts = [sign_attestation(hot_secret_for(node, seq), seq, yu.usd_to_micro(prices[seq]), cited, node.getblockhash(cited))
            for seq in selected if seq in prices]
    return encode_bundle(atts), selected


def register_and_arm(test, n=ATTEST_ARM_MIN, funder=None, miner=None, bond_zat=BOND_MIN_ZAT, lock_blocks=BOND_MIN_LOCK):
    """Register attestors ``0..n-1`` (fixed keys; ``build_register_tx`` funded by ``funder``,
    default node 0, in one block), import each hot key into its attestor wallet (node 6 for
    0-2, node 7 for 3-4, when present, so ``yed_signattestation`` works there), mine
    ``BOND_MATURITY`` blocks on ``miner`` (default the first pool) and assert ``TRIGGERED`` at
    exactly that height (ARM-1) when ``n >= ATTEST_ARM_MIN``, then ``ATTEST_ARM_DELAY`` more and
    assert ``ARMED`` on every enforcing node (ARM-2) plus ``assert_same_statehash``.  ``test`` is
    the ``YellowbackTestFramework``.  Returns ``[seq]`` in registration order."""
    nodes = test.nodes
    funder = nodes[USER] if funder is None else test._node(funder)
    miner = nodes[POOLS[0]] if miner is None else test._node(miner)
    if not has_rpc(funder, 'yed_listattestors'):
        # A3 before A2: the node cannot list attestors; register one per block and count.
        return _register_and_arm_offline(test, n, funder, miner, bond_zat, lock_blocks)
    hot, bond = attestor_keys(n), bond_keys(n)
    for i in range(n):
        hex_, _lt = build_register_tx(funder, hot[i][1], bond[i][1], bond_zat, lock_blocks)
        send_and_lock(funder, hex_)
        wallet = ATTESTOR_A if i < 3 else ATTESTOR_B
        if wallet < len(nodes) and nodes[wallet] is not None:
            nodes[wallet].importprivkey(ATTESTOR_WIFS[i], 'yellowback-attestor', False)
            nodes[wallet].importprivkey(BOND_WIFS[i], 'yellowback-bond', False)
    test.sync_all()
    test.mine(miner, 1)
    register_height = miner.getblockcount()
    test.mine(miner, BOND_MATURITY)
    mature_height = register_height + BOND_MATURITY
    assert_equal(miner.getblockcount(), mature_height)
    enforcing = test.enforcing_nodes()
    for node in enforcing:
        for rec in node.yed_listattestors():
            if rec['attestorPubKey'] in [pk for _s, pk in hot]:
                assert_equal(rec['status'], 'ELIGIBLE')
                _SEQ_SECRETS[int(rec['seq'])] = dict((pk, s) for s, pk in hot)[rec['attestorPubKey']]
    if n >= ATTEST_ARM_MIN:
        for node in enforcing:
            attest = node.yed_getinfo()['attest']
            assert_equal((attest['status'], attest['triggerHeight'], attest['armHeight']),
                         ('TRIGGERED', mature_height, mature_height + ATTEST_ARM_DELAY))
        test.mine(miner, ATTEST_ARM_DELAY)
        for node in enforcing:
            assert_equal(node.yed_getinfo()['attest']['status'], 'ARMED')
    yu.assert_same_statehash(enforcing, 'register_and_arm')
    seqs = sorted(seq for seq, s in _SEQ_SECRETS.items() if s in [h for h, _pk in hot])
    # Mirror the chain into the offline registry so the wallet helpers work either way.
    for node in enforcing:
        for rec in node.yed_listattestors():
            if int(rec['seq']) in seqs and int(rec['seq']) not in REGISTRY['attestors']:
                REGISTRY['attestors'][int(rec['seq'])] = {'register': rec['registerHeight'], 'bond_zat': int(rec['bondZat']),
                                                          'status': rec['status'], 'signer': None, 'secret': _SEQ_SECRETS[int(rec['seq'])],
                                                          'bond_key_address': rec.get('bondKeyAddress')}
        break
    REGISTRY['next_seq'] = max(REGISTRY['next_seq'], max(seqs) + 1 if seqs else 0)
    _recompute_arming()
    if REGISTRY['arm'] is not None and miner.getblockcount() < REGISTRY['arm'] + REF_LAG:
        test.mine(miner, REGISTRY['arm'] + REF_LAG - miner.getblockcount())
    return seqs


def assert_void_reason(node, txid, rule):
    """The vault minted by ``txid`` is VOID with ``voidReason`` naming ``rule`` (exact, or the
    rule identifier as a prefix of a longer reason)."""
    v = node.yed_getvault(txid)
    assert_equal(v['status'], 'VOID')
    reason = v['voidReason']
    assert reason == rule or reason.startswith(rule), 'voidReason %r does not name %s' % (reason, rule)
    return v


# ---------------------------------------------------------------------------
# A3: the wallet's two-step flow (W7) and an offline registry of attestors
#
# Every v3 wallet command that reads a price is two transactions: the carrier funding transaction,
# then the main one after the carrier confirms.  With ``wait=True`` the RPC blocks until then,
# so a single-threaded test would wait on itself for the block; ``two_step`` runs the call while
# a helper thread mines the carrier's block on a pool as soon as it sees the carrier in that
# pool's mempool.  ``two_step_pending`` is the ``wait=False`` flow: the pending shape comes back,
# the test mines, and the wallet's completion thread commits the main transaction.
#
# The node's ``yed_listattestors`` / ``yed_getselection`` / ``yed_getinfo.attest.status`` arrive
# with Phase A2.  Until they are present the helpers below keep an offline registry: seq is
# assigned in block order (REG-A1's ``AttestorSeq.next++``), so registering ONE attestor per
# block makes seq = registration order; the arming heights follow ARM-1/2 by block counting
# (TRIGGERED when the ATTEST_ARM_MIN-th bond matures, ARMED ATTEST_ARM_DELAY later); weights are
# ``bond_weight`` with the founding-cohort ``age_origin``; seated = the N_SLOTS heaviest
# ELIGIBLE.  When the node RPCs exist they are preferred.

import threading
import time
from decimal import Decimal

REGISTRY = {
    'next_seq': 0,
    'attestors': {},     # seq -> {'register': height, 'bond_zat': zat, 'status': 'ELIGIBLE'|'DORMANT'|'EJECTED'|'WITHDRAWN', 'signer': node|None, 'secret': bytes|None}
    'trigger': None,     # ARM-1 height
    'arm': None,         # ARM-2 height
}


def has_rpc(node, name):
    """True iff ``node`` answers ``help <name>`` without 'Method not found' / unknown command."""
    try:
        text = node.help(name)
    except Exception:
        return False
    return not text.startswith('help: unknown command')


def wait_for_spender(node, txid, timeout=60):
    """The txid in ``node``'s mempool that spends an output of ``txid`` (the main transaction of
    a two-step command); raises after ``timeout`` seconds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for cand in node.getrawmempool():
            try:
                raw = node.getrawtransaction(cand, 1)
            except Exception:
                continue
            if any(vin.get('txid') == txid for vin in raw['vin']):
                return cand
        time.sleep(0.2)
    raise AssertionError('no transaction spending %s appeared in the mempool within %ds' % (txid, timeout))


def _is_carrier_tx(raw):
    return (len(raw['vout']) >= 1 and raw['vout'][0]['valueZat'] == CARRIER_VALUE
            and raw['vout'][0]['scriptPubKey'].get('type') == 'scripthash')


class _CarrierMiner(threading.Thread):
    """Mine one block on node ``miner_index`` as soon as a carrier that was not in its mempool at
    start appears there (a private RPC connection: proxies are not shared across threads)."""

    def __init__(self, miner_index, timeout):
        super().__init__(daemon=True)
        from .util import get_rpc_proxy, rpc_url
        self.proxy = get_rpc_proxy(rpc_url(miner_index), miner_index, timeout=timeout + 30)
        self.timeout = timeout
        self.before = set(self.proxy.getrawmempool())
        self.error = None
        self.mined = None

    def run(self):
        try:
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                for txid in self.proxy.getrawmempool():
                    if txid in self.before:
                        continue
                    if _is_carrier_tx(self.proxy.getrawtransaction(txid, 1)):
                        self.mined = self.proxy.generate(1)[0]
                        return
                time.sleep(0.1)
            self.error = 'no carrier reached the miner within %ds' % self.timeout
        except Exception as e:      # pragma: no cover - surfaced by two_step
            self.error = str(e)


def two_step(test, node, method, *args, miner=None, timeout=120):
    """Call ``node.<method>(*args, True)`` (``wait=True``) while a helper thread mines the
    carrier's block on ``miner`` (index; default the first pool).  Returns the RPC's full result
    (``pending`` False).  The main transaction is left in the mempool for the caller to mine, as
    the v2 flow scripts expect; ``test.sync_all()`` is run before returning."""
    miner_index = POOLS[0] if miner is None else (miner if isinstance(miner, int) else test.nodes.index(miner))
    t = _CarrierMiner(miner_index, timeout)
    t.start()
    try:
        result = getattr(node, method)(*args, True)
    finally:
        t.join(timeout=5)
    if t.error and result.get('pending', False):
        raise AssertionError(t.error)
    assert_equal(result.get('pending'), False)
    test.sync_all()
    return result


def two_step_pending(test, node, method, *args, miner=None, timeout=60, sync=None):
    """The ``wait=False`` flow: call, mine the carrier's block, wait for the wallet's completion
    thread to commit the main transaction.  Returns ``(pending_result, main_txid)``; the main
    transaction is in the mempool.  ``sync`` replaces ``test.sync_all`` (a split network)."""
    sync = sync or test.sync_all
    res = getattr(node, method)(*args, False)
    assert_equal(res['pending'], True)
    sync()
    test._node(POOLS[0] if miner is None else miner).generate(1)
    sync(blocks_only=True) if sync is test.sync_all else sync()
    txid = wait_for_spender(node, res['carrierTxid'], timeout)
    sync()
    return res, txid


def _bundle_arg(test, node, selector, prices, ref_height):
    """``''`` when unarmed at R (the carrier is still created; the wallet ignores the bundle),
    else the offline bundle for (R, selector) at ``prices``."""
    if not arming_state(node, ref_height)['armed']:
        return ''
    if prices is None:
        raise AssertionError('armed at %d: pass prices={seq: usd} (or a default usd) for the bundle' % ref_height)
    return offline_bundle_hex(test, node, ref_height, selector, prices)


def wallet_mint(test, node, cents, lock_blocks, from_addr='', prices=None, miner=None, bundle_hex=None):
    """``yed_mint`` through ``two_step``.  ``prices``: ``{seq: usd}`` or one usd for every
    selected attestor (needed while armed; the bundle is built offline for R = tip - REF_LAG).
    ``bundle_hex`` overrides the bundle (the refusal cases)."""
    ref_height = node.yed_getinfo()['height'] - REF_LAG
    if bundle_hex is None:
        bundle_hex = _bundle_arg(test, node, b'', prices, ref_height)
    return two_step(test, node, 'yed_mint', cents, lock_blocks, from_addr, bundle_hex, miner=miner)


def wallet_claim(test, node, vault_txid, to='', prices=None, miner=None, bundle_hex=None):
    """``yed_claim`` through ``two_step``; the selector is the vault outpoint, R the index tip."""
    ref_height = node.yed_getinfo()['height']
    if bundle_hex is None:
        bundle_hex = _bundle_arg(test, node, outpoint_selector(vault_txid, 0), prices, ref_height)
    return two_step(test, node, 'yed_claim', vault_txid, to, bundle_hex, miner=miner)


def wallet_notice(test, node, vault_txid, prices=None, miner=None, bundle_hex=None):
    """``yed_claimnotice`` through ``two_step``."""
    ref_height = node.yed_getinfo()['height']
    if bundle_hex is None:
        bundle_hex = _bundle_arg(test, node, outpoint_selector(vault_txid, 0), prices, ref_height)
    return two_step(test, node, 'yed_claimnotice', vault_txid, bundle_hex, miner=miner)


def wallet_report_equivocation(test, node, hex_a, hex_b, miner=None):
    return two_step(test, node, 'yed_reportequivocation', hex_a, hex_b, miner=miner)


# --- the offline registry ---------------------------------------------------------------------

def arming_state(node, ref_height=None):
    """``{'armed', 'status', 'trigger', 'arm'}`` at ``ref_height`` (default the tip): from
    ``yed_getinfo().attest`` when the node renders ``status`` (A2), else from the registry."""
    info = node.yed_getinfo()
    attest = info.get('attest') or {}
    if 'status' in attest and ref_height is None:
        return {'armed': attest['status'] == 'ARMED', 'status': attest['status'],
                'trigger': attest.get('triggerHeight'), 'arm': attest.get('armHeight')}
    h = info['height'] if ref_height is None else ref_height
    trigger, arm = REGISTRY['trigger'], REGISTRY['arm']
    if arm is not None and h >= arm:
        status = 'ARMED'
    elif trigger is not None and h >= trigger:
        status = 'TRIGGERED'
    else:
        status = 'UNARMED'
    return {'armed': status == 'ARMED', 'status': status, 'trigger': trigger, 'arm': arm}


def _recompute_arming():
    """ARM-1/2 by block counting: TRIGGERED at the SNAP where the ATTEST_ARM_MIN-th registered
    attestor matures (registerHeight + BOND_MATURITY), ARMED ATTEST_ARM_DELAY later."""
    mature = sorted(a['register'] + BOND_MATURITY for a in REGISTRY['attestors'].values())
    if len(mature) >= ATTEST_ARM_MIN and REGISTRY['trigger'] is None:
        REGISTRY['trigger'] = mature[ATTEST_ARM_MIN - 1]
        REGISTRY['arm'] = REGISTRY['trigger'] + ATTEST_ARM_DELAY


def _note_registration(register_height, bond_zat, signer=None, secret=None, bond_key_address=None):
    seq = REGISTRY['next_seq']
    REGISTRY['next_seq'] += 1
    REGISTRY['attestors'][seq] = {'register': register_height, 'bond_zat': int(bond_zat), 'status': 'ELIGIBLE',
                                  'signer': signer, 'secret': secret, 'bond_key_address': bond_key_address}
    if secret is not None:
        _SEQ_SECRETS[seq] = secret
    _recompute_arming()
    return seq


def note_attestor_status(seq, status):
    """Tell the registry about a status change the test caused (EJECTED after an equivocation,
    DORMANT after the dormancy pass, WITHDRAWN after yed_withdrawbond, ELIGIBLE after a revival)."""
    REGISTRY['attestors'][seq]['status'] = status


def register_wallet_attestor(test, node, bond_yec, lock_blocks=BOND_MIN_LOCK, flags=0, miner=None):
    """``yed_registerattestor`` on ``node`` (a wallet node), mined in its own block so seq =
    registration order; recorded in the registry with ``node`` as its signer.  Returns
    ``(result, seq)``."""
    res = node.yed_registerattestor(bond_yec, lock_blocks, flags)
    test.sync_all()
    test.mine(POOLS[0] if miner is None else miner)
    seq = _note_registration(node.getblockcount(), res['bondZat'], signer=node, bond_key_address=res['bondKeyAddress'])
    return res, seq


def offline_selection(node, ref_height, selector):
    """``selected(R, selector)`` from the registry (or ``yed_getselection`` when the node has it):
    W9 over seated(R) \\ pinned with weight(s, R)."""
    if has_rpc(node, 'yed_getselection'):
        return sorted(int(s['seq']) for s in node.yed_getselection(ref_height, bytes_to_hex_str(bytes(selector)))['selected'])
    state = arming_state(node, ref_height)
    eligible = []
    for seq, a in REGISTRY['attestors'].items():
        if a['status'] != 'ELIGIBLE' or a['register'] + BOND_MATURITY > ref_height:
            continue
        origin = age_origin(a['register'], state['status'], state['trigger'])
        eligible.append((seq, bond_weight(a['bond_zat'], ref_height - origin)))
    seated = sorted(eligible, key=lambda sw: (-sw[1], sw[0]))[:N_SLOTS]
    return select_attestors(node.getblockhash(ref_height), selector, seated)


def _sign_for(node, seq, price_micro, cited, blockhash):
    a = REGISTRY['attestors'].get(seq, {})
    if a.get('secret') is not None or seq in _SEQ_SECRETS:
        return sign_attestation(a.get('secret') or _SEQ_SECRETS[seq], seq, price_micro, cited, blockhash)
    signer = a.get('signer')
    assert signer is not None, 'no way to sign for seq %d' % seq
    return hex_str_to_bytes(signer.yed_signattestation(seq, price_micro, cited)['hex'])


def attested_micro(usd, cited_height):
    """The micro-USD price the offline bundles attest for ``usd`` at ``cited_height``: a few
    hundred micro-USD that depend on the height — one price per (seq, height), which the signing
    guard (S16) demands, and a different one at every height, so no attestor repeats one price
    across bundles and PIN-2 never pins a test attestor."""
    return yu.usd_to_micro(usd) + ((int(cited_height) * 7) % 9) * 100


def offline_bundle(test, node, ref_height, selector, prices, cited=None, jitter=True):
    """The bundle for (R, selector): every selected seq that ``prices`` covers (``{seq: usd}``,
    or one usd for all) signs citing ``cited`` (default R) — fixed-key attestors in Python,
    wallet-registered ones through their node's ``yed_signattestation``.  ``jitter`` adds a few
    hundred micro-USD that change per call so no attestor ever repeats one price across bundles
    (PIN-2 would pin it and the node's selection would drift from this one).  Returns
    ``(bundle_bytes, selected)``."""
    selected = offline_selection(node, ref_height, selector)
    cited = ref_height if cited is None else cited
    blockhash = node.getblockhash(cited)
    if not isinstance(prices, dict):
        prices = {seq: prices for seq in selected}
    delta = attested_micro(0, cited) if jitter else 0
    atts = []
    for seq in selected:
        if seq not in prices:
            continue
        micro = yu.usd_to_micro(prices[seq]) + delta
        atts.append(_sign_for(node, seq, micro, cited, blockhash))
    return encode_bundle(atts), selected


def offline_bundle_hex(test, node, ref_height, selector, prices, **kw):
    return bytes_to_hex_str(offline_bundle(test, node, ref_height, selector, prices, **kw)[0])


def _register_and_arm_offline(test, n, funder, miner, bond_zat, lock_blocks):
    """``register_and_arm`` without the A2 node RPCs: one registration per block (seq = order),
    the hot and bond keys imported into the attestor wallets, then mining to ARMED + REF_LAG by
    block counting.  Returns ``[seq]``."""
    nodes = test.nodes
    hot, bond = attestor_keys(n), bond_keys(n)
    seqs = []
    for i in range(n):
        hex_, _lt = build_register_tx(funder, hot[i][1], bond[i][1], bond_zat, lock_blocks)
        funder.sendrawtransaction(hex_)
        wallet = ATTESTOR_A if i < 3 else ATTESTOR_B
        signer = None
        if wallet < len(nodes) and nodes[wallet] is not None:
            nodes[wallet].importprivkey(ATTESTOR_WIFS[i], 'yellowback-attestor', False)
            nodes[wallet].importprivkey(BOND_WIFS[i], 'yellowback-bond', False)
            signer = nodes[wallet]
        test.sync_all()
        test.mine(miner)
        seqs.append(_note_registration(miner.getblockcount(), bond_zat, signer=signer, secret=hot[i][0],
                                       bond_key_address=yu.pubkey_to_address(hex_str_to_bytes(bond[i][1]))))
    if REGISTRY['arm'] is not None:
        target = REGISTRY['arm'] + REF_LAG
        if miner.getblockcount() < target:
            test.mine(miner, target - miner.getblockcount())
    yu.assert_same_statehash(test.enforcing_nodes(), 'register_and_arm')
    return seqs


# --- raw v3 shapes under arming (the flow scripts' --armed mode) ----------------------------------

def attest_fee_zat(enforcement_fee_zat):
    """AFEE-1: ``feeZat * ATTEST_FEE_BPS / 10^4``."""
    return int(enforcement_fee_zat) * yu.ATTEST_FEE_BPS // yu.BPS


def _attest_payee(selected, prices):
    """``(seq, bondKeyAddress)`` of the first selected attestor the bundle carries (AFEE-1 accepts any s in A)."""
    for seq in selected:
        if not isinstance(prices, dict) or seq in prices:
            return seq, REGISTRY['attestors'][seq]['bond_key_address']
    raise AssertionError('no signer in the bundle')


def armed_raw_mint(test, node, cents, lock_blocks, ref_height, collateral_zat, prices, fee_addr=None, miner=None, **kw):
    """``build_mint_tx_v3`` with a carrier for (R, "") mined first and the attestor fee to a
    signer's bondKeyAddress: the raw MINT that passes MINT-9 / AFEE-1 while armed.  Returns
    ``(hex, owner_pubkey_hex)``; the caller mines it as ``build_mint_tx``'s."""
    bundle, selected = offline_bundle(test, node, ref_height, b'', prices)
    carrier = build_carrier_tx(node, bundle)
    test.sync_all()
    test.mine(POOLS[0] if miner is None else miner)
    _seq, addr = _attest_payee(selected, prices)
    fee = kw.pop('fee_zat_override', None)
    afee = attest_fee_zat(yu.fee_zat(collateral_zat) if fee is None else fee)
    return build_mint_tx_v3(node, cents, lock_blocks, ref_height, collateral_zat, fee_addr=fee_addr, carrier=carrier,
                            attest_fee=(addr, afee) if fee_addr else None, fee_zat_override=fee, **kw)


def armed_raw_claim(test, node, vault, burn_inputs, ref_height, prices, fee, miner=None, expiry=None):
    """``build_vault_spend_raw(path='claim')`` under arming: a carrier for (R, vault outpoint) is
    built and mined first, spent as vin[last]; the attestor fee (vout[2]) goes to a signer's
    bondKeyAddress and the REDEEM payload (version 3) names both fee outputs.  Clause (a) only
    (no residual).  Returns the hex."""
    selector = outpoint_selector(vault['txid'], int(vault['vout']))
    bundle, selected = offline_bundle(test, node, ref_height, selector, prices)
    carrier = build_carrier_tx(node, bundle)
    test.sync_all()
    test.mine(POOLS[0] if miner is None else miner)
    _seq, addr = _attest_payee(selected, prices)
    afee = attest_fee_zat(fee[1])
    payload = encode_redeem_v3(ref_height, 1, 2, [])
    hex_ = yu.build_vault_spend_raw(node, vault, 'claim', burn_inputs, payload=payload, fee=fee, ref_height=ref_height,
                                    extra_outputs=[(afee, yu._spk_of_address(addr))], extra_vin=[_carrier_vin(carrier)],
                                    value_adjust=CARRIER_VALUE - afee, expiry=expiry)
    return spend_carrier(node, hex_, 1 + len(burn_inputs), carrier)


# --- the v2 flow scripts' --armed mode ----------------------------------------------------------

def model_check(node, full=True):
    """``ym.assert_model_matches(node, full)`` and, when not ``full``, still the state hash."""
    model = ym.assert_model_matches(node, full=full)
    if not full:
        rpc_hash = node.yed_getstatehash()
        if isinstance(rpc_hash, dict):
            rpc_hash = rpc_hash.get('hash') or rpc_hash.get('statehash') or rpc_hash.get('stateHash')
        assert_equal(str(rpc_hash).lower(), model.state_hash())
    return model


class ArmedModeMixin(object):
    """``--armed`` for the v2 flow scripts: ``arm()`` runs ``register_and_arm`` after activation
    when the option is set; ``mint`` / ``claim`` are the two-step wallet commands with the
    offline bundle at ``attest_price`` (ignored while unarmed).  Mix in before
    ``YellowbackTestFramework``."""

    attest_price = None   # None: follow the node's cross-section at R (yed_getprice), so MINT-10 never trips as the medians move

    def add_options(self, parser):
        super().add_options(parser)
        parser.add_option('--armed', dest='armed', action='store_true', default=False,
                          help='run the flow under v3 arming: register_and_arm after activation, bundles on every mint and claim')

    @property
    def armed(self):
        return bool(getattr(self.options, 'armed', False))

    def arm(self):
        if self.armed:
            print('--armed: registering %d attestors and arming' % ATTEST_ARM_MIN)
            register_and_arm(self)

    def price_at(self, node, ref_height, field='pMint'):
        """The attested price (usd) for a bundle at R: ``attest_price`` when set, else the node's
        cross-section ``yed_getprice(R)[field]`` (xMint / xClaim), which is what a well-behaved
        attestor tracks; a test that wants divergence sets ``attest_price``."""
        if self.attest_price is not None:
            return self.attest_price
        micro = node.yed_getprice(ref_height).get(field)
        assert micro is not None, 'no %s at %d to attest' % (field, ref_height)
        return Decimal(micro) / 1_000_000

    def mint(self, node, cents, lock_blocks, from_addr='', miner=None, prices=None):
        if self.armed and prices is None:
            prices = self.price_at(node, node.yed_getinfo()['height'] - REF_LAG, 'pMint')
        return wallet_mint(self, node, cents, lock_blocks, from_addr, prices=prices if self.armed else None, miner=miner)

    def estimate(self, node, cents, lock_blocks):
        """``yed_estimatecollateral``; armed, with the price override at the attested price (the
        offline flows never feed the node's pool, so the pool path would be insufficient)."""
        if not self.armed:
            return node.yed_estimatecollateral(cents, lock_blocks)
        usd = self.price_at(node, node.yed_getinfo()['height'] - REF_LAG, 'pMint')
        return node.yed_estimatecollateral(cents, lock_blocks, yu.usd_to_micro(usd))

    def claim(self, node, vault_txid, to='', miner=None, prices=None):
        if self.armed and prices is None:
            prices = self.price_at(node, node.yed_getinfo()['height'], 'pClaim')
        return wallet_claim(self, node, vault_txid, to, prices=prices if self.armed else None, miner=miner)

    def model_check(self, node):
        """The Python model over the whole chain, the full comparison (yed_gettxinfo.type renders
        the v3 types since Phase A2)."""
        return model_check(node, full=True)

    def mint_args(self, node, cents, lock_blocks, from_addr=''):
        """Positional arguments for a direct ``yed_mint`` call that must reach a refusal past the
        bundle check while armed (a bundle for R = tip - REF_LAG is supplied)."""
        if not self.armed:
            return (cents, lock_blocks, from_addr)
        r = node.yed_getinfo()['height'] - REF_LAG
        return (cents, lock_blocks, from_addr, offline_bundle_hex(self, node, r, b'', self.price_at(node, r, 'pMint')))

    def claim_args(self, node, vault_txid, to=''):
        """Positional arguments for a direct ``yed_claim`` call that must reach a refusal past
        the bundle check while armed (a bundle for R = the tip is supplied)."""
        if not self.armed:
            return (vault_txid,) if not to else (vault_txid, to)
        r = node.yed_getinfo()['height']
        return (vault_txid, to, offline_bundle_hex(self, node, r, outpoint_selector(vault_txid, 0), self.price_at(node, r, 'pClaim')))
