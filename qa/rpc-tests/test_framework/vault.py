#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
The vault primitive (docs/plans/yellowback-upgrade-plan.md section 15) in pure Python, written
from the specification independently of the C++ in ``src/vault/``.  The golden vector
``src/test/data/vault_vectors.json`` (``gen_vault_vectors.py``) cross-checks the two.

What lives here:

- constants: ``VAULT_BRANCH_ID``, the opcode bytes (CSV ``0xb2``, ``OP_CHECKSETSIG`` ``0xc0``,
  ``OP_CHECKSETDORMANT`` ``0xc1``), roles, selectors, act types, field ranges (15.1-15.5);
- the V / I / bond templates: ``vault_script`` / ``parse_vault``, ``intent_script`` /
  ``parse_intent``, ``bond_script`` / ``parse_bond``, and the selector scriptSigs (15.3);
- the ``YV`` act codec for the six types: ``encode_act`` / ``decode_act`` and the OP_RETURN
  carrier ``act_script`` / ``parse_act_script`` (15.5);
- the two signed messages ``act_msg`` / ``set_sig_msg`` (15.5, 15.2 step 4) and 65-byte
  recoverable compact signatures: ``sign_recoverable`` (RFC 6979 exactly as libsecp256k1's
  default nonce function, low S, header 31..34) and ``recover_compact``;
- raw transaction builders for every act and every template spend;
- ``VaultModel``: a reference model of the set state and template rules (15.4-15.6), applied
  block by block, which functional tests use to predict the node's answers.

Byte conventions (all fixed by section 15; the ambiguities resolved here are listed in
``VAULT_VECTORS.md``):

- a ``setId`` (and every txid / prevout hash) is carried as its **32 internal bytes**, the bytes
  of ``uint256::begin()..end()`` = ``bytes.fromhex(txid_hex)[::-1]``, both in scripts and in act
  bodies; a prevout is ``hash (32 internal) || n (u32 LE)``, the ``COutPoint`` serialisation;
- act integers are fixed-width little-endian; ``bondMin`` is signed (``i64``);
- script numbers are what ``CScript << int64_t`` writes (``OP_0``, ``OP_1``..``OP_16``, else
  the minimal ``CScriptNum`` push) and parsers accept nothing else;
- a message digest (``act_msg``, ``set_sig_msg``) is returned as the 32 bytes the hash produced,
  which are the bytes ``CKey::SignCompact(uint256)`` signs (``uint256::begin()``).
"""

import copy
import hashlib
import hmac
import struct
from io import BytesIO

from .mininode import COutPoint, CTransaction, CTxIn, CTxOut

# ---------------------------------------------------------------------------
# Constants (15.1 - 15.5)

VAULT_BRANCH_ID = 0x6D5B7A31            # also in util.py (15.1); defined here so this module stands alone

OP_0 = 0x00
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1NEGATE = 0x4f
OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_16 = 0x60
OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_RETURN = 0x6a
OP_2DROP = 0x6d
OP_DROP = 0x75
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac
OP_CHECKLOCKTIMEVERIFY = 0xb1
OP_CHECKSEQUENCEVERIFY = 0xb2            # BIP112's own byte, OP_NOP3 without the flag (U-10)
OP_CHECKSETSIG = 0xc0
OP_CHECKSETDORMANT = 0xc1

SIGHASH_ALL = 1

ROLE_UNLOCK = 1
ROLE_CANCEL = 2

# V selectors
SEL_UNLOCK = 1
SEL_OWNER = 2
SEL_OWNER_RELEASED = 3
SEL_APP = 4
# I selectors
SEL_RELEASE = 1
SEL_CANCEL = 2
# SEL_OWNER_RELEASED = 3 as above

ACT_MAGIC = b'YV'
ACT_VERSION = 0x01
ACT_SET_CREATE = 0x01
ACT_SET_JOIN = 0x02
ACT_SET_HEARTBEAT = 0x03
ACT_SET_REMOVE = 0x04
ACT_SET_EQUIVOCATION = 0x05
ACT_SET_WINDDOWN = 0x06
ACT_NAMES = {
    ACT_SET_CREATE: 'SET_CREATE', ACT_SET_JOIN: 'SET_JOIN', ACT_SET_HEARTBEAT: 'SET_HEARTBEAT',
    ACT_SET_REMOVE: 'SET_REMOVE', ACT_SET_EQUIVOCATION: 'SET_EQUIVOCATION', ACT_SET_WINDDOWN: 'SET_WINDDOWN',
}
ACT_BODY_SIZE = {
    ACT_SET_CREATE: 64, ACT_SET_JOIN: 70, ACT_SET_HEARTBEAT: 65,
    ACT_SET_REMOVE: 66, ACT_SET_EQUIVOCATION: 264, ACT_SET_WINDDOWN: 32,
}
ACT_MAX_SCRIPT = 1200                    # policy: a YV OP_RETURN up to 1,200 bytes
SET_FLAG_OPEN = 0x01

ACT_DOMAIN = b'YcashSetAct'              # 11 ASCII bytes
SETSIG_DOMAIN = b'YcashSetSig'           # 11 ASCII bytes
SET_SIG_SIZE = 65

MAX_SEATS = 15
MAX_WINDOW = 1048576
DELAY_MIN, DELAY_MAX = 1, 65535
OWNER_HEIGHT_MIN, OWNER_HEIGHT_MAX = 1, 499999999
APP_HEIGHT_MIN, APP_HEIGHT_MAX = 0, 499999999
LOCKTIME_THRESHOLD = 500000000

SEQUENCE_FINAL = 0xFFFFFFFF
SEQUENCE_DISABLE_FLAG = 1 << 31
SEQUENCE_TYPE_FLAG = 1 << 22
SEQUENCE_MASK = 0x0000FFFF

MEMBER_ACTIVE = 'ACTIVE'
MEMBER_REMOVED = 'REMOVED'
MEMBER_EJECTED = 'EJECTED'
MEMBER_WITHDRAWN = 'WITHDRAWN'

VAULT_FEE = 10000                        # zat; the conventional fee the builders leave
COIN = 100000000
MAX_MONEY = 21000000 * COIN


class VaultError(Exception):
    """A rejection.  ``reason`` is a short code; the node's strings may differ in wording
    (``bad-vault-*``), the golden vector only records *that* a case is rejected and at which
    stage."""

    def __init__(self, reason, detail=''):
        Exception.__init__(self, reason if not detail else '%s: %s' % (reason, detail))
        self.reason = reason


# ---------------------------------------------------------------------------
# Hashes

def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return sha256(sha256(b))


def hash160(b):
    try:
        return hashlib.new('ripemd160', sha256(b)).digest()
    except ValueError:                   # OpenSSL 3 without the legacy provider (CI)
        from .yellowback_model import ripemd160
        return ripemd160(sha256(b))


def txid_internal(txid_hex):
    """The 32 internal bytes of an RPC txid (``uint256::begin()``)."""
    b = bytes.fromhex(txid_hex)
    assert len(b) == 32
    return b[::-1]


def txid_display(internal32):
    return bytes(internal32)[::-1].hex()


def ser_prevout(txid_hex, n):
    """``COutPoint`` serialisation: 32 internal bytes || n u32 LE (36 bytes)."""
    return txid_internal(txid_hex) + struct.pack('<I', n)


def tx_txid(tx):
    tx.sha256 = None
    tx.calc_sha256()
    return tx.hash


# ---------------------------------------------------------------------------
# secp256k1: pure Python, RFC 6979 as libsecp256k1's nonce_function_rfc6979, recoverable compact

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % _P == 0:
            return None
        lam = 3 * p[0] * p[0] * pow(2 * p[1], _P - 2, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], _P - 2, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return (x, (lam * (p[0] - x) - p[1]) % _P)


def _jdouble(p):
    x, y, z = p
    if y == 0:
        return (0, 1, 0)
    ysq = y * y % _P
    s_ = 4 * x * ysq % _P
    m = 3 * x * x % _P
    nx = (m * m - 2 * s_) % _P
    return (nx, (m * (s_ - nx) - 8 * ysq * ysq) % _P, 2 * y * z % _P)


def _jadd(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    z1s, z2s = p[2] * p[2] % _P, q[2] * q[2] % _P
    u1, u2 = p[0] * z2s % _P, q[0] * z1s % _P
    s1, s2 = p[1] * z2s * q[2] % _P, q[1] * z1s * p[2] % _P
    if u1 == u2:
        return _jdouble(p) if s1 == s2 else (0, 1, 0)
    h = (u2 - u1) % _P
    r = (s2 - s1) % _P
    h2 = h * h % _P
    h3 = h * h2 % _P
    u1h2 = u1 * h2 % _P
    nx = (r * r - h3 - 2 * u1h2) % _P
    return (nx, (r * (u1h2 - nx) - s1 * h3) % _P, h * p[2] * q[2] % _P)


def _mul(k, point):
    """Scalar multiplication (Jacobian internally; affine in and out, None = infinity)."""
    if point is None or k % _N == 0:
        return None
    r, a = (0, 1, 0), (point[0], point[1], 1)
    for bit in bin(k)[2:]:
        r = _jdouble(r)
        if bit == '1':
            r = _jadd(r, a)
    if r[2] == 0:
        return None
    zi = pow(r[2], _P - 2, _P)
    return (r[0] * zi * zi % _P, r[1] * zi * zi * zi % _P)


def _lift_x(x, odd):
    if x >= _P:
        return None
    y2 = (x * x * x + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if y * y % _P != y2:
        return None
    if (y & 1) != odd:
        y = _P - y
    return (x, y)


def _ser_point(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, 'big')


def pubkey_of(secret32):
    """Compressed 33-byte public key of a 32-byte secret."""
    x = int.from_bytes(secret32, 'big')
    assert 0 < x < _N
    return _ser_point(_mul(x, _G))


def is_compressed_pubkey(b):
    """33 bytes with prefix 02/03 (``CPubKey`` of a compressed size; no curve check).  This is
    15.3's "compressed" for template and act keys (ambiguity A-2 in VAULT_VECTORS.md: an
    off-curve key is accepted by the parsers; it simply never verifies or recovers)."""
    b = bytes(b)
    return len(b) == 33 and b[0] in (2, 3)


def is_valid_point(b):
    """``is_compressed_pubkey`` and x on the curve (``CPubKey::IsFullyValid``)."""
    b = bytes(b)
    return is_compressed_pubkey(b) and _lift_x(int.from_bytes(b[1:], 'big'), b[0] & 1) is not None


def _decompress(pubkey33):
    if not is_compressed_pubkey(pubkey33):
        return None
    return _lift_x(int.from_bytes(pubkey33[1:], 'big'), pubkey33[0] & 1)


def _rfc6979_nonces(secret32, msg32):
    """The candidate stream of libsecp256k1's ``nonce_function_rfc6979`` with no extra data:
    key = secret || (msg mod n), HMAC-SHA256 DRBG; candidate ``counter`` is the counter-th
    output.  libsecp256k1 skips a candidate that overflows or is zero, as the caller does."""
    h1 = (int.from_bytes(msg32, 'big') % _N).to_bytes(32, 'big')
    seed = bytes(secret32) + h1
    v = b'\x01' * 32
    k = b'\x00' * 32
    k = hmac.new(k, v + b'\x00' + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + seed, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        yield int.from_bytes(v, 'big')
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign_rec(secret32, msg32):
    """``(r, s, recid, flipped)`` with low S, as ``secp256k1_ecdsa_sign_recoverable`` with the
    default nonce function: recid = (R.x >= n) << 1 | R.y odd, flipped (and recid ^= 1) when
    s was normalised.  ``flipped`` is for the vectors (exercises the high-S branch)."""
    d = int.from_bytes(secret32, 'big')
    assert 0 < d < _N
    z = int.from_bytes(msg32, 'big') % _N
    for k in _rfc6979_nonces(secret32, msg32):
        if k == 0 or k >= _N:
            continue
        rx, ry = _mul(k, _G)
        r = rx % _N
        if r == 0:
            continue
        s = pow(k, _N - 2, _N) * (z + r * d) % _N
        if s == 0:
            continue
        recid = (2 if rx >= _N else 0) | (ry & 1)
        flipped = s > _N // 2
        if flipped:
            s = _N - s
            recid ^= 1
        return r, s, recid, flipped


def sign_recoverable(secret32, msg32):
    """65 bytes ``header || r || s``, header = 27 + recid + 4 (compressed key): 31..34.  Equals
    ``CKey::SignCompact(uint256(msg32))`` byte for byte."""
    r, s, recid, _f = ecdsa_sign_rec(secret32, msg32)
    return bytes([31 + recid]) + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def recover_compact(sig65, msg32, strict=True):
    """The 33-byte compressed key a 65-byte recoverable signature recovers to, or None.
    ``strict`` (the set-signature rule, 15.2 step 3): header 31..34 and S <= n/2.  Non-strict
    mirrors ``CPubKey::RecoverCompact``: any header, recid = (h - 27) & 3, and the key comes
    back uncompressed (65 bytes) unless (h - 27) & 4."""
    sig65 = bytes(sig65)
    if len(sig65) != SET_SIG_SIZE:
        return None
    header = sig65[0]
    if strict and not 31 <= header <= 34:
        return None
    recid = (header - 27) & 3
    r = int.from_bytes(sig65[1:33], 'big')
    s = int.from_bytes(sig65[33:65], 'big')
    if not (0 < r < _N and 0 < s < _N):
        return None
    if strict and s > _N // 2:
        return None
    x = r + (_N if recid & 2 else 0)
    if x >= _P:
        return None
    R = _lift_x(x, recid & 1)
    if R is None:
        return None
    z = int.from_bytes(msg32, 'big') % _N
    rinv = pow(r, _N - 2, _N)
    Q = _add(_mul(s * rinv % _N, R), _mul((-z * rinv) % _N, _G))
    if Q is None:
        return None
    if not strict and not (header - 27) & 4:
        return b'\x04' + Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big')
    return _ser_point(Q)


def ecdsa_sign_der(secret32, msg32):
    """Low-S DER (for OP_CHECKSIG: owner and bond keys); the nonce is the same RFC 6979."""
    r, s, _rec, _f = ecdsa_sign_rec(secret32, msg32)

    def _int(v):
        b = v.to_bytes((v.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = _int(r) + _int(s)
    return b'\x30' + bytes([len(body)]) + body


def ecdsa_verify_der(pubkey33, msg32, der):
    """Textbook verification of a strict DER signature (no hashtype byte)."""
    try:
        assert der[0] == 0x30 and der[1] == len(der) - 2 and der[2] == 0x02
        rl = der[3]
        r = int.from_bytes(der[4:4 + rl], 'big')
        assert der[4 + rl] == 0x02
        sl = der[5 + rl]
        s = int.from_bytes(der[6 + rl:6 + rl + sl], 'big')
        assert 6 + rl + sl == len(der)
    except (AssertionError, IndexError):
        return False
    Q = _decompress(pubkey33)
    if Q is None or not (0 < r < _N and 0 < s < _N):
        return False
    z = int.from_bytes(msg32, 'big') % _N
    w = pow(s, _N - 2, _N)
    pt = _add(_mul(z * w % _N, _G), _mul(r * w % _N, Q))
    return pt is not None and pt[0] % _N == r


def fixed_secret(label):
    """A deterministic test secret: SHA256(label) reduced into [1, n-1]."""
    if isinstance(label, str):
        label = label.encode()
    x = int.from_bytes(sha256(label), 'big') % (_N - 1) + 1
    return x.to_bytes(32, 'big')


# ---------------------------------------------------------------------------
# Script primitives

def script_num(n):
    """``CScriptNum::serialize``."""
    if n == 0:
        return b''
    neg, a, out = n < 0, abs(n), bytearray()
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def decode_script_num(b, max_size=5):
    """``CScriptNum(vch, fRequireMinimal=true, nMaxNumSize)``: None if too long or non-minimal."""
    b = bytes(b)
    if len(b) > max_size:
        return None
    if not b:
        return 0
    if (b[-1] & 0x7f) == 0 and (len(b) <= 1 or (b[-2] & 0x80) == 0):
        return None
    v = int.from_bytes(b, 'little')
    if b[-1] & 0x80:
        return -(v & ~(0x80 << (8 * (len(b) - 1))))
    return v


def push(data):
    """``CScript << std::vector<unsigned char>``: the canonical (smallest) push."""
    data = bytes(data)
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + struct.pack('<H', n) + data
    return bytes([OP_PUSHDATA4]) + struct.pack('<I', n) + data


def push_int(n):
    """``CScript << int64_t``: OP_0, OP_1NEGATE, OP_1..OP_16, else the CScriptNum push."""
    if n == 0:
        return bytes([OP_0])
    if n == -1:
        return bytes([OP_1NEGATE])
    if 1 <= n <= 16:
        return bytes([OP_1 + n - 1])
    return push(script_num(n))


def get_ops(script):
    """``CScript::GetOp`` over the whole script: ``[(opcode, data_or_None)]``, or None if a push
    runs past the end.  A push's opcode is the byte that introduced it (so a non-minimal push is
    visible: rebuilding with ``push`` gives different bytes)."""
    script = bytes(script)
    ops, i, n = [], 0, len(script)
    while i < n:
        op = script[i]
        i += 1
        if op <= OP_PUSHDATA4:
            if op < OP_PUSHDATA1:
                size = op
            elif op == OP_PUSHDATA1:
                if i + 1 > n:
                    return None
                size = script[i]
                i += 1
            elif op == OP_PUSHDATA2:
                if i + 2 > n:
                    return None
                size = struct.unpack('<H', script[i:i + 2])[0]
                i += 2
            else:
                if i + 4 > n:
                    return None
                size = struct.unpack('<I', script[i:i + 4])[0]
                i += 4
            if i + size > n:
                return None
            ops.append((op, script[i:i + size]))
            i += size
        else:
            ops.append((op, None))
    return ops


def _op_value(op, data):
    """The stack value an opcode pushes, or None if it is not a push (OP_RESERVED is not)."""
    if data is not None:
        return data
    if op == OP_1NEGATE:
        return b'\x81'
    if OP_1 <= op <= OP_16:
        return bytes([op - OP_1 + 1])
    return None


def push_values(script):
    """The values of a push-only script (``IsPushOnly``, OP_RESERVED excluded), else None."""
    ops = get_ops(script)
    if ops is None:
        return None
    vals = []
    for op, data in ops:
        v = _op_value(op, data)
        if v is None:
            return None
        vals.append(v)
    return vals


def p2sh_script(redeem):
    return bytes([OP_HASH160, 20]) + hash160(redeem) + bytes([OP_EQUAL])


def p2pkh_script_of_pubkey(pubkey33):
    return bytes([OP_DUP, OP_HASH160, 20]) + hash160(pubkey33) + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


def is_p2pkh(spk):
    spk = bytes(spk)
    return (len(spk) == 25 and spk[:3] == bytes([OP_DUP, OP_HASH160, 20])
            and spk[23:] == bytes([OP_EQUALVERIFY, OP_CHECKSIG]))


# ---------------------------------------------------------------------------
# Templates (15.3)

def _b(x, size, name):
    x = bytes.fromhex(x) if isinstance(x, str) else bytes(x)
    if len(x) != size:
        raise VaultError('bad-template-field', '%s must be %d bytes' % (name, size))
    return x


class VaultParams(object):
    """The V template's fields.  ``set_id``/``cancel_set_id`` are 32 internal bytes."""
    __slots__ = ('tag', 'set_id', 'cancel_set_id', 'delay', 'owner_height', 'app_height', 'owner_key')

    def __init__(self, tag, set_id, cancel_set_id, delay, owner_height, app_height, owner_key):
        self.tag = _b(tag, 4, 'tag')
        self.set_id = _b(set_id, 32, 'setId')
        self.cancel_set_id = _b(cancel_set_id, 32, 'cancelSetId')
        self.delay = int(delay)
        self.owner_height = int(owner_height)
        self.app_height = int(app_height)
        self.owner_key = _b(owner_key, 33, 'ownerKey')

    def __eq__(self, o):
        return isinstance(o, VaultParams) and all(getattr(self, a) == getattr(o, a) for a in self.__slots__)

    def __repr__(self):
        return 'VaultParams(%s)' % ', '.join('%s=%r' % (a, getattr(self, a)) for a in self.__slots__)

    def to_json(self):
        return {'tag': self.tag.hex(), 'setId': self.set_id.hex(), 'cancelSetId': self.cancel_set_id.hex(),
                'delay': self.delay, 'ownerHeight': self.owner_height, 'appHeight': self.app_height,
                'ownerKey': self.owner_key.hex()}

    @classmethod
    def from_json(cls, j):
        return cls(j['tag'], j['setId'], j['cancelSetId'], j['delay'], j['ownerHeight'], j['appHeight'], j['ownerKey'])


class IntentParams(object):
    """The I template's fields (all hashes / ids 32 raw bytes)."""
    __slots__ = ('tag', 'recipient_hash', 'vault_hash', 'delay', 'cancel_set_id', 'set_id', 'owner_key')

    def __init__(self, tag, recipient_hash, vault_hash, delay, cancel_set_id, set_id, owner_key):
        self.tag = _b(tag, 4, 'tag')
        self.recipient_hash = _b(recipient_hash, 32, 'recipientHash')
        self.vault_hash = _b(vault_hash, 32, 'vaultHash')
        self.delay = int(delay)
        self.cancel_set_id = _b(cancel_set_id, 32, 'cancelSetId')
        self.set_id = _b(set_id, 32, 'setId')
        self.owner_key = _b(owner_key, 33, 'ownerKey')

    def __eq__(self, o):
        return isinstance(o, IntentParams) and all(getattr(self, a) == getattr(o, a) for a in self.__slots__)

    def __repr__(self):
        return 'IntentParams(%s)' % ', '.join('%s=%r' % (a, getattr(self, a)) for a in self.__slots__)

    def to_json(self):
        return {'tag': self.tag.hex(), 'recipientHash': self.recipient_hash.hex(), 'vaultHash': self.vault_hash.hex(),
                'delay': self.delay, 'cancelSetId': self.cancel_set_id.hex(), 'setId': self.set_id.hex(),
                'ownerKey': self.owner_key.hex()}

    @classmethod
    def from_json(cls, j):
        return cls(j['tag'], j['recipientHash'], j['vaultHash'], j['delay'], j['cancelSetId'], j['setId'], j['ownerKey'])


def check_vault_ranges(p):
    """The V field ranges of 15.3, or raises."""
    if not DELAY_MIN <= p.delay <= DELAY_MAX:
        raise VaultError('bad-template-delay')
    if not OWNER_HEIGHT_MIN <= p.owner_height <= OWNER_HEIGHT_MAX:
        raise VaultError('bad-template-ownerheight')
    if not APP_HEIGHT_MIN <= p.app_height <= APP_HEIGHT_MAX:
        raise VaultError('bad-template-appheight')
    if not is_compressed_pubkey(p.owner_key):
        raise VaultError('bad-template-ownerkey')


def check_intent_ranges(p):
    if not DELAY_MIN <= p.delay <= DELAY_MAX:
        raise VaultError('bad-template-delay')
    if not is_compressed_pubkey(p.owner_key):
        raise VaultError('bad-template-ownerkey')


def vault_script_unchecked(p):
    """The V bytes for any field values (negative vectors use this to build out-of-range shapes)."""
    return (push(p.tag) + push(p.cancel_set_id) + push_int(p.delay) + bytes([OP_2DROP, OP_DROP])
            + bytes([OP_DUP, OP_1, OP_EQUAL, OP_IF])
            + bytes([OP_DROP]) + push(p.set_id) + bytes([OP_1, OP_CHECKSETSIG])
            + bytes([OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF])
            + bytes([OP_DROP]) + push_int(p.owner_height) + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP])
            + push(p.owner_key) + bytes([OP_CHECKSIG])
            + bytes([OP_ELSE, OP_DUP, OP_3, OP_EQUAL, OP_IF])
            + bytes([OP_DROP]) + push(p.set_id) + bytes([OP_CHECKSETDORMANT, OP_VERIFY])
            + push(p.owner_key) + bytes([OP_CHECKSIG])
            + bytes([OP_ELSE])
            + bytes([OP_4, OP_EQUALVERIFY]) + push_int(p.app_height) + bytes([OP_CHECKLOCKTIMEVERIFY])
            + bytes([OP_ENDIF, OP_ENDIF, OP_ENDIF]))


def nonminimal_delay_vault(p):
    """The V of ``p`` (``delay`` 1..16) with the delay as the data push ``01 <delay>`` instead of
    ``OP_<delay>``: the V skeleton with a non-minimal field (a malformed shape, negative tests)."""
    assert 1 <= p.delay <= 16
    head = push(p.tag) + push(p.cancel_set_id)
    good = vault_script(p)
    assert good[len(head)] == OP_1 + p.delay - 1
    return head + bytes([0x01, p.delay]) + good[len(head) + 1:]


def vault_script(p):
    """The V scriptPubKey (bare, U-12) of ``VaultParams`` ``p``; raises on out-of-range fields."""
    check_vault_ranges(p)
    return vault_script_unchecked(p)


def intent_script_unchecked(p):
    return (push(p.tag) + push(p.recipient_hash) + push(p.vault_hash) + bytes([OP_2DROP, OP_DROP])
            + bytes([OP_DUP, OP_1, OP_EQUAL, OP_IF])
            + bytes([OP_DROP]) + push_int(p.delay) + bytes([OP_CHECKSEQUENCEVERIFY])
            + bytes([OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF])
            + bytes([OP_DROP]) + push(p.cancel_set_id) + bytes([OP_2, OP_CHECKSETSIG])
            + bytes([OP_ELSE])
            + bytes([OP_3, OP_EQUALVERIFY]) + push(p.set_id) + bytes([OP_CHECKSETDORMANT, OP_VERIFY])
            + push(p.owner_key) + bytes([OP_CHECKSIG])
            + bytes([OP_ENDIF, OP_ENDIF]))


def intent_script(p):
    check_intent_ranges(p)
    return intent_script_unchecked(p)


def _num_field(op, data, max_size=5):
    """A script number written by ``push_int`` (any opcode form here; minimality is enforced by
    the rebuild comparison in the parsers)."""
    if data is None:
        if op == OP_0:
            return 0
        if OP_1 <= op <= OP_16:
            return op - OP_1 + 1
        if op == OP_1NEGATE:
            return -1
        return None
    return decode_script_num(data, max_size) if len(data) <= max_size else None


# token positions of the variable fields in the V / I op lists
_V_LEN = 43
_I_LEN = 31


def parse_vault(spk):
    """``VaultParams`` if ``spk`` is exactly a V (15.3: shape, minimal pushes, ranges), else None."""
    spk = bytes(spk)
    ops = get_ops(spk)
    if ops is None or len(ops) != _V_LEN:
        return None
    try:
        tag, cancel, set_id, key = ops[0][1], ops[1][1], ops[10][1], ops[22][1]
        if tag is None or cancel is None or set_id is None or key is None:
            return None
        delay = _num_field(*ops[2])
        owner_h = _num_field(*ops[19])
        app_h = _num_field(*ops[38])
        if delay is None or owner_h is None or app_h is None:
            return None
        p = VaultParams(tag, set_id, cancel, delay, owner_h, app_h, key)
        check_vault_ranges(p)
    except VaultError:
        return None
    return p if vault_script_unchecked(p) == spk else None


def parse_intent(spk):
    """``IntentParams`` if ``spk`` is exactly an I, else None."""
    spk = bytes(spk)
    ops = get_ops(spk)
    if ops is None or len(ops) != _I_LEN:
        return None
    try:
        tag, rh, vh, cancel, set_id, key = ops[0][1], ops[1][1], ops[2][1], ops[18][1], ops[24][1], ops[27][1]
        if None in (tag, rh, vh, cancel, set_id, key):
            return None
        delay = _num_field(*ops[10])
        if delay is None:
            return None
        p = IntentParams(tag, rh, vh, delay, cancel, set_id, key)
        check_intent_ranges(p)
    except VaultError:
        return None
    return p if intent_script_unchecked(p) == spk else None


def intent_for(vp, recipient_spk):
    """The I a V's unlock creates for ``recipient_spk`` (S-2: V's tag, setId, cancelSetId, delay,
    ownerKey; vaultHash = SHA256(V spk); recipientHash = SHA256(recipient spk))."""
    return IntentParams(vp.tag, sha256(bytes(recipient_spk)), sha256(vault_script(vp)), vp.delay,
                        vp.cancel_set_id, vp.set_id, vp.owner_key)


# The opcode skeletons of V and I, ``None`` at a field (any push: an opcode <= OP_16 other than
# OP_RESERVED), as the C++ ``VaultSkeleton`` / ``IntentSkeleton`` (src/vault/template.cpp).
_F = None
_V_SKELETON = [
    _F, _F, _F, OP_2DROP, OP_DROP,
    OP_DUP, OP_1, OP_EQUAL, OP_IF,
    OP_DROP, _F, OP_1, OP_CHECKSETSIG,
    OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF,
    OP_DROP, _F, OP_CHECKLOCKTIMEVERIFY, OP_DROP, _F, OP_CHECKSIG,
    OP_ELSE, OP_DUP, OP_3, OP_EQUAL, OP_IF,
    OP_DROP, _F, OP_CHECKSETDORMANT, OP_VERIFY, _F, OP_CHECKSIG,
    OP_ELSE, OP_4, OP_EQUALVERIFY, _F, OP_CHECKLOCKTIMEVERIFY,
    OP_ENDIF, OP_ENDIF, OP_ENDIF]
_I_SKELETON = [
    _F, _F, _F, OP_2DROP, OP_DROP,
    OP_DUP, OP_1, OP_EQUAL, OP_IF,
    OP_DROP, _F, OP_CHECKSEQUENCEVERIFY,
    OP_ELSE, OP_DUP, OP_2, OP_EQUAL, OP_IF,
    OP_DROP, _F, OP_2, OP_CHECKSETSIG,
    OP_ELSE, OP_3, OP_EQUALVERIFY, _F, OP_CHECKSETDORMANT, OP_VERIFY, _F, OP_CHECKSIG,
    OP_ENDIF, OP_ENDIF]
_OP_RESERVED = 0x50


def _matches_skeleton(spk, skel):
    ops = get_ops(spk)
    if ops is None or len(ops) != len(skel):
        return False
    for (op, _data), want in zip(ops, skel):
        if want is None:
            if op > OP_16 or op == _OP_RESERVED:
                return False
        elif op != want:
            return False
    return True


def template_shape(spk):
    """``'V'`` / ``'I'`` for an exact template, ``'malformed'`` for an output with a template's
    opcode skeleton whose fields do not parse (wrong sizes, out-of-range numbers, non-minimal
    pushes, or the V's two setId / ownerKey copies differing), ``None`` otherwise.  A malformed
    shape makes the transaction invalid (``bad-txns-vault-malformed``, plan §15.5 reconciliation
    (8), C++ ``MatchVault`` / ``MatchIntent``), so I-0 and V-1 cannot be bypassed by
    mis-encoding."""
    spk = bytes(spk)
    if _matches_skeleton(spk, _V_SKELETON):
        return 'V' if parse_vault(spk) is not None else 'malformed'
    if _matches_skeleton(spk, _I_SKELETON):
        return 'I' if parse_intent(spk) is not None else 'malformed'
    return None


def bond_script(member_key33, locktime):
    """B: ``<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <memberKey:33> OP_CHECKSIG`` (redeem)."""
    member_key33 = bytes(member_key33)
    assert len(member_key33) == 33
    return push_int(locktime) + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP]) + push(member_key33) + bytes([OP_CHECKSIG])


def bond_spk(member_key33, locktime):
    return p2sh_script(bond_script(member_key33, locktime))


def parse_bond(redeem):
    """``(memberKey33, locktime)`` if ``redeem`` is exactly B (minimal push), else None."""
    redeem = bytes(redeem)
    ops = get_ops(redeem)
    if ops is None or len(ops) != 5 or ops[3][1] is None or len(ops[3][1]) != 33:
        return None
    lt = _num_field(*ops[0])
    if lt is None or lt < 0:
        return None
    return (ops[3][1], lt) if bond_script(ops[3][1], lt) == redeem else None


# selector scriptSigs

def _sel(n):
    return bytes([OP_1 + n - 1])


def vault_unlock_scriptsig(set_sigs):
    return b''.join(push(s) for s in set_sigs) + _sel(SEL_UNLOCK)


def vault_owner_scriptsig(owner_sig):
    return push(owner_sig) + _sel(SEL_OWNER)


def vault_owner_released_scriptsig(owner_sig):
    return push(owner_sig) + _sel(SEL_OWNER_RELEASED)


def vault_app_scriptsig():
    return _sel(SEL_APP)


def intent_release_scriptsig():
    return _sel(SEL_RELEASE)


def intent_cancel_scriptsig(set_sigs):
    return b''.join(push(s) for s in set_sigs) + _sel(SEL_CANCEL)


def intent_owner_released_scriptsig(owner_sig):
    return push(owner_sig) + _sel(SEL_OWNER_RELEASED)


def parse_selector(script_sig, kind='V'):
    """S-1: ``(selector, [values before it])`` if ``script_sig`` is push-only and its last op is
    the opcode ``OP_1``..``OP_4`` (``OP_1``..``OP_3`` for an I), else None.  A selector pushed
    as data (``01 01``) does not parse."""
    ops = get_ops(script_sig)
    if not ops:
        return None
    vals = push_values(script_sig)
    if vals is None:
        return None
    last_op, last_data = ops[-1]
    top = SEL_APP if kind == 'V' else SEL_OWNER_RELEASED
    if last_data is not None or not OP_1 <= last_op <= OP_1 + top - 1:
        return None
    return last_op - OP_1 + 1, vals[:-1]


# ---------------------------------------------------------------------------
# Messages (15.2 step 4, 15.5)

def set_sig_msg(set_id32, role, prevout_txid_hex, prevout_n, sighash32):
    """SHA256d("YcashSetSig" || setId 32 || role u8 || prevout.hash 32 || prevout.n u32 LE ||
    sighash 32), the 32 digest bytes."""
    set_id32, sighash32 = bytes(set_id32), bytes(sighash32)
    assert len(set_id32) == 32 and len(sighash32) == 32 and 0 <= role <= 255
    return sha256d(SETSIG_DOMAIN + set_id32 + bytes([role]) + ser_prevout(prevout_txid_hex, prevout_n) + sighash32)


def set_sig_msg_raw(set_id32, role, prevout36, sighash32):
    return sha256d(SETSIG_DOMAIN + bytes(set_id32) + bytes([role]) + bytes(prevout36) + bytes(sighash32))


def act_msg(payload, prevout_txid_hex, prevout_n):
    """SHA256d("YcashSetAct" || P || vin[0].prevout (36))."""
    return sha256d(ACT_DOMAIN + bytes(payload) + ser_prevout(prevout_txid_hex, prevout_n))


def act_msg_raw(payload, prevout36):
    return sha256d(ACT_DOMAIN + bytes(payload) + bytes(prevout36))


def template_sighash(tx, n_in, spk, amount, branch_id=VAULT_BRANCH_ID):
    """``SignatureHash(scriptCode = the V/I spk, tx, nIn, SIGHASH_ALL, amount, branch)``
    (ZIP-243), the framework's implementation."""
    from .script import CScript, SignatureHash
    return SignatureHash(CScript(bytes(spk)), tx, n_in, SIGHASH_ALL, amount, branch_id)[0]


# ---------------------------------------------------------------------------
# The YV act codec (15.5)

def _u8(v):
    return struct.pack('<B', v)


def _key(k):
    k = bytes.fromhex(k) if isinstance(k, str) else bytes(k)
    assert len(k) == 33
    return k


def _h32(h):
    h = bytes.fromhex(h) if isinstance(h, str) else bytes(h)
    assert len(h) == 32
    return h


def encode_act_body(act):
    """The body bytes of an act dict (no validation: negative vectors encode bad values)."""
    t = act['type']
    if t == ACT_SET_CREATE:
        return (struct.pack('<BBBBB', act['seats'], act['unlockThreshold'], act['cancelThreshold'],
                            act['slashThreshold'], act['flags'])
                + struct.pack('<HIIqII', act['rateLimitBps'], act['rateWindow'], act['livenessWindow'],
                              act['bondMin'], act['bondLockMin'], act['maturity'])
                + _key(act['admitKey']))
    if t == ACT_SET_JOIN:
        return _h32(act['setId']) + _key(act['memberKey']) + struct.pack('<IB', act['bondLocktime'], act['bondVout'])
    if t == ACT_SET_HEARTBEAT:
        return _h32(act['setId']) + _key(act['memberKey'])
    if t == ACT_SET_REMOVE:
        return _h32(act['setId']) + _key(act['memberKey']) + _u8(act['burn'])
    if t == ACT_SET_EQUIVOCATION:
        po = bytes.fromhex(act['prevout']) if isinstance(act['prevout'], str) else bytes(act['prevout'])
        assert len(po) == 36
        sa = bytes.fromhex(act['sigA']) if isinstance(act['sigA'], str) else bytes(act['sigA'])
        sb = bytes.fromhex(act['sigB']) if isinstance(act['sigB'], str) else bytes(act['sigB'])
        assert len(sa) == 65 and len(sb) == 65
        return (_h32(act['setId']) + po + _u8(act['roleA']) + _h32(act['sighashA']) + sa
                + _u8(act['roleB']) + _h32(act['sighashB']) + sb)
    if t == ACT_SET_WINDDOWN:
        return _h32(act['setId'])
    raise VaultError('bad-vault-act-type')


def encode_act(act, check=True):
    """P = "YV" || 0x01 || type || body.  ``check`` runs ``decode_act`` on the result (so an
    encoder can never emit what the decoder rejects)."""
    p = ACT_MAGIC + bytes([act.get('version', ACT_VERSION), act['type']]) + encode_act_body(act)
    if check:
        decode_act(p)
    return p


def decode_act(p):
    """The act dict of payload ``P`` (hex fields), or raises ``VaultError``.  Checks everything
    that needs no chain state: magic, version, type, exact body length, and the field rules of
    15.5 that are context-free (CREATE's ranges and flags; compressed keys; ``bondLocktime <
    500000000``; ``burn`` in {0,1}; roles in {1,2}; signature headers 31..34)."""
    p = bytes(p)
    if len(p) < 4 or p[:2] != ACT_MAGIC:
        raise VaultError('bad-vault-act-magic')
    if p[2] != ACT_VERSION:
        raise VaultError('bad-vault-act-version')
    t = p[3]
    if t not in ACT_BODY_SIZE:
        raise VaultError('bad-vault-act-type')
    body = p[4:]
    if len(body) != ACT_BODY_SIZE[t]:
        raise VaultError('bad-vault-act-size', '%s body %d != %d' % (ACT_NAMES[t], len(body), ACT_BODY_SIZE[t]))
    a = {'type': t, 'name': ACT_NAMES[t]}

    def key_at(off, name):
        k = body[off:off + 33]
        if not is_compressed_pubkey(k):
            raise VaultError('bad-vault-act-key', name)
        return k.hex()

    if t == ACT_SET_CREATE:
        seats, ut, ct, st, flags = struct.unpack('<BBBBB', body[0:5])
        bps, rw, lw, bond_min, blm, mat = struct.unpack('<HIIqII', body[5:31])
        a.update(seats=seats, unlockThreshold=ut, cancelThreshold=ct, slashThreshold=st, flags=flags,
                 rateLimitBps=bps, rateWindow=rw, livenessWindow=lw, bondMin=bond_min, bondLockMin=blm,
                 maturity=mat, admitKey=key_at(31, 'admitKey'))
        if not 1 <= seats <= MAX_SEATS:
            raise VaultError('bad-vault-act-seats')
        for th in (ut, ct, st):
            if not 1 <= th <= seats:
                raise VaultError('bad-vault-act-threshold')
        if flags & ~SET_FLAG_OPEN:
            raise VaultError('bad-vault-act-flags')
        if bps > 10000:
            raise VaultError('bad-vault-act-rate')
        if not 1 <= rw <= MAX_WINDOW or not 1 <= lw <= MAX_WINDOW:
            raise VaultError('bad-vault-act-window')
        if not 1 <= bond_min <= MAX_MONEY:          # D-1 (reconciled 2026-10-05): MoneyRange
            raise VaultError('bad-vault-act-bondmin')
    elif t == ACT_SET_JOIN:
        lt, vout = struct.unpack('<IB', body[65:70])
        a.update(setId=body[0:32].hex(), memberKey=key_at(32, 'memberKey'), bondLocktime=lt, bondVout=vout)
        if lt >= LOCKTIME_THRESHOLD:
            raise VaultError('bad-vault-act-locktime')
    elif t == ACT_SET_HEARTBEAT:
        a.update(setId=body[0:32].hex(), memberKey=key_at(32, 'memberKey'))
    elif t == ACT_SET_REMOVE:
        a.update(setId=body[0:32].hex(), memberKey=key_at(32, 'memberKey'), burn=body[65])
        if body[65] not in (0, 1):
            raise VaultError('bad-vault-act-burn')
    elif t == ACT_SET_EQUIVOCATION:
        a.update(setId=body[0:32].hex(), prevout=body[32:68].hex(),
                 roleA=body[68], sighashA=body[69:101].hex(), sigA=body[101:166].hex(),
                 roleB=body[166], sighashB=body[167:199].hex(), sigB=body[199:264].hex())
        if a['roleA'] not in (ROLE_UNLOCK, ROLE_CANCEL) or a['roleB'] not in (ROLE_UNLOCK, ROLE_CANCEL):
            raise VaultError('bad-vault-act-role')
        if not 31 <= body[101] <= 34 or not 31 <= body[199] <= 34:
            raise VaultError('bad-vault-act-sig')
    elif t == ACT_SET_WINDDOWN:
        a.update(setId=body[0:32].hex())
    return a


def act_script(payload, sigs=()):
    """``OP_RETURN <P> [<S_1> ... <S_n>]``, canonical pushes."""
    s = bytes([OP_RETURN]) + push(payload) + b''.join(push(x) for x in sigs)
    return s


def is_act_script(spk):
    """True if ``spk`` is an OP_RETURN whose first push starts with "YV" (an act output, which
    must then parse or the transaction is invalid)."""
    spk = bytes(spk)
    if not spk or spk[0] != OP_RETURN:
        return False
    ops = get_ops(spk[1:])
    if not ops:
        return False
    d = ops[0][1]
    return d is not None and d[:2] == ACT_MAGIC


def parse_act_script(spk):
    """``(P, act, [sigs])`` for an act output, None if ``spk`` is not one, raises
    ``VaultError`` if it is one and is malformed: every element after OP_RETURN a canonical data
    push, each S_i exactly 65 bytes, P decodes."""
    spk = bytes(spk)
    if not is_act_script(spk):
        return None
    ops = get_ops(spk[1:])
    vals = []
    for op, data in ops:
        if data is None:
            raise VaultError('bad-vault-act-script', 'non-push after OP_RETURN')
        vals.append(data)
    if act_script(vals[0], vals[1:]) != spk:
        raise VaultError('bad-vault-act-script', 'non-canonical push')
    p, sigs = vals[0], vals[1:]
    for s in sigs:
        if len(s) != SET_SIG_SIZE:
            raise VaultError('bad-vault-act-sig', 'signature size')
    return p, decode_act(p), sigs


def act_outputs(tx):
    return [i for i, o in enumerate(tx.vout) if is_act_script(o.scriptPubKey)]


# act constructors (dicts)

def act_set_create(seats, unlock_threshold, cancel_threshold, slash_threshold, admit_key, flags=0,
                   rate_limit_bps=0, rate_window=144, liveness_window=1440, bond_min=COIN, bond_lock_min=100,
                   maturity=10):
    return {'type': ACT_SET_CREATE, 'seats': seats, 'unlockThreshold': unlock_threshold,
            'cancelThreshold': cancel_threshold, 'slashThreshold': slash_threshold, 'flags': flags,
            'rateLimitBps': rate_limit_bps, 'rateWindow': rate_window, 'livenessWindow': liveness_window,
            'bondMin': bond_min, 'bondLockMin': bond_lock_min, 'maturity': maturity,
            'admitKey': bytes(admit_key).hex()}


def act_set_join(set_id32, member_key, bond_locktime, bond_vout=0):
    return {'type': ACT_SET_JOIN, 'setId': bytes(set_id32).hex(), 'memberKey': bytes(member_key).hex(),
            'bondLocktime': bond_locktime, 'bondVout': bond_vout}


def act_set_heartbeat(set_id32, member_key):
    return {'type': ACT_SET_HEARTBEAT, 'setId': bytes(set_id32).hex(), 'memberKey': bytes(member_key).hex()}


def act_set_remove(set_id32, member_key, burn=0):
    return {'type': ACT_SET_REMOVE, 'setId': bytes(set_id32).hex(), 'memberKey': bytes(member_key).hex(), 'burn': burn}


def act_set_equivocation(set_id32, prevout36, role_a, sighash_a, sig_a, role_b, sighash_b, sig_b):
    return {'type': ACT_SET_EQUIVOCATION, 'setId': bytes(set_id32).hex(), 'prevout': bytes(prevout36).hex(),
            'roleA': role_a, 'sighashA': bytes(sighash_a).hex(), 'sigA': bytes(sig_a).hex(),
            'roleB': role_b, 'sighashB': bytes(sighash_b).hex(), 'sigB': bytes(sig_b).hex()}


def act_set_winddown(set_id32):
    return {'type': ACT_SET_WINDDOWN, 'setId': bytes(set_id32).hex()}


def equivocation_key(act):
    """The key ``K`` an equivocation proof convicts, or raises (the context-free half of the
    SET_EQUIVOCATION rule: both signatures strict-valid over their 15.2 messages, same key,
    ``(roleA, sighashA) != (roleB, sighashB)``)."""
    set_id = bytes.fromhex(act['setId'])
    po = bytes.fromhex(act['prevout'])
    if (act['roleA'], act['sighashA']) == (act['roleB'], act['sighashB']):
        raise VaultError('bad-vault-act-equivocation', 'same message')
    ka = recover_compact(bytes.fromhex(act['sigA']),
                         set_sig_msg_raw(set_id, act['roleA'], po, bytes.fromhex(act['sighashA'])))
    kb = recover_compact(bytes.fromhex(act['sigB']),
                         set_sig_msg_raw(set_id, act['roleB'], po, bytes.fromhex(act['sighashB'])))
    if ka is None or kb is None or ka != kb:
        raise VaultError('bad-vault-act-equivocation', 'signatures')
    return ka


# ---------------------------------------------------------------------------
# Transaction builders (pure: inputs are given; the node helpers below choose them)
#
# vin entries are (txid_hex, n, nSequence); vout entries (value, spk).  Every builder returns a
# mininode CTransaction (v4 Sapling, transparent only); inputs other than the template input are
# left unsigned for ``signrawtransaction`` (or ``sign_p2pkh_input``).

def make_tx(vin, vout, lock_time=0, expiry=0):
    tx = CTransaction()
    for txid_hex, n, seq in vin:
        tx.vin.append(CTxIn(COutPoint(int(txid_hex, 16), n), b'', seq))
    for value, spk in vout:
        tx.vout.append(CTxOut(int(value), bytes(spk)))
    tx.nLockTime = lock_time
    tx.nExpiryHeight = expiry
    return tx


def is_coinbase(tx):
    return len(tx.vin) == 1 and tx.vin[0].prevout.hash == 0 and tx.vin[0].prevout.n == 0xFFFFFFFF


def tx_hex(tx):
    return tx.serialize().hex()


def tx_from_hex(h):
    tx = CTransaction()
    tx.deserialize(BytesIO(bytes.fromhex(h)))
    return tx


def prevout_of(tx, n_in):
    po = tx.vin[n_in].prevout
    return '%064x' % po.hash, po.n


def build_act_tx(vin, act, signer_secrets=(), outputs_before=(), change=None, lock_time=0, expiry=0):
    """An act transaction: ``outputs_before`` (e.g. the JOIN's bond at vout 0), then the YV
    output carrying ``P`` and one signature per secret over ``act_msg(P, vin[0].prevout)``, then
    ``change`` ``(value, spk)``.  Returns ``(tx, P)``."""
    p = encode_act(act) if isinstance(act, dict) else bytes(act)
    txid0, n0, _seq = vin[0]
    msg = act_msg(p, txid0, n0)
    sigs = [sign_recoverable(s, msg) for s in signer_secrets]
    vout = list(outputs_before) + [(0, act_script(p, sigs))]
    if change is not None:
        vout.append(change)
    return make_tx(vin, vout, lock_time, expiry), p


def build_set_create_tx(vin, act, change=None):
    return build_act_tx(vin, act, (), (), change)


def build_set_join_tx(vin, set_id32, member_secret, bond_value, bond_locktime, admit_secrets=(), change=None):
    """SET_JOIN: vout[0] = P2SH(B(memberKey, bondLocktime)) of ``bond_value``, vout[1] the act
    (``S_1`` by the member, then ``admit_secrets``: the admitKey, or ``slashThreshold`` current
    members), change.  Returns ``(tx, P)``."""
    mk = pubkey_of(member_secret)
    act = act_set_join(set_id32, mk, bond_locktime, 0)
    return build_act_tx(vin, act, [member_secret] + list(admit_secrets),
                        [(bond_value, bond_spk(mk, bond_locktime))], change)


def build_set_heartbeat_tx(vin, set_id32, member_secret, change=None):
    return build_act_tx(vin, act_set_heartbeat(set_id32, pubkey_of(member_secret)), [member_secret], (), change)


def build_set_remove_tx(vin, set_id32, target_key, signer_secrets, burn=0, change=None):
    return build_act_tx(vin, act_set_remove(set_id32, target_key, burn), signer_secrets, (), change)


def build_set_equivocation_tx(vin, proof_act, change=None):
    return build_act_tx(vin, proof_act, (), (), change)


def build_set_winddown_tx(vin, set_id32, signer_secrets, change=None):
    return build_act_tx(vin, act_set_winddown(set_id32), signer_secrets, (), change)


def equivocation_proof(set_id32, member_secret, prevout_txid_hex, prevout_n, role_a, sighash_a, role_b, sighash_b):
    """A SET_EQUIVOCATION act from two set signatures by one member on one outpoint."""
    po = ser_prevout(prevout_txid_hex, prevout_n)
    sa = sign_recoverable(member_secret, set_sig_msg_raw(set_id32, role_a, po, sighash_a))
    sb = sign_recoverable(member_secret, set_sig_msg_raw(set_id32, role_b, po, sighash_b))
    return act_set_equivocation(set_id32, po, role_a, sighash_a, sa, role_b, sighash_b, sb)


def build_lock_tx(vin, vp, amount, change=None, extra_vout=()):
    """Vault lock: vout[0] = V(vp) of ``amount``."""
    vout = [(amount, vault_script(vp))] + list(extra_vout)
    if change is not None:
        vout.append(change)
    return make_tx(vin, vout)


def set_sigs_for(tx, n_in, spk, amount, set_id32, role, member_secrets, branch_id=VAULT_BRANCH_ID):
    """The ``k`` set signatures over ``set_sig_msg(setId, role, prevout, sighash)``."""
    sh = template_sighash(tx, n_in, spk, amount, branch_id)
    txid, n = prevout_of(tx, n_in)
    msg = set_sig_msg(set_id32, role, txid, n, sh)
    return [sign_recoverable(s, msg) for s in member_secrets]


def build_unlock_tx(vault_outpoint, vp, vault_value, recipients, relock_value=0, fee_vin=(), change=None,
                    member_secrets=(), branch_id=VAULT_BRANCH_ID, selector=SEL_UNLOCK, lock_time=0):
    """UNLOCK (selector 1) or APP (selector 4): vin[0] the V, ``fee_vin`` after it; vout = one I
    per ``(recipient_spk, value)``, then a byte-identical re-lock of ``relock_value`` if > 0,
    then ``change``.  With ``member_secrets`` the scriptSig ``<sig_1..k> OP_1`` is set (sign
    after every other field is final: the sighash commits to all outputs and sequences).  APP
    needs ``lock_time >= appHeight``; the V input's nSequence is then 0xFFFFFFFE."""
    v_spk = vault_script(vp)
    seq = SEQUENCE_FINAL if selector == SEL_UNLOCK else SEQUENCE_FINAL - 1
    vin = [(vault_outpoint[0], vault_outpoint[1], seq)] + list(fee_vin)
    vout = [(value, intent_script(intent_for(vp, spk))) for spk, value in recipients]
    if relock_value:
        vout.append((relock_value, v_spk))
    if change is not None:
        vout.append(change)
    tx = make_tx(vin, vout, lock_time)
    if selector == SEL_APP:
        tx.vin[0].scriptSig = vault_app_scriptsig()
    elif member_secrets:
        sigs = set_sigs_for(tx, 0, v_spk, vault_value, vp.set_id, ROLE_UNLOCK, member_secrets, branch_id)
        tx.vin[0].scriptSig = vault_unlock_scriptsig(sigs)
    return tx


def build_release_tx(intent_outpoint, ip, intent_value, recipient_spk, fee_vin=(), change=None):
    """RELEASE (I selector 1): vin[0] the I with nSequence = delay (BIP68), scriptSig OP_1;
    vout[0] pays ``intent_value`` to the recipient (I-1); the fee comes from ``fee_vin``."""
    assert sha256(bytes(recipient_spk)) == ip.recipient_hash, 'recipient does not match the intent'
    vin = [(intent_outpoint[0], intent_outpoint[1], ip.delay)] + list(fee_vin)
    vout = [(intent_value, recipient_spk)]
    if change is not None:
        vout.append(change)
    tx = make_tx(vin, vout)
    tx.vin[0].scriptSig = intent_release_scriptsig()
    return tx


def build_cancel_tx(intent_outpoint, ip, intent_value, vp, fee_vin=(), change=None, member_secrets=(),
                    branch_id=VAULT_BRANCH_ID):
    """CANCEL (I selector 2): vout[0] the originating V (``SHA256(spk) = vaultHash``) of the I's
    value; scriptSig ``<sig_1..k> OP_2`` by the cancel set."""
    v_spk = vault_script(vp)
    assert sha256(v_spk) == ip.vault_hash, 'vault does not match the intent'
    i_spk = intent_script(ip)
    vin = [(intent_outpoint[0], intent_outpoint[1], SEQUENCE_FINAL)] + list(fee_vin)
    vout = [(intent_value, v_spk)]
    if change is not None:
        vout.append(change)
    tx = make_tx(vin, vout)
    if member_secrets:
        sigs = set_sigs_for(tx, 0, i_spk, intent_value, ip.cancel_set_id, ROLE_CANCEL, member_secrets, branch_id)
        tx.vin[0].scriptSig = intent_cancel_scriptsig(sigs)
    return tx


def owner_sig(tx, n_in, spk, amount, owner_secret, branch_id=VAULT_BRANCH_ID):
    sh = template_sighash(tx, n_in, spk, amount, branch_id)
    return ecdsa_sign_der(owner_secret, sh) + bytes([SIGHASH_ALL])


def build_owner_spend_tx(outpoint, spk, value, owner_secret, dest_spk, selector, lock_time=0, fee=VAULT_FEE,
                         branch_id=VAULT_BRANCH_ID):
    """OWNER (V selector 2: ``lock_time >= ownerHeight``, nSequence 0xFFFFFFFE) or OWNER-RELEASED
    (V or I selector 3): one output of ``value - fee`` to ``dest_spk``."""
    seq = SEQUENCE_FINAL - 1 if selector == SEL_OWNER and parse_vault(spk) is not None else SEQUENCE_FINAL
    tx = make_tx([(outpoint[0], outpoint[1], seq)], [(value - fee, dest_spk)], lock_time)
    sig = owner_sig(tx, 0, spk, value, owner_secret, branch_id)
    if parse_vault(spk) is not None:
        tx.vin[0].scriptSig = vault_owner_scriptsig(sig) if selector == SEL_OWNER else vault_owner_released_scriptsig(sig)
    else:
        assert selector == SEL_OWNER_RELEASED
        tx.vin[0].scriptSig = intent_owner_released_scriptsig(sig)
    return tx


def build_app_tx(vault_outpoint, vp, vault_value, recipients, fee_vin=(), change=None, relock_value=0):
    """APP (selector 4): as UNLOCK but no signatures and ``nLockTime = appHeight``."""
    return build_unlock_tx(vault_outpoint, vp, vault_value, recipients, relock_value, fee_vin, change,
                           selector=SEL_APP, lock_time=vp.app_height)


def build_bond_spend_tx(bond_outpoint, member_secret, bond_value, bond_locktime, dest_spk, fee=VAULT_FEE,
                        branch_id=VAULT_BRANCH_ID):
    """Withdraw a bond at its locktime: ``<sig> <B>``, nLockTime = bondLocktime."""
    redeem = bond_script(pubkey_of(member_secret), bond_locktime)
    tx = make_tx([(bond_outpoint[0], bond_outpoint[1], SEQUENCE_FINAL - 1)], [(bond_value - fee, dest_spk)],
                 bond_locktime)
    sig = owner_sig(tx, 0, redeem, bond_value, member_secret, branch_id)
    tx.vin[0].scriptSig = push(sig) + push(redeem)
    return tx


def sign_p2pkh_input(tx, n_in, secret32, amount, branch_id=VAULT_BRANCH_ID):
    """Sign a P2PKH input in pure Python (for vectors and node-less tests)."""
    pk = pubkey_of(secret32)
    spk = p2pkh_script_of_pubkey(pk)
    sig = owner_sig(tx, n_in, spk, amount, secret32, branch_id)
    tx.vin[n_in].scriptSig = push(sig) + push(pk)
    return tx


# ---------------------------------------------------------------------------
# Node helpers (stock RPCs: listunspent, getnewaddress, validateaddress, signrawtransaction,
# sendrawtransaction, lockunspent)

def _amount_zat(a):
    from decimal import Decimal
    return int(Decimal(str(a)) * COIN)


def node_spk(node, address=None):
    return bytes.fromhex(node.validateaddress(address or node.getnewaddress())['scriptPubKey'])


def node_funding(node, needed):
    """Confirmed P2PKH coins of ``node``, largest first, until ``needed`` zat.  Returns
    ``([(txid, n, seq)], total)``."""
    us = [u for u in node.listunspent(1) if is_p2pkh(bytes.fromhex(u['scriptPubKey']))]
    us.sort(key=lambda u: _amount_zat(u['amount']), reverse=True)
    chosen, total = [], 0
    for u in us:
        chosen.append((u['txid'], int(u['vout']), SEQUENCE_FINAL))
        total += _amount_zat(u['amount'])
        if total >= needed:
            break
    assert total >= needed, 'insufficient funds for a hand-built vault transaction (%d < %d)' % (total, needed)
    return chosen, total


def node_sign(node, tx, template_scriptsig=None, n_template=0):
    """``signrawtransaction`` for the ordinary inputs, then (re)set the template input's scriptSig
    (ZIP-243 sighashes exclude scriptSigs, so the order does not matter).  Returns the hex."""
    hex_ = node.signrawtransaction(tx_hex(tx))['hex']
    if template_scriptsig is None:
        return hex_
    t = tx_from_hex(hex_)
    t.vin[n_template].scriptSig = bytes(template_scriptsig)
    return tx_hex(t)


def node_send(node, hex_):
    """``sendrawtransaction`` and ``lockunspent`` the inputs (so the next hand-built transaction
    of this block does not pick them).  Returns the txid."""
    txid = node.sendrawtransaction(hex_)
    t = tx_from_hex(hex_)
    try:
        node.lockunspent(False, [{'txid': '%064x' % i.prevout.hash, 'vout': i.prevout.n} for i in t.vin])
    except Exception:
        pass
    return txid


def node_act_tx(node, act, signer_secrets=(), outputs_before=(), fee=VAULT_FEE):
    """Fund, sign and return the hex of an act transaction from ``node``'s coins."""
    need = sum(v for v, _ in outputs_before) + fee
    vin, total = node_funding(node, need)
    change = (total - need, node_spk(node)) if total > need else None
    tx, _p = build_act_tx(vin, act, signer_secrets, outputs_before, change)
    return node_sign(node, tx)


def node_set_create(node, act, fee=VAULT_FEE):
    """Returns ``(hex, setId32)``; setId = the txid's internal bytes (its scriptSigs are final)."""
    hex_ = node_act_tx(node, act, (), (), fee)
    return hex_, txid_internal(tx_txid(tx_from_hex(hex_)))


def node_set_join(node, set_id32, member_secret, bond_value, bond_locktime, admit_secrets=(), fee=VAULT_FEE):
    mk = pubkey_of(member_secret)
    return node_act_tx(node, act_set_join(set_id32, mk, bond_locktime, 0), [member_secret] + list(admit_secrets),
                       [(bond_value, bond_spk(mk, bond_locktime))], fee)


def node_lock(node, vp, amount, fee=VAULT_FEE):
    vin, total = node_funding(node, amount + fee)
    change = (total - amount - fee, node_spk(node)) if total > amount + fee else None
    return node_sign(node, build_lock_tx(vin, vp, amount, change))


def node_fee_inputs(node, fee=VAULT_FEE):
    vin, total = node_funding(node, fee)
    change = (total - fee, node_spk(node)) if total > fee else None
    return vin, change


def node_unlock(node, vault_outpoint, vp, vault_value, recipients, member_secrets, relock_value=0,
                branch_id=VAULT_BRANCH_ID):
    fee_vin, change = node_fee_inputs(node)
    tx = build_unlock_tx(vault_outpoint, vp, vault_value, recipients, relock_value, fee_vin, change,
                         member_secrets, branch_id)
    return node_sign(node, tx, tx.vin[0].scriptSig)


def node_release(node, intent_outpoint, ip, intent_value, recipient_spk):
    fee_vin, change = node_fee_inputs(node)
    tx = build_release_tx(intent_outpoint, ip, intent_value, recipient_spk, fee_vin, change)
    return node_sign(node, tx, tx.vin[0].scriptSig)


def node_cancel(node, intent_outpoint, ip, intent_value, vp, member_secrets, branch_id=VAULT_BRANCH_ID):
    fee_vin, change = node_fee_inputs(node)
    tx = build_cancel_tx(intent_outpoint, ip, intent_value, vp, fee_vin, change, member_secrets, branch_id)
    return node_sign(node, tx, tx.vin[0].scriptSig)


# ---------------------------------------------------------------------------
# Reference model (15.4 - 15.6)

def bip68_ok(coin_height, n_sequence, height):
    """BIP68 height lock for one input (U-11), Bitcoin's CalculateSequenceLocks /
    EvaluateSequenceLocks: ``coinHeight + (nSequence & 0xffff) - 1 < height``.  (15.2's prose
    "<= spending height - 1" is one block stricter; see VAULT_VECTORS.md, ambiguity A-3.)"""
    if n_sequence & SEQUENCE_DISABLE_FLAG:
        return True
    if n_sequence & SEQUENCE_TYPE_FLAG:
        return False
    return coin_height + (n_sequence & SEQUENCE_MASK) - 1 < height


class Member(object):
    def __init__(self, key, bond_outpoint, bond_value, bond_locktime, join_height, maturity):
        self.key = key
        self.bond_outpoint = bond_outpoint
        self.bond_value = bond_value
        self.bond_locktime = bond_locktime
        self.join_height = join_height
        self.last_act = join_height + maturity
        self.status = MEMBER_ACTIVE
        self.bond_frozen = False

    def to_json(self):
        return {'memberKey': self.key.hex(), 'bondOutpoint': {'txid': self.bond_outpoint[0], 'vout': self.bond_outpoint[1]},
                'bondValue': self.bond_value, 'bondLocktime': self.bond_locktime, 'joinHeight': self.join_height,
                'lastAct': self.last_act, 'status': self.status, 'bondFrozen': self.bond_frozen}


class SetState(object):
    def __init__(self, set_id, act, create_height):
        self.set_id = set_id
        self.p = dict(act)
        self.create_height = create_height
        self.wind_down_height = 0
        self.locked_value = 0
        self.epoch = 0
        self.epoch_basis = 0
        self.epoch_used = 0
        self.members = {}              # key33 -> Member (insertion order = join order)

    def current(self, h):
        mat = self.p['maturity']
        return [m for m in self.members.values() if m.status == MEMBER_ACTIVE and h >= m.join_height + mat]

    def is_current(self, key, h):
        m = self.members.get(bytes(key))
        return m is not None and m.status == MEMBER_ACTIVE and h >= m.join_height + self.p['maturity']

    def active_count(self):
        return sum(1 for m in self.members.values() if m.status == MEMBER_ACTIVE)

    def dormant(self, h):
        live = [m for m in self.current(h) if m.last_act >= h - self.p['livenessWindow']]
        return len(live) < self.p['cancelThreshold']

    def released(self, h):
        return self.dormant(h) or (self.wind_down_height != 0 and h >= self.wind_down_height + self.p['livenessWindow'])

    def threshold(self, role):
        return self.p['unlockThreshold'] if role == ROLE_UNLOCK else self.p['cancelThreshold']

    def roll(self, h):
        """U-20, rolled before every read or write of the rate fields (ambiguity A-6), so the
        basis is lockedValue as it stood when the epoch began."""
        e = h // self.p['rateWindow']
        if e != self.epoch:
            self.epoch = e
            self.epoch_basis = self.locked_value
            self.epoch_used = 0

    def info(self, h):
        return {'setId': txid_display(self.set_id), 'createHeight': self.create_height,
                'windDownHeight': self.wind_down_height, 'lockedValue': self.locked_value,
                'epoch': self.epoch, 'epochBasis': self.epoch_basis, 'epochUsed': self.epoch_used,
                'current': len(self.current(h)), 'dormant': self.dormant(h), 'released': self.released(h),
                'members': [m.to_json() for m in self.members.values()],
                'params': {k: v for k, v in self.p.items() if k not in ('type', 'name')}}


class Coin(object):
    __slots__ = ('value', 'spk', 'height')

    def __init__(self, value, spk, height):
        self.value, self.spk, self.height = value, bytes(spk), height


class VaultModel(object):
    """Sequential block application of 15.4-15.6 from activation.

    The model keeps its own coin view: every output of every transaction it connects, plus
    whatever a test seeds with ``add_coin`` (e.g. a funding coin whose transaction predates the
    model).  An input whose coin it does not know is treated as an ordinary input (no BIP68
    check, no template rule).  Ordinary input scripts are not evaluated; template branches are,
    to the extent the rules need: set signatures (strict recovery, distinct current members of
    the parent-block snapshot), the owner's DER signature, CLTV / CSV, dormancy.

    ``connect_block(height, txs)`` returns None and commits, or returns ``(index, reason)`` of the
    first failing transaction and leaves the state untouched (the block is invalid).
    ``check_tx(tx, height)`` predicts the mempool answer at ``height`` (= tip + 1).
    ``disconnect_block()`` undoes the last connected block."""

    def __init__(self, activation_height=1, branch_id=VAULT_BRANCH_ID, check_scripts=True):
        self.activation_height = activation_height
        self.branch_id = branch_id
        self.check_scripts = check_scripts
        self.sets = {}               # setId32 -> SetState
        self.bonds = {}              # (txid, n) -> [setId32, key33, frozen]: the frozen-bond index
        self.coins = {}              # (txid, n) -> Coin
        self.tip = activation_height - 1
        self._undo = []

    # --- queries
    def get_set(self, set_id32):
        return self.sets.get(bytes(set_id32))

    def is_released(self, set_id32, h):
        s = self.get_set(set_id32)
        return True if s is None else s.released(h)

    def is_dormant(self, set_id32, h):
        s = self.get_set(set_id32)
        return True if s is None else s.dormant(h)

    def set_info(self, set_id32, h=None):
        s = self.get_set(set_id32)
        return None if s is None else s.info(self.tip + 1 if h is None else h)

    def add_coin(self, txid_hex, n, value, spk, height):
        self.coins[(txid_hex, n)] = Coin(value, spk, height)

    # --- blocks
    def _state(self):
        return (self.sets, self.bonds, self.coins, self.tip)

    def connect_block(self, height, txs):
        assert height == self.tip + 1, 'blocks connect in order (tip %d, got %d)' % (self.tip, height)
        saved = copy.deepcopy(self._state())
        snapshot = copy.deepcopy(self.sets)      # U-17: script checks see the parent block's state
        for i, tx in enumerate(txs):
            try:
                self._apply_tx(tx, height, snapshot)
            except VaultError as e:
                self.sets, self.bonds, self.coins, self.tip = saved
                return (i, e.reason)
        self._undo.append(saved)
        self.tip = height
        return None

    def disconnect_block(self):
        self.sets, self.bonds, self.coins, self.tip = self._undo.pop()

    def check_tx(self, tx, height=None):
        """Reason the transaction would be rejected at ``height`` (default tip + 1), or None."""
        h = self.tip + 1 if height is None else height
        saved = copy.deepcopy(self._state())
        try:
            self._apply_tx(tx, h, copy.deepcopy(self.sets))
            return None
        except VaultError as e:
            return e.reason
        finally:
            self.sets, self.bonds, self.coins, self.tip = saved

    # --- one transaction
    def _apply_tx(self, tx, h, snapshot):
        txid = tx_txid(tx)
        active = h >= self.activation_height
        spent = []
        for i, txin in enumerate(tx.vin):
            key = ('%064x' % txin.prevout.hash, txin.prevout.n)
            spent.append((i, key, self.coins.get(key)))
        if active:
            # outputs first, as the C++ classifies them: a second act, a malformed V / I shape
            # (reconciliation (8)), an act in a coinbase (9)
            n_acts = 0
            for o in tx.vout:
                if is_act_script(o.scriptPubKey):
                    n_acts += 1
                    if n_acts > 1:
                        raise VaultError('bad-vault-act-count')
                elif template_shape(o.scriptPubKey) == 'malformed':
                    raise VaultError('bad-txns-vault-malformed')
            if n_acts and is_coinbase(tx):
                raise VaultError('bad-vault-act-coinbase')
            # BIP68 on every input (U-11)
            for i, key, coin in spent:
                seq = tx.vin[i].nSequence
                if not seq & SEQUENCE_DISABLE_FLAG and seq & SEQUENCE_TYPE_FLAG:
                    raise VaultError('bad-txns-vault-timelock')
                if coin is not None and not bip68_ok(coin.height, seq, h):
                    raise VaultError('bad-txns-vault-timelock')
            # bonds
            for i, key, coin in spent:
                b = self.bonds.get(key)
                if b is None:
                    continue
                if b[2]:
                    raise VaultError('bad-vault-bond-frozen')
                m = self.sets[b[0]].members.get(b[1])
                if m is not None and m.bond_outpoint == key and m.status == MEMBER_ACTIVE:
                    m.status = MEMBER_WITHDRAWN
                del self.bonds[key]
            self._template_rules(tx, txid, spent, h, snapshot)
            acts = act_outputs(tx)
            if len(acts) > 1:
                raise VaultError('bad-vault-act-count')
            if acts:
                self._apply_act(tx, txid, acts[0], h)
        for _i, key, _c in spent:
            self.coins.pop(key, None)
        for n, o in enumerate(tx.vout):
            self.coins[(txid, n)] = Coin(o.nValue, o.scriptPubKey, h)

    def _template_rules(self, tx, txid, spent, h, snapshot):
        tins = []
        for i, key, coin in spent:
            if coin is None:
                continue
            vp, ip = parse_vault(coin.spk), parse_intent(coin.spk)
            if vp is not None or ip is not None:
                tins.append((i, key, coin, vp, ip))
        if len(tins) > 1:
            raise VaultError('bad-vault-template-count')                          # S-1
        v_outs = [(n, o, parse_vault(o.scriptPubKey)) for n, o in enumerate(tx.vout)]
        v_outs = [(n, o, p) for n, o, p in v_outs if p is not None]
        i_outs = [(n, o, parse_intent(o.scriptPubKey)) for n, o in enumerate(tx.vout)]
        i_outs = [(n, o, p) for n, o, p in i_outs if p is not None]
        covenant = False
        if tins:
            i, key, coin, vp, ip = tins[0]
            sel = parse_selector(tx.vin[i].scriptSig, 'V' if vp is not None else 'I')
            if sel is None:
                raise VaultError('bad-vault-selector')                            # S-1
            selector, args = sel
            if vp is not None:
                covenant = self._spend_vault(tx, i, coin, vp, selector, args, i_outs, h, snapshot)
            else:
                self._spend_intent(tx, i, coin, ip, selector, args, h, snapshot)
        if i_outs and not covenant:
            raise VaultError('bad-vault-intent-create')                           # I-0
        for n, o, p in v_outs:                                                    # V-1
            for sid in (p.set_id, p.cancel_set_id):
                s = self.sets.get(sid)
                if s is None or s.create_height >= h:
                    raise VaultError('bad-vault-unknown-set')
            s = self.sets[p.set_id]
            s.roll(h)
            s.locked_value += o.nValue

    def _check_set_sigs(self, tx, i, coin, set_id, role, args, h, snapshot):
        if not self.check_scripts:
            return
        s = snapshot.get(set_id)
        if s is None:
            raise VaultError('script-setsig', 'unknown set')
        k = s.threshold(role)
        if len(args) < k:
            raise VaultError('script-setsig', 'need %d signatures' % k)
        args = args[-k:]      # OP_CHECKSETSIG pops k; anything below stays (no CLEANSTACK)
        sh = template_sighash(tx, i, coin.spk, coin.value, self.branch_id)
        po = tx.vin[i].prevout
        msg = set_sig_msg_raw(set_id, role, po.serialize(), sh)
        seen = set()
        for sig in args:
            if len(sig) != SET_SIG_SIZE:
                raise VaultError('script-setsig', 'size')
            key = recover_compact(sig, msg)
            if key is None or key in seen or not s.is_current(key, h):
                raise VaultError('script-setsig', 'signer')
            seen.add(key)

    def _check_owner(self, tx, i, coin, owner_key, args):
        if not self.check_scripts:
            return
        if not args or len(args[-1]) < 2 or args[-1][-1] != SIGHASH_ALL:
            raise VaultError('script-ownersig')
        sh = template_sighash(tx, i, coin.spk, coin.value, self.branch_id)
        if not ecdsa_verify_der(owner_key, sh, args[-1][:-1]):
            raise VaultError('script-ownersig')

    @staticmethod
    def _cltv(tx, i, height_arg, h):
        """OP_CHECKLOCKTIMEVERIFY plus IsFinalTx (nLockTime < h unless every input is final)."""
        if tx.vin[i].nSequence == SEQUENCE_FINAL or tx.nLockTime >= LOCKTIME_THRESHOLD or tx.nLockTime < height_arg:
            raise VaultError('script-locktime')
        if tx.nLockTime >= h:
            raise VaultError('bad-txns-nonfinal')

    def _spend_vault(self, tx, i, coin, vp, selector, args, i_outs, h, snapshot):
        s = self.sets.get(vp.set_id)
        if selector == SEL_UNLOCK:
            self._check_set_sigs(tx, i, coin, vp.set_id, ROLE_UNLOCK, args, h, snapshot)
        elif selector == SEL_OWNER:
            self._cltv(tx, i, vp.owner_height, h)
            self._check_owner(tx, i, coin, vp.owner_key, args)
        elif selector == SEL_OWNER_RELEASED:
            snap = snapshot.get(vp.set_id)
            if snap is not None and not snap.released(h):
                raise VaultError('script-notreleased')
            self._check_owner(tx, i, coin, vp.owner_key, args)
        else:
            if vp.app_height == 0:
                raise VaultError('bad-vault-app-disabled')                         # S-4
            self._cltv(tx, i, vp.app_height, h)
        if selector in (SEL_OWNER, SEL_OWNER_RELEASED):                           # S-4
            if s is not None:
                s.roll(h)
                s.locked_value -= coin.value
            return False
        # S-2 covenant
        v_spk = coin.spk
        want = intent_for(vp, b'')
        sum_i = sum_relock = 0
        for n, o in enumerate(tx.vout):
            ip = parse_intent(o.scriptPubKey)
            if ip is not None:
                if (ip.tag, ip.set_id, ip.cancel_set_id, ip.delay, ip.owner_key, ip.vault_hash) != \
                        (want.tag, want.set_id, want.cancel_set_id, want.delay, want.owner_key, want.vault_hash):
                    raise VaultError('bad-vault-covenant', 'intent fields')
                sum_i += o.nValue
            elif o.scriptPubKey == v_spk:
                sum_relock += o.nValue
        if sum_i + sum_relock < coin.value:
            raise VaultError('bad-vault-covenant', 'value leaves the vault')
        if s is not None:                                                         # S-3
            s.roll(h)
            if s.p['rateLimitBps'] and s.epoch_used + sum_i > s.epoch_basis * s.p['rateLimitBps'] // 10000:
                raise VaultError('bad-vault-rate')
            s.epoch_used += sum_i
            s.locked_value -= coin.value       # the re-lock is added back by V-1 (A-5)
        return True

    def _spend_intent(self, tx, i, coin, ip, selector, args, h, snapshot):
        if selector == SEL_RELEASE:
            seq = tx.vin[i].nSequence
            if seq & SEQUENCE_DISABLE_FLAG or seq & SEQUENCE_TYPE_FLAG or (seq & SEQUENCE_MASK) < ip.delay:
                raise VaultError('script-sequence')                               # CSV
            if not any(sha256(o.scriptPubKey) == ip.recipient_hash and o.nValue >= coin.value for o in tx.vout):
                raise VaultError('bad-vault-release')                             # I-1
        elif selector == SEL_CANCEL:
            self._check_set_sigs(tx, i, coin, ip.cancel_set_id, ROLE_CANCEL, args, h, snapshot)
            if not h - coin.height < ip.delay:
                raise VaultError('bad-vault-cancel-late')                         # I-2
            if not any(sha256(o.scriptPubKey) == ip.vault_hash and o.nValue >= coin.value for o in tx.vout):
                raise VaultError('bad-vault-cancel')
        else:
            snap = snapshot.get(ip.set_id)
            if snap is not None and not snap.released(h):
                raise VaultError('script-notreleased')
            self._check_owner(tx, i, coin, ip.owner_key, args)

    def _sig_keys(self, p, sigs, prevout36, require_distinct=True):
        msg = act_msg_raw(p, prevout36)
        keys = []
        for s in sigs:
            k = recover_compact(s, msg)
            if k is None:
                raise VaultError('bad-vault-act-sig')
            keys.append(k)
        if require_distinct and len(set(keys)) != len(keys):
            raise VaultError('bad-vault-act-sig', 'duplicate signer')
        return keys

    def _apply_act(self, tx, txid, n, h):
        p, a, sigs = parse_act_script(tx.vout[n].scriptPubKey)
        po = tx.vin[0].prevout.serialize()
        t = a['type']
        if t == ACT_SET_CREATE:
            if sigs:
                raise VaultError('bad-vault-act-sig', 'SET_CREATE takes none')
            sid = txid_internal(txid)
            self.sets[sid] = SetState(sid, a, h)
            self.sets[sid].epoch = h // a['rateWindow']
            return
        if t == ACT_SET_EQUIVOCATION:
            if sigs:
                raise VaultError('bad-vault-act-sig', 'SET_EQUIVOCATION takes none')
            k = equivocation_key(a)
            s = self.sets.get(bytes.fromhex(a['setId']))
            m = None if s is None else s.members.get(k)
            b = None if m is None else self.bonds.get(m.bond_outpoint)
            if b is None or b[2]:
                raise VaultError('bad-vault-act-equivocation', 'not a member with a live bond')
            m.status = MEMBER_EJECTED
            m.bond_frozen = b[2] = True
            return
        sid = bytes.fromhex(a['setId'])
        s = self.sets.get(sid)
        if s is None:
            raise VaultError('bad-vault-act-set')
        keys = self._sig_keys(p, sigs, po)
        th = s.p['slashThreshold']
        if t == ACT_SET_JOIN:
            mk = bytes.fromhex(a['memberKey'])
            if s.create_height >= h or s.wind_down_height:
                raise VaultError('bad-vault-act-join', 'set not joinable')
            if s.active_count() >= s.p['seats']:
                raise VaultError('bad-vault-act-join', 'no seat')
            old = s.members.get(mk)
            if old is not None and old.status == MEMBER_ACTIVE:
                raise VaultError('bad-vault-act-join', 'already active')
            if not keys or keys[0] != mk:
                raise VaultError('bad-vault-act-sig', 'S_1 must be the member')
            admit = keys[1:]
            if not s.p['flags'] & SET_FLAG_OPEN:
                cur = s.current(h)
                if len(cur) >= th:
                    if len(admit) != th or any(not s.is_current(k, h) for k in admit):
                        raise VaultError('bad-vault-act-sig', 'admission')
                else:
                    if admit != [bytes.fromhex(s.p['admitKey'])]:
                        raise VaultError('bad-vault-act-sig', 'admitKey')
            elif admit:
                raise VaultError('bad-vault-act-sig', 'OPEN set takes only S_1')
            bv = a['bondVout']
            if bv >= len(tx.vout):
                raise VaultError('bad-vault-act-bond')
            bo = tx.vout[bv]
            if bo.scriptPubKey != bond_spk(mk, a['bondLocktime']) or bo.nValue < s.p['bondMin']:
                raise VaultError('bad-vault-act-bond')
            if a['bondLocktime'] < h + s.p['bondLockMin']:
                raise VaultError('bad-vault-act-bond', 'locktime')
            m = Member(mk, (txid, bv), bo.nValue, a['bondLocktime'], h, s.p['maturity'])
            s.members.pop(mk, None)
            s.members[mk] = m
            self.bonds[(txid, bv)] = [sid, mk, False]
        elif t == ACT_SET_HEARTBEAT:
            mk = bytes.fromhex(a['memberKey'])
            if keys != [mk] or not s.is_current(mk, h):
                raise VaultError('bad-vault-act-heartbeat')
            s.members[mk].last_act = h
        elif t == ACT_SET_REMOVE:
            mk = bytes.fromhex(a['memberKey'])
            m = s.members.get(mk)
            if m is None or m.status != MEMBER_ACTIVE:
                raise VaultError('bad-vault-act-remove', 'target not active')
            if len(keys) != th or mk in keys or any(not s.is_current(k, h) for k in keys):
                raise VaultError('bad-vault-act-sig', 'removal signers')
            m.status = MEMBER_REMOVED
            if a['burn']:
                m.bond_frozen = self.bonds[m.bond_outpoint][2] = True
        elif t == ACT_SET_WINDDOWN:
            if s.wind_down_height:
                raise VaultError('bad-vault-act-winddown', 'already wound down')
            if len(keys) != th or any(not s.is_current(k, h) for k in keys):
                raise VaultError('bad-vault-act-sig', 'winddown signers')
            s.wind_down_height = h
