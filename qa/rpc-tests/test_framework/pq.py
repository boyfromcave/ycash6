#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Post-quantum signatures for the test framework (docs/plans/yellowback-quantum-plan.md §4.1-§4.3,
§4.7), in pure Python with the standard library only, written from the standards independently of
the vendored C in ``src/crypto/pq/``.

- **SLH-DSA-SHA2-128s** (FIPS 205, scheme ``0x01``): ``slh_keygen(seed48)``, ``slh_sign(sk, msg)``
  (deterministic: ``opt_rand = PK.seed``), ``slh_verify(pk, msg, sig)``; the *pure* interface with an
  empty context, ``M' = 0x00 || 0x00 || M`` (``ctx`` is a parameter for the ACVP vectors only).
  The ``*_internal`` functions are FIPS 205 Algorithms 18-20 (ACVP's ``internal`` interface).
- **FN-DSA-512, PQClean ``falcon-padded-512``** (scheme ``0x02``): ``falcon_verify(pk, msg, sig)``
  in pure Python, integer arithmetic (897-byte key, 666-byte padded signature). Signing is optional
  and not Python: ``falcon_keygen(seed48)`` / ``falcon_sign(sk, msg, entropy=None)`` compile the
  tree's vendored PQClean C (``src/crypto/pq/falcon``, the wallet's signer) with ``$CC`` once per run
  and call it through ctypes, byte-identical to ``pq::KeyGen`` / ``pq::SignWithEntropy``; without a
  C compiler they raise ``FalconSignerUnavailable`` (``falcon_signer_available()`` to skip).
- **Script helpers**: ``key_hash``, ``chunk``, ``pq_scriptsig_pushes`` / ``pq_scriptsig``,
  ``pqpkh_script`` (``TX_PQPKH``) and ``pq_sign_input`` (ZIP-243 sighash, the same
  ``SignatureHash`` the framework signs vault spends with, hashtype byte appended to the signature).

The message a script signature signs is the 32-byte ZIP-243 sighash in memory order: the bytes
``SignatureHash(...)[0]`` returns, which are the ``uint256::begin()..end()`` bytes the node hands
``pq::Verify`` (the bytes ``CPubKey::Verify`` is given).

Speed (CPython 3.13, Apple silicon, one core): SLH-DSA keygen ~0.1 s, sign ~0.75 s, verify ~1 ms;
Falcon verify ~2 ms. ``slh_sign(..., processes=N)`` builds the seven hypertree layers in N processes
(fork where available; ~0.35 s with 4).
"""

import hashlib
import hmac

# ---------------------------------------------------------------------------
# Scheme registry (plan §4.1)

SCHEME_SLH_DSA_SHA2_128S = 0x01
SCHEME_FN_DSA_512 = 0x02

KEYHASH_SIZE = 32
MAX_CHUNK = 520                 # == MAX_SCRIPT_ELEMENT_SIZE
SIGOP_COST = 20

PUBKEY_SIZE = {SCHEME_SLH_DSA_SHA2_128S: 32, SCHEME_FN_DSA_512: 897}
SIG_SIZE = {SCHEME_SLH_DSA_SHA2_128S: 7856, SCHEME_FN_DSA_512: 666}     # without the hashtype byte

SIGHASH_ALL = 1


def pubkey_size(scheme):
    return PUBKEY_SIZE.get(scheme, 0)


def sig_size(scheme):
    return SIG_SIZE.get(scheme, 0)


def is_known_scheme(scheme):
    return scheme in PUBKEY_SIZE


# ---------------------------------------------------------------------------
# SLH-DSA-SHA2-128s (FIPS 205)

SLH_N = 16
SLH_H = 63
SLH_D = 7
SLH_HP = 9                       # h' = h / d
SLH_A = 12
SLH_K = 14
SLH_LGW = 4
SLH_W = 16
SLH_M = 30
SLH_LEN1 = 32
SLH_LEN2 = 3
SLH_LEN = 35
SLH_PK_BYTES = 2 * SLH_N
SLH_SK_BYTES = 4 * SLH_N
SLH_SIG_BYTES = SLH_N * (1 + SLH_K * (1 + SLH_A) + SLH_H + SLH_D * SLH_LEN)   # 7856
SLH_SEED_BYTES = 3 * SLH_N       # SK.seed || SK.prf || PK.seed

# ADRS types
_WOTS_HASH, _WOTS_PK, _TREE, _FORS_TREE, _FORS_ROOTS, _WOTS_PRF, _FORS_PRF = range(7)

_U32 = [i.to_bytes(4, 'big') for i in range(1 << SLH_A)]       # every word value a hot loop needs
_Z4 = bytes(4)


def _u32(i):
    return _U32[i] if i < len(_U32) else i.to_bytes(4, 'big')


def _base_2b(x, b, out_len):
    """FIPS 205 Algorithm 4."""
    i = bits = total = 0
    out = []
    mask = (1 << b) - 1
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) | x[i]
            i += 1
            bits += 8
        bits -= b
        out.append((total >> bits) & mask)
    return out


class _Ctx:
    """The SHA2 tweakable hashes for one key (FIPS 205 §11.2.1, n = 16), with SHA-256's state after
    the 64-byte ``PK.seed || toByte(0, 48)`` block precomputed and copied per call.  ADRS values
    are passed already compressed (ADRSc, 22 bytes): ``layer(1) || tree(8) || type(1) || w1 w2 w3``."""

    def __init__(self, pk_seed, sk_seed=None):
        self.pk_seed = bytes(pk_seed)
        self.sk_seed = None if sk_seed is None else bytes(sk_seed)
        self.seeded = hashlib.sha256(self.pk_seed + bytes(64 - SLH_N))

    def h(self, adrsc, m):       # F, H and T_l are the same function for n = 16
        c = self.seeded.copy()
        c.update(adrsc + m)
        return c.digest()[:SLH_N]

    def prf(self, adrsc):
        c = self.seeded.copy()
        c.update(adrsc + self.sk_seed)
        return c.digest()[:SLH_N]

    # -- WOTS+ (Algorithms 5-8) --

    def _wots_msg(self, m):
        msg = _base_2b(m, SLH_LGW, SLH_LEN1)
        csum = sum(SLH_W - 1 - v for v in msg) << 4        # (8 - (len2 * lg_w) % 8) % 8 = 4
        return msg + _base_2b(csum.to_bytes(2, 'big'), SLH_LGW, SLH_LEN2)

    def _chain(self, x, start, steps, pre):
        """``chain``; ``pre`` = ADRSc up to and including the chain address (18 bytes)."""
        seeded, n = self.seeded, SLH_N
        for j in range(start, start + steps):
            c = seeded.copy()
            c.update(pre + _U32[j] + x)
            x = c.digest()[:n]
        return x

    def wots_pk(self, lt, kp):
        """wots_pkGen for keypair ``kp`` of the XMSS tree ``lt`` (= layer(1) || tree(8))."""
        seeded, sk_seed, n = self.seeded, self.sk_seed, SLH_N
        kp4 = _u32(kp)
        prf_pre = lt + bytes([_WOTS_PRF]) + kp4
        hash_pre = lt + bytes([_WOTS_HASH]) + kp4
        out = []
        for i in range(SLH_LEN):
            i4 = _U32[i]
            c = seeded.copy()
            c.update(prf_pre + i4 + _Z4 + sk_seed)
            x = c.digest()[:n]
            pre = hash_pre + i4
            for j in range(SLH_W - 1):
                c = seeded.copy()
                c.update(pre + _U32[j] + x)
                x = c.digest()[:n]
            out.append(x)
        return self.h(lt + bytes([_WOTS_PK]) + kp4 + bytes(8), b''.join(out))

    def wots_sign(self, m, lt, kp):
        kp4 = _u32(kp)
        prf_pre = lt + bytes([_WOTS_PRF]) + kp4
        hash_pre = lt + bytes([_WOTS_HASH]) + kp4
        sig = []
        for i, v in enumerate(self._wots_msg(m)):
            sk = self.prf(prf_pre + _U32[i] + _Z4)
            sig.append(self._chain(sk, 0, v, hash_pre + _U32[i]))
        return b''.join(sig)

    def wots_pk_from_sig(self, sig, m, lt, kp):
        kp4 = _u32(kp)
        hash_pre = lt + bytes([_WOTS_HASH]) + kp4
        tmp = []
        for i, v in enumerate(self._wots_msg(m)):
            tmp.append(self._chain(sig[i * SLH_N:(i + 1) * SLH_N], v, SLH_W - 1 - v, hash_pre + _U32[i]))
        return self.h(lt + bytes([_WOTS_PK]) + kp4 + bytes(8), b''.join(tmp))

    # -- XMSS (Algorithms 9-11), whole tree at once --

    def xmss_tree(self, lt):
        """All levels of the XMSS tree ``lt``: ``levels[z][i]`` is xmss_node(i, z)."""
        level = [self.wots_pk(lt, i) for i in range(1 << SLH_HP)]
        levels = [level]
        tree_pre = lt + bytes([_TREE]) + _Z4
        for z in range(1, SLH_HP + 1):
            z4 = _U32[z]
            level = [self.h(tree_pre + z4 + _U32[i], level[2 * i] + level[2 * i + 1])
                     for i in range(len(level) // 2)]
            levels.append(level)
        return levels

    def xmss_sign(self, m, lt, idx):
        levels = self.xmss_tree(lt)
        auth = b''.join(levels[j][(idx >> j) ^ 1] for j in range(SLH_HP))
        return self.wots_sign(m, lt, idx) + auth, levels[SLH_HP][0]

    def xmss_pk_from_sig(self, idx, sig, m, lt):
        node = self.wots_pk_from_sig(sig[:SLH_LEN * SLH_N], m, lt, idx)
        auth = sig[SLH_LEN * SLH_N:]
        tree_pre = lt + bytes([_TREE]) + _Z4
        for k in range(SLH_HP):
            a = auth[k * SLH_N:(k + 1) * SLH_N]
            idx_k = idx >> k
            adrs = tree_pre + _u32(k + 1) + _u32(idx_k >> 1)
            node = self.h(adrs, node + a) if idx_k % 2 == 0 else self.h(adrs, a + node)
        return node

    # -- FORS (Algorithms 14-17) --

    def _fors_pre(self, idx_tree, idx_leaf):
        return bytes([0]) + idx_tree.to_bytes(8, 'big'), _u32(idx_leaf)

    def fors_sign(self, md, idx_tree, idx_leaf):
        lt, kp4 = self._fors_pre(idx_tree, idx_leaf)
        prf_pre = lt + bytes([_FORS_PRF]) + kp4 + _Z4
        node_pre = lt + bytes([_FORS_TREE]) + kp4
        seeded, sk_seed, n = self.seeded, self.sk_seed, SLH_N
        out = []
        for i, ix in enumerate(_base_2b(md, SLH_A, SLH_K)):
            base = i << SLH_A
            # leaves of tree i (height 0, index base + j)
            level = []
            h0 = node_pre + _Z4
            for j in range(1 << SLH_A):
                t4 = _u32(base + j)
                c = seeded.copy()
                c.update(prf_pre + t4 + sk_seed)
                sk = c.digest()[:n]
                if j == ix:
                    out.append(sk)
                c = seeded.copy()
                c.update(h0 + t4 + sk)
                level.append(c.digest()[:n])
            for z in range(SLH_A):
                out.append(level[(ix >> z) ^ 1])
                if z == SLH_A - 1:
                    break
                zb = node_pre + _u32(z + 1)
                off = base >> (z + 1)
                level = [self.h(zb + _u32(off + q), level[2 * q] + level[2 * q + 1]) for q in range(len(level) // 2)]
        return b''.join(out)

    def fors_pk_from_sig(self, sig, md, idx_tree, idx_leaf):
        lt, kp4 = self._fors_pre(idx_tree, idx_leaf)
        node_pre = lt + bytes([_FORS_TREE]) + kp4
        roots = []
        step = (1 + SLH_A) * SLH_N
        for i, ix in enumerate(_base_2b(md, SLH_A, SLH_K)):
            part = sig[i * step:(i + 1) * step]
            ti = (i << SLH_A) + ix
            node = self.h(node_pre + _Z4 + _u32(ti), part[:SLH_N])
            for j in range(SLH_A):
                a = part[(1 + j) * SLH_N:(2 + j) * SLH_N]
                if (ix >> j) % 2 == 0:
                    ti >>= 1
                    node = self.h(node_pre + _u32(j + 1) + _u32(ti), node + a)
                else:
                    ti = (ti - 1) >> 1
                    node = self.h(node_pre + _u32(j + 1) + _u32(ti), a + node)
            roots.append(node)
        return self.h(lt + bytes([_FORS_ROOTS]) + kp4 + bytes(8), b''.join(roots))


def _lt(layer, tree):
    return bytes([layer]) + tree.to_bytes(8, 'big')


def _ht_layer_job(args):
    """One hypertree layer's XMSS tree root and auth path (for the process pool)."""
    pk_seed, sk_seed, layer, tree = args
    levels = _Ctx(pk_seed, sk_seed).xmss_tree(_lt(layer, tree))
    return levels


def _ht_indices(idx_tree, idx_leaf):
    """[(layer, tree, leaf)] for d layers (Algorithm 12's walk)."""
    out = [(0, idx_tree, idx_leaf)]
    for j in range(1, SLH_D):
        idx_leaf = idx_tree & ((1 << SLH_HP) - 1)
        idx_tree >>= SLH_HP
        out.append((j, idx_tree, idx_leaf))
    return out


def _h_msg(r, pk_seed, pk_root, m):
    seed = r + pk_seed + hashlib.sha256(r + pk_seed + pk_root + m).digest()
    out = b''
    c = 0
    while len(out) < SLH_M:
        out += hashlib.sha256(seed + c.to_bytes(4, 'big')).digest()
        c += 1
    return out[:SLH_M]


def _split_digest(digest):
    md = digest[:21]                                        # ceil(k * a / 8)
    idx_tree = int.from_bytes(digest[21:28], 'big') & ((1 << (SLH_H - SLH_HP)) - 1)
    idx_leaf = int.from_bytes(digest[28:30], 'big') & ((1 << SLH_HP) - 1)
    return md, idx_tree, idx_leaf


def slh_keygen_internal(sk_seed, sk_prf, pk_seed):
    """FIPS 205 Algorithm 18: returns ``(sk 64, pk 32)``."""
    ctx = _Ctx(pk_seed, sk_seed)
    root = ctx.xmss_tree(_lt(SLH_D - 1, 0))[SLH_HP][0]
    pk = bytes(pk_seed) + root
    return bytes(sk_seed) + bytes(sk_prf) + pk, pk


def slh_keygen(seed48):
    """KeyGen from the 48-byte seed ``SK.seed || SK.prf || PK.seed`` (the wallet's derivation, plan
    §4.6, and ``pq::KeyGen``). Returns ``(pk 32, sk 64)`` in the C API's order."""
    seed48 = bytes(seed48)
    assert len(seed48) == SLH_SEED_BYTES
    sk, pk = slh_keygen_internal(seed48[:16], seed48[16:32], seed48[32:48])
    return pk, sk


def slh_sign_internal(m, sk, addrnd=None, processes=1):
    """FIPS 205 Algorithm 19; ``addrnd`` None = deterministic (``opt_rand = PK.seed``)."""
    sk = bytes(sk)
    assert len(sk) == SLH_SK_BYTES
    sk_seed, sk_prf, pk_seed, pk_root = sk[:16], sk[16:32], sk[32:48], sk[48:64]
    opt_rand = pk_seed if addrnd is None else bytes(addrnd)
    m = bytes(m)
    r = hmac.new(sk_prf, opt_rand + m, hashlib.sha256).digest()[:SLH_N]
    md, idx_tree, idx_leaf = _split_digest(_h_msg(r, pk_seed, pk_root, m))
    ctx = _Ctx(pk_seed, sk_seed)
    sig_fors = ctx.fors_sign(md, idx_tree, idx_leaf)
    node = ctx.fors_pk_from_sig(sig_fors, md, idx_tree, idx_leaf)
    walk = _ht_indices(idx_tree, idx_leaf)
    if processes and processes > 1:
        import multiprocessing
        method = 'fork' if 'fork' in multiprocessing.get_all_start_methods() else 'spawn'
        with multiprocessing.get_context(method).Pool(min(processes, SLH_D)) as pool:
            trees = pool.map(_ht_layer_job, [(pk_seed, sk_seed, layer, tree) for layer, tree, _ in walk])
    else:
        trees = None
    parts = [r, sig_fors]
    for j, (layer, tree, leaf) in enumerate(walk):
        lt = _lt(layer, tree)
        levels = trees[j] if trees else ctx.xmss_tree(lt)
        auth = b''.join(levels[z][(leaf >> z) ^ 1] for z in range(SLH_HP))
        parts.append(ctx.wots_sign(node, lt, leaf) + auth)
        node = levels[SLH_HP][0]          # == xmss_pkFromSig of what was just signed
    sig = b''.join(parts)
    assert len(sig) == SLH_SIG_BYTES
    return sig


def slh_verify_internal(m, sig, pk):
    """FIPS 205 Algorithm 20."""
    sig, pk, m = bytes(sig), bytes(pk), bytes(m)
    if len(sig) != SLH_SIG_BYTES or len(pk) != SLH_PK_BYTES:
        return False
    pk_seed, pk_root = pk[:16], pk[16:]
    r = sig[:SLH_N]
    fors_len = SLH_K * (1 + SLH_A) * SLH_N
    sig_fors = sig[SLH_N:SLH_N + fors_len]
    sig_ht = sig[SLH_N + fors_len:]
    md, idx_tree, idx_leaf = _split_digest(_h_msg(r, pk_seed, pk_root, m))
    ctx = _Ctx(pk_seed)
    node = ctx.fors_pk_from_sig(sig_fors, md, idx_tree, idx_leaf)
    xl = (SLH_HP + SLH_LEN) * SLH_N
    for j, (layer, tree, leaf) in enumerate(_ht_indices(idx_tree, idx_leaf)):
        node = ctx.xmss_pk_from_sig(leaf, sig_ht[j * xl:(j + 1) * xl], node, _lt(layer, tree))
    return node == pk_root


def _pure_msg(m, ctx):
    ctx = bytes(ctx)
    if len(ctx) > 255:
        raise ValueError('context longer than 255 bytes')
    return bytes([0, len(ctx)]) + ctx + bytes(m)


def slh_sign(sk, m, ctx=b'', addrnd=None, processes=1):
    """FIPS 205 Algorithm 22 (pure SLH-DSA), deterministic unless ``addrnd`` is given. The node's
    scheme ``0x01`` is this with ``ctx`` empty."""
    return slh_sign_internal(_pure_msg(m, ctx), sk, addrnd, processes)


def slh_verify(pk, m, sig, ctx=b''):
    """FIPS 205 Algorithm 24 (pure SLH-DSA)."""
    if len(bytes(ctx)) > 255:
        return False
    return slh_verify_internal(_pure_msg(m, ctx), sig, pk)


# ---------------------------------------------------------------------------
# FN-DSA-512 verification, PQClean falcon-padded-512 encodings

FALCON_Q = 12289
FALCON_LOGN = 9
FALCON_N = 512
FALCON_NONCE = 40
FALCON_PK_BYTES = 897
FALCON_SIG_BYTES = 666
FALCON_L2BOUND = 34034726


def _falcon_decode_pk(pk):
    """``modq_decode``: header 0x09, then 512 14-bit big-endian-packed coefficients, each < q."""
    if len(pk) != FALCON_PK_BYTES or pk[0] != 0x00 + FALCON_LOGN:
        return None
    v = int.from_bytes(pk[1:], 'big')            # 896 bytes = 512 * 14 bits exactly
    h = []
    for i in range(FALCON_N):
        c = (v >> (14 * (FALCON_N - 1 - i))) & 0x3FFF
        if c >= FALCON_Q:
            return None
        h.append(c)
    return h


def _falcon_comp_decode(buf):
    """``comp_decode``: returns ``(coefficients, bytes consumed)`` or None."""
    n_in = len(buf)
    x = []
    acc = acc_len = v = 0
    for _ in range(FALCON_N):
        if v >= n_in:
            return None
        acc = ((acc << 8) | buf[v]) & 0xFFFFFFFF
        v += 1
        b = acc >> acc_len
        s = b & 128
        m = b & 127
        while True:
            if acc_len == 0:
                if v >= n_in:
                    return None
                acc = ((acc << 8) | buf[v]) & 0xFFFFFFFF
                v += 1
                acc_len = 8
            acc_len -= 1
            if (acc >> acc_len) & 1:
                break
            m += 128
            if m > 2047:
                return None
        if s and m == 0:
            return None
        x.append(-m if s else m)
    if acc & ((1 << acc_len) - 1):
        return None
    return x, v


def _falcon_hash_to_point(nonce, m):
    """SHAKE256(nonce || m), 16-bit big-endian samples, reject >= 61445 (5q), reduce mod q."""
    out = []
    want = 2 * FALCON_N * 2
    while True:
        stream = hashlib.shake_256(nonce + m).digest(want)
        out = []
        for i in range(0, want, 2):
            w = (stream[i] << 8) | stream[i + 1]
            if w < 61445:
                out.append(w % FALCON_Q)
                if len(out) == FALCON_N:
                    return out
        want *= 2


def _negacyclic_mul_modq(a, b):
    """a * b in Z_q[x] / (x^512 + 1), Kronecker substitution on Python integers (exact)."""
    sh = 64
    ia = sum(c << (sh * i) for i, c in enumerate(a))
    ib = sum(c << (sh * i) for i, c in enumerate(b))
    p = ia * ib
    mask = (1 << sh) - 1
    coef = [(p >> (sh * i)) & mask for i in range(2 * FALCON_N - 1)]
    return [(coef[i] - (coef[i + FALCON_N] if i + FALCON_N < len(coef) else 0)) % FALCON_Q
            for i in range(FALCON_N)]


def falcon_verify(pk, m, sig):
    """PQClean ``falcon-padded-512`` ``crypto_sign_verify(sig, 666, m, pk)`` == 0."""
    pk, sig, m = bytes(pk), bytes(sig), bytes(m)
    if len(sig) != FALCON_SIG_BYTES or sig[0] != 0x30 + FALCON_LOGN:
        return False
    h = _falcon_decode_pk(pk)
    if h is None:
        return False
    nonce = sig[1:1 + FALCON_NONCE]
    body = sig[1 + FALCON_NONCE:]
    dec = _falcon_comp_decode(body)
    if dec is None:
        return False
    s2, used = dec
    if any(body[used:]):                         # the padding must be zero
        return False
    c0 = _falcon_hash_to_point(nonce, m)
    s2h = _negacyclic_mul_modq([c % FALCON_Q for c in s2], h)
    norm = 0
    for i in range(FALCON_N):
        w = (c0[i] - s2h[i]) % FALCON_Q
        if w > FALCON_Q // 2:
            w -= FALCON_Q
        norm += w * w
    norm += sum(c * c for c in s2)
    return norm <= FALCON_L2BOUND


# ---------------------------------------------------------------------------
# FN-DSA-512 signing (optional): the tree's own vendored PQClean code, compiled with $CC
#
# Falcon signing needs a floating-point Gaussian sampler, which this module does not re-implement
# in Python; the signer is the wallet's own C (``src/crypto/pq/falcon``, ``ycash_falcon.h``),
# compiled once into a shared library and called through ctypes. It is optional: the verify path
# above stays pure Python (stdlib only), and a caller without a C compiler checks
# ``falcon_signer_available()`` (or catches ``FalconSignerUnavailable``, a ``NotImplementedError``)
# and skips. The library is cached by a hash of its sources and the compiler command line, in
# ``falcon_set_build_dir(dir)`` (a test's tmpdir) or else ``$TMPDIR/ycash-pq-falcon``.

FALCON_SK_BYTES = 1281
FALCON_SEED_BYTES = 48             # pq::KeyGen's Falcon seed: SHAKE256 keygen RNG seed
FALCON_SIGN_ENTROPY_BYTES = 88     # pq::SignWithEntropy: nonce(40) || sampler seed(48)
FALCON_SOURCES = ('codec.c', 'common.c', 'fft.c', 'fips202.c', 'fpr.c', 'keygen.c', 'rng.c',
                  'sign.c', 'vrfy.c', 'ycash_falcon_sign.c', 'ycash_falcon_verify.c')
FALCON_HEADERS = ('fips202.h', 'fpr.h', 'inner.h', 'ycash_falcon.h')
FALCON_SRC_DIR = None              # default: <tree>/src/crypto/pq/falcon, beside qa/rpc-tests

_falcon = {'dir': None, 'lib': None, 'error': None}


class FalconSignerUnavailable(NotImplementedError):
    """No C compiler (or the vendored sources are missing): Falcon signing is skipped."""


def _falcon_src_dir():
    import os
    if FALCON_SRC_DIR:
        return FALCON_SRC_DIR
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         '..', '..', '..', 'src', 'crypto', 'pq', 'falcon'))


def falcon_set_build_dir(path):
    """Build (or reuse) the signer library in ``path``, e.g. the test's ``--tmpdir``. Call before the
    first ``falcon_keygen`` / ``falcon_sign``; a library already loaded stays loaded."""
    _falcon['dir'] = path


def _falcon_load():
    import ctypes
    import os
    import shlex
    import subprocess
    import sys
    import tempfile
    if _falcon['lib'] is not None:
        return _falcon['lib']
    if _falcon['error'] is not None:
        raise FalconSignerUnavailable(_falcon['error'])
    try:
        src = _falcon_src_dir()
        cc = shlex.split(os.environ.get('CC', 'cc')) or ['cc']
        flags = ['-O2', '-shared', '-fPIC']
        h = hashlib.sha256(' '.join(cc + flags).encode() + b'\0')
        for name in FALCON_SOURCES + FALCON_HEADERS:
            with open(os.path.join(src, name), 'rb') as f:
                h.update(name.encode() + b'\0' + hashlib.sha256(f.read()).digest())
        build = _falcon['dir'] or os.path.join(tempfile.gettempdir(), 'ycash-pq-falcon')
        os.makedirs(build, exist_ok=True)
        out = os.path.join(build, 'libycashfalcon-%s%s' % (h.hexdigest()[:16], '.dylib' if sys.platform == 'darwin' else '.so'))
        if not os.path.exists(out):
            tmp = '%s.%d.tmp' % (out, os.getpid())
            subprocess.run(cc + flags + ['-o', tmp] + [os.path.join(src, n) for n in FALCON_SOURCES],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            os.replace(tmp, out)
        lib = ctypes.CDLL(out)
        u8p, size = ctypes.c_char_p, ctypes.c_size_t
        lib.ycash_falcon512_keygen_from_seed.argtypes = [ctypes.c_void_p, ctypes.c_void_p, u8p, size]
        lib.ycash_falcon512_keygen_from_seed.restype = ctypes.c_int
        lib.ycash_falcon512_sign.argtypes = [ctypes.c_void_p, u8p, size, u8p, u8p, u8p]
        lib.ycash_falcon512_sign.restype = ctypes.c_int
    except (OSError, subprocess.CalledProcessError) as e:
        detail = getattr(e, 'stdout', None)
        _falcon['error'] = 'the Falcon signer could not be built with $CC: %s%s' % (
            e, (' -- ' + detail.decode(errors='replace')[-500:]) if detail else '')
        raise FalconSignerUnavailable(_falcon['error'])
    _falcon['lib'] = lib
    return lib


def falcon_signer_available():
    """True when the Falcon signer builds (or is already built); never raises."""
    try:
        _falcon_load()
        return True
    except FalconSignerUnavailable:
        return False


def falcon_keygen(seed48):
    """``pq::KeyGen`` for FN-DSA-512: SHAKE256(seed48) drives PQClean's keygen. Returns ``(pk, sk)``
    (897 and 1281 bytes), byte for byte the node wallet's key for that seed."""
    import ctypes
    seed48 = bytes(seed48)
    if len(seed48) != FALCON_SEED_BYTES:
        raise ValueError('a Falcon keygen seed is %d bytes' % FALCON_SEED_BYTES)
    lib = _falcon_load()
    pk = ctypes.create_string_buffer(FALCON_PK_BYTES)
    sk = ctypes.create_string_buffer(FALCON_SK_BYTES)
    if lib.ycash_falcon512_keygen_from_seed(pk, sk, seed48, len(seed48)) != 0:
        raise ValueError('Falcon keygen failed')
    return pk.raw, sk.raw


def falcon_sign(sk, msg, entropy=None):
    """``pq::SignWithEntropy`` for FN-DSA-512: a 666-byte padded signature over ``msg`` (the 32
    sighash bytes on the chain). ``entropy`` is nonce(40) || sampler seed(48); None draws it from
    ``os.urandom`` (``pq::Sign``). ``pq_sign_input`` checks the result with the pure-Python
    verifier."""
    import ctypes
    import os
    sk, msg = bytes(sk), bytes(msg)
    if len(sk) != FALCON_SK_BYTES:
        raise ValueError('a Falcon secret key is %d bytes' % FALCON_SK_BYTES)
    entropy = os.urandom(FALCON_SIGN_ENTROPY_BYTES) if entropy is None else bytes(entropy)
    if len(entropy) != FALCON_SIGN_ENTROPY_BYTES:
        raise ValueError('Falcon signing entropy is %d bytes (nonce || seed)' % FALCON_SIGN_ENTROPY_BYTES)
    lib = _falcon_load()
    sig = ctypes.create_string_buffer(FALCON_SIG_BYTES)
    if lib.ycash_falcon512_sign(sig, msg, len(msg), sk, entropy[:FALCON_NONCE], entropy[FALCON_NONCE:]) != 0:
        raise ValueError('Falcon signing failed')
    return sig.raw


# ---------------------------------------------------------------------------
# Scheme dispatch (the pq::Verify / pq::KeyGen / pq::Sign contract)

def verify(scheme, pk, sig, msg32):
    """``pq::Verify``: ``sig`` without the hashtype byte, ``msg32`` the sighash bytes."""
    pk, sig = bytes(pk), bytes(sig)
    if not is_known_scheme(scheme) or len(pk) != PUBKEY_SIZE[scheme] or len(sig) != SIG_SIZE[scheme]:
        return False
    if scheme == SCHEME_SLH_DSA_SHA2_128S:
        return slh_verify(pk, msg32, sig)
    return falcon_verify(pk, msg32, sig)


def keygen(scheme, seed):
    """``pq::KeyGen``: SLH-DSA in Python; FN-DSA-512 through the optional C signer
    (``FalconSignerUnavailable`` without a C compiler). Returns ``(pk, sk)``."""
    if scheme == SCHEME_SLH_DSA_SHA2_128S:
        return slh_keygen(seed)
    if scheme == SCHEME_FN_DSA_512:
        return falcon_keygen(seed)
    raise ValueError('unknown scheme %r' % scheme)


def sign(scheme, sk, msg32, processes=1, entropy=None):
    """``pq::SignWithEntropy``: SLH-DSA deterministic (``entropy`` must be None; the node's ``pq::Sign``
    hedges with 16 random bytes of ``opt_rand``, which the R-agnostic verifier accepts alike, so this
    signer never predicts the node's bytes);
    FN-DSA-512 through the optional C signer (``entropy`` = nonce || seed, None for os.urandom)."""
    if scheme == SCHEME_SLH_DSA_SHA2_128S:
        if entropy is not None:
            raise ValueError('SLH-DSA signs deterministically here (opt_rand = PK.seed)')
        return slh_sign(sk, msg32, processes=processes)
    if scheme == SCHEME_FN_DSA_512:
        return falcon_sign(sk, msg32, entropy)
    raise ValueError('unknown scheme %r' % scheme)


# ---------------------------------------------------------------------------
# Script helpers (plan §4.2, §4.3)

def key_hash(scheme, pk):
    """``pq::KeyHash``: SHA256(scheme || pk), 32 bytes in hash output order (``uint256`` memory)."""
    return hashlib.sha256(bytes([scheme]) + bytes(pk)).digest()


def chunk(data, size=MAX_CHUNK):
    """Canonical chunking: every chunk ``size`` bytes but the last (shorter, never empty)."""
    data = bytes(data)
    assert data
    return [data[i:i + size] for i in range(0, len(data), size)]


def _push(data):
    from .vault import push
    return push(data)


def _push_int(n):
    from .vault import push_int
    return push_int(n)


def pq_scriptsig_pushes(pk, sig_with_hashtype):
    """The stack items in push order: ``<sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>`` (``s``, ``p`` as
    their script-number bytes, OP_1..OP_16 when serialised)."""
    sigs, pks = chunk(sig_with_hashtype), chunk(pk)
    return sigs + [bytes([len(sigs)])] + pks + [bytes([len(pks)])]


def pq_scriptsig(pk, sig_with_hashtype, extra=b''):
    """The serialised push-only scriptSig: canonical pushes, ``s``/``p`` as OP_n; ``extra`` (e.g.
    ``push_int(2)`` = the V template's OWNER selector) is appended after ``<p>``."""
    sigs, pks = chunk(sig_with_hashtype), chunk(pk)
    out = b''.join(_push(c) for c in sigs) + _push_int(len(sigs))
    out += b''.join(_push(c) for c in pks) + _push_int(len(pks))
    return out + bytes(extra)


def pq_owner_slot(scheme, key_hash32):
    """``<keyHash:32> <schemeId> OP_CHECKPQSIG`` (35 bytes): ``20 <hash32> 51|52 c2``. The scheme is
    pushed as ``CScript << (int64_t)scheme``, i.e. ``OP_1`` / ``OP_2`` (spec F-1), never ``01 01``.
    This is both ``TX_PQPKH`` and the V/I owner slot."""
    assert len(key_hash32) == KEYHASH_SIZE
    assert 1 <= scheme <= 16
    return bytes([32]) + bytes(key_hash32) + bytes([0x50 + scheme, 0xc2])


def pqpkh_script(scheme, key_hash32):
    """``TX_PQPKH`` (35 bytes): ``0x20 <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG``."""
    return pq_owner_slot(scheme, key_hash32)


def parse_pqpkh(spk):
    """``(scheme, keyHash)`` for an exact ``TX_PQPKH`` (the Solver match), else None."""
    spk = bytes(spk)
    if len(spk) == 35 and spk[0] == 0x20 and spk[33] in (0x51, 0x52) and spk[34] == 0xc2:
        return spk[33] - 0x50, spk[1:33]
    return None


def pqpkh_script_of(scheme, pk):
    return pqpkh_script(scheme, key_hash(scheme, pk))


def pq_sighash(tx, n_in, script_code, amount, branch_id, hashtype=SIGHASH_ALL):
    """ZIP-243 ``SignatureHash(scriptCode, tx, nIn, hashType, amount, branch)``: the framework's
    implementation, the one ``vault.template_sighash`` signs vault spends with."""
    from .script import CScript, SignatureHash
    sh, err = SignatureHash(CScript(bytes(script_code)), tx, n_in, hashtype, amount, branch_id)
    if err is not None:
        raise ValueError(err)
    return sh


def pq_sign_input(tx, n_in, script_code, amount, branch_id, sk, scheme=SCHEME_SLH_DSA_SHA2_128S,
                  hashtype=SIGHASH_ALL, pk=None, sig=None, processes=1):
    """Sign input ``n_in`` and return the scriptSig push list
    ``[sig_1..sig_s, s, pk_1..pk_p, p]`` with the hashtype byte appended to the signature.

    SLH-DSA: ``sk`` is the 64-byte secret key (``pk`` is read from it). Falcon: ``pk`` must be given,
    and either ``sk`` (the 1281-byte key of ``falcon_keygen``; the optional C signer signs) or ``sig``
    (a 666-byte vector signature over this very sighash). A Falcon signature is checked by the
    pure-Python verifier either way.
    Serialise with ``pq_scriptsig_from_pushes`` (or ``pq_scriptsig(pk, sig)``)."""
    msg = pq_sighash(tx, n_in, script_code, amount, branch_id, hashtype)
    if scheme == SCHEME_SLH_DSA_SHA2_128S:
        sk = bytes(sk)
        pk = sk[32:64]
        sig = slh_sign(sk, msg, processes=processes)
    else:
        if pk is None or (sig is None and sk is None):
            raise ValueError('a Falcon input needs pk= and either sk= (the C signer) or sig= (a vector)')
        if sig is None:
            sig = falcon_sign(sk, msg)
        if not falcon_verify(pk, msg, sig):
            raise ValueError('the Falcon signature does not verify over this sighash')
    return pq_scriptsig_pushes(pk, bytes(sig) + bytes([hashtype]))


def pq_scriptsig_from_pushes(pushes, extra=b''):
    """Serialise ``pq_scriptsig_pushes`` output (the 1-byte counts as OP_n)."""
    out = b''
    for item in pushes:
        if len(item) == 1 and 1 <= item[0] <= 16:
            out += _push_int(item[0])
        else:
            out += _push(item)
    return out + bytes(extra)


