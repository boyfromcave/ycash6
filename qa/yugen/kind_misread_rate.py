#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# RECORD ONLY: the structural classifier this script measures was retired by spec 0.5.3 (§15.1,
# bundle_version 0x80 marks the kind; yugen::IsBundleEncoding is now the first-byte test). Kept as
# the computation behind doc/yugen-spec-proposal-0.5.3-envelope-kind.md.
# Probability that the 0.5.2-era yugen::IsBundleEncoding (ycash6 src/primitives/yugen.h) read an honest leaf
# transfer of fee class 0 as a bundle. Model: every byte the wallet derives from a PRF, a key,
# a commitment or ciphertext is uniform and independent; fixed fields are fixed; the anchor slot
# is uniform; value_balance has its top 3 bytes 0x00 (|vb| < 2^40 zat); pkg_bucket's high byte is 0.
# Exact under the model except the record-decode term, bounded (lower/upper). Needs numpy;
# about an hour on one core for the 18 leaf shapes (doc/yugen-spec-proposal-0.5.3-envelope-kind.md).
import numpy as np
from functools import lru_cache
FIXED, SHORT, LONG = 232, 1674, 2186
VB, LEAFFEE = 16, 64

def shape(vb, p1, p2):
    flags = LEAFFEE | (VB if vb else 0)
    size = FIXED + (8 if vb else 0)
    dist = {}           # position -> fixed byte value (absent: uniform)
    dist[0] = 0
    dist[2], dist[3] = flags & 0xff, flags >> 8
    o = FIXED
    if vb:
        for i in range(5, 8): dist[o + i] = 0
        o += 8
    for j, p in enumerate((p1, p2)):
        if p:
            flags |= (1 << j) | ((4 << j) if p == 'long' else 0)
            dist[o + 1] = 0
            o += LONG if p == 'long' else SHORT
    dist[2], dist[3] = flags & 0xff, flags >> 8
    return flags, o, dist

def run(vb, p1, p2):
    flags, size, fixed = shape(vb, p1, p2)
    P = np.full((size + 16, 256), 1 / 256)
    for pos, v in fixed.items():
        P[pos] = 0; P[pos, v] = 1
    pr = lambda pos, pred: sum(P[pos, v] for v in range(256) if pred(v)) if pos < size else 0.0
    total_up, total_lo = 0.0, 0.0
    F = np.arange(65536)
    LN = FIXED + np.where(F & VB, 8, 0)
    for j in range(2):
        LN = LN + np.where(F & (1 << j), np.where(F & (4 << j), LONG, SHORT), 0)
    can = ((F & 0x20) > 0).astype(int) + ((F & 0x80) > 0) + ((F & 0x100) > 0)
    VALID = ((F & 0xfe00) == 0) & ~((F & 4 > 0) & (F & 1 == 0)) & ~((F & 8 > 0) & (F & 2 == 0)) & (can <= 1)
    def record(e):
        q = np.outer(P[e + 3], P[e + 2]).reshape(-1)     # index hi*256+lo = flags value
        fits = (e + LN) <= size
        fit = q[fits].sum()
        ok = q[fits & VALID].sum() * pr(e, lambda v: v <= 3)
        return fit, ok
    for na in range(1, 7):
        w_na = P[1, na]
        o0 = 2 + 129 * na
        if o0 + 2 > size: continue
        # payee table: P uniform (its two bytes are never fixed positions; checked)
        assert o0 not in fixed and o0 + 1 not in fixed
        S = np.zeros(size + 300)
        S[o0 + 2] = 1.0
        for o in range(o0 + 2, size):
            if S[o] == 0: continue
            for v in range(256):
                if P[o, v]: S[o + 1 + v] += S[o] * P[o, v]
        S /= 65536.0
        @lru_cache(None)
        def node(o, depth):
            # distribution {end offset: prob} of a node starting at o
            out = {}
            if depth > 6 or o + 2 > size: return ()
            for tag in (0, 1):
                pt = P[o, tag]
                if not pt: continue
                for k in (1, 2, 3, 4):
                    pk = P[o + 1, k]
                    if not pk: continue
                    w = pt * pk
                    rec = 2 * (3 if k <= 2 else 4)
                    if tag == 0:
                        e = o + 2 + rec
                        if e <= size: out[e] = out.get(e, 0) + w
                        continue
                    cur = {o + 2 + (rec if k >= 2 else 0): w}
                    for _ in range(k):
                        nxt = {}
                        for s, ws in cur.items():
                            if ws < 1e-22: continue
                            for e, we in node(s, depth + 1):
                                nxt[e] = nxt.get(e, 0) + ws * we
                        cur = nxt
                    for e, we in cur.items():
                        if e <= size: out[e] = out.get(e, 0) + we
            return tuple(out.items())
        for o in range(o0 + 2, size):
            if S[o] == 0: continue
            for e, we in node(o, 0):
                if e + FIXED > size: continue
                fit, ok = record(e)
                total_up += w_na * S[o] * we * fit
                total_lo += w_na * S[o] * we * (fit - ok)
    return size, total_lo, total_up

if __name__ == '__main__':
    for vb in (False, True):
        for p1 in (None, 'short', 'long'):
            for p2 in (None, 'short', 'long'):
                size, lo, up = run(vb, p1, p2)
                print(f"vb={int(vb)} pkg1={p1 or '-':5} pkg2={p2 or '-':5} size={size:5d}  misread in [{lo:.4e}, {up:.4e}]  (per fee-class-0 leaf)", flush=True)
