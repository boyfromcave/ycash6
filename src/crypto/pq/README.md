# src/crypto/pq: post-quantum signatures

The signature schemes behind `OP_CHECKPQSIG` (docs/plans/yellowback-quantum-plan.md §4.1, §4.2, §4.7).

| id | scheme | pk | sig (without hashtype) | sk | KeyGen seed |
|---|---|---|---|---|---|
| `0x01` | SLH-DSA-SHA2-128s (FIPS 205, pure mode, empty context) | 32 | 7,856 | 64 | 48 = `SK.seed ‖ SK.prf ‖ PK.seed` |
| `0x02` | FN-DSA-512 / Falcon-512, PQClean **padded** format | 897 | 666 | 1,281 | 48 = the bytes PQClean's keygen reads from `randombytes(48)` |

* `scheme.{h,cpp}`: **consensus**. Sizes, `KeyHash = SHA256(scheme ‖ pk)`, `Verify`. Built into
  `libbitcoin_common` (beside the interpreter) and `libzcash_script`.
* `sign.{h,cpp}`: **wallet**. `KeyGen` from a seed, `Sign` (SLH-DSA **hedged**, FIPS 205 §9.2: 16 bytes of
  `opt_rand` from `GetRandBytes`, cleansed after use, so a repeated signature over one message takes a fresh
  FORS/hypertree path; Falcon randomized from `GetRandBytes`), `SignWithEntropy` (explicit randomness, for tests
  and vectors; empty entropy is the deterministic SLH-DSA variant, `opt_rand = PK.seed`). The golden vectors and
  the ACVP cases are produced through `SignWithEntropy` with their recorded entropy and are unaffected by
  hedging; the verifier is `R`-agnostic, so deterministic and hedged signatures verify alike.
  Built into `libbitcoin_common`; never called from a consensus path.
* The vendored C is built into `libbitcoin_crypto` (`PQ_VERIFY_SOURCES`, `PQ_SIGN_SOURCES` in `src/Makefile.am`);
  `libzcash_script` gets only the verify set.

## Golden vectors: `src/test/data/pq_vectors.json`

Consumed by the 6.20.0 node line, YEW's Rust core and the Python test framework, which must match it **byte for byte**.
`src/test/pq_crypto_tests.cpp` (`pq_golden_vectors`) recomputes every field and checks that the file is
exactly the regenerated text; `PQ_VECTORS_WRITE=<path>` rewrites it.

```
{
  "format": "ycash-pq-vectors-1",
  "comment": "...",
  "keys": [                      // 2 SLH-DSA entries, then 3 Falcon entries
    { "scheme":  1 | 2,
      "name":    "...",
      "label":   "...",          // provenance only: seed/msg/entropy = Expand(label + " seed"|" msg"|" entropy")
      "seed":    hex(48),        // KeyGen input
      "pk":      hex(32 | 897),
      "keyhash": hex(32),        // SHA256(scheme || pk), bytes in hash output order
      "msg":     hex(32),        // the sighash bytes in memory order (uint256 begin..end)
      "entropy": hex(0 | 88),    // "" for SLH-DSA (deterministic); Falcon: nonce(40) || sampler seed(48)
      "sig":     hex(7856 | 666) // WITHOUT the hashtype byte
    }, ...
  ],
  "spends": [                    // one per scheme, the first key of each
    { "scheme": 1 | 2,
      "key": <index into keys>,
      "scriptPubKey": hex(35),   // TX_PQPKH: 0x20 <keyhash:32> OP_1|OP_2 0xc2 (OP_CHECKPQSIG)
      "hashtype": 1,             // SIGHASH_ALL, appended to sig
      "sigChunks": s, "pkChunks": p,
      "scriptSigSize": n,
      "scriptSig": hex           // <sig_1>..<sig_s> <s> <pk_1>..<pk_p> <p>
    }
  ]
}
```

Chunking (plan §4.2): `sig ‖ hashtype` and `pk` are cut into 520-byte chunks, every chunk but the last exactly
520 bytes, each pushed minimally (`OP_PUSHDATA2` for 520, `OP_PUSHDATA2`/`OP_PUSHDATA1`/direct for the tail);
`s` and `p` are `OP_1`..`OP_16`. SLH-DSA: s = 16 (15 × 520 + 57), p = 1 → 7,938-byte scriptSig. Falcon:
s = 2 (520 + 147), p = 2 (520 + 377) → 1,577 bytes. `Expand(label, n)` = the first n bytes of
`SHA512(label ‖ 0x00) ‖ SHA512(label ‖ 0x01) ‖ …`; consumers do not need it, they take the hex.

Falcon signatures depend on `entropy`; a consumer that cannot replay PQClean's sampler (Python, `fn-dsa`)
checks them with **verify** only. Falcon keygen from a seed is reproducible only with this implementation
(plan §4.6): other implementations store the public key rather than re-deriving it.

## Vendored sources

### `slhdsa/`: SLH-DSA, PQ Code Package `slhdsa-c`

* Source: https://github.com/pq-code-package/slhdsa-c, commit `174c02e42257f95c210963272877c49dbb50070f`
  (2026-08-06).
* Licence: `Apache-2.0 OR ISC OR MIT` (SPDX header in every file; `slhdsa/LICENSE` unchanged). Ycash uses it under MIT.
* Files, **unmodified**: `slh_dsa.h slh_sha2.c sha2_256.c sha2_512.c sha2_api.h plat_local.h slh_adrs.h
  slh_param.h slh_var.h slh_sys.h cbmc.h LICENSE`.
  **Patched**: `slh_dsa.c` (local patch P3, zeroization; see "Local patches" below). Not vendored: the SHAKE parameter sets (`slh_shake.c`,
  `sha3_*`), prehash (`slh_prehash.*`), tests, CBMC proofs. `sha2_512.c` is needed only because `slh_sha2.c`
  also defines the 192/256 parameter sets.
* Why this one: FIPS 205 final (pure and internal interfaces, context string, all 12 parameter sets), portable
  C90 without dependencies, passes the full NIST ACVP set upstream, and the implementation PQClean's retirement
  notice names for SLH-DSA. PQClean's `sphincs-sha2-128s-simple` is SPHINCS+ round 3.1, which is not FIPS 205
  (no domain separator/context in `H_msg`/`PRF_msg`) and was rejected. Upstream still marks `slhdsa-c` "work in
  progress, not recommended for production"; the conformance tests below are the gate.

### `falcon/`: Falcon-512 padded, PQClean `falcon-padded-512/clean`

* Source: https://github.com/PQClean/PQClean, commit `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` (2026-08-04),
  `crypto_sign/falcon-padded-512/clean/` and `common/fips202.{c,h}`. PQClean is **archived** (retirement
  notice, 2026); the code is frozen, which suits a pin.
* Licence: MIT (Falcon Project, `falcon/LICENSE` unchanged, with its patent note on US7308097B2);
  `fips202.{c,h}` are public domain (header notice unchanged).
* Files, **unmodified**: `inner.h fpr.h codec.c common.c vrfy.c keygen.c sign.c fft.c fpr.c rng.c LICENSE`.
  **Patched**: `fips202.c fips202.h` (one local patch, see "Local patches" below).
  `fips202.{c,h}` moved from PQClean's `common/` into `falcon/` so `inner.h`'s `#include "fips202.h"` resolves
  without an include path.
* **Not vendored: `pqclean.c` and `api.h`.** `pqclean.c` takes its randomness from a global `randombytes()`.
  It is replaced by Ycash files (MIT, derived from it):
  * `ycash_falcon_verify.c`: `do_verify` + `crypto_sign_verify`, logic unchanged (consensus) but for local patch
    P2 (exact lengths, below).
  * `ycash_falcon_sign.c`: `crypto_sign_keypair` / `do_sign` with the randomness as parameters (keygen seed of
    any length; nonce 40 + sampler seed 48), plus wiping the secret polynomials, the scratch and the SHAKE256 DRBG state (keygen `rng`, sampler `sc`)
    on exit (wallet).
  * `ycash_falcon.h`: their declarations and the sizes.
  No `randombytes` symbol exists in the node.
* PQClean's padded verifier also accepts the unpadded "compact" signature at its own shorter length;
  `ycash_falcon512_verify` (local patch P2) and `pq::Verify` each accept exactly 666 bytes, so the only accepted
  form is `0x39 ‖ nonce ‖ compressed s ‖ zero padding` (tested: every non-zero padding byte, every other header,
  and the compact form are rejected, by the C entry point and by the registry).
* **Malleability** (audit F-2, F-5): a (pk, sig) has exactly one accepted byte encoding, so the signature adds no
  *new* third-party malleability. Push minimality (`MINIMALDATA`) is policy, as for every Ycash input, so a miner
  can still re-encode the chunk pushes of a scriptSig (ECDSA inputs included). Likewise `STRICTENC` is policy:
  an undefined hashtype byte is consensus-valid, as for `OP_CHECKSIG`, but it is committed in the ZIP-243
  preimage, so only the signer chooses it.
* **`hash_to_point_ct`** (audit F-3): the verifier hashes the message to a point with Falcon's constant-time
  sampler (717 SHAKE draws, 205 spares; `common.c`). It equals the specification's variable-time rejection
  sampler (used by the Python model and `fn-dsa`) unless more than 205 of the 717 draws are rejected, probability
  about 2^-256; the audit traced 1,500 inputs coefficient for coefficient. Not a consensus divergence.

### No floating point in verification

`clean` Falcon implements its "floating point" by integer emulation (`fpr.h`: `typedef uint64_t fpr`), and the
verify path never reaches it: `ycash_falcon_verify.c` calls only `modq_decode`, `comp_decode` (codec.c),
`to_ntt_monty`, `verify_raw` (vrfy.c, NTT mod 12289), `hash_to_point_ct` (common.c) and SHAKE256 (fips202.c).
Evidence (2026-10-10, Apple clang, arm64):
* those five files contain no `float`/`double` token and no `fpr` use (grep);
* they compile with `-mgeneral-regs-only` (no FP/SIMD register may be used; any `float`/`double` is a compile
  error), and so do `slh_dsa.c slh_sha2.c sha2_256.c sha2_512.c`; in fact all of the vendored Falcon code
  (keygen, sign, fft, fpr) does too;
* in the `-O3` objects of the build, the only FP-unit instructions are `fmov` between vector lanes and general
  registers (auto-vectorised integer code); there is no FP arithmetic or conversion (`fadd`, `fmul`, `fdiv`,
  `fcvt*`, `scvtf`, `ucvtf`) anywhere in the Falcon objects.

## Local patches

### P1: `falcon/fips202.{c,h}`, SHAKE256 incremental context on the stack (2026-10-10)

PQClean's `fips202.c` allocates each SHAKE context with `malloc` and calls `exit(111)` if that fails. Falcon reaches
SHAKE only through `inner.h`'s `inner_shake256_*` macros, which map onto the **SHAKE256 incremental** API
(`shake256incctx`); a Falcon verify (consensus) made one such allocation per signature, and keygen/sign several.
A consensus path must not heap-allocate and exit, so `shake256incctx` now holds its state inline. Every changed line
is marked `YCASH LOCAL PATCH`. The patch, in full:

* `fips202.h`: `typedef struct { uint64_t *ctx; } shake256incctx;` becomes `typedef struct { uint64_t ctx[26]; }
  shake256incctx;` (25 Keccak lanes + the position word = `PQC_SHAKEINCCTX_BYTES`, 208 bytes), plus a comment.
* `fips202.c`: `shake256_inc_init` drops the `malloc`/`exit(111)` and only calls `keccak_inc_init(state->ctx)`;
  `shake256_inc_ctx_clone` drops the `malloc`/`exit(111)` and keeps the `memcpy`; `shake256_inc_ctx_release` no
  longer calls `free` (it is a no-op, `(void)state;`).

The function names, signatures and the Keccak code are unchanged, so no Falcon file changes (`state->ctx` decays to
the same `uint64_t *` the Keccak helpers take, and no Falcon code copies a context by value). The output is
unchanged: `pq_crypto_tests` (golden vectors, the round-3 and PQClean padded KATs) pass byte-identically. The other
contexts (`shake128*`, `shake256ctx`, `sha3_*`) still `malloc`; nothing in the node calls them (Falcon uses only the
SHAKE256 incremental API, and nothing else includes `fips202.h`). The same patch is carried on the 6.20.0 line.

`slhdsa/` needs no such patch: for SLH-DSA-SHA2-128s it runs only SHA-256/SHA-512 (`slh_sha2.c`, `sha2_256.c`,
`sha2_512.c`; the SHAKE parameter sets and `sha3_*` are not vendored), and no vendored `slhdsa/` file contains
`malloc`, `calloc`, `free`, `exit` or `abort` (grep, 2026-10-10); its state lives on the stack. That stack state
holds secrets in keygen and signing, which P3 below wipes.

Because P1 put the SHAKE256 context inline and made its release a no-op, a Falcon keygen/sign frame keeps the
DRBG state after return unless it is wiped: `ycash_falcon_sign.c` (a Ycash file, not a patch) wipes `rng` in
`ycash_falcon512_keygen_from_seed` (seeded with the keygen seed, which alone determines the key pair) and `sc` in
`ycash_falcon512_sign` (the sampler state) in their `done:` blocks, with the volatile `wipe()` (audit 02/PQ-1,
2026-10-12).

### P2: `falcon/ycash_falcon_verify.c` + `ycash_falcon.h`, exact lengths in the C entry point (2026-10-10)

Falcon consensus audit F-1 (`docs/audits/yellowback-falcon-consensus-audit-20261010.md` in the workspace):
`ycash_falcon512_verify` gains a `pklen` argument and returns -1 unless `siglen == 666` and `pklen == 897`, before
any decoding. PQClean's `do_verify` logic is otherwise unchanged; `pq::Verify` keeps its own size gate, so the
consensus path checks the lengths twice. Changed lines are marked `YCASH LOCAL PATCH`; `pq_crypto_tests`
calls the entry point directly with the compact form, a short and a long key (all rejected). Both node lines.

### P3: `slhdsa/slh_dsa.c`, zeroization of `slh_var_t` (2026-10-12)

Audit 02/PQ-2: `sha2_mk_var` (`slh_sha2.c`) copies `SK.seed` and `SK.prf` (the 32 bytes that fully determine an
SLH-DSA key) into a stack-resident `slh_var_t`, and upstream never zeroizes it, so `slh_keygen_internal` and
`slh_sign` returned with the copy in the dead frame. The patch, in full (every line marked `YCASH LOCAL PATCH P3`):

* a static helper `slh_wipe(void *p, size_t sz)` after the includes (volatile byte stores, C90, the same
  construction as `wipe()` in `ycash_falcon_sign.c`; not `memset`, which the optimiser may elide), and a macro
  `slh_wipe_var(v)` = `slh_wipe((v), sizeof(*(v)))`;
* `slh_wipe_var(&var);` immediately before the `return` of each function that builds `var` from a secret key:
  `slh_keygen_internal`, `slh_keygen`, `slh_sign_internal` and `slh_sign`; the two signing functions also wipe
  `digest` (public, but free).

No function signature, constant or output changes: `pq_crypto_tests` (golden vectors, ACVP, round trip) pass
byte-identically. The consensus path (`slh_verify`, `slh_verify_internal`) builds `var` from the public key only
and is untouched. The provenance check is: every file listed as unmodified `cmp`s equal to upstream at the pinned
commit, and `diff` of `slh_dsa.c` against upstream shows only lines marked `YCASH LOCAL PATCH P3`.
`qa/yellowback-audit.sh` checks that the wipes are present. The same patch is carried on the 6.20.0 line.

## Conformance data (tests)

* `src/test/data/pq_acvp_slhdsa.json`: NIST ACVP-Server `gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/internalProjection.json`
  at commit `975de31eb83d87039ec88934fdc47d8c312b892d`, SLH-DSA-SHA2-128s: keyGen tcId 1–4 (through `pq::KeyGen`), sigGen
  external/pure deterministic 157, 161, 162 and hedged 474, 475 (2 with empty context), sigVer external/pure
  253–259, 262, 266 (every fail reason, 2 passes).
* `src/test/data/pq_falcon_kat.json`: NIST round-3 Falcon-512 KAT (`falcon-round3.zip`, `KAT/falcon512-KAT.rsp`)
  counts 0–4, replayed through the NIST AES-CTR DRBG: keys equal; signatures equal the round-3 compressed
  signatures in padded layout. `r3_all`: all 100 entries of the same file as verify-only rows (pk, msg, the
  compressed signature in the padded layout; all 100 fit 625 bytes), each verified by `ycash_falcon512_verify`
  and rejected with one bit flipped (audit F-6; converted with the audit harness's `kat.py`, the first five
  cross-checked against `r3`). And PQClean's padded KAT (count 0; its `.rsp` hashes to META.yml's
  `nistkat-sha256` 91842d41…0395).
