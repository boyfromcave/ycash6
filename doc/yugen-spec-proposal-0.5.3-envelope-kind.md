# Spec proposals for 0.5.3: a leaf's transaction fields, and the kind of a Yugen field

Provenance: Original (the Ycash developers, 2026), from the independent review of ycash6's Yugen
consensus commit (findings M-1 and L-1, 2026-11-25). **Approved by the lead architect, 2026-11-25,
and applied as yugen-spec 0.5.3 (4adaaba): §7.9 rule 1a and §15.1 `bundle_version` = `0x80`; this
line implements both.** Node decisions: `doc/yugen-node.md` N-D8, N-D9.

## 1. The fields of a leaf's transaction (finding M-1)

**Gap.** §7.3 binds `vout` only through `tout_hash`, which is 32 zero bytes when flag `VB` is
clear, and §7.2 takes `vout` from "the enclosing transaction" without saying what else that
transaction may hold. A leaf with no transparent input carries no signature over the transaction,
so its `vin`, `vout`, lock time and expiry height are bound by nothing but the txid: a relay can add
an output paying itself the transfer's fee, or change the lock time, and the result is another valid
transaction spending the same nullifiers.

**Proposed wording** (a new rule 1a in §7.9, after rule 1):

> 1a. The transaction that holds the leaf transfer has no transparent input and no transparent
> output unless flag `VB` is set. If it has no transparent input, its lock time is 0 and its expiry
> height is `h_a + ANCHOR_WINDOW`, with `h_a` the transfer's anchor height (§8.2). (Every other field
> of such a transaction is fixed by §7.1 and by the transfer hash; with a transparent input, the
> inputs' signatures cover the rest.)

**Effect.** None on honest wallets: the reference wallet engine (yew `yewd/yugen/wallet`) writes
lock time 0 and `expiry_height(h_a) = h_a + ANCHOR_WINDOW` always, a deposit has `vin` and no
`vout`, a withdrawal `vout` and no `vin`, a shielded send neither. No vector changes (the transfer
vectors have no enclosing transaction). ycash6 enforces the rule from `UPGRADE_YUGEN`
(`yugen::CheckLeafEnvelope`); kogany must enforce the same rule for parity.

## 2. An explicit kind for the Yugen field (finding L-1)

**Gap.** A leaf transfer of fee class 0 begins with `0x00`, as a bundle does (`bundle_version`), so
nothing in the bytes marks the kind; ycash6 reads it with a structural heuristic
(`yugen::IsBundleEncoding`, N-D8), and kogany would have to copy the heuristic bit for bit, since a
different reading is a different verdict.

**The heuristic's misread rate.** Computed exactly by `qa/yugen/kind_misread_rate.py` (a dynamic
program over the parse of `IsBundleEncoding`, ycash6 `src/primitives/yugen.h`), under this model:
every byte a wallet derives from a key, a PRF, a commitment or a ciphertext is uniform and
independent, the anchor slot is uniform, `value_balance` has its top three bytes zero and each
`pkg_bucket` its high byte zero. For a leaf of fee class 0 (the only class whose first byte is
`0x00`): 0 when it has no package (232 or 240 bytes: the anchor table does not fit); 5.6e-11 with one
short package; 8.6e-11 with one long one; 2.3e-10 to 3.1e-10 with two; at most 3.98e-10 (about
2^-31.2) for the longest leaf, 4,612 bytes (`VB` and two long packages). The record-decode term is
bounded both ways and changes only the fifth digit. So N-D8's "far below 2^-30" is wrong: the rate
is just below 2^-31 for the leaves that carry packages, and an estimate of 3e-8 is about 75 times
too high under this model. A misread honest leaf is refused as a malformed bundle by every node
alike (the rule is deterministic), so it is a lost transaction, not a split, but kogany must
reproduce the heuristic exactly.

**Proposed wording** (§15.1, field 1):

> | 1 | `bundle_version` | 1 | `0x80` |
>
> A Yugen field whose first byte is `0x80` is a bundle; any other is a leaf transfer (§7.1), whose
> first byte is `fee_class`, at most 3. The kind is therefore read from the first byte, which the
> txid commits to, and never from the proof fields or the sidecar.

(and in §15.1's rule B1, "another version" stays as written: a decoder rejects any first byte but
`0x80`.)

**Why `0x80` and this change.** It is the smallest change that makes the kind explicit: one constant
(`yugen-ref` `params::BUNDLE_VERSION`), no new field and no new transaction format (option (c) of
N-D8, a new version group, would change the transaction format and every signature hash). Every
value from 4 to 255 is free because §7.1 refuses `fee_class > 3`; `0x80` leaves 4 to 127 for future
leaf formats. No network has activated Yugen, so no deployed parser reads the field (as for SPEC-207,
which kept `0x00` for that reason).

**Effect on the vectors and on yew.** `vectors/bundle.json`: byte 0 of the 64 encodings that
begin `00` (the 17 accepted bundles and the reject vectors built on them) changes to `80`, and the
version-reject vector `version-1` (byte 0 `01`) keeps refusing; no digest the spec defines covers the
whole encoding (`bstmt` covers the tree and the leaf digests, the proof hashes cover the proofs), so no
statement and no proof changes. Transfer vectors: unchanged. yew: the bundle encoder and decoder
take the constant from `yugen-ref` (the pinned `yugen-spec`), so a re-pin is the change; the bundler
(`yugen-bundlerd`) likewise. ycash6: `IsBundleEncoding` becomes `b[0] == 0x80` and
`DecodeBundleTransfers` checks `0x80`; the node change waits for approval (until then the heuristic
stayed; replaced at 0.5.3).
