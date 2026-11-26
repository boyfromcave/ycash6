# Spec proposals for 0.5.4: value balances in a bundle, and a bundle's transaction fields

Provenance: Original (the Ycash developers, 2026), from the third review round of ycash6's Yugen
consensus commit (2026-11-25). **Approved by the lead architect, 2026-11-25, as spec 0.5.4, with
two changes to what is proposed below: value balances in a bundle are implemented, not refused
(§15.1 and §15.5 stand as written; item 1's refusal wording is withdrawn), and a bundle's envelope
is bound as a leaf's (item 2, as proposed).** On this line item 2 is enforced
(`yugen::CheckLeafEnvelope`, `bad-yugen-bundle-locktime`, `bad-yugen-bundle-expiry`); item 1 is
still refused (`bad-yugen-bundle-vb-unsupported`) until the §15.5 work lands (open, see
`doc/yugen-node.md`, third review round). Kept as the record of the options considered.

## 1. Value balances in a bundle

**Gap.** §15.1 allows a transfer record with flag `VB` (its `vout`, and `vin` for a deposit) and
§15.5 gives such a record's rules (deposit signatures under `dep_sighash`, outputs created only for
applied transfers, outpoints indexed over all records). ycash6 refuses every such record
(`DecodeBundleTransfers`, `src/primitives/yugen.h`: `bad-yugen-bundle-vb-unsupported`, DoS 100) and
every bundle transaction with a transparent input or output (`bad-yugen-bundle-transparent`), so on
this line a bundle that the spec accepts is refused: a divergence, and a split against any
implementation that follows §15.5.

**Proposed wording** (a new bullet in §15.1 rule B1, and a note under the §15.5 heading):

> - a transfer record with flag `VB` set. Until a network upgrade removes this bullet, value
>   balances are carried by leaf transactions only (§7.9); §15.5 states the rules that upgrade
>   will enforce, and no node applies them before it.
>
> (§15.5) *Reserved (0.5.4): rule B1 refuses a bundled transfer with a value balance; this section
> takes effect with the network upgrade that lifts that refusal.*

**Smallest node behaviour.** None: ycash6 already refuses (DoS 100, a verdict on the txid-bound
bytes, as for every other B1 refusal) and requires a bundle transaction to have no `vin` and no
`vout`. kogany must refuse the same records for parity. The reference (`yugen-ref`) decoder and the
bundler (`yugen-bundlerd`) must refuse or never build them; the bundle vectors that carry `VB`
records move to the reject set (or to a vector file for the later upgrade).

**Recommendation: refuse in 0.5.4, and implement §15.5 in a later upgrade.** Implementing it now
means a second signature hash (`dep_sighash`) inside the script interpreter (`src/script/`), outputs
created from records instead of `tx.vout` (the coins view, the undo data and every index that reads
outputs), inputs spent only when their transfer is applied (§15.6 S1), and the same on kogany: the
largest consensus surface of the whole upgrade, in the code the prime directive guards most closely.
What is given up: a deposit or withdrawal pays a leaf's weight (`LEAF_RESERVE`, two wallet proofs)
instead of a bundled transfer's share of two bundle proofs, so transparent flows do not get the
bundle's throughput until the later upgrade. Every shielded transfer still bundles. Since relaxing a
refusal is itself a consensus change, "refuse now" keeps the later upgrade possible and costs nothing
to undo except that upgrade.

## 2. The lock time and expiry height of a bundle transaction

**Gap.** §15 does not fix the lock time or the expiry height of the transaction that holds a bundle.
A bundle transaction has no transparent input (§15.1, and this line's `bad-yugen-bundle-transparent`),
so no signature covers either field: a relay can rewrite them, which changes the txid (the bundle and
its proof hashes stay) and lets one bundle travel under many txids, or be delayed by a lock time.
§7.9 rule 1a closed the same gap for leaves.

**Proposed wording** (a new rule in §15.1, after rule B1):

> Rule B1a. The transaction that holds a bundle has no transparent input and no transparent output
> of its own, lock time 0, and expiry height `h_a + ANCHOR_WINDOW`, with `h_a` the anchor height of
> the first anchor table entry (the lowest, rule B1). Every other field of the transaction is fixed by
> §15.1; with these, the bundle bytes fix its txid.

**Why this expiry.** It is rule 1a's value for the bundle's oldest anchor, the last height at which
rule B2 can hold (§8.1: `h − h_a ≤ ANCHOR_WINDOW`), so the stock expiry machinery drops the
transaction when the bundle can no longer be mined, as it does for a leaf; it is also the bundler's
`last_height` (`transfer::expiry_height(min_anchor)`). The context-free alternative, lock time 0 and
expiry 0 (never expires), fixes the txid as well and needs no height, but treats the two kinds
differently; either closes the gap.

**Smallest node behaviour.** `yugen::CheckLeafEnvelope` (`src/yugen/leaf.cpp`) returns early for a
bundle today; it would instead take the first table slot, resolve it at the block height, and refuse
`nLockTime != 0` (`bad-yugen-bundle-locktime`) and `nExpiryHeight != h_a + ANCHOR_WINDOW`
(`bad-yugen-bundle-expiry`), DoS 100 (both fields are in the txid). The `vin`/`vout` part is
enforced already. The functional tests' `bundle_tx` (lock time 0, expiry 0) and `submitbundle`
callers would write the expiry; kogany must apply the same rule.
