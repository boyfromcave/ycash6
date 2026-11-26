# Spec proposal for 0.5.5: VB records and the coins a rule module tracks

Provenance: Original (the Ycash developers, 2026), from the review of ycash6's VB records (2026-11-25,
2026-11-26). **Pending: not yet approved by the lead architect, not in yugen-spec.** ycash6 implements
both rules from `UPGRADE_YUGEN` (node decision `doc/yugen-node.md` N-D12); kogany must implement the
same rules for parity.

## Gap

A bundle's VB records (§15.1, §15.5) spend and create transparent coins outside the transaction's
`vin` and `vout` (B1a). Every rule that reads a transaction's inputs and outputs, among them the vault
primitive and its registered rule modules (the YED module), never sees them. Two consequences:

1. A deposit may spend a coin a module tracks (a YED token sits at an ordinary P2PKH or TX_PQPKH
   output, which §15.5 admits). The coin leaves the UTXO set while the module still counts it.
2. A record output may be any bytes (§15.1), so it may be a vault or intent template or a primitive act,
   created past every rule that judges such outputs.

## Proposed wording

**§15.6, S2** (after "a deposit input that is not an unspent output spendable at h"):

> or that was created in the same block, or that a rule module registered on the vault primitive tracks
> in its state after the block's parent (for YED: a token, a vault, an intent or an attestor bond). The
> transfer is skipped; a skipped deposit is not verified (§15.5).

**§15.1 / §15.6 B6** (a new clause, decided whether the transfer is skipped or not, as the gross cap K):

> A record output whose script is a vault primitive act, or matches the vault (V) or intent (I)
> template skeleton (§15.3; a malformed instance included), makes the bundle invalid.

## Rationale

- Inputs are a skip, not a failure: a bundle may name a coin that does not exist yet, so a holder of a
  signed, unbroadcast module transaction could otherwise void a bundle (and its proving work) by
  broadcasting it after the bundle is built. As a skip, only that record is lost, unless every
  transfer of the bundle is skipped: the bundle then fails as a whole ("no transfer applied"), so a
  bundle made only of deposits that its depositors can turn into skips can still be voided (hosts
  screen deposits, below).
- The module's answer is a node's local fact: a node whose module cannot answer (its state not at the
  parent, unavailable) must not decide the block either way; it stops rather than call the block
  invalid. The rule module's state must be maintained by every validating node of a network from the
  upgrade's activation (on ycash6 the YED attestor set, which the tracked coins depend on, is a chain
  parameter on every public network).
- The same-block clause lets a node decide S2 from the module's state at the parent: only a coin of the
  same block can have become tracked earlier in that block, and wallets and hosts deposit confirmed
  coins anyway.
- Outputs are a failure: they are fixed by the bundle author, and the test is a pure function of the
  script, so no later transaction can trigger it.
- Such coins deposit, and such outputs are paid, by a leaf transfer, whose `vin`/`vout` the primitive
  and the modules read.

## Effect

No vector changes in bundle.json (no vector deposits a tracked coin or creates a template output); new
vectors should cover a tracked-coin skip, a same-block-coin skip and each refused output shape. Hosts
should accept only confirmed, module-untracked deposit coins, and should not build a bundle made only
of deposits from one untrusted source.
