# z_sendmany to a Yugen address (decision Y-9b)

Spec 0.5.2 (yugen-spec tag spec-0.5.2).

## What is built

- `z_sendmany <from> [{"address": <Yugen address>, "amount": a, "memo"?: hex}]` pays a Yugen payment
  request (spec §9) or a static full address (§12.1, hex) in one user command and one operation id.
  A Yugen address is any recipient string that is no Ycash address and that the builder helper accepts.
- From a transparent address (P2PKH, SLH-DSA `sqs`/`rqs`, FN-DSA `sqf`/`rqf`) or `ANY_TADDR`: ONE
  transaction, version group `0x59474e47` (N-TX): `vin` = the sender's coins, `vout` = change to the
  sender's address (dust change goes to the fee), Yugen field = a deposit-shape leaf transfer (§7.1:
  two dummy spends, `value_balance = -(amount + 255,600)`, FLAG_LEAFFEE; output 1 pays `amount` to the
  recipient, with the memo in the note package for a static address; output 2 is a zero note). The
  inputs are signed by ycashd with their own keys (ZIP-243 + hashYugen under the Yugen branch id).
- From a Sapling address: the wallet pays `amount + 255,600` to a fresh transparent key of its own
  (stock z_sendmany operation, policy AllowRevealedRecipients, its own fee), then deposits that one coin
  (no change output). One operation id; its result is the deposit txid.
- A memo to a payment request is refused up front (§9.2), never dropped.
- Helpers, never linked into ycashd: `-yugenbuilder=<contrib/yugen-sendbuild>` builds the transfer
  (yewd-yugen's builder, yew 49fc04a) and runs `-yugenprover=<yewd-yugen>` as `prove a` / `prove b`
  child processes. `-yugenprovetimeout` (default 1,800 s).

## Decisions

**N-S1: build the transfer in a helper process, prove with the wallet's prover binary.**
Options: (a) port the transfer builder (keys, note commitments, package seal, Falcon signature) into
C++; (b) a Rust helper reusing the wallet's builder, the node signing the transparent inputs; (c) fund
the wallet's deposit address and let yewd-yugen shield (two transactions). (c) is the old two-step
route decision Y-9b replaces. (a) duplicates the spec's reference code in a second language. (b) chosen:
the builder is the wallet's own code at a pin, the provers stay the wallet's binary, ycashd only
selects coins, signs and submits. Reversed if the wallet exposes a "build deposit for given vout"
command itself; the helper then shrinks to that call.

**N-S2: a one-time Yugen account per send.** The deposit has two dummy spends, so it needs no note
or key of a user's Yugen wallet; the helper derives a fresh account from 32 random bytes and forgets
it. Trade-off: the sender keeps no outgoing-view record (otag/orec are under the one-time key); the
transparent side is in the node wallet as usual. Reversed when ycashd holds a Yugen account of its own.

**N-S3: the Sapling hop uses a fresh transparent address, spent whole, once.** A new key from the
keypool per send; the hop pays exactly `amount + transfer fee`, so the deposit spends it whole and
leaves no change there; the address is never reused. What it reveals: the hop output and the deposit
amount (the deposit's `value_balance` is public anyway, §7.1); the Sapling sender stays shielded.
A watcher can link the hop and the deposit (adjacent, same value): this is the transparent turnstile
crossing decision Y-10 requires to be visible to the pool accounting. Reversed by a direct Sapling to
Yugen transaction shape, which the spec does not have.

**N-S4: Yugen address strings, and a short address resolved by the helper through `-yugenhosts`.**
The helper decodes the recipient with the wallet's own codec (`yewd_yugen::yaddr`, yew cc032ff):
`yqf…`/`yqtf…`/`yqrf…` (decision Y-14) are paid; `yqk…`/`yqtk…`/`yqrk…` are refused until Falcon-1024 is
enabled; `yug1…`/`yugreq1…` and the withdrawn `ygf/tgf/rgf` are refused (decision Y-13), each with a
refusal message rather than "unknown address format". The sender's choice is the wallet's (UX-1 P-3):
the request when present, without memo and payable at the anchor, else the static part with the memo.
ycashd keeps no set of paid requests, so it never treats a request as paid before (the wallet does;
a request is single-payer and two payments from ycashd both reach the recipient). A short static part
(the 66/67-character default address) is resolved by the helper's `resolve` mode with the wallet's own
two-host client (`hosts.rs`: one sync session's DPF queries, each answer checked against both hosts'
`aroot_h`), before any coin moves. Options considered: the hosts on ycashd (`-yugenhosts`, passed to the
helper) or inside the helper only (its own config file). Chosen: `-yugenhosts` on ycashd, because the
node operator configures ycashd and nothing else, and the yewd flag has the same name and form. Decision
Y-16: when the hosts do not serve the record yet (it is served from the next 16-block boundary after it
is written), the operation stays open and `z_getoperationstatus` reports `"status": "pending"` with the
reason; it is asked again once the tip reaches the next multiple of ANCHOR_GRID, and fails only on a
refusal, a host fault or cancellation. Not done: the cover queries of the fixed schedule (§17.8 item 1)
are not sent between payments by ycashd; a session runs only when a payment needs it (as yewd's devnet
cut Y-W8). Reversed by a ycashd-side sync loop with cover queries.

## Verified

`qa/rpc-tests/spend_matrix.py` (see `qa/rpc-tests/spend_matrix_status.md`).
