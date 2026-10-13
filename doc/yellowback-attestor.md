# Running a YED price attestor

This is the **YED price attestor** (`yellowback-attest`, `yed_signattestation`). The **wYEC bridge
attestor** (Hawkeye) is a different program with a different key: see `hawkeye/docs/operations.md`
in the Hawkeye repository.

**One hot key, one node — ever.** The attestor hot key (`attestorPubKey`) must be held by exactly
one `ycashd` wallet, and only that node's `yed_signattestation` may sign with it. Two prices signed
for one block height by one `seq` are an equivocation (EQV-1): anyone can put the two attestations
on chain and the attestor is **ejected for good** — the key and the bond outpoint can never
register again, the fee stream stops, and the bond sits idle until its locktime. The node
protects you from yourself on one machine: `yed_signattestation` records every `(seq,
citedHeight, price)` it has ever signed in `<datadir>/yellowback/attest-signed.dat`, fsyncs it
before answering, returns the earlier signature if you ask for the same price again and refuses
(`equivocation-guard`) if you ask for a different one — so an agent restart mid-interval, or two
agents on one node, cannot equivocate. **Two nodes holding one hot key defeat that guard**: a
hot-standby node with a copy of `wallet.dat`, a restored backup started while the original still
runs, a second `yellowback-attest` pointed at a second node. Do not run them. If you must move an
attestor to a new machine, stop the old node first, copy `wallet.dat` *and* `attest-signed.dat`
together, and never start the old one again. Do not delete `attest-signed.dat`.

## Since the vault upgrade (P4-b): the attestor registry is the attestor set

Read this first; where the sections below disagree, this section wins (upgrade plan §15.10).

- **Every validating node names the same attestor set.** Until the release that sets it as a chain
  parameter (upgrade plan P8) the set is the node parameter `-yellowbackattestorset` (regtest; unset
  on mainnet and testnet). Every validating node of a regtest or devnet network must be started with
  the same value: a node without it computes different set state for the same blocks (no ejections,
  no liveness `lastact`, no displacement) and may reject blocks the others accept. Compare
  `vault_getinfo.attestorsetid` across your nodes.
- **Registration is a `SET_JOIN`** to the vault primitive's YED attestor set (`attestorSetId`,
  `yed_getinfo.upgrade`). `yed_registerattestor <bondYec> <lockBlocks>` is exactly that join with a
  fresh wallet key (`flags` is ignored); `set_join <attestorSetId> <bondYec> <bondLocktime>
  [memberKey]` is the same with a key of your choice. `ATTESTOR_REGISTER` and `ATTESTOR_REVIVE`
  payloads are invalid transactions now.
- **One key**: the member key is the hot key (it signs attestations), the bond key (the bond is
  `P2SH(<bondLocktime> CLTV DROP <memberKey> CHECKSIG)`, the same script as before) and the fee
  key. **The bond key cannot be kept cold any more** — the "Bond key hygiene" section below no
  longer applies: whoever holds the attestor node's wallet can spend the bond after
  `bondLocktime` (given up for a single registry, upgrade plan §15.10 P4-b).
- **Heartbeats**: the set's member dormancy makes an attestor DORMANT when its `lastAct` is older
  than the set's `livenesswindow`. Since the seats review (B2, 2026-10-11) an attestation of yours used in a held
  mint, registered notice or claim (its bundle passing BUNDLE-1, its refHeight within `REF_WINDOW`) also counts:
  `lastAct` rises to its `citedHeight` (in the primitive and the mirror alike), so an attestor whose prices are used
  stays live; heartbeats still cover quiet periods. `yellowback-attest attest`
  sends `set_heartbeat <attestorSetId> <memberKey>` every `heartbeat_blocks` blocks (default
  1,152 ≈ a day; keep it well below the set's `livenesswindow`, `set_getinfo <attestorSetId>`).
  The v3 dormancy (selected and absent, below) still applies on top.
- **Revival is a `SET_HEARTBEAT`** (`yed_revive <seq> <priceMicroUsd>` sends it and still returns a
  freshly signed attestation): the record is ELIGIBLE again at that block.
- **Maturity** is `max(the set's maturity, BOND_MATURITY)`; a join whose bond is below the module's floor (D-Q-30: 5 % of all YEC locked
  in YED vaults spread over the 9 seats, never below 10,000 YEC nor above 20,000 YEC; `yed_getinfo`
  `params.attest.bondMinZat` is the floor for a join in the next block) is **invalid** (`attestor-bond-below-min`,
  seats re-review 2026-10-11: no member that can never become ELIGIBLE holds a seat); a join at or above it becomes
  ELIGIBLE at maturity. It is judged once, at registration; a seated attestor is never re-judged.
  **Post headroom:** the floor is judged at the snapshot before the join's own block, so a bond sized at
  exactly today's `bondMinZat` can fall short if vault collateral grows before it confirms — and the join then
  leaves the mempool unmined. Post at least 10 % above `bondMinZat` (`yed_registerattestor` warns
  `bond-near-min` otherwise), or `bondMinCapZat` (20,000 YEC), which always qualifies.
- **Ejection freezes the bond.** EQV-1 (two prices, one height) ejects the member *and* freezes
  its bond in the set: the bond can never be withdrawn, and the key never becomes ELIGIBLE again.
  Equivocation is the **only** removal (owner 2026-10-11): `SET_REMOVE` and `SET_WINDDOWN` of the attestor
  set are invalid (`attestor-set-act`), so members cannot vote one another out.
- **The set is open, 15 seats, and a larger bond can evict.** The module adopts the attestor set only
  when it is OPEN with 15 seats. A join into the full set evicts one member: first a member that is not
  live (`lastAct < h − livenessWindow`: no heartbeat and no carried attestation for the liveness window), the
  one of least seat weight; else the member of least seat weight, only when the new bond exceeds that seat
  weight by 5 % (`evictMarginBps`). No join evicts with a bond below `bondMinFloorZat` (10,000 YEC; seats review
  B2: no dust evictions; the floor, not the collateral-based minimum, because the primitive's displacement hook
  reads no module state). The module adopts the set only when its `livenesswindow` is at least
  `ATTESTOR_LIVENESS_MIN` (1,152 blocks, one day; regtest 16; review B3). The evicted record becomes `WITHDRAWN`
  with `evicted: true`; its bond is **not** frozen and is returned `BOND_MATURITY` after the eviction, and the
  key may join again once that bond is spent. Otherwise a join into the full set is refused (`bad-vault-act-seats`).
- `yed_listattestors` rows carry `lastAct` and `bondFrozen`; `set_getinfo <attestorSetId>` shows
  the same members from the primitive's side.

This guide is written from the v3 plan (`docs/plans/yellowback-v3-development-plan.md` §4.7, §5)
and the proposal (`docs/reference/yellowback-price-attestation.md` §4–§6, §12, §13). The RPCs it
names are specified in `doc/yellowback-rpc.md`; the agent's every setting is documented in
`contrib/yellowback/attest/attest.toml.sample` and its README. Ycash Yellowback (YED) is the
system; YED is the unit.

## Member-key hosts (sign once)

Your member key also signs set spends: the YED attestor set is the cancel set of every YED claim
intent (`set_signcancel`), and a bridge attestor (Hawkeye) signs unlocks and cancels of the bridge
vault with `set_signunlock` / `set_signcancel`. Two signatures by one key over two different spends
of one outpoint are a provable equivocation: anyone submits `set_equivocation`, the member is
EJECTED and its bond frozen. The node's wallet refuses a second, different signature — but only
from the **sign-once record in its own `wallet.dat`** (`doc/vault-rpc.md`, "Sign once"). The seed
does not carry it, so:

- **One wallet, on one signing host, per member key.** Never run two nodes (an HA pair, a test copy)
  with one member key in their wallets, and never restore a `wallet.dat` by copying an old backup
  over a live one: the node cannot detect either (an old file carries an old record and no restore
  marker).
- **Back up `wallet.dat` after every `set_signunlock` / `set_signcancel`** — the seed is not enough.
  A bridge attestor backs up Hawkeye's `hawkeye.db` together with the node's `wallet.dat`, as one
  unit (Hawkeye's operations runbook owns the full procedure).
- **Restoring from the seed alone is unsafe for a member key.** Before a restored wallet (or one
  that imported the key with `importwallet` / `z_importwallet` / `importprivkey`) signs, import the
  record: `set_listsigned` on the old wallet, or its `dumpwallet` / `z_exportwallet` dump, whose
  `vaultsetsig=` lines carry it, then `set_importsigned` (or `importwallet` / `z_importwallet` of the
  dump) on the new one, check it with `set_listsigned`, and only then `set_acknowledgerestore` —
  your confirmation that no other host or backup has signed since that history was taken. The
  node enforces this: such a wallet (and one whose imported key joins a set later, e.g. during
  IBD) refuses with `set-sign-restored` until the acknowledgement — importing alone never clears
  it — unless a call passes `{"acknowledgerestore": true}`, your statement that the key never
  signed a spend of that outpoint.
- Re-funding is safe: set signatures are over `SIGHASH_ALL|ANYONECANPAY` and bind the template input
  and the outputs, not the fee inputs, so a spend re-funded with `vault_refee` (or returned
  re-funded by `vault_buildcancel`) has the same sighash and re-signing it is idempotent. The hazard
  is a *different* build.
- **Broadcast cancels early and watch them.** Anyone may re-fund a signed cancel, so a wrong-price
  claimant can broadcast a variant of it that chains on a low-fee, unconfirmed parent and pin it
  (no replace-by-fee) until the intent's delay passes. Send a cancel as soon as it is signed,
  directly to well-connected peers and miners, monitor its confirmation, and if it lingers re-fund
  it from a confirmed coin with `vault_refee` and send that.

## Cancelling wrong-price claims (the cancel limit, automated)

The YED attestor set is the cancel set of every YED claim: until `CLAIM_DELAY` (576 blocks, 12 h) after a claim
confirms, the set can cancel it, and the vault comes back as the same position with the claim's burn refunded
(CAN-1). The cancel limit (docs/plans/yellowback-cancel-limit-design.md, owner 2026-10-13) makes repeated cancels of
one position expensive: the k-th cancel within `CANCEL_QUIET` (8,064 blocks, 7 days) needs co-signatures of
`min(k, CANCEL_SIGNERS_MAX)` distinct current members (`CANCEL_SIGNERS_MAX` 4; `cancelsRequired` in `yed_getvault`),
and each co-signature is your **signed price statement at the claim's refHeight** (C4b): the node signs it
(`yed_signcancelcosign`) with the price your key attested at that height, so it can never contradict your own
attestation, and EQV-1 ejects a member whose attestation there says otherwise. Only **confirmed** claims are
co-signed: a claim's txid can still change before it confirms.

The owner decided that this brake is automated before release, so **the agent does it with no operator**: `attest`
runs, beside its attestation loop and with `[cancel]` on by default,

- a **watcher** that judges every confirmed YED claim with *your* price at the claim's refHeight and calls it
  **wrong-price** when the vault was not claimable at that price with `margin_bps` (default 5 %) to spare. Your price
  there is, first, one your key is **on record** for at that height -- the attestations the agent signed (its state
  file), your attestation in the claim's own bundle (only if its signature verifies under your key: a bundle is not
  checked by the node before arming), the node's attestation pool, the node's equivocation guard --
  and only otherwise the last aggregate the agent computed at or before that height. With none of these the claim is
  `unjudged` (alerted, never guessed from a later price). It raises an alert, co-signs (`auto_cosign`) and publishes
  the co-signature on a second gossip topic, `yellowback/cancel/<network>/1`, carried by the same iroh endpoint and
  the same `peers`. A claim that is claimable at your price is honest and left alone. A **new** price is stated for
  a height only when the agent's own record covers that height (its state file began before it); otherwise, if the
  guard holds nothing either, the agent refuses (`no-record`), because your key may have attested there before the
  record began, and two prices at one height are slashed (EQV-1). Reorgs are followed: a claim whose block leaves the
  chain is held (`claim-reorged`), never closed, and is judged again when it is re-mined; a reorg across the refHeight
  makes the agent re-sign over the new block hash;
- a **gossip receiver** on its own task that takes only 115-byte frames from the topic: duplicates are dropped,
  then the cheap checks (a current member's seq -- the primitive's own `current`, maturity included --, a claim this
  node knows, its refHeight, a price at which the vault was not claimable, no valid entry of that seq already held),
  then a **uniform random sample** within a budget of 2,000 signature checks a second (so a flood, from anyone and
  relayed by anyone, only dilutes an honest frame's chance per copy), then the signature must recover to that seq's
  member key, then a per-member rate limit. Your agent republishes your co-signature every block while the claim is
  short of co-signatures, so it gets through a flood within a few blocks;
- **delivery** of co-signatures (owner decisions 2026-10-13): straight to the other members over iroh on a
  members-only protocol. A connection on it is refused at the handshake unless its endpoint id is bound to a current
  member. You bind yours once (the agent does it): your node signs `YED-IROH-1|<network>|<set>|<seq>|<endpoint>|
  <issued>|<expiry>` with your member key through the stock `signmessage` -- a statement about a network address,
  never a price -- and re-signs it every few days. During the trial the old public cancel topic runs beside it
  (`delivery = "trial"`); `delivery = "direct"` uses the direct path alone. If a claim is still short of
  co-signatures `fallback_after_blocks` (192, a third of `CLAIM_DELAY`) after it confirmed, your agent also publishes
  your co-signature on chain in one standard transaction (an 82-byte OP_RETURN, fee `fallback_fee_zat` = 10,000 zat,
  at most `fallback_max_txs` = 20 a day; alert `onchain-fallback`), and every driver reads such records from the
  chain. Keep a few small confirmed P2PKH coins in the node's wallet for it;
- a **collector** in which one member drives each claim: the members in seq order, rotated per claim; rank r takes
  over `r × takeover_blocks` blocks after the claim confirmed (at most 36, and shrunk at run time so the last rank
  still fits in `CLAIM_DELAY`). The driver gathers `cancelsRequired` co-signatures plus `spares` (the rule counts the
  valid ones, so spares absorb a co-signer that leaves before the cancel confirms), then `yed_buildcancel` →
  `set_signcancel` → `vault_send`, pushes the cancel and its carrier to `broadcast_rpc`, re-pushes it if it lingers,
  and re-funds and rebuilds it (`vault_refee`, then `yed_buildcancel`) if it falls out of the mempool -- with
  backoff, at most `max_sends` times (default 5, failed attempts included), then `cancel-send-cap`.

Its state (claims, co-signatures, the cancel it sent, your signed prices and price history) is in `state_file`
(default `yellowback-cancel-<seq>.json` beside the node's cookie, else `~/.ycash/yellowback-cancel-<network>-<seq>.json`);
a restart resumes from it. Losing it costs a little: the agent co-signs again through the node's guard and rebuilds
the same cancel, but it will not state a new price for heights before the new file began.

**The node's guard file `attest-signed.dat` is precious.** It is the record of every price your key signed, by height,
and the node uses it to refuse a second, different price for a height (`yed_signattestation`, `yed_revive`,
`yed_signcancelcosign`). Back it up with `wallet.dat`, move it with `wallet.dat`, and never run a member key on a node
without it: a node that lost it can be made to state a price your key already contradicted, and EQV-1 then ejects the
member and freezes the bond.

**Relays.** The direct endpoint uses n0's public relays by default. Add the project's relay as a fallback with
`[cancel] fallback_relays = ["https://relay.<project host>"]` (and `[transport] fallback_relays` for the price topic). To
run a relay yourself: `cargo install iroh-relay --features server` at the version matching the agent's iroh (1.2),
a `relay.toml` with a `[tls]` table (`hostname = "<host>"`, `cert_mode = "LetsEncrypt"`), ports 80 and 443/TCP open
(7842/UDP too with `enable_quic_addr_discovery = true`), and `iroh-relay --config-path relay.toml` under systemd;
members then list `https://<host>`. A relay only forwards
encrypted QUIC: it cannot read, forge or admit anything, but it sees IP addresses and endpoint ids.

**What you do.** Keep a few YEC of confirmed coins in the node's wallet (the cancel's carrier and fee come from it);
after importing your member key or restoring the wallet, complete the sign-once history and run
`set_acknowledgerestore` (above), or `set_signcancel` refuses and the agent alerts `sign-refused`; give
`broadcast_rpc` the RPC of a well-connected node or a pool you trust if you have one; and wire `alert_command` (or a
log watcher on `ALERT`) to a pager (at most four run at once, each killed after 30 s). The alerts:

| Alert | Meaning | Act |
|---|---|---|
| `wrong-price` | a confirmed claim is not claimable at your price; the agent co-signs and the rota cancels it | watch it close as `cancelled` |
| `unjudged` | you have no price of your own at the claim's refHeight (your feed or the agent was down there): you do not co-sign | fix the feed; others may still cancel |
| `no-record` | the guard holds no price of your key at that height and the agent's record does not cover it: it states none | none needed; restore `attest-signed.dat` if it was lost |
| `cosign-refused` | the node refused for good: your key signed, for that height, a price at which the vault *was* claimable, or another price (`equivocation-guard`), or a price out of range | none for the first: your own attestation says the claim is right; investigate the others |
| `cosign-within-margin` | the price your key signed there is inside the margin | none, or review `margin_bps` |
| `sign-refused` | `set_signcancel` refused (restore marker, locked wallet) | fix the wallet; the next member in the rota takes over |
| `claim-reorged` | the claim's block left the chain; the claim is held and followed again if re-mined | none; watch it |
| `foreign-spend` | a transaction that is not yours has spent the claim's intent in the mempool for `refee_after_blocks` without confirming (a pinned cancel variant, or a release) | send a cancel directly to miners |
| `onchain-fallback` | a claim was still short of co-signatures `fallback_after_blocks` after it confirmed: your co-signature went on chain | check your direct connectivity (`direct-probe` from another member, relays) |
| `onchain-fallback-cap` | `fallback_max_txs` fallback transactions in a day: no more | investigate: a wrong-price campaign, or the direct path is down |
| `cancel-send-cap` | your cancel left the mempool `max_sends` times | act by hand |
| `wrong-price-past-delay`, `wrong-price-released` | a claim you judged wrong-price reached its release height uncancelled | escalate: the brake failed (too few live members, censorship) |

Transient refusals of a co-signature (a timeout, a locked wallet, the index behind the chain or the claim's
refHeight not yet indexed) raise nothing: the agent retries at the next poll.

If the gossip task dies the agent exits non-zero; the packaged service restarts it (`Restart=always`).

The record (`recording_since`) begins only once the node is out of initial block download and at the tip; before
that the agent states no new price.

`auto_cosign = false` keeps the watcher and its alerts but never makes, stores or carries your own co-signature
(the agent still drives on other members' co-signatures) and leaves the co-signing to you (`yellowback-attest cosign
<txid:n>` prints your co-signature; anyone with `cancelsRequired` of them runs `yed_buildcancel <intent> [cosigs]`,
`set_signcancel`, `vault_send`). `drive = false` co-signs but never sends. `enabled = false` turns all of it off.

**What it cannot do.** It cannot make a cancel confirm: a majority that censors cancels for `CLAIM_DELAY` still
lets a wrong-price claim through (the design's A-7), and a pinned third-party variant of a signed cancel can only be
outrun by sending early to well-connected peers (there is no replace-by-fee). Four colluding members can still
cancel an honest claim every time (the design's stated captured-set residual), and a lone member can still delay one
claim per vault per `CANCEL_QUIET`.

## What you are NOT asked to do

- **No domain, no TLS certificate, no inbound port.** The agent publishes over an `iroh-gossip`
  topic (QUIC with hole punching and relay fallback); nothing listens. The optional HTTPS
  endpoint that subscribers can poll (`[subscribe] endpoints` on *their* side) is a second path
  some attestors may offer; it is not required and this guide does not set one up.
- **But one third party does see you.** With the default `[transport] relays = []` the swarm
  bootstraps through iroh's public relays (operated by n0). A relay cannot forge, alter or sign
  anything — attestations are signed and public — but its operator sees your IP address and
  endpoint id, can delay your messages, and can partition the swarm. If that matters to you, run
  `relays = ["https://relay.you.example"]` (your own, or one the Ycash project lists for mainnet)
  or `relays = ["none"]` with direct peers only. Either way, what leaves your machine is 74
  public bytes per interval and nothing else.
- **No periodic transactions.** Registration is one transaction; leaving (`set_leave`) is one more and
  the withdrawal, 14 days later, a third. Attestations are 74-byte gossip messages, never on chain unless a minter
  or claimant carries them (or someone proves an equivocation with them).
- **No hot wallet beyond the node's own.** The node holds the hot key and signs; the only spend
  it may ever make on your behalf is the rare `yed_revive`, funded from whatever confirmed YEC
  the wallet holds — a few YEC of change is enough. Fees accrue to the bond key, which since the
  vault upgrade is the member key itself (v3 kept it cold: the obsolete section below).
- **No mining, no payout address, no `-yellowbackpayout…` flag**, and no pool membership. An
  attestor node is a plain upgraded `ycashd` on a network where Yellowback is live.
- **No price of your own.** The agent aggregates public sources; the node never reads a socket
  for Yellowback. You choose sources, you do not type prices (`--mock-price` exists for regtest
  and demos only, and the agent refuses it when the node reports any other network unless
  `--i-know-this-is-not-regtest` is given).

## What an attestor is

An attestor is a party that has posted a **bond** (a long CLTV time-lock back to its own key,
never custody) as a member of the YED attestor set and runs the **attestor agent** `yellowback-attest`, which polls price
sources, has the node sign a price every `k` blocks (`10` on mainnet) and gossips the 74-byte
attestation. Minters and claimants carry those attestations into their transactions; the enforcing
nodes verify the signatures, take a bond-weighted quantile and combine it with the mining pools'
medians (`pMint = min`, `pClaim = max`). An attestor is paid for attestations that are **used** in a
confirmed mint or claim (`ATTEST_FEE_BPS`: half the pool fee on mainnet and testnet, a quarter on
regtest, to `P2PKH(bondPubKey)`), never for attestations published.

Equivocation is slashed. Two prices signed for one height by one attestor (EQV-1), or two
conflicting set signatures by one member (`SET_EQUIVOCATION`), eject the member from the YED
attestor set and **freeze its bond**: the vault primitive refuses every later spend of a frozen
bond (`bad-vault-bond-frozen`), so the bond is lost even after its time-lock expires. The set can
not remove members by vote (`SET_REMOVE` of the attestor set is invalid). Every other
misbehaviour costs ejection or dormancy and a bond that earns nothing until it unlocks; attestors
can **grief but not extract** — no direction the price is pushed in pays them (proposal §10.3).

What you need: an upgraded `ycashd` on a network where Yellowback is live (no payout address, no
mining), outbound connectivity, a bond of at least `params.attest.bondMinZat` (D-Q-30 on mainnet: 5 % of YED vault collateral over 9
seats, between 5,000 and 20,000 YEC; a larger bond outranks smaller ones
for a seat, and tenure adds up to ×1.9 over a year) — no fixed lock: you can leave any time and the bond
returns 14 days after you leave (below) — and price sources. No inbound port, no
domain, no funded hot wallet beyond the node's own for the rare `yed_revive`.

## Registration

```
ycashd                                              # any upgraded node; no payout address, no mining
ycash-cli yed_registerattestor 20000 0              # once (a SET_JOIN); then wait BOND_MATURITY
yellowback-attest attest --conf attest.toml          # forever: polls, yed_signattestation, gossips
```

`yed_registerattestor <bondYec> <lockBlocks> [flags]` builds the one transaction an attestor ever
needs: `vout[0]` the bond — `P2SH(<bondLocktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <bondPubKey>
OP_CHECKSIG)` of `bondYec` — and an `OP_RETURN` payload naming two fresh keys of your wallet: the
**hot key** (`attestorPubKey`, signs attestations) and the **bond key** (`bondPubKey`, owns the
bond and receives fees). `flags` declares your source tier (`0` direct exchange APIs, `1` mixed,
`2` aggregator) and, in bit 2, whether you also operate a mining pool — voluntary, and the
explorer shows it (proposal §7.5). The record is `PENDING` for `BOND_MATURITY` blocks (16,128 ≈ two
weeks), then `ELIGIBLE`; `yed_listattestors` shows your `seq` — the attestor's identity from then
on — once the transaction confirms.

**A bond cannot be topped up.** To change it, register a new identity (new keys, new `seq`, age
from zero) and let the old one leave (`set_leave`) and withdraw 14 days later. **Back up `wallet.dat`
right after registering** — both keys came from the keypool, and a backup taken before the
registration does not contain them (Ycash 4.5 transparent keys are not HD).

Registration is open from `START_HEIGHT`; it never makes a block invalid and needs no miner's
approval (proposal §5.3). Duplicate hot keys are refused (REG-A1) unless the earlier record is
`WITHDRAWN`; an `EJECTED` key is barred for good.

## Bond key hygiene

**Obsolete since the vault upgrade (P4-b):** the bond key *is* the member key and cannot be kept
cold (see "Since the vault upgrade" above). This section describes the v3 registry and applies to
no running network; it is kept for the record.

The registering wallet holds both keys. The hot key must stay in it — `yed_signattestation` uses
it every ten blocks. The bond key is used by exactly one command, `yed_withdrawbond`, 14 days
after you leave; until then it is worth `bondYec` to whoever holds it, and it collects your fees.

Two addresses are involved, and only one of them takes a private key: `bondAddress` (in
`yed_registerattestor`, `yed_listattestors` and `yed_decodepayload`) is the **P2SH address of the
bond output itself**, `P2SH(<bondLocktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <bondPubKey>
OP_CHECKSIG)` — an address of a script, not of a key, so `dumpprivkey` does not accept it. The
key behind it is `bondPubKey` (shown by `yed_decodepayload` on the registration transaction's
`OP_RETURN`), and attestation fees are paid to **`P2PKH(bondPubKey)`**, an ordinary transparent
address of your wallet. Move that key cold:

1. After the registration confirms, find the bond key's P2PKH address: it is one of the wallet's
   own transparent addresses (`z_exportwallet` lists them; `validateaddress <addr>` shows
   `pubkey` for an own address — the one whose `pubkey` equals `bondPubKey`). Then
   `dumpprivkey <that address>` and store the WIF offline, twice.
2. Verify the offline copy imports into an offline wallet and yields the same P2PKH address.
3. Only then remove it from the hot wallet. Ycash 4.5 has no key deletion; the practical form is a
   fresh wallet: `yed_registerattestor` from a wallet created for the purpose, export the bond key,
   then keep that wallet as the attestor wallet knowing the bond key it still contains is a copy
   of an offline original — or, stricter, register from a wallet that holds only the bond key
   afterwards and `importprivkey` the hot key into the attestor node. Documented, not enforced
   (plan §4.6).
4. Fees accrue to `P2PKH(bondPubKey)` as ordinary transparent YEC (`attestPayee` in a minter's
   `yed_mint` result is that address); spending them needs the bond key, so collect them from the
   cold side, not the attestor node.

The bond output itself is **not** `IsMine` to the wallet (its script is non-standard to `Solver`):
`listunspent` will not show it, `sendtoaddress` cannot reach it, and nothing about it is in
`wallet.dat` except the key. The wallet finds it through the chain's `Attestors` table by
`bondPubKey`, which is how `yed_withdrawbond` works after a restore (`importprivkey` +
`-rescan`).

## The agent

`yellowback-attest` is one Rust binary in `contrib/yellowback/attest/` (plan §5): `attest`
(this guide), `subscribe` (beside a minting node; YecWallet and the devnet run it), and two
one-shot checks, `sources` (fetch every configured source once and show what resolved — run it
before the first start and whenever a venue changes shape) and `check-config`. It holds no key
and opens no listening socket.

**Building.** `rust-toolchain.toml` pins stable 1.91.0 and `cargo` picks it up from that
directory; the node's own `depends/` Rust (1.63, vendored crates) is not involved. Inside a node
checkout that has had a `depends` build, an untracked `.cargo/config` at the tree's root redirects
crates.io to the vendored directory; the crate's own `.cargo/config.toml` undoes that redirect, so
the same commands work in a fresh clone and in a built checkout:

```
cd contrib/yellowback/attest
cargo build --locked --release          # target/release/yellowback-attest
cargo test --locked
```

**Configuration** — `attest.toml`, from `attest.toml.sample` (every key documented there; unknown
keys are refused, exit 2):

```
[node]        rpc_url = "http://127.0.0.1:8832"; rpc_cookie = "~/.ycash/.cookie"   (or rpc_user/rpc_password); rpc_timeout
              allow_insecure_rpc = false       http:// with credentials to a host other than loopback is refused without this
[attest]      seq = <your seq>                 REQUIRED: from yed_listattestors once the registration confirmed
              every_blocks = 10                k; sign every N new blocks (regtest devnet: 4)
              fail_polls = 2                   after this many failed aggregates at a due tick, publish nothing until a good one
              ref_lag = 2                      citedHeight = tip - ref_lag (REF_LAG)
              poll_seconds = 15                yed_getinfo cadence; the sources are polled at the same cadence to fill the window
              twap_seconds = 900, min_sources = 3, min_venues = 2, min_btc_sources = 2, outlier_bps = 1000,
              silence_seconds = 120, fetch_timeout = 15       the aggregator, as the quote agent's [quote] table
[[sources]]   name, kind = coingecko_simple | coingecko_ticker | nonkyc_market | peatio_ticker | kraken_ticker | coinbase_ticker | generic,
              plus the preset's parameters and the guards (max_age, max_spread_bps, reject_paths ...);
              exactly the quote agent's rows (contrib/yellowback/pool/yellowback-quote.toml.sample)
[[btc_usd_sources]]   BTC/USD references, only needed when a source is BTC-quoted
[transport]   kind = "iroh"                    production
              relays = []                      empty: iroh's default relays; ["none"]: direct only; or your own
              peers = [...]                    bootstrap endpoint ids of other attestors/subscribers (the swarm has no discovery)
              secret_key_file = "~/.ycash/yellowback-attest.key"   keeps this agent's endpoint id stable across restarts
              topic_override = ""              default "yellowback/attest/<network>/3"; leave it
              kind = "dir"; path = "..."       tests and the regtest devnet: <seq>-<citedHeight>.att files in a shared directory
[cancel]      enabled = true; auto_cosign = true; margin_bps = 500    the cancel automation ("Cancelling wrong-price claims")
              delivery = "trial" (trial | direct | gossip | onchain); direct_secret_key_file; direct_relays = []; fallback_relays = []
              binding_ttl_blocks = 8064; onchain_fallback = true; fallback_after_blocks = 192; fallback_fee_zat = 10000; fallback_max_txs = 20
              drive = true; spares = 2; spare_wait_blocks = 1; takeover_blocks = 6 (at most 36); min_confirmations = 1
              refee_after_blocks = 6; max_sends = 5; republish_blocks = 4; price_tolerance_blocks = 24; state_file = "..."
              broadcast_rpc = [...]; allow_insecure_broadcast = false; alert_command = "..."; gossip_burst = 16; gossip_refill_seconds = 10
[subscribe]   listattestors_seconds = 60; endpoints = [...]; endpoints_seconds = 30      subscriber side only
              allow_insecure_endpoints = false (endpoints are https://; http:// only on loopback without this)
              seq_burst = 8; seq_refill_seconds = 15   per-seq token bucket in front of yed_addattestation
```

**Keep `attest.toml` private.** Prefer `rpc_cookie` (the node's own file, re-read on every call).
If you use `rpc_user`/`rpc_password` the file holds the node's RPC secret — which can
`yed_signattestation` with your hot key — so `chmod 600 attest.toml`: the agent refuses to start
on a group- or world-readable one (`--insecure-config-permissions` overrides). It also refuses to
send those credentials as cleartext Basic auth over plain `http://` to any host but loopback: run
the agent beside the node, tunnel to `127.0.0.1`, or use `https://` (`allow_insecure_rpc = true`
to insist). The packaged unit reads `/etc/yellowback/attest.toml`; create it `0600 root:yellowback`
or whichever user the unit runs as.

Set `secret_key_file` and publish the endpoint id the agent prints at startup (the `iroh`
transport bootstraps from `peers`, so subscribers need the ids of attestors and attestors of one
another; without a stable key your id changes on every restart). Every `every_blocks` blocks the
agent aggregates the sources exactly as the quote agent does (prefer a median across venues over a
VWAP from one deep book: on thin markets venue diversity beats volume), calls
`yed_signattestation <seq> <priceMicroUsd> <tip − ref_lag>` and publishes the 74 bytes it gets
back. `yed_signattestation` returns `reused: true` when it already signed that `(seq,
citedHeight)` at that price (a restart mid-interval), and refuses with `equivocation-guard` when
it signed a different one — the agent logs that and publishes nothing for the height. After
`fail_polls` failed aggregates it publishes nothing until a good one: a missing attestation is the
correct report of a broken feed, and costs you only that interval's fees. Prices are integer
micro-USD per YEC inside `[PRICE_MIN, PRICE_MAX]`.

Correlation is the cost of aggregators: eight attestors reading one aggregator are one
observation. Declare your tier honestly (`flags` at registration) and prefer direct APIs where you
can.

**Running it.** `contrib/yellowback/attest/packaging/` holds `yellowback-attest.service`
(systemd; `Restart=always`, `ProtectSystem=strict`, an `/etc/yellowback/attest.toml`, mode 0600),
the subscriber's unit, and `org.ycash.yellowback-attest.plist` for launchd. Start the node first;
the agent retries RPC and transport failures forever and exits non-zero only for a bad
configuration. A regtest walk-through with the `dir` transport is in the crate's README.

The subscriber side runs on a public topic anyone can join, so before it spends an RPC on a
frame it drops what it already handed to the node (the last 4,096 frames), frames citing a
height outside `[tip − 64, tip + 8]` of its own node, and frames beyond a per-`seq` token
bucket (`seq_burst` at once, then one per `seq_refill_seconds`; a legitimate attestor emits one
per `every_blocks` blocks). The signature is still verified only by the node.

**Monitoring.** On your node, `yed_getinfo.attest` — `status` (`UNARMED`/`TRIGGERED`/`ARMED`),
`triggerHeight`, `armHeight`, `seatedCount`, `poolSize`, `poolFresh`, `required`, `armed` — and
`yed_listattestors`, where your row's `status`, `seated`, `weight`, `pinned` and
`lastBundleHeight` (the newest confirmed bundle that carried your attestation; it moves only when
you were selected and delivered) are what matters. `poolFresh` in *your* node's row is always
`false` unless you also run a subscriber: the attest side pushes nothing into its own pool. To see
that your attestations reach the network, run `yellowback-attest subscribe` beside any node (or
ask a minter) and check `yed_getattestations` there for your `seq` with `fresh: true`. The agent
logs one `info` line per publish.

**Track the market; never attest a constant (PIN-2).** The mirror of the pools' PIN-1 applies to
attestors: when the cross-section `xMint` moved by more than `PIN_DELTA_BPS` (5 %) over the last
`PIN_WINDOW` blocks, a `seq` whose confirmed bundle rows in that window (at least `PIN_MIN_TAGS`
of them) all carry one price is pinned — it leaves `seated(R)` for selection and its
attestations stop contributing while the pin holds. And the same threshold governs the pools:
a pool whose tags are constant is pinned once *your* attested prices move more than 5 % within
a window, which is what the calibration scripts in `contrib/yellowback/` exercise. The agent's
sources must be live market data; a fixed price in `attest.toml` for anything but a regtest
walk-through is a way to be selected and then ignored.

## Arming, and the day's notice

Nothing reads attestations until the layer **arms** (proposal §6.4, D-4). At the first snapshot
with `ATTEST_ARM_MIN` (7 on mainnet and testnet, hardening H-2; 3 on regtest) `ELIGIBLE` attestors the state becomes `TRIGGERED` with `armHeight =
triggerHeight + ATTEST_ARM_DELAY` (1,152 blocks ≈ one day); at `armHeight` it becomes `ARMED` and
every mint and claim from then on must carry a valid bundle. The trigger is a public fact for that
day: wallets show "attestation layer arms at height …", `yed_getinfo.attest` reports
`TRIGGERED`/`armHeight`, and an operator can hold a mint until the layer is live. Arming never
reverses by itself; a release can switch the layer off with `ATTEST_REQUIRED = false` (W15). For
an attestor the notice means: have the agent running and publishing **before** `armHeight` — the
first snapshot after it seats by weight, and every bundle that selects a seated attestor and
does not find it counts toward that attestor's dormancy.

Everyone registered on or before `triggerHeight + FOUNDING_WINDOW` (8,064 blocks ≈ a week after
the trigger) is a **founding member** and accrues age from `triggerHeight`, so nobody gains by
having registered a block earlier than the rest. Later registrants age from their own
`registerHeight`.

**Seating (owner 2026-10-11).** At every snapshot the `N_SLOTS` (9) eligible attestors with the greatest
**seat weight** are **seated**: `seatWeight = bondZat · f(age)`, where the tenure factor
`f = 1 + 0.9 · (lg(u + a) − lg(u)) / (lg(u + cap) − lg(u))` (`u` = `SEAT_AGE_UNIT` 1,152 blocks, one day;
`cap` = `SEAT_AGE_CAP` 420,480, one year; `a` = age clamped to `[0, cap]`; deterministic Q16 integer logs, at most 1/65536 below the true floor) runs from
1.0 at registration to 1.9 at a year — 1.317 at a week, 1.63 at six months. A currently seated attestor's
seat weight counts ×1.05 (`SEAT_MARGIN`), so seats do not flap between near-equal bonds. Consequences: a new
20,000 YEC bond outranks 8,000 YEC at any tenure; a bond 1.5× larger outranks a week-old member but not a
year-old one. The same seat weight (from the join height) decides eviction from the full 15-seat set (above).
A transaction's bundle draws `M_SELECT + K_SLACK` (4 + 2) of the seated by a hash of the reference block,
and at least `M_SELECT` of the selected must be in it; the bundle statistic and that draw still weigh by
`weight = bondZat · min(age, AGE_CAP)`. Being seated, bonded and reachable is what earns; latency does not.
An unseated attestor keeps publishing, keeps its age, and takes the lowest seat when its seat weight passes
the holder's (with the 5 % margin). `yed_listattestors` shows `seatWeight` (in Q16: divide by 65,536 for zat)
beside `weight`.

## Dormancy and revival

An attestor is **DORMANT** when it was seated for the whole of the last `DORMANCY_BLOCKS` (16,128 ≈
two weeks), was *selected* by at least `DORMANCY_MIN_BUNDLES` (20) confirmed bundles in that
window, and appeared in none of them — selected that often and never delivered (proposal §12).
During a halt or a quiet period there are no bundles and nobody goes dormant for it. A dormant
attestor is not seated and earns nothing; its age is kept.

Revival is one transaction of your own: `yed_revive <seq> <priceMicroUsd>` signs one fresh
attestation for `citedHeight = tip − REF_LAG` with the hot key (through the same equivocation
guard, so it can never contradict what the agent signed for that height — give it the price the
agent would publish now, read from `yellowback-attest sources`), puts it in an `OP_RETURN`
(`ATTESTOR_REVIVE`, payload `0x08`), funds it from any confirmed YEC in the wallet, and REV-1 sets
the record `ELIGIBLE` again with its age kept. It is the only on-chain act asked of an attestor
after registration, and only after a fortnight of being selected and absent. Refusals:
`not-dormant`, `attest-key-not-held`, `attest-range`, `equivocation-guard`, `RPC_WALLET_ERROR`
(no YEC to fund it). Fix the outage first (`poolFresh` for your `seq` in `yed_listattestors` on a
subscriber's node tells you whether your attestations arrive), then revive; a revived attestor
that keeps missing goes dormant again after another fortnight.

**Ejection** (`EJECTED`) has one cause: equivocation, the first paragraph of this document. It is
terminal for the key and the outpoint. A stolen hot key can grief (sign wrong prices; it is
bounded like a colluding attestor) or get your seat ejected by equivocating. Since the vault
upgrade the bond key is the same key, so a thief also takes the bond once its exit delay has passed
(v3 kept the bond key separate and cold). (The bridge attestor's key is different: see
hawkeye/README.md.)

## Withdrawal

**The bond exit delay (owner 2026-10-11).** There is no one-year lock: an attestor can leave at any time,
and its bond returns `BOND_MATURITY` (16,128 blocks, 14 days; 8 on regtest) after it leaves, evicted or
voluntary. The lock lives in the vault primitive's state, not in the bond script (`BOND_MIN_LOCK` is 0; the
attestor set's maturity is `BOND_MATURITY`, the delay): a bond is spendable only from its member's
`exitHeight + maturity`; before that the primitive refuses it (`bad-vault-bond-locked`).

1. **Leave**: `set_leave <attestorSetId> [memberkey]` broadcasts the member's own `SET_REMOVE`, signed by its
   key alone, without burn — the one `SET_REMOVE` of the attestor set that is valid. The record is
   `WITHDRAWN` from that block (no seat, no selection), `statusHeight` the exit height. An eviction (above)
   starts the same clock.
2. **Wait** `BOND_MATURITY` blocks. You are still slashable: an equivocation proved during the delay ejects
   you and freezes the bond for good.
3. **Withdraw**: `yed_withdrawbond <seq> [to]` spends the bond to any address (the record keeps its
   `statusHeight`; `bondSpentHeight` is set). Before `statusHeight + BOND_MATURITY`, while still a member, or
   with a frozen bond it refuses (`bond-locked`).

The hot key is then free to be discarded; a withdrawn attestor's key may register again.

## Quick reference

| I want to… | Command | Refusals to expect |
|---|---|---|
| register | `yed_registerattestor <bondYec> <lockBlocks> [flags]` | `bond-below-min`, `lock-below-min` |
| see my status, seat, weight | `yed_listattestors` | — |
| read my registration's keys | `yed_decodepayload $(ycash-cli getrawtransaction <txid>)` (`register.attestorPubKey`, `bondPubKey`, `bondAddress`) | — |
| check the sources before starting | `yellowback-attest sources --conf attest.toml` | exit 1 when no aggregate |
| sign (the agent does this) | `yed_signattestation <seq> <priceMicroUsd> [citedHeight]` | `attest-unknown-seq`, `attest-key-not-held`, `equivocation-guard`, `attest-range`, `attest-stale` |
| return from dormancy | `yed_revive <seq> <priceMicroUsd>` | `not-dormant`, `attest-key-not-held`, `equivocation-guard` |
| report someone's equivocation | `yed_reportequivocation <hexA> <hexB>` | `not-equivocation` |
| cancel wrong-price claims (the agent does this) | `attest` with `[cancel]` on: watcher, gossip, collector | the alerts in "Cancelling wrong-price claims" |
| co-sign a cancel by hand | `yellowback-attest cosign <txid:n>` (`yed_signcancelcosign <intent> [price] [seq]`) | `price-required`, `cancel-statement-claimable`, `equivocation-guard` |
| build a cancel by hand | `yed_buildcancel <intent> [cosigs]`, `set_signcancel <hex>`, `vault_send <hex>` | `cancel-cosign-needed`, `cancel-cosign-not-member`, `set-sign-restored` |
| leave the set (starts the 14-day delay) | `set_leave <attestorSetId> [memberkey]` | `bad-vault-act-remove` (not an active member) |
| withdraw the bond (after `set_leave` and `BOND_MATURITY`; still the bond spend on the vault upgrade) | `yed_withdrawbond <seq> [to]` | `bond-locked`, `bond-spent`, `attest-key-not-held` |

Every identifier is defined in `doc/yellowback-rpc.md`. The two calibration measurements that
precede the first mainnet registration (`DIVERGE_BPS_ATTEST`, `PIN_DELTA_BPS`) are the release's
job, not the attestor's: `contrib/yellowback/attest/calibrate/README.md`.
