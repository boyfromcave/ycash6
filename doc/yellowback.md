# Ycash Yellowback (YED) — user guide

Ycash Yellowback (YED) is an over-collateralised US-dollar token on Ycash: lock YEC in a vault to
mint YED (`1 YED = 1 US dollar`), return the YED to get the YEC back. It is built on the **vault
upgrade**, a proposed Ycash network upgrade (`Consensus::UPGRADE_VAULT`, consensus branch ID
`0x6d5b7a31`, "Vault") that adds vaults and bonded signer sets to Ycash's consensus rules.
Yellowback is the upgrade's one registered rule module (tag `YED\0`): from the activation height
every upgraded node checks its rules as consensus rules, and a node that does not upgrade stops
following the chain there. The same vault feature also carries the wYEC bridge template, a
separate application with no module and nothing to do with YED.

**Status: proposed, not live.** Mainnet and testnet have no `UPGRADE_VAULT` activation height and
no YED attestor set; Yellowback runs on regtest and the one-laptop devnet only.

Below the activation height, and on a network that names no YED attestor set, nothing of
Yellowback applies and the `yed_*` commands do not exist; for everything Yellowback touches the
node behaves as the ycashd 6.20.0 baseline (tag `ycash6-baseline`). YED's own records are
ordinary transparent Ycash v4 transactions, one `OP_RETURN` payload, and a self-contained index
under `<datadir>/yellowback/`.

Where to read further: the vault primitive and its `set_*` / `vault_*` RPCs are `doc/vault-rpc.md`;
the `yed_*` RPC surface is `doc/yellowback-rpc.md`; what a mining pool runs is
`doc/yellowback-mining.md`; what an attestor runs is `doc/yellowback-attestor.md`; how to bring a
local devnet or a regtest node up in a few minutes is `doc/yellowback-devnet.md`. The normative
specification of this line is §15 of the workspace's `docs/plans/yellowback-upgrade-plan.md`
(§15.10 for YED). `doc/yellowback-spec.md` is the generated protocol text of the soft-fork design
(`harden/yellowback`): its MINT, TRANSFER, redemption, price and attestation rules are the ones the
YED module keeps, as amended by §15.10, and its activation, signalling, sunset and abandonment
rules do not apply here. This file is the user-facing guide to the node and its wallet commands.

## How it works

- **A Yellowback is a vault.** `yed_mint` locks YEC in the vault primitive's **V template**, with
  the YED attestor set as its signer set, `CLAIM_DELAY` as its delay, the lock height as its owner
  height and the claim height (lock height + `GRACE`) as its application height. It issues the
  minted YED to the minter as a transparent output carrying a small `OP_RETURN` payload. The
  attestor set never spends a YED vault: its only power over one is to cancel a pending claim.
- **YED moves like YEC.** `yed_send` builds an ordinary transparent transaction whose payload
  assigns cents to outputs; every Yellowback node keeps the same ledger of who holds what
  (`yed_getbalance`, `yed_listunspent`). Spending a YED output with a plain YEC command **burns**
  the YED it carries; the wallet locks its YED outputs so that cannot happen by accident.
- **Redemption burns the debt.** `yed_redeem` at or after the lock height spends the vault on its
  owner branch, burns the vault's minted cents, pays the pool fee and returns the collateral. A
  vault spend without that burn is an invalid transaction.
- **Underwater vaults can be claimed, after a delay.** From the claim height anyone holding enough
  YED can `yed_claim` a vault whose collateral is worth less than its debt at the claim price
  (`yed_listclaimable` lists them). The claim burns the debt and moves the collateral into a
  **pending release** (an intent) paying the claimant; any remainder above the claimant's share
  goes into a second one paying the owner. The vault is `CLAIMING` for `CLAIM_DELAY` blocks
  (576, twelve hours, on mainnet; 10 on regtest), during which the YED attestor set can cancel the
  claimant's intent; then anyone releases it (`vault_release`) and the vault is `CLAIMED`.
- **Prices come from pools and attestors.** Every pool running the module tags its coinbase with a
  YEC/USD quote; bonded attestors sign prices off-chain. A mint is sized at the lower of the two
  and a claim opens at the higher (*Where the price comes from*, below). Minting is refused while
  any halt holds (`yed_getstats.mintingAllowed`, `halts`).
- **The rules are consensus.** From the `UPGRADE_VAULT` height, on a network that names a YED
  attestor set, a transaction that breaks a Yellowback rule is refused by every mempool and a block
  carrying one is rejected by every upgraded node, whoever mined it. `yed_getactivation` reports
  the upgrade.
- **Fees pay the pools.** Mints, redemptions and claims pay a **pool fee** (the larger of a flat
  minimum and a few basis points of the collateral) to a pool that published a quote in the
  `payeeWindow` blocks up to the transaction's reference height (100 on mainnet, 10 on regtest);
  the wallet picks the payee, avoiding pools whose quotes strayed from their peers'.

## Where the price comes from

Every rule that matters reads a YEC/USD price: how much collateral a mint needs, when a vault
becomes claimable. Two independent populations supply it.

- **Pools.** Each pool's coinbase tag carries its quote. The pool price for a mint is the minimum
  of three rolling medians (8, 24 and 64 blocks on regtest; longer on mainnet), the claim price the
  maximum of the two longer ones. No price is defined until enough blocks in a window carry quotes.
- **Attestors.** An attestor is a member of the **YED attestor set**, a signer set of the vault
  primitive: it joins with a bonded `SET_JOIN` (`yed_registerattestor` does that with a fresh
  wallet key), stays live with periodic `SET_HEARTBEAT`s, and signs prices with an off-chain agent
  (`contrib/yellowback/attest/`). It needs no domain, no open port and only the node's own wallet.
  The highest-weighted bonds are *seated*; weight is bond size times age, so influence is slow,
  visible and costly to buy. An attestor that signs two different prices for one height is ejected
  and its bond frozen in the set.
- **Arming.** The attestation layer switches on by itself: once seven attestors have matured bonds
  on mainnet (`ATTEST_ARM_MIN`; three on regtest), a one-day countdown starts (`yed_getinfo.attest`
  shows `UNARMED` / `TRIGGERED` / `ARMED`). **Minting requires an armed layer** on mainnet and
  testnet (`MINT_REQUIRES_ARMED`; `yed_getinfo.mintRequiresArmed`): until it arms every mint is
  refused (`mintpol-unarmed`), and a hand-built one is invalid. Redemptions, transfers and claims
  do not wait for it. Regtest mints unarmed unless `-yellowbackmintrequiresarmed` is set.
- **What you see as a minter.** Once armed, `yed_mint` and `yed_claim` are **two transactions**:
  the wallet first publishes a small *carrier* output that commits to the attestations it will
  use, waits one block, then sends the mint or claim that spends it. The wallet does this for you;
  the GUI shows "preparing price proof (1 block)". You pay one extra small output and an attestor
  fee on top of the pool fee — half of it on mainnet (`ATTEST_FEE_BPS` 5,000), a quarter on regtest
  — which goes to an attestor whose signature you used.
- **The combination.** Mints size at the **lower** of the two sources and claims open at the
  **higher**, so each operation is priced against whichever population the transacting party
  controls least. If the two disagree by more than 15 %, minting pauses rather than guessing.
- **If attestations are unavailable**, minting refuses with `bundle-insufficient` and nothing else
  changes: YED still moves, redemptions still work, and existing vaults are untouched.

Attestor `seq`s are a 16-bit counter that never reuses a number: after 65,536 registrations no
further attestor can be registered, so the attestation layer would be exhausted permanently. With
`BOND_MIN` at 20,000 YEC and a one-year lock the concurrent set is bounded near supply / 20,000
(about 1,000), so exhaustion takes decades; the bound is a parameter-review item if `BOND_MIN`
ever drops, not a run-time concern. The per-block scan of every attestor record is linear in that
same count.

## Configuration

No flag turns Yellowback on or off. It is live wherever `UPGRADE_VAULT` has an activation height
and the network names its YED attestor set: on mainnet and testnet both are compiled in by the
release that activates it (neither is set yet); on regtest they are
`-nuparams=6d5b7a31:<h> -yellowbackattestorset=<setid>`. The set has to exist before the second
flag can name it, so a regtest node starts with the vault upgrade alone, creates the set with
`set_create` once the chain is past `<h>`, and restarts with `-yellowbackattestorset`
(`doc/yellowback-devnet.md` §2 walks through it). Without the attestor set the `yed_*` commands
are not registered.

Where Yellowback is live the node refuses `-prune` (the index rebuilds from blocks on disk), and a
node whose index is unhealthy stops rather than validate blocks without it (*Rebuilding the
index*). Options:

- `-reindex-yellowback` — wipe and rebuild the index on startup;
- `-yellowbackfee=<zat>` — the network fee of every Yellowback transaction (minimum 1,000);
- `-yellowbackmintlag=<blocks>` — how far below the tip a mint is evaluated (default 2);
- `-yellowbackpreferredpayee=<s1…>` — where this wallet's own transactions pay their pool fee when
  that pool is eligible; `-yellowbackpayeepenaltyblocks`, `-yellowbackpayeeaccuracywindow` and
  `-yellowbackpayeetiltbps` tune the payee choice;
- `-yellowbackpreferredattestor=<seq>` — the attestor this wallet pays its attestation fee to when
  it is in the bundle;
- `-yellowbackcarriertimeout=<sec>` — how long a waiting `yed_mint` / `yed_claim` blocks for its
  carrier to confirm;
- `-debug=yellowback` (and `-debug=vault` for the primitive).

The mining-side options (`-yellowbackpayoutaddress`, `-yellowbackquotemaxage`) are in
`doc/yellowback-mining.md`. Regtest additionally takes `-yellowbacksigmaref`,
`-yellowbacksupplycapbps`, `-yellowbackattestarmmin`, `-yellowbackmintrequiresarmed`,
`-yellowbackbundlecarrier` and `-yellowbacktestfault`; each is refused on mainnet and testnet.

**Flags from earlier designs.** `-yellowback` is accepted and ignored (`-yellowback=0` only
acknowledges a leftover index, see below), and `-experimentalfeatures` does not gate Yellowback.
`-yellowbackenforce`, `-yellowbacksignal`, `-yellowbacktemplatepolicy` and
`-yellowbackrequirehealthy` are logged and ignored. `-yellowbackstartheight` and
`-yellowbackenforceuntil` stop the node at startup with an error: YED starts at the
`UPGRADE_VAULT` activation height and has no end height.

## Using Yellowback from `ycash-cli`

Every amount is in **cents** (`10000` = $100.00); prices are in micro-USD per YEC (`2000000` =
$2.00). The node must have caught its index up (`yed_getinfo` → `healthy: true`, `height` at the
chain tip) before any of these work.

```
ycash-cli yed_getinfo                       # index height, healthy, upgrade, attest, miner, params
ycash-cli yed_getstats                      # supply, collateral, prices, halts, mintingAllowed
ycash-cli yed_getprice                      # the three medians and their fill
ycash-cli yed_getactivation                 # the vault upgrade: status, activationHeight, attestorSetId, claimDelay
ycash-cli yed_getnewaddress                 # a YED address (ye… on mainnet)
ycash-cli yed_getbalance
ycash-cli yed_estimatecollateral 10000 48   # YEC needed now to mint $100.00 with a 48-block lock (class A on regtest)
ycash-cli yed_mint 10000 48                 # mint; back up wallet.dat afterwards
ycash-cli yed_mint 10000 48 ys1…            # the same, funded from that Sapling address in one transaction
ycash-cli yed_listpositions                 # your vaults: status, lockHeight, claimHeight, canRedeem, intents
ycash-cli yed_send ye… 2500                 # send $25.00
ycash-cli yed_redeem <vaultTxid>            # burn the debt, pay the pool fee, take the collateral back
ycash-cli yed_listclaimable                 # vaults under the claim threshold (in term or past it)
ycash-cli yed_claim <vaultTxid>             # claim one with your own YED (a pending release for CLAIM_DELAY)
ycash-cli vault_release <intentTxid> 0      # after CLAIM_DELAY: pay the claimant's intent out
ycash-cli yed_listtransactions
```

A mint commits to a reference height two blocks below the tip; the collateral requirement is fixed
there (it is what `yed_mint` reports). A mint whose reference snapshot is not active, or whose
collateral is short at that snapshot, is an invalid transaction: every mempool refuses it
(`bad-yellowback-<verdict>`) and no block may carry it. The wallet refuses to build such a mint in
the first place (`mintpol-*` identifiers in `doc/yellowback-rpc.md`).

**The supply cap is soft.** YED supply is capped at `SUPPLY_CAP_BPS` (15 %) of YEC's issued market
cap, but reaching the cap is read as a sign that demand for YED is strong relative to YEC, not as
a stop: above it a mint is accepted iff its term class's base ratio is at least `RECAP_RATIO_BPS`
(500 %: class C, the long tier, on every network). Every YED minted above the cap locks at least
that multiple of its value in YEC, the buffer wanted if the market cap corrects.
`yed_getinfo.supplyCapReached` says the cap is reached, `yed_getstats.mintableClasses` which
classes still mint, and the wallet's `mintpol-cap` refusal says so. The same gate opens a mint
under the global-ratio halt (`HALT-2`).

**Claims open at the threshold, not at the term end** (in-term claims,
`docs/plans/yellowback-in-term-claims-plan.md`). A vault's claim branch is spendable from the
block after its mint; a claim is valid at any height at which the collateral is worth less than
`CLAIM_THRESHOLD_BPS` (125 %) of the debt at the attested claim price, and invalid otherwise, in
term, in grace and past it alike. Anyone may claim by burning the full debt; the claimant receives
collateral worth 125 % of the debt at that price, capped at the collateral, and whatever is left
returns to the owner; the attestor set may cancel a wrong-price claim within `CLAIM_DELAY`. The
owner's redeem is open from the block after the mint as well (the term's `lockHeight` is record-keeping; an
early-redeem fee is a separate decision), always for the full debt; `yed_getinfo.params`
says `inTermClaims: true`.

**Launch parameters.** Three flat tiers, the longer the term the higher the collateral ratio:
class A 30–90 days at 300 %, B 91–180 days at 400 %, C 181–365 days at 500 %
(`yed_getinfo.params.classes`); the volatility multiplier is pinned at 1 (`SIGMA_REF_BPS` 0). The
largest single mint is $2,500 (`MAX_MINT`), the pool fee 15 bps of the collateral (`FEE_BPS`,
minimum 0.5 YEC) with half of it again to the attestor (`ATTEST_FEE_BPS` 5,000), the global-ratio
halt 200 % and the recapitalisation floor 500 %. Regtest uses 25 bps, 2,500 bps, $10,000,
48–96 / 97–144 / 145–240 blocks and 250 % / 500 %.

Never spend a YED output with a plain YEC command: the YED it carries is burned. The wallet locks
every YED output it owns (`listlockunspent` shows them) so `sendtoaddress` and friends cannot pick
them by accident; `lockunspent true` on one of them removes that protection.

## What the consensus rules guarantee

- **Every YED rule is a consensus rule** at every height where `UPGRADE_VAULT` is active on a
  network that names the YED attestor set: a block that spends a YED vault against the rules, or
  mints YED it may not, is invalid on every upgraded node, whoever mined it. The rules hold without
  any pool's participation, in initial block download, during a reindex and at every height after
  activation.
- **The owner branch.** The vault's owner redeems with the V template's owner branch (selector 2)
  from the lock height, burning the debt. If the YED attestor set goes dormant or winds down, the
  primitive treats it as *released* and also opens selector 3 to the owner, at any height; the
  module applies the same redemption rules to it, so the debt is still burned. `yed_redeem` builds
  the selector-2 redemption.
- **The claim branch.** From the claim height a claim (selector 4) burns the debt and moves the
  collateral into the claimant's intent, plus the owner's residual intent when one is due. Until
  `CLAIM_DELAY` has passed, the YED attestor set may cancel the claimant's intent
  (`vault_buildcancel` + `set_signcancel` + `vault_send`): the vault is re-created at the cancel's
  output 0 as the same `ACTIVE` position, and the claim's burn is not refunded. After the delay
  anyone may release it. The owner's residual intent is never cancelled; anyone may release it to
  the owner after the delay.
- **No other way out.** A vault has no anyone-can-spend path: collateral leaves only by the owner
  branch or by a claim that burns the debt.

## Rebuilding the index

The index lives under `<datadir>/yellowback/` and is rebuilt from the blocks on disk when it is
missing, when the node was reindexed, or on `-reindex-yellowback`. `yed_getinfo.healthy: false`
names the reason (`unhealthyReason`) and always means "restart with `-reindex-yellowback`". Every
`yed_*` call except `yed_getinfo`, `yed_getblockverdict`, `yed_gettag`, `yed_decodepayload` and
`yed_setquote` refuses while the index is unhealthy or behind the chain tip. Because the module's
verdict is consensus, a node whose index is unhealthy stops (`AbortNode`) rather than validate
blocks without it; restart with `-reindex-yellowback`.

## How your YED is protected from being spent as plain YEC

A YED output is an ordinary 10,000-zatoshi P2PKH output; the dollars it carries live in the
Yellowback index, not in the output. Spend it with any command that does not know about Yellowback
and the YED is destroyed while the 10,000 zatoshi survive. The wallet therefore:

- **locks every YED outpoint it owns** (before it broadcasts, when it sees the transaction, and
  again after every block and at startup), so `sendtoaddress`, `sendmany` and `z_sendmany` never
  select one. `yed_getinfo.lockedOutputs` says how many are held and `yed_lockcoins` re-runs the
  reconciliation if `yed_listunspent` ever shows more coins than that;
- **refuses `lockunspent`** for one of those outpoints (`yed-locked-outpoint`), and re-applies its
  own locks after `lockunspent true` unlocks everything. The deliberate way out is
  `yed_unlockcoin "<txid>" <n> "I understand this burns YED"`;
- **refuses `sendrawtransaction`** for a raw transaction that spends one of them without a payload
  that reassigns it, unless you pass the third argument `allowyedburn` as `true`;
- **refuses to start with a wallet where Yellowback is not live** when the datadir holds a
  Yellowback index — for example a regtest node restarted without `-yellowbackattestorset`. Start
  it with the network's attestor set to keep those outputs locked, or with `-yellowback=0` to say
  you accept that the YED outputs in this wallet are spendable as plain YEC for this run
  (`-disablewallet` needs neither);
- **re-locks after an import**: `importprivkey`, `importaddress`, `importwallet` and `z_importkey`
  reconcile once their rescan is done, so YED that has just become yours is locked at once.

**What is not protected (documented, not enforced).** These are real ways to lose YED and no
software here can prevent them:

- **Keys used elsewhere.** A private key exported from this wallet and imported into any other
  Ycash wallet, a hardware signer or a script: that software has no Yellowback index, its coin
  selection sees an ordinary 10,000-zatoshi output, and the first transaction it builds burns the
  YED.
- **Other Yellowback nodes.** Another node that holds the same keys but is not this wallet locks
  nothing of yours until it reconciles; two wallets sharing keys can each build a spend the other
  does not know about.
- **Sending YED to someone whose wallet does not know Yellowback.** The `ye…`/`yt…`/`yr…` address
  prefix is the only technical guard: an address that decodes to the same key hash spells the
  same output. If the recipient's wallet does not run Yellowback, the YED you sent is theirs to
  burn by accident. Ask before sending.
- **Restoring an old `wallet.dat`.** A backup taken before a mint does not contain that vault's
  owner key, and the collateral cannot be redeemed without it (see *Backups*).

The rule of thumb: YED lives in the node that owns the keys **and** runs Yellowback. Keep it in one
place, and treat any export of a key as an export of the dollars with it.

## Sending an amount the wallet refuses

`yed_send` refuses (`change-floor`) when no selection of your YED coins leaves change of either
nothing at all or at least $1.00 — the minimum a payload can assign to an output. The message
names the nearest amounts that do work, below and above, and `yed_estimatesend <cents>` shows the
same thing before you commit to it, along with the inputs it would spend and the change it would
leave. A redemption or a claim does not refuse: it burns the sub-dollar remainder instead
(at most $0.99, reported as `extraBurnCents`) rather than leave the vault stranded.

## Backups

Ycash transparent keys are a random keypool, not derived from a seed. The vault owner key of every
mint lives only in `wallet.dat`. **Back up `wallet.dat` after every mint.** Wallet encryption in
Ycash is experimental; protect the file with full-disk encryption, keep RPC on localhost and hold an
offline copy.

## History

Earlier designs: Yellowback began as a federation prototype, being replaced from 2026-09-10 by a
design in which mining pools enforce the vault rules as a soft fork; the branch
`feature/digidollar` keeps the prototype's record and is never built on. The `harden/yellowback`
branch keeps that soft-fork version, which needs no network upgrade. The design history is in the
project workspace's plans.

## Trust statement

- **Every Yellowback and every bridge rule is a Ycash consensus rule, checked by every full node.**
  There is no pool that enforces, no pause, no abandonment.
- YED is created only when both a hashpower majority and a bonded attestor majority agree on the
  price. Neither alone can mint against a price it sets. A single signer is never a price.
- Your YEC is locked for the term you choose. You can redeem at any time by paying back the YED
  you minted. If your collateral falls below 125 % of your debt at the attested price, anyone may
  close your vault by paying your debt; you then receive whatever collateral is worth more than
  125 % of the debt. Before that happens, your wallet will warn you, and redeeming stops it. A
  claim completes only after a delay during which any honest attestor can stop one at a wrong
  price.
- **Wrapped Ycash is a federated bridge.** YEC behind wYEC is released only by its bonded signer
  set, after a delay, within a per-window cap, and only while no bonded watcher has cancelled.
  Ycash never reads Ethereum. If the signers go silent or wind down, every depositor recovers
  their own YEC with no counterparty. Bonds are burned for signing conflicting releases.
- Nothing in either application touches the shielded pool.

## Build and test baseline (ycashd 6.20.0)

This is the ycashd 6.20.0 line (`ycash6`), branch `upgrade/vault` (the vault upgrade). The v4.5.0
line's build notes live in `ycash-dd`'s copy of this file. CI is the record of what passes:
`.github/workflows/yellowback-tests.yml` runs the unit tests, the Yellowback functional scripts,
the inherited `STOCK_BASELINE`, the fuzz and devnet jobs and the audit. What the 6.20.0 pin needed before Yellowback could be measured
against it, and why, is recorded in [`yellowback-baseline.md`](yellowback-baseline.md); the port plan is
`docs/plans/yellowback-ycash6-plan.md` in the workspace repository.

```
# host conditions (macOS, Apple Silicon)
export PATH="/opt/homebrew/opt/libtool/libexec/gnubin:/opt/homebrew/opt/coreutils/libexec/gnubin:/opt/homebrew/bin:$PATH"
export CARGO_TARGET_DIR="$PWD/target"
LIBTOOLIZE=glibtoolize ./zcutil/build.sh -j8              # cold: ~35 min (depends builds clang 15 and Rust)
make -C src -j8 ycashd ycash-cli test/test_bitcoin         # incremental
# a fresh worktree must generate the cxx bridge headers before a target-only make:
#   awk '/^CXXBRIDGE_H = /{f=1;next} f&&/^ *rust\/gen/{gsub(/[ \\]/,"");print;next} f{exit}' src/Makefile.am | xargs make -C src -j8

# unit tests
src/test/test_bitcoin --run_test='yellowback_*,vault_*'
# one functional script (the 6.20.0 harness reads ZCASHD, not BITCOIND)
ZCASHD="$PWD/src/ycashd" ../.venv/bin/python -u qa/rpc-tests/yellowback_index.py --srcdir="$PWD/src" --tmpdir=/tmp/yb-index --portseed=11
# the audit gates vs the tag ycash6-baseline (report-only on this line: the consensus review gate replaces them)
qa/yellowback-audit.sh --report-only
```

Regtest runs all six Ycash upgrades at height 1, as on the v4.5.0 line: baseline fix 3 keeps regtest's
Equihash at (48,5) under every upgrade (6.20.0 had dropped v4.5.0's regtest exemption). The stock node
for parity tests is built from branch `ycash6-stock` (all three baseline fixes, no Yellowback).

**A test fault this line has and v4.5.0 does not: `-yellowbacktestfault=crash:<height>`** (regtest
only, as every `-yellowbacktestfault` spec; `init.cpp` refuses the flag on any other network). When
`CheckConnect` is about to judge the block at `<height>` for real (never under `fJustCheck`), the
node flushes the block index and chainstate and then `raise(SIGKILL)`s itself
(`src/yellowback/index.cpp`, `TestFault::crashHeight`). That reproduces a state only 6.20.0 can
reach: a rule-breaking block stored on disk, flushed, and not yet judged. 6.20.0's `ThreadImport`
holds `fImporting` across its final `ActivateBestChain` on every start, so without the port's
pre-`ThreadImport` `ActivateBestChain` (plan F-37) the restarted node connected that block unjudged
under N2 ("initial sync / reindex / import"). On v4.5.0 `RewindBlockIndex` erased the never-connected
entry at start and the block was fetched and judged again, so the fault has no counterpart there.
`yellowback_index.py` (`rejected_survives_kill9`) drives it; the debug log line is
`yellowback: -yellowbacktestfault: crash before judging block <hash> at <height>`.

The inherited functional suite at the pin is classified script by script in
[`yellowback-baseline.md`, "Inherited functional suite at the pin"](yellowback-baseline.md#inherited-functional-suite-at-the-pin).
Of the 119 `BASE_SCRIPTS`, 39 pass against the stock node. 77 of the failures come from
upstream-Zcash assumptions in the harness (branch ids, explicit fees above the 0.00004 cap, mininode,
addresses, caches, branding) or from intended Ycash policy. Three are defects in the pin (findings
7–9), and the fee-error message bug is finding 10. None of them is fixed in this port; they are
reported to miodragpop. The 42 entries that pass twice, including `zmq_test`, `invalidateblock` and
`getblocktemplate_longpoll`, are the `STOCK_BASELINE` that CI runs against the fork binary with no YED
attestor set. One operator note follows from finding 7: on 6.20.0, `-lightwalletd` must be run
together with `-insightexplorer`.

## Releases and continuity

A Yellowback parameter set is consensus from the `UPGRADE_VAULT` height and has no end height:
there is no sunset, no renewal release and no freeze. Changing a value is a network upgrade like
any other, coordinated through a new consensus branch ID. A defect found in the meantime is
contained by the rules themselves: a claim at a wrong price is cancelled by the YED attestor set
within `CLAIM_DELAY`, and an owner can always redeem by the owner branch.
