# Ycash Yellowback (YED) — user guide

Ycash Yellowback (YED) is a decentralized, over-collateralised US-dollar stablecoin **overlay** on
Ycash. **Yellowback v2 is a miner-enforced soft fork** (plan §1): Tier 1 mining policy plus one
block-validity hook in `main.cpp` that is inert until an activation derived from the chain itself,
that only ever fires on transactions spending a Yellowback vault, that never bans a peer, that fails
open only on a storage failure, and that an operator can switch off with one flag. Every block an
enforcing miner produces is valid to a stock node; a stock miner's block is rejected only if it
spends a vault in a way the rules forbid — a soft fork in the P2SH/CLTV sense. Everything else is an
overlay: ordinary Ycash v4 transactions, one `OP_RETURN` payload, a self-contained index under
`<datadir>/yellowback/`. A node that does not enable the feature runs the code paths of the ycashd 6.20.0 baseline (tag `ycash6-baseline`).

**Yellowback v3 adds a second price population** on top of that: bonded **attestors** sign
YEC/USD prices off-chain, and a mint or claim carries a few of those signatures with it, so a
price that pays needs a hashpower majority *and* a bond-weighted majority of the attestors picked
for that transaction. It changes nothing about custody. See *Where the price comes from* below.

The normative protocol is `doc/yellowback-spec.md` (§3 of the workspace plans, published verbatim
by `make spec`, with the v3 delta appended); the design record, the decisions and the phase plan
are the workspace's `docs/plans/yellowback-v3-development-plan.md` (a delta on
`yellowback-v2-development-plan.md`); the RPC surface is `doc/yellowback-rpc.md`; what a mining
pool runs is `doc/yellowback-mining.md`; what an attestor runs is `doc/yellowback-attestor.md`;
how to bring a local devnet or a regtest node up in a few minutes is `doc/yellowback-devnet.md`.
This file is the user-facing guide to the node and its wallet commands.

## How it works

- **A Yellowback is a vault.** `yed_mint` locks YEC in a pay-to-script-hash output whose script
  says: *until the lock height nobody spends this; from the lock height the minter's key can; from
  the claim height (lock + grace) anyone can.* It issues the minted YED to the minter as a
  transparent output carrying a small `OP_RETURN` payload. Ycash consensus enforces the lock and
  the owner key; nothing else about Yellowback is consensus.
- **YED moves like YEC.** `yed_send` builds an ordinary transparent transaction whose payload
  assigns cents to outputs; every Yellowback-aware node keeps the same ledger of who holds what
  (`yed_getbalance`, `yed_listunspent`). Spending a YED output with a plain YEC command **burns**
  the YED it carries; the wallet locks its YED outputs so that cannot happen by accident.
- **Redemption burns the debt.** `yed_redeem` at or after the lock height burns the vault's minted
  cents, pays an enforcement fee to a pool that quoted recently, and returns the collateral.
  Spending the vault *without* that burn is the one thing the enforcing pools reject.
- **Underwater vaults can be claimed.** After the claim height anyone holding enough YED can
  `yed_claim` a vault whose collateral is worth less than its debt at the claim price, burning that
  YED (`yed_listclaimable` lists them).
- **Prices come from pools.** Every pool running the module tags its coinbase with a YEC/USD quote
  from its own price agent; the mint price is the minimum of three rolling medians (8, 24 and 64
  blocks on regtest; longer on mainnet) and the claim price the maximum of the two longer ones. No
  price is defined until enough blocks in a window carry quotes, and minting is refused while any
  halt holds (`yed_getstats.mintingAllowed`, `halts`).
- **Activation is by signalling.** Pools set a signal bit in the same tag; once 75 % of a window
  signal the rules lock in and one window later they are active (`yed_getactivation`). Before that
  the module only tags, filters and accounts. Minting is impossible before activation.
- **Fees pay the enforcers.** Mints, redemptions and claims pay a fee (the larger of a flat minimum
  and a few basis points of the collateral) to a pool that published a quote in the `payeeWindow`
  blocks up to the transaction's reference height (100 on mainnet, 10 on regtest); the wallet picks the payee, avoiding pools whose quotes strayed
  from their peers'.

## Where the price comes from (v3: price attestation)

Every rule that matters reads a YEC/USD price: how much collateral a mint needs, when a vault
becomes claimable. v2 took that price from one place — the quotes pools publish in their
coinbases. v3 keeps those and adds a second, independent population.

- **Attestors.** Anyone may post a long time-locked bond (`yed_registerattestor`) and then sign
  prices with an off-chain agent (`contrib/yellowback/attest/`). Attestors send no transactions
  after registering and need no domain, no open port and no funded hot wallet. The highest-weighted
  bonds are *seated*; weight is bond size times age, so influence is slow, visible and costly to buy.
- **Arming.** The layer switches on by itself: once five attestors have matured bonds, a one-day
  countdown starts (`yed_getinfo.attest` shows `UNARMED` / `TRIGGERED` / `ARMED`). Until it arms,
  the node behaves exactly as v2.
- **What you see as a minter.** `yed_mint` and `yed_claim` become **two transactions**: the wallet
  first publishes a small *carrier* output that commits to the attestations it will use, waits one
  block, then sends the mint or claim that spends it. The wallet does this for you; the GUI shows
  "preparing price proof (1 block)". You pay one extra small output and a 25 % addition to the
  enforcement fee, which goes to an attestor whose signature you used.
- **The combination.** Mints size at the **lower** of the two sources and claims open at the
  **higher**, so each operation is priced against whichever population the transacting party
  controls least. If the two disagree by more than 15 %, minting pauses rather than guessing.
- **If attestations are unavailable**, minting refuses with `bundle-insufficient` and nothing else
  changes: YED still moves, redemptions still work, and existing vaults are untouched.

Attestor `seq`s are a 16-bit counter that never reuses a number (audit A-8): after 65,536
registrations REG-A1 can register nobody (the transaction is simply not applied, by totality), so
the attestation layer is exhausted permanently. With `BOND_MIN` at 20,000 YEC and a one-year lock
the concurrent set is bounded near supply / 20,000 (about 1,000), so exhaustion takes decades;
the bound is a parameter-review item if `BOND_MIN` ever drops, not a run-time concern. The
per-block scan of every attestor record (REG-A1, dormancy) is linear in that same count.

## Enabling

```
experimentalfeatures=1
yellowback=1
```

`-yellowback` refuses to start with `-prune` (the index rebuilds from blocks on disk). Other
options: `-reindex-yellowback` (wipe and rebuild the index), `-yellowbackfee=<zat>` (the network
fee of every Yellowback transaction, minimum 1000), `-yellowbackmintlag=<blocks>` (default 2),
`-yellowbackpreferredpayee=<s1…>` (where this wallet's own transactions pay their enforcement fee
when that pool is eligible), `-debug=yellowback`. The mining-side options (`-yellowbackpayoutaddress`,
`-yellowbacksignal`, `-yellowbackenforce`, `-yellowbackquotemaxage`, …) are in
`doc/yellowback-mining.md`. Regtest additionally takes `-yellowbackstartheight`,
`-yellowbacksigmaref`, `-yellowbacksupplycapbps` and `-yellowbackenforceuntil`.

## Using Yellowback from `ycash-cli`

Every amount is in **cents** (`10000` = $100.00); prices are in micro-USD per YEC (`2000000` =
$2.00). The node must have caught its index up (`yed_getinfo` → `healthy: true`, `height` at the
chain tip) before any of these work.

```
ycash-cli yed_getinfo                       # index height, healthy, enforcing, activation, abandoned, miner, params
ycash-cli yed_getstats                      # supply, collateral, prices, halts, mintingAllowed
ycash-cli yed_getprice                      # the three medians and their fill
ycash-cli yed_getactivation                 # signaling / locked_in / active, signalCount
ycash-cli yed_getnewaddress                 # a YED address (ye… on mainnet)
ycash-cli yed_getbalance
ycash-cli yed_estimatecollateral 10000 48   # YEC needed now to mint $100.00 with a 48-block lock (class A on regtest)
ycash-cli yed_mint 10000 48                 # mint; back up wallet.dat afterwards
ycash-cli yed_mint 10000 48 ys1…            # the same, funded from that Sapling address in one transaction
ycash-cli yed_listpositions                 # your vaults: status, lockHeight, claimHeight, canRedeem, canSweep, sweepBefore
ycash-cli yed_send ye… 2500                 # send $25.00
ycash-cli yed_redeem <vaultTxid>            # burn the debt, pay the fee, take the collateral back (a VOID vault: release, no burn)
ycash-cli yed_listclaimable                 # underwater vaults past their claim height
ycash-cli yed_claim <vaultTxid>             # claim one with your own YED
ycash-cli yed_listtransactions
```

A mint commits to a reference height two blocks below the tip; the collateral requirement is fixed
there (it is what `yed_mint` reports). A mint whose reference snapshot is not ACTIVE or whose
collateral is short at that snapshot is **VOID**: the YED it would have issued never exists and the
collateral is released by its owner with `yed_redeem` at the lock height (no burn, no fee). The
wallet refuses to build a mint that would be VOID (`mintpol-*` identifiers in `doc/yellowback-rpc.md`).

Never spend a YED output with a plain YEC command: the YED it carries is burned. The wallet locks
every YED output it owns (`listlockunspent` shows them) so `sendtoaddress` and friends cannot pick
them by accident; `lockunspent true` on one of them removes that protection.

## If the pools stop enforcing: abandonment and the sweep

Enforcement is only as strong as the share of blocks that signal. `yed_getactivation.signalCount`
and `yed_getstats.halts` show it:

- **Below 60 % of blocks signalling, minting pauses** (the `PARTICIPATION` halt); it resumes at
  75 %. Existing YED stays redeemable by a minter who holds it.
- **Below 50 %, block rejection pauses too** (the `ENFORCEMENT` halt): while it holds, neither the
  owner path nor the claim path is policed — collateral can leave a vault without its burn, and
  YED so left unbacked stays in circulation. Vaults untouched during the pause are protected again
  when rejection resumes at 60 %.
- **`ABANDON_BLOCKS` of the `ENFORCEMENT` halt is abandonment** (`yed_getinfo.abandoned`; 128
  blocks on regtest, 34,560 — thirty days, the same length as `GRACE` — on mainnet; W21). It is
  the minimum time the module waits for its developers after any halt, including a deliberate
  freeze (`doc/yellowback-release.md`, "Freeze, then fix"). This is also where a sunset with no
  successor release ends up. From then on every vault's claim path is spendable by anyone at its claim height and nobody
  refuses the spend: whoever mines first takes the collateral.
- **Every enforcement gap is such a window, not only abandonment** (audit A-5). The claim branch
  of a vault script is `<claimHeight> CLTV DROP OP_TRUE`: the only thing that stops a claim
  without its burn is an enforcing miner refusing the block. Whenever this node's enforcement
  stands down — initial block download (more than 24 h behind), `-reindex` / `-loadblock`, the
  work valve tripped, catch-up suppression (six blocks of work ahead on a rejected chain), the
  `ENFORCEMENT` halt, the sunset — a stock-mined claim-path spend of any ACTIVE vault past its
  claim height takes the collateral with no burn and the vault closes `unbacked`. At the sunset
  with no successor release the gap lasts until abandonment is declared: the signal bits decay
  below the floor over a window (2,016 blocks) and `ABANDON_BLOCKS` (34,560) follow, roughly a
  month on mainnet during which `yed_sweep` is still refused on an owner's own node (MP-1 stands
  down only under abandonment). **Owners: redeem, or let no vault sit past its claim height
  across a sunset**; a wallet should warn at `ENFORCE_UNTIL_HEIGHT - grace` (the GUI's job, not
  the node's).

What an owner does under abandonment: **sweep before the claim height.** `yed_listpositions` shows
`canSweep: true` and `sweepBefore` (the claim height) on every ACTIVE vault you own; `yed_sweep
<vaultTxid> "I understand this leaves YED unbacked"` spends the vault back to you with no burn and
no fee, and every node of every release relays and mines it like any other transaction (the
command also returns the raw `hex` so you can submit it elsewhere). The YED minted against a swept
or claimed vault is **unbacked** from then on — `yed_getvault.unbacked`, `Totals.unbackedCents` —
which is why the acknowledgement is required; the claim path stays open to everyone, so the race is
fair, but it is a race. Outside abandonment `yed_sweep` refuses (`sweep-not-abandoned`) and an
enforcing pool would never mine such a spend. A VOID vault (a failed mint, which never carried a
debt) is not affected: its owner releases it with `yed_redeem` at its lock height at any time.

## Rebuilding the index

The index lives under `<datadir>/yellowback/` and is rebuilt from the blocks on disk when it is
missing, when the node was reindexed, or on `-reindex-yellowback`. `yed_getinfo.healthy: false`
names the reason (`unhealthyReason`) and always means "restart with `-reindex-yellowback`". Every
`yed_*` call except `yed_getinfo`, `yed_getblockverdict`, `yed_gettag`, `yed_decodepayload` and
`yed_setquote` refuses while the index is unhealthy or behind the chain tip. Plain `-reindex` is
safe on an enforcing node: nothing is rejected while the node is reindexing or in initial block
download.

## How your YED is protected from being spent as plain YEC (H5–H10)

A YED output is an ordinary 10,000-zatoshi P2PKH output; the dollars it carries live in the
overlay index, not in the output. Spend it with any command that does not know about Yellowback
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
- **refuses to start without `-yellowback`** when the datadir holds a Yellowback index. Start with
  `-experimentalfeatures -yellowback`, or with `-yellowback=0` to say you accept that the YED
  outputs in this wallet are spendable as plain YEC for this run;
- **re-locks after an import**: `importprivkey`, `importaddress`, `importwallet` and `z_importkey`
  reconcile once their rescan is done, so YED that has just become yours is locked at once.

**What is not protected (H9 — documented, not enforced).** These are real ways to lose YED and no
software here can prevent them:

- **Keys used elsewhere.** A private key exported from this wallet and imported into any other
  Ycash wallet, a hardware signer or a script: that software has no overlay, its coin selection
  sees an ordinary 10,000-zatoshi output, and the first transaction it builds burns the YED.
- **Other `-yellowback` nodes.** Another node that holds the same keys but is not this wallet
  locks nothing of yours until it reconciles; two wallets sharing keys can each build a spend the
  other does not know about.
- **Sending YED to someone who does not run the overlay.** The `ye…`/`yt…`/`yr…` address prefix is
  the only technical guard: an address that decodes to the same key hash spells the same output.
  If the recipient's wallet does not run Yellowback, the YED you sent is theirs to burn by
  accident. Ask before sending.
- **Restoring an old `wallet.dat`.** A backup taken before a mint does not contain that vault's
  owner key, and the collateral cannot be redeemed without it (see *Backups*).

The rule of thumb: YED lives in the node that owns the keys **and** runs `-yellowback`. Keep it in
one place, and treat any export of a key as an export of the dollars with it.

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

v1 was a federation prototype, being replaced by phase since 2026-09-10 (plan §0, retired
design in `docs/plans/archived/`): a k-of-n federation co-signed every redemption and published
prices in anchor-chain transactions. v2 keeps the vault, the payload and the index and replaces the
federation with the pools' quote tags and miner enforcement; the branch `feature/digidollar` in
this repository is the prototype's record and is never built on. The v1 trust statement retired
with it; what follows is the v2 statement, §8.1 of `doc/yellowback-spec.md`, which the `audit`
job checks byte for byte against that file.

## Trust statement

Yellowback v2 is a miner-enforced, over-collateralised stablecoin overlay on Ycash.

- Consensus-enforced (by every Ycash node, upgraded or not): collateral cannot leave a vault
  before its lock height; before the claim height only the minter's key can spend it.
- Enforced by every Yellowback-aware node deterministically: Yellowback accounting (conservation,
  supply, collateral totals, vault status, prices, activation, halts).
- Enforced by the mining pools that run the Yellowback module, and effective for the whole
  network once a supermajority of blocks signal: collateral is released only against the burn of
  the vault's debt; an underwater, abandoned vault can be claimed only by burning that debt; both
  pay a fee to a pool that published a price quote in the 100 blocks up to the transaction's
  reference height.
- Prices are the medians of the quotes pools publish in their own blocks; moving them needs a
  majority of *quote-tagged* blocks over a window, which is a majority of hashpower only when
  most blocks carry quotes — so the windows that decide claims are undefined until two-thirds of
  their blocks carry quotes, and the mint window until half do. A pool whose quotes stray from
  its peers' loses the fee income that wallets' default payee choice would otherwise send it.
- **Therefore:** a majority of hashpower that runs the module and follows it makes the rules
  hold; a majority that does not — or a minority that the trailing signal count mistakes for a
  majority, since the count is self-reported — could release collateral without burns or, with
  enough quote-tagged blocks, move the price; the same majority could already reorganise the
  chain. No operator, committee or key other than the minter's can move collateral before the
  claim height; after it, only a burn of the vault's debt can. No pool can move a user's YED or
  take collateral before the grace period; a pool can create YED only by first moving the mint
  price with a majority of quote-tagged blocks.
- An enforcing node that finds itself on the minority side of a split — a rejected chain that
  outruns its own by six blocks — stops enforcing for the session, rejoins the network's chain,
  raises an alert and waits for its operator; it is never stranded for more than six blocks, and
  it never bans the peers that relayed the other chain, neither for the rejected block nor for
  its descendants. A node that catches up after an outage *usually* does not reject a block the
  network has already built six blocks on: when the network's headers reach it before the block
  does — the ordinary case, since headers lead blocks — it accepts the block, records that it
  did, and keeps enforcing. When the block arrives first it can still reject it, and the work
  valve above is then what bounds the consequence: the node rejoins within six blocks. The valve,
  not catch-up suppression, is the guarantee. Enforcement means "majority in fact", not "majority
  by count".
- Every release enforces only until a sunset height about a year past its start; past it the
  node keeps publishing quotes and accounting but rejects nothing until upgraded, so two
  releases with different rules can never both be enforcing.
- As with any soft fork, every pool — participating or not — should run the module at least in
  filter-only mode, or its blocks can be orphaned by rule-breaking transactions it cannot see.
- Signalling is announced only once the pools running the module are diverse enough that no one
  of them decides alone (at least three independent pools, none above 40 % of quoting blocks,
  measured and published before the announcement).
- If pools stop participating: below 60 % of blocks signalling, minting pauses; below 50 %, block
  rejection pauses as well, and while it is paused neither the owner path nor the claim path is
  policed — collateral can leave a vault without its burn and YED so unbacked stays in
  circulation; vaults untouched during the pause are protected again when it ends. Minting resumes
  at 75 % and rejection at 60 %. Existing YED always remains redeemable by a minter who holds it.
- If the module is abandoned — rejection paused continuously for `ABANDON_BLOCKS` (about 30
  days on mainnet, v3 W21), which is also where a sunset with no successor release ends up —
  every vault's claim path becomes spendable by
  anyone at its claim height: owners must sweep their collateral before that height
  (`yed_sweep`, which every node of every release offers under that one same condition, and
  whose transaction every node then relays and mines like any other) or lose it to whoever
  claims first; the claim path stays open to everyone, so the race is fair, but the YED minted
  against a swept or claimed vault is unbacked from then on. A failed mint's collateral (a VOID
  vault, which never carried a debt) is released by its owner with `yed_redeem` at its lock
  height at any time, abandonment or not.


v2's paragraph "price honesty rests on the honest-majority-hashpower assumption" becomes:

> Prices come from two populations that cannot forge each other: mining pools, weighted by
> blocks, and bonded attestors, weighted by bond and age. A mint is sized at the lower of the
> two; a claim opens at the higher. Moving a price in the direction that pays therefore needs a
> majority of hashpower and a bond-weighted majority of the selected attestors at once. A
> hashpower majority alone keeps exactly the powers it has today — it can halt minting, delay or
> censor transactions, and reorganise the chain — and gains none. A captured attestor set alone
> can halt minting or force an early liquidation at an honest price with the remainder returned
> to the owner; it cannot take collateral. Attestors are not slashed: their penalty is ejection
> and a bond that earns nothing until it unlocks. Attestations travel outside the chain; if that
> transport fails, minting pauses and nothing else changes. Every YEC/USD price is bounded by the
> depth of the markets it is read from.
## Build and test baseline (ycashd 6.20.0)

This is the ycashd 6.20.0 line (`ycash6`, branch `feature/yellowback`). The v4.5.0 line's build notes
live in `ycash-dd`'s copy of this file. What the 6.20.0 pin needed before Yellowback could be measured
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
src/test/test_bitcoin --run_test='yellowback_*'
# one functional script (the 6.20.0 harness reads ZCASHD, not BITCOIND)
ZCASHD="$PWD/src/ycashd" ../.venv/bin/python -u qa/rpc-tests/yellowback_index.py --srcdir="$PWD/src" --tmpdir=/tmp/yb-index --portseed=11
# the audit gates (frozen set and line budgets vs the tag ycash6-baseline)
qa/yellowback-audit.sh
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
`getblocktemplate_longpoll`, are the `STOCK_BASELINE` that CI runs against the fork binary without
`-yellowback`. One operator note follows from finding 7: on 6.20.0, `-lightwalletd` must be run
together with `-insightexplorer`.
