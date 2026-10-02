# Ycash Yellowback (YED) — pool operator runbook

This is what a mining pool runs, watches and does to take part in Yellowback v2, the
miner-enforced stablecoin overlay on Ycash (the user guide is `doc/yellowback.md`; the protocol is
`doc/yellowback-spec.md`; the RPC surface is `doc/yellowback-rpc.md`). It is written for **every
Ycash pool, participating or not**: a pool that does not want to enforce should still run the
module in *filter-only mode* (below) so that its own blocks cannot be orphaned by a rule-breaking
transaction it cannot otherwise see.

Nothing here changes Ycash consensus. An enforcing pool produces blocks that every stock node
accepts; the only thing it ever refuses is a block that spends a Yellowback vault in a way the
rules forbid, and only after the network has activated the rules by signalling.

**This runbook is for ycashd 6.20.0** (`ycash6`, branch `feature/yellowback`). The overlay, its
options, RPCs and procedures are the v4.5.0 ones; what 6.20.0 changes for a pool — the
`getblocktemplate` field names, the template selection and the fee rules (§3.1, §3.2), how blocks
reach the valve (§6), the wallet backup (§11) — is marked **[6.20.0]**. Line numbers below are in
this tree.

## 1. What a pool does, in one paragraph

Run the release `ycashd` with the module on and a payout address, run the **quote agent** beside
it (a small Python process that fetches YEC/USD from exchanges and pushes one number into the node
with `yed_setquote`), and mine as before. The node puts a 36-byte **tag** into every coinbase it
builds — the quote, a signal bit and the hash of the payout key — and pools that quote are paid
enforcement fees by the users who mint, redeem and claim. Watch four RPC fields; act only on the
three situations in §9.

## 2. Options

`ycash.conf` of the pool's node:

```
experimentalfeatures=1
yellowback=1
yellowbackpayoutaddress=s1…        # where enforcement fees arrive; must be a P2PKH (s1…) address of this wallet
yellowbacksignal=1                 # default on testnet/regtest; default 0 on mainnet until the signalling announcement (L4)
yellowbackenforce=1                # default; set 0 to leave the enforcing set (filter-only mode; restart)
```

| Option | Default | Meaning |
|---|---|---|
| `-yellowback` | off | enable the module (index, tag, template filter, enforcement) |
| `-yellowbackpayoutaddress=<s1…>` | `-mineraddress` when that is a transparent P2PKH address | the key the tag names for enforcement fees (MINER-2); without one the node emits **no tag of either kind** |
| `-yellowbacksignal` | testnet/regtest `1`, **mainnet `0`** | set the activation signal bit in the tag; effective only with `-yellowbackenforce=1` |
| `-yellowbackenforce` | `1` | reject rule-breaking blocks once active; `0` is the **kill switch** / filter-only mode |
| `-yellowbackquotemaxage=<sec>` | `1800` | a stored quote older than this is not put in the tag (the tag is then signal-only) |
| `-yellowbacktemplatepolicy=strict\|consensus` | `strict` | what the template filter drops (TPL-1..3) |
| `-yellowbackrequirehealthy` | `0` | refuse `getblocktemplate` while the index is unhealthy (K24); default: mine an untagged, unpoliced template instead |
| `-yellowbackpreferredpayee=<s1…>` | unset | the wallet side only: where this node's own mints/redemptions pay their fee when that key is eligible |
| `-reindex-yellowback` | off | wipe and rebuild the index from the blocks on disk; clears the rejected-block memory |
| `-debug=yellowback` | off | log category |

**[6.20.0] Stock options a pool now meets.** None needs setting for Yellowback; know what they do:

| Option | Ycash 6.20.0 default | Meaning for a pool |
|---|---|---|
| `-allowdeprecated=<feature>` | every deprecated feature allowed (`src/deprecation.h:47-53`), including `gbt_oldhashes` | `-allowdeprecated=none` removes the three old root keys from `getblocktemplate` (§3.1) — read `defaultroots` and it does not matter |
| `-blockunpaidactionlimit` / `-txunpaidactionlimit` | `SIZE_MAX`: ZIP-317 unpaid-action limits **off** on Ycash (`src/zip317.h:24-54`) | `=0` turns ZIP-317 on for this node's templates / mempool; Yellowback transactions pay the conventional fee (P-2, §3.2), so they are mined either way |
| `-feepolicy=peroutput\|zip317` | `peroutput` | how this node's **wallet** funds a transaction sent with no explicit fee (`src/init.cpp:548`); not relay policy. Yellowback RPCs compute their own fee (§3.2) |
| `-mineraddress` | unset | a Sapling, transparent P2PKH or (6.20.0) Unified Address (`src/init.cpp:1513-1530`); the tag's payout default (`-yellowbackpayoutaddress`) takes it only when it is transparent P2PKH (`src/init.cpp:2198-2203`), otherwise set the payout address explicitly or the node emits no tag |

`-prune` is refused with the module on (the index needs every block on disk). `-datacarrier` stays
at its default (`-datacarrier=0` drops every `OP_RETURN` transaction from the mempool of a relaying
node; the index does not care either way).

**The mainnet signal default (L4).** The first mainnet release *quotes but does not signal*:
`yellowbacksignal` defaults to `0` on mainnet. Pools that install it publish quote tags, earn
nothing yet and change nothing yet. Signalling is announced only once the pools running the module
are diverse enough that no one of them decides alone — at least three independent pools, none above
40 % of quote-tagged blocks over a full 2,016-block window, measured with `yed_listminers <height>
2016` and published with the announcement. After the announcement each pool sets
`yellowbacksignal=1` and restarts; lock-in and activation are then automatic (75 % of a 2,016-block
window signalling → lock-in; active one window later). Do not set `yellowbacksignal=1` on mainnet
before the announcement.

## 3. The coinbase tag and your stack

The node keeps the current tag in the coinbase flags every template carries, so:

| Your stack | What to do |
|---|---|
| internal miner / solo `generate` | nothing |
| `getblocktemplate` and you use `coinbasetxn` as your coinbase | nothing: the tag is already in `coinbasetxn.data` |
| `getblocktemplate` and you assemble your own coinbase | append the bytes of `coinbaseaux.flags` **verbatim** (they begin with the `0x24` push opcode) after the BIP34 height push and before your extranonce and text; keep your own text ≤ ~55 bytes so the scriptSig stays ≤ 100 bytes |
| a stratum layer that honours neither | use the per-stack note in `contrib/yellowback/pool/README.md`, or switch to the `coinbasetxn` path |

Refresh the template every block: the tag's price changes as the agent publishes. (The node
caches a template for up to 5 s and rebuilds it on a new tip or a mempool change, not on a new
quote, so the first template after a quote update can still carry the previous price — at most
one block's worth.)

### 3.1 [6.20.0] `getblocktemplate` field names

6.20.0 renames the block-header roots and trims the founders' fields. What changed against v4.5.0
(the full emitter is `src/rpc/mining.cpp:733-840`):

| Key | v4.5.0 | 6.20.0 | Read it as |
|---|---|---|---|
| `defaultroots` | absent | **new** object: `merkleroot`, `chainhistoryroot`, and from NU5 `authdataroot`, `blockcommitmentshash` (`:808-820`) | the upstream-recommended source; valid only for the template used unmodified (help text `:449-452`). Recompute `merkleroot` once you change the coinbase: it commits to *this* node's coinbase and its tag. NU5 is not active on Ycash, so expect `merkleroot` and `chainhistoryroot` only |
| `blockcommitmentshash`, `lightclientroothash`, `finalsaplingroothash` (top level) | `lightclientroothash`, `finalsaplingroothash` | all three, one value (the header's `hashBlockCommitments`), **emitted only while the `gbt_oldhashes` deprecation is allowed** (`:802-807`, flag `src/deprecation.cpp:14`) — the Ycash default (`src/deprecation.h:47-53`) | deprecated, still "put this in the header" semantics; gone under `-allowdeprecated=none` and in some future release |

**Which value goes in the header's commitments field** (`src/miner.cpp:434-470`): from Heartwood
(active on Ycash mainnet since height 1,100,003 and testnet since 661,622,
`src/chainparams.cpp:136,431`) until NU5 it is `defaultroots.chainhistoryroot`; at the
Heartwood activation block it is null; under NU5 it is `defaultroots.blockcommitmentshash`. **Before
Heartwood — the regtest the functional suite and the devnet run (Overwinter + Sapling only) — it
is the final Sapling root, which only the deprecated top-level keys carry** (`chainhistoryroot` is
null there). So: read `defaultroots`, take the header value by the rule above, and fall back to
`blockcommitmentshash` when the network is pre-Heartwood; keep `gbt_oldhashes` allowed (the
default) on any node a pre-Heartwood pool reads. Software written against v4.5.0's
`finalsaplingroothash` keeps working while the deprecation is allowed.

| Key | v4.5.0 | 6.20.0 | Read it as |
|---|---|---|---|
| `coinbasetxn.foundersreward` | always (0 when the coinbase has one output) | only before the Ycash upgrade within the founders' period (subsidy/5) or during the YDF mandate (subsidy/20) (`:766-776`) | `get()`, never index it |
| `coinbasetxn.ydfpercentage`, `coinbasetxn.foundersaddress` | always | **gone** | the post-mandate YDF share is still `-ydf=<n>` (`src/init.cpp:562`) and is already inside `coinbasetxn.data`; `getblocksubsidy <height>` reports the amounts (`miner`, `founders`, `totalblocksubsidy`) |
| `coinbasetxn.required` | `height < YDF mandate end` | **always `true`** (`:777`) | a pool that builds its own coinbase must still pay the YDF output while the mandate runs — consensus enforces it |
| `coinbaseaux.flags` | with `-yellowback` only on the `coinbasetxn` path | unchanged (`:822-829`) | the tag bytes (§3 table) |
| `mutable` | gains `coinbase/append` with `-yellowback` | unchanged (`:795`) | |
| `yellowback` | overlay summary with `-yellowback` | unchanged (`:840`) | |
| template cache | rebuilt on a new tip, a long-poll, or a mempool change after 5 s | unchanged (`:686-687`) | the quote-lag note above still holds |

Each transaction entry also carries `authdigest` (`:751`), used only for NU5's auth-data root; a
Ycash pool can ignore it. Nothing about the tag changes: it is still `coinbaseaux.flags` and the start of
`coinbasetxn.data`'s scriptSig.

### 3.2 [6.20.0] Which transactions your template carries, and the fees they pay

**Selection.** v4.5.0 filled a template by priority, then fee rate. 6.20.0 fills it by ZIP-317
weighted random sampling in two tiers — transactions paying at least the conventional fee first,
then the rest — each sampled by weight ratio (`BlockAssembler::constructZIP317BlockTemplate` /
`addTransactions`, `src/miner.cpp:614-690`). Every candidate goes through
`BlockAssembler::TestForBlock` (`:497`): size, sigops, finality, expiry, then **the Yellowback
template filter (TPL-1/2) at `:545-546`**, then the ZIP-209 turnstile check; the finished template
is validated by `ConnectBlock` in template mode, which runs the module's own block check. The
filter's behaviour (strict / consensus, §2) is unchanged; only where it sits moved, from
`CreateNewBlock`'s priority loop into `TestForBlock`. Two templates built from the same mempool can
now differ in order and, near a full block, in content — expected, not a fault.

**Fees.** Two rules apply at mempool admission, both relay policy, not consensus:

- **The Ycash per-Sapling-output floor** (`PerSaplingOutputFees`, `src/policy/policy.cpp:16-37`;
  applied `src/main.cpp:1958-1970`): a transaction with Sapling outputs pays at least 1000 zat
  (`DEFAULT_PER_SAPLING_OUTPUT_FEE`) when it has up to 50 (`DEFAULT_EXEMPT_SAPLING_OUTPUTS`,
  `src/policy/policy.h:22-23`), else 1000 zat per output beyond 50; refused as
  `insufficient per-Sapling-output fee` otherwise. Note that 6.20.0's Sapling builder pads every
  bundle to two outputs, so a "one-output" shielded transaction has two.
- **ZIP-317 unpaid actions** (`src/main.cpp:1972-1985`): off by default on Ycash (limits at
  `SIZE_MAX`, §2) but the conventional fee still decides the template tier above.

**The Yellowback network fee (P-2).** Every transaction the module builds pays
`max(-yellowbackfee, ZIP-317 conventional fee)` (`NetworkFee`, `src/yellowback/txbuilder.cpp:185-192`;
`-yellowbackfee` ≥ 1000 zat), computed from the built transaction with the Sapling padding counted.
So Yellowback mints, transfers, redemptions and carriers land in the **conventional-fee tier** and
survive `-blockunpaidactionlimit=0` / `-txunpaidactionlimit=0` (proven by
`qa/rpc-tests/yellowback_fee.py`). This is the base-layer fee only; the protocol's enforcement fee
to the payee pool (FEE_MIN 0.5 YEC) is unchanged. A zero-fee transaction is refused at admission
(`min relay fee not met`, `src/main.cpp:1955`).

**A verified stack:** `yolo` (`boyfromcave/yolo`, Rust, the rewrite of the Perl
`stratumsolo`/`stratumpool`/`cenote`, one program with `--payout` and `--text` flags) carries
the tag in every flag combination and is exercised on regtest by
`qa/rpc-tests/yellowback_stratum.py` and the devnet's `--stratum` pool seat. The Perl `cenote`
does **not** carry it; see `contrib/yellowback/pool/README.md`, per-stack notes.

**Verify** on a block you mined: `contrib/yellowback/pool/check-coinbase <height>` (add `--
-datadir=…` or any `ycash-cli` option) prints `kind: quote`, the price, the source mask and the
payout key; `ycash-cli yed_gettag <height>` is the node's own reading and must agree.

## 4. The quote agent

`contrib/yellowback/yellowback-quote` (Python ≥ 3.11, standard library only; nothing inbound: no
listening socket, no TLS server).

```
cp contrib/yellowback/pool/yellowback-quote.toml.sample /etc/yellowback-quote.toml   # edit [node] and [[sources]]
chmod 600 /etc/yellowback-quote.toml                                                 # it may hold the node's RPC password
yellowback-quote sources --conf /etc/yellowback-quote.toml                           # what every source resolves to right now
yellowback-quote --conf /etc/yellowback-quote.toml                                   # the daemon (systemd / launchd units in contrib/yellowback/pool/)
```

The sample authenticates with the node's cookie file (`rpc_cookie`, re-read on every call), which
keeps the secret out of this file. With `rpc_user`/`rpc_password` instead, the file must be mode
0600 — the agent refuses a group- or world-readable one (`--insecure-config-permissions`
overrides) — and the agent refuses to send those credentials as cleartext Basic auth over plain
`http://` to any host but loopback (run it beside the node, tunnel to `127.0.0.1`, or use
`https://`; `allow_insecure_rpc = true` insists). `--mock-price` is for regtest: on any other
network the agent exits 2 unless `--i-know-this-is-not-regtest` is given.

Every `poll_seconds` (30) it fetches the configured sources, takes each source's 15-minute
volume-weighted (or time-weighted) average, drops outliers, requires `min_sources` live sources
from `min_venues` venues, and calls `yed_setquote <priceMicroUsd> <sourceMask>` on your node.
**After two consecutive failed aggregates it calls `yed_setquote 0`** so your tags go signal-only
at once (L5) rather than carrying a stale price; it resumes on the next good aggregate. The node's
own `-yellowbackquotemaxage` clock (30 minutes) is the backstop for a dead agent. An RPC failure
(node down, wrong password, index unhealthy) is logged and retried on the next poll; the daemon
never exits for it. Exit codes: `0`, `1` nothing published (`--once`, for cron), `2` bad
configuration.

The `sourceMask` bits are informational (bit 0 SafeTrade, 1 CoinGecko, 2 CoinMarketCap, 3 Nonkyc;
4–15 unassigned). A pool whose quotes stray from its peers' loses the default fee income: wallets
pick a payee among the pools that quoted recently, weighted against those whose quotes were far
from the medians.

**Your quote agent must actually track the market (PIN-1, v3).** Once attestors are armed, the
node compares the attested prices confirmed in bundles over the last `PIN_WINDOW` blocks; when
they moved by more than `PIN_DELTA_BPS` (5 %) between the lowest and the highest bundle in that
window, every pool key whose tags in the window all carry **one constant price** (at least
`PIN_MIN_TAGS` of them) is treated as pinned and drops out of the cross-section medians for that
height. A hard-coded or long-stale quote therefore stops counting exactly when the market moves —
the moment it matters — and a pinned pool's tags contribute no price until its quotes move again.
This is a property of the quote, not of the agent: `yellowback-quote` publishes the live aggregate
and goes signal-only on failure precisely so its quotes never look constant.

## 5. Monitoring

Four things, in order of urgency:

```
ycash-cli yed_getinfo | jq '{healthy, enforcing, valveTripped, sunset, rejectedBlocks, suppressedBlocks, miner}'
ycash-cli yed_listminers                       # own accuracy and penalty among the recent quoters
ycash-cli yed_getactivation                    # signaling / locked_in / active, signalCount of 2016
contrib/yellowback/pool/monitor-quote.sh       # exit 0 iff the next tag is a fresh quote and the key is eligible (cron / Nagios / textfile)
```

| Field | Normal | Act when |
|---|---|---|
| `miner.quoteKind` / `quoteAgeSeconds` | `"quote"`, age well under `-yellowbackquotemaxage` | `"signal"` for more than a few polls: the agent is down or fails closed (its log says `no aggregate` or `yed_setquote … failed`) |
| `miner.registered` / `miner.eligible` | `true` / `true` once you have quoted in the last 100 blocks | `false` after you have been quoting for a while: your quotes are being dropped or your key is not the one in the tag |
| `healthy` | `true` | `false`: the index is broken — the node keeps mining **unpoliced, untagged** templates unless `-yellowbackrequirehealthy`; restart with `-reindex-yellowback` |
| `rejectedBlocks` | `0`, or a count the network agrees with | rising while the network does **not** follow this node: §9 scenario 1 |
| `suppressedBlocks` | `0` | see §7: worth a look, no action |
| `valveTripped` | `false` | `true`: §6 |
| `sunset` | `false` | `true`: upgrade (§8) |

`getinfo.errors` carries the valve's warning; `-alertnotify` receives it too.

## 6. The kill switch, the work valve and the `-reindex` procedure

**Kill switch.** `yellowbackenforce=0` and restart. The node keeps tagging (with the signal bit
cleared), keeps its index, keeps filtering its own templates, and rejects nothing. At start it
reconsiders every block it had rejected and clears that memory, so it rejoins the network's chain on
its own. This is also *filter-only mode* (§10). Nothing else is needed to leave the enforcing set.
**[6.20.0]** A rejected block now keeps its block-index entry across a clean restart (6.20.0's
`RewindBlockIndex` keeps never-connected entries, upstream Ycash commit `1770fce16`), so the start-up
log shows the reconsider branch for it; on v4.5.0 the entry was gone and the log said it was skipped.
Both are the kill switch working.

**The work valve (L7, P1).** An enforcing node that rejects a block the rest of the network
accepts would, left alone, stay on its own shorter chain. It does not: once the chain rooted at a
block this node rejected has **six blocks** more work than the node's own tip, the valve trips. The
node turns enforcement off for the session, reconsiders the rejected blocks, reorganises onto the
heavier chain at the next block the network announces, drops the signal bit from its tags, and
raises

```
Yellowback: work valve tripped at height H (rejected root …); enforcement off until restart
```

through `-alertnotify` and `getinfo.errors`; `yed_getinfo.enforcing` is `false` and
`valveTripped` is `true`. (The stock "invalid chain at least ~6 blocks longer" warning does **not**
fire here: it counts only blocks the node stored, and descendants of a rejected block are refused as
headers.) The node is never stranded for more than six blocks and never bans the peers that relayed
the other chain, neither for the rejected block nor for its descendants.

**[6.20.0] How the valve sees the other chain.** v4.5.0 fetched an announced block directly, so
every block of the other chain reached the valve's counter. 6.20.0 downloads blocks only through
the header index (an `inv` only triggers a `getheaders`), and its `headers` handler stops reading a
message at the first header it refuses. This release therefore reads on past the headers it refuses
for Yellowback reasons — the rejected block and its descendants — while the valve is untripped
(`src/main.cpp:8621-8636`), so every header of the other chain is counted and the valve trips as on
v4.5.0, including after a restart with the rejection still live. After the trip the stock handling
applies. One limit, the same as on v4.5.0: the counter notes at most 64 headers per rejected root
(`VALVE_NOTE_CAP`, `src/yellowback/index.h:65`), and a refused run longer than that in one message can
draw the stock `prev block not found` misbehaviour score (10, `src/main.cpp:5980`) against the
relaying peer, far below the ban threshold (the valve needs about six blocks' work, not 64 headers).

The operator's job after a trip is to find out *why the network did not follow*: `ycash-cli
yed_getblockverdict <hash>` for the rejected root explains the verdict; the causes are a bug in this
release, a stale release on this node, or a real enforcing minority (the network's majority does not
run the module). Report it (§9 scenario 1). **Only a restart re-arms the valve**; restart with
`yellowbackenforce=0` until the cause is understood.

**The `-reindex` procedure (M12, N2).** A node that must rebuild its chainstate — or that is more
than 99 blocks behind and cannot reorganise (`MAX_REORG_LENGTH`) — runs a plain

```
ycashd -reindex
```

This is safe with enforcement on: the module never rejects a block while the node is in initial
block download, reindexing or importing; it evaluates every block and rebuilds its index, and only
the rejection is suppressed. Belt and braces: `-reindex -yellowbackenforce=0`, then remove the flag
and restart once caught up. `-reindex-yellowback` alone rebuilds only the Yellowback index (the
chainstate stays) and clears the rejected-block memory.

A node restarted after more than a day offline is in initial block download until its tip is a day
old and rejects nothing until then.

## 7. Catch-up suppression and `suppressedBlocks` (L11)

A node that fell behind by less than a day — a partition, a restart after two hours offline — is
*not* in initial block download and evaluates the network's blocks as it catches up. It never
rejects a block the network has already built six blocks on: it accepts it, logs

```
yellowback: catch-up: accepted rule-breaking block … (network N blocks ahead)
```

and counts it in `yed_getinfo.suppressedBlocks`, with enforcement still on and no trip. A non-zero
count means the network accepted a rule-breaking block while this node was away — each one is a
vault whose collateral left without its burn, and the YED minted against it is now unbacked. It is
worth a look at `yed_getblockverdict` and worth reporting (the 90-day review collects them); it
needs no action on this node. A rejection still happens when the network is fewer than six blocks
ahead; the valve then trips within one block if the network keeps building on the rejected block.

## 8. The sunset (L8)

Every release enforces only until an `ENFORCE_UNTIL_HEIGHT` about a year past its parameter set's
start height, and never past the next known Ycash network-upgrade height. Past it the node keeps
tagging and accounting but **rejects nothing** until upgraded: `yed_getinfo.sunset == true`,
`enforcing == false`, the signal bit is dropped and the log says `upgrade required`. Two releases
with different rules can therefore never both be enforcing. Expect a fork release within 14 days of
every Ycash release; install it before the sunset height, which `yed_getinfo.params.enforceUntilHeight`
reports.

## 9. Incident playbook (skeleton, P14)

The contact list and the on-call owner are filled in before the signalling announcement; until
then the pool channel of the Ycash Discord is the contact. **Cadence for every incident that needs
code: a fix release within 7 days; a post-mortem in `doc/yellowback-incidents.md` within 14 days,
with the regtest case that reproduces it added to the suite before the fix release is tagged.**

| | On-call owner | Contact |
|---|---|---|
| Yellowback module | *to be named before the signalling announcement* | — |
| Pool A / B / C | *filled in from the launch-bar survey* | — |

**Scenario 1 — an enforcing node rejects a block the network accepts** (a rule bug, a stale
release, a real enforcing minority). What you see: `rejectedBlocks` rising, then the valve warning
`Yellowback: work valve tripped …` and `valveTripped == true`. What happens on its own: the valve
rejoins the network's chain within six blocks. What to do: restart with `yellowbackenforce=0`, post
`ycash-cli yed_getblockverdict <rejected root>` and `yed_getinfo` to the on-call owner. The owner
asks every pool to set `yellowbackenforce=0` and restart until the cause is known, publishes the
verdict, and ships a fix release (or a parameter set with a new start height) within 7 days;
signalling stays off until the fix has run on testnet through the D2 and D12 drills again.

**Scenario 2 — a rule-breaking spend is accepted by the enforcing set** (an under-rejection bug).
What you see: nothing forks; `suppressedBlocks` may rise on nodes that were away; users' wallets show
the affected vault as `unbacked`. What to do: nothing on the pool; report it. The fix release follows
the 7-day path; the trust statement's "unbacked" wording already covers the outcome.

**Scenario 3 — price manipulation** (a pool, or a majority of quote-tagged blocks, moves a median).
What you see: `yed_listminers` shows one payout key with a large share of quote-tagged blocks and a
poor accuracy figure; `yed_getprice` moves against every exchange. What to do: pools compare
`yed_listminers`; the on-call owner asks pools to set `-yellowbackpreferredpayee` away from the
offender and — if the claim price moved — to halt signalling (`yellowbacksignal=0`, restart) so
that minting pauses (below 60 % signalling) while the windows roll; no code change. The arithmetic
bounds the damage: a median moves only as far as the middle quote of the window.

## 10. Filter-only mode for pools that do not participate (N3)

Run the module with `yellowbackenforce=0` and no payout address:

```
experimentalfeatures=1
yellowback=1
yellowbackenforce=0
```

The node emits no tag, signals nothing, rejects nothing, and only **filters its own templates**:
it never includes a transaction that the enforcing pools would reject. That is the zero-risk option
and it protects you. As with any soft fork, a pool that ignores the rules entirely can have its
blocks orphaned by a rule-breaking transaction it cannot see: an attacker mints the smallest vault,
waits for its lock height, and broadcasts an owner-path spend without a burn to stock nodes only;
every stock pool that includes it has its block orphaned by the enforcing majority, the transaction
is valid at the base layer, so it comes back in the next block, and it costs the attacker nothing
after the first mint. Filter-only mode closes that at no risk to you.

## 11. The payout key and backups

The payout address is a hot-wallet key of the node the pool runs. Enforcement fees arrive there as
ordinary transparent YEC outputs; nothing about the module is stored in the wallet. **Back up that
node's `wallet.dat` like any other hot wallet**, and back it up again after `importprivkey` or a
new keypool. **[6.20.0]** The wallet also carries an emergency recovery phrase
(`ycashd-wallet-tool`); Ycash leaves `-walletrequirebackup` off on every network
(`src/chainparams.h:200-211`), so the node issues addresses without the phrase being confirmed — back
up `wallet.dat` regardless, because a payout key imported with `importprivkey` is not recoverable from
the phrase (`getwalletinfo.has_external_imports`). Losing the key loses the fees paid to it; it changes nothing for the users who paid
them (an unspendable payout key only sends the payer's fee to nobody). A pool may quote from many
keys; the launch bar counts operators, not keys.

## 12. Quick reference

```
# start
experimentalfeatures=1 yellowback=1 yellowbackpayoutaddress=s1… yellowbacksignal=<per §2> ; yellowback-quote --conf …
# watch
yed_getinfo (healthy, enforcing, valveTripped, sunset, rejectedBlocks, suppressedBlocks, miner.*) ; yed_listminers ; yed_getactivation ; monitor-quote.sh
# 6.20.0 templates
getblocktemplate: header roots from defaultroots (blockcommitmentshash fallback pre-Heartwood, gbt_oldhashes allowed); coinbasetxn.foundersreward may be absent
# verify a block
contrib/yellowback/pool/check-coinbase <height> ; ycash-cli yed_gettag <height>
# leave the enforcing set / filter-only
yellowbackenforce=0 and restart
# rebuild
ycashd -reindex            (safe with enforcement on; -reindex-yellowback for the index alone)
# the valve tripped
yed_getblockverdict <rejected root> ; restart with yellowbackenforce=0 ; report (section 9, scenario 1)
```
