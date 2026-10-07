# Ycash Yellowback (YED) — pool operator runbook

This is what a mining pool runs, watches and does for Ycash Yellowback (YED) on the **vault
upgrade line** (`UPGRADE_VAULT`, docs/plans/yellowback-upgrade-plan.md §5, §15.10). The user guide
is `doc/yellowback.md`; the protocol is `doc/yellowback-spec.md`; the RPC surface is
`doc/yellowback-rpc.md`.

Since the vault upgrade Yellowback's rules are **consensus**: every upgraded node rejects a block
that spends a YED vault against them, from the upgrade height, whoever mined it (U-21). A pool
therefore has nothing to enforce, signal or switch off: pool signalling, lock-in, the work valve,
the kill switch, catch-up suppression, filter-only mode and the sunset of the v2/v3 runbook are
retired (plan §6). What remains for a pool is optional and paid: the **quote tag**.

**This runbook is for ycashd 6.20.0** (the `ycash6` node line, vault upgrade branch). The overlay,
its options, RPCs and procedures are the v4.5.0 line's; what 6.20.0 changes for a pool — the
`getblocktemplate` field names, the template selection and the fee rules (§3.1, §3.2), the wallet
backup (§11) — is marked **[6.20.0]**. Line numbers below are in this tree.

## 1. What a pool does, in one paragraph

Run the release `ycashd` (an upgraded node, as for any Ycash network upgrade) with a payout
address, run the **quote agent** beside it (a small Python process that fetches YEC/USD from
exchanges and pushes one number into the node with `yed_setquote`), and mine as before. While the
node holds a fresh quote it puts a 36-byte **tag** into every coinbase it builds — the quote and
the hash of the payout key — and pools that quote are paid fees by the users who mint, redeem and
claim. A pool that does not quote mines untagged blocks and is still a full participant in
consensus. Watch three RPC fields; act only on the situations in §9.

## 2. Options

`ycash.conf` of the pool's node:

```
yellowbackpayoutaddress=s1…        # where fees arrive; must be a P2PKH (s1…) address of this wallet
```

YED needs no enabling flag: it is on wherever `UPGRADE_VAULT` and the network's YED attestor set
are configured (U-22; regtest: `-nuparams=6d5b7a31:<h> -yellowbackattestorset=<setid>`).

| Option | Default | Meaning |
|---|---|---|
| `-yellowbackpayoutaddress=<s1…>` | `-mineraddress` when that is a transparent P2PKH address | the key the tag names for fees (MINER-2); without one the node emits **no tag** |
| `-yellowbackquotemaxage=<sec>` | `1800` | a stored quote older than this is not put in the tag (the template is then untagged) |
| `-yellowbackpreferredpayee=<s1…>` | unset | the wallet side only: where this node's own mints/redemptions pay their fee when that key is eligible |
| `-reindex-yellowback` | off | wipe and rebuild the index from the blocks on disk |
| `-debug=yellowback` | off | log category |

Retired with the upgrade and **ignored** (logged at start): `-yellowbacksignal`,
`-yellowbackenforce`, `-yellowbacktemplatepolicy`, `-yellowbackrequirehealthy`.
`-yellowbackstartheight` and `-yellowbackenforceuntil` are init errors (finding (31)).

`-prune` is refused while Yellowback is live (the index needs every block on disk). `-datacarrier`
stays at its default (`-datacarrier=0` drops every `OP_RETURN` transaction from the mempool of a
relaying node; the index does not care either way).

**[6.20.0] Stock options a pool now meets.** None needs setting for Yellowback; know what they do:

| Option | Ycash 6.20.0 default | Meaning for a pool |
|---|---|---|
| `-allowdeprecated=<feature>` | every deprecated feature allowed (`src/deprecation.h:47-53`), including `gbt_oldhashes` | `-allowdeprecated=none` removes the three old root keys from `getblocktemplate` (§3.1) — read `defaultroots` and it does not matter |
| `-blockunpaidactionlimit` / `-txunpaidactionlimit` | `SIZE_MAX`: ZIP-317 unpaid-action limits **off** on Ycash (`src/zip317.h:24-54`) | `=0` turns ZIP-317 on for this node's templates / mempool; Yellowback transactions pay the conventional fee (P-2, §3.2), so they are mined either way |
| `-feepolicy=peroutput\|zip317` | `peroutput` | how this node's **wallet** funds a transaction sent with no explicit fee (`src/init.cpp:548`); not relay policy. Yellowback RPCs compute their own fee (§3.2) |
| `-mineraddress` | unset | a Sapling, transparent P2PKH or (6.20.0) Unified Address (`src/init.cpp:1513-1530`); the tag's payout default (`-yellowbackpayoutaddress`) takes it only when it is transparent P2PKH (`src/init.cpp:2198-2203`), otherwise set the payout address explicitly or the node emits no tag |

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

**A verified stack:** `yolo` (`boyfromcave/yolo`, Rust, the rewrite of the Perl
`stratumsolo`/`stratumpool`/`cenote`, one program with `--payout` and `--text` flags) carries
the tag in every flag combination and is exercised on regtest by
`qa/rpc-tests/yellowback_stratum.py` and the devnet's `--stratum` pool seat. The Perl `cenote`
does **not** carry it; see `contrib/yellowback/pool/README.md`, per-stack notes.

**Verify** on a block you mined: `contrib/yellowback/pool/check-coinbase <height>` (add `--
-datadir=…` or any `ycash-cli` option) prints `kind: quote`, the price, the source mask and the
payout key; `ycash-cli yed_gettag <height>` is the node's own reading and must agree.

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
`BlockAssembler::TestForBlock` (`:497`): size, sigops, finality, expiry, then **the vault
primitive's and the YED module's checks against a running copy of the set state**
(`vault::TemplateRun`, `:557-566`) and the Yellowback template filter (`:567`), then the ZIP-209
turnstile check; the finished template is validated by `ConnectBlock` in template mode, which runs
the module's own block check (consensus since the upgrade, §1). Where the checks sit moved from
v4.5.0's `CreateNewBlock` priority loop into `TestForBlock`. Two templates built from the same mempool can
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
`qa/rpc-tests/yellowback_fee.py`). This is the base-layer fee only; the protocol's pool fee
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
**After two consecutive failed aggregates it calls `yed_setquote 0`** so your templates carry no
tag at once (L5) rather than a stale price; it resumes on the next good aggregate. The node's
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
and stops tagging on failure precisely so its quotes never look constant.

## 5. Monitoring

Three things, in order of urgency:

```
ycash-cli yed_getinfo | jq '{healthy, upgrade, miner}'
ycash-cli yed_listminers                       # own accuracy and penalty among the recent quoters
contrib/yellowback/pool/monitor-quote.sh       # exit 0 iff the next tag is a fresh quote and the key is eligible (cron / Nagios / textfile)
```

| Field | Normal | Act when |
|---|---|---|
| `miner.quoteKind` / `quoteAgeSeconds` | `"quote"`, age well under `-yellowbackquotemaxage` | `"none"` for more than a few polls: the agent is down or fails closed (its log says `no aggregate` or `yed_setquote … failed`) |
| `miner.registered` / `miner.eligible` | `true` / `true` once you have quoted in the last 100 blocks | `false` after you have been quoting for a while: your quotes are being dropped or your key is not the one in the tag |
| `healthy` | `true` | never seen `false` for long: a node whose index is unhealthy **stops** (`AbortNode`, finding (32)), because it cannot validate blocks without it; restart with `-reindex-yellowback` |

## 6. Reindexing

A node that must rebuild its chainstate runs a plain `ycashd -reindex`; the Yellowback index is
rebuilt with it, block by block, as part of validation. `-reindex-yellowback` alone rebuilds only
the Yellowback index. There is no enforcement to switch off first and nothing is suppressed in
initial block download: the module's verdict is consensus like every other rule.

## 7.–8. (retired)

The v2/v3 sections *Catch-up suppression* and *The sunset* described node-local enforcement
conjuncts that the vault upgrade removed (plan §6, U-21). A Yellowback rule change is a network
upgrade with a new branch ID, like any other Ycash consensus change (plan §8).

## 9. Incident playbook (skeleton, P14)

The contact list and the on-call owner are filled in before mainnet activation; until then the
pool channel of the Ycash Discord is the contact. **Cadence for every incident that needs code: a
fix release within 7 days; a post-mortem in `doc/yellowback-incidents.md` within 14 days, with the
regtest case that reproduces it added to the suite before the fix release is tagged.**

| | On-call owner | Contact |
|---|---|---|
| Yellowback module | *to be named before mainnet activation* | — |
| Pool A / B / C | *filled in from the launch-bar survey* | — |

**Scenario 1 — the upgraded network disagrees about a block** (a consensus bug in the module or
the primitive). What you see: nodes on one release reject a block that others accept, a fork in
`getchaintips`. What to do: as for any Ycash consensus incident — stay on the release the
coordinator names, post `ycash-cli yed_getblockverdict <hash>` and `yed_getinfo` to the on-call
owner. There is no per-pool switch: the fix is a release.

**Scenario 2 — a wrong-price claim.** What you see: a claimant intent on a vault that is not
underwater at the market. What happens: the YED attestor set cancels it during `CLAIM_DELAY`
(I-2, `vault_buildcancel` + `set_signcancel`); the claimant's burn is forfeited (U-24). Nothing to
do on the pool.

**Scenario 3 — price manipulation** (a pool, or a majority of quote-tagged blocks, moves a median).
What you see: `yed_listminers` shows one payout key with a large share of quote-tagged blocks and a
poor accuracy figure; `yed_getprice` moves against every exchange. What to do: pools compare
`yed_listminers`; the on-call owner asks pools to set `-yellowbackpreferredpayee` away from the
offender. Mints size at the lower of the pool and attestor prices and claims open at the higher,
and the attestor set can cancel a wrong-price claim, so the arithmetic and the cancel bound the
damage; there is no signal to withdraw any more.

## 10. (retired) Filter-only mode

Since the upgrade every node that follows the chain validates the module; a node that does not
run an upgraded release cannot follow the chain past the upgrade height at all (finding (37)).
There is no filter-only mode to choose.

## 11. The payout key and backups

The payout address is a hot-wallet key of the node the pool runs. Fees arrive there as
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
yellowbackpayoutaddress=s1… ; yellowback-quote --conf …
# watch
yed_getinfo (healthy, upgrade, miner.*) ; yed_listminers ; monitor-quote.sh
# verify a block
contrib/yellowback/pool/check-coinbase <height> ; ycash-cli yed_gettag <height>
# rebuild
ycashd -reindex            (-reindex-yellowback for the index alone)
# 6.20.0 templates
getblocktemplate: header roots from defaultroots (blockcommitmentshash fallback pre-Heartwood, gbt_oldhashes allowed); coinbasetxn.foundersreward may be absent
```
