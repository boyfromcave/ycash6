# Running a Yellowback attestor

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

This guide is written from the v3 plan (`docs/plans/yellowback-v3-development-plan.md` §4.7, §5)
and the proposal (`docs/reference/yellowback-price-attestation.md` §4–§6, §12, §13). The RPCs it
names are specified in `doc/yellowback-rpc.md`; the agent's every setting is documented in
`contrib/yellowback/attest/attest.toml.sample` and its README. Ycash Yellowback (YED) is the
system; YED is the unit.

## What you are NOT asked to do

- **No domain, no TLS certificate, no inbound port.** The agent publishes over an `iroh-gossip`
  topic (QUIC with hole punching and relay fallback); nothing listens. The optional HTTPS
  endpoint that subscribers can poll (`[subscribe] endpoints` on *their* side) is a second path
  some attestors may offer; it is not required and this guide does not set one up.
- **No periodic transactions.** Registration is one transaction; withdrawal, a year or more
  later, is one more. Attestations are 74-byte gossip messages, never on chain unless a minter
  or claimant carries them (or someone proves an equivocation with them).
- **No hot wallet beyond the node's own.** The node holds the hot key and signs; the only spend
  it may ever make on your behalf is the rare `yed_revive`, funded from whatever confirmed YEC
  the wallet holds — a few YEC of change is enough. Fees accrue to the bond key, which should be
  cold (below).
- **No mining, no payout address, no `-yellowbackpayout…` flag**, and no pool membership. An
  attestor node is a plain `ycashd -yellowback`.
- **No price of your own.** The agent aggregates public sources; the node never reads a socket
  for Yellowback. You choose sources, you do not type prices (`--mock-price` exists for regtest
  and demos only).

## What an attestor is

An attestor is a party that has posted a **bond** (a long CLTV time-lock back to its own key,
never custody, never burned) and runs the **attestor agent** `yellowback-attest`, which polls price
sources, has the node sign a price every `k` blocks (`10` on mainnet) and gossips the 74-byte
attestation. Minters and claimants carry those attestations into their transactions; the enforcing
nodes verify the signatures, take a bond-weighted quantile and combine it with the mining pools'
medians (`pMint = min`, `pClaim = max`). An attestor is paid for attestations that are **used** in a
confirmed mint or claim (`ATTEST_FEE_BPS` = 25 % of the pool enforcement fee, to `P2PKH(bondPubKey)`),
never for attestations published.

There is no slashing: the penalty for misbehaviour is ejection and a bond that earns nothing until
it unlocks. That is sufficient because attestors can **grief but not extract** — no direction the
price is pushed in pays them (proposal §10.3) — and it is why the bond can be your own coin.

What you need: a v3 `ycashd` with `-yellowback` (no payout address, no mining), outbound
connectivity, a bond of at least `BOND_MIN` (20,000 YEC on mainnet) you can lock for at least
`BOND_MIN_LOCK` blocks (420,480 ≈ one year), and price sources. No inbound port, no domain, no
funded hot wallet beyond the node's own for the rare `yed_revive`.

## Registration

```
ycashd -yellowback                                  # any v3 node; no payout address, no mining
ycash-cli yed_registerattestor 20000 420480 0       # once; then wait BOND_MATURITY
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
from zero) and let the old one go dormant and withdraw at its locktime. **Back up `wallet.dat`
right after registering** — both keys came from the keypool, and a backup taken before the
registration does not contain them (Ycash 4.5 transparent keys are not HD).

Registration is open from `START_HEIGHT`; it never makes a block invalid and needs no miner's
approval (proposal §5.3). Duplicate hot keys are refused (REG-A1) unless the earlier record is
`WITHDRAWN`; an `EJECTED` key is barred for good.

## Bond key hygiene

The registering wallet holds both keys. The hot key must stay in it — `yed_signattestation` uses
it every ten blocks. The bond key is used by exactly one command, `yed_withdrawbond`, a year or
more later; until then it is worth `bondYec` to whoever holds it, and it collects your fees.

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
[subscribe]   listattestors_seconds = 60; endpoints = [...]; endpoints_seconds = 30      subscriber side only
```

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
(systemd; `Restart=always`, `ProtectSystem=strict`, an `/etc/yellowback/attest.toml`), the
subscriber's unit, and `org.ycash.yellowback-attest.plist` for launchd. Start the node first; the
agent retries RPC and transport failures forever and exits non-zero only for a bad configuration.
A regtest walk-through with the `dir` transport is in the crate's README.

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
with `ATTEST_ARM_MIN` (5) `ELIGIBLE` attestors the state becomes `TRIGGERED` with `armHeight =
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

**Seating.** At every snapshot the `N_SLOTS` (9) eligible attestors with the greatest
`weight = bondZat · min(age, AGE_CAP)` are **seated**; a transaction's bundle draws `M_SELECT +
K_SLACK` (4 + 2) of the seated by a hash of the reference block, and at least `M_SELECT` of the
selected must be in it. Being seated, bonded and reachable is what earns; latency does not. An
unseated attestor keeps publishing, keeps its age, and takes the lowest seat when its weight passes
the holder's.

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
terminal for the key and the outpoint. A stolen hot key can only grief (sign wrong prices; it is
bounded like a colluding attestor) or get your seat ejected by equivocating; the bond key is
separate and stays safe if it stayed cold.

## Withdrawal

After `bondLocktime`, `yed_withdrawbond <seq> [to]` spends the bond to any address; the record
becomes `WITHDRAWN` (an ejected record stays `EJECTED`, the spend only recorded). Before
`bondLocktime` the command refuses (`bond-locked`); the coin is time-locked by consensus, not by
the overlay, so nothing shorter exists. The hot key is then free to be discarded; a withdrawn
attestor's hot key may register again.

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
| withdraw the bond | `yed_withdrawbond <seq> [to]` | `bond-locked`, `bond-spent`, `attest-key-not-held` |

Every identifier is defined in `doc/yellowback-rpc.md`. The two calibration measurements that
precede the first mainnet registration (`DIVERGE_BPS_ATTEST`, `PIN_DELTA_BPS`) are the release's
job, not the attestor's: `contrib/yellowback/attest/calibrate/README.md`.
