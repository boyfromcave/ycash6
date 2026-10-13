# yellowback-attest

The Ycash Yellowback attestor agent (plan §5, W13; proposal §4, §13): one Rust binary, two
long-running modes, beside a `ycashd -yellowback`.

| Mode | Runs beside | Loop |
|---|---|---|
| `attest` | an attestor's node (registered with `yed_registerattestor`: since P4-b a SET_JOIN to the attestor set, the vault primitive's signer set) | poll `yed_getinfo` every 15 s; every `every_blocks` new blocks aggregate the price sources, ask the node to sign with `yed_signattestation <seq> <priceMicroUsd> <tip − ref_lag>`, publish the returned 74-byte attestation on the topic; every `heartbeat_blocks` blocks send `set_heartbeat <attestorSetId> <memberKey>` (an attestor without an act inside the set's `livenesswindow` is DORMANT, and signing is not an act); with `[cancel]` (on by default) also the cancel automation: judge every confirmed YED claim, co-sign and gossip the wrong-price ones, drive the cancel in turn ("Cancel automation" below) |
| `subscribe` | any minting node (the devnet's node 0; YecWallet's bundled node) | join the topic; drop anything that is not 74 bytes, whose `seq` is not in `yed_listattestors` (refreshed every 60 s), that was already handed to the node (LRU of 4,096 frames), whose `citedHeight` is outside `[tip − 64, tip + 8]` of the node, or that exceeds the `seq`'s token bucket (`seq_burst`, `seq_refill_seconds`); push the rest with `yed_addattestation`; count acceptances; back off 1..60 s while the RPC is down; optionally poll `[subscribe] endpoints` over HTTPS as a second path |

Plus three one-shot commands: `sources` (fetch every source once and show what resolved),
`check-config`, and `cosign <txid:n> [--price µUSD]` (the cancel-limit design, CAN-2 + C4b: the node co-signs the cancel
of a YED claimant intent with this seq's member key, `yed_signcancelcosign`; the co-signature is also this attestor's
price statement at the claim's reference height, which EQV-1 slashes if it contradicts the attestation the key signed
there, so the node's equivocation guard states the price it already signed for that height, and only when it signed
none does the agent state its aggregate now; prints the 69-byte hex that `yed_buildcancel` takes).
**The cancel-limit brake is automated** (owner 2026-10-13, the design's §5 client impact): `attest` also runs the
watcher, the co-signature gossip and the collector of "Cancel automation" below, with no operator. `cosign` stays for an
operator who wants to act by hand.

**The agent never holds a key.** Signing happens inside the node, whose equivocation guard
(`attest-signed.dat`, plan §4.5 S16) makes two prices for one height impossible from one node.
Running two agents against two nodes with one hot key is the operator's error; do not.

**Failure behaviour** (the quote agent's, plan L5): an RPC or transport failure is logged at
`error` and retried on the next tick, never fatal; after `fail_polls` consecutive failed
aggregates at a due tick nothing is published until a good one — a missing attestation is the
correct report of a broken feed. The exit code is non-zero only for a bad configuration (2):
unknown keys, a file holding `rpc_password` that is group/world-readable (unless
`--insecure-config-permissions`), credentials over plain `http://` to a host other than loopback
(unless `allow_insecure_rpc = true`), an `http://` endpoint off loopback (unless
`allow_insecure_endpoints = true`), or `--mock-price` on a network other than regtest (unless
`--i-know-this-is-not-regtest`).

**What the agent refuses from the network.** Venue replies are fetched with no redirects (a 3xx
would carry an API key to another host), a total deadline per request, and a 1 MiB body cap;
`"inf"`/`"nan"` strings and bare `Infinity`/`NaN` literals are shape errors, never samples;
`median` is total-order. The node's replies are capped at 64 MiB.

## Layout

```
attest/
├── Cargo.toml, Cargo.lock      exact `=` pins; build with --locked
├── rust-toolchain.toml         stable 1.91.0 (see "Toolchain" below)
├── attest.toml.sample          every setting, documented
├── rustfmt.toml, .gitignore
├── src/
│   ├── main.rs                 clap: attest | subscribe | sources | check-config | cosign
│   ├── config.rs               attest.toml → Config (bad config = exit 2)
│   ├── rpc.rs                  JSON-RPC 1.0 client (cookie or user/password), + a mock server for tests
│   ├── price.rs                the aggregator: port of contrib/yellowback/yellowback_price.py
│   ├── framing.rs              the 74-byte attestation (seq u16 ‖ price u32 ‖ citedHeight u32 ‖ sig 64, LE)
│   ├── attest.rs               the attest loop, `sources` and `cosign`
│   ├── cancel.rs               the cancel automation: watcher, gossip filter, collector, persisted state
│   ├── cosig.rs                the cancel co-signature: message, key recovery (k256), 115-byte gossip frame
│   ├── subscribe.rs            the subscribe loop
│   ├── transport/{mod,dir,iroh}.rs   the Transport trait and its two implementations
│   ├── fixtures.rs             the Rust side of the Rust/Python cross-check
│   └── tls.rs                  installs the one rustls provider (ring) shared with iroh
├── fixtures/                   recorded exchange replies, scenarios.json, expected.json, expected.py
└── packaging/                  systemd units (attest, subscribe) and a launchd plist
```

## Transports

- **`iroh`** (default, production): one `iroh-gossip` topic, id = SHA-256 of
  `"yellowback/attest/<network>/3"` (`network` from `yed_getinfo`). QUIC with hole punching and
  relay fallback, so an attestor behind NAT reaches subscribers with no inbound port. `relays`
  is configurable and never compiled in (empty = iroh's default set, `["none"]` = direct only).
  `iroh-gossip` has no topic discovery: the swarm is bootstrapped from `[transport] peers`
  (endpoint ids other operators publish); the agent prints its own id at startup, and
  `secret_key_file` keeps it stable (created 0600, never over an existing file). The endpoint's
  address is published through iroh's default DNS/pkarr lookup so an id alone is dialable. With
  `relays = []` the public n0 relays see this agent's IP and endpoint id (not its content, which
  is signed); own relays or `["none"]` avoid that.
- **`dir`** (tests, devnet, and any two processes on one machine): a shared directory. A publish
  writes `<path>/<seq>-<citedHeight>.att` through a temp file and one rename; a subscriber
  polls every 2 s and delivers each file once. No relay, no network.
- **The cancel topic.** `attest` with `[cancel] enabled` (the default) opens a second topic on the same transport:
  `"yellowback/cancel/<network>/1"` on the same iroh endpoint and `peers` (`<topic_override>/cancel` when the
  attestation topic is overridden), or `<path>/cancel/` with digest file names on `dir`. It carries 115-byte frames,
  nothing else (see below).

## The aggregator and the cross-check

`price.rs` keeps `yellowback_price.py`'s presets (`coingecko_simple`, `coingecko_ticker`,
`nonkyc_market`, `peatio_ticker`, `kraken_ticker`, `coinbase_ticker`, `generic`), its guards
(`max_age`, `max_spread_bps`, `reject_paths`, BTC-pair conversion with the median of
`[[btc_usd_sources]]`, silence drop, outlier filter, `min_sources`/`min_venues`) and its window
(15-minute VWAP where the venue reports volume, TWAP otherwise). The floating-point operations
run in the Python order so the rounded µUSD agree exactly.

`fixtures/` holds exchange replies recorded on 2026-09-13 (SafeTrade's own ticker answers curl
with 403 behind Cloudflare, so `peatio.json` is hand-written from the Python tests' 2026-09-05
capture). `scenarios.json` describes three source sets over them; `expected.py` runs the Python
aggregator on them and writes `expected.json`; the Rust test `fixtures::tests` and
`test_yellowback_price.py::FixtureCrossCheck` both assert that file. **When they disagree the
Python behaviour is the reference** and the Rust port gets fixed. Regenerate after editing the
scenarios: `../../../../.venv/bin/python fixtures/expected.py && cargo test --locked fixtures`
(the CI job does the same and fails on a diff).

## Toolchain, and why it is separate from `depends`

`.cargo/config.toml` re-points crates.io at the real index because a built node checkout carries an untracked `.cargo/config` (v4.5.0; `.cargo/config.toml` on 6.20.0) that redirects it to the depends vendored directory (a worktree without a depends build does not, which is why the crate builds there without it). `rust-toolchain.toml` pins stable **1.91.0**; `cargo` run from this directory picks it up (the
machine's default cargo may be older). The node's `depends/` builds with Rust 1.63 and a vendored
crate set; `iroh` needs far newer. This crate never enters that build — no `cargo vendor`,
nothing from the node's `Cargo.toml` — and its CI job is its own (`agent` in
`.github/workflows/yellowback-tests.yml`). Bumping the pin is a PR like any dependency.

```
cd contrib/yellowback/attest
cargo build --locked --release          # target/release/yellowback-attest
cargo test --locked                     # unit tests incl. the in-process RPC mock and a local iroh round trip
cargo clippy --locked --all-targets -- -D warnings
```

## Running against the regtest devnet with `dir`

The devnet (`contrib/yellowback/devnet/yellowback-devnet`) grows the attestor nodes and the
three agents in Phase A4's devnet chunk; by hand today, with a devnet or any regtest node:

```
# 1. an attestor node: register once, mine through BOND_MATURITY, read the seq
ycash-cli -regtest yed_registerattestor 10 200
ycash-cli -regtest yed_listattestors            # -> seq

# 2. attest.toml for that node (cookie at <datadir>/regtest/.cookie), transport dir
[node]      rpc_url = "http://127.0.0.1:<rpcport>", rpc_cookie = "<datadir>/regtest/.cookie"
[attest]    seq = <seq>, every_blocks = 4
[transport] kind = "dir", path = "/tmp/yb-devnet/attest-bus"

# 3. one attest per attestor node, with a fixed or file-driven price (no exchanges on regtest)
echo 0.50 > /tmp/yb-devnet/price-1
yellowback-attest attest --conf attest-1.toml --mock-price /tmp/yb-devnet/price-1

# 4. one subscribe beside node 0 (same [transport] table, node 0's [node])
yellowback-attest subscribe --conf subscribe-0.toml
ycash-cli -regtest yed_getattestations           # the pool fills as blocks are mined
```

`--mock-price FILE` is re-read every poll, so `echo 0.60 > price-1` is the divergence demo.

## Cancel automation (the cancel-limit design, CAN-2 + C4b)

A claimant intent can be cancelled by the attestor set until `CLAIM_DELAY`; the k-th cancel of one position within
`CANCEL_QUIET` needs `min(k, CANCEL_SIGNERS_MAX)` co-signatures of distinct current members (`cancelsRequired`;
`CANCEL_SIGNERS_MAX` 4, regtest 3; the rule counts the valid entries and ignores the rest). Each co-signature is the
member's C4b price statement at the claim's refHeight, signed by the node (`yed_signcancelcosign`), whose equivocation
guard locks it to the price that key attested at that height. `attest` automates the whole response, once per poll:

1. **Watcher.** Every claim in `yed_listvaults CLAIMING` (confirmed claims only; `min_confirmations`) is judged at its
   refHeight (`getrawtransaction` + `yed_decodepayload`) with this agent's own price: what this seq signed for that
   height, else the last aggregate it computed at or before that height (`price_tolerance_blocks`; the first after it only when it recorded none), else its aggregate now while the
   refHeight is recent. **Wrong-price**: `collateralZat · p · 10⁴ ≥ mintedCents · θ · COIN · (10⁴ + margin_bps)`, the
   vault was not claimable at the agent's price with the margin to spare. It is logged as `ALERT wrong-price` (error
   level; `alert_command` runs too) and, with `auto_cosign`, co-signed and published; republished every
   `republish_blocks`. A claim the agent cannot judge (no price near its refHeight) is `ALERT unjudged` and never
   co-signed; an honest one is logged and left alone.
2. **Gossip.** A frame is `"YCG1" ‖ intent txid (internal order) ‖ n LE32 ‖ seq LE16 ‖ refHeight LE32 ‖ price LE32 ‖
   sig65` (115 bytes). The receiver drops anything else, then duplicates (a digest LRU), then whatever exceeds a
   global token bucket, parks frames for a claim its node does not know yet (256 at most, 10 minutes), and verifies
   the rest locally: the signature must recover (secp256k1, the node's `RecoverSig` rules) over the co-sign message
   rebuilt from its own node's view (set id, the claim's refHeight and block hash) to the current member key of the
   frame's `seq` (ELIGIBLE or DORMANT, bond unspent and unfrozen, the newest record of that key); the price must say
   the vault was not claimable. Only verified frames reach the per-seq bucket (`gossip_burst`,
   `gossip_refill_seconds`), so a forged `seq` cannot spend a real member's allowance.
3. **Collector.** One member drives each claim: the current members in seq order, rotated by SHA-256(txid ‖ n); the
   member of rank r drives `r × takeover_blocks` blocks after the claim confirmed, so a missing leader is replaced
   without coordination. The driver waits for `cancelsRequired` valid co-signatures plus `spares` (no longer than
   `spare_wait_blocks` for the spares), calls `yed_buildcancel` with up to seven (an entry the node refuses is set
   aside and the call retried), `set_signcancel` and `vault_send`, and pushes the carrier and the cancel to every
   `broadcast_rpc` node. A cancel that lingers is pushed again every `refee_after_blocks`; one that left the mempool
   unconfirmed is re-funded (`vault_refee`) and rebuilt with the co-signatures valid at that moment. Co-signers that
   stop being current are set aside. Nothing is driven while another transaction spends the intent in the mempool.
4. **State.** `state_file` (default: `yellowback-cancel-<seq>.json` beside the node's `rpc_cookie`, else `~/.ycash/yellowback-cancel-<network>-<seq>.json`; 0600, written by rename) holds
   the claims, their co-signatures, the cancel sent, the price history and the signed prices: a restarted agent
   neither co-signs again nor rebuilds. Read it with `jq '.claims' <file>`.

What it needs from the operator: the member key in the node's wallet (as for `yed_signattestation`), a few YEC of
confirmed coins in that wallet for the carrier and the fee, and, on a wallet that imported the key or was restored,
`set_acknowledgerestore` once the sign-once history is complete (`doc/vault-rpc.md`); without it `set_signcancel`
refuses and the agent raises `ALERT sign-refused`. Alerts to act on: `wrong-price` (informational: the agent is
acting), `unjudged`, `cosign-refused` (the key signed a claimable price at that height), `cosign-within-margin`,
`sign-refused`, `wrong-price-past-delay` and `wrong-price-released` (the brake failed: escalate). The end-to-end test is
`qa/rpc-tests/yellowback_cancel_agent.py` (four agents, two cancels with 1 then 2 co-signatures, a leader takeover, and
an honest claim left alone).
