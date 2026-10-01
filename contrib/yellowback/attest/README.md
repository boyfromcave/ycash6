# yellowback-attest

The Ycash Yellowback attestor agent (plan §5, W13; proposal §4, §13): one Rust binary, two
long-running modes, beside a `ycashd -yellowback`.

| Mode | Runs beside | Loop |
|---|---|---|
| `attest` | an attestor's node (registered with `yed_registerattestor`) | poll `yed_getinfo` every 15 s; every `every_blocks` new blocks aggregate the price sources, ask the node to sign with `yed_signattestation <seq> <priceMicroUsd> <tip − ref_lag>`, publish the returned 74-byte attestation on the topic |
| `subscribe` | any minting node (the devnet's node 0; YecWallet's bundled node) | join the topic; drop anything that is not 74 bytes or whose `seq` is not in `yed_listattestors` (refreshed every 60 s); push the rest with `yed_addattestation`; count acceptances; optionally poll `[subscribe] endpoints` over HTTPS as a second path |

Plus two one-shot commands: `sources` (fetch every source once and show what resolved) and
`check-config`.

**The agent never holds a key.** Signing happens inside the node, whose equivocation guard
(`attest-signed.dat`, plan §4.5 S16) makes two prices for one height impossible from one node.
Running two agents against two nodes with one hot key is the operator's error; do not.

**Failure behaviour** (the quote agent's, plan L5): an RPC or transport failure is logged at
`error` and retried on the next tick, never fatal; after `fail_polls` consecutive failed
aggregates at a due tick nothing is published until a good one — a missing attestation is the
correct report of a broken feed. The exit code is non-zero only for a bad configuration (2).

## Layout

```
attest/
├── Cargo.toml, Cargo.lock      exact `=` pins; build with --locked
├── rust-toolchain.toml         stable 1.91.0 (see "Toolchain" below)
├── attest.toml.sample          every setting, documented
├── rustfmt.toml, .gitignore
├── src/
│   ├── main.rs                 clap: attest | subscribe | sources | check-config
│   ├── config.rs               attest.toml → Config (bad config = exit 2)
│   ├── rpc.rs                  JSON-RPC 1.0 client (cookie or user/password), + a mock server for tests
│   ├── price.rs                the aggregator: port of contrib/yellowback/yellowback_price.py
│   ├── framing.rs              the 74-byte attestation (seq u16 ‖ price u32 ‖ citedHeight u32 ‖ sig 64, LE)
│   ├── attest.rs               the attest loop and `sources`
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
  `secret_key_file` keeps it stable. The endpoint's address is published through iroh's default
  DNS/pkarr lookup so an id alone is dialable.
- **`dir`** (tests, devnet, and any two processes on one machine): a shared directory. A publish
  writes `<path>/<seq>-<citedHeight>.att` through a temp file and one rename; a subscriber
  polls every 2 s and delivers each file once. No relay, no network.

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

`.cargo/config.toml` re-points crates.io at the real index because a built node checkout carries an untracked `ycash-dd/.cargo/config` that redirects it to the depends vendored directory (a worktree without a depends build does not, which is why the crate builds there without it). `rust-toolchain.toml` pins stable **1.91.0**; `cargo` run from this directory picks it up (the
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
