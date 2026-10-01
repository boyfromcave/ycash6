# `contrib/yellowback/` — Yellowback quote agent, pool kit and attestor agent

Python 3 (≥ 3.11, standard library only) tooling that runs **beside** `ycashd`, never inside it.
The node has no outbound networking for Yellowback: the quote agent fetches exchange prices and
pushes one number into the pool's node with `yed_setquote`; the node puts it in its coinbase tag
(plan §5, V6). Run everything through the workspace venv's Python.

| File | Role | Status |
|---|---|---|
| `yellowback_price.py` | Price-source layer: presets per venue (CoinGecko, Nonkyc, SafeTrade/Peatio, Kraken, Coinbase, generic URL + JSON path), every field overridable, per-source freshness / spread / flag guards, BTC pairs converted with a median of `[[btc_usd_sources]]`, 15-minute per-source VWAP/TWAP, outlier filter, median over `min_sources`/`min_venues` (fail closed); the §5 source-mask bit registry; the §3.2 coinbase-tag codec (TAG-1..5) | done |
| `yellowback-quote` | The quote agent daemon: `--conf <toml>`, polls every `poll_seconds`, calls `yed_setquote <priceMicroUsd> <sourceMask>`, `yed_setquote 0` after `fail_polls` failed aggregates (L5), RPC failures retried and never fatal; `--once`, `--dry-run`, `--mock-price <file>`, `sources` | done; `qa/rpc-tests/yellowback_quote.py` runs three of them against pool nodes |
| `pool/` | Pool-integration kit: `yellowback-quote.toml.sample`, `check-coinbase`, `monitor-quote.sh`, systemd/launchd units, `README.md` with the carriers and per-stack notes | tools done; the per-stack notes stay a skeleton until the operator survey (§12 Q9) |
| `test_yellowback_price.py`, `test_yellowback_quote.py` | Unit tests, no node, no network: `python3 -m unittest contrib/yellowback/test_yellowback_price.py contrib/yellowback/test_yellowback_quote.py` | done |
| `attest/` | **v3** attestor agent `yellowback-attest` (Rust; `attest`, `subscribe`, `sources`, `check-config`), its `attest.toml.sample`, fixtures for the Rust/Python aggregator cross-check, systemd/launchd units; see below | crate done; devnet integration and the nightly functional test follow (v3 plan Phase A4) |
| `attest/calibrate/` | **v3** the two calibration measurements of proposal §16: `spreads.py` (log CoinGecko / SafeTrade / nonkyc.io for two weeks, then `analyze` → `DIVERGE_BPS_ATTEST`), `pinrate.py` (arming rate of PIN-1 over hourly history → `PIN_WINDOW`/`PIN_DELTA_BPS`), `test_calibrate.py` (offline) | done; the live runs precede the first mainnet registration |
| `devnet/` | One-laptop Yellowback network: `yellowback-devnet up` (eight regtest nodes, activated and ARMED with three real attestor agents), `up --role {user,attestor,pool}` (eleven nodes, one seat left for you, a heartbeat, a price walk and `yellowback-sim`'s six personas), `check`, `status`, `mine`, `heartbeat`, `price [--walk|--shock]`, `attestor`, `pool`, `sim`, `notice`, `scenario`, `report`, `wallet`, `cli`, `down`; `scenarios/` holds the four walk-throughs. See `devnet/README.md` and `docs/plans/role-based-regtest-plan.md` | done; `qa/rpc-tests/yellowback_devnet_roles.py` (nightly) is its regression suite |
| `yellowback_fed.py`, `test_yellowback_fed.py`, `yellowback-redeem` | The retired federation coordinator and its tests; deleted in Phase 0 / Phase 7 (the feed layer lives on in `yellowback_price.py`) | removed |

## Quote agent contract

```
yellowback-quote [run|sources] --conf FILE [--mock-price FILE] [--once] [--dry-run] [--log-level L | -v]
```

- Exit codes: `0` a quote was published (`--once`) or an aggregate exists (`--dry-run`) or the
  daemon was stopped by SIGTERM/SIGINT; `1` nothing published / no aggregate (`--once`, `--dry-run`,
  `sources`); `2` bad configuration. The daemon never exits on an RPC or source failure.
- `--mock-price FILE`: the file holds one USD price (e.g. `0.05`), re-read every poll; `/dev/stdin`
  works for a single `--dry-run`/`--once`. In mock mode the sources are not fetched and the
  published `sourceMask` is `0`. An unreadable file is a failed aggregate.
- `--dry-run` does one poll and prints `{"priceMicroUsd", "priceUsd", "sourceMask", "sources"}` (or
  `{"aggregate": null, ...}`) as JSON; no RPC, so `[node] rpc_url` may be absent.
- Configuration (TOML): `[node] rpc_url` and either `rpc_cookie` or `rpc_user`/`rpc_password`
  (`rpc_timeout` optional); `[quote] poll_seconds (30), fail_polls (2), twap_seconds (900),
  min_sources (3), min_venues (2), min_btc_sources (2), outlier_bps (1000), silence_seconds (120),
  fetch_timeout (15)`; `[[sources]]` and `[[btc_usd_sources]]` rows with `name, kind, url, path,
  quote, scale, timestamp_path, timestamp_unit, max_age, spread_path, spread_unit, bid_path, ask_path,
  max_spread_bps, reject_paths, headers, volume_path, mask_bit` plus the preset parameters
  (`coin, vs, market, target, symbol, base_url, api_key, pair, key, product`). Unknown keys are
  refused. See `pool/yellowback-quote.toml.sample`.
- Source-mask bits: 0 SafeTrade, 1 CoinGecko, 2 CoinMarketCap, 3 Nonkyc; 4–15 unassigned. A
  preset's venue picks its bit; `mask_bit` overrides; a venue without a bit contributes none.

The Phase 7 acceptance line:
```
contrib/yellowback/yellowback-quote --conf contrib/yellowback/pool/yellowback-quote.toml.sample --dry-run --mock-price /dev/stdin <<< 0.05
```

## Attestor agent (v3) and the calibration scripts

`attest/` is a separate Rust crate (`rust-toolchain.toml` pins stable 1.91.0, `Cargo.lock`
committed, built with `--locked`; never part of the node's `depends` build — v3 plan §5, W13). It
runs beside a node the way the quote agent does and, like it, holds no key:

| Mode | Beside | Does |
|---|---|---|
| `yellowback-attest attest --conf attest.toml` | an attestor's `ycashd -yellowback` | every `every_blocks` (10) blocks: aggregate the `[[sources]]` exactly as `yellowback_price.py` does (`price.rs` is a port; `fixtures/` cross-checks the two), `yed_signattestation <seq> <priceMicroUsd> <tip − ref_lag>`, publish the returned 74 bytes on the gossip topic |
| `yellowback-attest subscribe --conf attest.toml` | any minting node (YecWallet's bundled node, the devnet's node 0) | join the topic, drop malformed or unknown-`seq` messages, `yed_addattestation` the rest; optional HTTPS `[subscribe] endpoints` as a second path |
| `sources`, `check-config` | — | one-shot checks |

Transports: `iroh` (production; `[transport] peers` bootstraps the swarm, `secret_key_file`
keeps the endpoint id stable) and `dir` (a shared directory; tests and the regtest devnet, no
network). `attest/README.md` documents the layout, the toolchain note (the crate's
`.cargo/config.toml` undoes a built checkout's vendored-sources redirect) and a regtest
walk-through; `doc/yellowback-attestor.md` is the operator's guide. Build and test:

```
cd contrib/yellowback/attest && cargo build --locked --release && cargo test --locked
```

`attest/calibrate/` holds the two measurements proposal §16 asks for before the first mainnet
registration, standard library plus `yellowback_price.py` (imported, so the exchanges are read
exactly as the agents read them):

```
V=../../.venv/bin/python
$V contrib/yellowback/attest/calibrate/spreads.py log --out spreads.csv --duration 14     # two weeks, five-minute cadence (--once for cron)
$V contrib/yellowback/attest/calibrate/spreads.py analyze spreads.csv                     # pairwise spread p95 → DIVERGE_BPS_ATTEST ≈ 3 × p95
$V contrib/yellowback/attest/calibrate/pinrate.py --days 90 --save-csv yec-hourly.csv     # arming rate over rolling 6-hour windows → PIN_DELTA_BPS
$V -m unittest contrib/yellowback/attest/calibrate/test_calibrate.py                      # offline
```

`attest/calibrate/README.md` explains how to read both results.

A five-minute crash course on running the devnet, a regtest node and both agents:
[`doc/yellowback-devnet.md`](../../doc/yellowback-devnet.md).
