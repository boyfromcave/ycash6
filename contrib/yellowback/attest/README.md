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
│   ├── gossip.rs               the co-signature receiver task: cheap checks, uniform sampling (topic), verification
│   ├── direct.rs               the members-only direct path: iroh endpoint, handshake gate, handler, sender, probe
│   ├── binding.rs              the signmessage binding of a member's direct endpoint id to its seat
│   ├── onchain.rs              the on-chain fallback: the 79-byte OP_RETURN record, its transaction, the block scan
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
guard locks it to the price that key attested at that height. `attest` automates the whole response:

1. **Watcher** (once per poll). Every claim in `yed_listvaults CLAIMING` (confirmed claims only; `min_confirmations`)
   is judged at its refHeight (`getrawtransaction` in the claim's block + `yed_decodepayload`) with this agent's own
   price there: first a price the key is on record for at that height -- the attestations the agent signed (state
   file), its attestation in the claim's own bundle (only when its 64-byte signature verifies under this seq's key over
   AttestMessage: the node decodes a bundle without verifying it), the node's pool (`yed_getattestations`), the node's guard (a
   `yed_signcancelcosign` without a price) -- else the last aggregate it computed at or before that height
   (`price_tolerance_blocks`). Nothing later, nothing current: with no price there the claim is `ALERT unjudged`.
   **Wrong-price**: `collateralZat · p · 10⁴ ≥ mintedCents · θ · COIN · (10⁴ + margin_bps)`. It is logged as `ALERT
   wrong-price` (`alert_command` runs too: at most four at once, each killed after 30 s) and, with `auto_cosign`,
   co-signed and published; republished every `republish_blocks`. A new price is stated (after `price-required`)
   only for a refHeight above the state file's `recording_since`, where the record proves the agent did not attest;
   otherwise `ALERT no-record`. Refusals: `cancel-statement-claimable`, `equivocation-guard` and `attest-range` are
   final for the claim (`ALERT cosign-refused`); anything else is retried at the next poll. **Reorgs**: each poll the
   claim's confirming block hash and blockHash(refHeight) are re-read. A claim whose block left the chain is held
   (`ALERT claim-reorged`, not driven, never closed); one that is CLAIMING again after it was closed is reopened; a
   claim is closed as `cancelled` or `released` only once its intent is spent in a confirmed block. A changed
   confirmation resets the claim (its co-signatures are restored when the refHeight and its hash are unchanged); a
   changed blockHash(refHeight) resets it and re-signs over the new hash.
2. **Delivery** (owner decisions 2026-10-13, docs/plans/yellowback-attest-gossip-evaluation.md). `[cancel] delivery`:
   `"trial"` (default until the trial ends: the members-only direct path **and** the old gossip topic), `"direct"`
   (the direct path only; the topic is not opened), `"gossip"` (the old topic only), `"onchain"` (neither: the
   on-chain fallback alone).
   - **Direct, members only** (`direct.rs`). A dedicated iroh endpoint (`direct_secret_key_file`, default
     `<state_file>.direct.key`) serves one ALPN, `yellowback/cancel-cosig/1`. An `EndpointHooks::after_handshake` gate
     refuses any connection on it whose authenticated endpoint id is not bound to a current member, and the agent
     never dials one (`before_connect`) -- except a **self-introduction** (review N-A): an unbound connection is let
     through the handshake only with a token from its source's bucket (a burst of 4, then one per 10 s; the source is
     an IPv4 address, an IPv6 /64, or -- arriving by a relay, whose URL everyone behind it shares -- its endpoint
     id), from the relay ceiling for a relay arrival (200, then 50 a second) and from the global ceiling (400, then
     100 a second). It then counts as pending until it verifies or closes; at most 64 are held, and a new one past
     that closes the oldest, so holding connections open shuts nobody out. Its first uni stream must carry, within 3 s,
     `0x03 ‖ announce` binding a current member's seat to that very endpoint id with a valid proof of possession, no older than
     the binding held for that seat (a key retired by rotation cannot come back) --
     checked once per connection (one secp256k1 recovery) -- or the connection is closed with the refusal. Every new
     connection the agent opens starts with its own announce, so a member reaches another that has not seen its
     binding yet on the first connection, whatever the topic carries; the receiver takes the binding into its table
     (and, newly binding a member at a new endpoint, announces its own at the next poll, which dials it back). Each co-signature goes straight to every other bound member on a fresh uni
     stream (`0x01 ‖ frame`); it is accepted only under the seq its connection is bound to and within that member's
     quota (64 at once, 4 a second), then verified at once -- no sampler: the author is authenticated, so a member can
     exhaust only its own allowance. Nothing is forwarded.
   - **The binding** (`binding.rs`): `YED-IROH-1|<network>|<attestorSetId>|<seq>|<endpoint id>|<issued>|<expiry>`, signed
     by the node's stock `signmessage` with the member key (its address, checked against `attestorPubKey` with
     `validateaddress`), valid at most `binding_ttl_blocks` (8,064; a longer one is refused) and re-signed at half
     of it. The endpoint key adds a **proof of possession** over the statement **and the dial hints** (ed25519 over
     `"YED-IROH-POP-2|" ‖ statement ‖ "|" hint_seq "|" addrs "|" relay`; review N-B), so no member can bind another
     member's endpoint id, and any copy's hints are the endpoint's own: a replay with other hints fails. The agent
     re-signs the proof locally (no node call; the `signmessage` statement is unchanged) whenever its addresses
     change, with a higher `hint_seq`, and a valid proof with a higher `hint_seq` replaces the hints held; a binding of an endpoint id another current seat holds is
     refused anyway (and two seats binding one id in the same poll are both refused), with `ALERT binding-conflict`.
     Announces (`"YBD3"`: statement, member signature, hint_seq, proof of possession, address hints, relay) travel on
     the public binding topic `yellowback/bindings/<network>/1` and over each member's own direct connection: every
     poll for the first 20 blocks after a new binding, then every 10 blocks. A member connection is taken only for that member's own seat, and first; the public topic keeps, per
     claimed seat, a uniform sample of 4 announces a poll (an honest announce competes only with forgeries of its own
     seat), seats without a binding or near expiry first, deduplicated by the announce's digest (review N-C: a look-alike
     with the same statement but a bad signature cannot displace the genuine copy), at most 64 signature checks a
     poll. The table is persisted. **Timing:** through the topic alone, under a 100x flood of forgeries for a seat,
     each announce lands with p = 4/151; the 20 fresh blocks at 15-second polls are about 100 announces (25 minutes
     on mainnet, ~93 %), then one per 10 blocks adds 4/151 each (~98 % by 12 hours). Self-introduction does not
     depend on the topic: a member admits a fresh member on its first direct connection.
   - **On-chain fallback** (`onchain.rs`, `onchain_fallback`, default on). A claim still short of `cancelsRequired`
     `fallback_after_blocks` (192) after it confirmed: every co-signing agent publishes its co-signature once in a
     standard transaction, `OP_RETURN OP_PUSHDATA1 79 ‖ "YF" ‖ short id (8) ‖ price ‖ sig65` (82-byte script, within
     `MAX_OP_RETURN_RELAY` 83 on both lines; "YF" is not the Yellowback payload magic), funded from one confirmed
     P2PKH coin worth more than a YED token's 10,000 zat, never an outpoint the YED index lists as this wallet's
     token, never a coinbase output and never a bond, fee exactly `fallback_fee_zat` (10,000), at most `fallback_max_txs` (20)
     a day; `ALERT onchain-fallback` each time. Every agent scans the claim's blocks for the tag (at most 20 blocks a
     poll) and takes each record that recovers to a current member's key at a non-claimable price.
   - **Relays.** The direct endpoint uses n0's public relays (and their pkarr/DNS lookup) by default;
     `fallback_relays` adds the project's own relays to that set; `direct_relays = ["none"]` uses no relay and no
     lookup (the binding's address hints only: a devnet or a LAN). `[transport] fallback_relays` does the same for the
     gossip endpoint. Running a relay: `cargo install iroh-relay --features server` (the version matching iroh 1.2),
     `iroh-relay --config-path relay.toml` with a `[tls]` table (`hostname = "<host>"`, `cert_mode = "LetsEncrypt"`),
     80 and 443/TCP open (and 7842/UDP with `enable_quic_addr_discovery = true`), then publish `https://<host>` for
     attestors' `fallback_relays`.
   - `yellowback-attest direct-probe <endpoint id> --addr ip:port` dials a member's direct endpoint with a fresh,
     unbound key: exit 3 "refused" is what any non-member sees (and how an operator checks its gate).
3. **Gossip** (the old topic, during the trial; its own task, `gossip.rs`, never waiting for a poll). A frame is `"YCG1" ‖ intent txid (internal order)
   ‖ n LE32 ‖ seq LE16 ‖ refHeight LE32 ‖ price LE32 ‖ sig65` (115 bytes). The receiver drops anything else, then
   duplicates of frames already verified, then frames failing the cheap checks against the agent's latest view (a
   current member's seq -- the primitive's `current` from `set_getinfo`, maturity included --, a claim this node
   knows, its refHeight, a price at which the vault was not claimable, and **no valid entry of that seq already held
   for the claim**). Frames for a claim not known yet wait (1,024 at most, random replacement, 10 minutes). What
   passes is offered to a **uniform random sample**: every 250 ms the reservoir's 500 frames (a budget of 2,000
   signature recoveries per second) are verified and the rest dropped, so under a flood an honest copy is drawn with
   probability budget/offered whoever relays it; there is no per-peer state, so no relaying neighbour is blamed for
   its traffic. Verified frames pass the per-seq bucket (`gossip_burst`, `gossip_refill_seconds`) and go to the agent.
   The agent republishes its own co-signature **every block** while the claim is short of `cancelsRequired` (else
   every `republish_blocks`): against a 20,000 frames/s flood it gets through within 60 blocks with probability
   above 0.998 (`gossip::tests::a_flood_cannot_starve_an_honest_frame`).
4. **Collector** (once per poll). One member drives each claim: the current members in seq order, rotated by
   SHA-256(txid ‖ n); the member of rank r drives `r × takeover_blocks` blocks after the claim confirmed
   (`takeover_blocks` ≤ 36, shrunk at run time to `(claimDelay − spare_wait_blocks − 2) / (members − 1)`). The driver
   waits for `cancelsRequired` valid co-signatures of current members plus `spares` (no longer than
   `spare_wait_blocks` for the spares), calls `yed_buildcancel` with up to seven (an entry the node drops for good,
   named in its `warnings`, is set aside; one dropped as not a member is only left out while it is not current),
   `set_signcancel` and `vault_send`, and pushes the carrier and the cancel to every `broadcast_rpc` node. A cancel
   that lingers is pushed again every `refee_after_blocks`; one that left the mempool unconfirmed is re-funded
   (`vault_refee`) and rebuilt, the k-th rebuild no sooner than `refee_after_blocks × 2^(k−1)` blocks after the last
   send and at most `max_sends` sends in all (`ALERT cancel-send-cap`); every attempt, a failed one included, is
   counted before it is tried. A spend of the intent in the mempool that is
   not the agent's and lingers raises `ALERT foreign-spend`.
5. **State.** `state_file` (default: `yellowback-cancel-<seq>.json` beside the node's `rpc_cookie`, else
   `~/.ycash/yellowback-cancel-<network>-<seq>.json`; 0600, written to a fresh O_EXCL temporary file and renamed)
   holds the claims, their co-signatures, the cancel sent, the price history, the signed prices and
   `recording_since` (set only once the node is out of initial block download and within two blocks of the best
   header): a restarted agent neither co-signs again nor rebuilds. Read it with `jq '.claims' <file>`.
6. **Liveness.** If the gossip tasks die the agent exits non-zero (the packaged unit restarts it).
7. **`auto_cosign = false`** never makes, stores or carries this member's own co-signature (not even through the
   guard); the agent still alerts, and still drives on other members' co-signatures when `drive` is on.

What it needs from the operator: the member key in the node's wallet (as for `yed_signattestation`) **and the node's
`attest-signed.dat` with it** (the guard file is the record of every price the key signed; a node without it can be
led to contradict an old attestation, which EQV-1 slashes), a few YEC of confirmed coins in that wallet for the
carrier and the fee, and, on a wallet that imported the key or was restored, `set_acknowledgerestore` once the
sign-once history is complete (`doc/vault-rpc.md`); without it `set_signcancel` refuses and the agent raises `ALERT
sign-refused`. The alert table is in `doc/yellowback-attestor.md` ("Cancelling wrong-price claims"). The end-to-end
test is `qa/rpc-tests/yellowback_cancel_agent.py` (four agents; two cancels with 1 then 2 co-signatures; a reorg of
the claim's block; a leader takeover; an honest claim left alone).
