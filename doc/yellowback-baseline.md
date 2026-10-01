# ycashd 6.20.0 baseline for the Yellowback port

This fork (`boyfromcave/ycash6`, branch `feature/yellowback`) is cut from
`miodragpop/ycash` `dev-rebase-6.20.0` @ `040894344b`, the exact commit its author built. Before any
Yellowback code lands here, the pin itself has to build, start on regtest, mine, and move funds —
transparent and Sapling — on this platform. This file records that exercise and what it found.
Nothing in it is Yellowback; the Yellowback port is measured against *this* state (`ycash6-legacy`
plus the baseline fixes below), never against the raw pin.

Platform: macOS 26 (Darwin 25), Apple Silicon, Apple clang 17 host, depends-built clang 15 + Rust
1.96. Date: 2026-09-30.

## Build

```
export PATH="/opt/homebrew/opt/libtool/libexec/gnubin:/opt/homebrew/opt/coreutils/libexec/gnubin:/opt/homebrew/bin:$PATH"
export CARGO_TARGET_DIR=$PWD/target          # a global CARGO_TARGET_DIR in ~/.zshrc would break the librustzcash link
LIBTOOLIZE=glibtoolize ./zcutil/build.sh -j8  # cold: ~35 min (depends builds native clang, cmake, rust, cxxbridge, boost, bdb …)
make -C src -j8 ycashd ycash-cli test/test_bitcoin   # incremental
```

Result: `src/ycashd --version` → `Ycash Daemon version v6.20.0-040894344`; `getnetworkinfo` →
`6200050`, `/YcashCpp:6.20.0/`. `Cargo.lock` resolves every `zcash_*` crate from
`miodragpop/librustzcash` rev `ec525fae…` — the workspace's `ref/librustzcash6` pin.

## Regtest

Default regtest activates **no** network upgrade (every entry is `NO_ACTIVATION_HEIGHT`), so coinbase
is unspendable and the shielded RPCs refuse. Both qa harnesses (this tree's and v4.5.0's) activate
Overwinter and Sapling at height 1, and that is the baseline configuration:

```
regtest=1
nuparams=5ba81b19:1   # Overwinter
nuparams=76b809bb:1   # Sapling
```

Do **not** activate the Ycash upgrade (`374d694f`) on regtest: see finding 1.

With that config, a fresh node: `generate 110` in ~0 s, `getbalance` 100, transparent
`sendtoaddress` mined in the next block, `z_shieldcoinbase <t-addr> <sapling>` (100 YEC, 10 UTXOs)
mined, `z_sendmany` Sapling→Sapling mined, `z_sendmany … AllowRevealedRecipients` Sapling→transparent
mined, 20 more blocks over that history in ~0 s, clean `stop`. **Only after finding 3 was fixed.**

Mainnet at the pin is at Canopy (Ycash 570000; Blossom 1100000; Heartwood 1100003; Canopy 1100006);
NU5 and later are `NO_ACTIVATION_HEIGHT` on every network, and `z_getnewaccount` /
`z_getaddressforaccount` refuse with "Unified-address accounts require the NU5 network upgrade,
which is not active on Ycash". Yellowback's transparent-only transactions (rule TX-0) are unaffected.

## Findings at the pin

| # | What | Where | Effect | Disposition |
|---|---|---|---|---|
| 1 | The Ycash upgrade's Equihash (192,7) override applies on regtest too | `src/chainparams.cpp` `GetEquihashOverride()` walks the upgrade table for every network; v4.5.0's `EquihashN()` returned `consensus.nEquihashN` whenever `strNetworkID == "regtest"` | With `nuparams=374d694f:1`, `generate` runs the basic solver at (192,7): block 1 took 5 min. Any regtest that needs Blossom/Heartwood/Canopy (which must activate after Ycash) is impractical | Not changed. Regtest stays at Overwinter+Sapling. A port that needs later upgrades on regtest will need a regtest exemption here (note for the Yellowback v6 plan; v4.5.0's devnet never activated Ycash either) |
| 2 | Inherited qa harness cannot start a node | `qa/rpc-tests/test_framework/util.py` wrote `zcash.conf` and defaulted `ZCASHD_BINARY` to `src/zcashd`; `multi_rpc.py`, `wallet_deprecation.py` likewise. `ycashd` reads `ycash.conf` (`src/util/system.cpp:82`) and exits: "Before starting ycashd, you need to create a configuration file" | All 147 inherited functional tests fail in `initialize_chain` at the pin | **Fixed** (baseline-fix commit): `ycash.conf`, `src/ycashd`. Tests run with `ZCASHD=<repo>/src/ycashd python wallet.py --srcdir=… --tmpdir=… --portseed=N` |
| 3 | Uninitialised coinbase Sapling anchor | `src/miner.cpp`: all three coinbase paths (`operator()` for Orchard, Sapling, transparent recipients) declared `std::array<uint8_t, 32> saplingAnchor;` and passed it to `sapling::new_builder(…, saplingAnchor, true)`; `src/rust/src/sapling.rs` `new_sapling_builder` does `Anchor::from_bytes(anchor)` and errors "Invalid Sapling anchor" on non-canonical bytes | Whether a block template can be built depends on stack garbage. Here: `test_bitcoin` fails `miner_tests/CreateNewBlock_validity` and `tx_validationcache_tests/tx_mempool_block_doublespend` deterministically; on regtest `getblocktemplate`/`generate` fail with the same error once a Sapling-spending tx is in the mempool (reproduced with the chain's own `finalsaplingroot` as the tx anchor, so the tx was valid). Inherited from upstream zcashd `fd675c320` ("rust: Migrate to zcash_primitives 0.14.0", Jack Grigg, 2024-03-01) | **Fixed** (baseline-fix commit): `= {}` (all-zero is a canonical field element; coinbase bundles have no spends so the anchor is unconstrained). After the fix: both tests pass, full `test_bitcoin` → "No errors detected", the stuck Sapling spend mined on the next `generate`. Worth reporting upstream and to miodragpop |
| 4 | Harness branch-id constants are upstream Zcash's | `qa/rpc-tests/test_framework/util.py:41-44`: `BLOSSOM_BRANCH_ID = 0x2BB40E60`, `HEARTWOOD 0xF5B9230B`, `CANOPY 0xE9FF75A6`, `NU5 0xC2D6D0B4`; the node's Ycash values (`src/consensus/upgrades.cpp`) are `8e471bd6`, `66314da3`, `19bd2d2f`, `f919a198` | Inherited tests that pass `nuparams(BLOSSOM_BRANCH_ID, h)` (coinbase_funding_streams, feature_zip221, feature_zip244_blockcommitments, …) cannot activate the upgrade they test | Not changed; recorded. Confirmed by `feature_zip221.py` (table below) |
| 5 | Fee gate | `z_sendmany` with an explicit `0.0001` fee: "Fee 0.0001 is greater than 4 times the conventional fee for this tx (which is 0.00001)"; the active `-feepolicy` is Ycash's per-Sapling-output fee | v4.5.0-era scripts that hard-code 0.0001 fail | Pass `null` (default fee). Note for the Yellowback RPCs' fee handling in the port |
| 6 | Privacy policy on shielding | `z_shieldcoinbase '*' …` → "AllowRevealedSenders does not permit … Select AllowLinkingAccountAddresses" | Shielding from several t-addrs needs the explicit policy (6th argument) or a single from-address | Behavioural; recorded |

## Functional tests (inherited, after fix 2, with fix 3)

Filled in from the 2026-09-30 run; see the workspace commit for the exact log paths.

| Script | Result |
|---|---|
| `wallet.py` | **pass** (`Tests successful`) — transparent wallet, mining, sends, 4 nodes |
| `wallet_sapling.py` | **fail** at its first `z_sendmany`: the script passes the ZIP-317 `conventional_fee(3)` = 0.00015 and the node's per-output `-feepolicy` rejects it ("Fee 0.00015 is greater than 4 times the conventional fee for this tx (which is 9.99985)" — note the message reports the *amount*, not the fee: a second, cosmetic defect in the fee-policy error path). Finding 5; a harness/policy mismatch at the pin, not a consensus or Sapling defect: the same flows (shield, Sapling→Sapling, deshield) pass by hand with the default fee |
| `feature_zip221.py` (activates Blossom with the upstream id) | **fail** at node start: `Error: Invalid network upgrade (2bb40e60)` — finding 4 confirmed |
