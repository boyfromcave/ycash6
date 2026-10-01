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

## Inherited functional suite at the pin

Every inherited script was run against the stock node: branch `ycash6-stock` @ `e98128239` (the pin
plus the three baseline fixes, no Yellowback). That means all 119 `BASE_SCRIPTS` of
`qa/pull-tester/rpc-tests.py`, `zmq_test.py`, and the four scripts the v4.5.0 line excluded. Each was
run directly (`ZCASHD=… python -u <script> --srcdir … --tmpdir … --portseed=…`). Every pass was run a
second time, and every failure was re-run or inspected. The `PIN` and `SUSPECT` rows were reproduced
on their own. Recorded on 2026-09-30, macOS 26 arm64.

**BASE_SCRIPTS: 39 pass, 80 fail.** The failures, by cause:

| Class | Scripts | Cause | Examples |
|---|---|---|---|
| Branch ids | 44 | The harness passes upstream Zcash branch ids (`qa/rpc-tests/test_framework/util.py`; finding 4) and the node refuses to start: `Invalid network upgrade (2bb40e60)` / `(c2d6d0b4)` / `(e9ff75a6)` | `wallet_listunspent`, `wallet_z_sendmany`, `getblocktemplate`, `nuparams`, every `*orchard*` |
| Fee cap | 13 | The script passes an explicit ZIP-317-era fee (0.0001 / 0.00015 / 0.0002). 6.20.0 rejects any fee above 4 × the conventional fee, and Ycash's per-output conventional fee is a flat 0.00001, so the cap is 0.00004 (finding 5) | `wallet_sapling`, `mempool_tx_expiry`, `zkey_import_export`, `prioritisetransaction` |
| Mininode | 9 | `mininode`/`comptool` speak protocol 170006, but Ycash's `PROTOCOL_VERSION` = `MIN_PEER_PROTO_VERSION` = 270013, so the node logs `obsolete version 170006; disconnecting`. The script asserts or hangs | `bip65-cltv-p2p`, `invalidblockrequest`, `p2p_node_bloom`, `p2p-fullblocktest` |
| Addresses | 3 | Hard-coded Zcash regtest addresses (`tm…`, `zregtestsapling…`, `texregtest…`) | `signrawtransactions`, `sprout_sapling_migration`, `converttex` |
| Pin defects | 3 | Findings 7–9 below | `addressindex`, `rewind_index`, `orchard_nu6_2` |
| Caches | 2 | The checked-in persistent caches are Zcash regtest wallets (`Wallet wallet.dat is not for Ycash regtest network`) | `mergetoaddress_mixednotes`, `turnstile` |
| Branding | 2 | The script expects the string `Zcash` | `framework` (`Zcash version` in the log), `show_help` (fixture text) |
| Ycash policy | 2 | Intended Ycash behaviour that the upstream test does not know about: unified-address accounts are refused while NU5 is inactive (`81bab58fb`), and `walletconfirmbackup` with imported keys requires `acknowledge_imports=true` (`9e8b4f58c`) | `soft_fork_disabling_orchard`, `wallet_import_export` |
| Environment | 1 | The venv has no `base58` module. Without that error, the script would hit the branch-id and funding-stream problems next | `coinbase_funding_streams` |
| Unexplained | 1 | With `-disablewallet`, `getblockchaininfo.fullyNotified` never becomes true, so `sync_all` never returns (reproduced 3/3). Not yet traced to a commit. It only affects a regtest-only signal | `disablewallet` |

Outside `BASE_SCRIPTS`: `zmq_test`, `invalidateblock` and `getblocktemplate_longpoll` pass. The last two
were excluded on v4.5.0, where they aborted in `GetFoundersRewardAddressAtHeight`.
`getblocktemplate_proposals` still fails as it did on v4.5.0, because it builds a Bitcoin-format block.
`p2p-acceptblock` still hangs, because it uses the mininode.

**The stock baseline**, i.e. the 42 entries that passed twice. CI runs them against the fork binary
without `-yellowback` (`STOCK_BASELINE` plus `STOCK_BASELINE_MINEBLOCK` in
`.github/workflows/yellowback-tests.yml`):

```
wallet walletbackup fundrawtransaction reorg_limit getrawtransaction_insight spentindex timestampindex
key_import_export zapwallettxes feature_logging feature_walletfile rawtransactions threeofthreerestore
rest wallet_deprecation nodehandling reindex listtransactions merkle_blocks sapling_rewind_check
sapling_v4_value_balance wallet_parsing_amounts wallet_zero_value wallet_broadcast proxy_test errors
keypool txn_doublespend "txn_doublespend --mineblock" mempool_reorg mempool_resurrect_test
mempool_spendcoinbase regtest_signrawtransaction httpbasics multi_rpc blockchain getmininginfo
decodescript getchaintips invalidateblock getblocktemplate_longpoll zmq_test
```

The v4.5.0 line ran 7 scripts. Six of them carry over. `mempool_tx_expiry` drops out because of the
fee cap (its explicit `z_sendmany` fee is 0.0001). Of the 80 failures, 77 come from upstream-Zcash
assumptions in the inherited harness or from intended Ycash policy. They are not defects of the node,
and the Yellowback port does not touch them. The other three are defects in the pin:

| # | What | Where | Effect | Disposition |
|---|---|---|---|---|
| 7 | `-lightwalletd` without `-insightexplorer` crashes on the first connected block | Commit `0e4c703da` ("Move insight explorer indexes to a separate database", 2026-05-11) creates `pinsightExplorerDB` only when the insight cache is sized for `-insightexplorer` (`src/init.cpp`, `new CInsightExplorerDB`). `-lightwalletd` still sets `fAddressIndex`, so `ConnectBlock` (stock `src/main.cpp:4080`) calls `pinsightExplorerDB->WriteAddressIndex` on NULL. Stack: `ConnectBlock` > `CInsightExplorerDB::WriteAddressIndex` > `CDBWrapper::WriteBatch` | `addressindex.py`: its `-lightwalletd` node (node3) dies on its first block (reproduced 3/3; on macOS the dead process hangs and the script times out). **Phase 7:** a lightwalletd operator running a 6.20.0 node with `-lightwalletd` alone will crash it. The node must also be given `-insightexplorer`. The devnet's node 0, which serves lightwalletd, already runs `-insightexplorer -txindex` (`contrib/yellowback/devnet/yellowback-devnet`) | Not fixed in this port; report to miodragpop. Operator docs for Phase 7 must say "`-lightwalletd` needs `-insightexplorer` on 6.20.0" |
| 8 | `RewindBlockIndex` keeps block-index entries that never connected, including invalid ones, across a restart with new consensus parameters | Commit `1770fce16` ("rewind: Preserve unconnected block index entries across restarts", 2026-05-08). Entries below `BLOCK_VALID_CONSENSUS` are kept, so a block that *failed* under the old `-nuparams` stays marked invalid after a restart under the new ones. Upstream erased the entry and re-evaluated the block | `rewind_index.py` fails (`assert_equal … 10`, reproduced 2/2). **Yellowback:** on a node restarted across an activation-parameter change (regtest/devnet re-configuration, or a node that rejected a block before upgrading its binary), a block rejected under the old rules is not reconsidered without `reconsiderblock`. This matters for regtest and devnet re-configurations and for parity runs that restart a node under different `-nuparams`. It does not affect a node that keeps its parameters | Not fixed in this port; report to miodragpop |
| 9 | NU6 / NU6.1 / NU6.2 regtest protocol versions exceed the node's `PROTOCOL_VERSION` | Commit `04d22dda9` ("chainparams: fix NU6.2 activation default; Ycash-scheme NU6.x versions", 2026-06-03) sets regtest `nProtocolVersion` to 270110 / 270130 / 270150, but `PROTOCOL_VERSION` is 270013 | `orchard_nu6_2.py`: once NU6.x activates, every peer gets `obsolete version 270013; disconnecting` and the nodes partition (`Block sync failed`). Latent: NU6.x has `NO_ACTIVATION_HEIGHT` on every network. **Yellowback:** none while regtest/devnet activate only the six upgrades through Canopy. A regtest that activates NU6.x would partition before any Yellowback rule is involved | Not fixed in this port; report to miodragpop |
| 10 | The absurd-fee error reports the payment total as "the conventional fee" | `src/wallet/wallet_tx_builder.cpp:815`, no-change branch: `AbsurdFeeError(resolved.Total(), finalFee)` passes the total, not `conventionalFee`. This comes from upstream zcashd `c54c4ee98` ("Adjust wallet absurd fee check for ZIP 317", Greg Pfeil, 2023-04-13) | The error reads "Fee 0.00015 is greater than 4 times the conventional fee for this tx (which is 9.99985)". This is cosmetic: the check itself compares against the right value. **Yellowback:** none of the overlay's own RPCs build through this path, but YecWallet users see this message when a custom fee (or v4.5.0's `0.00001 × n` default for 5+ Sapling outputs) exceeds the 0.00004 cap (finding 5) | Not fixed in this port; report to miodragpop (and upstream zcashd) |
