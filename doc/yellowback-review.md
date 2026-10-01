# Ycash Yellowback (YED) on ycashd 6.20.0 — review package

For the Ycash maintainers, and for miodragpop as the author of the 6.20.0 rebase this port sits on.
It answers one question: **what does the Yellowback overlay change in ycashd 6.20.0, and what
evidence is there that the change is safe?** It is written fresh for this tree (plan decision P-6).
The v4.5.0 review package (`ycash-dd/doc/yellowback-review.md`, branch
`feature/yellowback-price-attest`) remains the record for the v4.5.0 line and is not restated here.

**What was measured, and where.** Every number below was measured on branch `feature/yellowback` of
`boyfromcave/ycash6` at commit `50192cd1d` on 2026-09-30, on macOS 26 / Apple Silicon, against the tag
**`ycash6-baseline`** (`8808258cd`). That tag is miodragpop's `dev-rebase-6.20.0` @ `040894344b` plus
two baseline fixes and one baseline document (§1.5). Commands are in §7.

**Read the evidence markers literally.**

- **measured** — the command was run for this document and its output is quoted.
- **recorded** — the result comes from a commit message or the plan's execution-status table, and
  was not re-run here.
- **pending: <what>** — the evidence does not exist yet. Nothing marked pending is counted as passing.

The port is not finished. Phases 0–3 of `docs/plans/yellowback-ycash6-plan.md` are complete. Phase 4,
the functional suite, is in progress. Phases 5 (devnet) and 6 (hardening, CI jobs, demonstration)
have not started. §6 lists what this document does **not** claim.

Citation conventions:

- `src/x.cpp:N` without a prefix is the 6.20.0 fork at `50192cd1d`.
- "baseline `:N`" is the same file at `ycash6-baseline`.
- `ref/ycash/…:N` is stock Ycash v4.5.0 (`624c12814`).
- `ycash-dd …:N` is the v4.5.0 Yellowback fork (`feature/yellowback-price-attest`).

---

## 1. Diff budget — actuals

### 1.1 The budgeted mining/validation files

`qa/yellowback-audit.sh` (**measured**, exit status 0):

```
frozen set: zero delta vs ycash6-baseline
src/main.cpp            11 changed lines (budget 40)
src/miner.cpp           14 changed lines (budget 35)
src/miner.h              4 changed lines (budget 10)
src/rpc/mining.cpp       7 changed lines (budget 35)
src/chainparams.cpp      4 changed lines (budget 4)
rpc/common.h: 48 yed_* rows current
```

| File | Budget (plan §2) | +/− | Changed | v4.5.0 fork (`ycash-dd` vs `ycash-legacy`) | Verdict |
|---|---|---|---|---|---|
| `src/main.cpp` | ≤ 40 | +11 / −0 | **11** | +11 / −0 | within budget, the same 11 lines |
| `src/miner.cpp` | ≤ 35 | +12 / −2 | **14** | +10 / −2 | within budget; +2 for the `BlockAssembler` seam (S2) |
| `src/miner.h` | ≤ 10 | +4 / −0 | **4** | — (no `BlockAssembler` in v4.5.0) | within budget; new in this port |
| `src/rpc/mining.cpp` | ≤ 35 | +7 / −0 | **7** | +7 / −0 | within budget, the same 7 lines |
| `src/chainparams.cpp` | = 4 | +4 / −0 | **4** | 0 | exactly the budget; this is **baseline fix 3, not Yellowback** (§1.5) |

### 1.2 Every pre-existing file the port changes

`git diff --numstat ycash6-baseline...feature/yellowback`, restricted to files that exist at the
baseline (**measured**):

| File | +/− | Tier | What |
|---|---|---|---|
| `src/main.cpp` | +11 / −0 | node, hook | six hooks + one include (§2.1) |
| `src/miner.cpp` | +12 / −2 | node, hook | tag, template view, filter, scriptSig append, K17 lock (§2.2) |
| `src/miner.h` | +4 / −0 | node, hook | forward declaration + `ybview` member (§2.2) |
| `src/rpc/mining.cpp` | +7 / −0 | node, RPC | four `getblocktemplate` insertions + include (§2.3) |
| `src/chainparams.cpp` | +4 / −0 | **baseline fix 3** | regtest Equihash guard (§1.5, §2.4) |
| `src/init.cpp` | +188 / −2 | node, startup | help, step-3 checks, index construction, kill switch, shutdown, registration (§2.5) |
| `src/rpc/rawtransaction.cpp` | +23 / −3 | wallet tier | H7 `allowyedburn` (§2.6) |
| `src/wallet/rpcwallet.cpp` | +21 / −1 | wallet tier | H5 `lockunspent` (§2.6) |
| `src/wallet/rpcdump.cpp` | +19 / −0 | wallet tier | H8 reconcile after import (§2.6) |
| `src/transaction_builder.cpp` | +18 / −0 | wallet tier | I2 extension, S4 (§2.6) |
| `src/transaction_builder.h` | +16 / −0 | wallet tier | I2 extension, S4 (§2.6) |
| `src/rpc/common.h` | +51 / −1 | RPC table | S1: 48 `yed_*` arity rows + `sendrawtransaction` (§2.6) |
| `src/experimental_features.{h,cpp}` | +7 / −0 | build/flag | the `-yellowback` experimental flag |
| `src/rpc/register.h` | +5 / −0 | build | two registration declarations, one call |
| `src/Makefile.am`, `src/Makefile.test.include` | +49 / −1 | build | new sources and tests |
| `qa/pull-tester/rpc-tests.py` | +36 / −2 | test runner | Yellowback scripts listed; `--cachedir`/`--portseed` precedence |
| `qa/rpc-tests/test_framework/script.py` | +1 / −1 | test framework | the signed `valueBalance` pack (`'<q'`), as on v4.5.0 |

Everything else in the diff is a new file under `src/yellowback/`, `src/rpc/yellowback*.cpp`,
`src/rpc/yellowbackrpc.h`, `src/test/yellowback_*` (plus `src/test/data/yellowback_*.json` and the
two `gen_yellowback_*.py` generators), `src/fuzzing/Yellowback*/`, `qa/rpc-tests/yellowback_*.py`,
`qa/rpc-tests/test_framework/{yellowback*,test_yellowback_*,SERIALISATION.md}`, `qa/yellowback-*`,
`contrib/yellowback/`, `doc/yellowback*`, and `.github/workflows/yellowback-tests.yml`.

**Whole-fork totals** (**measured**): 624 files, **+75,575 / −13**. All 13 deleted lines are
replaced lines in the table above:

- 2 in `miner.cpp`: the scriptSig statement and the `IncrementExtraNonce` call;
- 2 in `init.cpp`: the debug-category string and `if (!fDisableWallet)`;
- 3 in `rawtransaction.cpp`: the arity guard, the usage line and `RPCTypeCheck`;
- 1 in `rpcwallet.cpp`: `if (fUnlock)` became a block;
- 1 in `rpc/common.h`: the `sendrawtransaction` row;
- 1 in `Makefile.test.include`;
- 2 in `rpc-tests.py`;
- 1 in `script.py`.

### 1.3 The frozen set is at zero

`qa/yellowback-frozen-files.txt` lists `src/consensus/`, `src/script/`, `src/primitives/`,
`src/pow/`, `src/pow.{cpp,h}`, `src/policy/`, `src/txdb.{cpp,h}`, `src/wallet/wallet.{h,cpp}`,
`src/rust/`, `Cargo.toml`, `Cargo.lock` and `configure.ac`. The audit prints
`frozen set: zero delta vs ycash6-baseline` (**measured**). `git diff --stat
ycash6-baseline...feature/yellowback` over the same paths plus `src/gtest` also prints nothing
(**measured**). The port contains no Rust and does not touch `librustzcash6`.

### 1.4 v4.5.0 hunks that this port does not carry

v4.5.0's fork modified the files below. On this tree they are at zero (**measured**, `git diff
--stat` empty), because 6.20.0 already contains the fix or the anchor no longer exists (mapping §19):

- `src/sync.cpp`;
- `src/wallet/asyncrpcoperation_sendmany.cpp`;
- `src/test/main_tests.cpp`, `src/test/net_tests.cpp`, `src/wallet/test/rpc_wallet_tests.cpp`;
- `src/rpc/client.cpp`. Its v4.5.0 `vRPCConvertParams` rows (+44) became the `rpc/common.h`
  rows (S1).

### 1.5 The baseline fixes: **not Yellowback**

At the pin, 6.20.0 did not build a block template reliably on this platform, and its own test
harness could not start a node. The fixes below are separate commits that never mix with
Yellowback code. Each is a candidate upstream patch for miodragpop (plan Phase 6, last item). The
full record is in `doc/yellowback-baseline.md`.

| Commit | +/− | Inside `ycash6-baseline`? | What and why |
|---|---|---|---|
| `940987c51` baseline fix: zero-initialise the coinbase Sapling anchor in the miner | `src/miner.cpp` +3 / −3 | **yes**: not in the measured diff | All three coinbase paths passed an **uninitialised** `std::array<uint8_t,32> saplingAnchor` to `sapling::new_builder`. The Rust side rejects bytes that are not a canonical field element ("Invalid Sapling anchor"), so whether a block template could be built depended on stack contents. On this platform, `miner_tests/CreateNewBlock_validity` and `tx_validationcache_tests/tx_mempool_block_doublespend` failed deterministically, and `getblocktemplate`/`generate` failed once a Sapling spend was in the mempool. A coinbase bundle has no spends, so its anchor is unconstrained, and all-zero is canonical. Inherited from upstream zcashd `fd675c320`. After the fix the full `test_bitcoin` is green. |
| `141df8d48` baseline fix: qa harness writes ycash.conf and defaults to src/ycashd | `multi_rpc.py`, `test_framework/util.py`, `wallet_deprecation.py`, +5 / −5 | **yes**: not in the measured diff | `ycashd` refuses to start without `ycash.conf` (`src/util/system.cpp:82`). The inherited harness wrote `zcash.conf` and looked for `src/zcashd`, so all 147 inherited functional tests died in `initialize_chain`. Test-only. |
| `e98128239` baseline fix 3: regtest keeps Equihash (48,5) under every network upgrade | `src/chainparams.cpp` +4 / −0 | **no**: committed after the tag, so its 4 lines are the whole `chainparams.cpp` budget in §1.1 | v4.5.0 returned the regtest (48,5) parameters before consulting the upgrade table (`ref/ycash/src/chainparams.cpp:860-869`). 6.20.0's `GetEquihashOverride()` applies the Ycash upgrade's (192,7) on every network. Activating the mainnet epoch on regtest (six upgrades at height 1, Canopy branch id) therefore cost about 5 minutes per block. The guard is regtest-only (`NetworkIDString() == REGTEST`); mainnet and testnet do not reach it. Owner decision P-1(a): the port has to be proven at the epoch mainnet actually runs (Canopy). The stock comparison binary is built from branch `ycash6-stock` (`e98128239`, all three fixes) for the same reason. |
| `8808258cd` doc: baseline exercise | `doc/yellowback-baseline.md` +69 | yes (it is the tagged commit) | The record of the exercise: build, regtest smoke, findings 1–6. |

**Not fixed, recorded only** (`doc/yellowback-baseline.md` findings 4–6):

- the harness's upstream-Zcash branch ids (`util.py:41-44`);
- the per-output fee policy rejecting `wallet_sapling.py`'s ZIP-317 fee, whose error message prints
  the amount where it should print the fee;
- the shielding privacy-policy message.

---

## 2. The hook table

Every hook in a mining or validation file is an **insertion**. Every statement that changes
behaviour is guarded by `yellowback::g_yellowback`, which is `nullptr` (`src/yellowback/index.cpp:31`)
unless `init.cpp:2190` constructs it under `fExperimentalYellowback`. That flag is set only by
`-experimentalfeatures -yellowback`.

The four-part check (AGENTS.md rule 4) is applied to the **v4.5.0 → 6.20.0 move**: *v4.5.0 put
hook X at Y; 6.20.0 kept or moved that seam to Z; so the adaptation is W.* Why each hook exists at
all — the DigiByte → Ycash four-part check and the tier argument — was settled for v4.5.0 and is in
`ycash-dd/doc/yellowback-review.md` §2 and mapping §13. It is not re-argued here, because the
behaviour is unchanged.

### 2.1 `src/main.cpp` — 11 lines

| # | 6.20.0 fork | Baseline anchor | v4.5.0 (`ref/ycash` anchor → `ycash-dd` hook) | Guard |
|---|---|---|---|---|
| V0 | `:40` `#include "yellowback/index.h"` | — | `ycash-dd :39` | none needed (declaration only) |
| V1 | `:1891-1892` MP-1 in `AcceptToMemoryPool` | after `view.SetBackend(dummy)` `:1889` | `ref/ycash :1643` → `ycash-dd :1645-1646` | `g_yellowback &&` |
| V2 | `:3161` undo at the end of `DisconnectBlock` | before `return fClean ? …` `:3158` | `ref/ycash :2796` → `ycash-dd :2799` | `updateIndices && g_yellowback` |
| V3 | `:4047-4049` `CheckConnect` in `ConnectBlock` | before `if (fJustCheck)` `:4043` | `ref/ycash :3194` → `ycash-dd :3198-3200` | `if (g_yellowback) {…}` |
| V4 | `:4123` `CommitConnect` | after `view.SetBestBlock(pindex->GetBlockHash())` `:4115` | `ref/ycash :3268` → `ycash-dd :3276` | `g_yellowback` |
| V5 | `:4526` `RemoveInvalidVaultSpends` in `ConnectTip` | after `mempool.removeExpired(…)` `:4517` | `ref/ycash :3636` → `ycash-dd :3645` | `g_yellowback` |
| V6 | `:5976-5977` BLK-2 descendant clause in `AcceptBlockHeader` | first statement inside `if (hash != genesis)` `:5966` | `ref/ycash :4552` → `ycash-dd :4562-4563` | `g_yellowback &&` |

**V1, MP-1.** *v4.5.0* placed the relay-policy check after the inputs were cached and the view was
switched back to the dummy backend. *6.20.0 kept* `AcceptToMemoryPool` monolithic in `main.cpp`,
with the same `view.SetBackend(dummy)` statement (baseline `:1889`). *Adaptation:* none. The two
lines are byte-identical to v4.5.0. The refusal is `DoS(0, …, REJECT_NONSTANDARD)`, which is
policy only. One open item specific to 6.20.0 (plan §1): ZIP-317's unpaid-action gate
(baseline `:1973-1981`) runs *after* MP-1. **pending:** the P-2 fee-floor tests in Phase 6.

**V2, undo.** *v4.5.0*: the last statement of `DisconnectBlock`, inside `updateIndices`, after the
coins, nullifier and anchor rollback. *6.20.0 kept* that order and added an Orchard leg:

- `view.SetNullifiers(tx, false)` baseline `:3031`;
- `PopAnchor(…, SPROUT)` `:3105`, `SAPLING` `:3113/3115`, `ORCHARD` `:3124/3126`;
- `view.SetBestBlock(pindex->pprev->GetBlockHash())` `:3138`.

`DisconnectTip` calls with `updateIndices = true` (baseline `:4413`), `VerifyDB` with `false`
(`:6792`). *Adaptation:* none. The line is byte-identical, so every shielded rollback, Orchard
included, has finished before the overlay undoes anything.

**V3, the block-validity check.** *v4.5.0*: in `ConnectBlock`'s window after every consensus check
and before `if (fJustCheck) return true;`. A verdict is `state.DoS(0, …, REJECT_INVALID,
"yellowback-vault-spend")`. *6.20.0 kept* the window (baseline `:4043`). It changed two things
around it:

- **(a) A new template call path.** Templates now reach `ConnectBlock(fJustCheck,
  CheckAs::BlockTemplate)` through `TestNewBlockAtTipValidity` (`miner.cpp:473`, `main.cpp:6251`;
  `pindex` is an `indexDummy`, baseline `:6269-6290`). This is **not** new exposure. v4.5.0 also ran
  its own template through `TestBlockValidity` (`ref/ycash/src/miner.cpp:660`). See finding F-6.
- **(b) Body-corruption classification.** A `DoS` raised with the default `BodyCorruption::Default`
  is classed "body-replaceable", and the block is **not** marked `BLOCK_FAILED_VALID`
  (`InvalidBlockFound`, baseline `:2602-2615`), unless both commitment flags have been set in this
  pass. `ConnectBlock` resets them at entry (`:3244`), and `CheckBlock` (`:3303`, which checks the
  Merkle root when `!fJustCheck`) and `CheckBlockBodyAuthCommitment` (`:3316`) set them **before**
  the hook at `:4047`. So on the `ConnectTip` path a Yellowback verdict is final and marks the block
  failed, exactly as on v4.5.0. Under `fJustCheck`, the Merkle flag is not set and the verdict is
  classed corruption-possible. That has no effect: a template or proposal check writes nothing to
  the block index. See finding V-4.

*Adaptation:* none; the three lines are byte-identical. **pending:** the multi-node proof that a
rejected block stays `BLOCK_FAILED_VALID` on 6.20.0 (`yellowback_enforcement.py`). Commit
`50192cd1d` **records** one related observation: after a clean restart the kill switch takes its
`ReconsiderBlock` branch, because the rejected block keeps its index entry. That is consistent with
this analysis.

**V4, the commit.** *v4.5.0*: directly after `view.SetBestBlock`, which is after every write in
`ConnectBlock` that can `AbortNode`. It is never reached under `fJustCheck`, because V3's early
return comes first. *6.20.0 kept* the statement (baseline `:4115`). The 6.20.0 block-commitment and
chain-history work happens earlier, in `CheckBlockBodyAuthCommitment`. *Adaptation:* none.

**V5, the mempool sweep.** *v4.5.0*: after `removeExpired` in `ConnectTip`. *6.20.0 kept* it
(baseline `:4517`). *Adaptation:* none. A new interaction is recorded in plan §1: the
`-mempooltxcostlimit` eviction also runs in 6.20.0. **pending:** the Phase 6 test that combines
the sweep with eviction.

**V6, the BLK-2 descendant clause.** *v4.5.0*: the first check on a non-genesis header, before both
stock `bad-prevblk` refusals. It answers with DoS 0 where stock would answer DoS 100 for a child of
a failed block. *6.20.0 kept* the structure (baseline `:5966-5980`). It added a `BodyCorruption`
argument to every header-path `DoS`, and its two `bad-prevblk` neighbours pass `HeaderOnly`.
*Adaptation:* the clause passes `BodyCorruption::HeaderOnly` too. This is the **only edited token**
among the `main.cpp` hooks, and the classification is correct: the verdict depends on the header's
ancestry, never on the body.

### 2.2 `src/miner.cpp` (14) and `src/miner.h` (4)

| # | 6.20.0 fork | Baseline anchor | v4.5.0 (`ref/ycash` → `ycash-dd`) | Guard |
|---|---|---|---|---|
| M0 | `miner.cpp:39` `#include "yellowback/policy.h"` | — | `ycash-dd :36` | — |
| M1 | `miner.cpp:289` scriptSig `… + COINBASE_FLAGS` in `CreateCoinbaseTransaction` | baseline `:288` (replaced line) | `ref/ycash :327` → `ycash-dd :328` | none: appends an empty script without the flag (§3) |
| M2 | `miner.cpp:352-354` tag assignment and `TemplateView` in `BlockAssembler::CreateNewBlock` | right after `LOCK2(cs_main, mempool.cs)` `:350` | `ref/ycash :368` → `ycash-dd :370-372` | `g_yellowback ? … : CScript()`; `if (g_yellowback)` |
| M3 | `miner.cpp:545-546` TPL-1/2 filter in `BlockAssembler::TestForBlock` | after `IsExpiredTx` `:538-539`, before the ZIP-209 turnstile check `:541` | `ref/ycash :582` (before `UpdateCoins`) → `ycash-dd :586` | `ybview &&` (non-null only under the flag) |
| M4 | `miner.cpp:916-919` `LOCK(cs_main)` around `IncrementExtraNonce` in `BitcoinMiner` | `:909` (replaced line) | `ref/ycash :832` → `ycash-dd :838-841` | none: K17 lock (§3) |
| M5 | `miner.h:25` forward declaration; `miner.h:132-133` `TemplateView* ybview = nullptr;` member of `BlockAssembler` | `class BlockAssembler` private section | — (v4.5.0 used a local `std::optional` in a free function) | default `nullptr` |

**M1 and M2, the coinbase tag.** *v4.5.0* emitted the 36-byte tag through `COINBASE_FLAGS`. The
variable was declared in stock Ycash (`ref/ycash/src/main.cpp:134`) but never assigned there, so
the internal miner, `generate` and `getblocktemplate` all carried the tag with no new plumbing.
*6.20.0 kept* `COINBASE_FLAGS` (`main.cpp:151`) and its two stock readers:

- `IncrementExtraNonce`, `miner.cpp:788` / baseline `:781`, which still appends it after the extra
  nonce;
- `getblocktemplate`'s `coinbaseaux.flags`, `rpc/mining.cpp:785` / baseline `:781`.

The template is now built by the `BlockAssembler` class, and the coinbase goes through the Rust
Sapling builder. *Adaptation:*

- the assignment moves to the top of `BlockAssembler::CreateNewBlock`, under `LOCK2`;
- the scriptSig append moves inside the 6.20.0 recipient visitor (`:289`), which is before
  `ComputeBindingSig`, so the binding signature covers the final scriptSig;
- no other writer of `COINBASE_FLAGS` exists: `git grep 'COINBASE_FLAGS ='` returns only `:352`.

**M3, the template filter (seam S2).** *v4.5.0* filtered each candidate in the priority loop,
**before** `UpdateCoins`, so that a skipped transaction's descendants could not see phantom coins.
*6.20.0 moved* transaction selection to ZIP-317 weighted-random sampling in `addTransactions` →
`TestForBlock` → `AddToBlock` (baseline `:493-690`), and a candidate with an unconfirmed parent
waits in `waiting` until that parent is added (`isStillDependent`, baseline `:663-666`). *Adaptation:* the
filter becomes a `return false` in `TestForBlock`, after the size, sigop, finality and expiry
refusals. A refused parent is never added, so its children never leave `waiting`. That property is
structural in 6.20.0, and it is what "before `UpdateCoins`" used to provide. The only refusal
after the filter is the ZIP-209 turnstile check: see finding V-1. The `TemplateView` RAII holder
(`cs_yellowback`) lives in `CreateNewBlock`'s frame and is declared after `LOCK2`, so it is
released before `mempool.cs` and `cs_main`. That matches the recorded order `cs_main → cs_wallet →
mempool.cs → cs_yellowback`. `TestForBlock` reaches the holder through the raw `ybview` member
(M5).

**M4, K17.** *v4.5.0*: `IncrementExtraNonce` reads `COINBASE_FLAGS`, whose writer holds `cs_main`,
so the `-gen` thread takes `cs_main` around the call. *6.20.0*: `IncrementExtraNonce` now takes
four arguments (baseline `:764`); the call site is otherwise unchanged. *Adaptation:* the same
scope around the 4-argument call. The call itself is byte-identical to the baseline.

### 2.3 `src/rpc/mining.cpp` — 7 lines, `getblocktemplate`

| 6.20.0 fork | Baseline anchor | v4.5.0 (`ref/ycash` → `ycash-dd`) | What |
|---|---|---|---|
| `:33` include | — | `ycash-dd :29` | — |
| `:520-521` | after `LOCK(cs_main)` `:517` | `ref/ycash :489` → `ycash-dd :492-493` | `-yellowbackrequirehealthy` refusal |
| `:795` | after `aMutable.push_back("prevblock")` `:790` | `:751` → `:756` | `"coinbase/append"` in `mutable` |
| `:825` | after `pushKV("coinbasetxn", …)` `:819` | `:764` → `:770` | `coinbaseaux` alongside `coinbasetxn` |
| `:840` | after `pushKV("height", …)` `:833` | `:778` → `:785` | the `yellowback` object |

All four sit behind `if (g_yellowback…)`. *6.20.0 kept* the function's shape and added
`blockcommitmentshash` and `defaultroots`; `finalsaplingroothash` is still emitted by default under
`gbt_oldhashes`. *Adaptation:* none; the lines are byte-identical to v4.5.0. Without the flag the
response is the baseline's, key for key. **pending:** `yellowback_mining.py`'s
`gbt_shape_without_flag` on 6.20.0. Commit `50192cd1d` **records** that the script's stock key set
was updated to include the two new 6.20.0 keys.

### 2.4 `src/chainparams.cpp` — 4 lines (baseline fix 3)

The two `if (NetworkIDString() == CBaseChainParams::REGTEST) return consensus.nEquihash{N,K};`
guards are in `CChainParams::EquihashN/K` (fork `:984-985`, `:993-994`; baseline `:983`, `:990`).
*v4.5.0* had the same guard (`ref/ycash/src/chainparams.cpp:860-862`). *6.20.0 dropped* it when it
introduced `GetEquihashOverride()`. *Adaptation:* restore it in the two accessors that both the
miner and `ContextualCheckBlockHeader` read, so mining and validation agree. The guard is not
Yellowback; it is listed in §1.5.

### 2.5 `src/init.cpp` — +188 / −2

The five v4.5.0 blocks are carried byte for byte (commit `6d5c176a7`). They sit at these 6.20.0
anchors:

| 6.20.0 fork | Baseline anchor | v4.5.0 `ycash-dd` | What | Guard |
|---|---|---|---|---|
| `:45-48` | after `#include "validationinterface.h"` | `:42-45` | includes | — |
| `:211-216` | `Shutdown()`, after `StopHTTPServer()` `:206` | `:216-221` | unregister, `Stop()`, `Flush(true)` | `if (g_yellowback)` |
| `:403-425` | `HelpMessage`, after `-txindex` `:392` | `:417-440` | help text for every `-yellowback*` option | **none** (§3.2) |
| `:512` | the single debug-category string `:478` | `:520`, `:523` (v4.5.0 had two strings) | adds `yellowback` | **none** (§3.2) |
| `:1274-1341` | step 3, before `RegisterAllCoreRPCCommands` `:1240` | `:1141-1207` | H6 datadir check; option validation; "options require -yellowback" | H6 runs without the flag (§3.2); the rest `if (fExperimentalYellowback)` |
| `:1345-1350` | wallet RPC registration `:1243-1244` | `:1253-1258` | `RegisterYellowbackWalletRPCCommands` | `if (fExperimentalYellowback)` |
| `:2185-2264` | after `RewindBlockIndex`/`VerifyDB`, before the notifier thread `:2078` | `:1937-2015` | index construction, `SyncToChain`, kill-switch `ReconsiderBlock` loop, `RegisterValidationInterface`, wallet attach | `if (fExperimentalYellowback)` |

*6.20.0 kept* the `AppInit2` step order. Its one change at these anchors is that the debug
categories became a single string. *Adaptation:* one edited string. `ActivateBestChain`'s arity was
checked in Phase 3.

### 2.6 The wallet tier and the RPC table

These files change only what **this node's RPCs** do. Nothing in them changes what any node accepts
from the network.

**H7 — `sendrawtransaction allowyedburn`** (`src/rpc/rawtransaction.cpp:20-22` include,
`:1254-1264` arity/help, `:1279` type check, `:1309-1320` guard).

- *v4.5.0*: `ref/ycash/src/rpc/rawtransaction.cpp:1083` → `ycash-dd :1090-1150`, plus a client
  conversion row (`ycash-dd src/rpc/client.cpp:95`).
- *6.20.0 kept* the handler (baseline `:1249`). The server now enforces arity through `rpcCvtTable`
  (S1).
- *Adaptation:* the same handler hunk, plus `{{s},{o,o}}` in `rpc/common.h:121`.
- Guard: `YedBurnedByRawTransaction` returns `false` at once when `g_yellowbackWallet` is null
  (`src/yellowback/wallet.cpp:507`). The arity widening is unguarded (§3.2).

**H5 — `lockunspent`** (`src/wallet/rpcwallet.cpp:33` include, `:2802-2804` help, `:2847-2849`
`ReapplyLocks`, `:2853-2887` two-pass loop with the `yed-locked-outpoint` refusal at `:2877`).

- *v4.5.0*: `ref/ycash/src/wallet/rpcwallet.cpp:2187` → `ycash-dd :2199-2280`.
- *6.20.0 kept* the handler (baseline `:2790`). Its `rpcCvtTable` row `{{o,o},{}}` makes the second
  argument **required**.
- *Adaptation:* the same hunk. The unlock-all branch is now unreachable (finding V-2).

**H8 — reconcile after import** (`src/wallet/rpcdump.cpp:21` include, `:88-99`
`YellowbackReconcileOnExit`).

- *v4.5.0* declared the guard object before the `LOCK2` of four RPCs: `rescanblockchain`
  (`ycash-dd :116`), `importprivkey` (`:168`), `importaddress` (`:302`) and `z_importkey` (`:944`).
- *6.20.0 removed* `rescanblockchain` (no such RPC in this tree; v4.5.0 had it at
  `ref/ycash/src/wallet/rpcdump.cpp:80`) and still has `importwallet`.
- *Adaptation:* four sites — `importprivkey :130`, `importaddress :262`, `importwallet_impl :397`
  (new: finding F-7) and `z_importkey :843`. The view-only imports (`importpubkey`,
  `z_importviewingkey`, `z_importivk`) are deliberately left alone: they cannot spend.
- Guard: the destructor runs only `if (g_yellowbackWallet)`.

**I2 / S4 — `TransactionBuilder` extension** (`src/transaction_builder.h:259`, `:305`, `:332`,
`:388-399`; `src/transaction_builder.cpp:415-430`, `:637`).

- *v4.5.0* added a `bool sign` to `TransparentInputInfo` and skipped unsigned inputs in `Build()`
  (`ycash-dd src/transaction_builder.h:84-95`, `.cpp:507`; stock `ref/ycash :259`, `:491`). ZIP-243
  never covers a scriptSig.
- *6.20.0*: `tIns` is a `std::vector<CTxOut>` that is fed to the ZIP-244 precompute
  (`PrecomputedTransactionData(tx, allPrevOutputs)`). The builder is move-only, and its move
  operations are written out field by field.
- *Adaptation:*
  - an unsigned input carries its **real** `scriptPubKey` and value into `tIns`;
  - a separate `std::set<size_t> tInsUnsigned` marks it, and both move operations carry the set;
  - `Build()` skips those indices;
  - plus `AddTransparentOutput(const CScript&, CAmount)` and `SetLockTime`.
- The three new methods are called only from `src/yellowback/`. **Measured:** `git grep -n
  'AddTransparentInputUnsigned\|AddTransparentOutput(.*CScript\|SetLockTime' -- src
  ':!src/transaction_builder.*' ':!src/yellowback' ':!src/test'` prints nothing.

**S1 — `rpc/common.h` arity table** (`:121` `sendrawtransaction`, `:220-268` 48 `yed_*` rows).

- *v4.5.0* had client-only conversion rows (`ref/ycash/src/rpc/client.cpp:94`).
- *6.20.0* has `rpcCvtTable`, consulted by the client **and** by the server (`src/rpc/server.cpp:488-512`).
  The server refuses a call whose arity is not in the table, and throws an internal error for a
  registered command that has no row.
- *Adaptation:* one exact-arity row per `yed_*` RPC. The rows are generated from the handlers' own
  arity guards by `qa/yellowback-rpc-cvt.py` and checked by `qa/yellowback-audit.sh` ("48 yed_*
  rows current", **measured**).
- The server looks up the command (`:479-481`, "Method not found") **before** consulting the table,
  so on a node without `-yellowback` the 48 rows are inert.

---

## 3. The unguarded residue

### 3.1 Mining and validation files

The grep from v4.5.0's checklist, run here (**measured**):

```
$ git diff ycash6-baseline...feature/yellowback -- src/main.cpp src/miner.cpp src/miner.h src/rpc/mining.cpp \
    | grep '^+' | grep -v 'g_yellowback\|#include\|LOCK(cs_main)\|COINBASE_FLAGS\|^+$\|^+++'
+            return state.DoS(0, false, REJECT_NONSTANDARD, "yellowback-vault-spend");
+    }
+            return state.DoS(0, error("%s: descends from a Yellowback-rejected block", __func__), REJECT_INVALID, "bad-prevblk-yellowback", BodyCorruption::HeaderOnly);
+    std::optional<yellowback::TemplateView> ybviewHolder;   // holds cs_yellowback until this frame ends, before LOCK2's release
+    // Yellowback TPL-1/2, last refusal before AddToBlock (only a turnstile violation follows, mapping §19)
+    if (ybview && !yellowback::policy::FilterTemplate(*ybview, iter->GetTx(), nHeight)) return false;
+            {
+                IncrementExtraNonce(pblocktemplate.get(), pindexPrev, nExtraNonce, chainparams.GetConsensus());
+            }
+namespace yellowback { class TemplateView; }
+    // Yellowback (TPL-1/2): the template's overlay view; points into CreateNewBlock's frame, valid only during it
+    yellowback::TemplateView* ybview = nullptr;
```

| Line(s) | Why it is not an unguarded behaviour change |
|---|---|
| `return state.DoS(0, false, … "yellowback-vault-spend")` | second line of V1; the first line is `if (yellowback::g_yellowback && …)` |
| `}` | closes V3's `if (yellowback::g_yellowback) {` |
| `return state.DoS(0, error(…), … "bad-prevblk-yellowback", HeaderOnly)` | second line of V6 |
| `std::optional<…TemplateView> ybviewHolder;` | an **empty** optional; it is engaged only on the next line, under `if (g_yellowback)` |
| the `// Yellowback TPL-1/2` comment | comment |
| `if (ybview && !…FilterTemplate(…)) return false;` | `ybview` is non-null only after M2's guarded `emplace` |
| `{` / `IncrementExtraNonce(…)` / `}` | the K17 `LOCK(cs_main)` scope; the call is the baseline's, byte for byte. `cs_main` is recursive and is not held by the `-gen` thread at this point |
| `namespace yellowback { class TemplateView; }` | forward declaration |
| the `miner.h` comment and `TemplateView* ybview = nullptr;` | a member that stays `nullptr` without the flag |

The excluded patterns cover:

- **three `#include` lines** (`main.cpp`, `miner.cpp`, `rpc/mining.cpp`);
- **the `+ COINBASE_FLAGS` append** (M1). Without the flag `COINBASE_FLAGS` is empty: it is assigned
  only at `miner.cpp:352`, which assigns `CScript()` when `g_yellowback` is null. The coinbase
  scriptSig is therefore the baseline's byte for byte.
- **`LOCK(cs_main)`** (M4).

**pending:** the unit test `coinbase_flags_empty_without_flag`, which proves this directly. It was
already missing on v4.5.0 (that review's finding R3), and `git grep` finds it in neither tree.

### 3.2 Startup, wallet tier and RPC surface

Each item below runs, or is visible, on a node started **without** `-yellowback`. None of them
touches validation, relay, mining or the chain state.

| Site | Observable without the flag | Justification |
|---|---|---|
| `init.cpp:403-425` help text; `:512` debug category | `ycashd -help` lists the `-yellowback*` options and the `yellowback` debug category | Documentation of an experimental flag, the same way `-atomicswaps` is listed. A byte-for-byte `-help` comparison against the stock binary will differ. |
| `init.cpp:1281-1286` H6 | Refuses to start when `<datadir>/yellowback` exists and neither `-yellowback` nor `-yellowback=0` is given | Inert on any datadir that never ran the overlay. On one that did, it stops a wallet holding YED from silently treating it as plain YEC. `-yellowback=0` is the explicit acknowledgement, and `-disablewallet` is exempt. |
| `init.cpp:1333-1339` | `InitError("Yellowback options require -yellowback.")` when a `-yellowback*` option is given without the flag | Fires only on a misconfiguration that names Yellowback. |
| `experimental_features.cpp` | `-yellowback` without `-experimentalfeatures` is refused, like `-atomicswaps` | The standard experimental-feature pattern. |
| `rpc/register.h:38` → `RegisterYellowbackRPCCommands` | none: the function returns at once when `!fExperimentalYellowback` (`src/rpc/yellowback.cpp:1947`) | `help` and the RPC surface stay the baseline's (v2 plan §8.3; proved on v4.5.0 by `yellowback_stock_node.py`). **pending:** that script on 6.20.0. |
| `rpc/common.h` 48 `yed_*` rows | none (§2.6: method lookup precedes the table) | — |
| `sendrawtransaction` (`rawtransaction.cpp:1254`, `:1279`; `common.h:121`) | accepts a third boolean argument (ignored) and documents `allowyedburn` in `help` | An argument that does nothing without the flag. Stock would refuse three arguments. Inherited from v4.5.0 H7. |
| `lockunspent` (`rpcwallet.cpp:2802-2804`, `:2853-2887`) | the help text mentions Yellowback. **Behaviour:** the list is validated completely before any lock changes, so a call with a malformed later entry now applies **none** of the entries, where the baseline applied the earlier ones and then threw | Strictly more conservative (all or nothing). Inherited from v4.5.0 H5. Recorded as finding V-5 so that nobody calls the wallet tier "byte-identical without the flag". |
| `transaction_builder.{h,cpp}` | `Build()` checks `tInsUnsigned.count(nIn)` for every transparent input; the set is empty unless `AddTransparentInputUnsigned` was called, and only `src/yellowback/` calls it | One `std::set` lookup per input; no change in output. |
| `rpcdump.cpp` `YellowbackReconcileOnExit` | its destructor runs on four import RPCs and does nothing when `g_yellowbackWallet` is null | — |

---

## 4. Safety properties and the evidence that exists now

### 4.1 Unit tests

The run is in §4.3 (**measured**: 226/226 Yellowback cases, 695/695 overall).

The 12 `src/test/yellowback_*_tests.cpp` files define **226** test cases (static count of
`BOOST_AUTO_TEST_CASE`/`BOOST_FIXTURE_TEST_CASE`, **measured**). That equals `ycash-dd`'s 226. Phase 2
**recorded** that all 226 pass and that the full `test_bitcoin` is green (plan execution status,
commit `05b7892dd`).

### 4.2 The properties

| Property | What it means here | Code | Evidence | State |
|---|---|---|---|---|
| **No consensus change** | No file that defines network rules differs from the baseline. The overlay can make an enforcing node *refuse* a block (V3, V6) but never accept one stock would refuse. | frozen set §1.3. V3 sits after every stock check, so it can only subtract. | `qa/yellowback-audit.sh` frozen set at zero; `DoS(` in the `main.cpp` diff is `DoS(0` 3 of 3; `git grep 'DoS([1-9]' -- src/yellowback 'src/rpc/yellowback*'` → no output | **measured** |
| **The soft-fork nature is unchanged** | Once activated, enforcing nodes reject blocks that stock nodes accept: a soft fork by the miners who opt in, not a "no consensus change" system. The trust statement in `doc/yellowback.md` says so. | `CheckConnect` (V3) | as v4.5.0; `doc/yellowback-spec.md`, `-rpc.md` and the contract JSON are byte-identical to `ycash-dd`'s (`shasum`, **measured**) | **measured** (documents); behaviour **pending:** `yellowback_enforcement.py` on 6.20.0 |
| **Fail-open** | Only a storage failure can make an enforcing node accept a block it would otherwise reject. The index then marks itself unhealthy and enforcement turns off. No rejection during IBD/`-reindex`/import, after the work valve trips, or once the network has built `VALVE_BLOCKS` on the block. | `CheckConnect`/`CommitConnect` in `src/yellowback/index.cpp` (ported verbatim apart from API renames, commit `05b7892dd`) | `yellowback_index_tests`: `check_storage_fault_accepts_and_sets_unhealthy`, `commit_storage_fault_sets_unhealthy`, `check_ibd_suppresses_reject`, `catchup_suppresses_reject`, `check_tripped_valve_never_rejects`, `check_null_hash`, `check_reverify` | unit: **measured** (§4.3). Functional (`yellowback_index.py` `rejected_survives_kill9`, `crash_unflushed_chainstate`): **pending: Phase 4** |
| **Totality of the state machine** | No `throw`, no `assert` on input; undefined means the rule is false | `src/yellowback/state.cpp` | `git grep -nE '\bthrow\b\|\bassert\(' -- src/yellowback/state.cpp` → no output; determinism grep over `state math.h tag payload script view` → no output; no sockets in `src/yellowback`/`src/rpc/yellowback*` | **measured**. Fuzz *runs*: **pending: Phase 6 `weekly-fuzz`** |
| **Never ban a peer** | DoS 0 for a rejected block and for its descendants | V3, V6 | greps above; `blk2_dos_level_zero` (unit) | grep **measured**; multi-node `banscore == 0` **pending:** `yellowback_enforcement.py` |
| **Switch-off: without `-yellowback`** | `g_yellowback == nullptr`: every hook is skipped, and the RPC surface and `getblocktemplate` are the baseline's | §2, §3 | the residue analysis in §3 | **measured** (by inspection of the full diff) |
| **Switch-off: kill switch** | `-yellowbackenforce=0` stops rejection and reconsiders stored rejected blocks at the next start | `init.cpp:2185-2264` | `yellowback_index.py` kill-switch steps | **pending: Phase 4**. Commit `50192cd1d` **records** that on 6.20.0 the kill switch takes its `ReconsiderBlock` branch after a clean restart |
| **Stock parity** | A `feature/yellowback` binary without `-yellowback` behaves exactly as the stock `ycash6-stock` binary over a scripted 300-block scenario | — | `qa/rpc-tests/yellowback_stockparity.py` and `yellowback_stock_node.py` exist on this branch (ported from v4.5.0) | **pending: Phase 4** (the coordinator's run against `wt/ycash6-stock/src/ycashd`). Known, expected differences: §3.2 (`-help`, `sendrawtransaction` arity, `lockunspent` atomicity) |
| **Shielded pool untouched** | The overlay reads only `vin`, `vout`, the `OP_RETURN` payload and the coinbase scriptSig. A rejection discards `view` before any flush. The undo runs after the Sprout, Sapling and Orchard rollback. | V2, V3; `ConnectTip` returns at baseline `:4499` before `assert(view.Flush())` `:4503` | the builder-method grep (§2.6); `src/gtest` at zero; frozen `src/rust/` at zero | **measured** (structure). `ycash-gtest --gtest_filter='TransactionBuilder*'` **pending** (not built here) |
| **Lock order** | `cs_main → cs_wallet → mempool.cs → cs_yellowback` | M2/M3, `rpcdump.cpp` H8 destructor | `qa/yellowback-lockorder-check.py`; the CI `lockorder` job (S3: `g_debug_lockorder_abort`) | **pending: Phase 6** (the job is `if: false` in `.github/workflows/yellowback-tests.yml`) |
| **Sanitizers, coverage** | ASan/UBSan/TSan clean; per-file coverage floors | — | CI `sanitizers`, `coverage` jobs | **pending: Phase 6** (both `if: false`) |

### 4.3 Measured unit-test run

Built in a clean worktree at `50192cd1d` (`src/ycashd --version` → `Ycash Daemon version
v6.20.0-50192cd1d`), run on 2026-09-30 (**measured**):

```
$ ./src/test/test_bitcoin --run_test='yellowback_*' --report_level=short
Running 226 test cases...
Test module "Bitcoin Test Suite" has passed with:
  226 test cases out of 695 passed
  469 test cases out of 695 skipped
  27229 assertions out of 27229 passed

$ ./src/test/test_bitcoin --report_level=short
Running 695 test cases...
Test module "Bitcoin Test Suite" has passed with:
  695 test cases out of 695 passed
  55242662 assertions out of 55242662 passed

$ ./src/test/test_bitcoin --run_test='yellowback_index_tests/mempoolcheck_bench' --log_level=message
MempoolCheck over 10000 plain transactions: 5963 us
*** No errors detected
```

All 226 Yellowback cases pass, as does the full suite of 695. That includes `miner_tests`, which
exercises the M1–M4 code path without the flag. The MP-1 cost is 0.6 µs per non-Yellowback
transaction on this host, the same as v4.5.0's 0.59 µs. Unlike v4.5.0's tree, which had two
pre-existing failures, the 6.20.0 baseline plus fixes has none. `ycash-gtest` was not built.

### 4.4 Functional suite

There are 24 `qa/rpc-tests/yellowback_*.py` scripts on this branch. `yellowback_reorg_stress.py` was
retired under decision P-7.

- `yellowback_framework_smoke.py`: **recorded** as passing (commit `05f345faa`).
- Every other script: **pending: Phase 4**, including `yellowback_index.py`,
  `yellowback_rpc_contract.py`, `yellowback_enforcement.py`, `yellowback_mining.py`,
  `yellowback_stockparity.py`, `yellowback_stock_node.py` and `yellowback_hardening.py`. They are
  being run in the coordinator's tree; none was run for this document.
- `yellowback_stratum.py` and `yellowback_chainviz.py` skip without their component binaries
  (Phase 7).

No functional result is counted as evidence in §4.2.

---

## 5. Findings specific to 6.20.0

### 5.1 From the port so far (plan §6, mapping §19)

| # | Finding | Disposition |
|---|---|---|
| F-1 | Defects at the pin `040894344b`: uninitialised coinbase Sapling anchor; harness `zcash.conf`; Equihash (192,7) on regtest under the Ycash upgrade; upstream branch ids in the harness; the ZIP-317 fee gate against `wallet_sapling.py`; NU5 inactive | Baseline fixes 1–3 (§1.5); the rest recorded in `doc/yellowback-baseline.md` |
| F-2 | Upstream `TransactionBuilder`'s move constructor moves `orchardSpendingKeys`, `firstOrchardSpendAddr` and `firstSaplingSpendAddr` from **itself**, not from the source (`transaction_builder.h:296-298`). A builder moved after `AddSaplingSpend` loses its first spend address. | The overlay constructs builders in place and never moves one. **Report upstream.** |
| F-3 | `main.h:332` still declares the free `GetBlockSubsidy(int, const Consensus::Params&)`, but 6.20.0 defines only `Consensus::Params::GetBlockSubsidy`, so a call fails at link time | The overlay calls the method. Upstream dead declaration. |
| F-4 | The RPC contract's `args` grammar omits the optional argument of `yed_getbalance` and `yed_listunspent` and the required one of `yed_sendmany` (a v4.5.0 documentation gap) | The arity rows are generated from the handlers' guards, not from the contract |
| F-5 | 6.20.0 has no keypool draw (`GetKeyFromPool` is gone), so the contract's `keypool-empty` error can no longer be raised; a locked wallet now fails with `wallet-locked` | Recorded. Contract text to be revisited only if `yellowback_rpc_contract.py` requires it. **pending** |
| F-6 | `CheckConnect` running on templates was thought to be new. v4.5.0 already did it through `TestBlockValidity` (`ref/ycash/src/miner.cpp:660`). | No new exposure (§2.1 V3a) |
| F-7 | v4.5.0's H8 did not guard `importwallet`, which imports spending keys and rescans | Guarded on this port (`rpcdump.cpp:397`) |
| F-8 | 6.20.0's `setmocktime` works only on a node started with a non-zero `-mocktime` (`rpc/misc.cpp:519`); v4.5.0 switched clocks on the first call. A fixed clock also freezes 6.20.0's transaction relay trickle. | Harness: one `clock_base` for all nodes; mock clock opt-in (commits `05f345faa`, `50192cd1d`) |
| F-9 | 6.20.0's mempool adds a Ycash per-Sapling-output fee floor beside ZIP-317 | The overlay's Sapling shapes stay within it. **pending:** the P-2 tests in Phase 6 |
| S1–S4 | Moved seams: the server-enforced RPC arity table; `BlockAssembler` with ZIP-317 selection; `g_debug_lockorder_abort`; the ZIP-244 builder precompute | §2.2 M3, §2.6; S3 **pending** with the `lockorder` job |
| — | `-feepolicy`, `-walletrequirebackup`, `-allowdeprecated`, `-preferredtxversion`, `BodyCorruption`, clang thread-safety annotations and `gbt_oldhashes` exist on 6.20.0 and not on v4.5.0 | Each is either addressed above (`BodyCorruption`: V-4) or **pending** its Phase 4–6 test (plan §1) |

### 5.2 Found while writing this document

These are not yet in mapping §19 or plan §6. The coordinator records them there.

**V-1 — The template filter commits its dry run before the turnstile check.** On a pass,
`FilterTemplate` calls `sub.Commit()` into the template's overlay (`src/yellowback/policy.cpp:125`).
In 6.20.0, one refusal follows it in `TestForBlock`: the ZIP-209 turnstile check (`miner.cpp:548+`).
If a Yellowback-relevant transaction passes the filter and then fails the turnstile, the template
overlay holds the effects of a transaction that is not in the block. Its own descendants are still
excluded (`isStillDependent`). Unrelated Yellowback candidates later in the same template, however,
would be judged against that phantom state.

The direction is fail-safe:

- a wrongly *accepted* candidate is still checked by `TestNewBlockAtTipValidity` →
  `CheckConnect`, which throws and yields no template, never an invalid block;
- a wrongly *refused* candidate waits for the next template.

The trigger needs a mempool transaction that violates a shielded-pool turnstile, which implies
counterfeiting. v4.5.0 had no refusal between the filter and `UpdateCoins`.

*Suggested disposition:* record and accept. The alternative — moving the filter below the turnstile
block — adds lines to `miner.cpp` for a case that cannot occur on a sound chain. The comment at
`miner.cpp:545` cites "mapping §19" for this, but the §19 S2 row does not yet mention the turnstile.

**V-2 — `lockunspent`'s unlock-all branch is unreachable on 6.20.0, and its help text says
otherwise.** 6.20.0's `rpcCvtTable` row for `lockunspent` is `{{o,o},{}}` (`rpc/common.h:174`): both
arguments are required, and the server refuses a one-argument call before the handler runs. So
`ReapplyLocks()` at `rpcwallet.cpp:2848` is dead code, and the H5 help sentence "Unlocking
everything (lockunspent true, with no second argument) still works and re-applies the Yellowback
locks" (`:2803-2804`) is false on this tree. The stock help already lists argument 2 as required.
Commit `50192cd1d` adapted the harness (`unlock_all()`) and the H5 hardening case to the same fact.

*Suggested disposition:* drop that one help sentence in a later wallet-tier commit. The dead branch
is harmless; keeping it keeps the hunk identical to v4.5.0.

**V-3 — H8's `rescanblockchain` site has no 6.20.0 counterpart.** v4.5.0 guarded `rescanblockchain`
(`ycash-dd src/wallet/rpcdump.cpp:116`). 6.20.0 has no such RPC; rescans happen inside the import
RPCs, all of which are guarded. Plan F-7's wording ("v4.5.0's H8 guarded `importprivkey`,
`importaddress`, `z_importkey`") omits this fourth v4.5.0 site.

*Suggested disposition:* correct F-7's wording. No code change.

**V-4 — `BodyCorruption` and the V3 verdict.** 6.20.0 marks a block failed only when the rejection
is not body-replaceable (§2.1 V3b). Analysis of `ConnectBlock` (`:3244` reset; `:3303`, `:3316`
set) shows that the Yellowback verdict at `:4047` is classed final on the `ConnectTip` path, as on
v4.5.0. Under `fJustCheck` it is classed body-replaceable, which is harmless.

*Suggested disposition:* a mapping §19 row. **pending:** the functional confirmation
(`yellowback_enforcement.py`: the rejected block is `BLOCK_FAILED_VALID`, its descendants are not
requested again, and the peer is not banned).

**V-5 — `lockunspent` is all-or-nothing on the fork, with or without `-yellowback`.** See §3.2. This
is inherited from v4.5.0 and is strictly more conservative than stock. It is recorded because the
stock-parity claim covers the chain and the RPC *surface*, not every wallet RPC's error-path side
effects.

**V-6 — `ybview` outlives its pointee.** The `BlockAssembler::ybview` member (`miner.h:133`) points
into `CreateNewBlock`'s stack frame and is not reset when the call returns. That is safe because:

- every `BlockAssembler` in the tree is a temporary used for exactly one `CreateNewBlock`
  (`miner.cpp:904`, `rpc/mining.cpp:226`, `:715`, `test/miner_tests.cpp`);
- `TestForBlock` is reached only from inside that call.

A future caller that reused one `BlockAssembler` would still be safe, because `CreateNewBlock`
reassigns the member. Only a call to `TestForBlock` from outside `CreateNewBlock` would read a
dangling pointer.

*Suggested disposition:* none. Noted for the reviewer.

---

## 6. What this document does **not** claim

- **That the functional suite passes on 6.20.0.** Only `yellowback_framework_smoke.py` is recorded
  as passing. Every multi-node property (enforcement, the never-ban proof, the valve, the kill
  switch, reorg equality, stock parity) is **pending: Phase 4**.
- **That stock parity holds mechanically.** §3 is an argument from the full diff. The mechanical
  proof, `yellowback_stockparity.py` against the `ycash6-stock` binary, has not been run here, and
  §3.2 lists differences it should be expected to tolerate or report.
- **That the devnet demonstration (plan §4) has run.** It has not: Phase 5 has not started, and the
  §4 transcript the plan requires is not attached.
- **That any CI job beyond `audit` has run.** `main`, `agent`, `python`, `nightly`, `lockorder`,
  `sanitizers`, `coverage` and `weekly-fuzz` are disabled (`if: false && …`) until their phase
  enables them. Whether `audit` itself has run on GitHub for `origin/feature/yellowback` was not
  checked (no `gh` on this host). Its local mirror passes (§1.1).
- **ZIP-317 / mempool-limit interaction, the P-2 fee floor, `IsExpiringSoonTx`.** These are Phase 6
  items. The overlay still pays a flat 1000 zat. 6.20.0's defaults admit and mine it (recorded in
  plan Phase 2), but it ranks below conventional-fee transactions.
- **Fuzzing.** Only corpus replays inside `test_bitcoin` exist. No fuzz *run* has been performed on
  6.20.0.
- **The §8.4 25-item checklist of the v2 plan, re-scored for 6.20.0.** Not done here: most of its
  items depend on the pending functional and CI evidence above. Re-score it when Phase 6 closes.
- **Anything about mainnet**: hashpower, pool adoption, the launch bar, or the economics. Those
  belong to the pool operators and the product owner. The trust statement in `doc/yellowback.md`
  (byte-locked to the spec's §8.1) is the normative text.
- **A review of the 6.20.0 rebase itself.** This document reviews the Yellowback delta against
  `ycash6-baseline`. The rebase from v4.5.0 to 6.20.0 is miodragpop's work and is outside its scope,
  except for the three baseline defects found while exercising it (§1.5).

---

## 7. Reproducing

From a worktree of `boyfromcave/ycash6` on `feature/yellowback` with the tag `ycash6-baseline`
fetched:

```bash
export PATH="/opt/homebrew/opt/libtool/libexec/gnubin:/opt/homebrew/opt/coreutils/libexec/gnubin:/opt/homebrew/bin:$PATH"
export CARGO_TARGET_DIR="$PWD/target" LIBTOOLIZE=glibtoolize
./autogen.sh && CONFIG_SITE="$PWD/depends/aarch64-apple-darwin25.0.0/share/config.site" ./configure --quiet
# 6.20.0 trap: generate the cxx bridge headers before any target-only make
awk '/^CXXBRIDGE_H = /{f=1;next} f&&/^ *rust\/gen/{gsub(/[ \\]/,"");print;next} f{exit}' src/Makefile.am | xargs make -C src -j6
make -C src -j6 ycashd ycash-cli test/test_bitcoin

# §1  budgets, frozen set, RPC arity rows
qa/yellowback-audit.sh
git diff --numstat ycash6-baseline...feature/yellowback
git diff --shortstat ycash6-baseline...feature/yellowback
git diff --stat ycash6-baseline...feature/yellowback -- src/sync.cpp src/wallet/asyncrpcoperation_sendmany.cpp \
    src/test/main_tests.cpp src/test/net_tests.cpp src/wallet/test/rpc_wallet_tests.cpp src/rpc/client.cpp src/gtest

# §1.5  the baseline fixes
git show --stat 940987c51 141df8d48 e98128239 8808258cd
git merge-base --is-ancestor e98128239 ycash6-baseline || echo "fix 3 is inside the measured diff"

# §2  the hooks
git diff ycash6-baseline...feature/yellowback -- src/main.cpp src/miner.cpp src/miner.h src/rpc/mining.cpp src/chainparams.cpp
git diff ycash6-baseline...feature/yellowback -- src/init.cpp src/rpc/rawtransaction.cpp src/wallet/rpcwallet.cpp \
    src/wallet/rpcdump.cpp src/transaction_builder.h src/transaction_builder.cpp src/rpc/common.h
git log ycash6-baseline..feature/yellowback          # the four-part checks are in the commit messages

# §3.1  the residue
git diff ycash6-baseline...feature/yellowback -- src/main.cpp src/miner.cpp src/miner.h src/rpc/mining.cpp \
    | grep '^+' | grep -v 'g_yellowback\|#include\|LOCK(cs_main)\|COINBASE_FLAGS\|^+$\|^+++'
git grep -n 'COINBASE_FLAGS =' -- src

# §4  greps
git diff ycash6-baseline...feature/yellowback -- src/main.cpp | grep '^+' | grep -o 'DoS([0-9]*' | sort | uniq -c
git grep -n 'DoS([1-9]' -- src/yellowback 'src/rpc/yellowback*'
git grep -nE '\bthrow\b|\bassert\(' -- src/yellowback/state.cpp
git grep -nE 'GetTime|GetArg|\brand\b|\bdouble\b|\bfloat\b|mempool|chainActive' -- src/yellowback/state.cpp \
    src/yellowback/math.h src/yellowback/tag.cpp src/yellowback/payload.cpp src/yellowback/script.cpp src/yellowback/view.cpp
git grep -nE 'evhttp|socket\(|\bconnect\(|curl' -- src/yellowback 'src/rpc/yellowback*'
git grep -n 'AddTransparentInputUnsigned\|AddTransparentOutput(.*CScript\|SetLockTime' -- src \
    ':!src/transaction_builder.*' ':!src/yellowback' ':!src/test'

# §4.3  unit tests
./src/test/test_bitcoin --run_test='yellowback_*'
./src/test/test_bitcoin

# §4.4  functional (unique --portseed and --tmpdir per concurrent run)
ZCASHD=$PWD/src/ycashd REF_YCASHD=<path to the ycash6-stock build>/src/ycashd \
  ../.venv/bin/python -u qa/rpc-tests/yellowback_<x>.py --srcdir=$PWD/src --tmpdir=<dir> --portseed=<n>
```

The crosswalk (`docs/mapping.md` §19), the plan (`docs/plans/yellowback-ycash6-plan.md`) and the
normative spec live in the workspace, outside this fork.
