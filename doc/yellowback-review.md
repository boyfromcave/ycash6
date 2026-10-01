# Ycash Yellowback (YED) on ycashd 6.20.0 — review package

For the Ycash maintainers, and for miodragpop as the author of the 6.20.0 rebase this port sits on.
It answers one question: **what does the Yellowback overlay change in ycashd 6.20.0, and what
evidence is there that the change is safe?** It is written fresh for this tree (plan decision P-6).
The v4.5.0 review package (`ycash-dd/doc/yellowback-review.md`, branch
`feature/yellowback-price-attest`) remains the record for the v4.5.0 line and is not restated here.

**What was measured, and where.** Every number marked *measured* below was taken on branch
`feature/yellowback` of `boyfromcave/ycash6` at commit **`df409ade8`** on 2026-10-01, on macOS 26 /
Apple Silicon, against the tag **`ycash6-baseline`** (`8808258cd`). That tag is miodragpop's
`dev-rebase-6.20.0` @ `040894344b` plus two baseline fixes and one baseline document (§1.5). A first
draft of this document was written at `50192cd1d` (commit `bdffa67eb`); this revision supersedes it.
Commands are in §9.

**Read the evidence markers literally.**

- **measured** — the command was run for this revision at `df409ade8` and its output is quoted or
  summarised.
- **recorded** — the result comes from a commit message, a run log of the integration tree, or the
  plan's execution-status table, and was not re-run for this revision. Each such claim names its
  source.
- **pending: <what>** — the evidence does not exist yet. Nothing marked pending is counted as passing.

**Status of the port at `df409ade8`** (plan `docs/plans/yellowback-ycash6-plan.md`, revision 3):
Phases 0–5 are complete. Phase 6's gates are green **locally** (lockorder, ASan/UBSan, TSan,
coverage floors, fuzz), but their CI jobs are still disabled. The §4 demonstration has a
transcript-producing script (`yellowback_demo_v6.py`) and is being run by the coordinator; its
transcript goes in §8. Phase 7 compatibility has been verified for lightwalletd-dd, yolo, chain-viz
and YEW against 6.20.0 on their own branches (§4.5); none of those branches is merged. §7 lists what
this document does **not** claim.

Citation conventions:

- `src/x.cpp:N` without a prefix is the 6.20.0 fork at `df409ade8`.
- "baseline `:N`" is the same file at `ycash6-baseline`.
- `ref/ycash/…:N` is stock Ycash v4.5.0 (`624c12814`); `ref/ycash6/…:N` is the 6.20.0 pin.
- `ycash-dd …:N` is the v4.5.0 Yellowback fork (`feature/yellowback-price-attest`).

---

## 1. Diff budget — actuals

### 1.1 The budgeted mining/validation files

`qa/yellowback-audit.sh` (**measured**, exit status 0):

```
frozen set: zero delta vs ycash6-baseline
src/main.cpp            19 changed lines (budget 40)
src/miner.cpp           14 changed lines (budget 35)
src/miner.h              4 changed lines (budget 10)
src/rpc/mining.cpp       7 changed lines (budget 35)
src/chainparams.cpp      4 changed lines (budget 4)
rpc/common.h: 48 yed_* rows current
```

Every step of the CI `audit` job (frozen set and budgets; determinism, clock, socket and ban greps;
documents; v2 gates; rule → test tags, v2 and v3 identifiers) was also run locally from
`.github/workflows/yellowback-tests.yml` at this commit: **all exit 0** (**measured**).

| File | Budget (plan §2) | +/− | Changed | v4.5.0 fork (`ycash-dd` vs `ycash-legacy`) | Verdict |
|---|---|---|---|---|---|
| `src/main.cpp` | ≤ 40 | +19 / −0 | **19** | +11 / −0 | within budget; the same 11 lines plus 8 for the headers-loop skip (V7, §2.1) |
| `src/miner.cpp` | ≤ 35 | +12 / −2 | **14** | +10 / −2 | within budget; +2 for the `BlockAssembler` seam (S2) |
| `src/miner.h` | ≤ 10 | +4 / −0 | **4** | — (no `BlockAssembler` in v4.5.0) | within budget; new in this port |
| `src/rpc/mining.cpp` | ≤ 35 | +7 / −0 | **7** | +7 / −0 | within budget, the same 7 lines |
| `src/chainparams.cpp` | = 4 | +4 / −0 | **4** | 0 | exactly the budget; this is **baseline fix 3, not Yellowback** (§1.5) |

### 1.2 Every pre-existing file the port changes

`git diff --numstat ycash6-baseline...feature/yellowback`, restricted to files that exist at the
baseline (**measured**):

| File | +/− | Tier | What |
|---|---|---|---|
| `src/main.cpp` | +19 / −0 | node, hook | six hooks + one include + the headers-loop skip (§2.1) |
| `src/miner.cpp` | +12 / −2 | node, hook | tag, template view, filter, scriptSig append, K17 lock (§2.2) |
| `src/miner.h` | +4 / −0 | node, hook | forward declaration + `ybview` member (§2.2) |
| `src/rpc/mining.cpp` | +7 / −0 | node, RPC | four `getblocktemplate` insertions + include (§2.3) |
| `src/chainparams.cpp` | +4 / −0 | **baseline fix 3** | regtest Equihash guard (§1.5, §2.4) |
| `src/init.cpp` | +193 / −2 | node, startup | help, step-3 checks, index construction, kill switch (with its flush), shutdown, registration (§2.5) |
| `src/rpc/rawtransaction.cpp` | +23 / −3 | wallet tier | H7 `allowyedburn` (§2.6) |
| `src/wallet/rpcwallet.cpp` | +20 / −1 | wallet tier | H5 `lockunspent` (§2.6) |
| `src/wallet/rpcdump.cpp` | +19 / −0 | wallet tier | H8 reconcile after import (§2.6) |
| `src/transaction_builder.cpp` | +18 / −0 | wallet tier | I2 extension, S4 (§2.6) |
| `src/transaction_builder.h` | +16 / −0 | wallet tier | I2 extension, S4 (§2.6) |
| `src/rpc/common.h` | +51 / −1 | RPC table | S1: 48 `yed_*` arity rows + `sendrawtransaction` (§2.6) |
| `src/experimental_features.{h,cpp}` | +7 / −0 | build/flag | the `-yellowback` experimental flag |
| `src/rpc/register.h` | +5 / −0 | build | two registration declarations, one call |
| `src/Makefile.am`, `src/Makefile.test.include` | +49 / −1 | build | new sources and tests |
| `qa/pull-tester/rpc-tests.py` | +39 / −2 | test runner | Yellowback scripts listed; `--cachedir`/`--portseed` precedence |
| `qa/rpc-tests/test_framework/script.py` | +1 / −1 | test framework | the signed `valueBalance` pack (`'<q'`), as on v4.5.0 |
| `doc/yellowback-baseline.md` | +55 / −0 | doc | the inherited-suite record (findings 7–10), appended after the tag |

Everything else in the diff is a new file under `src/yellowback/`, `src/rpc/yellowback*.cpp`,
`src/rpc/yellowbackrpc.h`, `src/test/yellowback_*` (plus `src/test/data/yellowback_*.json` and the
two `gen_yellowback_*.py` generators), `src/fuzzing/Yellowback*/`, `qa/rpc-tests/yellowback_*.py`,
`qa/rpc-tests/test_framework/{yellowback*,test_yellowback_*,SERIALISATION.md}`, `qa/yellowback-*`,
`contrib/yellowback/`, `doc/yellowback*`, and `.github/workflows/yellowback-tests.yml`.

**Whole-fork totals** (**measured**): 629 files, **+78,071 / −13**. All 13 deleted lines are
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

- `src/sync.cpp` (the lockorder job patches the CI checkout's copy at run time instead, §4.2);
- `src/wallet/asyncrpcoperation_sendmany.cpp`;
- `src/test/main_tests.cpp`, `src/test/net_tests.cpp`, `src/wallet/test/rpc_wallet_tests.cpp`;
- `src/rpc/client.cpp`. Its v4.5.0 `vRPCConvertParams` rows (+44) became the `rpc/common.h`
  rows (S1).

### 1.5 The baseline fixes: **not Yellowback**

At the pin, 6.20.0 did not build a block template reliably on this platform, and its own test
harness could not start a node. The fixes below are separate commits that never mix with
Yellowback code. Each is a candidate upstream patch for miodragpop: they are prepared as
`upstream-report/report.md` + `patches/0001-0003` (each `git apply --check` clean on `040894344b`)
and **not sent**; the owner decides when. The full record is in `doc/yellowback-baseline.md`.

| Commit | +/− | Inside `ycash6-baseline`? | What and why |
|---|---|---|---|
| `940987c51` baseline fix: zero-initialise the coinbase Sapling anchor in the miner | `src/miner.cpp` +3 / −3 | **yes**: not in the measured diff | All three coinbase paths passed an **uninitialised** `std::array<uint8_t,32> saplingAnchor` to `sapling::new_builder`. The Rust side rejects bytes that are not a canonical field element ("Invalid Sapling anchor"), so whether a block template could be built depended on stack contents. On this platform, `miner_tests/CreateNewBlock_validity` and `tx_validationcache_tests/tx_mempool_block_doublespend` failed deterministically, and `getblocktemplate`/`generate` failed once a Sapling spend was in the mempool. A coinbase bundle has no spends, so its anchor is unconstrained, and all-zero is canonical. Inherited from upstream zcashd `fd675c320`. After the fix the full `test_bitcoin` is green. |
| `141df8d48` baseline fix: qa harness writes ycash.conf and defaults to src/ycashd | `multi_rpc.py`, `test_framework/util.py`, `wallet_deprecation.py`, +5 / −5 | **yes**: not in the measured diff | `ycashd` refuses to start without `ycash.conf` (`src/util/system.cpp:82`). The inherited harness wrote `zcash.conf` and looked for `src/zcashd`, so all 147 inherited functional tests died in `initialize_chain`. Test-only. |
| `e98128239` baseline fix 3: regtest keeps Equihash (48,5) under every network upgrade | `src/chainparams.cpp` +4 / −0 | **no**: committed after the tag, so its 4 lines are the whole `chainparams.cpp` budget in §1.1 | v4.5.0 returned the regtest (48,5) parameters before consulting the upgrade table (`ref/ycash/src/chainparams.cpp:860-869`). 6.20.0's `GetEquihashOverride()` applies the Ycash upgrade's (192,7) on every network. Activating the mainnet epoch on regtest (six upgrades at height 1, Canopy branch id) therefore cost about 5 minutes per block. The guard is regtest-only (`NetworkIDString() == REGTEST`); mainnet and testnet do not reach it. Owner decision P-1(a): the port has to be proven at the epoch mainnet actually runs (Canopy). The stock comparison binary is built from branch `ycash6-stock` (`e98128239`, all three fixes) for the same reason. |
| `8808258cd` doc: baseline exercise | `doc/yellowback-baseline.md` +69 | yes (it is the tagged commit) | The record of the exercise: build, regtest smoke, findings 1–6. Findings 7–10 (the inherited suite) were appended later in `f6ba1037f` (§1.2). |

**Not fixed, recorded only** (`doc/yellowback-baseline.md` findings 4–10): the harness's
upstream-Zcash branch ids (`util.py:41-44`); the per-output fee policy against `wallet_sapling.py`'s
ZIP-317 fee and the absurd-fee message that prints the total (findings 5, 10); the shielding
privacy-policy message; `-lightwalletd` without `-insightexplorer` crashing on the first block (7);
`RewindBlockIndex` keeping never-connected invalid entries across restarts (8, upstream Ycash
`1770fce16` — the root of findings F-18, F-25 and both flush fixes in §2); NU6.x regtest protocol
versions above `PROTOCOL_VERSION` (9).

---

## 2. The hook table

Every hook in a mining or validation file is an **insertion**. Every statement that changes
behaviour is guarded by `yellowback::g_yellowback`, which is `nullptr` (`src/yellowback/index.cpp:31`)
unless `init.cpp:2190` constructs it under `fExperimentalYellowback`. That flag is set only by
`-experimentalfeatures -yellowback`.

The four-part check (AGENTS.md rule 4) is applied to the **v4.5.0 → 6.20.0 move**: *v4.5.0 put
hook X at Y; 6.20.0 kept or moved that seam to Z; so the adaptation is W.* Why each carried-over
hook exists at all — the DigiByte → Ycash four-part check and the tier argument — was settled for
v4.5.0 and is in `ycash-dd/doc/yellowback-review.md` §2 and mapping §13. It is not re-argued here,
because the behaviour is unchanged. The three sites that are **new on 6.20.0** (V7, the kill-switch
flush, the valve flush) get the full check, including the tier.

### 2.1 `src/main.cpp` — 19 lines

| # | 6.20.0 fork | Baseline anchor | v4.5.0 (`ref/ycash` anchor → `ycash-dd` hook) | Guard |
|---|---|---|---|---|
| V0 | `:40` `#include "yellowback/index.h"` | — | `ycash-dd :39` | none needed (declaration only) |
| V1 | `:1891-1892` MP-1 in `AcceptToMemoryPool` | after `view.SetBackend(dummy)` `:1889` | `ref/ycash :1643` → `ycash-dd :1645-1646` | `g_yellowback &&` |
| V2 | `:3161` undo at the end of `DisconnectBlock` | before `return fClean ? …` `:3158` | `ref/ycash :2796` → `ycash-dd :2799` | `updateIndices && g_yellowback` |
| V3 | `:4047-4049` `CheckConnect` in `ConnectBlock` | before `if (fJustCheck)` `:4043` | `ref/ycash :3194` → `ycash-dd :3198-3200` | `if (g_yellowback) {…}` |
| V4 | `:4123` `CommitConnect` | after `view.SetBestBlock(pindex->GetBlockHash())` `:4115` | `ref/ycash :3268` → `ycash-dd :3276` | `g_yellowback` |
| V5 | `:4526` `RemoveInvalidVaultSpends` in `ConnectTip` | after `mempool.removeExpired(…)` `:4517` | `ref/ycash :3636` → `ycash-dd :3645` | `g_yellowback` |
| V6 | `:5976-5977` BLK-2 descendant clause in `AcceptBlockHeader` | first statement inside `if (hash != genesis)` `:5966` | `ref/ycash :4552` → `ycash-dd :4562-4563` | `g_yellowback &&` |
| **V7** | `:8623-8630` ACT-7 headers-loop skip in `ProcessMessage("headers")` | inside `if (!AcceptBlockHeader(…))`, after `int nDoS;` `:8611` | **none** (new on 6.20.0, `b9b3e6556`) | `g_yellowback && !ValveTripped() && <reason>` |

**V1, MP-1.** *v4.5.0* placed the relay-policy check after the inputs were cached and the view was
switched back to the dummy backend. *6.20.0 kept* `AcceptToMemoryPool` monolithic in `main.cpp`,
with the same `view.SetBackend(dummy)` statement (baseline `:1889`). *Adaptation:* none. The two
lines are byte-identical to v4.5.0. The refusal is `DoS(0, …, REJECT_NONSTANDARD)`, which is
policy only. ZIP-317's unpaid-action gate (baseline `:1973-1981`) runs *after* MP-1; the builders
now price themselves at the conventional fee (P-2, §2.7), and `yellowback_fee.py` proves the
carrier, a mint, a transfer and a redemption are relayed and mined by nodes with
`-txunpaidactionlimit=0` / `-blockunpaidactionlimit=0` (**recorded**, integration run
`fee rc=0`, `fee_armed rc=0`).

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
  CheckAs::BlockTemplate)` through `TestNewBlockAtTipValidity` (`miner.cpp:477`, `main.cpp:6262`;
  `pindex` is an `indexDummy`). This is **not** new exposure. v4.5.0 also ran its own template
  through `TestBlockValidity` (`ref/ycash/src/miner.cpp:660`). See finding F-6.
- **(b) Body-corruption classification.** A `DoS` raised with the default `BodyCorruption::Default`
  is classed "body-replaceable", and the block is **not** marked `BLOCK_FAILED_VALID`
  (`InvalidBlockFound`, baseline `:2602-2615`), unless both commitment flags have been set in this
  pass. `ConnectBlock` resets them at entry (baseline `:3244`), and `CheckBlock` (`:3303`, which
  checks the Merkle root when `!fJustCheck`) and `CheckBlockBodyAuthCommitment` (`:3316`) set them
  **before** the hook. So on the `ConnectTip` path a Yellowback verdict is final and marks the block
  failed, exactly as on v4.5.0. Under `fJustCheck` the verdict is classed corruption-possible, which
  has no effect: a template or proposal check writes nothing to the block index. Finding V-4.

*Adaptation:* none; the three lines are byte-identical. The multi-node proof that a rejected block
stays `BLOCK_FAILED_VALID`, that its descendants are refused at DoS 0 and that no peer is banned is
`yellowback_enforcement.py` and `yellowback_attest_enforcement.py`, both green on the integration
tree after the valve fix (**recorded**: plan execution status, 1233 s and 1035 s; V-4 resolved).

**V4, the commit.** *v4.5.0*: directly after `view.SetBestBlock`, which is after every write in
`ConnectBlock` that can `AbortNode`. It is never reached under `fJustCheck`, because V3's early
return comes first. *6.20.0 kept* the statement (baseline `:4115`). The 6.20.0 block-commitment and
chain-history work happens earlier, in `CheckBlockBodyAuthCommitment`. *Adaptation:* none.

**V5, the mempool sweep.** *v4.5.0*: after `removeExpired` in `ConnectTip`. *6.20.0 kept* it
(baseline `:4517`). *Adaptation:* none. The sweep removes through the stock
`CTxMemPool::remove` (`src/yellowback/index.cpp:767`), which is also what keeps 6.20.0's
`-mempooltxcostlimit` bookkeeping consistent (`limitSet->remove`, `src/txmempool.cpp:653`,
**measured** by inspection). `-mempooltxcostlimit` already existed at v4.5.0
(`ref/ycash/src/init.cpp:425`; finding V-8). **pending:** a functional case that runs the sweep on a
mempool at its cost limit (no script does today; `yellowback_fee.py` covers the unpaid-action
limits only).

**V6, the BLK-2 descendant clause.** *v4.5.0*: the first check on a non-genesis header, before both
stock `bad-prevblk` refusals. It answers with DoS 0 where stock would answer DoS 100 for a child of
a failed block. *6.20.0 kept* the structure (baseline `:5966-5980`). It added a `BodyCorruption`
argument to every header-path `DoS`, and its two `bad-prevblk` neighbours pass `HeaderOnly`.
*Adaptation:* the clause passes `BodyCorruption::HeaderOnly` too. This is the **only edited token**
among the carried-over `main.cpp` hooks, and the classification is correct: the verdict depends on
the header's ancestry, never on the body.

**V7, the ACT-7 headers-loop skip** (new on 6.20.0, `b9b3e6556`, merged `eca70db09`; finding F-25):

```cpp
            if (!AcceptBlockHeader(header, state, chainparams, &pindexLast)) {
                int nDoS;
+               // Yellowback ACT-7: read on past the rejected block and its refused descendants so the
+               // odometer sees every header (6.20.0 fetches blocks only after their headers).
+               if (yellowback::g_yellowback && !yellowback::g_yellowback->ValveTripped() &&
+                   (state.GetRejectReason() == "bad-prevblk-yellowback" ||
+                    (state.GetRejectReason() == "duplicate" && yellowback::g_yellowback->IsRejectedAncestor(pindexLast)))) {
+                   pindexLast = NULL;
+                   continue;
+               }
                if (state.IsInvalid(nDoS)) {
```

- **v4.5.0 (X / Y / M):** the work valve (ACT-7) measures how much work the network has built on a
  block this node rejected, through V6's `NoteHeaderOnRejectedChain`. v4.5.0 fed it through the
  `inv` handler's direct block fetch: every announced block was `getdata`'d at once and reached
  `AcceptBlockHeader` through `ProcessNewBlock` → `AcceptBlock`, one note per block
  (`ref/ycash/src/main.cpp:6270-6292`).
- **6.20.0 (Z, lacks M):** the `inv` handler only sends `getheaders`
  (`ref/ycash6/src/main.cpp:8303-8330`); blocks are fetched only once their headers are in the
  index. The `headers` loop abandons the whole message at the first refused header, so a reply
  `[R+1, R+2, …]` stopped at `R+1` (refused at DoS 0 by V6) and `R+2…` never reached the odometer.
  After a restart it was worse: 6.20.0 keeps the failed never-connected entry (Ycash `1770fce16`),
  `pindexBestHeader` is recomputed to the tip, and the reply opens with the rejected block itself,
  refused as `duplicate`, so nothing was noted at all. The valve never tripped (F-23).
- **Adaptation (W):** while the valve is untripped, a header refused as `bad-prevblk-yellowback`, or
  a known header refused as `duplicate` that `IsRejectedAncestor` traces to a Yellowback-rejected
  root, is skipped instead of ending the message. `pindexLast` is reset so the stock continuity
  check does not fire on the refused run.
- **Tier:** node net code, no consensus rule. What any node accepts is unchanged; only how much of
  one `headers` message the odometer reads. The cheaper-looking alternative, restoring v4.5.0's
  direct fetch, would change stock block download for every block on every node.

*Why it is safe.*

- Both refusals it skips are already DoS 0, and the stock path for them returns
  `error("invalid header received")` without `Misbehaving`. Skipping changes no ban score.
- It acts only under `g_yellowback` and only while the valve is untripped. Once the valve trips,
  `Rejected` is cleared and the stock abort applies again, so the stock chain is accepted from the
  next announcement.
- Every skipped header has already passed `CheckBlockHeader` (proof of work) inside
  `AcceptBlockHeader`. The note map is capped per root (`VALVE_NOTE_CAP` = 64), and one message
  carries at most `MAX_HEADERS_RESULTS` headers, as in stock.
- `ValveTripped()` reads a plain `bool` without `cs_yellowback`. The loop holds `cs_main`, and the
  only writer (`TripValve`, `src/yellowback/index.cpp:590`) asserts `cs_main`, so the read is
  ordered. `IsRejectedAncestor` takes `cs_yellowback` under `cs_main`, the recorded order.
- If the last header of a message was skipped, `pindexLast` is `NULL` after the loop: no
  `UpdateBlockAvailability`, no follow-up `getheaders`. That is the same outcome as the stock abort.

*Residual effects* (finding V-7): the header **after** a skipped one is not checked for continuity,
so a peer that follows a Yellowback-refused header with a non-continuous one loses the stock
`Misbehaving(20)` for that message. Every such header is still fully validated by
`AcceptBlockHeader`. F-25's open item also stands: a refused run longer than `VALVE_NOTE_CAP` meets
the stock `prev block not found` DoS 10 (`main.cpp:5980`), as on v4.5.0.

*Evidence* (**recorded**): `yellowback_enforcement.py` case 9 (`case9_work_valve`) trips the valve
on 6.20.0, including after a restart of node 3 with the rejection live (the `1770fce16` regression
guard), and `yellowback_attest_enforcement.py` reuses it; both fail on the pre-fix binary and pass
after it (commit `b9b3e6556`, plan execution status). Unit: the three `// Rule: ACT-7` cases in
`yellowback_index_tests.cpp` (`:971`, `:1042`, `:1075`).

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
- no other writer of `COINBASE_FLAGS` exists: `git grep 'COINBASE_FLAGS ='` returns only `:352`
  (**measured**).

**M3, the template filter (seam S2).** *v4.5.0* filtered each candidate in the priority loop,
**before** `UpdateCoins`, so that a skipped transaction's descendants could not see phantom coins.
*6.20.0 moved* transaction selection to ZIP-317 weighted-random sampling in `addTransactions` →
`TestForBlock` → `AddToBlock` (baseline `:493-690`), and a candidate with an unconfirmed parent
waits in `waiting` until that parent is added (`isStillDependent`, baseline `:663-666`). *Adaptation:*
the filter becomes a `return false` in `TestForBlock`, after the size, sigop, finality and expiry
refusals. A refused parent is never added, so its children never leave `waiting`. That property is
structural in 6.20.0, and it is what "before `UpdateCoins`" used to provide. The only refusal
after the filter is the ZIP-209 turnstile check: see finding V-1. The `TemplateView` RAII holder
(`cs_yellowback`) lives in `CreateNewBlock`'s frame and is declared after `LOCK2`, so it is
released before `mempool.cs` and `cs_main`. That matches the recorded order `cs_main → cs_wallet →
mempool.cs → cs_yellowback`. `TestForBlock` reaches the holder through the raw `ybview` member
(M5; finding V-6).

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
response is the baseline's, key for key: `yellowback_mining.py`'s `gbt_shape_without_flag`
(`qa/rpc-tests/yellowback_mining.py:132`) passes on 6.20.0 with the stock key set updated for the two
new keys (**recorded**: `50192cd1d`, `966d8d746`; integration run `mining rc=0`). The pool-facing
consequences of 6.20.0's template (header commitments by upgrade, F-29) are in
`doc/yellowback-mining.md` §3.1.

### 2.4 `src/chainparams.cpp` — 4 lines (baseline fix 3)

The two `if (NetworkIDString() == CBaseChainParams::REGTEST) return consensus.nEquihash{N,K};`
guards are in `CChainParams::EquihashN/K` (fork `:984-985`, `:993-994`; baseline `:983`, `:990`).
*v4.5.0* had the same guard (`ref/ycash/src/chainparams.cpp:860-862`). *6.20.0 dropped* it when it
introduced `GetEquihashOverride()`. *Adaptation:* restore it in the two accessors that both the
miner and `ContextualCheckBlockHeader` read, so mining and validation agree. The guard is not
Yellowback; it is listed in §1.5.

### 2.5 `src/init.cpp` — +193 / −2

The five v4.5.0 blocks are carried byte for byte (commit `6d5c176a7`), plus one new call (the
kill-switch flush, `83e6c1cb2`). They sit at these 6.20.0 anchors:

| 6.20.0 fork | Baseline anchor | v4.5.0 `ycash-dd` | What | Guard |
|---|---|---|---|---|
| `:45-48` | after `#include "validationinterface.h"` | `:42-45` | includes | — |
| `:211-216` | `Shutdown()`, after `StopHTTPServer()` `:206` | `:216-221` | unregister, `Stop()`, `Flush(true)` | `if (g_yellowback)` |
| `:403-426` | `HelpMessage`, after `-txindex` `:392` | `:417-440` | help text for every `-yellowback*` option | **none** (§3.2) |
| `:512` | the single debug-category string `:478` | `:520`, `:523` (v4.5.0 had two strings) | adds `yellowback` | **none** (§3.2) |
| `:1274-1341` | step 3, before `RegisterAllCoreRPCCommands` `:1240` | `:1141-1207` | H6 datadir check; option validation; "options require -yellowback" | H6 runs without the flag (§3.2); the rest `if (fExperimentalYellowback)` |
| `:1345-1350` | wallet RPC registration `:1243-1244` | `:1253-1258` | `RegisterYellowbackWalletRPCCommands` | `if (fExperimentalYellowback)` |
| `:2185-2269` | after `RewindBlockIndex`/`VerifyDB`, before the notifier thread `:2078` | `:1937-2015` | index construction, `SyncToChain`, kill-switch `ReconsiderBlock` loop **with `FlushStateToDisk()` at `:2256`**, `RegisterValidationInterface`, wallet attach | `if (fExperimentalYellowback)` |

*6.20.0 kept* the `AppInit2` step order. Its change at these anchors is that the debug categories
became a single string. *Adaptation:* one edited string. `ActivateBestChain`'s arity was checked in
Phase 3.

**The kill-switch flush** (`:2251-2256`, new on 6.20.0, `83e6c1cb2`):

- **v4.5.0:** with `-yellowbackenforce=0`, startup calls `ReconsiderBlock` on every block in
  `Rejected`, then `ClearRejected()`. On v4.5.0 the loop only ever took its "not in the block
  index; skipped" branch, because `RewindBlockIndex` had already erased every never-connected
  entry. The node re-downloaded the block fresh, so there was no failure flag to persist.
- **6.20.0:** keeps such entries (Ycash `1770fce16`), so the loop now reaches `ReconsiderBlock`,
  whose cleared flags live only in `setDirtyBlockIndex` until the next periodic flush.
  `ClearRejected()` commits the record's erasure at once. A crash in between left a failure flag on
  disk and no record to undo it, and the node was stuck even when restarted with
  `-yellowbackenforce=0` again. `yellowback_index.py`'s `attest_tables_survive_kill9` hit exactly
  that ("Block sync failed", node 3, block 527).
- **Adaptation:** `FlushStateToDisk()` after the reconsider and `ActivateBestChain`, and before
  `ClearRejected()`. A crash after the flush and before the clear keeps the records with the marks
  already cleared, and the next start reconsiders again (idempotent).
- **Tier:** 0. It is the startup path, outside consensus, and `init.cpp` is neither frozen nor
  budgeted. One call, taken outside `cs_main`'s scope as `FlushStateToDisk` expects.
- **Evidence** (**recorded**): `yellowback_index.py` passes on the integration tree (1178 s, plan
  execution status) and failed deterministically without the call, on the release, `--enable-debug`
  and ASan binaries alike (commit messages `83e6c1cb2`, `db91a1975`).

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

**H5 — `lockunspent`** (`src/wallet/rpcwallet.cpp:33` include, `:2802-2803` help, `:2844-2848`
`ReapplyLocks`, `:2853` and `:2872-2883` two-pass loop with the `yed-locked-outpoint` refusal at
`:2876-2877`).

- *v4.5.0*: `ref/ycash/src/wallet/rpcwallet.cpp:2187` → `ycash-dd :2199-2280`.
- *6.20.0 kept* the handler (baseline `:2790`). Its `rpcCvtTable` row `{{o,o},{}}` makes the second
  argument **required**.
- *Adaptation:* the same hunk, less the help sentence about the one-argument form (dropped in
  `966d8d746`). The unlock-all branch is now unreachable (finding V-2).

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

### 2.7 Overlay-internal changes since the draft that affect node state

These are in files that are new in this port (`src/yellowback/`, `src/rpc/yellowback*.cpp`), so no
budget applies. They are listed because each changes what the node writes or relays under
`-yellowback`, and each has its four-part check in its commit message.

**The valve flush** (`src/yellowback/index.cpp:604-609`, `eda580983`):

- **v4.5.0:** `TripValve` reconsiders every `Rejected` block, then erases the records and commits
  them (`db->Commit(true)`). The same code was safe there, because `RewindBlockIndex` erased the
  never-connected entry at the next start.
- **6.20.0:** keeps the entry and its `FAILED` mark, and the periodic block-index write is an hour
  away (`DATABASE_WRITE_INTERVAL`). A `kill -9` after a trip reloaded `BLOCK_FAILED_VALID` with no
  record left. The restarted node refused the rejected block as `duplicate` 1372 times in 3 minutes
  and never left its pre-trip tip.
- **Adaptation:** `FlushStateToDisk()` after the `ReconsiderBlock` loop and before the erase. A crash
  between the two keeps the records with the marks cleared, so the re-armed node re-rejects on
  reconnect: the pre-trip state, which is safe.
- **Tier:** 0. Overlay file, one call.
- **Locks.** `TripValve` runs from `AcceptBlockHeader` (the headers loop, `AcceptBlock`, the
  `-reindex` import) with `cs_main` and `cs_yellowback` held. `FlushStateToDisk`'s
  `LOCK2(cs_main, cs_LastBlockFile)` re-enters the recursive `cs_main` and adds only the edge
  `cs_yellowback → cs_LastBlockFile`. That lock's four holders (`FlushBlockFile`, `FindBlockPos`,
  `FindUndoPos`, `FindFilesToPrune`) never call into the overlay. The flush emits no validation
  signal and makes no wallet call. Flushing under `cs_main` mid-header-processing is what
  `ActivateBestChain`'s periodic flush already does. A trip happens at most once per process
  (enforcement is off until restart), so the I/O cost is bounded.
- **Evidence** (**recorded**): `valve_trips_at_six_blocks` now reads the entry back from
  `pblocktree` and checks the mark is clear on disk. `yellowback_enforcement.py` case 9 kills node 3
  with `-9` after the trip and requires it to rejoin; that step fails on the pre-fix binary.

**The carrier witness wait** (`src/rpc/yellowbackwallet.cpp:374-386`, `308bb3fbe`, finding F-27).
`CarrierConfirmed()` now also requires every wallet Sapling note of the carrier to carry a witness.
`ThreadNotifyWallets` syncs a block's transactions before `ChainTip` increments witnesses, with
`cs_wallet` free in between. The race was latent on v4.5.0
(`ref/ycash/src/validationinterface.cpp:210-217`), and 6.20.0 widens the window. Wallet tier only.

**P-2, the network fee** (`src/yellowback/txbuilder.{h,cpp}`, `NetworkFee` at `txbuilder.h:246`;
`dfa630717`):

- every builder now pays `max(-yellowbackfee, CalculateConventionalFee(logical actions))` and
  reprices its coin selection until the fee covers the shape it selects;
- vault spends take the fee from the collateral;
- the enforcement fee (`FEE_MIN`/`feeBps`), rpcversion and the contract JSON are unchanged. Only
  `doc/yellowback-rpc.md` gains a paragraph (finding V-10).

Wallet tier only. The builders' expiry guard (`CheckExpiry`, `txbuilder.cpp:388-393`) already
refuses to build a transaction that `IsExpiringSoonTx` would refuse: `nExpiryHeight` must be at
least `chainHeight + 1 + TX_EXPIRING_SOON_THRESHOLD` (finding V-8).

---

## 3. The unguarded residue

### 3.1 Mining and validation files

The grep from v4.5.0's checklist, run here (**measured**; the CI `audit` job's "v2 gates" step
prints the `main.cpp` part of the same list):

```
$ git diff ycash6-baseline...feature/yellowback -- src/main.cpp src/miner.cpp src/miner.h src/rpc/mining.cpp \
    | grep '^+' | grep -v 'g_yellowback\|#include\|LOCK(cs_main)\|COINBASE_FLAGS\|^+$\|^+++'
+            return state.DoS(0, false, REJECT_NONSTANDARD, "yellowback-vault-spend");
+    }
+            return state.DoS(0, error("%s: descends from a Yellowback-rejected block", __func__), REJECT_INVALID, "bad-prevblk-yellowback", BodyCorruption::HeaderOnly);
+                // Yellowback ACT-7: read on past the rejected block and its refused descendants so the
+                // odometer sees every header (6.20.0 fetches blocks only after their headers).
+                    (state.GetRejectReason() == "bad-prevblk-yellowback" ||
+                    pindexLast = NULL;
+                    continue;
+                }
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
| `}` (first) | closes V3's `if (yellowback::g_yellowback) {` |
| `return state.DoS(0, error(…), … "bad-prevblk-yellowback", HeaderOnly)` | second line of V6 |
| the two `// Yellowback ACT-7` comment lines | comment |
| `(state.GetRejectReason() == "bad-prevblk-yellowback" \|\|`, `pindexLast = NULL;`, `continue;`, `}` | continuation and body of V7's `if (yellowback::g_yellowback && !…ValveTripped() && …`; its third line (the `duplicate` clause) contains `g_yellowback` and is filtered out |
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
  scriptSig is therefore the baseline's byte for byte. This is proved directly by the unit test
  `coinbase_flags_empty_without_flag` (`src/test/yellowback_index_tests.cpp:1268`,
  `// Rule: MINER-1`). It checks `g_yellowback == nullptr`, `COINBASE_FLAGS.empty()`, and that both
  appends equal the stock scriptSig at every BIP34 push-width boundary. The draft of this document
  said the test existed in neither tree; that was wrong (finding V-9). The test is green in the
  228-case run (§4.1, **recorded**).
- **`LOCK(cs_main)`** (M4).

### 3.2 Startup, wallet tier and RPC surface

Each item below runs, or is visible, on a node started **without** `-yellowback`. None of them
touches validation, relay, mining or the chain state.

| Site | Observable without the flag | Justification |
|---|---|---|
| `init.cpp:403-426` help text; `:512` debug category | `ycashd -help` lists the `-yellowback*` options and the `yellowback` debug category | Documentation of an experimental flag, the same way `-atomicswaps` is listed. A byte-for-byte `-help` comparison against the stock binary will differ. |
| `init.cpp:1281-1286` H6 | Refuses to start when `<datadir>/yellowback` exists and neither `-yellowback` nor `-yellowback=0` is given | Inert on any datadir that never ran the overlay. On one that did, it stops a wallet holding YED from silently treating it as plain YEC. `-yellowback=0` is the explicit acknowledgement, and `-disablewallet` is exempt. |
| `init.cpp:1333-1339` | `InitError("Yellowback options require -yellowback.")` when a `-yellowback*` option is given without the flag | Fires only on a misconfiguration that names Yellowback. |
| `experimental_features.cpp` | `-yellowback` without `-experimentalfeatures` is refused, like `-atomicswaps` | The standard experimental-feature pattern. |
| `rpc/register.h:38` → `RegisterYellowbackRPCCommands` | none: the function returns at once when `!fExperimentalYellowback` (`src/rpc/yellowback.cpp:1947`) | `help` and the RPC surface stay the baseline's. `yellowback_stock_node.py` passes on 6.20.0 (**recorded**, integration run `stock_node rc=0`). |
| `rpc/common.h` 48 `yed_*` rows | none (§2.6: method lookup precedes the table) | — |
| `sendrawtransaction` (`rawtransaction.cpp:1254`, `:1279`; `common.h:121`) | accepts a third boolean argument (ignored) and documents `allowyedburn` in `help` | An argument that does nothing without the flag. Stock would refuse three arguments. Inherited from v4.5.0 H7. |
| `lockunspent` (`rpcwallet.cpp:2802-2803`, `:2853`, `:2872-2883`) | the help text mentions Yellowback. **Behaviour:** the list is validated completely before any lock changes, so a call with a malformed later entry now applies **none** of the entries, where the baseline applied the earlier ones and then threw | Strictly more conservative (all or nothing). Inherited from v4.5.0 H5. Finding V-5, so that nobody calls the wallet tier "byte-identical without the flag". |
| `transaction_builder.{h,cpp}` | `Build()` checks `tInsUnsigned.count(nIn)` for every transparent input; the set is empty unless `AddTransparentInputUnsigned` was called, and only `src/yellowback/` calls it | One `std::set` lookup per input; no change in output. |
| `rpcdump.cpp` `YellowbackReconcileOnExit` | its destructor runs on four import RPCs and does nothing when `g_yellowbackWallet` is null | — |

V7 (§2.1) and both flushes (§2.5, §2.7) are unreachable without the flag: V7 starts with
`g_yellowback &&`, the kill-switch block is inside `if (fExperimentalYellowback)`, and `TripValve`
is a member of the object that only exists under the flag.

The mechanical form of §3 is stock parity, which is now proved three ways (**recorded**):

- `yellowback_stockparity.py`: a `feature/yellowback` binary without `-yellowback` against the
  `ycash6-stock` binary, 300 blocks with transactions and a reorg, "300 blocks, 11 comparison
  points, all equal" (integration run log, F-24);
- `yellowback_stock_node.py` green;
- the inherited suite: all 42 stock-baseline scripts pass on the fork binary without `-yellowback`
  (F-28). `getblocktemplate_longpoll` was then dropped from CI because it flakes on **any** binary
  (`ed9bcfcc7`); 41 scripts plus the `--mineblock` variant now gate CI.

Expected and tolerated differences are the rows of the table above (`-help`, `sendrawtransaction`
arity, `lockunspent` atomicity) and the per-node fields F-20 and F-21.

---

## 4. Safety properties and the evidence

### 4.1 Unit tests

The 12 `src/test/yellowback_*_tests.cpp` files define **228** test cases (static count of
`BOOST_AUTO_TEST_CASE`/`BOOST_FIXTURE_TEST_CASE`, **measured**). That is `ycash-dd`'s 226 plus the
two P-2 fee cases (`dfa630717`).

Runs (**recorded**; none re-run for this revision):

| Run | Result | Source |
|---|---|---|
| draft, `50192cd1d`, release | 226/226 Yellowback, 695/695 overall; MP-1 cost 0.6 µs per plain tx (`mempoolcheck_bench`) | the draft's §4.3, measured then |
| integration tree after P-2 + armed + kill-switch merges, release | full `test_bitcoin`: 697 cases, "No errors detected" | integration log, 2026-10-01 |
| `--enable-debug` (`DEBUG_LOCKORDER`, `AssertLockHeld` live) | 228/228 Yellowback, after `6f65d2bc9` took the locks the test asserts require | `6f65d2bc9` message; lockorder run log |
| ASan + UBSan | 228/228, no sanitizer report | sanitizer run log |
| TSan | unit run (233 cases incl. the debug-only extras), no ThreadSanitizer warning | sanitizer run log |

`ycash-gtest` was not built on this host (§4.2 "Shielded pool").

### 4.2 The properties

| Property | What it means here | Code | Evidence | State |
|---|---|---|---|---|
| **No consensus change** | No file that defines network rules differs from the baseline. The overlay can make an enforcing node *refuse* a block (V3, V6) but never accept one stock would refuse. | frozen set §1.3. V3 sits after every stock check, so it can only subtract. V7 changes only which DoS-0 refusals end a `headers` message. | `qa/yellowback-audit.sh` frozen set at zero; `DoS(` in the `main.cpp` diff is `DoS(0` 3 of 3; `git grep 'DoS([1-9]' -- src/yellowback 'src/rpc/yellowback*'` → no output | **measured** |
| **The soft-fork nature is unchanged** | Once activated, enforcing nodes reject blocks that stock nodes accept: a soft fork by the miners who opt in, not a "no consensus change" system. The trust statement in `doc/yellowback.md` says so. | `CheckConnect` (V3) | `doc/yellowback-spec.md` and `doc/yellowback-rpc-contract.json` byte-identical to `ycash-dd`'s (`shasum`, **measured**); `doc/yellowback-rpc.md` differs only by P-2's fee paragraph (V-10); the audit "Documents" step passes (**measured**). Behaviour: `yellowback_enforcement.py`, `yellowback_attest_enforcement.py` green (**recorded**) | **measured** (documents); **recorded** (behaviour) |
| **Fail-open** | Only a storage failure can make an enforcing node accept a block it would otherwise reject. The index then marks itself unhealthy and enforcement turns off. No rejection during IBD/`-reindex`/import, after the work valve trips, or once the network has built `VALVE_BLOCKS` on the block. | `CheckConnect`/`CommitConnect`, `TripValve` in `src/yellowback/index.cpp` | unit: `check_storage_fault_accepts_and_sets_unhealthy`, `commit_storage_fault_sets_unhealthy`, `check_ibd_suppresses_reject`, `catchup_suppresses_reject`, `check_tripped_valve_never_rejects`, `valve_trips_at_six_blocks`, `check_null_hash`, `check_reverify`. Functional: `yellowback_index.py` (`rejected_survives_kill9`, `crash_unflushed_chainstate`, `attest_tables_survive_kill9`); `yellowback_enforcement.py` case 9 (valve trips, incl. after restart and after `kill -9`) | **recorded** (unit and functional green). Open: F-25's refused run > 64 headers (§2.1 V7) |
| **Totality of the state machine** | No `throw`, no `assert` on input; undefined means the rule is false | `src/yellowback/state.cpp` | `git grep -nE '\bthrow\b\|\bassert\(' -- src/yellowback/state.cpp` → no output; determinism grep over `state math.h tag payload script view` → no output; no sockets in `src/yellowback`/`src/rpc/yellowback*` (**measured**). Fuzz: six targets (`YellowbackBundle`, `Evaluate`, `Payee`, `Payload`, `Script`, `Tag`) built with libFuzzer + ASan and run 61 s each, 163k–473k executions per target, no crash (**recorded**: fuzz run logs, `14ec0c171`, `ca452e719`) | **measured** (greps); **recorded** (fuzz) |
| **Never ban a peer** | DoS 0 for a rejected block and for its descendants | V3, V6, V7 | greps above (**measured**); `blk2_dos_level_zero` (unit); `assert_banscore_zero` over every node in `yellowback_enforcement.py` (`:142`, `:271-276`) | **recorded** (multi-node `banscore == 0` green) |
| **Switch-off: without `-yellowback`** | `g_yellowback == nullptr`: every hook is skipped, and the RPC surface and `getblocktemplate` are the baseline's | §2, §3 | the residue analysis in §3 (**measured**); stock parity (§3.2, **recorded**) | **measured** + **recorded** |
| **Switch-off: kill switch** | `-yellowbackenforce=0` stops rejection and reconsiders stored rejected blocks at the next start, durably | `init.cpp:2185-2269`, flush `:2256` | `yellowback_index.py` kill-switch steps (`killswitch_fresh_datadir`, `killswitch_rejected_hash_not_in_mapblockindex`) and `attest_tables_survive_kill9` | **recorded**. On 6.20.0 the kill switch takes its `ReconsiderBlock` branch (F-18); the flush makes that branch crash-safe (`83e6c1cb2`) |
| **Stock parity** | A `feature/yellowback` binary without `-yellowback` behaves exactly as the stock `ycash6-stock` binary | — | §3.2: `yellowback_stockparity.py` (300 blocks), `yellowback_stock_node.py`, the inherited suite 42/42 on the fork binary | **recorded**. Known, expected differences: §3.2 |
| **Shielded pool untouched** | The overlay reads only `vin`, `vout`, the `OP_RETURN` payload and the coinbase scriptSig. A rejection discards `view` before any flush. The undo runs after the Sprout, Sapling and Orchard rollback. | V2, V3; `ConnectTip` returns at baseline `:4499` before `assert(view.Flush())` `:4503` | builder-method grep (§2.6), `src/gtest` at zero, frozen `src/rust/` at zero (**measured**); `yellowback_sapling.py` green unarmed and `--armed` (**recorded**) | **measured** (structure). **pending:** `ycash-gtest --gtest_filter='TransactionBuilder*'` (not built on this host) |
| **Lock order** | `cs_main → cs_wallet → mempool.cs → cs_yellowback`; the valve flush adds `cs_yellowback → cs_LastBlockFile` only | M2/M3, H8 destructor, `TripValve` | debug-build lockorder run: the suite under `--enable-debug` with the log-only patch (`qa/yellowback-lockorder-logonly.sh`; `sync.cpp` stays at zero in the tree), `qa/yellowback-lockorder-check.py` re-derived for 6.20.0's log format. One new non-deadlocking pair allow-listed: `mempool.cs`/`cs_inventory`, both sides under `cs_main` (`518b97a31`) | **recorded** (green locally). **pending:** the CI `lockorder` job (still `if: false`) |
| **Sanitizers, coverage** | ASan/UBSan/TSan clean; per-file coverage floors | — | ASan+UBSan and TSan clean (§4.1); coverage floors met with the functional suite included, `wallet.cpp` at exactly its 80 % floor (plan revision 3). The unit-only run alone is below the floors for `index`, `policy`, `txbuilder`, `wallet` and the RPC files, as expected | **recorded** (green locally). **pending:** the CI `sanitizers`, `coverage` and `weekly-fuzz` jobs (all `if: false`; the runner glibc question in the plan) |

### 4.3 Functional suite

There are 26 `qa/rpc-tests/yellowback_*.py` scripts on this branch (**measured**).
`yellowback_reorg_stress.py` was retired under decision P-7. Results are **recorded** from the plan's
execution status (revision 3) and the integration tree's run logs (2026-10-01); none was re-run for
this revision.

| Scripts | Result |
|---|---|
| `activation`, `index` | green (1380 s, 1178 s) after `33b6a6059` (harness: refresh peer download state after a network-wide `invalidateblock`, F-22) and `83e6c1cb2` (kill-switch flush) |
| `enforcement`, `attest_enforcement` | green after the valve fix `b9b3e6556` (F-23/F-25), with case 9's restart and post-trip `kill -9` (`eda580983`) |
| `attest`, `attest_wallet`, `claim`, `framework_smoke`, `hardening`, `lifecycle`, `mining`, `pricefeed`, `quote`, `rpc_contract`, `sapling`, `stock_node`, `stockparity`, `void_mint`, `wallet_lifecycle`, `wallet_restore` | green |
| `fee` (P-2) | green unarmed and `--armed` |
| `--armed` runs | `lifecycle`, `void_mint`, `claim`, `sapling`, `wallet_restore`, `fee` green (`308bb3fbe` fixed the one armed failure) |
| `demo_v6` | green on the integration tree (plan Phase 4 note); the run of record is §8 |
| `attest_agent`, `devnet_roles` (all three presets, ~39 min) | green (Phase 5, `d1d1ac9e5`) |
| `chainviz` | green on ycash6 with `CHAINVIZ_BIN` from chain-viz `feature/ycash6` (seeds 480, 481) |
| `stratum` | **pending:** a run with `YOLO_BIN` from yolo `feature/ycash6`. The yolo regtest grid is green on ycash6 (§4.5), but this script's run is not recorded |

The plan counts these as "all 19 scripts + `yellowback_fee`". The suite rows above name 20 scripts
including `framework_smoke` (V-11).

**pending:** `--armed` runs of the remaining armed-capable scripts. Plan §4's last criterion asks
for "all `yellowback_*.py` scripts pass unarmed and `--armed`", and only the six above are recorded
armed.

### 4.4 CI

| Job | State at `df409ade8` |
|---|---|
| `audit` | live; every step green locally (**measured**, §1.1) |
| `python` | live (`5576005b0`) |
| `main`, `agent`, `nightly`, `lockorder`, `sanitizers`, `coverage`, `weekly-fuzz` | defined and adapted for 6.20.0, still prefixed `if: false &&` (**measured**). **pending:** switch-on and first green runs. Their local equivalents are green (§4.2), but the plan's §8.4 items 23–24 ask for CI runs |

Whether the live jobs have run green on GitHub for `origin/feature/yellowback` was not checked (no
`gh` on this host).

### 4.5 Component compatibility (Phase 7, **recorded** from the plan's Phase 7 notes)

None of these component branches is merged; each waits for Phase 6 to close.

- **lightwalletd-dd**, no code change: `scripts/devnet-test.sh` against the 6.20.0 devnet passes
  the byte-equality gate (232 compact blocks + `GetLightdInfo` identical to the yodl baseline), the
  no-Yellowback baseline test, and wallet and raw mints seen through the server. Still to do:
  `GetTreeState` at a height with a shielded note.
- **yolo**, branch `feature/ycash6`: the header root is taken by upgrade (`defaultroots` →
  `blockcommitmentshash` → old hashes; F-29), and the regtest test uses `-mocktime` (F-8). `cargo
  test` 47 green; the regtest grid is 6/6 on v4.5.0, on ycash6, and on ycash6 with
  `-allowdeprecated=none`.
- **chain-viz**, branch `feature/ycash6`: revenue attribution works without `foundersaddress`.
  `yellowback_chainviz.py` (a)–(g) is green on ycash6 and on v4.5.0 with identical revenue totals.
  Still to do: a devnet session with `invalidateblock` reorgs and a restart.
- **YEW**, branch `feature/ycash6`: the M1 integration flow passes against the 6.20.0 devnet
  through lightwalletd-dd ("All tests passed!"). One test-timing fix was needed for 6.20.0's slower
  relay (`aebaf9a`).
- **yecwallet-dd**: **pending**. The survey found three certain breaks (`z_importivk` argument
  order, `importprivkey`'s fourth argument, `rescanblockchain`/`getrescaninfo` removed), and the
  version-aware-calls decision is open.

---

## 5. Findings

### 5.1 Plan §6 findings F-1 … F-29 (mirrored in mapping §19)

| # | Finding | Disposition at `df409ade8` |
|---|---|---|
| F-1 | Defects at the pin `040894344b`: uninitialised coinbase Sapling anchor; harness `zcash.conf`; Equihash (192,7) on regtest under the Ycash upgrade; upstream branch ids in the harness; the ZIP-317 fee gate against `wallet_sapling.py`; NU5 inactive | Baseline fixes 1–3 (§1.5); the rest recorded in `doc/yellowback-baseline.md`; upstream patches prepared, not sent |
| F-2 | Upstream `TransactionBuilder`'s move constructor moves three fields from **itself**, not from the source (`transaction_builder.h:296-298`) | The overlay constructs builders in place and never moves one. **Report upstream** |
| F-3 | `main.h:332` declares a free `GetBlockSubsidy` that 6.20.0 no longer defines | The overlay calls the method. Upstream dead declaration |
| F-4 | The RPC contract's `args` grammar omits three arguments (a v4.5.0 documentation gap) | Arity rows are generated from the handlers' guards |
| F-5 | No keypool draw on 6.20.0: `keypool-empty` can no longer be raised; a locked wallet fails with `wallet-locked` | Recorded; `yellowback_rpc_contract.py` passes with the contract unchanged, so no contract edit was needed |
| F-6 | `CheckConnect` on templates is not new (v4.5.0 ran `TestBlockValidity`) | No new exposure (§2.1 V3a) |
| F-7 | v4.5.0's H8 missed `importwallet`; 6.20.0 has no `rescanblockchain` | `importwallet` guarded (`rpcdump.cpp:397`); wording corrected (V-3) |
| F-8 | `setmocktime` needs a non-zero `-mocktime` at start | Harness: one `clock_base`, mock clock opt-in |
| F-9 | Per-Sapling-output fee floor beside ZIP-317 | Within it; P-2 builders price both (§2.7) |
| F-10, F-11 | Apple git ERE has no `\b`; BSD grep BRE alternation with `$` | `git grep -P`, `grep -E` (`5576005b0`); local audit equals CI |
| F-12 | `rpc-tests.py` silently drops an unregistered name | Audit registration check (`5576005b0`, extended in `c67a94090`) |
| F-13 | `mininode.py` imports `asyncore` (gone in Python 3.12) | CI on Python 3.11; venv keeps the backport |
| F-14 | A fixed mock clock freezes 6.20.0's tx relay trickle | Mock clock opt-in; framework nudges the clock |
| F-15 | `lockunspent` requires both arguments on 6.20.0 | Harness `unlock_all()`; H5 hardening asserts the refusal; help text fixed (V-2) |
| F-16 | GBT gains `blockcommitmentshash` and `defaultroots` | Stock key set updated; stockparity compares `defaultroots` |
| F-17 | The Rust Sapling builder pads to two outputs | Three count assertions expect two |
| F-18 | The kill switch takes its `ReconsiderBlock` branch (failed never-connected entries survive restarts, Ycash `1770fce16`) | Scripts accept either branch; made crash-safe by the kill-switch flush (§2.5) |
| F-19 | `coinbasetxn.foundersreward` only during the YDF mandate; `ydfpercentage`, `foundersaddress` gone | Stockparity reads it with `get()`; chain-viz and yolo adapted on their branches |
| F-20, F-21 | `getinfo.errorstimestamp` and `defaultroots.merkleroot` are per-node | Excluded from the stockparity compare |
| F-22 | Block sync stalled after a restart / network-wide `invalidateblock` (stock 6.20.0 download state; v4.5.0 passed only by its direct fetch) | **resolved**: harness `refresh_peer_views()` (`33b6a6059`) for `activation`; the kill-switch flush (`83e6c1cb2`) for `index`; both green. The plan §6 row still reads "open" (V-11) |
| F-23, F-25 | The work valve never tripped on 6.20.0 (headers-first relay; the headers loop aborts at the first refusal) | **fixed** by V7 (`b9b3e6556`); `main.cpp` 19/40. **Open:** a refused run longer than `VALVE_NOTE_CAP` (64) meets stock DoS 10 at `main.cpp:5980`, as on v4.5.0 |
| F-24 | Stockparity after round 2 | **resolved**: 300 blocks, all equal |
| F-26 | Devnet timings (blocks settle in ~2 s), port overlap, teardown leak, `assert_walk` race | `d1d1ac9e5`; no node change |
| F-27 | `CarrierConfirmed` raced `ThreadNotifyWallets` (Sapling change note unwitnessed) | **fixed** (`308bb3fbe`, §2.7) |
| F-28 | Inherited suite parity 42/42 on the fork binary; `getblocktemplate_longpoll` flakes on any binary | Dropped from CI (`ed9bcfcc7`); 41 + `--mineblock` gate CI |
| F-29 | Pre-Heartwood, `defaultroots` does not carry the header commitment | `doc/yellowback-mining.md` §3.1; yolo takes the header value by upgrade |

### 5.2 Review findings V-1 … V-6 (from the draft; dispositions as recorded in plan §6)

**V-1 — The template filter commits its dry run before the turnstile check.** On a pass,
`FilterTemplate` calls `sub.Commit()` into the template's overlay (`src/yellowback/policy.cpp:125`).
In 6.20.0, one refusal follows it in `TestForBlock`: the ZIP-209 turnstile check (`miner.cpp:548+`).
If a Yellowback-relevant transaction passes the filter and then fails the turnstile, the template
overlay holds the effects of a transaction that is not in the block. Its own descendants are still
excluded (`isStillDependent`), but unrelated Yellowback candidates later in the same template would
be judged against that phantom state.

The direction is fail-safe. A wrongly *accepted* candidate is still checked by
`TestNewBlockAtTipValidity` → `CheckConnect`, which throws and yields no template, never an invalid
block. A wrongly *refused* candidate waits for the next template. The trigger needs a mempool
transaction that violates a shielded-pool turnstile, which implies counterfeiting.

*Disposition:* **accepted**; the mapping §19 S2 row records it.

**V-2 — `lockunspent`'s unlock-all branch is unreachable on 6.20.0** (`rpcCvtTable` `{{o,o},{}}`,
`rpc/common.h:174`), so `ReapplyLocks()` at `rpcwallet.cpp:2847` is dead code.

*Disposition:* the false help sentence was **dropped** (`966d8d746`). The dead branch is kept, so the
hunk stays identical to v4.5.0.

**V-3 — H8's `rescanblockchain` site has no 6.20.0 counterpart.**

*Disposition:* F-7's wording corrected; no code change.

**V-4 — `BodyCorruption` and the V3 verdict.** Final on the `ConnectTip` path, body-replaceable
(harmlessly) under `fJustCheck` (§2.1 V3b).

*Disposition:* **resolved** by `yellowback_enforcement.py` and `yellowback_attest_enforcement.py`
green on 6.20.0.

**V-5 — `lockunspent` is all-or-nothing on the fork, with or without `-yellowback`** (§3.2).

*Disposition:* recorded. Stock parity covers the chain and the RPC surface, not every wallet RPC's
error-path side effects.

**V-6 — `ybview` outlives its pointee.** `BlockAssembler::ybview` (`miner.h:133`) points into
`CreateNewBlock`'s frame and is not reset. That is safe because every `BlockAssembler` is a one-shot
temporary (`miner.cpp:904`, `rpc/mining.cpp:226`, `:715`, `test/miner_tests.cpp`), and
`CreateNewBlock` reassigns the member.

*Disposition:* none; noted for the reviewer.

### 5.3 Found while finishing this document

These are not yet in mapping §19 or plan §6. The coordinator records them there.

**V-7 — V7 drops the continuity check for the header after a skipped one.** `pindexLast = NULL`
(`main.cpp:8628`) keeps the stock `non-continuous headers sequence` check from firing on the
refused run itself. It also means the *next* header in the same message is not checked for
continuity, so a peer could follow a Yellowback-refused header with an unrelated one without the
stock `Misbehaving(20)`. Every such header is still fully validated by `AcceptBlockHeader`. Only a
ban-score signal is lost, only under `-yellowback`, and only while the valve is untripped and a
rejection is live.

*Suggested disposition:* record and accept. Tracking the refused run's last hash instead would add
lines to `main.cpp` to restore a DoS signal on a path that already answers DoS 0.

**V-8 — `-mempooltxcostlimit` and `IsExpiringSoonTx` are not new in 6.20.0, and the Phase 6 item
that names them is only partly tested.** Plan §1 lists both as 6.20.0 features that interact with
the overlay, but both exist at v4.5.0 (`ref/ycash/src/init.cpp:425`, `ref/ycash/src/main.cpp:741`).
What 6.20.0 changed is the limiter's internals (`limitSet`, `recentlyEvicted`). The sweep goes
through the stock `CTxMemPool::remove`, which maintains `limitSet` (`src/txmempool.cpp:653`). The
builders refuse to build anything `IsExpiringSoonTx` would refuse (`CheckExpiry`,
`src/yellowback/txbuilder.cpp:388-393`).

The plan's Phase 6 checkbox "ZIP-317 and mempool-limit interaction tests … done by P-2"
over-claims: `yellowback_fee.py` covers the unpaid-action limits only, and no script runs
`RemoveInvalidVaultSpends` against a mempool at its cost limit (`git grep mempooltxcostlimit --
qa/rpc-tests/yellowback*` → nothing).

*Suggested disposition:* reword the checkbox, and either add a small case (a vault spend made
invalid by a new tip while the mempool is at `-mempooltxcostlimit`) or accept on the structural
argument above. Marked **pending** in §2.1 V5.

**V-9 — `coinbase_flags_empty_without_flag` exists; the draft said it did not.** It was transplanted
in Phase 1 (`7bcd38ff1`) at `src/test/yellowback_index_tests.cpp:1268`, tagged `// Rule: MINER-1`.
Its comments still cite v4.5.0 line numbers (`miner.cpp:328`, `:725`, `:370`); on 6.20.0 they are
`:289`, `:788` and `:352`.

*Suggested disposition:* refresh the three citations in a later test-only commit. §3.1 is corrected.

**V-10 — `doc/yellowback-rpc.md` is no longer byte-identical to `ycash-dd`'s.** P-2 (`dfa630717`)
added the fee paragraph. `doc/yellowback-spec.md` and `doc/yellowback-rpc-contract.json` are still
identical (`shasum`, **measured**). The draft's §4.2 claimed all three were identical, which was
true at `50192cd1d`.

*Suggested disposition:* none. The contract, which is the interface, is unchanged. The rpc.md
change is documentation of P-2.

**V-11 — Plan bookkeeping.** These are coordinator items, not defects in the tree:

- Plan §6's F-22 row still reads "open — agent act-sync", while the execution status records
  `activation` and `index` green.
- The plan's "19 scripts" names 20 including `framework_smoke` (§4.3).
- The Phase 6 lockorder line cites `49a9f2a9a`, the branch commit. The merged commits are
  `518b97a31` and `6f65d2bc9`; `49a9f2a9a` and `f0b521f72` are on `yb6/lockorder` only.
- `yb6/lockorder` also carries `db91a1975`, a second, unmerged copy of the kill-switch flush that
  `83e6c1cb2` already merged. **That commit must not be merged**: it would add a second
  `FlushStateToDisk()` call.

---

## 6. The v2 §8.4 review checklist, re-scored for 6.20.0

These are the 25 items of the v2 plan's §8.4 (scored for v4.5.0 in
`ycash-dd/doc/yellowback-review.md` §4), with this tree's evidence.

**Scoring rules:**

- **PASS** needs measured or recorded evidence for every part of the item.
- **PARTIAL** means part of the item is pending.
- No pending part is counted as passing.

| # | Item (§8.4) | Evidence on 6.20.0 at `df409ade8` | Score |
|---|---|---|---|
| 1 | Diff matches the budgets; consensus set zero; `main.cpp` ≤ 40, `miner.cpp` ≤ 35, `rpc/mining.cpp` ≤ 35 | audit (**measured**): 19 / 14 / 7, `miner.h` 4, `chainparams.cpp` 4 (baseline fix 3), frozen set zero | **PASS** |
| 2 | Every behaviour-changing inserted statement guarded; the residue justified | §3.1 grep (**measured**), every line justified; `coinbase_flags_empty_without_flag` exists and is green (V-9, **recorded**) | **PASS** |
| 3 | The `ConnectBlock` check's preconditions, `check_null_hash`, `check_reverify` | the ten `check_*`/`catchup_*`/`act5_*` unit cases exist (**measured**) and pass in the 228 (**recorded**) | **PASS** |
| 4 | `DoS(0)` only, ever | greps (**measured**); multi-node `assert_banscore_zero` in `yellowback_enforcement.py` green (**recorded**). V7 adds no DoS | **PASS** |
| 5 | Fail open on storage only; `EvaluateBlock` total | storage-fault, totality and exception-boundary unit cases (**recorded**); `state.cpp` throw/assert grep empty (**measured**); six fuzz targets run crash-free (**recorded**) | **PASS** |
| 6 | Undo inside `if (updateIndices)`; `VerifyDB -checklevel=4` leaves the hash unchanged | `main.cpp:3161` (**measured**); `yellowback_index.py` `verifychain(4, 20)` with the hash unchanged (**recorded**) | **PASS** |
| 7 | `CommitConnect` never reached under `fJustCheck` | structural: V3's early return `:4050-4051` precedes V4 `:4123` (**measured**) | **PASS** |
| 8 | Kill switch and valve; `Rejected` survives `kill -9`; a consensus-invalid block is absent from `Rejected` | `yellowback_index.py` (`rejected_survives_kill9`, `killswitch_*`, `attest_tables_survive_kill9`) and `yellowback_enforcement.py` case 9 (trip, restart, `kill -9` after the trip) green (**recorded**); both flushes (§2.5, §2.7). Open edge: F-25's > 64 run | **PASS** (edge recorded) |
| 9 | Every rule identifier has a `// Rule:` / `# Rule:` tag | the audit's two rule → test tag steps exit 0, no untagged identifier, TPL-1/2/3 and MINTPOL-1 included (**measured**). v4.5.0 failed this item (R4) | **PASS** |
| 10 | Apply/undo identity and cold-rebuild equality under reorg stress | `apply_undo_identity_over_sequences`, `overlay_view_equivalence` (unit), `yellowback_index.py` reorg and `-reindex`/`-reindex-yellowback` sections, `yellowback_demo_v6.py` item 7 (2- and 10-block reorgs, restart, `-reindex`) (**recorded**). `reorg_stress` retired by owner decision P-7 | **PASS** under P-7 |
| 11 | `IsStandardTx`/`AreInputsStandard` pass for every template incl. the claim path | `mint3_templates_are_standard_under_{sapling,canopy}`, `red1_owner_path_verifies`, `red4_claim_path_verifies` (exist, **measured**; green, **recorded**) | **PASS** |
| 12 | Determinism grep empty; `GetTime` only where allowed | determinism grep empty (**measured**); the audit's "Determinism, no clock, no sockets, no bans" step exits 0 (**measured**) | **PASS** |
| 13 | Coin locking: every owned YED output locked before commit, across reorgs and restarts; `lockunspent` cannot unlock | H5 refusal and `yed_unlockcoin` exist (**measured**); `yellowback_hardening.py`, `yellowback_wallet_restore.py`, `yellowback_wallet_lifecycle.py` green (**recorded**). v4.5.0 scored NOT YET | **PASS** |
| 14 | The wallet refuses a mint before activation and under each halt (`mintpol-*`); refuses a redeem/claim that `MempoolCheck` rejects | `yellowback_claim.py`, `yellowback_pricefeed.py`, `yellowback_void_mint.py` green (**recorded**) | **PASS** |
| 15 | `getblocktemplate` carries the tag in all three carriers; a pool-rebuilt coinbase yields a readable tag | `yellowback_mining.py` incl. `gbt_shape_without_flag` green (**recorded**); tag byte-budget unit cases; yolo's grid on ycash6 (§4.5). `yellowback_stratum.py` with `YOLO_BIN` **pending** | **PASS** (stratum script pending, §4.3) |
| 16 | The index survives `kill -9` with the chainstate unflushed; refuses `-prune` | `yellowback_index.py` `crash_unflushed_chainstate`, the `-prune` refusal (`:235-236`) green (**recorded**) | **PASS** |
| 17 | For every `Rejected` hash, `yed_getblockverdict` gives `blockInvalid == true`; refuses when the parent is not the tip | `yellowback_index.py` `verdict_parent_not_tip`, `yellowback_enforcement.py` green (**recorded**) | **PASS** |
| 18 | Docs: no "no consensus change"; trust statement byte-identical; runbook covers the seven topics | `grep 'no consensus change' doc/yellowback.md` → nothing; the audit "Documents" step exits 0; all seven runbook topics present in `doc/yellowback-mining.md` (**measured**) | **PASS** |
| 19 | No new build dependency; `configure.ac` untouched; no sockets in node Yellowback code | `configure.ac`, `Cargo.*`, `src/rust/` frozen at zero; socket grep empty (**measured**) | **PASS** |
| 20 | The shutdown sequence holds for the synchronous hooks | `init.cpp:211-216` after `StopHTTPServer()` (**measured**); mechanical companions `crash_unflushed_chainstate`, `rejected_survives_kill9` green (**recorded**). A reviewer-signed claim | **awaiting a human reviewer** |
| 21 | Stock parity: fork binary without `-yellowback` indistinguishable from stock | `yellowback_stockparity.py` (300 blocks), `yellowback_stock_node.py`, inherited suite 42/42 (**recorded**); tolerated differences §3.2. v4.5.0 scored NOT YET | **PASS** |
| 22 | Shielded pool: builder tests unchanged and green; the new methods called only from `src/yellowback/` | builder grep empty, `src/gtest` zero (**measured**); `yellowback_sapling.py` green unarmed and armed (**recorded**). **pending:** `ycash-gtest --gtest_filter='TransactionBuilder*'` | **PARTIAL** |
| 23 | Concurrency: `lockorder` and `sanitizers` jobs green on the last seven nightly runs | green locally (debug-build lockorder, ASan+UBSan, TSan; **recorded**). **pending:** both CI jobs are `if: false`; no nightly run exists | **PARTIAL** |
| 24 | Coverage: `qa/yellowback-coverage-floor.sh` exits 0 on the last run's `lcov.info` | floors met locally with the functional suite (**recorded**, plan revision 3). **pending:** the CI `coverage` job | **PARTIAL** |
| 25 | RPC contract: `yellowback_rpc_contract.py` green; the contract unchanged | script green (**recorded**); contract JSON byte-identical to `ycash-dd`'s (**measured**); `python` job live | **PASS** |

**Summary: 21 PASS, 3 PARTIAL, 1 awaiting a human reviewer, 0 FAIL, 0 NOT YET.** For comparison,
v4.5.0 at `5ea56c577` scored 11 PASS, 7 PARTIAL, 4 NOT YET, 2 FAIL and 1 awaiting a reviewer.
All three PARTIALs close with things this host did not do: build and run `ycash-gtest`, and switch
on and run the CI `lockorder`, `sanitizers` and `coverage` jobs.

---

## 7. What this document does **not** claim

- **That the §4 demonstration of record has passed.** `yellowback_demo_v6.py` exists (`3f312f28a`),
  and the plan records it green on the integration tree. The run of record and its transcript belong
  in §8, which is empty until the coordinator attaches them.
- **That any CI job beyond `audit` and `python` has run.** `main`, `agent`, `nightly`, `lockorder`,
  `sanitizers`, `coverage` and `weekly-fuzz` are disabled (`if: false && …`). Their gates are green
  locally only (§4.2, §4.4).
- **Re-runs at `df409ade8`.** No test was built or run for this revision. Everything marked
  *recorded* comes from the integration tree and the agents' runs on 2026-09-30 and 2026-10-01, at
  commits that are ancestors of this one or merged into it.
- **The `-mempooltxcostlimit` sweep interaction, tested.** It is argued structurally (V-8), not run.
- **`yellowback_stratum.py`, the `--armed` runs beyond six scripts, `ycash-gtest`.** All pending
  (§4.3, §6 item 22).
- **Component compatibility as merged.** §4.5 is the component branches' own evidence. No branch is
  merged, and yecwallet-dd has known breaks awaiting a decision.
- **Anything about mainnet**: hashpower, pool adoption, the launch bar, or the economics. Those
  belong to the pool operators and the product owner. The trust statement in `doc/yellowback.md`
  (byte-locked to the spec's §8.1) is the normative text.
- **A review of the 6.20.0 rebase itself.** This document reviews the Yellowback delta against
  `ycash6-baseline`. The rebase from v4.5.0 to 6.20.0 is miodragpop's work and is outside its scope,
  except for the baseline defects found while exercising it (§1.5).

---

## 8. Demonstration of record

**PLACEHOLDER — to be completed by the coordinator.** This is the exit criterion of the node scope
(plan §4, Phase 6): `qa/rpc-tests/yellowback_demo_v6.py`, run end to end on one eight-node regtest
chain, with node 1 as the `ycash6-stock` binary. It produces one transcript line per step and a PASS
line per plan §4 checkbox.

- binary under test: <commit, `ycashd --version`>
- stock binary: <`wt/ycash6-stock/src/ycashd`, commit>
- command: <exact invocation, portseed, tmpdir>
- result: <PASS lines, duration>

transcript: <to be attached by the coordinator>

The plan §4 checkboxes that the script covers by pointer rather than in its own run:

- item 8, the 30-minute economy, is `yellowback_devnet_roles.py`: all three presets green, ~39 min
  (Phase 5);
- item 10 is the CI gates (§4.4), still partly pending.

---

## 9. Reproducing

From a worktree of `boyfromcave/ycash6` on `feature/yellowback` with the tag `ycash6-baseline`
fetched:

```bash
export PATH="/opt/homebrew/opt/libtool/libexec/gnubin:/opt/homebrew/opt/coreutils/libexec/gnubin:/opt/homebrew/bin:$PATH"
export CARGO_TARGET_DIR="$PWD/target" LIBTOOLIZE=glibtoolize
./autogen.sh && CONFIG_SITE="$PWD/depends/aarch64-apple-darwin25.0.0/share/config.site" ./configure --quiet
# 6.20.0 trap: generate the cxx bridge headers before any target-only make
awk '/^CXXBRIDGE_H = /{f=1;next} f&&/^ *rust\/gen/{gsub(/[ \\]/,"");print;next} f{exit}' src/Makefile.am | xargs make -C src -j6
make -C src -j6 ycashd ycash-cli test/test_bitcoin

# §1  budgets, frozen set, RPC arity rows; the full CI audit job's steps
qa/yellowback-audit.sh
git diff --numstat ycash6-baseline...feature/yellowback
git diff --shortstat ycash6-baseline...feature/yellowback
git diff ycash6-baseline...feature/yellowback | grep '^-' | grep -v '^---'      # the 13 replaced lines
git diff --stat ycash6-baseline...feature/yellowback -- src/sync.cpp src/wallet/asyncrpcoperation_sendmany.cpp \
    src/test/main_tests.cpp src/test/net_tests.cpp src/wallet/test/rpc_wallet_tests.cpp src/rpc/client.cpp src/gtest

# §1.5  the baseline fixes
git show --stat 940987c51 141df8d48 e98128239 8808258cd
git merge-base --is-ancestor e98128239 ycash6-baseline || echo "fix 3 is inside the measured diff"

# §2  the hooks (the four-part checks are in the commit messages)
git diff ycash6-baseline...feature/yellowback -- src/main.cpp src/miner.cpp src/miner.h src/rpc/mining.cpp src/chainparams.cpp
git diff ycash6-baseline...feature/yellowback -- src/init.cpp src/rpc/rawtransaction.cpp src/wallet/rpcwallet.cpp \
    src/wallet/rpcdump.cpp src/transaction_builder.h src/transaction_builder.cpp src/rpc/common.h
git show b9b3e6556 83e6c1cb2 eda580983 308bb3fbe dfa630717
git log ycash6-baseline..feature/yellowback

# §3.1  the residue
git diff ycash6-baseline...feature/yellowback -- src/main.cpp src/miner.cpp src/miner.h src/rpc/mining.cpp \
    | grep '^+' | grep -v 'g_yellowback\|#include\|LOCK(cs_main)\|COINBASE_FLAGS\|^+$\|^+++'
git grep -n 'COINBASE_FLAGS =' -- src
git grep -n 'coinbase_flags_empty_without_flag' -- src/test

# §4  greps
git diff ycash6-baseline...feature/yellowback -- src/main.cpp | grep '^+' | grep -o 'DoS([0-9]*' | sort | uniq -c
git grep -n 'DoS([1-9]' -- src/yellowback 'src/rpc/yellowback*'
git grep -nE '\bthrow\b|\bassert\(' -- src/yellowback/state.cpp
git grep -nE 'GetTime|GetArg|\brand\b|\bdouble\b|\bfloat\b|mempool|chainActive' -- src/yellowback/state.cpp \
    src/yellowback/math.h src/yellowback/tag.cpp src/yellowback/payload.cpp src/yellowback/script.cpp src/yellowback/view.cpp
git grep -nE 'evhttp|socket\(|\bconnect\(|curl' -- src/yellowback 'src/rpc/yellowback*'
git grep -n 'AddTransparentInputUnsigned\|AddTransparentOutput(.*CScript\|SetLockTime' -- src \
    ':!src/transaction_builder.*' ':!src/yellowback' ':!src/test'
for f in doc/yellowback-spec.md doc/yellowback-rpc.md doc/yellowback-rpc-contract.json; do
  git show HEAD:$f | shasum; git -C ../../ycash-dd show feature/yellowback-price-attest:$f | shasum; done

# §4.1  unit tests
./src/test/test_bitcoin --run_test='yellowback_*'
./src/test/test_bitcoin

# §4.3, §8  functional (unique --portseed and --tmpdir per concurrent run)
ZCASHD=$PWD/src/ycashd REF_YCASHD=<path to the ycash6-stock build>/src/ycashd \
  ../.venv/bin/python -u qa/rpc-tests/yellowback_<x>.py --srcdir=$PWD/src --tmpdir=<dir> --portseed=<n>
```

The crosswalk (`docs/mapping.md` §19), the plan (`docs/plans/yellowback-ycash6-plan.md`) and the
normative spec live in the workspace, outside this fork.
