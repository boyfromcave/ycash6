# `yellowback_model.py` — serialisation and reading choices

This note records every choice the Python model had to make where plan §3
(`docs/plans/yellowback-v2-development-plan.md`, revision 6) leaves a detail open. The C++
implementation of `src/yellowback/` must make the same choices for `yed_getstatehash` to
equal `YellowbackModel.state_hash()` and for `assert_model_matches(node, full=True)` to pass.
Where a choice is a *reading* of an ambiguous rule rather than an encoding detail, it is
marked **reading** so the plan can be amended or the model changed in one place.

Since the vault upgrade (`docs/plans/yellowback-upgrade-plan.md` §15.10, `SCHEMA_VERSION` 6) the
rules are consensus at `UPGRADE_VAULT`: the vault is the primitive's V template, a claim moves it
into intents, a failing mint or vault spend makes the block invalid, and the activation state
machine, the enforcement halts and the VOID vault are gone. The entries below are updated in place;
what the upgrade changed is marked **(U-2x)**. P4-b (`SCHEMA_VERSION` 7: the attestor registry is the
primitive's set `attestorSetId`) is marked **(P4-b)**.

The golden vector `yellowback_golden.json` (440 synthetic heights, 444 block entries, regtest
params `{startHeight 1, sigmaRefBps 0, supplyCapBps 0, attestorSetId = the txid of the vector's own
SET_CREATE at 224 (livenessWindow 150, maturity 1, 15 seats, open), attestArmMin 3, bundleCarrier
scriptsig, mintRequiresArmed false}`) pins the result of all of these choices: state hash
`b0103e921a9bf4da5bd3f8ba7f740cd2e9fa2c09b4c72e91a820dbf2115f20bc`. Four entries are flagged
`"invalid"` (heights 137, 217, 231, 251): they are rejected and not applied, and the next entry is
the same height mined again without the offending transaction.
Regenerate with `python test_yellowback_model.py --write-golden` only after a deliberate change,
and update `GOLDEN_STATE_HASH` in the test and the C++ `statehash_golden_vector` together.

## 1. State-hash preimage (§3.6 *State hash*, N18)

`SHA256` over the concatenation, in this order, of:

| # | Record(s) | Key | Value (in field order) |
|---|---|---|---|
| 1 | `Tip` | `T` | `i32 height`, `uint256 blockHash`, `u32 schemaVersion = 7`, `string network` |
| 2 | every `Tags[h]`, ascending `h` | `Q` ‖ `u32be h` | `uint160 payoutKey`, `u64 priceMicroUsd`, `bool signal`, `u16 sourceMask` |
| 3 | every `Judgements[t]`, ascending `t` | `J` ‖ `u32be t` | `bool evaluated`, `bool inBand`, `bool penalized` |
| (4) | ~~`Activation`~~ | ~~`C`~~ | removed with ACT-1..6 **(U-21)** |
| 5 | every `Vaults[op]`, ascending outpoint | `V` ‖ `uint256 txid` ‖ `u32be n` | `bytes ownerPubKey`, `u8 termClass`, `i32 lockHeight`, `i32 claimHeight`, `i64 collateralZat`, `i64 mintedCents`, `i32 mintHeight`, `i32 refHeight`, `u8 status`, `string voidReason`, `i32 closeHeight`, `uint256 closingTxid`, `i64 burnedCents`, `i64 feePaidZat`, `bool unbacked` |
| 6 | every `Tokens[op]`, ascending outpoint | `K` ‖ `uint256 txid` ‖ `u32be n` | `i64 cents`, `i64 nValue`, `bytes scriptPubKey`, `i32 height` |
| 7 | `Totals` | `G` | `i64 supplyCents`, `i64 collateralZat`, `u32 activeVaults`, `u32 voidVaults`, `u32 closedVaults`, `u32 claimedVaults`, `i64 unbackedCents` |
| 8 | every `Snapshots[h]`, ascending `h` | `S` ‖ `u32be h` | `uint256 blockHash`, `bool tagged`, `bool quote`, `i64 pFast`, `i64 pMid`, `i64 pSlow`, `i64 pMint`, `i64 pClaim`, `i32 sigmaMultBps`, `i64 issuedZat`, `i64 supplyCents`, `i64 collateralZat`, `i64 globalRatioBps`, `u32 haltMask`; v3: `Attest` (`u8 status`, `i32 triggerHeight`, `i32 armHeight`), `u16[] seated`, `uint160[] pinnedKeys`, `u16[] pinnedSeqs` (**U-21**: `u32 signalCount` and the `Activation` copy are gone) |
| 9 | `Params` | `P` | `i32 startHeight` (the `UPGRADE_VAULT` activation height, U-22), `i32 sigmaRefBps`, `i32 supplyCapBps`, `uint256 attestorSetId` (32 internal bytes; it replaced v3's `i32 enforceUntil`, **U-22**); v3: `u32 attestArmMin`, `u8 bundleCarrier`; hardening H-1: `u8 mintRequiresArmed` |
| 10–14 | v3: `Attestors[seq]`, `AttestorSeq`, `Attest`, `BundleLog[h]`, `Notices[op]` | `A` ‖ `u16be seq`, `N`, `M`, `W` ‖ `u32be h`, `E` ‖ outpoint | as `yellowback_model.py` `_ser_attestor`, `_ser_attest`, `_ser_bundle_log`, `_ser_notice`. `Attestors`: `bytes attestorPubKey`, `bytes bondPubKey`, `COutPoint bondOutpoint`, `i64 bondZat`, `u32 bondLocktime`, `u8 flags`, `i32 registerHeight`, `u8 status` (`PENDING, ELIGIBLE, DORMANT, EJECTED, WITHDRAWN`), `i32 statusHeight`, `i32 bondSpentHeight`, `i32 seatedSince`, then **(P4-b)** `i32 lastAct`, `bool bondFrozen` |
| 15 | every `Intents[op]`, ascending outpoint **(U-23)** | `I` ‖ `uint256 txid` ‖ `u32be n` | `COutPoint vault` (`uint256 txid`, `u32 n` little-endian), `u8 role` (`CLAIMANT = 0`, `RESIDUAL = 1`), `i32 height` |
| 16 | `AttestorSet` **(P4-b)**, once the set's `SET_CREATE` is seen | `Z` | `i32 createHeight`, `u8 seats`, `u32 maturity`, `u32 livenessWindow` |

Each record is its key immediately followed by its value. `TxLog`, `Rejected`, `Undo` are
excluded (plan; `Rejected` no longer exists, **U-21**). Encodings:

- **Integers in values** are fixed-width **little-endian** (Bitcoin `READWRITE`). Widths as
  above: every height field is `i32`; cents, zat and bps ratios are `i64`; `sigmaMultBps` is
  `i32`; counts and `haltMask` are `u32`; `priceMicroUsd` in a tag is `u64` (the wire width of
  the tag field); `sourceMask` `u16`.
- **Heights in keys** are `u32` **big-endian** (`Q<u32 height>` etc.), the prototype's
  `keys::U32BE`, so LevelDB iterates them in ascending order and "sorted by key" equals
  "ascending height". Outpoint keys are the prototype's `OutPointKey`: prefix, the 32 raw
  `uint256` bytes, `u32be n`; "ascending outpoint order" is the byte order of that key.
- `uint256` / `uint160` are the raw internal bytes (`uint256::begin()`, i.e. the RPC display hex
  **reversed** for txids and block hashes; `payoutKey` as the 20 bytes in the tag).
- `bool` is one byte `0x00`/`0x01`.
- Enumerations are `u8` in declaration order: `Vaults.status` `ACTIVE = 0, VOID = 1, CLOSED = 2,
  CLAIMED = 3, CLAIMING = 4` (VOID is never produced since the upgrade; CLAIMING is a vault whose
  claim intents await `CLAIM_DELAY`, **U-23**); `termClass` `0/1/2` = A/B/C.
- `haltMask` bits in declaration order: `NOT_ACTIVE = 1, NO_PRICE = 2, PARTICIPATION = 4,
  GLOBAL_RATIO = 8, DIVERGENCE = 16, ENFORCEMENT = 32`. **U-21:** `NOT_ACTIVE` marks only the
  virtual snapshot below `START_HEIGHT`; `PARTICIPATION` and `ENFORCEMENT` are never set (the bits
  stay reserved).
- `string` and `bytes` (`voidReason`, `network`, `ownerPubKey`, `scriptPubKey`) are
  **CompactSize-length-prefixed** — exactly what `READWRITE(std::string)`, `READWRITE(CPubKey)`
  and `READWRITE(*(CScriptBase*)&script)` produce. For every length below 253 that is a single
  length byte (`ownerPubKey` is always `0x21` ‖ 33 bytes).
- **Undefined** prices (`pFast … pClaim`) and `globalRatioBps` are `0` (plan). `closingTxid` of
  an open vault is the zero hash; `closeHeight` `0`.
- `Tip.network` is `CBaseChainParams`' id string: `"main"`, `"test"`, `"regtest"`.
- An index that has not reached `START_HEIGHT` hashes `Tip = {height 0, zero hash}`; the
  functional tests never hash that state.

## 2. Snapshot arithmetic choices (§3.7)

- **`issuedZat` (reading).** The plan writes `issuedZat(H) = Σ_{h ≤ H} GetBlockSubsidy(h)`, but
  `EvaluateBlock` receives only the subsidy of the block it applies (N22) and the virtual
  snapshot below `START_HEIGHT` says nothing about `issuedZat`. The model carries it from
  `Snapshots[H − 1]` with the virtual snapshot's value **0**, i.e. the sum over
  `[START_HEIGHT, H]`. `YellowbackModel(params, issued_before_start=…)` exists in case the C++
  side seeds the first snapshot differently; the golden vector uses 0 (and starts at 1, so the
  only block excluded is genesis: 12.5 YEC on regtest).
- **SIGMA-1 with `SIGMA_REF_BPS = 0`** yields `10,000` *before* the undefined-sample check
  ("fixes the multiplier"); with a non-zero reference any undefined sample (including a sample
  height below `START_HEIGHT`, i.e. a virtual snapshot) yields the cap (K12). Regtest samples:
  `s_0` plus `k = 1 … 8` (`VOL_WINDOW / VOL_STEP`), `n = 8` returns.
- Products are reduced modulo 2²⁵⁶ (`u256()`), reproducing `arith_uint256` should an overflow
  ever occur; with the §3.1 bounds none does.
- **Judgements (reading).** `Judgements[t]` is written at `H = t + PEER_LAG` for **every quote
  tag** at `t` (never for a signal-only tag): `{evaluated = false, inBand = false, penalized =
  false}` when `|peers| < PEER_MIN`, else the REG-4 values. The alternative — writing nothing
  when the tag is not evaluated — changes the hash; the plan's "written at height + PEER_LAG"
  was read as "a record per judged tag".
- The peer window `[t − PEER_LAG, t + PEER_LAG − 1]` reads only heights `≥ START_HEIGHT` (there
  are no tags below it).
- `E(R)` is the quote tags' keys in `(R − PAYEE_WINDOW, R]`, height order, deduplicated.
- **(U-21)** ACT-1..6 are gone: no signal count, no Activation record, no carried PARTICIPATION /
  ENFORCEMENT bits and no ACT-5 enforcement predicate. The module is active from `START_HEIGHT`
  (the `UPGRADE_VAULT` activation height) and every invalid block is rejected.

## 3. Money-rule choices (§3.8)

- **A. Coinbase (TX-0).** The coinbase is skipped entirely — its payload, if any, creates
  nothing and it gets no `TxLog` entry. Only its `scriptSig` is read (the tag).
- **B. §3.3 vs XFER-1 (reading).** An assignment whose `vout` is out of range, duplicated, the
  `OP_RETURN` itself, or whose `cents == 0` makes the payload **malformed ⇒ non-Yellowback**
  (§3.3), so XFER-1's "exists and is not the OP_RETURN" clause is never the failing one; XFER-1
  contributes only the `MIN_OUTPUT ≤ cents ≤ MAX_OUTPUT` bound (`bad-transfer-assignment`). For a
  vault spend the two readings coincide: `vault-spend-malformed` either way.
  `cents == 0` in a **MINT** payload is not a malformation (MINT-2's `bad-mint-amount` covers it).
- **C. No VOID vault (U-21, §15.10).** A MINT whose verdict is not `ok` makes the transaction
  invalid, and so the block: nothing of it is applied (v2 registered a VOID record). `voidReason`
  stays in the record layout and is always `""`; `voidVaults` stays `0`. The vault output must be
  exactly the YED V (§4), so a MINT payload over any other `vout[0]` is `bad-mint-vault-script`.
- **C2. Invalid transactions and blocks (U-21).** The verdicts that make a transaction invalid:
  every MINT verdict but `ok`; every RED-1..5 verdict of a spend of an ACTIVE vault;
  `vault-claim-intents`, `intent-spend-malformed`, `intent-cancel-residual`,
  `intent-cancel-no-vault` and `yed-template-output` (L–N below); **(P4-b)** any `ATTESTOR_REGISTER`
  payload (`attestor-register-retired`) and any `ATTESTOR_REVIVE` payload (`attestor-revive-retired`),
  whatever its body. A failing TRANSFER still burns (E) and a failing NOT-1 or EQV-1 is still
  non-Yellowback: neither is invalid. The block's evaluation
  stops at the first invalid transaction; its reason is `"<verdict>:<txid>"`. A coinbase output
  that is a YED V or I makes the block invalid (`yed-template-output`).
- **D. MINT verdict precedence.** MINT-2 in the plan's clause order: `bad-mint-class`,
  `bad-mint-amount`, `bad-mint-lock-height` (`lockHeight + GRACE ≥ LOCKTIME_THRESHOLD`),
  `bad-mint-ref-height` (window, then `≥ START_HEIGHT`), `bad-mint-lock-height` (`lockHeight >
  refHeight` and the class range). MINT-3: `bad-mint-outputs`, `bad-mint-owner-key`,
  `bad-mint-vault-script`. MINT-4: a missing snapshot ⇒ `mint-not-active`; then the halt bits in
  declaration order — `NOT_ACTIVE` (the virtual snapshot) ⇒ `mint-not-active`, `NO_PRICE` ⇒
  `mint-halted-no-price`, `GLOBAL_RATIO`, `DIVERGENCE` (**U-21**: `mint-halted-participation` is gone); last (hardening H-1), with
  `MINT_REQUIRES_ARMED` and `R` not ARMED ⇒ `mint-halted-unarmed`. MINT-5: `mint-unsatisfiable` before
  `bad-mint-collateral` (which also covers `< 4 · FEE_MIN`). MINT-6, MINT-7, MINT-8 (`bad-mint-fee`
  for every MINT-8 failure).
- **E. XFER verdict precedence.** XFER-1 (`bad-transfer-assignment`), XFER-2
  (`transfer-over-assigned`), XFER-3 (`transfer-no-yed-input`). When XFER-1..3 hold the verdict is
  `ok` if `Σ = yedIn` and **`burned`** if `Σ < yedIn` ("a burn by rule is `burned`"). A
  non-Yellowback transaction that consumes tokens has `TxLog.type = NONE`, `verdict = burned`;
  one that only closes a VOID vault has `type = NONE`, `verdict = ok`.
- **F. `TxLog.type` / `path`.** Any transaction spending an ACTIVE vault is `REDEEM` (M3) with
  `path = owner` for the V's selectors 2 and 3, `claim` for 4, `""` otherwise (selector 1, a set
  unlock, or a scriptSig without a selector — RED-1 fails). A MINT's `assigned` is `[(1, cents)]`;
  `yedOut = cents`. **(U-23)** An intent's release is `CLAIM_RELEASE`, its cancel `CLAIM_CANCEL`.
- **G. RED-2 verdicts.** `burn = yedIn − Σ assigned`; `burn ≤ 0` ⇒ `vault-spend-missing-burn`;
  `0 < burn < mintedCents` ⇒ `vault-spend-short-burn`.
- **H. RED-3 verdicts.** `vault-spend-bad-fee` for `feeVout = 0xFF`, out of range, the
  `OP_RETURN`, an assigned vout, or `nValue < feeZat`; `vault-spend-bad-payee` when the output is
  not `P2PKH(k)` for some `k ∈ E(R)`. Checked in that order (structure, payee, value).
- **I. Closing (U-21, U-23).** A passing owner spend closes the vault (`CLOSED`); a passing claim
  leaves it `CLAIMING` (its `closeHeight`/`closingTxid` the claim's) with its collateral out of
  `Totals.collateralZat` and `activeVaults`; the claimant intent's release makes it `CLAIMED`
  (`claimedVaults += 1`). A failing spend is invalid: nothing closes and nothing is `unbacked`
  (the field stays `false`, `unbackedCents` `0`). IN-3's `burned` is recorded on the spent vault.
- **J. `feePaidZat` (reading).** The vault has one `feePaidZat`; the MINT writes the mint fee
  and a passing REDEEM/CLAIM **rewrites** it with the fee that spend paid — `0` under FEE-0.
- **K. Two ACTIVE vaults, or the vault not at `vin[0]`:** RED-1 fails; the transaction is invalid.
- **L. The claim's outputs (U-23).** The claim (selector 4) must have one or two YED intents whose
  `vaultHash` is `SHA256` of the spent V and no output equal to the V (re-lock), else
  `vault-claim-intents` (checked right after RED-1's payload checks, before BUNDLE-1). At RED-5:
  when a residual `≥ RESIDUAL_MIN_ZAT` is due there must be exactly two intents, one of them
  paying `P2PKH(hash160(ownerPubKey))` (its `recipientHash`) at least the residual — the first such
  in output order is the owner's residual intent, the other the claimant's — else `red5-residual`;
  with no residual due there must be exactly one (the claimant's), else `vault-claim-intents`.
  Each gets an `Intents` record `{vault, role, height}`. The claim's REDEEM burn happens there (IN-3).
- **M. Intent spends (U-23, U-24).** A transaction spending an `Intents` outpoint (exactly one, and
  no ACTIVE vault, else `intent-spend-malformed`) must use selector 1 (release) or 2 (cancel) and
  carry no Yellowback payload (`intent-spend-malformed`). The record is erased. The residual's
  cancel is `intent-cancel-residual`; its release changes nothing else. The claimant's release
  makes the vault `CLAIMED`. The claimant's cancel must create exactly one output equal to the
  vault's V, at `vout[0]` (`intent-cancel-no-vault`): the vault record moves to `(cancelTxid, 0)`
  as `ACTIVE` with `collateralZat` = that output's value, `closeHeight = 0`, `closingTxid` zero,
  `burnedCents = 0` (the rest kept: the same position), its notice (if any) erased, and back in
  `collateralZat`/`activeVaults`; the claim's burn is **not** refunded (U-24). `TxLog.closedVaults`
  names the old outpoint, `reopenedVaults` the new one. The model checks neither the delay nor
  the payment (the primitive does).
- **N. YED template outputs (U-23).** After the payload rules, any output that is a YED V or I
  and was not created by the rule that ran (the mint's `vout[0]`, the claim's intents, the
  cancel's `vout[0]`) makes the transaction invalid (`yed-template-output`).

- **O. The attestor set's acts (P4-b).** Per non-coinbase transaction, after IN-1/IN-2 (the bond
  spends) and before the payload rules: the first output that is a `YV` act (`vault.is_act_script`)
  is parsed (`vault.parse_act_script`; the C++ uses `vault::DecodeAct` + `ActFieldsValid`); one that
  does not parse is ignored (the primitive would have refused the block). With `setId` (or, for
  `SET_CREATE`, the txid) equal to `attestorSetId`:
  `SET_CREATE` writes `AttestorSet` once (`createHeight = H`, the body's `seats`, `maturity`,
  `livenessWindow`); the others need `AttestorSet`. `SET_JOIN`: a new `Attestors[next]` with
  `attestorPubKey = bondPubKey = memberKey`, `bondOutpoint = (txid, bondVout)`, `bondZat =
  vout[bondVout].value`, `bondLocktime`, `flags 0`, `registerHeight = statusHeight = H`, `PENDING`,
  `lastAct = min(H + maturity, 2^31 − 1)`, a `BondIndex` row; `AttestorSeq += 1`; `TxLog.type =
  ATTESTOR_REGISTER`, `attestorSeq` the new seq. `SET_HEARTBEAT` / `SET_REMOVE` / `SET_EQUIVOCATION`
  act on the key's **newest** record (highest seq with that `attestorPubKey`; the key of a
  `SET_EQUIVOCATION` is the one `sigA` recovers to): heartbeat `lastAct = H`; remove `EJECTED`
  (`bondFrozen` when `burn = 1`); set equivocation `EJECTED` and `bondFrozen`; `EJECTED` moves
  `statusHeight` only when the status changes; `TxLog.type = ATTESTOR_SET_ACT`, `attestorSeq` that
  seq. `SET_WINDDOWN` changes nothing. The acts are not re-validated (no seat count, no signature):
  the primitive has done that, which is also why the mirror may hold more records than the set has
  seats. **reading:** the transaction's `TxLog.type` is the act's unless the payload rules set one.
- **P. EQV-1 (P4-b).** The evidence is EQV-1's (two attestations, one `seq`, one `citedHeight ≥
  START_HEIGHT` and `< H`, two prices, the scriptsig carrier); the key is the **first record in seq
  order** that is its key's newest, has `bondSpentHeight = 0` and `bondFrozen = false`, under which
  both attestations verify over `Snapshots[citedHeight].blockHash` (the record named by the
  attestations' `seq` is not consulted: a key cannot sign under another key). Effect: `EJECTED`
  (`statusHeight` on change) and `bondFrozen`; `TxLog.attestorSeq` that record's seq,
  `bundleSeqs = [seq of the attestations]`. The primitive freezes the same member's bond (the module
  ejection hook, U-25), which the model does not model.
- **Q. Seats (P4-b, SNAP).** For every record in seq order, before ARM-1/2, with `AttestorSet`
  present: `PENDING → ELIGIBLE` (`statusHeight = H`) when `H ≥ registerHeight + max(maturity,
  BOND_MATURITY)`, `bondZat ≥ BOND_MIN`, `bondLocktime ≥ registerHeight + BOND_MIN_LOCK` and no
  record of the key has `bondFrozen`; then an `ELIGIBLE` record with `lastAct < H − livenessWindow`
  becomes `DORMANT`, and a `DORMANT` one with `lastAct ≥ H − livenessWindow` and `lastAct >
  statusHeight` becomes `ELIGIBLE` (`statusHeight = H` either way). S15 runs after the halts as in
  v3. `seated` takes `min(N_SLOTS, seats)` records (`0` without `AttestorSet`).

## 4. Codec choices (§3.2–3.4)

- **TAG-1.** The height prefix is skipped by the **length** of `CScript() << nHeight` (1 byte for
  heights 1–16, else `1 + len(CScriptNum(nHeight))`), whatever bytes are actually there — a
  coinbase without the BIP34 push is consensus-invalid anyway. A scriptSig shorter than the
  prefix has no tag.
- **§3.3 push shape.** `OP_RETURN <push>` accepts any `GetOp`-valid push encoding of the data
  (direct `0x01–0x4b`, `PUSHDATA1/2/4`), not only the canonical one; `OP_0`, `OP_1..OP_16`,
  `OP_1NEGATE` are not "a push of 4..80 bytes". Exactly one push, nothing after it.
- **Selector (U-23, §15.3).** The scriptSig of a vault or intent spend must be push-only in
  `CScript::IsPushOnly`'s sense (every opcode `≤ OP_16`, `OP_RESERVED` included, exactly as
  `vault::ParseSelector`) and its last opcode exactly `OP_1..OP_4`; the selector is that number.
  v2's OP_IF path detection (`spend_path`, K4) is no longer read by any rule.
- **The YED V (U-23).** The vault output is byte-compared against the primitive's V with `tag =
  YED\0`, `setId = cancelSetId` = the attestor set's 32 internal bytes, `delay = CLAIM_DELAY`
  (regtest 10, mainnet 1,152), `ownerHeight = lockHeight`, `ownerKey` = the payload's, `appHeight
  = lockHeight + GRACE` (numbers as minimal `CScriptNum` pushes); a YED intent is the I of that V
  (`yed_intent_script`). Both are parsed only in their exact shape with in-range fields
  (`parse_vault_template` / `parse_intent_template`: rebuild and compare); the model implements
  the two templates itself (it imports `vault.py` only for the `YV` act codec, P4-b).
- Compressed-key validity is `CPubKey::IsFullyValid` for 33 bytes: prefix `02`/`03`, `x < p`,
  `x³ + 7` a quadratic residue.

## 5. What the model does not do

It verifies no signature, script, CLTV, `nLockTime`, `nExpiryHeight`, UTXO existence or
amount — only §3's rules over the transparent inputs, outputs and the `OP_RETURN`. It has no
reorg support: blocks must arrive in height order (`ValueError` otherwise); rebuild from scratch
to compare after a reorg. `regtest_subsidy()` mirrors `GetBlockSubsidy` for the functional
tests' configuration (Blossom at 1, halving 144/288, no slow start); `assert_model_matches`
takes the subsidy from `getblocksubsidy` (miner + founders + funding streams) instead.
