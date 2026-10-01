# `yellowback_model.py` — serialisation and reading choices

This note records every choice the Python model had to make where plan §3
(`docs/plans/yellowback-v2-development-plan.md`, revision 6) leaves a detail open. The C++
implementation of `src/yellowback/` must make the same choices for `yed_getstatehash` to
equal `YellowbackModel.state_hash()` and for `assert_model_matches(node, full=True)` to pass.
Where a choice is a *reading* of an ambiguous rule rather than an encoding detail, it is
marked **reading** so the plan can be amended or the model changed in one place.

The golden vector `yellowback_golden.json` (224 synthetic blocks, regtest params
`{startHeight 1, sigmaRefBps 0, supplyCapBps 0, enforceUntil 0}`) pins the result of all of
these choices: state hash `6eb05394317a8c1d6f3cd23a5a824eaf55d45605deb774e0d5d70f3a55638682`.
Regenerate with `python test_yellowback_model.py --write-golden` only after a deliberate change,
and update `GOLDEN_STATE_HASH` in the test and the C++ `statehash_golden_vector` together.

## 1. State-hash preimage (§3.6 *State hash*, N18)

`SHA256` over the concatenation, in this order, of:

| # | Record(s) | Key | Value (in field order) |
|---|---|---|---|
| 1 | `Tip` | `T` | `i32 height`, `uint256 blockHash`, `u32 schemaVersion = 2`, `string network` |
| 2 | every `Tags[h]`, ascending `h` | `Q` ‖ `u32be h` | `uint160 payoutKey`, `u64 priceMicroUsd`, `bool signal`, `u16 sourceMask` |
| 3 | every `Judgements[t]`, ascending `t` | `J` ‖ `u32be t` | `bool evaluated`, `bool inBand`, `bool penalized` |
| 4 | `Activation` | `C` | `u8 status`, `i32 lockInHeight`, `i32 activateHeight` |
| 5 | every `Vaults[op]`, ascending outpoint | `V` ‖ `uint256 txid` ‖ `u32be n` | `bytes ownerPubKey`, `u8 termClass`, `i32 lockHeight`, `i32 claimHeight`, `i64 collateralZat`, `i64 mintedCents`, `i32 mintHeight`, `i32 refHeight`, `u8 status`, `string voidReason`, `i32 closeHeight`, `uint256 closingTxid`, `i64 burnedCents`, `i64 feePaidZat`, `bool unbacked` |
| 6 | every `Tokens[op]`, ascending outpoint | `K` ‖ `uint256 txid` ‖ `u32be n` | `i64 cents`, `i64 nValue`, `bytes scriptPubKey`, `i32 height` |
| 7 | `Totals` | `G` | `i64 supplyCents`, `i64 collateralZat`, `u32 activeVaults`, `u32 voidVaults`, `u32 closedVaults`, `u32 claimedVaults`, `i64 unbackedCents` |
| 8 | every `Snapshots[h]`, ascending `h` | `S` ‖ `u32be h` | `uint256 blockHash`, `bool tagged`, `bool quote`, `u32 signalCount`, `Activation` (as row 4's value), `i64 pFast`, `i64 pMid`, `i64 pSlow`, `i64 pMint`, `i64 pClaim`, `i32 sigmaMultBps`, `i64 issuedZat`, `i64 supplyCents`, `i64 collateralZat`, `i64 globalRatioBps`, `u32 haltMask` |
| 9 | `Params` | `P` | `i32 startHeight`, `i32 sigmaRefBps`, `i32 supplyCapBps`, `i32 enforceUntil` |

Each record is its key immediately followed by its value. `TxLog`, `Rejected`, `Undo` are
excluded (plan). Encodings:

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
- Enumerations are `u8` in declaration order: `Activation.status` `SIGNALING = 0, LOCKED_IN = 1,
  ACTIVE = 2`; `Vaults.status` `ACTIVE = 0, VOID = 1, CLOSED = 2, CLAIMED = 3`; `termClass`
  `0/1/2` = A/B/C (stored as the payload byte, see §3 C).
- `haltMask` bits in declaration order: `NOT_ACTIVE = 1, NO_PRICE = 2, PARTICIPATION = 4,
  GLOBAL_RATIO = 8, DIVERGENCE = 16, ENFORCEMENT = 32`.
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
- ACT-4/ACT-6 carried bits: `bit = prev; if bit: bit = count < RESUME; if ACTIVE and count <
  FLOOR: bit = true` (RESUME = `ACTIVATION_THRESHOLD` for PARTICIPATION,
  `ENFORCEMENT_RESUME` for ENFORCEMENT).
- ACT-5: enforcement at `H` is on iff `Snapshots[H − 1]` is real (not virtual), `ACTIVE`,
  `ENFORCEMENT` clear, and (`enforceUntil == 0` or `H ≤ enforceUntil`).

## 3. Money-rule choices (§3.8)

- **A. Coinbase (TX-0).** The coinbase is skipped entirely — its payload, if any, creates
  nothing and it gets no `TxLog` entry. Only its `scriptSig` is read (the tag).
- **B. §3.3 vs XFER-1 (reading).** An assignment whose `vout` is out of range, duplicated, the
  `OP_RETURN` itself, or whose `cents == 0` makes the payload **malformed ⇒ non-Yellowback**
  (§3.3), so XFER-1's "exists and is not the OP_RETURN" clause is never the failing one; XFER-1
  contributes only the `MIN_OUTPUT ≤ cents ≤ MAX_OUTPUT` bound (`bad-transfer-assignment`). For a
  vault spend the two readings coincide: `vault-spend-malformed` either way.
  `cents == 0` in a **MINT** payload is not a malformation (MINT-2's `bad-mint-amount` covers it).
- **C. VOID vault record.** `Vaults[txid:0] = VOID` copies the payload verbatim even when the
  failing rule concerned those fields: `ownerPubKey` = the 33 payload bytes (valid or not),
  `termClass` = the payload byte (may be > 2), `mintedCents` = the payload `cents`, `lockHeight`
  = payload, `claimHeight = lockHeight + GRACE`, `refHeight` = payload, `collateralZat` =
  `vout[0].nValue`, `feePaidZat = 0`, `voidReason` = the verdict. A VOID vault's collateral is
  **not** in `Totals.collateralZat` (only an ACTIVE vault's enters and leaves it); it counts in
  `voidVaults`. A MINT whose `vout[0]` is not P2SH (or is absent) creates no vault and, if it
  spent no token, no `TxLog` entry.
- **D. MINT verdict precedence.** MINT-2 in the plan's clause order: `bad-mint-class`,
  `bad-mint-amount`, `bad-mint-lock-height` (`lockHeight + GRACE ≥ LOCKTIME_THRESHOLD`),
  `bad-mint-ref-height` (window, then `≥ START_HEIGHT`), `bad-mint-lock-height` (`lockHeight >
  refHeight` and the class range). MINT-3: `bad-mint-outputs`, `bad-mint-owner-key`,
  `bad-mint-vault-script`. MINT-4: a missing snapshot or a non-ACTIVE status ⇒
  `mint-not-active`; then the halt bits in declaration order — `NOT_ACTIVE` ⇒ `mint-not-active`,
  `NO_PRICE` ⇒ `mint-halted-no-price`, `PARTICIPATION` **or** `ENFORCEMENT` ⇒
  `mint-halted-participation`, `GLOBAL_RATIO`, `DIVERGENCE`. MINT-5: `mint-unsatisfiable` before
  `bad-mint-collateral` (which also covers `< 4 · FEE_MIN`). MINT-6, MINT-7, MINT-8 (`bad-mint-fee`
  for every MINT-8 failure).
- **E. XFER verdict precedence.** XFER-1 (`bad-transfer-assignment`), XFER-2
  (`transfer-over-assigned`), XFER-3 (`transfer-no-yed-input`). When XFER-1..3 hold the verdict is
  `ok` if `Σ = yedIn` and **`burned`** if `Σ < yedIn` ("a burn by rule is `burned`"). A
  non-Yellowback transaction that consumes tokens has `TxLog.type = NONE`, `verdict = burned`;
  one that only closes a VOID vault has `type = NONE`, `verdict = ok`.
- **F. `TxLog.type` / `path`.** Any transaction spending an ACTIVE vault is `REDEEM` (M3) with
  `path = owner | claim` from §3.4 path detection, or `""` when the scriptSig is not push-only or
  has fewer than two pushes. A MINT's `assigned` is `[(1, cents)]`; `yedOut = cents`.
- **G. RED-2 verdicts.** `burn = yedIn − Σ assigned`; `burn ≤ 0` ⇒ `vault-spend-missing-burn`;
  `0 < burn < mintedCents` ⇒ `vault-spend-short-burn`.
- **H. RED-3 verdicts.** `vault-spend-bad-fee` for `feeVout = 0xFF`, out of range, the
  `OP_RETURN`, an assigned vout, or `nValue < feeZat`; `vault-spend-bad-payee` when the output is
  not `P2PKH(k)` for some `k ∈ E(R)`. Checked in that order (structure, payee, value).
- **I. Closing.** Every ACTIVE vault a transaction spends is closed by IN-2 (`CLOSED`, or
  `CLAIMED` on a passing claim-path spend); on a failing RED all of them become `CLOSED` and each
  gets `unbacked = burned < mintedCents`, `unbackedCents += max(0, mintedCents − burned)` against
  the transaction's single `burned`. A closed vault's `collateralZat` leaves
  `Totals.collateralZat` whether RED passed or failed (the plan states it for the passing case
  only; the alternative would leave phantom collateral in the total). IN-3's "`burned` is recorded
  on every vault closed by this transaction" is applied literally, VOID vaults included.
- **J. `feePaidZat` (reading).** The vault has one `feePaidZat`; the MINT writes the mint fee
  and a passing REDEEM/CLAIM **rewrites** it with the fee that spend paid — `0` under FEE-0.
- **K. Two ACTIVE vaults, or the vault not at `vin[0]`:** RED-1 fails for the transaction; every
  ACTIVE vault it spends is closed per I.

## 4. Codec choices (§3.2–3.4)

- **TAG-1.** The height prefix is skipped by the **length** of `CScript() << nHeight` (1 byte for
  heights 1–16, else `1 + len(CScriptNum(nHeight))`), whatever bytes are actually there — a
  coinbase without the BIP34 push is consensus-invalid anyway. A scriptSig shorter than the
  prefix has no tag.
- **§3.3 push shape.** `OP_RETURN <push>` accepts any `GetOp`-valid push encoding of the data
  (direct `0x01–0x4b`, `PUSHDATA1/2/4`), not only the canonical one; `OP_0`, `OP_1..OP_16`,
  `OP_1NEGATE` are not "a push of 4..80 bytes". Exactly one push, nothing after it.
- **Push-only scriptSig (RED-1).** Opcodes `≤ OP_16` are pushes (`OP_1..OP_16` push the number,
  `OP_1NEGATE` pushes `0x81`), **except `OP_RESERVED` (0x50)**, which `CScript::IsPushOnly` counts
  but which pushes nothing and fails evaluation; the model treats it as not push-only (RED-1
  fails; conservative). The selector is the push before the last; `CastToBool` as in the
  interpreter (empty and negative zero are false).
- The vault script is byte-compared against `vault_script(lockHeight, ownerPubKey, lockHeight +
  GRACE)` with heights pushed as minimal `CScriptNum` (`OP_1..OP_16` for 1–16, never reached on
  any network because `lockHeight > refHeight ≥ START_HEIGHT ≥ 1` plus a class minimum of 48).
- Compressed-key validity is `CPubKey::IsFullyValid` for 33 bytes: prefix `02`/`03`, `x < p`,
  `x³ + 7` a quadratic residue.

## 5. What the model does not do

It verifies no signature, script, CLTV, `nLockTime`, `nExpiryHeight`, UTXO existence or
amount — only §3's rules over the transparent inputs, outputs and the `OP_RETURN`. It has no
reorg support: blocks must arrive in height order (`ValueError` otherwise); rebuild from scratch
to compare after a reorg. `regtest_subsidy()` mirrors `GetBlockSubsidy` for the functional
tests' configuration (Blossom at 1, halving 144/288, no slow start); `assert_model_matches`
takes the subsidy from `getblocksubsidy` (miner + founders + funding streams) instead.
