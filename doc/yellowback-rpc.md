# Yellowback RPC contract (`yed_*`), rpcversion 3

This file is the interface between the node (`ycash-dd`) and the wallet application
(`yecwallet-dd`). Nothing else crosses that boundary. It is written *before* the code it
describes (plan §4.5, M7, N27, P7): the node context is Phase 3's gate, the wallet context is
Phase 6's, and `qa/rpc-tests/yellowback_rpc_contract.py` calls every command and asserts every
documented key with its JSON type. `scripts/extract-spec.sh` (`make spec`) turns the fenced
`json` block under each command heading into `doc/yellowback-rpc-contract.json`, copied into both
forks; the wallet's `yellowbackrpc.h` is checked against that copy.

**How to read the `json` blocks.** Each is an *example result*: the field names and nesting are
the contract, the values show the JSON type (`number`, `string`, `boolean`, `null`, object,
array). A list result is written as a one-element array holding one example row. A field whose
example value is `null` is one the text marks *null when …* — the checker accepts `null` or the
documented type for it. A field the text marks **optional** may be absent, and the checker asserts
it only in the state the text names. Nothing else may be absent.

**`rpcversion` rule.** `yed_getinfo.rpcversion` is `3`. Additions (new commands, new fields)
never bump it; a removal or a shape change does. Phase 8's additions (`yed_estimatesend`,
`yed_unlockcoin`, `yed_getinfo.lockedOutputs`/`protectedByIndex`, H3/H5/H10) therefore landed
under `rpcversion = 2`. **v3 bumps to `3` by decision (v3 plan W14), not by the letter of the
rule:** every v3 change below is an addition, but a wallet built against the v2 contract cannot
build a bundle-bearing mint or claim once the attestation layer is armed, so the mismatch must be
refused rather than tolerated. The wallet's `YellowbackRpc::RPC_VERSION` goes to `3` in Phase A5's
first commit; until then a v3 node and a v2 wallet refuse each other (N27), which is intended.
Everything marked **v3** in this file is Phase A0's contract for Phases A2 (node context) and A3
(wallet context); the v2 text is unchanged except where a field's meaning changed and is marked.

## Conventions

- **Units.** YED in integer **cents** (`100` = $1.00); YEC in **zatoshi** fields (`…Zat`) with a
  decimal YEC twin (`collateral`) where the prototype had one; prices in **micro-USD per YEC**
  (`1000000` = $1.00); ratios and shares in **basis points** (`10000` = 100 %). Heights are block
  heights. The protocol never speaks wall-clock time; the only clock fields are the miner's own
  (`quoteAgeSeconds`, `receivedAt`) and they are read by no rule.
- **Undefined prices are `null`.** `pFast`, `pMid`, `pSlow`, `pMint`, `pClaim`, `globalRatioBps`
  and `supplyCapCents` are `null` when §3.7 leaves them undefined (no fill, no supply, no cap);
  stored as `0` in the index (§3.6 M1), rendered as `null` here.
- **Outpoints** are objects `{"txid": "<hex>", "vout": n}`; a vault is named by its outpoint
  string `"<txid>:0"` where the prototype did (`vault`).
- **Term classes** are the strings `"A"`, `"B"`, `"C"`; vault statuses `"ACTIVE"`, `"VOID"`,
  `"CLOSED"`, `"CLAIMED"`; activation statuses `"signaling"`, `"locked_in"`, `"active"`; halt-mask
  names `"NOT_ACTIVE"`, `"NO_PRICE"`, `"PARTICIPATION"`, `"GLOBAL_RATIO"`, `"DIVERGENCE"`,
  `"ENFORCEMENT"` (§3.6).
- **Payees** are rendered as the P2PKH address (`s1…` mainnet, `sm…` testnet/regtest) of the key
  hash, `null` when there is none (FEE-0, or a VOID release / sweep).
- **Verdicts** are the §4.2a strings (`ok`, `bad-mint-collateral`, `vault-spend-malformed`, …).
  `type` is `"mint"`, `"transfer"`, `"redeem"` or `"none"`; `path` is `"owner"`, `"claim"` or `""`.
  **v3** adds the verdicts `mint9-no-bundle`, `mint9-bundle-<reason>`, `mint10-diverged`,
  `red1-bundle-<reason>`, `red5-residual`, `afee1-fee`, where `<reason>` is a BUNDLE-1 reason:
  `shape`, `hash`, `count`, `member`, `dup`, `stale`, `range`, `sig`, `two-carriers` (v3 plan
  §4.2a, checked in that order, W8). `type` gains `"notice"` (CLAIM_NOTICE), `"register"`
  (ATTESTOR_REGISTER), `"equivocation"` and `"revive"`; `claimPath` is `"a"` (underwater under
  `pClaim`, RED-4 clause (a)), `"b"` (the emergency clause only) or `""` (not a claim).
- **v3 statuses.** Attestor statuses are the strings `"PENDING"`, `"ELIGIBLE"`, `"DORMANT"`,
  `"EJECTED"`, `"WITHDRAWN"` (v3 §3.6); the arming state `attest.status` is `"UNARMED"`,
  `"TRIGGERED"` or `"ARMED"` (ARM-1/2); `carrierMode` is `"scriptsig"`, `"opreturn"` or
  `"either"` (`BUNDLE_CARRIER`, W2); a price `source` is `"x"` (the pool cross-section bound) or
  `"a"` (the attestation quantile bound). Registration `flags` are rendered as the object
  `{"tier": 0|1|2, "pool": bool}` (bits 0–1 source tier: `0` exchange APIs, `1` mixed, `2`
  aggregator; bit 2 "operates a mining pool"; proposal §5.2) and accepted as the raw `u8` where a
  command takes them.
- **v3 attestor identity.** An attestor is named by its `seq` (number, `u16`, assigned in block
  order at registration, W4). `attestorPubKey` is the 33-byte hot key in hex; `bondAddress` is
  the P2SH address of `BondScript(bondPubKey, bondLocktime)` (the bond output itself; nothing pays
  to it) and `bondKeyAddress` the P2PKH address of `bondPubKey` — the attestation-fee payee
  (AFEE-1) and the key `yed_withdrawbond` signs with. An **attestation** is 74
  bytes — `seq u16 ‖ priceMicroUsd u32 ‖ citedHeight u32 ‖ sig 64`, little-endian, compact low-S
  ECDSA over `SHA256("YBATTEST1" ‖ seq ‖ price ‖ citedHeight ‖ blockHash(citedHeight))` — and
  travels through RPC as its hex (`hex`, 148 characters). A **bundle** is `"YA" ‖ 0x01 ‖ count ‖
  count × attestation` (≤ 448 bytes) and travels as `bundleHex`. A **selector** is the empty
  string for a MINT and the 36-byte serialised vault `COutPoint` (hex, 72 characters) for a
  REDEEM or CLAIM_NOTICE (v3 §3.7, R13); `selectorHex` takes exactly those two forms.
- **v3 weights** (`weight`) are `arith_uint256` values that exceed 2⁵³ on mainnet
  (`bondZat · AGE_CAP ≈ 4·10¹⁷`, R10) and are therefore rendered as **decimal strings**, never
  JSON numbers.
- **v3 two-step commands.** `yed_mint`, `yed_claim`, `yed_claimnotice` and
  `yed_reportequivocation` broadcast a carrier funding transaction first and the main
  transaction after its confirmation (W7). Each takes a trailing optional `wait` (boolean,
  default `true`): with `true` the call blocks until the main transaction is committed and
  returns the full shape with `pending: false`; with `false` it returns after the carrier
  broadcast with `pending: true`, `carrierTxid` set and every field the main transaction would
  supply at its zero value (`""`, `0`, `null`, `[]`); the wallet completes the transaction on
  the next `ChainTip` and `yed_listtransactions` then shows it. Whether the layer is armed or
  not, a v3 wallet always takes the carrier step for these commands: before arming the bundle
  is empty and the carrier is still created, so one code path exists (the carrier costs
  `CARRIER_VALUE` = 10,000 zat plus the network fee).
- **Gating.** Every command requires `-experimentalfeatures -yellowback`; without them the node
  answers JSON-RPC `-32601` "Method not found". Every refusal is `RPC_INVALID_PARAMETER` (a bad
  argument), `RPC_WALLET_ERROR` (funds, locking) or `RPC_VERIFY_REJECTED` (a rule), with a
  message that **begins with a stable identifier** from the table in *Error identifiers*; the
  wallet matches the identifier, never the text after it.
- **While the index is unhealthy** (`yed_getinfo.healthy == false`) every command refuses with
  `yellowback-unhealthy: <unhealthyReason>` **except** `yed_getinfo`, `yed_getblockverdict`,
  `yed_gettag`, `yed_decodepayload` and `yed_setquote` — the diagnostic and operator commands the
  runbook (`doc/yellowback-mining.md`) needs (M8). Recovery is `-reindex-yellowback`.

## Address format

A Yellowback address is Base58Check(version ‖ 20-byte key hash) with version bytes `0x1F 0xE4`
(mainnet, `ye…`), `0x20 0x07` (testnet, `yt…`), `0x20 0x02` (regtest, `yr…`); it decodes to an
ordinary P2PKH destination (`src/yellowback/address.cpp`, no `chainparams.cpp` edit). YED is
carried by `TOKEN_VALUE` (10,000 zat) P2PKH outputs assigned cents by a payload; the `ye…` prefix
is the only technical guard against sending YED to software that does not run the overlay (H9).
`yed_send`/`yed_sendmany`/`yed_validateaddress` refuse anything else with
`not-a-yellowback-address`. Sapling `ys1…` addresses are accepted as the *funding* of `yed_mint`
and the *destination* of `yed_redeem`/`yed_claim`/`yed_sweep` (§4.6), never as YED recipients.

---

## Node context (`src/rpc/yellowback.cpp`; no wallet needed)

### `yed_getinfo`

Arguments: none. Never refuses while unhealthy. `height`/`blockhash` are always the tip the index
holds (V2; `height` is `-1` and `blockhash` `""` while the index is empty). `enforcing` is `false`
under the kill switch (`-yellowbackenforce=0`), the valve (`valveTripped`, ACT-7, L7), the sunset
(`sunset`, ACT-5, L8) or an unhealthy index. `rejectedBlocks` counts blocks this node refused
(`Rejected`); `suppressedBlocks` counts rule-breaking blocks accepted by BLK-2 clause 3 because the
network had already built `VALVE_BLOCKS` on them (L11) — an information line, not an alarm.
`abandoned` is the abandonment predicate below (L10). `templatePolicy` is `"strict"` or
`"consensus"`. `miner.quoteKind` is what the next template's tag would be (`"quote"`, `"signal"`,
`"none"`); `miner.quoteAgeSeconds` is `null` when no quote is held; `miner.payoutAddress` is `null`
when the node has no payout key (then `quoteKind` is `"none"`). `params` reports every value the
Mint page derives from; on regtest `startHeight`, `sigmaRefBps`, `supplyCapBps` and
`enforceUntilHeight` are the four hashed values (§3.1, M13; `enforceUntilHeight` `0` = none).
`params.feeZat` is the network fee `YELLOWBACK_FEE`, distinct from the enforcement fee
(`feeMinZat`/`feeBps`). `params.policy.preferredPayee` is `null` unless `-yellowbackpreferredpayee`
is set. `lockedOutputs` (H10) is how many outpoints the Yellowback wallet layer holds locked
(stage (i)–(iii) of §4.6; `0` when the node runs without a wallet) and `protectedByIndex` is
`true` whenever that layer is attached: the GUI treats a mismatch between `lockedOutputs` and the
length of `yed_listunspent` as the trigger for `yed_lockcoins`.

**v3.** `attest` is the arming state at the index tip (v3 §3.6 `Attest`): `status`,
`triggerHeight`/`armHeight` (`0` while UNARMED; `armHeight = triggerHeight + ATTEST_ARM_DELAY`
once TRIGGERED), `seatedCount` = `|Snapshots[tip].seated|`, `poolSize` = attestations in this
node's attestation pool (all `seq`s, up to three each, W5), `poolFresh` = the number of
**seated** `seq`s for which the pool holds an attestation with `citedHeight > tip − REF_LAG −
ATTEST_MAX_AGE`, `carrierMode` = the `BUNDLE_CARRIER` in force, `required` = `ATTEST_REQUIRED`
of the set in force (W15; `false` means every bundle-reading rule is vacuous whatever `status`
says), `armed` = `status == "ARMED" && required`. `params` gains `attest` (every v3 §3.1 value
the Mint page and the Attestors view derive from; on regtest `armMin` and `carrierMode` are the
two additional hashed values, M13) and `params.policy.preferredAttestor` (`null` unless
`-yellowbackpreferredattestor` is set). `rebuilt` (**v3**) is `true` for the rest of the
session when this start found a `SCHEMA_VERSION` mismatch and rebuilt the index from the chain.

Result of `yed_getinfo`:

```json
{
  "rpcversion": 3,
  "enabled": true,
  "network": "regtest",
  "height": 331,
  "blockhash": "0f3a9c1e5b7d2a4c6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f",
  "chainHeight": 331,
  "startHeight": 1,
  "healthy": true,
  "unhealthyReason": "",
  "enforcing": true,
  "valveTripped": false,
  "sunset": false,
  "rejectedBlocks": 0,
  "suppressedBlocks": 0,
  "templatePolicy": "strict",
  "abandoned": false,
  "lockedOutputs": 2,
  "protectedByIndex": true,
  "rebuilt": false,
  "activation": {
    "status": "active",
    "lockInHeight": 129,
    "activateHeight": 193,
    "signalCount": 64,
    "window": 64
  },
  "attest": {
    "status": "ARMED",
    "triggerHeight": 300,
    "armHeight": 308,
    "seatedCount": 3,
    "poolSize": 9,
    "poolFresh": 3,
    "carrierMode": "scriptsig",
    "required": true,
    "armed": true
  },
  "miner": {
    "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111",
    "signal": true,
    "quoteKind": "quote",
    "quoteAgeSeconds": 12,
    "registered": true,
    "eligible": true
  },
  "params": {
    "startHeight": 1,
    "enforceUntilHeight": 0,
    "sigmaRefBps": 0,
    "supplyCapBps": 0,
    "refLag": 2,
    "refWindow": 40,
    "grace": 24,
    "payeeWindow": 10,
    "feeMinZat": 50000000,
    "feeBps": 25,
    "tokenValueZat": 10000,
    "feeZat": 1000,
    "valveBlocks": 6,
    "abandonBlocks": 128,
    "windows": { "fast": 8, "mid": 24, "slow": 64, "signal": 64 },
    "minFill": { "fast": 4, "mid": 16, "slow": 43 },
    "classes": [
      { "class": "A", "minBlocks": 48, "maxBlocks": 96, "baseRatioBps": 50000 }
    ],
    "globalRatioHaltBps": 25000,
    "recapRatioBps": 50000,
    "policy": {
      "penaltyBlocks": 12,
      "accuracyWindow": 24,
      "tiltBps": 10000,
      "preferredPayee": null,
      "preferredAttestor": null
    },
    "attest": {
      "payloadVersion": 3,
      "armMin": 3,
      "armDelay": 8,
      "required": true,
      "carrierMode": "scriptsig",
      "nSlots": 5,
      "mSelect": 2,
      "kSlack": 1,
      "bundleMax": 6,
      "qLowBps": 3333,
      "qHighBps": 6667,
      "attestMaxAge": 8,
      "pinWindow": 16,
      "pinDeltaBps": 500,
      "pinMinTags": 2,
      "pinMinBundles": 2,
      "divergeBpsAttest": 1500,
      "emergencyRatioBps": 10500,
      "emergencyPersist": 4,
      "emergencyNoticeTtl": 64,
      "residualMinZat": 100000,
      "attestFeeBps": 2500,
      "bondMinZat": 1000000000,
      "bondMinLock": 200,
      "bondMaturity": 8,
      "ageCap": 64,
      "foundingWindow": 16,
      "dormancyBlocks": 16,
      "dormancyMinBundles": 2,
      "dormancyCheck": 4,
      "carrierValueZat": 10000
    }
  }
}
```

`classes` always has three rows (A, B, C) in class order; the example shows one. Every value in
`params` other than the four hashed regtest values (six with **v3**'s `attest.armMin` and
`attest.carrierMode`) is compiled into the network's parameter set (§3.1) — a wallet may display
them but must not treat them as configurable. `params.attest` names are the v3 §3.1 rows in
lowerCamelCase (`ATTEST_ARM_MIN` → `armMin`, `BOND_MIN` → `bondMinZat` in zatoshi, …);
`carrierValueZat` is wallet policy and reported for display only.

### `yed_getstatehash [height]`

Arguments: `height` (number, optional) — must equal the index height when given (the index holds
one state). Unchanged from v1: `statehash` is SHA-256 over the §3.6 preimage (`Tip`, `Tags`,
`Judgements`, `Activation`, `Vaults`, `Tokens`, `Totals`, `Snapshots`, `Params`; `TxLog`,
`Rejected` and `Undo` excluded, N18). Two nodes on the same chain with the same parameters
return the same hash; `yellowback_model.py` recomputes it from `yed_gethistory`.

Result of `yed_getstatehash`:

```json
{
  "height": 331,
  "blockhash": "0f3a9c1e5b7d2a4c6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f",
  "statehash": "9b4e2f1c8d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"
}
```

### `yed_getstats`

Arguments: none. `Totals` plus the tip snapshot. `pClaim` is `null` when undefined (fewer than
the minimum fill on the mid or slow window); `globalRatioBps` is `null` when there is no supply or
no `pMint`; `supplyCapCents` is `null` when there is no cap (`supplyCapBps == 0` or no price).
`haltMask` is the decoded tip `haltMask` as an array of names (empty when minting is open);
`mintingAllowed` is `activation == active && haltMask == [] && cap has room` — every class can
mint. **v3 (W16)** `mintableClasses` is the list of term classes a mint can use *now*: every
class when `mintingAllowed`; under a `GLOBAL_RATIO` halt alone, the classes whose minimum ratio
(`baseRatioBps · sigmaMultBps / 10⁴`) reaches `params.recapRatioBps` (class A on every network
at a sigma multiplier of 1); empty under any other halt or at the cap. The MINTPOL-1 gate
`yed_mint` applies is "the class of `lockBlocks` is in `mintableClasses`".

Result of `yed_getstats`:

```json
{
  "height": 331,
  "supplyCents": 250000,
  "collateralZat": 62500000000,
  "activeVaults": 3,
  "voidVaults": 1,
  "closedVaults": 2,
  "claimedVaults": 0,
  "unbackedCents": 0,
  "issuedZat": 1656250000000,
  "pFast": 2000000,
  "pMid": 2000000,
  "pSlow": 1990000,
  "pMint": 1990000,
  "pClaim": 2000000,
  "sigmaMultBps": 10000,
  "globalRatioBps": 49750,
  "supplyCapCents": null,
  "haltMask": [],
  "mintingAllowed": true,
  "mintableClasses": [ "A", "B", "C" ]
}
```

### `yed_getprice [height]`

Arguments: `height` (number, optional; default the index tip; must be `≥ startHeight` and
`≤ tip`). The snapshot prices at that height with the window fills that produced them and the
tag of that block (`tag` has exactly the shape of `yed_gettag`). Prices `null` when undefined.

**v3.** The snapshot's `pMint`/`pClaim` are the pool **cross-section** medians (v3 §3.6 renames
them `xMint`/`xClaim`; the combined `pMint = min(xMint, aMint)` / `pClaim = max(xClaim, aClaim)`
of PRICE-2 exists only per transaction, in `yed_gettxinfo`). The v2 keys `pMint`/`pClaim` keep
reporting exactly the snapshot values, now also exposed as `xMint`/`xClaim` (**v3**, identical
numbers) — a v2 reader sees nothing change. Added: `armed` (`Snapshots[height].attest.status ==
"ARMED"` and `ATTEST_REQUIRED` — what a transaction with `refHeight = height` is judged under),
`attestStatus` (the snapshot's arming status string), `seated` (the `seq`s of
`Snapshots[height].seated[]`, ascending), `pinnedKeys` (the P2PKH addresses of PIN-1's excluded
pool keys at that height; empty when the test is not armed) and `pinnedSeqs` (PIN-2's excluded
`seq`s). `xMint` is the median over the tags of keys **not** in `pinnedKeys`.

Result of `yed_getprice`:

```json
{
  "height": 331,
  "pFast": 2000000,
  "pMid": 2000000,
  "pSlow": 1990000,
  "pMint": 1990000,
  "pClaim": 2000000,
  "xMint": 1990000,
  "xClaim": 2000000,
  "armed": true,
  "attestStatus": "ARMED",
  "seated": [ 1, 2, 3 ],
  "pinnedKeys": [ "smQvTmAz2ExamplePayoutAddress1111111" ],
  "pinnedSeqs": [ 3 ],
  "fill": {
    "fast": { "quoteTags": 8, "window": 8, "minFill": 4 },
    "mid": { "quoteTags": 24, "window": 24, "minFill": 16 },
    "slow": { "quoteTags": 60, "window": 64, "minFill": 43 }
  },
  "tag": {
    "found": true,
    "kind": "quote",
    "version": 1,
    "signal": true,
    "priceMicroUsd": 2000000,
    "sourceMask": 3,
    "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111"
  }
}
```

### `yed_getactivation`

Arguments: none. The ACT-1..7 state at the tip. `window`, `threshold`, `participationFloor`,
`enforcementFloor`, `enforcementResume` are the network constants (`SIGNAL_WINDOW`,
`ACTIVATION_THRESHOLD`, `PARTICIPATION_FLOOR`, `ENFORCEMENT_FLOOR`, `ENFORCEMENT_RESUME`);
`signalCount` is the tip's; `lockInHeight`/`activateHeight` are `0` until reached. `mintHalted`
is the tip's `PARTICIPATION` bit (ACT-4), `enforcementSuspended` its `ENFORCEMENT` bit (ACT-6).
`enforcing`, `valveTripped`, `sunset` are as `yed_getinfo`; `enforceUntilHeight` is
`ENFORCE_UNTIL_HEIGHT` (`0` = none). `history` samples `signalCount` every `SIGNAL_WINDOW / 8`
blocks ending at the tip (8 rows, oldest first; fewer when the chain is shorter than a window).

Result of `yed_getactivation`:

```json
{
  "status": "active",
  "lockInHeight": 129,
  "activateHeight": 193,
  "signalCount": 64,
  "window": 64,
  "threshold": 48,
  "participationFloor": 39,
  "enforcementFloor": 32,
  "enforcementResume": 39,
  "mintHalted": false,
  "enforcementSuspended": false,
  "enforcing": true,
  "valveTripped": false,
  "sunset": false,
  "enforceUntilHeight": 0,
  "history": [
    { "height": 331, "signalCount": 64 }
  ]
}
```

### `yed_listminers [height] [window]`

Arguments: `height` (number, optional; default the tip), `window` (number, optional; default
`PAYEE_WINDOW`; the launch bar uses `2016`, L4). One row per `payoutKey` that carries a quote tag
in `(height − window, height]`, in descending `lastTagHeight` order. `share` is the row's share
of the quote-tagged blocks in the window in bps; `registered` is REG-1 at `height`, `eligible`
membership in `E(height)` (FEE-2); `penalizedUntil` is the height the REG-2 penalty ends, `0`
when not penalised; `accuracyBps` is REG-3 over the node's accuracy window, `null` when no tag of
this key has been judged in it; `quoted` and `inBand` are the judged quote tags of this key in
that window and how many of them REG-4 found within `ACCURACY_BAND_BPS`.

Result of `yed_listminers`:

```json
[
  {
    "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111",
    "lastTagHeight": 331,
    "lastQuote": 2000000,
    "quoteTags": 4,
    "share": 4000,
    "registered": true,
    "eligible": true,
    "penalizedUntil": 0,
    "accuracyBps": 9800,
    "quoted": 8,
    "inBand": 8
  }
]
```

### `yed_gettag <height|blockhash>`

Arguments: one **string** (no `client.cpp` conversion): all digits ⇒ a height on the active
chain, otherwise a block hash of a stored block. Decodes the coinbase tag (TAG-1..5) of that
block. When `found` is `false` (no tag, or a height below `startHeight`) `kind` is `"none"` and
the other fields are absent (**optional**). `kind` is `"quote"` or `"signal"`; a signal-only tag
has `priceMicroUsd: 0`. Allowed while unhealthy.

Result of `yed_gettag`:

```json
{
  "found": true,
  "kind": "quote",
  "version": 1,
  "signal": true,
  "priceMicroUsd": 2000000,
  "sourceMask": 3,
  "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111"
}
```

### `yed_setquote <priceMicroUsd> <sourceMask>`

Arguments: `priceMicroUsd` (number; `0` clears the quote so the next tag is signal-only or
none), `sourceMask` (number, 16-bit; the §5 source-bit registry). Miner control (MINER-1): stores
`{quote, sourceMask, receivedAt = GetTime()}`; requires RPC auth like every command. Allowed
while unhealthy (the tag is not emitted then, MINER-3, but the quote is kept). `nextTag` is what
the next template would carry given the stored quote, `-yellowbackquotemaxage`,
`-yellowbacksignal`, `-yellowbackenforce`, the valve and the sunset (`kind` `"quote"`,
`"signal"` or `"none"`; `payoutAddress` `null` when there is no payout key — but then the command
has already refused with `no-payout-address`). `receivedAt` is Unix seconds on the node's clock.
The quote agent (`contrib/yellowback/yellowback-quote`) calls this every `poll_seconds` and
`yed_setquote 0 0` after `fail_polls` failed aggregates (L5).

Result of `yed_setquote`:

```json
{
  "priceMicroUsd": 2000000,
  "sourceMask": 3,
  "receivedAt": 1789000000,
  "nextTag": {
    "kind": "quote",
    "signal": true,
    "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111"
  }
}
```

### `yed_getfeepayee <refHeight> <collateralZat> [selectorHex]`

Arguments: `refHeight` (number), `collateralZat` (number), `selectorHex` (string, optional; the
33-byte owner key of a MINT or the 36-byte serialised vault outpoint of a REDEEM). For external
transaction builders: `eligible` is `E(refHeight)` (FEE-2, height order, deduplicated), `feeZat`
is FEE-1 for that collateral, `default` is the FEE-W choice for the selector with its weight
(`10⁴ + tiltBps · accuracyBps / 10⁴`; when no selector is given the choice for an all-zero
selector), `preferred` (**optional**) is present only when `-yellowbackpreferredpayee` is
configured and in `E(refHeight)` — it then replaces `default` for the wallet — and `policy` is
the L6 values the node used. Refuses with `fee-no-eligible-payee` when `E(refHeight)` is empty
(FEE-0; the wallet then omits the fee output and never calls this).

Result of `yed_getfeepayee`:

```json
{
  "eligible": [
    "smQvTmAz2ExamplePayoutAddress1111111"
  ],
  "feeZat": 50000000,
  "default": {
    "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111",
    "weight": 19800
  },
  "preferred": "smQvTmAz2ExamplePayoutAddress1111111",
  "policy": { "penaltyBlocks": 12, "accuracyWindow": 24, "tiltBps": 10000 }
}
```

### `yed_getvault <txid>`

Arguments: `txid` (string; vault outpoints are always `vout 0`). The `Vaults` record plus
derived fields. `collateral` is the decimal-YEC twin of `collateralZat`. `voidReason` is the
verdict of the MINT rule that failed, `""` for a vault that was ever ACTIVE. `closeHeight`,
`closingTxid`, `burnedCents` are `null`/`""`/`0` until the vault is CLOSED or CLAIMED
(`closingTxid` `""`, `closeHeight` `null`). `claimable` is true for an ACTIVE vault at or past
`claimHeight` that is underwater at the tip snapshot (RED-4 would pass); `underwaterAt` is the
`pClaim` (µUSD) below which `collateralZat · pClaim < mintedCents · CLAIM_THRESHOLD_BPS`, i.e. the
price at which the vault becomes claimable (`null` for a VOID vault, which has no debt). `unbacked`
is true for a vault closed without its burn (a sweep, IN-2). **`sweepBefore`** (**optional**,
= `claimHeight`) is present on every VOID vault (its claim path is anyone-can-spend after
`claimHeight`, K3) and on every ACTIVE vault while abandonment holds (L10); absent otherwise.
The prototype's `tier`, `rosterIndex`, `errBpsAtClose`, `requiredBurnCents`, `indexHeight` are
gone. Refuses with `vault-not-found`.

**v3.** `noticed` is whether a `Notices` record stands for this vault (NOT-1; always `false` for
a vault that is not ACTIVE — the record is deleted when the vault leaves ACTIVE); `noticeHeight`
is the block the standing notice confirmed in and `emergencyOpenAt` = `notice.refHeight +
EMERGENCY_PERSIST`, the first `refHeight` at which RED-4 clause (b) can open a claim; both
`null` when `noticed` is `false`. `yed_getnotice` gives the whole record.

Result of `yed_getvault`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "vout": 0,
  "status": "ACTIVE",
  "ownerPubKey": "02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "ownerKeyId": "1f2e3d4c5b6a79880706050403020100f1e2d3c4",
  "ownerAddress": "yrExampleOwnerAddress111111111111111",
  "termClass": "A",
  "lockHeight": 380,
  "claimHeight": 404,
  "collateralZat": 25125628141,
  "collateral": 251.25628141,
  "mintedCents": 100000,
  "mintHeight": 332,
  "refHeight": 329,
  "feePaidZat": 62814071,
  "closeHeight": null,
  "closingTxid": "",
  "burnedCents": 0,
  "unbacked": false,
  "claimable": false,
  "underwaterAt": 437800,
  "voidReason": "",
  "sweepBefore": 404,
  "noticed": false,
  "noticeHeight": null,
  "emergencyOpenAt": null
}
```

### `yed_listvaults [status] [count] [skip]`

Arguments: `status` (string, optional; `""` or absent = every status, else one of `ACTIVE`,
`VOID`, `CLOSED`, `CLAIMED`), `count` (number, default `100`), `skip` (number, default `0`).
Paged, in ascending outpoint order; the result is a **list** of `yed_getvault` rows (an empty
list past the end). The prototype's `rosterIndex` argument and its `{height, total, vaults}`
envelope are gone (the `client.cpp` row is now `1,2`).

Result of `yed_listvaults`:

```json
[
  {
    "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    "vout": 0,
    "status": "ACTIVE",
    "ownerPubKey": "02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
    "ownerKeyId": "1f2e3d4c5b6a79880706050403020100f1e2d3c4",
    "ownerAddress": "yrExampleOwnerAddress111111111111111",
    "termClass": "A",
    "lockHeight": 380,
    "claimHeight": 404,
    "collateralZat": 25125628141,
    "collateral": 251.25628141,
    "mintedCents": 100000,
    "mintHeight": 332,
    "refHeight": 329,
    "feePaidZat": 62814071,
    "closeHeight": null,
    "closingTxid": "",
    "burnedCents": 0,
    "unbacked": false,
    "claimable": false,
    "underwaterAt": 437800,
    "voidReason": "",
    "sweepBefore": 404,
    "noticed": false,
    "noticeHeight": null,
    "emergencyOpenAt": null
  }
]
```

### `yed_listtokens <addresses> [minHeight]`

Arguments: `addresses` (array of strings, 1..100; each a YED address `ye…`/`yt…`/`yr…` or the
transparent P2PKH form `s1…`/`sm…` of the same key hash — the two name one script), `minHeight`
(number, default `0`: only tokens created at or above it). **Node context**: the `Tokens` records
(§3.6) whose `scriptPubKey` pays one of the addresses, whoever holds the keys — the authoritative
YED UTXO set of an address, which `yed_listunspent` gives only for the node's own wallet. This is
the RPC a light-client server proxies for a wallet it has never seen (lightwalletd plan D-L-7,
`GetAddressTokens`). A full scan of the live token set (spent tokens are erased by IN-1), sorted
by `(height, txid, vout)`; `address` is the YED form, `transparentAddress` the `s…` form. Refuses
with `too-many-addresses` (none, or more than 100) and `invalid-address` (a string that is neither
form on this network).

Result of `yed_listtokens`:

```json
[
  {
    "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    "vout": 1,
    "cents": 100000,
    "valueZat": 10000,
    "height": 332,
    "address": "yrExampleOwnerAddress111111111111111",
    "transparentAddress": "smQvTmAz2ExamplePayoutAddress1111111"
  }
]
```

### `yed_listclaimable`

Arguments: none. ACTIVE vaults past `claimHeight` that are underwater at the tip snapshot — the
source of the wallet's Claim page. `mintedCents` is the burn a claim must carry (RED-2), `feeZat`
the FEE-1 fee it pays from the collateral, `pClaim` the tip's claim price (never `null` here: an
undefined `pClaim` makes RED-4 false, so nothing is claimable). Empty list when nothing is.

**v3.** While armed, "claimable" means RED-4 by clause (a) under the tip's combined `pClaim`
computed with the bundle this node **would build** from its pool for that vault (selector = the
vault outpoint), **or** by clause (b) when a notice has persisted (`emergencyOpenAt ≤ tip −
REF_LAG` and the emergency inequality holds under `pEmerg`). `pClaim` is then that combined
price; `claimPath` says which clause opened it. Rows gain `noticed`, `noticeHeight`,
`emergencyOpenAt` (as `yed_getvault`), `residualZat` (RED-5's amount the claim must return to
the owner; `0` for a clause-(a) claim at the threshold) and `attestFeeZat` (AFEE-1). A vault
that is under `EMERGENCY_RATIO_BPS` but not yet claimable is **not** listed here; the wallet
finds it through `yed_listpositions`/`yed_getvault.underwaterAt` and offers `yed_claimnotice`.
When no bundle can be built (`bundle-insufficient` would be raised) the list is computed from
the cross-section alone and every row carries `claimPath: ""` — the wallet must expect
`yed_claim` to refuse until the pool refills.

Result of `yed_listclaimable`:

```json
[
  {
    "vault": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8:0",
    "ownerAddress": "yrExampleOwnerAddress111111111111111",
    "collateralZat": 25125628141,
    "mintedCents": 100000,
    "feeZat": 62814071,
    "claimHeight": 404,
    "underwaterAt": 437800,
    "pClaim": 400000,
    "claimPath": "a",
    "noticed": false,
    "noticeHeight": null,
    "emergencyOpenAt": null,
    "residualZat": 0,
    "attestFeeZat": 15703517
  }
]
```

### `yed_gettxinfo <txid>`

Arguments: `txid` (string). The `TxLog` record of a confirmed transaction that created or spent
`Tokens`/`Vaults` (N7; `-txindex` is not required). `assigned` lists the cents the payload
assigned per output, `spentTokens` the `Tokens` outpoints consumed (IN-1), `closedVaults` the
vaults closed (IN-2), `payee` the fee output's address or `null`. `expired` is true — with
`height: -1` and `verdict: "expired"` — for a wallet transaction past its `nExpiryHeight` that is
in neither `TxLog` nor the mempool (§4.6; only meaningful on a node with a wallet). A txid the index
does not know and the wallet does not hold is refused with `tx-not-found`.

**v3** (`TxLog` additions, v3 §3.6): `aMint`/`aClaim` are the bundle statistic of this
transaction's verified bundle (`null` when it carried none or BUNDLE-1 failed), `xMint`/`xClaim`
the cross-section at its `refHeight`, `pMint`/`pClaim` the combined PRICE-2 prices it was judged
under (`null` when undefined; equal to `x…` when not armed), `bundleSeqs` the `seq`s of its
contributing attestations `C` (ascending; empty when none), `attestFeeZat` and `attestPayee`
(the `bondKeyAddress` paid, `null` under AFEE-0), `residualZat` (RED-5's amount, `0` when none was
due), `claimPath` (`"a"`, `"b"` or `""`), `notice` (`true` when this transaction wrote a
`Notices` record — a CLAIM_NOTICE that NOT-1 accepted), `carrierVin` (the input index of the
carrier, `-1` when none) and `bundleSource` (`"scriptsig"`, `"opreturn"` or `""`). `type` gains
`"notice"`, `"register"`, `"equivocation"`, `"revive"`; for `"register"` `seq` (**optional**)
is the assigned sequence number.

Result of `yed_gettxinfo`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "height": 332,
  "type": "mint",
  "path": "",
  "verdict": "ok",
  "yedIn": 0,
  "yedOut": 100000,
  "burned": 0,
  "feeZat": 62814071,
  "payee": "smQvTmAz2ExamplePayoutAddress1111111",
  "assigned": [
    { "vout": 1, "cents": 100000 }
  ],
  "spentTokens": [
    { "txid": "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b", "vout": 1 }
  ],
  "closedVaults": [
    { "txid": "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b", "vout": 0 }
  ],
  "expired": false,
  "xMint": 1990000,
  "xClaim": 2000000,
  "aMint": 1985000,
  "aClaim": 1995000,
  "pMint": 1985000,
  "pClaim": 2000000,
  "bundleSeqs": [ 1, 2 ],
  "attestFeeZat": 15703517,
  "attestPayee": "smExampleBondAddress11111111111111111",
  "residualZat": 0,
  "claimPath": "",
  "notice": false,
  "carrierVin": 1,
  "bundleSource": "scriptsig"
}
```

### `yed_decodepayload <hex>`

Arguments: `hex` (string): a payload, an `OP_RETURN` script or a raw transaction. Decodes the
**version-3** payload (v3 §3.3) without touching state; allowed while unhealthy. `valid` is false
— with `type: "none"` and `reason` naming the defect — for anything §3.3 calls malformed or
unknown, **including a version-1 or version-2 payload** (`reason: "version"`, V23).
Type-specific fields: MINT `termClass`, `cents`, `lockHeight`, `refHeight`, `ownerPubKey`,
`feeVout` (`255` = none), `attestFeeVout` (**v3**, `255` = none); TRANSFER `assignments:
[{vout, cents}]`, `assignedCents`; REDEEM `refHeight`, `feeVout`, `attestFeeVout`,
`assignments`, `assignedCents`; **v3** `register` (`0x05`) `attestorPubKey`, `bondPubKey`,
`bondAddress`, `bondKeyAddress`, `bondLocktime`, `flags {tier, pool}`; `notice` (`0x06`) `vault {txid, vout}`,
`refHeight`; `equivocation` (`0x07`) nothing; `revive` (`0x08`) `attestation {seq,
priceMicroUsd, citedHeight, sig, hex}`. Fields of the other types are absent (**optional** — the
checker decodes a MINT payload, the example). When `hex` is a **raw transaction** that has a
carrier-shaped input (v3 §3.4), `bundle` (**optional**) is the decoded bundle — `{vin, hash,
version, count, attestations: [{seq, priceMicroUsd, citedHeight, sig, hex}]}` — decoded only,
never verified (`yed_validaterawtransaction` verifies).

Result of `yed_decodepayload`:

```json
{
  "valid": true,
  "version": 3,
  "type": "mint",
  "reason": "",
  "termClass": "A",
  "cents": 100000,
  "lockHeight": 380,
  "refHeight": 329,
  "ownerPubKey": "02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "feeVout": 3,
  "attestFeeVout": 4
}
```

### `yed_validaterawtransaction <hex>`

Arguments: `hex` (string; a complete, normally signed transaction). Dry run of §3.8 at the tip
(`EvaluateBlock` over a one-transaction pseudo-block at `tip + 1`, exactly `MempoolCheck`'s
predicate) plus `VerifyAllInputs` for the scripts (`valid`). For a vault spend `blockValid` is
RED-1..4 (BLK-1's condition, independent of activation) and `wouldBeRejected` says whether an
enforcing miner refuses it — `!blockValid`, or the MP-1 expiry bound (`mempoolExpiryOk` false:
`nExpiryHeight == 0` or `> refHeight + REF_WINDOW`) — *unless* abandonment holds (L13), when it
is false. `unconfirmedInputs` lists inputs the index does not know (unconfirmed parents; the
verdict cannot see them, M13). Never commits anything.

Result of `yed_validaterawtransaction`:

```json
{
  "valid": true,
  "verdict": "ok",
  "type": "redeem",
  "path": "owner",
  "yedIn": 100000,
  "yedOut": 0,
  "burned": 100000,
  "feeZat": 62814071,
  "payee": "smQvTmAz2ExamplePayoutAddress1111111",
  "blockValid": true,
  "wouldBeRejected": false,
  "mempoolExpiryOk": true,
  "unconfirmedInputs": [
    { "txid": "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b", "vout": 1 }
  ]
}
```

### `yed_getblockverdict <blockhash>`

Arguments: `blockhash` (string; a block the node has on disk). Runs `EvaluateBlock` on the
stored block and explains a rejection: `blockInvalid` is BLK-1's condition, `enforcementOn` ACT-5
at that height (from `Snapshots[H − 1]`, incl. the sunset), `reason` is `"<verdict>:<txid>"` of
the first failing vault spend or `""`. `transactions` lists every Yellowback-relevant
transaction in block order with its verdict; `closedVaults` as `yed_gettxinfo`. Allowed while
unhealthy. **Precondition (N12):** refuses with `verdict-parent-not-tip` unless the block's
parent is the index tip (a candidate child, or the block the node just rejected) or the block is
in `Rejected` with the current tip as its parent — the state at any other parent would need an
undo replay.

Result of `yed_getblockverdict`:

```json
{
  "blockInvalid": true,
  "reason": "vault-spend-short-burn:6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "enforcementOn": true,
  "transactions": [
    {
      "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
      "type": "redeem",
      "path": "owner",
      "verdict": "vault-spend-short-burn",
      "yedIn": 50000,
      "yedOut": 0,
      "feeZat": 62814071,
      "payee": "smQvTmAz2ExamplePayoutAddress1111111",
      "closedVaults": [
        { "txid": "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b", "vout": 0 }
      ]
    }
  ]
}
```

### `yed_estimatecollateral <cents> <lockBlocks> [priceMicroUsd]`

Arguments: `cents` (number), `lockBlocks` (number; the class follows from it, V19),
`priceMicroUsd` (number, optional; replaces the snapshot's `pMint`). At the current reference
snapshot `R = tip − REF_LAG`: `termClass`, `baseRatioBps` for the class, `sigmaMultBps`
(SIGMA-1), `minRatioBps = MinRatioBps(base, sigma)`, `pMint` (`null` when undefined and no price
was given — then `requiredZat` is `null` too), `requiredZat` rounded up to 1,000 zat,
`lockHeight = R + lockBlocks`, `claimHeight = lockHeight + GRACE`, `refHeight = R`. Refuses with
`mint-bad-lock` (`lockBlocks` outside every class, or `lockHeight + GRACE ≥ LOCKTIME_THRESHOLD`)
and `mint-unsatisfiable` (`requiredZat > MAX_MONEY`, K14). It does not apply MINTPOL-1: a halted
gate still estimates, so the Mint page can show the figure next to the halt reason.

**v3.** While `Snapshots[R]` is armed the estimate uses the **combined** `pMint = min(xMint,
aMint)` of PRICE-2 with the bundle this node would build from its pool for a MINT at `R` (empty
selector, W9): `xMint` and `aMint` are both reported, `source` says which bound (`"x"` or
`"a"`; `""` when not armed or a `priceMicroUsd` override was given), `armed` is the snapshot's
arming state, `bundleSeqs` the `seq`s the estimate used (empty when not armed), `attestFeeZat`
the AFEE-1 fee that mint would pay on top of `feeZat`, and `divergenceBps` = `|pFast − aMint| ·
10⁴ / min(xMint, aMint)` (`null` when either is undefined). Refuses with `bundle-insufficient`
when armed and fewer than `M_SELECT` of the selected attestors have a fresh attestation in the
pool (the message names the missing `seq`s), and with `mint10-diverged` when `divergenceBps >
DIVERGE_BPS_ATTEST` — the two refusals `yed_mint` would give, surfaced before the user commits.
A `priceMicroUsd` override bypasses both sources and both refusals, as in v2.

Result of `yed_estimatecollateral`:

```json
{
  "requiredZat": 25125628141,
  "termClass": "A",
  "lockHeight": 380,
  "claimHeight": 404,
  "minRatioBps": 50000,
  "baseRatioBps": 50000,
  "sigmaMultBps": 10000,
  "pMint": 1985000,
  "refHeight": 329,
  "xMint": 1990000,
  "aMint": 1985000,
  "source": "a",
  "armed": true,
  "bundleSeqs": [ 1, 2 ],
  "attestFeeZat": 15703517,
  "divergenceBps": 25
}
```

### `yed_listattestors [height]` (v3)

Arguments: `height` (number, optional; default the index tip; `seated`/`pinned`/`weight` are
evaluated at that height's snapshot, the records are always the current table). Every
`Attestors` record (v3 §3.6), ascending `seq`. `bondOutpoint` is `txid:0` of the registration;
`bondAddress` the P2SH address of `BondScript(bondPubKey, bondLocktime)` (the bond output itself);
`bondKeyAddress` the P2PKH address of `bondPubKey` (where attestation fees are paid);
`bondLocktime` the CLTV height; `flags` the decoded registration flags; `status` one of the five
attestor statuses and `statusHeight` the height it was last set; `bondSpentHeight` `null` until
the bond outpoint is spent (IN-2); `seatedSince` the height the attestor entered `seated[]`,
`null` while unseated; `weight` the bond weight at `height` as a decimal string (`"0"` before
its `ageOrigin`); `seated` and `pinned` membership in `Snapshots[height].seated[]` /
`pinnedSeqs[]`; `lastBundleHeight` the newest `BundleLog` row whose `seqs[]` holds this `seq`
(`null` when none); `poolFresh` whether this node's pool holds an attestation of this `seq` with
`citedHeight > height − REF_LAG − ATTEST_MAX_AGE`. `founding` is whether the record's age runs
from `triggerHeight` (v3 §3.7 founding cohort; `false` while UNARMED). Empty list before the
first registration.

Result of `yed_listattestors`:

```json
[
  {
    "seq": 1,
    "attestorPubKey": "03b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071829304a5b6c7d8e9f0",
    "bondAddress": "smExampleBondAddress11111111111111111",
    "bondKeyAddress": "smExampleBondKeyAddr11111111111111111",
    "bondOutpoint": { "txid": "7b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f708192a3b4c5d6e7f809", "vout": 0 },
    "bondZat": 1000000000,
    "bondLocktime": 500,
    "flags": { "tier": 0, "pool": false },
    "registerHeight": 280,
    "status": "ELIGIBLE",
    "statusHeight": 288,
    "bondSpentHeight": null,
    "seatedSince": 300,
    "founding": true,
    "weight": "31000000000",
    "seated": true,
    "pinned": false,
    "lastBundleHeight": 330,
    "poolFresh": true
  }
]
```

### `yed_getattestations` (v3)

Arguments: none. This node's **attestation pool** (W5; in-memory, non-consensus, refilled by the
subscriber through `yed_addattestation`): every held attestation, ascending `seq` then
`citedHeight`. `receivedHeight` is the index tip when it was pooled; `seated` whether its `seq`
is in the tip snapshot's `seated[]`; `fresh` whether `citedHeight > tip − REF_LAG −
ATTEST_MAX_AGE`; `hex` the 74 bytes. Empty list after a restart until the subscriber refills it.

Result of `yed_getattestations`:

```json
[
  {
    "seq": 1,
    "priceMicroUsd": 1985000,
    "citedHeight": 329,
    "receivedHeight": 331,
    "seated": true,
    "fresh": true,
    "hex": "0100e84a1e00490100002b3c…"
  }
]
```

### `yed_addattestation <hex>` (v3)

Arguments: `hex` (string; exactly 74 bytes). Verifies one attestation against the tip and pools
it (S4: any `seq` whose record is not EJECTED or WITHDRAWN is accepted — a subscriber that
starts before arming must not refuse everything; selection at build time decides relevance).
Checks, in order, each with its identifier: `attest-unknown-seq` (no `Attestors` record),
`attest-not-eligible` (EJECTED or WITHDRAWN), `attest-stale` (`citedHeight ≤ tip − REF_LAG −
ATTEST_MAX_AGE`, or above the index tip, or below `startHeight`), `attest-range` (price outside
`[PRICE_MIN, PRICE_MAX]`), `attest-bad-sig` (compact low-S ECDSA under `attestorPubKey(seq)`
over the message with this chain's `blockHash(citedHeight)` fails — a high-S signature is
"bad", never normalised, R17). On success the pool keeps the newest three per `seq`
(`⌈ATTEST_MAX_AGE / k⌉ + 1`, W5): `accepted` is `true`; `replaced` is `true` when an older
attestation of this `seq` was dropped to make room, or when the pool already held a different
attestation of this `seq` for the same `citedHeight` (the newest wins — the pool is not the
equivocation detector, `yed_reportequivocation` is); a byte-identical resubmission is `accepted:
true, replaced: false`. `RPC_INVALID_PARAMETER` (`attest-malformed`) for anything not 74 bytes
of hex. RPC-auth only; never gated on the wallet.

Result of `yed_addattestation`:

```json
{
  "accepted": true,
  "seq": 1,
  "priceMicroUsd": 1985000,
  "citedHeight": 329,
  "replaced": false,
  "poolSize": 9
}
```

### `yed_buildbundle <refHeight> <selectorHex>` (v3)

Arguments: `refHeight` (number; `startHeight ≤ refHeight ≤ tip`), `selectorHex` (string; `""`
for a MINT, the 72-hex-character serialised vault outpoint for a REDEEM or CLAIM_NOTICE). The
bundle this node would build for `(R, selector)` from its pool (W6, W9): `selected` is
`selected(R, selector)` in draw order, `seqs` the `seq`s that contributed (the newest pooled
attestation per selected `seq` with `citedHeight ∈ (R − ATTEST_MAX_AGE, R]`, ascending `seq` in
the bundle), `missing` the selected `seq`s with no usable attestation, `hex` the bundle bytes
(`"YA" ‖ 0x01 ‖ count ‖ attestations`), `count` = `|seqs|`, `aMint`/`aClaim` the bundle statistic
over those attestations with weights at `R`, `armed` the snapshot's arming state. Refuses with
`bundle-insufficient` when `count < M_SELECT` (the message is `bundle-insufficient: <count> of
<|selected|> selected attestors have a fresh attestation; missing seq <a,b,…>`), with
`RPC_INVALID_PARAMETER` for a `selectorHex` that is neither empty nor 36 bytes, and it **does
not refuse while unarmed** — a bundle can be built and inspected before arming (it is simply
read by no rule). The result is what `yed_mint … bundleHex` accepts verbatim; the manual path
under total transport failure.

Result of `yed_buildbundle`:

```json
{
  "refHeight": 329,
  "selector": "",
  "armed": true,
  "selected": [ 2, 1, 3 ],
  "seqs": [ 1, 2 ],
  "missing": [ 3 ],
  "count": 2,
  "hex": "594101020100e84a1e0049010000…",
  "aMint": 1985000,
  "aClaim": 1995000
}
```

### `yed_getselection <refHeight> <selectorHex>` (v3)

Arguments as `yed_buildbundle`. `selected(R, selector)` (v3 §3.7, W9) with what the wallet needs
for its "*n* of *m* selected attestors reachable" line: `pool` is `Snapshots[R].seated[] \
pinnedSeqs[]`, `selected` the drawn `seq`s in draw order, each with its `weight` at `R` (decimal
string), `bondKeyAddress`, `status` and `poolFresh` (this node's pool holds a usable attestation
for it at `R`); `reachable` = the count of `poolFresh` among `selected`, `mSelect`/`kSlack` the
constants, `armed` the snapshot's arming state, `sumWeight` the pool's total weight (decimal
string; `"0"` triggers the by-`seq` fallback of §3.7, `fallback: true`). Never refuses for an
empty pool (then every array is empty and `reachable` is `0`).

Result of `yed_getselection`:

```json
{
  "refHeight": 329,
  "selector": "",
  "armed": true,
  "pool": [ 1, 2, 3 ],
  "sumWeight": "93000000000",
  "fallback": false,
  "mSelect": 2,
  "kSlack": 1,
  "selected": [
    {
      "seq": 2,
      "weight": "31000000000",
      "bondKeyAddress": "smExampleBondKeyAddr11111111111111111",
      "status": "ELIGIBLE",
      "poolFresh": true
    }
  ],
  "reachable": 2
}
```

### `yed_getnotice <vaultTxid>` (v3)

Arguments: `vaultTxid` (string; vault outpoints are always `vout 0`). The `Notices` record for
the vault (NOT-1; one per ACTIVE vault, never replaced while it stands, W10). `found` is `false`
— and the other fields absent (**optional**) — when no record stands (the plan's "or null" is
rendered this way so the result is always an object). `height` is the block the notice confirmed
in, `refHeight` its `R₁`, `pEmerg` the `min(xClaim(R₁), aClaim)` it was judged under,
`emergencyOpenAt` = `refHeight + EMERGENCY_PERSIST` (the first `refHeight` a clause-(b) claim may
use), `expiresAt` = `refHeight + EMERGENCY_NOTICE_TTL` (the last), `txid` the notice
transaction. Refuses with `vault-not-found` for an unknown vault.

Result of `yed_getnotice`:

```json
{
  "found": true,
  "vault": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8:0",
  "txid": "8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5",
  "height": 340,
  "refHeight": 338,
  "pEmerg": 1800000,
  "emergencyOpenAt": 342,
  "expiresAt": 402
}
```

### `yed_estimatefee <collateralZat>`

Arguments: `collateralZat` (number). FEE-1: `max(FEE_MIN, collateralZat · FEE_BPS / 10⁴)`.

Result of `yed_estimatefee`:

```json
{
  "feeZat": 62814071
}
```

### `yed_gethistory <from> <to>`

Arguments: `from`, `to` (numbers; `startHeight ≤ from ≤ to ≤ tip`, at most 2,016 rows per call,
else `RPC_INVALID_PARAMETER`). The `Snapshots` records (§3.6) for `from ≤ h ≤ to`, ascending,
`haltMask` decoded to names, `activation` as an object, undefined prices and ratio `null`.
`tagged` is whether the block carried a valid tag, `quote` whether that tag carried a quote
(`priceMicroUsd ≠ 0`). `yellowback_model.py` compares every field of every row.

Result of `yed_gethistory`:

```json
[
  {
    "height": 331,
    "blockHash": "0f3a9c1e5b7d2a4c6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f",
    "tagged": true,
    "quote": true,
    "signalCount": 64,
    "activation": { "status": "active", "lockInHeight": 129, "activateHeight": 193 },
    "pFast": 2000000,
    "pMid": 2000000,
    "pSlow": 1990000,
    "pMint": 1990000,
    "pClaim": 2000000,
    "sigmaMultBps": 10000,
    "issuedZat": 1656250000000,
    "supplyCents": 250000,
    "collateralZat": 62500000000,
    "globalRatioBps": 49750,
    "haltMask": []
  }
]
```

### `getblocktemplate` (stock command; the `yellowback` object)

On a node with `-yellowback` — and only then; otherwise the response is v4.5.0's key for key
(N10, `yellowback_stockparity.py`) — `getblocktemplate` returns `coinbasetxn` with the tag in its
scriptSig, `coinbaseaux.flags` = the tag push in hex (it begins with the `0x24` push opcode; a
pool that assembles its own coinbase appends these bytes verbatim after the BIP34 height push,
§5), `"coinbase/append"` in `mutable`, and `TemplateInfo()`:

```
"yellowback": { "tag": "<hex>", "kind": "quote"|"signal"|"none", "priceMicroUsd": n,
                "quoteAgeSeconds": n, "signal": bool, "payoutAddress": "s1…",
                "registered": bool, "eligible": bool, "activation": "signaling"|"locked_in"|"active",
                "signalCount": n, "enforcing": bool, "valveTripped": bool, "sunset": bool,
                "healthy": bool, "templatePolicy": "strict" }
```

With `-yellowbackrequirehealthy` the command refuses outright while the index is unhealthy
(K24); without it the template is unpoliced and untagged (MINER-3). Regtest `generate` goes
through the same `CreateNewBlock`, so a regtest node with a payout address and a quote mines
tagged blocks with no further code (V25).

---

## Wallet context (`src/rpc/yellowbackwallet.cpp`)

### The abandonment predicate (shared by every wallet command that reads it)

The chain shows **abandonment** when `Snapshots[tip].haltMask.ENFORCEMENT` has been set
continuously for at least `ABANDON_BLOCKS` (= 2 · `SIGNAL_WINDOW`: 4,032 on mainnet, 128 on
regtest) — two full windows in which fewer than half of blocks signalled. That is the whole
predicate (`YellowbackIndex::IsAbandoned()`, computed from `Snapshots` alone, so every node of
every release answers alike, L12). It is **never** gated on the node's own `-yellowbackenforce`,
its valve state, its health or a passed sunset. While it holds: `yed_getinfo.abandoned` is true;
`yed_getvault` and `yed_listpositions` show `sweepBefore` on every ACTIVE vault and
`yed_listpositions.canSweep`; `yed_sweep` builds; MP-1 and TPL-1/2 stand down for vault spends
(L13), so `yed_validaterawtransaction.wouldBeRejected` is false for a sweep. Otherwise
`yed_sweep` refuses with `sweep-not-abandoned`.

### Coin locking (three stages; carried over from the prototype)

A wallet's own 0-conf outputs are trusted and spendable at once, so a plain `sendtoaddress`
issued right after a Yellowback command could burn fresh YED. Therefore (i) `yed_mint`,
`yed_send`, `yed_sendmany`, `yed_redeem`, `yed_claim` call `LockCoin` on every YED output of the
transaction they are about to commit **before** `CommitTransaction`; (ii) the index's
`SyncTransaction` pre-locks every output a well-formed payload assigns to a script that `IsMine`,
for mempool and block transactions alike; (iii) after every applied block and at startup the
wallet reconciles against the state: every `Tokens` outpoint that is mine is locked, a pre-lock
is released only when its transaction is confirmed and the applied verdict assigned it no cents,
spent outpoints are pruned. Nothing is unlocked on disconnect. Locks are in-memory
(`setLockedCoins`) and re-applied at startup; `yed_lockcoins` re-runs the reconciliation on
demand. Vault outputs need no lock (a P2SH the wallet cannot `IsMine`). Every input of every
Yellowback transaction is confirmed (YED from the index, YEC via `AvailableCoins(nMinDepth = 1)`).
Phase 8 (H5, H10) makes the locks protected and reports them in `yed_getinfo`.

### The `wallet.dat` backup rule

Ycash 4.5 transparent keys are a random keypool, not HD, so a vault owner key lives only in
`wallet.dat`: **back up `wallet.dat` after minting** — a backup taken before the keypool was
consumed does not contain the vault key. `yed_mint.warning` nags when the keypool is low. Ycash's
wallet encryption is experimental (`-developerencryptwallet`) and must not be presented as
protection for vault keys; the custody rule is full-disk encryption, RPC on localhost only, and
an offline copy of `wallet.dat`.

### `yed_getnewaddress`

Arguments: none. A fresh keypool key as a Yellowback address string (`ye…` mainnet, `yt…`
testnet, `yr…` regtest). The result is a bare string.

Result of `yed_getnewaddress`:

```json
"yrExampleOwnerAddress111111111111111"
```

### `yed_validateaddress <address>`

Arguments: `address` (string). `isvalid` false — and the other fields absent (**optional**) —
with `not-a-yellowback-address` in `reason` when the string is not a `ye…`/`yt…`/`yr…` address of
this network (the command itself does not throw, so the wallet can validate as the user types;
`yed_send` throws the same identifier). `transparentAddress` is the same key hash as an `s1…`/
`sm…` address.

Result of `yed_validateaddress`:

```json
{
  "isvalid": true,
  "address": "yrExampleOwnerAddress111111111111111",
  "keyid": "1f2e3d4c5b6a79880706050403020100f1e2d3c4",
  "ismine": true,
  "transparentAddress": "smExampleTransparentTwin111111111111",
  "reason": ""
}
```

### `yed_getbalance`

Arguments: none. `confirmedCents` from the index's `Tokens` that are mine, `unconfirmedCents`
the mempool's payload assignments to this wallet (a dry run per transaction), `height` the index
tip the confirmed figure was read at.

Result of `yed_getbalance`:

```json
{
  "confirmedCents": 100000,
  "unconfirmedCents": 0,
  "height": 331
}
```

### `yed_listunspent`

Arguments: none. Every `Tokens` outpoint that is mine. `spentUnconfirmed` is `CWallet::IsSpent`
(spent by an own unconfirmed transaction; skipped by the selectors), `locked` whether stage (iii)
holds it (always true after reconciliation; a false is the H10 mismatch that triggers
`yed_lockcoins`).

Result of `yed_listunspent`:

```json
[
  {
    "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    "vout": 1,
    "cents": 100000,
    "valueZat": 10000,
    "address": "yrExampleOwnerAddress111111111111111",
    "height": 332,
    "confirmations": 1,
    "spentUnconfirmed": false,
    "locked": true
  }
]
```

### `yed_lockcoins`

Arguments: none. Re-runs stage (iii) and returns the outpoints now locked.

Result of `yed_lockcoins`:

```json
[
  { "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8", "vout": 1 }
]
```

### `yed_mint <cents> <lockBlocks> [from] [bundleHex] [wait]`

Arguments: `cents` (number, `MIN_MINT ≤ cents ≤ MAX_MINT`), `lockBlocks` (number; the class
follows from it, V19), `from` (string, optional; a `ys1…` Sapling address to fund the collateral
from that address's confirmed notes, largest-first — blocks for the proving time; default, or
`""`: transparent YEC via `AvailableCoins`), **v3** `bundleHex` (string, optional; `""` or absent
= build from the pool; else a `yed_buildbundle`-shaped bundle used verbatim, the manual path),
**v3** `wait` (boolean, optional, default `true`; see *v3 two-step commands*). Builds the §3.5
MINT at `R = tip − REF_LAG` after the MINTPOL-1 gate (`Snapshots[R].activation == ACTIVE`,
`haltMask == 0`, the cap has room), draws one fresh key for the vault owner and the token output,
locks the token output, commits. `vault` is `"<txid>:0"`; `payee` is the FEE-W choice (or the
configured preference) and `null` under FEE-0 (then `feeZat` is `0`); `fundedFrom` is
`"transparent"` or `"sapling"`; `warning` is the keypool-low nag, `""` when there is none.

**v3.** The carrier step first (W7): the wallet fixes `R`, builds the bundle for `(R, "")`,
creates the carrier funding transaction (`carrierTxid`) paying `P2SH(carrierScript(freshKey,
SHA256(bundle)))` of `CARRIER_VALUE`, records it in `<datadir>/yellowback/carriers.dat`, waits
one confirmation, then builds the MINT with the carrier as `vin[last]` (the only transparent
input when `from` is Sapling) and — when armed and `A ≠ ∅` — the attestor fee output
`P2PKH(bondPubKey(attestPayee))` (its `bondKeyAddress`) of `attestFeeZat` after the pool fee output. Before commit the
wallet **dry-runs MINT-1..10** with that bundle and refuses on any failure, naming the rule; a
VOID mint is therefore unbuildable except through a reorg. `xMint`, `aMint`, `pMint` are the
prices it was sized at (`aMint` `null` when not armed; `source` as `yed_estimatecollateral`),
`bundleSeqs` the contributing `seq`s, `attestPayee` the `bondKeyAddress` paid (`null` under
AFEE-0; the AFEE-W choice or `-yellowbackpreferredattestor` when that `seq ∈ A`),
`attestFeeZat` its amount (`0` when none), `carrierTxid` the funding transaction, `pending` as
above. Refusals (**v3**): `bundle-insufficient` (armed and fewer than `M_SELECT` selected
attestors are in the pool — the message names the missing `seq`s; also for a `bundleHex` whose
attestations do not satisfy BUNDLE-1 at `R`, with the reason), `mint10-diverged` (refused
**before** the carrier is built), `bundle-malformed` (`bundleHex` is not a bundle). v2 refusals
unchanged: `mintpol-not-active`, `mintpol-no-price`, `mintpol-participation`,
`mintpol-global-ratio`, `mintpol-divergence`, `mintpol-cap`, `mint-unsatisfiable`,
`mint-bad-lock`, `RPC_INVALID_PARAMETER` for `cents` out of range, `RPC_WALLET_ERROR` for
insufficient YEC (the carrier's `CARRIER_VALUE` plus two network fees are part of the need) or a
locked wallet.

Result of `yed_mint`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "vault": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8:0",
  "termClass": "A",
  "lockHeight": 380,
  "claimHeight": 404,
  "collateralZat": 25125628141,
  "feeZat": 62814071,
  "payee": "smQvTmAz2ExamplePayoutAddress1111111",
  "fundedFrom": "transparent",
  "warning": "",
  "carrierTxid": "5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c",
  "pending": false,
  "refHeight": 329,
  "xMint": 1990000,
  "aMint": 1985000,
  "pMint": 1985000,
  "source": "a",
  "bundleSeqs": [ 1, 2 ],
  "attestFeeZat": 15703517,
  "attestPayee": "smExampleBondAddress11111111111111111"
}
```

### `yed_send <yedaddress> <cents>` and `yed_sendmany <{yedaddress: cents, …}>`

Arguments: `yed_send`: `yedaddress` (string), `cents` (number). `yed_sendmany`: one object of
at most 14 recipients. Builds the §3.5 TRANSFER from confirmed YED inputs (index) and confirmed
YEC fee inputs, locks the outputs, commits. The YED inputs are chosen by the **floor-aware
selector** (H1), which is deterministic — the same wallet state and the same amount always give
the same inputs — and tries, in order: an exact match (change `0`), a single input whose change is
valid, greedy smallest-first with extension while the change is unworkable, then a bounded search.
A TRANSFER **never burns** (H2): when no selection leaves change of `0` or `≥ MIN_OUTPUT` the
command refuses with `change-floor` rather than build one. `yed_estimatesend` runs the same
selector without signing or locking. Refusals: `not-a-yellowback-address`, `insufficient-yed`,
`change-floor` (YED change would lie in `(0, MIN_OUTPUT)`; the message carries the nearest
workable amounts below and above, H2), `too-many-inputs`,
`RPC_INVALID_PARAMETER` for an amount outside `[MIN_OUTPUT, MAX_OUTPUT]`.

Result of `yed_send`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "changeCents": 50000,
  "expiryHeight": 371
}
```

`yed_sendmany` returns the same shape.

Result of `yed_sendmany`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "changeCents": 50000,
  "expiryHeight": 371
}
```

### `yed_estimatesend <{yedaddress: cents, …}|cents>`

Arguments: one object of at most 14 recipients (as `yed_sendmany`), **or** a single number — the
total cents, when the recipients are not yet known (the GUI calls this while the user types).
A dry run of `yed_send`/`yed_sendmany` (H3): it runs the same floor-aware selector (H1) over the
same confirmed YED coins, signs nothing, locks nothing and commits nothing. It mirrors
`yed_estimatecollateral`: a halted gate or an unworkable amount still returns a figure to show.

`workable` is whether a selection exists whose change is `0` or `≥ MIN_OUTPUT`. When it is
`true`, `inputs` are the outpoints the selector would spend (in the order it would spend them),
`selectedCents` their total, `changeCents` the YED change (`0` for an exact match), `stage` the
selector stage that produced it (`"exact"`, `"single"`, `"greedy"` or `"search"`), and
`spendableCents` the wallet's confirmed, unspent YED. When it is `false`, `inputs` is empty,
`changeCents` is `0`, `stage` is `"none"`, `error` is the identifier that `yed_send` would throw
(`change-floor` or `insufficient-yed`, `""` when `workable`) and `alternatives` names the nearest
workable amounts: `below` the largest workable amount strictly below the request and `above` the
smallest strictly above it, each `null` when there is none. `alternatives` is `null` when
`workable`. The command never refuses for the amount itself; `RPC_INVALID_PARAMETER` only for a
malformed argument, an amount outside `[MIN_OUTPUT, MAX_OUTPUT]`, or more than 14 recipients.

Result of `yed_estimatesend`:

```json
{
  "amountCents": 4000,
  "recipients": 1,
  "workable": true,
  "stage": "greedy",
  "inputs": [
    { "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8", "vout": 1, "cents": 10000 }
  ],
  "selectedCents": 10000,
  "changeCents": 6000,
  "spendableCents": 10000,
  "error": "",
  "alternatives": null
}
```

### `yed_unlockcoin <txid> <n> <acknowledgement>`

Arguments: `txid` (string), `n` (number), `acknowledgement` (string; must be exactly
`I understand this burns YED`). The deliberate escape hatch of H5: `lockunspent` refuses to unlock
an outpoint the Yellowback wallet layer holds (`yed-locked-outpoint`) and `lockunspent true`
without an argument re-applies those locks after unlocking everything else, so this command is the
only way to hand a YED outpoint back to plain YEC coin selection. The YED it carries is burned by
the first transaction that spends it outside the overlay, and the next `yed_lockcoins`,
reconciliation or restart locks it again — unlock it and spend it in the same session.

Refusals: `unlock-acknowledgement-missing` (the third argument is not the exact string),
`RPC_INVALID_PARAMETER` for a bad txid or a negative `n`. Unlocking an outpoint the layer does not
hold succeeds and reports `wasYellowbackLocked: false`.

Result of `yed_unlockcoin`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "vout": 1,
  "unlocked": true,
  "wasYellowbackLocked": true,
  "cents": 10000
}
```

### `yed_redeem <vaultTxid> [to]`

Arguments: `vaultTxid` (string), `to` (string, optional; a transparent or `ys1…` destination for
the collateral; default a fresh own transparent address). One step (V24):

- On an **ACTIVE** vault at or past `lockHeight`: the §3.5 owner-path REDEEM — burns
  `mintedCents` of the wallet's YED, pays the FEE-1 fee to `payee(R, vaultOutpoint)`, sends the
  rest of the collateral to `to`. Runs `MempoolCheck` first and refuses (`mempool-check-failed:
  <verdict>`) rather than commit anything MP-1 would refuse (K7); on success `CommitTransaction`
  puts it in the node's own mempool.
- On a **VOID** vault at or past `lockHeight` (L14): the §3.5 VOID RELEASE — owner path, no
  burn, no fee, no payload; an ordinary spend no rule polices (K3). Returns `burnedCents: 0`,
  `feeZat: 0`, `payee: null`. The GUI calls this **Release**.

`collateralOut` is the zat paid to `to`. `extraBurnCents` (H4) is a sub-dollar YED remainder the
selector burned rather than refuse: it is `0` whenever a selection with change of `0` or
`≥ MIN_OUTPUT` exists (those are always preferred) and otherwise lies in `[1, MIN_OUTPUT − 1]`,
i.e. at most $0.99. `burnedCents` stays the vault's debt; `extraBurnCents` is burned on top of it.
Refusals: `vault-not-found`, `vault-not-owned`,
`vault-not-active` (CLOSED or CLAIMED only), `vault-locked` (tip below `lockHeight`, ACTIVE and
VOID alike), `insufficient-yed`, `change-floor`, `mempool-check-failed:<verdict>`,
`RPC_WALLET_ERROR` for a locked wallet.

Result of `yed_redeem`:

```json
{
  "txid": "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
  "burnedCents": 100000,
  "feeZat": 62814071,
  "payee": "smQvTmAz2ExamplePayoutAddress1111111",
  "collateralOut": 25062804070,
  "to": "smExampleTransparentTwin111111111111",
  "extraBurnCents": 0
}
```

### `yed_claim <vaultTxid> [to] [bundleHex] [wait]`

Arguments as `yed_redeem`, plus **v3** `bundleHex` and `wait` as `yed_mint` (`to` may be `""`
for the default). The §3.5 CLAIM of somebody else's underwater vault (from `yed_listclaimable`):
claim-path scriptSig, `nLockTime = claimHeight`, burns `mintedCents` of the claimant's own YED,
pays the fee from the collateral, collateral to `to`. The v2 fields of `yed_redeem` (including
`extraBurnCents`, H4) plus the **v3** fields below. Refusals: `vault-not-found`,
`vault-not-active`, `claim-not-yet` (tip below `claimHeight`), `claim-not-underwater` (RED-4
would fail at the reference snapshot by both clauses), `insufficient-yed`, `change-floor`,
`mempool-check-failed:<verdict>`, **v3** `bundle-insufficient`, `bundle-malformed`.

**v3.** The carrier step first (selector = the vault outpoint), then the CLAIM with the carrier
input (never `vin[0]`), the attestor fee output when armed and `A ≠ ∅`, and — when
`residualZat ≥ RESIDUAL_MIN_ZAT` — the residual output `P2PKH(ownerPubKey)` of `residualZat`
(RED-5); with a `ys1…` `to` the residual stays transparent (S11). The wallet dry-runs RED-1..5
before commit. `claimPath` is the clause that opened the claim (`"a"` underwater under the
combined `pClaim`; `"b"` the emergency clause: a notice `EMERGENCY_PERSIST..EMERGENCY_NOTICE_TTL`
blocks old and `collateralZat · pEmerg < mintedCents · EMERGENCY_RATIO_BPS · COIN`); under `"b"`
alone the claimant keeps exactly the debt at `pClaim` — no margin (R1) — and `collateralOut` is
correspondingly smaller. `xClaim`, `aClaim`, `pClaim`, `pEmerg` are the prices it was judged
under (`pEmerg` `null` under clause (a)).

Result of `yed_claim`:

```json
{
  "txid": "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
  "burnedCents": 100000,
  "feeZat": 62814071,
  "payee": "smQvTmAz2ExamplePayoutAddress1111111",
  "collateralOut": 25062804070,
  "to": "smExampleTransparentTwin111111111111",
  "extraBurnCents": 0,
  "carrierTxid": "5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c",
  "pending": false,
  "refHeight": 405,
  "xClaim": 400000,
  "aClaim": 395000,
  "pClaim": 400000,
  "pEmerg": null,
  "claimPath": "a",
  "bundleSeqs": [ 1, 2 ],
  "attestFeeZat": 15703517,
  "attestPayee": "smExampleBondAddress11111111111111111",
  "residualZat": 0
}
```

### `yed_claimnotice <vaultTxid> [bundleHex] [wait]` (v3)

Arguments: `vaultTxid` (string), `bundleHex`, `wait` as `yed_mint`. Step 1 of the emergency
claim (proposal §10.3, NOT-1): the carrier step (selector = the vault outpoint), then a
transaction of confirmed own YEC inputs plus the carrier, the `0x06` CLAIM_NOTICE payload
(`vaultTxid ‖ vaultVout ‖ refHeight`) and change — no vault input, no fee outputs. Anyone may
post a notice; it needs YEC for the carrier and the network fee, no YED. Before build the
wallet evaluates NOT-1 at `R`: the vault must be ACTIVE, the snapshot armed, `pEmerg =
min(xClaim(R), aClaim)` defined with `collateralZat · pEmerg < mintedCents ·
EMERGENCY_RATIO_BPS · COIN`, and no notice standing. `emergencyOpenAt` = `R +
EMERGENCY_PERSIST`. Refusals: `vault-not-found`, `vault-not-active`, `notice-standing` (a
`Notices` record exists whose `height` is within `EMERGENCY_NOTICE_TTL` of the tip — the reset
attack NOT-1 forbids), `notice-not-underwater` (the inequality does not hold under this
node's `pEmerg`, or the snapshot is not armed — a notice is meaningless before arming),
`bundle-insufficient`, `bundle-malformed`, `RPC_WALLET_ERROR` for insufficient YEC.

Result of `yed_claimnotice`:

```json
{
  "txid": "8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5",
  "carrierTxid": "5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c",
  "pending": false,
  "vault": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8:0",
  "refHeight": 338,
  "xClaim": 1900000,
  "aClaim": 1800000,
  "pEmerg": 1800000,
  "bundleSeqs": [ 1, 2 ],
  "emergencyOpenAt": 342
}
```

### `yed_sweepcarriers` (v3)

Arguments: none. Reclaims every outstanding carrier of this wallet (W7: `carriers.dat`) whose
window has lapsed — the main transaction never confirmed and `tip > R + REF_WINDOW`, so the
pair expired together — into one transaction to a fresh own address, signing each carrier input
by hand with its recorded key and a bundle push equal to the recorded bundle (the redeem script
demands it). Also run at startup. `count` is the number of carriers swept, `txid` the sweep
(`""` when `count` is `0`), `reclaimedZat` the value returned net of the network fee,
`outstanding` the carriers still inside their window. A carrier whose record was lost is not
reachable by this command (accepted, W7). Never refuses for "nothing to do".

Result of `yed_sweepcarriers`:

```json
{
  "txid": "",
  "count": 0,
  "reclaimedZat": 0,
  "outstanding": 1
}
```

### `yed_registerattestor <bondYec> <lockBlocks> [flags]` (v3)

Arguments: `bondYec` (number, decimal YEC, `≥ BOND_MIN`), `lockBlocks` (number, `≥
BOND_MIN_LOCK`; `bondLocktime = tip + 1 + lockBlocks`), `flags` (number, optional, default `0`;
the raw `u8` of proposal §5.2: bits 0–1 source tier, bit 2 pool operator). The §3.5
ATTESTOR_REGISTER: `vout[0]` = `P2SH(bondScript(bondPubKey, bondLocktime))` of `bondYec`,
`vout[1]` = the `0x05` payload, change; `attestorPubKey` (hot) and `bondPubKey` are two fresh
keypool keys of this wallet (draw two — back up `wallet.dat` afterwards, the rule above). The
bond is **not** `IsMine` (its script is non-standard to `Solver`, R6): the wallet finds it
through `Attestors` by `bondPubKey` and nothing is written to `wallet.dat`. `seq` is `null` in
the result — it is assigned when the transaction confirms (REG-A1); read it from
`yed_listattestors` by `attestorPubKey`; `warning` is the keypool-low nag as `yed_mint` (`""`
when there is none). Refusals: `bond-below-min`, `lock-below-min` (also for
`bondLocktime ≥ LOCKTIME_THRESHOLD`), `RPC_WALLET_ERROR` for insufficient YEC or a locked
wallet, `keypool-empty`.

Result of `yed_registerattestor`:

```json
{
  "txid": "7b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f708192a3b4c5d6e7f809",
  "seq": null,
  "attestorPubKey": "03b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071829304a5b6c7d8e9f0",
  "bondAddress": "smExampleBondAddress11111111111111111",
  "bondKeyAddress": "smExampleBondKeyAddr11111111111111111",
  "bondOutpoint": { "txid": "7b2c3d4e5f60718293a4b5c6d7e8f9001a2b3c4d5e6f708192a3b4c5d6e7f809", "vout": 0 },
  "bondZat": 1000000000,
  "bondLocktime": 500,
  "flags": { "tier": 0, "pool": false },
  "maturesAt": 289,
  "warning": ""
}
```

### `yed_withdrawbond <seq> [to]` (v3)

Arguments: `seq` (number), `to` (string, optional; a transparent or `ys1…` destination; default
a fresh own transparent address). Spends the bond outpoint of an attestor whose `bondPubKey`
this wallet holds, after `bondLocktime` (`nLockTime = bondLocktime`, the CLTV path), signed by
hand as the vault owner path is. Any status may withdraw once the locktime passes: IN-2 then
marks the record WITHDRAWN (or, for an EJECTED record, only `bondSpentHeight`). `bondOut` is
the zat paid to `to` net of the network fee. Refusals: `attest-unknown-seq`, `attest-key-not-held`
(the bond key is not in this wallet), `bond-locked` (tip `< bondLocktime`), `bond-spent` (the
outpoint is already spent), `bad-address`.

Result of `yed_withdrawbond`:

```json
{
  "txid": "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
  "seq": 1,
  "bondZat": 1000000000,
  "bondOut": 999990000,
  "to": "smExampleTransparentTwin111111111111"
}
```

### `yed_revive <seq> <priceMicroUsd>` (v3, attestor node)

Arguments: `seq` (number; a DORMANT attestor whose hot key this wallet holds), `priceMicroUsd`
(number; the price the revival attests — the plan writes `yed_revive` with no arguments, but a
wallet may hold several attestor keys and the node has no price source of its own, so both are
explicit here). Builds the §3.5 ATTESTOR_REVIVE: one attestation for `citedHeight = tip −
REF_LAG` signed through the same guard as `yed_signattestation` (so a revival can never
equivocate against an earlier signature for that height), payload `0x08`, funded from any
confirmed YEC, change. REV-1 then sets the record ELIGIBLE with its age preserved. Refusals:
`attest-unknown-seq`, `not-dormant` (any status but DORMANT), `attest-key-not-held`,
`attest-range`, `equivocation-guard`, `RPC_WALLET_ERROR` for insufficient YEC.

Result of `yed_revive`:

```json
{
  "txid": "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
  "seq": 5,
  "citedHeight": 329,
  "priceMicroUsd": 1985000,
  "hex": "0500e84a1e00490100002b3c…"
}
```

### `yed_reportequivocation <attestationHexA> <attestationHexB> [wait]` (v3)

Arguments: two 74-byte attestations in hex, `wait` as `yed_mint`. Before build the wallet checks
EQV-1's conditions itself: same `seq` (any status but WITHDRAWN or EJECTED), same `citedHeight`
`≥ startHeight` with a block hash in the index, different prices, both signatures valid under
`attestorPubKey(seq)` over **this chain's** `blockHash(citedHeight)` (two honest attestations
from two sides of a fork are not an equivocation). Then the carrier step with a bundle that is
exactly the two attestations, and a transaction of confirmed own YEC plus the carrier, the empty
`0x07` payload, change (`refHeight` is the carrier's `R = tip − REF_LAG`, the start of its
sweep window as for every two-step command). Anyone may report; it costs the carrier and the
network fee. Refusals:
`not-equivocation` (any EQV-1 condition fails; the message says which), `attest-malformed`,
`RPC_WALLET_ERROR` for insufficient YEC.

Result of `yed_reportequivocation`:

```json
{
  "txid": "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
  "carrierTxid": "5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c",
  "pending": false,
  "refHeight": 331,
  "seq": 4,
  "citedHeight": 329,
  "priceA": 1985000,
  "priceB": 2185000
}
```

### `yed_signattestation <seq> <priceMicroUsd> [citedHeight]` (v3, attestor node)

Arguments: `seq` (number), `priceMicroUsd` (number, `[PRICE_MIN, PRICE_MAX]`), `citedHeight`
(number, optional; default `tip − REF_LAG`; must be `≥ startHeight`, `≤ tip`, and a height the
index holds a block hash for). **The agent's RPC** (`yellowback-attest attest` calls it every
`k` blocks): signs the attestation message with the attestor hot key `attestorPubKey(seq)` held
in this wallet, compact low-S, and returns the 74 bytes; the key never leaves the node.

**Equivocation guard (S16).** Before signing, the node looks up `(seq, citedHeight)` in
`<datadir>/yellowback/attest-signed.dat`, an append-only record of every `(seq, citedHeight,
priceMicroUsd, sig)` it has ever signed, **fsynced before the RPC returns**. (1) No record ⇒ sign,
append, fsync, return with `reused: false`. (2) A record at the **same price** ⇒ return the
recorded signature with `reused: true` and sign nothing (RFC 6979 would give the same bytes; the
record is authoritative). (3) A record at a **different price** ⇒ refuse with
`equivocation-guard` and sign nothing; the message carries the earlier price and `citedHeight`
(`equivocation-guard: seq <n> already signed <p₀> for height <h>`), and the caller that wants
the earlier attestation calls again with `p₀` (case 2). The guard is per `(seq, citedHeight)`
for the life of the datadir; it is never gated on the attestor's status, on arming, or on
whether the height is still fresh. It protects against one node's own restarts and two agents
on one node; **two nodes holding one hot key defeat it** — `doc/yellowback-attestor.md`, first
paragraph. `yed_revive` signs through the same guard. Refusals: `attest-unknown-seq` (no
record; a registration not yet confirmed cannot be signed for), `attest-key-not-held` (the hot
key is not in this wallet), `attest-range`, `attest-stale` (`citedHeight` above the tip or below
`startHeight`), `equivocation-guard`, `RPC_WALLET_ERROR` for a locked wallet or a failed write
of the guard file (nothing is returned that was not persisted). RPC-auth only.

Result of `yed_signattestation`:

```json
{
  "hex": "0100e84a1e00490100002b3c…",
  "seq": 1,
  "priceMicroUsd": 1985000,
  "citedHeight": 329,
  "reused": false
}
```

### `yed_sweep <vaultTxid> <acknowledgement> [to]`

Arguments: `vaultTxid` (string), `acknowledgement` (string; must be exactly
`I understand this leaves YED unbacked`), `to` (string, optional, as `yed_redeem`). L10: builds
the §3.5 SWEEP of an own ACTIVE vault — an owner-path spend with no burn and no fee — **only
while the abandonment predicate holds**; signs it and commits it through the node's own mempool,
which admits it under abandonment (L13), and returns the raw `hex` so the owner can submit it to
any other node as well. The transaction is a rule-breaking vault spend by design (it fails RED-1):
an enforcing node — one on a chain that does not show abandonment — never mines it; on the
abandoned chain every node admits, relays and mines it like any other transaction. The vault is
then `CLOSED, unbacked = true`, `Totals.unbackedCents` grows by the debt (`unbackedCents` here),
and `yed_listtransactions` shows `type: "sweep"`. What the owner is told (§4.6): after
`claimHeight` the claim path is anyone-can-spend and, with nobody enforcing RED-4, whoever mines
first takes the collateral — sweep before `claimHeight` (`sweepBefore`) or lose it. Refusals:
`sweep-not-abandoned`, `sweep-acknowledgement-missing`, `vault-not-found`, `vault-not-owned`,
`vault-not-active`, `vault-locked`.

Result of `yed_sweep`:

```json
{
  "txid": "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
  "hex": "0400008085202f8901…",
  "collateralOut": 25125627141,
  "to": "smExampleTransparentTwin111111111111",
  "unbackedCents": 100000
}
```

### `yed_listpositions [status]`

Arguments: `status` (string, optional; as `yed_listvaults`). The wallet's own vaults (a vault is
mine iff `HaveKey(ownerPubKey)`): every `yed_getvault` field plus `canRedeem` (true for an
ACTIVE or VOID vault at or past `lockHeight` — for VOID it is the Release, L14), `canClaim`
(true when `claimable` and the wallet holds `≥ mintedCents`) and `canSweep` (true for an ACTIVE
vault while abandonment holds). `sweepBefore` as `yed_getvault` (**optional**).

**v3.** `noticed`, `noticeHeight`, `emergencyOpenAt` as `yed_getvault` (the Positions page's
"notice posted; emergency claim opens at …" badge); `canNotice` (true when the vault is ACTIVE,
the tip snapshot is armed, no notice stands, and the vault is under `EMERGENCY_RATIO_BPS` under
this node's `pEmerg` but not claimable — the wallet offers "post notice", v3 §4.8); `canClaim`
is now RED-4 by either clause.

Result of `yed_listpositions`:

```json
[
  {
    "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    "vout": 0,
    "status": "ACTIVE",
    "ownerPubKey": "02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
    "ownerKeyId": "1f2e3d4c5b6a79880706050403020100f1e2d3c4",
    "ownerAddress": "yrExampleOwnerAddress111111111111111",
    "termClass": "A",
    "lockHeight": 380,
    "claimHeight": 404,
    "collateralZat": 25125628141,
    "collateral": 251.25628141,
    "mintedCents": 100000,
    "mintHeight": 332,
    "refHeight": 329,
    "feePaidZat": 62814071,
    "closeHeight": null,
    "closingTxid": "",
    "burnedCents": 0,
    "unbacked": false,
    "claimable": false,
    "underwaterAt": 437800,
    "voidReason": "",
    "sweepBefore": 404,
    "noticed": false,
    "noticeHeight": null,
    "emergencyOpenAt": null,
    "canRedeem": false,
    "canClaim": false,
    "canSweep": false,
    "canNotice": false
  }
]
```

### `yed_listtransactions [count] [skip]`

Arguments: `count` (number, default `100`), `skip` (number, default `0`). Newest first; every
wallet transaction that is in `TxLog` with an own token or vault involved (N21: filtered on
`spentTokens`/`assigned`/`closedVaults` that are mine), plus own unconfirmed and expired
Yellowback transactions. `type` is the wallet's view: `mint`, `send`, `receive`, `burn` (a
transfer that burned), `redeem` (own owner-path redemption), `claim` (this wallet claimed),
`claimed` (an own vault was claimed by someone else), `sweep` (an own vault swept under
abandonment), **v3** `notice` (a CLAIM_NOTICE this wallet posted), `noticed` (a notice was
posted on an own vault), `register`, `withdraw` (an own bond withdrawn), `revive`,
`equivocation` (a report this wallet posted), `carrier` (an own carrier funding or sweep
transaction). `amountCents` is the signed effect on this wallet. `unbacked` is true on a row that
closed an own vault without its burn; `expired` rows have `height: -1`, `confirmations: 0`,
`verdict: "expired"`. `payee` `null` where there is no fee output.

Result of `yed_listtransactions`:

```json
[
  {
    "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    "height": 332,
    "confirmations": 1,
    "type": "mint",
    "verdict": "ok",
    "path": "",
    "yedIn": 0,
    "yedOut": 100000,
    "burned": 0,
    "amountCents": 100000,
    "feeZat": 62814071,
    "payee": "smQvTmAz2ExamplePayoutAddress1111111",
    "unbacked": false,
    "expired": false
  }
]
```

---

## Error identifiers (M8)

The identifier is the first token of the message, followed by `: ` and free text. Provocations are
what `yellowback_rpc_contract.py` uses.

| Identifier | Raised by | When (provocation) |
|---|---|---|
| `yellowback-unhealthy` | every gated command | the index is unhealthy (`unhealthyReason` follows); provoke with `-yellowbacktestfault=storage:commit` then any non-allow-listed command |
| `mintpol-not-active`, `mintpol-no-price`, `mintpol-participation`, `mintpol-global-ratio`, `mintpol-divergence`, `mintpol-cap` | `yed_mint` | MINTPOL-1, one per halt bit and the cap: mint before activation; with no quote tags in the windows; after fewer than `PARTICIPATION_FLOOR` signals in a window; with the global ratio below `GLOBAL_RATIO_HALT_BPS` and the class's minimum ratio below `RECAP_RATIO_BPS` (W16: class A mints through a global-ratio halt, the message names the classes that can); with `P_fast`/`P_slow` diverging by more than `DIVERGENCE_BPS`; with `-yellowbacksupplycapbps` low and supply at the cap |
| `mint-unsatisfiable` | `yed_mint`, `yed_estimatecollateral` | `requiredZat > MAX_MONEY` (K14): `MAX_MINT` cents at `priceMicroUsd = PRICE_MIN` |
| `mint-bad-lock` | `yed_mint`, `yed_estimatecollateral` | `lockBlocks` outside every class, or `lockHeight + GRACE ≥ LOCKTIME_THRESHOLD` |
| `too-many-addresses` | `yed_listtokens` | an empty array, or more than 100 addresses |
| `invalid-address` | `yed_listtokens` | a string that is neither a YED nor a transparent P2PKH address of this network |
| `vault-not-found`, `vault-not-active`, `vault-not-owned` | `yed_redeem`, `yed_claim`, `yed_sweep`, `yed_getvault` | an unknown txid; a CLOSED or CLAIMED vault (a VOID vault is releasable by `yed_redeem`, L14); another wallet's vault |
| `vault-locked` | `yed_redeem`, `yed_sweep` | tip below `lockHeight` (ACTIVE and VOID alike) |
| `claim-not-yet` | `yed_claim` | tip below `claimHeight` |
| `claim-not-underwater` | `yed_claim` | RED-4 would fail at the reference snapshot (the price did not fall) |
| `sweep-not-abandoned` | `yed_sweep` | the abandonment predicate is false: enforcement on, or suspended for less than `ABANDON_BLOCKS` (L10, L12 — a passed sunset alone is not abandonment) |
| `sweep-acknowledgement-missing` | `yed_sweep` | the second argument is not the exact acknowledgement string |
| `change-floor` | `yed_send`, `yed_sendmany`, `yed_redeem`, `yed_claim` | no selection leaves YED change of `0` or `≥ MIN_OUTPUT` (H2; a REDEEM or CLAIM burns a sub-dollar remainder instead, H4, so it reaches this only when even that is impossible): send `cents − 50` from a single `cents` output. The message is structured and always has this shape: `change-floor: <requested> cents cannot be sent from these coins without change below the $1.00 minimum output; nearest workable amounts: below <n\|none>, above <n\|none>` — the GUI reads the two numbers with that grammar and `yed_estimatesend.alternatives` returns them as fields |
| `unlock-acknowledgement-missing` | `yed_unlockcoin` | the third argument is not exactly `I understand this burns YED` |
| `yed-locked-outpoint` | `lockunspent` (the stock RPC) | `lockunspent false\|true [{txid,vout}]` naming an outpoint the Yellowback wallet layer holds: use `yed_unlockcoin` |
| `yed-burn-refused` | `sendrawtransaction` (the stock RPC) | with `-yellowback`, a raw transaction that spends a `Tokens` outpoint of this wallet without a payload that reassigns it (no payload, or a TRANSFER that assigns nothing): pass `allowyedburn = true` to send it anyway |
| `not-a-yellowback-address` | `yed_send`, `yed_sendmany`, `yed_validateaddress` (in `reason`, no throw) | the recipient is not a `ye…`/`yt…`/`yr…` address of this network: pass an `s1…`/`sm…` address |
| `verdict-parent-not-tip` | `yed_getblockverdict` | the block's parent is not the index tip and the block is not a rejected child of it (N12): pass the tip's grandparent |
| `insufficient-yed` | `yed_redeem`, `yed_claim`, `yed_send`, `yed_sendmany` | wallet YED below the burn or amount |
| `mempool-check-failed:<verdict>` | `yed_redeem`, `yed_claim` | `MempoolCheck` returned the named RED verdict (K7); provoke with a redemption whose reference snapshot has no `pClaim` where the claim path is chosen (`vault-claim-not-underwater`) |
| `fee-no-eligible-payee` | `yed_getfeepayee` | `E(refHeight)` empty (FEE-0; not an error for the wallet, which omits the output): a `refHeight` below the first quote tag |
| `quote-out-of-range` | `yed_setquote` | price outside `[PRICE_MIN, PRICE_MAX]` and not `0` |
| `no-payout-address` | `yed_setquote` | the node has no payout key and so can emit no tag (no `-yellowbackpayoutaddress` and no P2PKH `-mineraddress`) |

**v3 identifiers** (v3 plan §4.5). `RPC_VERIFY_REJECTED` unless stated; `yellowback_rpc_contract.py`
provokes each.

| Identifier | Raised by | When (provocation) |
|---|---|---|
| `attest-unknown-seq` | `yed_addattestation`, `yed_signattestation`, `yed_withdrawbond`, `yed_revive` | no `Attestors` record with that `seq`: `yed_addattestation` of an attestation signed for `seq 999` |
| `attest-not-eligible` | `yed_addattestation` | the record is EJECTED or WITHDRAWN (S4: PENDING, ELIGIBLE and DORMANT are pooled): feed an attestation of an ejected `seq` |
| `attest-stale` | `yed_addattestation`, `yed_signattestation` | `citedHeight ≤ tip − REF_LAG − ATTEST_MAX_AGE`, above the tip, or below `startHeight`: feed one citing `tip − 20` on regtest |
| `attest-bad-sig` | `yed_addattestation` | the compact signature does not verify under `attestorPubKey(seq)` with this chain's `blockHash(citedHeight)`, **or is high-S** (R17): flip a byte; or sign with `s` un-normalised |
| `attest-range` | `yed_addattestation`, `yed_signattestation`, `yed_revive` | `priceMicroUsd` outside `[PRICE_MIN, PRICE_MAX]` |
| `attest-malformed` | `yed_addattestation`, `yed_reportequivocation` | not 74 bytes of hex (`RPC_INVALID_PARAMETER`) |
| `bundle-insufficient` | `yed_buildbundle`, `yed_estimatecollateral`, `yed_mint`, `yed_claim`, `yed_claimnotice` | armed and fewer than `M_SELECT` of `selected(R, selector)` have a usable attestation in the pool; also a given `bundleHex` that fails BUNDLE-1 at `R` (the message ends with the BUNDLE-1 reason). Message grammar: `bundle-insufficient: <count> of <selected> selected attestors have a fresh attestation; missing seq <a,b,…>` — the GUI reads the two numbers. Provoke: arm, feed one attestor only |
| `bundle-malformed` | `yed_mint`, `yed_claim`, `yed_claimnotice` | `bundleHex` is not `"YA" ‖ 0x01 ‖ count ‖ count × 74 bytes` (`RPC_INVALID_PARAMETER`) |
| `mint10-diverged` | `yed_estimatecollateral`, `yed_mint` | armed and `\|pFast − aMint\| · 10⁴ > DIVERGE_BPS_ATTEST · min(pFast, aMint)` (W17: the pools' fast median, the current market, not the lagging minimum `xMint`) — refused before any transaction is built: attestors at 2× the pools |
| `notice-standing` | `yed_claimnotice` | a `Notices` record for the vault exists with `tip − notice.height ≤ EMERGENCY_NOTICE_TTL` (NOT-1's no-reset clause): post twice |
| `notice-not-underwater` | `yed_claimnotice` | `collateralZat · pEmerg ≥ mintedCents · EMERGENCY_RATIO_BPS · COIN` under this node's bundle, or the snapshot at `R` is not armed: notice on a healthy vault |
| `bond-below-min` | `yed_registerattestor` | `bondYec < BOND_MIN` (10 YEC on regtest): register with 9 |
| `lock-below-min` | `yed_registerattestor` | `lockBlocks < BOND_MIN_LOCK` (200 on regtest), or the resulting `bondLocktime ≥ LOCKTIME_THRESHOLD` |
| `bond-locked` | `yed_withdrawbond` | tip `< bondLocktime`: withdraw right after registering |
| `bond-spent` | `yed_withdrawbond` | the bond outpoint is already spent (`bondSpentHeight` set): withdraw twice |
| `not-dormant` | `yed_revive` | the record's status is not DORMANT: revive an ELIGIBLE attestor |
| `not-equivocation` | `yed_reportequivocation` | any EQV-1 condition fails — different `seq`s, different `citedHeight`s, equal prices, a bad signature, an EJECTED/WITHDRAWN `seq`, or a `citedHeight` whose hash is not in the index (two sides of a fork): report the same attestation twice |
| `attest-key-not-held` | `yed_signattestation`, `yed_revive` (the hot key), `yed_withdrawbond` (the bond key) | the wallet does not hold the key the command needs: sign for a `seq` registered by another node |
| `equivocation-guard` | `yed_signattestation`, `yed_revive` | `attest-signed.dat` holds a signature for `(seq, citedHeight)` at a different price (S16): sign twice for one height at two prices, also across a restart. Message grammar: `equivocation-guard: seq <n> already signed <p₀> for height <h>` |

The wallet builder's own refusals (`src/yellowback/txbuilder.cpp`; Phase 6) carry identifiers
the same way, so the GUI can match them too. They are not rule refusals: `RPC_INVALID_PARAMETER`
for a bad argument, `RPC_WALLET_ERROR` otherwise.

| Identifier | Raised by | When (provocation) |
|---|---|---|
| `bad-address` | `yed_mint` (`from`), `yed_redeem`, `yed_claim`, `yed_sweep` (`to`) | the address is not an `s1…`/`sm…` or `ys1…` address of this network (a `ye…` YED address, a Sprout address, nonsense), or its Sapling spending key is not in this wallet: pass a `yed_getnewaddress` result as `from` |
| `bad-mint-amount` | `yed_mint` | `cents` outside `[MIN_MINT, MAX_MINT]` |
| `bad-xfer-amount` | `yed_send`, `yed_sendmany` | an amount outside `[MIN_OUTPUT, MAX_OUTPUT]` |
| `insufficient-yec` | `yed_mint` | the wallet (or the named `from` address) cannot cover collateral + fees from confirmed, unlocked outputs or notes: `yed_mint … <an empty s1… address>` |
| `wallet-locked` | every signing command | the wallet is encrypted and locked (`walletpassphrase` first); the stock `EnsureWalletIsUnlocked` message may precede it |
| `keypool-empty` | `yed_mint`, `yed_send`, `yed_redeem`, `yed_claim` | no fresh key could be drawn (`keypoolrefill`) |
| `too-many-inputs`, `too-many-notes` | `yed_send`, `yed_redeem`, `yed_claim` / `yed_mint` | more than 250 YED inputs / more than 20 Sapling notes would be spent: consolidate first |
| `expiring-too-soon`, `index-below-start` | every builder | the index is far enough behind the chain that `R + REF_WINDOW` would expire the transaction at once, or the index has not reached `startHeight + REF_LAG` |
| `vault-value-too-small` | `yed_redeem`, `yed_claim`, `yed_sweep` | the vault does not cover the network fee plus the enforcement fee (cannot happen for a vault MINT-5 accepted) |

## `rpc/client.cpp` conversion rows (Phase 3)

The CLI converts positional arguments by index, so every numeric argument is listed and every
string argument is not. **Rebuild `ycash-cli` after every `client.cpp` change** — a stale CLI
passes a number as a string and the node answers `RPC_INVALID_PARAMETER` (N27).

| Command | Converted indices |
|---|---|
| `yed_getstatehash` | 0 |
| `yed_getprice` | 0 |
| `yed_listminers` | 0, 1 |
| `yed_setquote` | 0, 1 |
| `yed_getfeepayee` | 0, 1 |
| `yed_listvaults` | 1, 2 (was 1, 2, 3) |
| `yed_estimatecollateral` | 0, 1, 2 |
| `yed_estimatefee` | 0 |
| `yed_gethistory` | 0, 1 |
| `yed_mint` | 0, 1 |
| `yed_listtransactions` | 0, 1 (unchanged) |
| `yed_send` | 1 (unchanged) |
| `yed_sendmany` | 0 (unchanged; the object) |
| `yed_estimatesend` | 0 (Phase 8; the recipients object or the plain cents number) |
| `yed_unlockcoin` | 1 (Phase 8; the vout) |
| `yed_gettag`, `yed_getvault`, `yed_gettxinfo`, `yed_decodepayload`, `yed_validaterawtransaction`, `yed_getblockverdict`, `yed_validateaddress`, `yed_redeem`, `yed_sweep`, `yed_listpositions` | none (all strings) |
| `yed_claim` | 3 (**v3**; `wait`) |
| `yed_mint` | 0, 1, 4 (**v3**: `wait` joins `cents`, `lockBlocks`) |
| `yed_listattestors` | 0 (**v3**) |
| `yed_buildbundle`, `yed_getselection` | 0 (**v3**; `selectorHex` is a string) |
| `yed_claimnotice` | 2 (**v3**; `wait`) |
| `yed_registerattestor` | 0, 1, 2 (**v3**) |
| `yed_withdrawbond` | 0 (**v3**) |
| `yed_revive` | 0, 1 (**v3**) |
| `yed_reportequivocation` | 2 (**v3**; `wait`) |
| `yed_signattestation` | 0, 1, 2 (**v3**) |
| `yed_getattestations`, `yed_addattestation`, `yed_getnotice`, `yed_sweepcarriers` | none (**v3**) |

## Configuration the contract depends on

`-yellowback`; `-yellowbackenforce` (default 1); `-yellowbackpayoutaddress=<s1…>` (P2PKH; defaults
to a P2PKH `-mineraddress`); `-yellowbacksignal` (default 0 on mainnet, 1 on testnet and regtest,
L4; effective only with `-yellowbackenforce=1`, L3); `-yellowbackquotemaxage=<sec>` (default
1800); `-yellowbacktemplatepolicy=strict|consensus`; `-yellowbackrequirehealthy` (default 0);
`-yellowbackpreferredpayee=<s1…>`; `-yellowbackpayeepenaltyblocks`, `-yellowbackpayeeaccuracywindow`,
`-yellowbackpayeetiltbps` (FEE-W overrides, L6; reported in `yed_getinfo.params.policy` and
`yed_getfeepayee.policy`); `-reindex-yellowback` (also clears `Rejected`); `-yellowbackfee`
(clamped to `≥ DEFAULT_FEE`); `-yellowbackmintlag` (`REF_LAG`, 0..36); `-debug=yellowback`;
regtest only: `-yellowbackstartheight`, `-yellowbacksigmaref`, `-yellowbacksupplycapbps`,
`-yellowbackenforceuntil` (all four in `yed_getinfo.params` and the state hash); test only:
`-yellowbacktestfault=storage:<check|commit|undo>[:<height>]|template|novalve`. `-prune` is refused
with `-yellowback`.

**v3:** `-yellowbackpreferredattestor=<seq>` (AFEE-W override when that `seq ∈ A`; reported in
`yed_getinfo.params.policy.preferredAttestor`); regtest only: `-yellowbackattestarmmin=<n>`
(`ATTEST_ARM_MIN`, `0` = never arms; hashed) and `-yellowbackbundlecarrier=scriptsig|opreturn|either`
(`BUNDLE_CARRIER`; hashed) — both in `yed_getinfo.params.attest` and the state hash (M13). The
files `<datadir>/yellowback/carriers.dat` (outstanding carriers, W7) and
`<datadir>/yellowback/attest-signed.dat` (the signing guard, S16) belong to the wallet layer and
are never in `wallet.dat`; deleting `attest-signed.dat` on an attestor node removes the only
protection against self-equivocation.

## Phase 8 additions (delivered; `rpcversion` stays 2)

Every item below is implemented and has its shape above; the `rpcversion` rule holds (additions
only, nothing removed and nothing reshaped).

- `yed_estimatesend` (H3): the dry run of `yed_send`/`yed_sendmany` — the selection, the change
  and, when the amount is unworkable, the nearest workable amounts; no signing, no locking.
- `yed_unlockcoin <txid> <n> "I understand this burns YED"` (H5): the deliberate escape hatch now
  that `lockunspent` refuses to unlock a Yellowback-held outpoint.
- `yed_getinfo.lockedOutputs` (number) and `protectedByIndex` (boolean) (H10).
- `yed_redeem.extraBurnCents` and `yed_claim.extraBurnCents` (H4): a sub-dollar remainder the
  selector burned rather than refuse, `0` whenever a selection with valid change exists.

### Stock RPCs the overlay changes (H5, H7, H8; wallet tier, no consensus effect)

These are Ycash's own commands. Each change is additive and inert without `-yellowback`:

| Command | Change |
|---|---|
| `lockunspent` | With `-yellowback` and a wallet, `lockunspent false\|true [{txid,vout},…]` refuses (`yed-locked-outpoint`, `RPC_WALLET_ERROR`) when any named outpoint is held by the Yellowback wallet layer, and nothing in the call is applied. `lockunspent true` with no second argument still unlocks everything, then **re-applies** the Yellowback locks before returning, so it can never leave YED spendable as plain YEC. |
| `sendrawtransaction` | Third parameter `allowyedburn` (boolean, default `false`), the same shape as `allowhighfees`: with `-yellowback` and a wallet, a raw transaction that spends a `Tokens` outpoint that is mine and does not reassign it is refused with `yed-burn-refused` (`RPC_WALLET_ERROR`) unless it is `true`. *Reassigns* means the transaction carries a well-formed REDEEM payload (a vault spend, which MP-1 judges and whose burn is a rule, not an accident) or a TRANSFER payload with at least one assignment; no payload, an unreadable one, a MINT payload, or a TRANSFER that assigns nothing all leave the spent cents with nowhere to go. Without `-yellowback`, without a wallet, or for a transaction that spends no YED of this wallet, the parameter changes nothing. |
| `importprivkey`, `importaddress`, `importwallet`, `z_importkey` | After their rescan, each calls the Yellowback wallet layer's `Reconcile()` (H8), so YED that has just become mine is locked before the next block rather than at the next reconciliation. No return-value change. |

### Startup (H6)

A datadir that holds a Yellowback index refuses to start without `-yellowback`: `init` fails with
*"This datadir holds a Yellowback index … start with -yellowback, or with -yellowback=0 to
acknowledge that any YED outputs in this wallet are spendable as plain YEC."* Passing
`-yellowback=0` explicitly is that acknowledgement and starts normally (with the warning logged);
the check is skipped with `-disablewallet`, which cannot burn anything.

## v3 additions (bond-weighted price attestation; `rpcversion = 3`)

The contract of v3 plan §4.5, written in Phase A0 before the code; the node context lands in
Phase A2, the wallet context in Phase A3. Every item has its shape above under a **v3** mark.

- **New node commands:** `yed_listattestors`, `yed_getattestations`, `yed_addattestation`,
  `yed_buildbundle`, `yed_getselection`, `yed_getnotice`.
- **New wallet commands:** `yed_claimnotice`, `yed_sweepcarriers`, `yed_registerattestor`,
  `yed_withdrawbond`, `yed_revive`, `yed_reportequivocation`, `yed_signattestation`.
- **New fields:** `yed_getinfo.attest{status, triggerHeight, armHeight, seatedCount, poolSize,
  poolFresh, carrierMode, required, armed}`, `yed_getinfo.rebuilt`, `yed_getinfo.params.attest{…}`,
  `params.policy.preferredAttestor`; `yed_getprice.{xMint, xClaim, armed, attestStatus, seated,
  pinnedKeys, pinnedSeqs}`; `yed_getvault`/`yed_listvaults`/`yed_listpositions`.{noticed,
  noticeHeight, emergencyOpenAt}` and `yed_listpositions.canNotice`;
  `yed_listclaimable.{claimPath, noticed, noticeHeight, emergencyOpenAt, residualZat,
  attestFeeZat}`; `yed_gettxinfo.{xMint, xClaim, aMint, aClaim, pMint, pClaim, bundleSeqs,
  attestFeeZat, attestPayee, residualZat, claimPath, notice, carrierVin, bundleSource}` (+
  `seq` on a `register` row); `yed_decodepayload.attestFeeVout` and the v3 types with their
  fields, `bundle` for a raw transaction; `yed_estimatecollateral.{xMint, aMint, source, armed,
  bundleSeqs, attestFeeZat, divergenceBps}`; `yed_mint.{carrierTxid, pending, refHeight, xMint,
  aMint, pMint, source, bundleSeqs, attestFeeZat, attestPayee}`; `yed_claim.{carrierTxid,
  pending, refHeight, xClaim, aClaim, pClaim, pEmerg, claimPath, bundleSeqs, attestFeeZat,
  attestPayee, residualZat}`; `yed_listtransactions.type` values `notice`, `noticed`, `register`,
  `withdraw`, `revive`, `equivocation`, `carrier`.
- **New arguments:** `yed_mint … [bundleHex] [wait]`, `yed_claim … [bundleHex] [wait]`.
- **New error identifiers:** the *v3 identifiers* table above (`attest-unknown-seq`,
  `attest-not-eligible`, `attest-stale`, `attest-bad-sig`, `attest-range`, `attest-malformed`,
  `bundle-insufficient`, `bundle-malformed`, `mint10-diverged`, `notice-standing`,
  `notice-not-underwater`, `bond-below-min`, `lock-below-min`, `bond-locked`, `bond-spent`,
  `not-dormant`, `not-equivocation`, `attest-key-not-held`, `equivocation-guard`).
- **Meaning changes without a shape change:** `yed_decodepayload.version` is `3` and a
  version-2 payload is `valid: false`; `yed_getprice.pMint`/`pClaim` are the cross-section (as
  before) while the combined prices are per transaction; `yed_listclaimable`/`canClaim` include
  the emergency clause; every wallet transaction that reads a price is two transactions (the
  carrier step).
- **Unchanged:** the unhealthy allow-list; `getblocktemplate`'s `yellowback` object;
  `yed_getinfo.miner`; every v2 command's arguments and fields.
