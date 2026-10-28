# Yellowback RPC contract (`yed_*`), rpcversion 8

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

**`rpcversion` rule.** `yed_getinfo.rpcversion` is `8` (the fee structure, below; post-quantum owners took `7`, in-term claims `6`, the vault upgrade `5`, v3 `3`). Additions (new commands, new fields)
never bump it; a removal or a shape change does. Phase 8's additions (`yed_estimatesend`,
`yed_unlockcoin`, `yed_getinfo.lockedOutputs`/`protectedByIndex`, H3/H5/H10) therefore landed
under `rpcversion = 2`. **v3 bumps to `3` by decision (v3 plan W14), not by the letter of the
rule:** every v3 change below is an addition, but a wallet built against the v2 contract cannot
build a bundle-bearing mint or claim once the attestation layer is armed, so the mismatch must be
refused rather than tolerated. The wallet's `YellowbackRpc::RPC_VERSION` goes to `3` in Phase A5's
first commit; until then a v3 node and a v2 wallet refuse each other (N27), which is intended.
Everything marked **v3** in this file is Phase A0's contract for Phases A2 (node context) and A3
(wallet context); the v2 text is unchanged except where a field's meaning changed and is marked.

**`rpcversion` 4 (hardening plan H-9.3, 2026-10-05), by decision as `3` was; superseded by `5` below.** The change is again
an addition: optional client bounds (`yed_mint`'s `maxCollateralZat` and `yed_claim`'s
`minOutZat`, both since the 2026-10-01 audit, and `yed_claim`'s new `maxBurnCents`). The bump
makes a client that does not know the bounds (and so cannot cap what a malicious or mistaken
server builds for it) refuse the node rather than run unprotected. Clients go to `4` with the
hardening plan's H5 chunks (YecWallet, YEW through lightwalletd); until then they refuse each other,
which is intended.

**The vault upgrade (`rpcversion` 5; docs/plans/yellowback-upgrade-plan.md §15.10, U-21..U-24).**
Ycash Yellowback (YED) is the rule module of the vault primitive: its rules are consensus at every
height where `UPGRADE_VAULT` is active and the network's YED attestor set is known (regtest:
`-nuparams=6d5b7a31:<h> -yellowbackattestorset=<setid>`; mainnet and testnet unset, so the yed_*
commands do not exist there). `-yellowback` and `-experimentalfeatures` no longer gate anything.
What changed for a client, every item a removal or a shape change (hence the bump; the hardening
plan's H3-c had taken 4 on its own branch, and the two merge to 5):
- `yed_getactivation` reports the upgrade (`status`, `activationHeight`, `branchId`,
  `attestorSetId`, `claimDelay`, `height`); `yed_getinfo` drops `activation`, `enforcing`,
  `valveTripped`, `sunset`, `rejectedBlocks`, `suppressedBlocks`, `templatePolicy`, `abandoned`,
  `miner.signal`, `params.enforceUntilHeight`/`valveBlocks`/`abandonBlocks`/`windows.signal` and
  gains `upgrade` (the `yed_getactivation` object), `params.attestorSetId` and `params.claimDelay`.
- `yed_gethistory` rows drop `signalCount` and `activation`; `yed_gettag` drops `signal`;
  `yed_getblockverdict` drops `enforcementOn` and gains `verdict`; `yed_sweep` is gone (and the
  abandonment predicate with it); `yed_listpositions` drops `canSweep`.
- The vault is the primitive's V template (tag `YED\0`, the attestor set as both sets, delay
  `CLAIM_DELAY`, ownerHeight `lockHeight`, appHeight `lockHeight + GRACE`): `yed_getvault` and
  every vault row gain `scriptPubKey` (its hex) and lose `sweepBefore`. A claim moves the vault
  into a claimant intent (and, when RED-5's residual is due, an owner residual intent): the vault is
  `CLAIMING` (a new status) with **optional** `intents` until the claimant intent is released
  (`vault_release`, after `CLAIM_DELAY`: `CLAIMED`) or cancelled by the attestor set
  (`vault_buildcancel` + `set_signcancel` + `vault_send`: the vault is re-created at the cancel's
  output 0 and is the same position, `ACTIVE`; the claim's burn is not refunded, U-24 -- **revised by
  CAN-1, audit 03/H-1:** the cancel refunds the burn, built with `yed_buildcancel`, below).
  `yed_gettxinfo` gains `reopenedVaults` and the types `claim_release` and `claim_cancel`.
- A failing mint or vault spend is an invalid transaction: no VOID vault is produced
  (`voidReason` stays `""`), the mempool refuses it with `bad-yellowback-<verdict>` and a block
  carrying it is rejected (DoS 100). `mempool-check-failed:<verdict>` keeps its meaning.

**In-term claims (`rpcversion` 6; docs/plans/yellowback-in-term-claims-plan.md §4, IT-1..IT-9; its §4.1
is the contract delta this file implements).** A vault is claimable at any height after its mint
once its collateral is worth less than θ × debt (`claimThresholdBps`, 125 %) at the attested claim
price, and its owner may redeem at any height (the V template's `ownerHeight` and `appHeight` are
both `refHeight + 1`); a redeem before `lockHeight` pays the early-redeem fee
`earlyRedeemFeeBps[class]` of the collateral on top of the pool fee (as it was at `rpcversion` 6; since `rpcversion` 8 it is of the debt at `pMint`, IT-9′, below). For a client: `yed_getinfo.params`
gains `claimThresholdBps`, `sigmaMultMaxBps`, `earlyRedeemFeeBps` (per class, also on each `classes`
row) and `inTermClaims: true`; `yed_listclaimable` lists every ACTIVE vault whose claim branch is
open, each with `claimable` and `lockHeight` — rows with `claimable: false` are vaults above the
threshold, with `underwaterAt` the claim price at which they become claimable (a shape change: a
client that claimed every row must now read `claimable`, hence the bump); `yed_redeem` and
`yed_claim` results gain `earlyRedeemFeeZat` (the part of `feeZat` the early-redeem fee is, `0` on a
claim); `yed_listpositions` rows gain `earlyRedeemFeeZat`; `yed_estimateredeem` is new (the quote a
wallet shows before the owner confirms a redeem); `vault-locked` no longer refuses an ACTIVE redeem
in term and `claim-not-yet` no longer refuses a claim in term (the threshold decides:
`claim-not-underwater`). Clients go to `6` with the in-term plan's T4.

**The fee structure (`rpcversion` 8; docs/plans/yellowback-quantum-fees-spec.md §1–§3, quantum plan
D-Q-23 Option D, D-Q-23a, D-Q-24, D-Q-25).** The pool fee is a **protocol fee in dollars**, tiered by the
vault's debt like tax brackets (`params.fees.protocol.bands`: 1.0 % of the first $1,000, 0.5 % to $10,000,
0.1 % above; `floorCents` $1 per action: mint, redeem, claim), converted to YEC at the vault's **stored mint
price** `pMint` (`ceil(fee × COIN / pMint)` zat, FEE-1′): the mint pays it, a redeem or claim pays it again at
the same price (RED-3′), the attestor share stays half of it (AFEE-1′), and the early-redeem fee (IT-9′) is
`earlyRedeemFeeBps[class]` of the **debt** at `pMint`, no longer of the collateral. MINT-5's `4 · FEE_MIN`
floor is gone (`requiredZatFloored = requiredZat`). `maxMint` is $100,000 (`params.maxMintCents`, D-Q-24); one
mint may not exceed max(10 % of the supply cap, $10,000) (`mint-vault-share`, MINT-6b, D-Q-23a); the supply
cap's base is the circulating YEC supply at the tip (`params.supplyCap`, D-Q-25); a claim's residual is due
from $0.48 at `pMint` (never below 100,000 zat, RED-5′). Network fees of post-quantum and Yellowback
transactions are **dollars per KB** at the attested tip price — the highest of the tip's window medians
(`params.fees.network.priceMicroUsd`; published while the price is trusted: none, `priceSource: "fallback"`, under
HALT-1 `NO_PRICE` or HALT-3 `DIVERGENCE`; HALT-2 `GLOBAL_RATIO` alone keeps it, since it restricts minting only —
fees spec §5.1, amendment 2026-10-28) — (`params.fees.network`: plain PQ
$0.02/KB, vault/Yellowback $0.05/KB, floor max(5,000 zat/KB, `-pqfeerate`), the Yellowback cap
min(max(`-maxtxfee`, $2 at the price), `-yellowbackmaxtxfee`, default 10 YEC:
`yellowback.maxTxFeeCeilingZat`), which caps plain post-quantum transfers too (D-Q-26: the node's own wallet
relays one above `-maxtxfee` but within that cap; `sendrawtransaction` keeps `-maxtxfee` unless
`allowhighfees`); the `-pqfeerate` rate is the fallback while no price exists). A
Yellowback-builder transaction is priced by its estimated size whether or not it has a post-quantum input; an
owner-path vault spend whose dollar-priced fee would exceed what the vault has left pays max(the flat fee,
the floor rate × size) instead of being refused. Removed (hence the bump): `params.feeMinZat`,
`params.feeBps`, `yed_getfeepayee`'s `collateralZat` argument and `feeZat` field (the fee is a property of
the debt and the mint price, quoted by the estimate RPCs); `yed_estimatefee` changes its signature to
`<mintedCents> [priceMicroUsd]` → `{feeCents, feeZat, pMint, attestFeeZat}`. Added: `params.maxMintCents`,
`params.fees`, `params.supplyCap`; `pMint` on every vault row (`yed_getvault`, `yed_listvaults`,
`yed_listpositions`, `yed_listclaimable`); `yed_estimatecollateral.protocolFeeCents` / `protocolFeeZat`;
`yed_estimateredeem.pMint` / `protocolFeeCents` / `protocolFeeZat` / `earlyRedeemFeeCents`. Changed meanings:
`params.pq.feeRateZatPerKB` = `params.fees.network.plain.zatPerKB` (so `rpcversion`-7 clients keep working);
`params.earlyRedeemFeeBps` and `classes[].earlyRedeemFeeBps` are of the debt; every `feeZat` /
`attestFeeZat` / `feePaidZat` is the same field on the new base. The samples below are a regtest node's:
`fees.protocol.attestFeeBps` is 2,500 there (the regtest parameter set) and 5,000 on mainnet and testnet
(`ATTEST_FEE_BPS`, AFEE-1′), so a sample `attestFeeZat` is a quarter of the protocol fee where mainnet's is
half; the sample vault ($1,000 minted at `pMint` $1.985) pays a $10 protocol fee = 503,778,338 zat and, in
term, a 5 % early fee of the debt = 2,518,891,688 zat. Under FEE-0 (no eligible payee) every protocol and
early fee field is `0`, `protocolFeeCents` and `earlyRedeemFeeCents` included.

**Post-quantum owners (`rpcversion` 7; docs/plans/yellowback-quantum-spec.md §3, §4, §6.2; quantum plan
§4.4).** Every vault's owner is a post-quantum key id, `scheme ‖ keyHash` (scheme 1 SLH-DSA-SHA2-128s, 2
FN-DSA-512, the latter from the Falcon height only). Removed: `ownerPubKey` and `ownerKeyId` on
`yed_getvault`, `yed_listvaults` and `yed_listpositions` rows, and `ownerPubKey` on a MINT's
`yed_decodepayload` (no public key is on chain; hence the bump). Added: `ownerScheme` (number) and
`ownerHash` (64 hex, the 32 bytes as the V pushes them) in their place; `yed_getinfo.params.pq`
`{schemes, falconActive, falconHeight, feeRateZatPerKB, plainAddressVersion}` (`schemes` = the owner schemes MINT-3 admits at
the next block; `falconHeight` = the module's mirror of the Falcon activation, the later of the `UPGRADE_VAULT`
height and the consensus `pqFalconHeight` (`-1` = never). Falcon goes live from day one (quantum plan D-Q-2, owner
2026-10-10): `pqFalconHeight` is 0 on mainnet and testnet, so there `falconHeight` is the vault activation height
(`-1` while that height is unset, until the release that sets it) and `falconActive` is true from the vault upgrade's
first block; regtest reports `-1` unless started with `-pqfalconheight`/`-pqfalcon=1`; `feeRateZatPerKB` = the size-priced rate wallets charge as
`max(DEFAULT_FEE, rate × size)`, the node's `-pqfeerate`; `plainAddressVersion` = the hex Base58Check version of
the plain-YEC PQ address, `4dd9`/`4f61`/`4c51` for `sq…`/`tq…`/`rq…`, D-Q-20); `yed_getinfo.params.addressVersion` and
`pqAddressVersion` (hex, the YED address versions of this network: mainnet `1fdd`/`56ab`, testnet `2007`/`571e`,
regtest `2002`/`5710`; clients read them instead of hard-coding the prefixes); `yed_getinfo.params.attest.mintPayloadVersion` (`4`: the MINT alone
is payload version 4, every other type stays `payloadVersion` 3 — quantum spec C-1, so a client's
TRANSFER builder is unchanged and a v3 MINT is non-Yellowback); `yed_mint`'s `ownerAddress` (the fresh
SLH-DSA owner's address; the arguments are unchanged, A-3; the examples below show the example `ownerHash`
in its 53-character mainnet `yb…` form); `yed_validateaddress`'s `type` (`p2pkh` |
`pq`) and, for a PQ address, `pqscheme` (`keyid` is then the 66-hex `scheme ‖ keyHash` and
`transparentAddress` is the key's plain-YEC PQ address `sq…`/`tq…`/`rq…` — D-Q-20, Base58Check
`4DD9`/`4F61`/`4C51` ‖ scheme ‖ keyHash, 53 characters; it was `""` before the SQ task); `yed_getnewaddress`'s optional `type` argument (`p2pkh`, `pq` a post-quantum
holder, `pqowner` an SLH-DSA key; the default follows the holder policy: `p2pkh` until Falcon is active,
`pq` after — on mainnet and testnet Falcon is active from the vault upgrade, so the default there is always `pq` and
no P2PKH YED holder ever exists; `p2pkh` defaults only on a regtest chain without Falcon). Addresses: a post-quantum YED address is Base58Check(`56AB`/`571E`/`5710` ‖ scheme ‖
keyHash), `yb…`/`yt…`/`yr…`, **53** characters (the P2PKH form stays 35); `yed_send`, `yed_sendmany`,
`yed_listtokens` and `yed_validateaddress` take either (`yed_listtokens` also takes the plain-YEC
`sq…`/`tq…`/`rq…` form of a PQ holder, as it takes `s1…` for a P2PKH one). The owner's residual intent of a claim pays the
owner's `TX_PQPKH` (`20 <ownerHash> 51|52 c2`, F-3). From the Falcon height every YED token output must
be a Falcon `TX_PQPKH` (TOK-PQ, `bad-yed-holder`: the transaction is refused, never burned); the
wallet then draws its token and change outputs from Falcon keys. A YED transaction built before that height with a
P2PKH (or SLH-DSA) token output and still unconfirmed when the tip reaches Falcon height − 1 is evicted from the
mempool (it would be invalid in the next block, review B I-1): the wallet rebuilds it. TOK-PQ binds only outputs
that actually receive YED: a TRANSFER with no YED input, or one XFER-1..3 burns, is unaffected (quantum spec, "Q4
as implemented"). A hybrid channel output (`TX_PQCHANNEL`, D-Q-19) holds YED from the Falcon height when its
client is a Falcon key; `yed_listtokens` lists it under the client's address.

**Plain-YEC PQ addresses (`sq…`/`tq…`/`rq…`, D-Q-20): what node operators and clients should know.**

- **Inputs spending PQ coins carry no address** in `getblockdeltas`, `getspentinfo` and
  `getrawtransaction` (verbose `vin[].address`): the insight index keys a spent output by its
  Hash160, and a `TX_PQPKH` key hash is 32 bytes, so the index cannot name it from the input side.
  `getaddressdeltas` (and `getaddressutxos`/`getaddressbalance`/`getaddresstxids`) name them as
  requested, by `sq…`/`tq…`/`rq…` or the PQ `yb…`/`yt…`/`yr…` form.
- **`-reindex` once** on a node with `-insightexplorer` or `-lightwalletd` that synced before this
  build: the address index of earlier blocks holds no `TX_PQPKH` outputs until it is rebuilt.
- **`createrawtransaction` takes an `sq…` output** without the wallet's payability checks (Falcon
  activation, the PQ dust threshold); relay policy still refuses a non-standard or dust output. Prefer `sendtoaddress`/`sendmany`, which check.
- **`yed_getnewaddress "pq"` now files holder keys in the address book** (under the `sq…` form, so
  the YEC their token outputs carry is not taken for change); holder keys issued by an earlier build
  are not added retroactively (`getnewaddress "" "pq"` files plain-YEC PQ keys; `"pqowner"` keys stay
  out).
- **`z_sendmany` / `z_mergetoaddress` refuse an `sq…` recipient** on this line (their recipients are `libzcash::PaymentAddress`, which has no post-quantum alternative): pay an `sq…` address with `sendtoaddress` or `sendmany`.
- **Seed-only restore (`-mnemonicfile`)** restores the seed's first legacy Sapling address and its
  post-quantum keys up to a gap of `PQ_KEY_LOOKAHEAD` = 20 unused keys per scheme: a key beyond 20
  unused ones in a row is not re-found. Recover such keys by issuing PQ addresses past the gap
  (`getnewaddress "" "pq"`) and running `rescanblockchain`; further Sapling addresses likewise with
  `z_getnewaddress` before `rescanblockchain`. On an existing wallet the option is ignored when the
  seed matches (checked by fingerprint, so a locked wallet starts too) and refused when it does not.
- **`-sendchangeback=1`** returns a PQ input's change to its `sq…` address; the change's dust check
  uses the PQ spend size (`GetPQDustThreshold`), as relay policy does.
- **`z_importpqkey`** takes a dump's whole `pqseed=` line and refuses it when its `owner=`/`addr=`/
  `yecaddr=` do not name the key the seed makes under the line's scheme (the scheme decides the key;
  both schemes take a 48-byte seed). **`vault_release`** refuses a 66-hex pqkeyid as the recipient
  (pass the address or the script).

**P4-b: the attestor registry is the attestor set** (upgrade plan §15.10; additions only, so
`rpcversion` stays 5). An attestor is a member of the vault primitive's set `attestorSetId`: it
joins with a `SET_JOIN` (`set_join`, or `yed_registerattestor`, which is that join with a fresh
wallet key), stays live with `SET_HEARTBEAT` (`set_heartbeat`, or `yed_revive`), and its one member
key is its hot key (it signs prices), its bond key (the set's bond B) and its fee key. Every
`Attestors` record mirrors one join (a new `seq` per join). `ATTESTOR_REGISTER` and
`ATTESTOR_REVIVE` payloads are invalid (`bad-yellowback-attestor-register-retired`,
`-attestor-revive-retired`). `yed_listattestors` rows gain `lastAct` (the set's lastAct for the
member) and `bondFrozen` (the bond is frozen in the set: `SET_REMOVE` with burn, `SET_EQUIVOCATION`,
or EQV-1, which now freezes the bond through the module ejection hook, U-25); `yed_gettxinfo.type`
gains `"set_act"` (a heartbeat, removal or set equivocation of an attestor; `seq` names its record)
and `"register"` now names a `SET_JOIN` to the set. A record is ELIGIBLE from `registerHeight +
max(set maturity, BOND_MATURITY)` when its bond meets the module's floor (D-Q-30: `bondMinZat` from vault collateral at the snapshot before the join) and `BOND_MIN_LOCK` and its key was
never slashed; DORMANT when its `lastAct` is older than the set's `livenesswindow` (or by S15, as
before); ELIGIBLE again after a heartbeat that follows. `seated` holds at most `min(N_SLOTS, seats)`.

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
  `"CLOSED"`, `"CLAIMED"`, `"CLAIMING"`; upgrade statuses (`yed_getactivation`) `"pending"`,
  `"active"` (the v2 `"signaling"` / `"locked_in"` left with signalling, upgrade plan §6); halt-mask
  names `"NOT_ACTIVE"`, `"NO_PRICE"`, `"PARTICIPATION"`, `"GLOBAL_RATIO"`, `"DIVERGENCE"`,
  `"ENFORCEMENT"` (§3.6; `PARTICIPATION` and `ENFORCEMENT` are no longer set since the upgrade).
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
- **Gating.** Every command requires Yellowback to be live: the vault upgrade scheduled and the
  network's YED attestor set configured (U-22; regtest: `-nuparams=6d5b7a31:<h>` and
  `-yellowbackattestorset=<setid>`); otherwise the node answers JSON-RPC `-32601` "Method not
  found (Yellowback is not active: …)". Every refusal is `RPC_INVALID_PARAMETER` (a bad
  argument), `RPC_WALLET_ERROR` (funds, locking) or `RPC_VERIFY_REJECTED` (a rule), with a
  message that **begins with a stable identifier** from the table in *Error identifiers*; the
  wallet matches the identifier, never the text after it.
- **While the index is unhealthy** (`yed_getinfo.healthy == false`) every command refuses with
  `yellowback-unhealthy: <unhealthyReason>` **except** `yed_getinfo`, `yed_getblockverdict`,
  `yed_gettag`, `yed_decodepayload` and `yed_setquote` — the diagnostic and operator commands the
  runbook (`doc/yellowback-mining.md`) needs (M8). Recovery is `-reindex-yellowback`.

## Address format

A Yellowback address is Base58Check(version ‖ 20-byte key hash) with version bytes `0x1F 0xDD`
(mainnet, `yb…`; `ye…`/`0x1F 0xE4` before quantum plan D-Q-21), `0x20 0x07` (testnet, `yt…`), `0x20 0x02` (regtest, `yr…`); it decodes to an
ordinary P2PKH destination (`src/yellowback/address.cpp`, no `chainparams.cpp` edit). YED is
carried by `TOKEN_VALUE` (10,000 zat) P2PKH outputs assigned cents by a payload; the `yb…` prefix
is the only technical guard against sending YED to software that does not run the overlay (H9).
`yed_send`/`yed_sendmany`/`yed_validateaddress` refuse anything else with
`not-a-yellowback-address`. Sapling `ys1…` addresses are accepted as the *funding* of `yed_mint`
and the *destination* of `yed_redeem` (§4.6), never as YED recipients (a claim pays an intent,
whose recipient is transparent).

**Integration note: validate a YED address with `yed_validateaddress`, never the stock
`validateaddress`** (cf. DigiByte v9.26.7 `validateaddress`'s pointer to `validateddaddress`,
abda0647). The stock command knows only the plain-YEC prefixes, so it returns `isvalid: false` for
every `yb…`/`yt…`/`yr…` address, a valid one included; `yed_validateaddress` decodes both YED
forms (35-character P2PKH, 53-character post-quantum), says whether the key is this wallet's and
gives the `s…`/`sq…` twin of the same key (`transparentAddress`). An exchange or a payment
integration that checks a withdrawal address with `validateaddress` would refuse every YED
address; one that checks a YED address's twin with it would accept a plain-YEC address, which
burns YED (H9). The stock help text is unchanged.

---

## Node context (`src/rpc/yellowback.cpp`; no wallet needed)

### `yed_getinfo`

Arguments: none. Never refuses while unhealthy. `height`/`blockhash` are always the tip the index
holds (V2; `height` is `-1` and `blockhash` `""` while the index is empty). `upgrade` is the
`yed_getactivation` object (the vault upgrade; `startHeight` is its activation height, U-22).
`supplyCapReached` (**v3, W20**) is `true`
when the next mint of any class would exceed the supply cap at the tip snapshot (`supplyCents +
MIN_MINT > supplyCapCents`) and `false` when the cap is undefined (no cap, no price, empty index);
above the cap only a class whose base ratio reaches `params.recapRatioBps` mints (IT-5: class C
with the in-term parameter set; `yed_getstats.mintableClasses`). `mintRequiresArmed` (**hardening, H-1**) is
`MINT_REQUIRES_ARMED` of the set in force: when `true` a mint whose reference height is not
ARMED (`attest.armed`) is VOID with `mint-halted-unarmed` (MINT-4) and `yed_mint` refuses it with
`mintpol-unarmed`; `true` on mainnet and testnet, `false` on regtest unless
`-yellowbackmintrequiresarmed` is set (a hashed value there, M13). `miner.quoteKind` is what the
next template's tag would be (`"quote"` or `"none"`; the signal-only tag left with ACT-1); `miner.quoteAgeSeconds` is `null` when no quote is held; `miner.payoutAddress` is `null`
when the node has no payout key (then `quoteKind` is `"none"`). `params` reports every value the
Mint page derives from; on regtest `startHeight`, `sigmaRefBps`, `supplyCapBps` and
`attestorSetId` are the four hashed values (§3.1, M13); `claimDelay` is `CLAIM_DELAY` (U-23).
`params.feeZat` is the network fee floor `YELLOWBACK_FEE` (`-yellowbackfee`), distinct from the protocol fee
(`params.fees.protocol`, rpcversion 8); every transaction the wallet builds pays max(`feeZat`, its ZIP-317 conventional fee),
so it has no unpaid actions under `-txunpaidactionlimit`/`-blockunpaidactionlimit` (ycash6 plan P-2). `params.policy.preferredPayee` is `null` unless `-yellowbackpreferredpayee`
is set. **In-term claims.** `params.claimThresholdBps` is θ (`CLAIM_THRESHOLD_BPS`, 12,500: a vault
is claimable at any height after its mint while `collateralZat · pClaim < mintedCents · θ · COIN`,
IT-2); `params.inTermClaims` is `true` on a node with that rule (a client tells the line by it);
`params.earlyRedeemFeeBps` is the per-class early-redeem fee (IT-9′: 500 / 250 / 100, of the
debt at the vault's `pMint`, on an owner redeem confirming below `lockHeight`), repeated on each `classes` row;
`params.sigmaMultMaxBps` is the volatility multiplier's cap (`10000` with `sigmaRefBps` `0`: the
multiplier is pinned at 1, so a class's required ratio is its `baseRatioBps`, IT-4).
`params.globalRatioDenominator` is `"openDebt"`: HALT-2 compares the ACTIVE and CLAIMING vaults' collateral with
their open debt (`yed_getstats.openDebtCents`), not with `supplyCents` (owner decision 2026-10-28). `lockedOutputs` (H10) is how many outpoints the Yellowback wallet layer holds locked
(stage (i)–(iii) of §4.6; `0` when the node runs without a wallet) and `protectedByIndex` is
`true` whenever that layer is attached: the GUI treats a mismatch between `lockedOutputs` and the
length of `yed_listunspent` as the trigger for `yed_lockcoins`.

**v3.** `attest` is the arming state at the index tip (v3 §3.6 `Attest`): `status`,
`triggerHeight`/`armHeight` (`0` while UNARMED; `armHeight = triggerHeight + ATTEST_ARM_DELAY`
once TRIGGERED), `seatedCount` = `|Snapshots[tip].seated|`, `poolSize` = attestations in this
node's attestation pool (all `seq`s, up to three each, W5), `poolFresh` = the number of
**seated** `seq`s for which the pool holds an attestation a mint built now could cite: `R = tip −
REF_LAG` and `R − ATTEST_MAX_AGE < citedHeight ≤ R` (and `≥` the start height; the window
`yed_buildbundle` uses — a citation above `R` is not counted until `R` reaches it),
`carrierMode` = the `BUNDLE_CARRIER` in force, `required` = `ATTEST_REQUIRED` of the set in
force (W15; `false` means every bundle-reading rule is vacuous whatever `status` says), `armed` = `status == "ARMED" && required`. `params` gains `attest` (every v3 §3.1 value
the Mint page and the Attestors view derive from; on regtest `armMin` and `carrierMode` are the
two additional hashed values, M13) and `params.policy.preferredAttestor` (`null` unless
`-yellowbackpreferredattestor` is set). `rebuilt` (**v3**) is `true` for the rest of the
session when this start found a `SCHEMA_VERSION` mismatch and rebuilt the index from the chain.

Result of `yed_getinfo`:

```json
{
  "rpcversion": 8,
  "enabled": true,
  "network": "regtest",
  "height": 331,
  "blockhash": "0f3a9c1e5b7d2a4c6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f",
  "chainHeight": 331,
  "startHeight": 103,
  "healthy": true,
  "unhealthyReason": "",
  "supplyCapReached": false,
  "mintRequiresArmed": false,
  "lockedOutputs": 2,
  "protectedByIndex": true,
  "rebuilt": false,
  "upgrade": {
    "name": "Vault",
    "branchId": "6d5b7a31",
    "status": "active",
    "activationHeight": 103,
    "attestorSetId": "5e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e75",
    "claimDelay": 10,
    "height": 331
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
    "quoteKind": "quote",
    "quoteAgeSeconds": 12,
    "registered": true,
    "eligible": true
  },
  "params": {
    "startHeight": 103,
    "attestorSetId": "5e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e75",
    "claimDelay": 10,
    "sigmaRefBps": 0,
    "supplyCapBps": 0,
    "refLag": 2,
    "refWindow": 40,
    "grace": 24,
    "payeeWindow": 10,
    "tokenValueZat": 10000,
    "feeZat": 1000,
    "maxMintCents": 10000000,
    "fees": {
      "protocol": {
        "bands": [ { "uptoCents": 100000, "bps": 100 }, { "uptoCents": 1000000, "bps": 50 }, { "uptoCents": null, "bps": 10 } ],
        "floorCents": 100,
        "attestFeeBps": 2500,
        "priceSource": "pMint"
      },
      "earlyRedeemFeeBps": [ 500, 250, 100 ],
      "network": {
        "priceMicroUsd": 400000,
        "priceSource": "tip",
        "plain": { "usdPerKBMicro": 20000, "zatPerKB": 5000000 },
        "yellowback": { "usdPerKBMicro": 50000, "zatPerKB": 12500000, "maxTxFeeUsdMicro": 2000000, "maxTxFeeCeilingZat": 1000000000, "maxTxFeeZat": 500000000 },
        "floorZatPerKB": 5000,
        "fallbackZatPerKB": 100,
        "flatZat": 1000,
        "maxTxFeeZat": 10000000
      }
    },
    "supplyCap": {
      "circulatingZat": 1656250000000,
      "issuedBeforeStartZat": 625000000000,
      "priceMicroUsd": 400000,
      "capCents": null,
      "maxVaultShareBps": 1000,
      "vaultShareFloorCents": 1000000,
      "maxVaultCents": null
    },
    "addressVersion": "2002",
    "pqAddressVersion": "5710",
    "windows": { "fast": 8, "mid": 24, "slow": 64 },
    "minFill": { "fast": 4, "mid": 16, "slow": 43 },
    "classes": [
      { "class": "A", "minBlocks": 48, "maxBlocks": 96, "baseRatioBps": 30000, "earlyRedeemFeeBps": 500 }
    ],
    "earlyRedeemFeeBps": [ 500, 250, 100 ],
    "globalRatioHaltBps": 25000,
    "globalRatioDenominator": "openDebt",
    "recapRatioBps": 50000,
    "claimThresholdBps": 12500,
    "sigmaMultMaxBps": 10000,
    "inTermClaims": true,
    "pq": {
      "schemes": [ 1 ],
      "falconActive": false,
      "falconHeight": -1,
      "feeRateZatPerKB": 5000000,
      "plainAddressVersion": "4c51"
    },
    "policy": {
      "penaltyBlocks": 12,
      "accuracyWindow": 24,
      "tiltBps": 10000,
      "preferredPayee": null,
      "preferredAttestor": null
    },
    "attest": {
      "payloadVersion": 3,
      "mintPayloadVersion": 4,
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
      "bondMinZat": 500000000,
      "bondMinFloorZat": 500000000,
      "bondMinCapZat": 1000000000,
      "bondShareBps": 500,
      "bondMinLock": 0,
      "bondMaturity": 8,
      "ageCap": 64,
      "foundingWindow": 16,
      "seats": 15,
      "seatAgeUnit": 1152,
      "seatAgeCap": 420480,
      "seatMarginBps": 500,
      "evictMarginBps": 500,
      "dormancyBlocks": 16,
      "dormancyMinBundles": 2,
      "dormancyCheck": 4,
      "carrierValueZat": 10000
    }
  }
}
```

`classes` always has three rows (A, B, C) in class order; the example shows one. A row with
`minBlocks > maxBlocks` is a disabled class (H-5; none is since the in-term plan's D-IT-9 re-enabled
B and C), which no mint can use. Every value in `params` other than the four hashed regtest values (six with **v3**'s
`attest.armMin` and `attest.carrierMode`, seven with the top-level `mintRequiresArmed`) is
compiled into the network's parameter set (§3.1) — a wallet may display
them but must not treat them as configurable. `params.attest` names are the v3 §3.1 rows in
lowerCamelCase (`ATTEST_ARM_MIN` → `armMin`, …); `carrierValueZat` is wallet policy and reported for display
only. **rpcversion 8 (D-Q-30):** the attestor bond minimum follows the YEC locked in YED vaults; no price is read.
`bondMinFloorZat` (10,000 YEC since the owner's 2026-10-11 amendment, was 5,000; regtest 5), `bondMinCapZat` (20,000 YEC; regtest 10) and `bondShareBps` (500) are the
parameters; `bondMinZat` is computed: the floor a `SET_JOIN` in the **next** block must meet, `clamp(⌈collateralZat ·
bondShareBps / (10⁴ · nSlots)⌉, bondMinFloorZat, bondMinCapZat)` over the tip snapshot's `collateralZat` (ACTIVE and CLAIMING vaults: a claimed vault's collateral counts until its release) —
5 % of all vault collateral backs the seats together; on mainnet the floor binds below ≈ 1.8 M YEC of collateral and the cap
above ≈ 3.6 M YEC. A record is judged once, against the snapshot before its own join block; a seated or ELIGIBLE record is
never re-judged as collateral moves. **Seat ranking and eviction (owner 2026-10-11, rpcversion 8, no bump):** seats rank by
`seatWeight = bondZat × f(age)` with the log tenure factor `f` from 1.0 (no tenure) to 1.9 at `seatAgeCap` (one year;
`f = 1 + 0.9 · (lg(u + a) − lg(u)) / (lg(u + cap) − lg(u))`, `u = seatAgeUnit`, deterministic Q16 integer logs, `Log2Q16` in math.h), a seated attestor's counting
×(1 + `seatMarginBps`/10⁴); the price statistic and attestor selection keep `weight = bondZat × min(age, ageCap)`. The attestor set
is OPEN with `seats` (15) seats: a `SET_JOIN` into the full set evicts the member that is not live (`lastAct < h − livenessWindow`)
of least seat weight, else the member of least seat weight when the new bond (at age 0) exceeds it by `evictMarginBps`; the evicted
record becomes `WITHDRAWN` with `evicted: true` in `yed_listattestors`, its bond not frozen. `SET_REMOVE` and `SET_WINDDOWN` of the
attestor set are invalid (`attestor-set-act`); equivocation is the only removal. **Seats re-review (2026-10-11):** a
`SET_JOIN` of the attestor set whose bond is below `bondMinZat` at its block is invalid (`attestor-bond-below-min`), so
every member becomes ELIGIBLE at maturity; an attestor's own attestations count as liveness only from a held mint,
notice or claim whose bundle passes BUNDLE-1, with a refHeight within `REF_WINDOW` (one cached signature check per
attestation); a transaction whose bundle would count but is not such an act is invalid (`liveness-unheld`).

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

### `yed_verifyindex`

Arguments: none. Additive (rpcversion 8, no bump). The invariant audit the node also runs at every start, after
the index reaches the tip (cf. DigiByte v9.26.7 `19c8b1c272`, `src/index/digidollarstatsindex.cpp`
SupplyVerification): the `Totals` record is re-derived from the records it summarises, read only, in one pass
over `Tokens` and `Vaults` -- `supplyCents` is the sum of every unspent YED token's cents (a claim's burn left
supply with the claim and a cancel's refund came back as a token, so a `CLAIMING` vault adds nothing),
`collateralZat` the collateral of the `ACTIVE` and `CLAIMING` vaults (IT-6), `activeVaults`, `voidVaults`,
`closedVaults` and `claimedVaults` the count of records in that status, `unbackedCents` 0, `openDebtCents` the
`mintedCents` of the `ACTIVE` and `CLAIMING` vaults (HALT-2's denominator, 2026-10-28), with `supplyCents <=
openDebtCents` checked too -- and the tip snapshot's `supplyCents` / `collateralZat` / `openDebtCents` must equal
the `Totals` they were copied from. Every signer set's
`lockedValue` in the vault set-state database is re-derived the same way, as the sum of its unspent V outputs
(`sets`). `stored` is the `Totals` record, `records` the re-derived one; `mismatches` has one line per
disagreement and is empty when `ok`. The command writes nothing, but a mismatch marks the index unhealthy, with
the log line `yellowback: index unhealthy: invariant audit failed … restart with -reindex-yellowback` (a set's
`lockedValue`: restart with `-reindex`), and the node stops at the next block (U-21); at start a mismatch
refuses to start the same way. It answers on an unhealthy index too. Cost: one read of every `Tokens` and
`Vaults` record under `cs_main`. `rulesVersion` is the stamp the index carries (`RULES_VERSION`, `R` key, not
in the state hash): a release that changes how stored heights are judged bumps it and every node rebuilds its
index at start, `yed_getinfo.rebuilt` reporting it.

Result of `yed_verifyindex`:

```json
{
  "height": 331,
  "ok": true,
  "tokens": 4,
  "vaults": 5,
  "stored": { "supplyCents": 1500000, "collateralZat": 62500000000, "activeVaults": 3, "voidVaults": 0, "closedVaults": 2, "claimedVaults": 0, "unbackedCents": 0, "openDebtCents": 1500000 },
  "records": { "supplyCents": 1500000, "collateralZat": 62500000000, "activeVaults": 3, "voidVaults": 0, "closedVaults": 2, "claimedVaults": 0, "unbackedCents": 0, "openDebtCents": 1500000 },
  "sets": [ { "setid": "4c1d9b2e7a6f5e8d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d", "lockedValueZat": 62500000000, "recordsZat": 62500000000 } ],
  "mismatches": [],
  "healthy": true,
  "rulesVersion": 1
}
```

### `yed_getstats`

Arguments: none. `Totals` plus the tip snapshot. `supplyCents` is the circulating supply -- the YED
that can still be presented -- and MINT-6's cap reads it. **`openDebtCents`** (added 2026-10-28,
additive) is the sum of the `mintedCents` of every ACTIVE and CLAIMING vault, and `globalRatioBps`
(HALT-2) divides by it: `collateralZat` at `pMint` against the open debt, the same vaults the
collateral counts (IT-6). **`globalRatioDenominator`** names that denominator and is always
`"openDebt"` (owner decision 2026-10-28; DigiByte v9.26.6 made the same move, `selected_health_denominator`).
The two differ: YED burned outside a redemption (an over-burn, XFER-2's remainder, a non-Yellowback
spend) leaves supply but not the debt, and a claim's burn leaves supply while its vault is CLAIMING
(an attestor-set cancel puts the claim's whole burn back, CAN-1); a release closes the debt. So
`supplyCents <= openDebtCents` always, and the gap is debt no YED is left to burn. `pClaim` is
`null` when undefined (fewer than the minimum fill on the mid or slow window); `globalRatioBps` is
`null` when there is no open debt or no `pMint`; `supplyCapCents` is `null` when there is no cap (`supplyCapBps == 0` or no price).
`haltMask` is the decoded tip `haltMask` as an array of names (empty when minting is open);
`mintingAllowed` is `activation == active && haltMask == [] && !supplyCapReached` and, when
`yed_getinfo.mintRequiresArmed`, the tip ARMED (H-1) — every enabled class can mint.
**v3 (W16, W20), in-term IT-5** `mintableClasses` is the list of term classes a mint can use
*now*: every enabled class when `mintingAllowed`; under a `GLOBAL_RATIO` halt alone, and **at the
supply cap** (W20: `yed_getinfo.supplyCapReached` — the smallest mint would exceed it), only the
classes whose base ratio (`baseRatioBps`) reaches `params.recapRatioBps` — class C with the in-term
parameter set, whose recapitalisation floor is class C's base ratio and whose sigma multiplier is
pinned at 1 (IT-4, IT-5; IT-5 replaces H-10's class-A rule); empty under any other halt and, with
`mintRequiresArmed`, while the tip is not ARMED. A disabled class (empty term range, H-5) is never
listed. The MINTPOL-1 gate `yed_mint` applies is "the class of `lockBlocks` is in `mintableClasses`".

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
  "openDebtCents": 250000,
  "issuedZat": 1656250000000,
  "pFast": 2000000,
  "pMid": 2000000,
  "pSlow": 1990000,
  "pMint": 1990000,
  "pClaim": 2000000,
  "sigmaMultBps": 10000,
  "globalRatioBps": 49750,
  "globalRatioDenominator": "openDebt",
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
    "priceMicroUsd": 2000000,
    "sourceMask": 3,
    "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111"
  }
}
```

### `yed_getactivation`

Arguments: none. The vault upgrade's status (U-22; ACT-1..7 — signalling, lock-in, the valve, the
sunset — are retired, upgrade plan §6). `status` is `"active"` once the index tip has reached
`activationHeight` (the `UPGRADE_VAULT` height = `startHeight`), else `"pending"`; `branchId` is
the upgrade's (`6d5b7a31`); `attestorSetId` is the network's YED attestor set (the vault
primitive set whose members cancel claims); `claimDelay` is `CLAIM_DELAY`; `height` the index tip.

Result of `yed_getactivation`:

```json
{
  "name": "Vault",
  "branchId": "6d5b7a31",
  "status": "active",
  "activationHeight": 103,
  "attestorSetId": "5e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e75",
  "claimDelay": 10,
  "height": 331
}
```

### `yed_listminers [height] [window]`

Arguments: `height` (number, optional; default the tip), `window` (number, optional; default
`PAYEE_WINDOW`, at most `4032` — the launch bar uses `2016`, L4). One row per `payoutKey` that carries a quote tag
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
the other fields are absent (**optional**). `kind` is `"quote"`, or `"signal"` for a tag carrying a
payout key but no quote (`priceMicroUsd: 0`; the name is kept, though the ACT-1 signal bit it once
carried is retired with the upgrade, plan §6). Allowed while unhealthy.

Result of `yed_gettag`:

```json
{
  "found": true,
  "kind": "quote",
  "version": 1,
  "priceMicroUsd": 2000000,
  "sourceMask": 3,
  "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111"
}
```

### `yed_setquote <priceMicroUsd> <sourceMask>`

Arguments: `priceMicroUsd` (number; `0` clears the quote so the next tag is none), `sourceMask` (number, 16-bit; the §5 source-bit registry). Miner control (MINER-1): stores
`{quote, sourceMask, receivedAt = GetTime()}`; requires RPC auth like every command. Allowed
while unhealthy (the tag is not emitted then, MINER-3, but the quote is kept). `nextTag` is what
the next template would carry given the stored quote, `-yellowbackquotemaxage`,
(`kind` `"quote"` or `"none"`; `payoutAddress` `null` when there is no payout key — but then the command
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
    "payoutAddress": "smQvTmAz2ExamplePayoutAddress1111111"
  }
}
```

### `yed_getfeepayee <refHeight> [selectorHex]`

Arguments: `refHeight` (number), `selectorHex` (string, optional; the 33-byte owner id of a MINT or the
36-byte serialised vault outpoint of a REDEEM). rpcversion 8: the `collateralZat` argument and the `feeZat`
field are gone — the fee is a dollar amount of the debt at the mint price (`yed_estimatefee`,
`yed_estimatecollateral` for a mint; `yed_estimateredeem`, `yed_listclaimable` for a spend). For external
transaction builders: `eligible` is `E(refHeight)` (FEE-2, height order, deduplicated), `default` is the FEE-W choice for the selector with its weight
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
(`closingTxid` `""`, `closeHeight` `null`). `claimable` is true for an ACTIVE vault whose claim
branch is open (from the block after its mint, IT-1/IT-2: in term, in grace and past it alike) that
is underwater at the tip snapshot (RED-4 would pass; **v3**, while armed: by
clause (a) or (b), exactly `yed_listclaimable`'s test, so a vault listed there with `claimPath`
`"b"` reads `claimable: true` here); `underwaterAt` is the `pClaim` (µUSD) below which
`collateralZat · pClaim < mintedCents · CLAIM_THRESHOLD_BPS`, i.e. the price at which the vault
becomes claimable (`null` for a VOID vault, which has no debt). `unbacked`
is true for a vault closed without its burn (IN-2; no rule produces one since the sweep was
retired, upgrade plan §6). `scriptPubKey` is the vault's V template in hex (tag `YED\0`, both
sets the YED attestor set, delay `CLAIM_DELAY`, ownerHeight and appHeight `refHeight + 1` (IT-1;
a vault minted before the in-term rule keeps `lockHeight` / `lockHeight + GRACE`); U-23) — what an external builder needs to spend it. A vault that is **`CLAIMING`** (a
claim moved its collateral into a claimant intent, and the RED-5 residual into an owner residual
intent) carries **`intents`** (**optional**, absent otherwise): `[{txid, vout, role, height,
releaseHeight}]`, `role` `"claimant"` or `"residual"`, `releaseHeight` = `height + CLAIM_DELAY`,
the first height `vault_release` can spend it. Releasing the claimant intent makes the vault
`CLAIMED`; an attestor-set cancel re-creates it as an `ACTIVE` vault at the cancel's output 0
(the same position under that outpoint) and **refunds the claim's burn** (CAN-1, audit 03/H-1, U-24
revised): a CLAIMING vault also carries **`refundHolder`** (**optional**, absent otherwise; hex), the
scriptPubKey the claim's burned YED came from, which a cancel must pay a token carrier at an output
`≥ 1` (`yed_buildcancel`). `burnedCents` of a CLAIMING vault is the amount that cancel re-issues. **The per-vault cancel limit**
(docs/plans/yellowback-cancel-limit-design.md, owner 2026-10-13; additive, `rpcversion` unchanged): `cancelCount` is
the position's cancels counted by CAN-2's escalation schedule (it survives every re-creation; `0` at the mint),
`cancelsRequired` the number of distinct current attestor-set members whose co-signatures a cancel of its claim would
need if it confirmed in the next block (`min(q + 1, CANCEL_SIGNERS_MAX)`, `q` = `cancelCount` while inside the quiet
period, else 0; `CANCEL_SIGNERS_MAX` 4 (owner round 2, 2026-10-13), regtest 3), and `cancelQuietUntil` the first height at which the schedule
starts from one again (`lastCancelHeight + CANCEL_QUIET`, 8,064 blocks, regtest 40; *null when the vault was never
cancelled*). **`heldResiduals`** (**optional**, absent when none): `[{txid, vout}]`, the residual intents of cancelled
claims this position holds (CAN-3): `vault_release` of one is refused (`intent-residual-held`) until the position is
CLOSED or CLAIMED, or ACTIVE at or after `cancelQuietUntil`. A VOID vault is
no longer produced (a failing mint is an invalid transaction); `VOID` stays a valid status
filter for a chain indexed before the upgrade. The prototype's `tier`, `rosterIndex`, `errBpsAtClose`, `requiredBurnCents`, `indexHeight` are
gone. Refuses with `vault-not-found`.

**v3.** `noticed` is whether a `Notices` record stands for this vault (NOT-1; always `false` for
a vault that is not ACTIVE — the record is deleted when the vault leaves ACTIVE); `noticeHeight`
is the block the standing notice confirmed in and `emergencyOpenAt` = `notice.refHeight +
EMERGENCY_PERSIST`, the first `refHeight` at which RED-4 clause (b) can open a claim; both
`null` when `noticed` is `false`. `yed_getnotice` gives the whole record.

**Pending spend** (cf. DigiByte v9.26.7 00136af6; additive, `rpcversion` unchanged).
`spendPending` is true while a transaction in this node's mempool spends the vault outpoint (a
redemption, a claim or a release not yet mined; `mempool.mapNextTx`), and **`spendTxid`**
(**optional**, present only then) is its txid. The record above is still the confirmed one: a
pending redemption leaves the vault `ACTIVE` until it confirms. `yed_redeem` and `yed_claim` refuse
`vault-spend-pending` while it is set, and `yed_listpositions` reports `canRedeem` / `canClaim`
false.

Result of `yed_getvault`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "vout": 0,
  "status": "ACTIVE",
  "ownerScheme": 1,
  "ownerHash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "ownerAddress": "yb5u8LCGfU3hYYhhAqvYzR3ZQuNFEUWzx5dmLiGjPW8Gqto3xqqCc",
  "termClass": "A",
  "lockHeight": 377,
  "claimHeight": 401,
  "collateralZat": 251889169000,
  "collateral": 2518.89169,
  "mintedCents": 100000,
  "mintHeight": 332,
  "refHeight": 329,
  "feePaidZat": 503778338,
  "pMint": 1985000,
  "closeHeight": null,
  "closingTxid": "",
  "burnedCents": 0,
  "unbacked": false,
  "cancelCount": 0,
  "cancelsRequired": 1,
  "cancelQuietUntil": null,
  "claimable": false,
  "underwaterAt": 436700,
  "voidReason": "",
  "scriptPubKey": "045945440020755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e5a6d75765187637520755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e51c0677652876375027c01b1752102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ac67765387637520755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755ec1692102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ac675488029401b1686868",
  "noticed": false,
  "noticeHeight": null,
  "emergencyOpenAt": null,
  "spendPending": false
}
```

### `yed_listvaults [status] [count] [skip]`

Arguments: `status` (string, optional; `""` or absent = every status, else one of `ACTIVE`,
`VOID`, `CLOSED`, `CLAIMED`, `CLAIMING`), `count` (number, default `100`), `skip` (number, default `0`).
Paged, in ascending outpoint order; the result is a **list** of `yed_getvault` rows (an empty
list past the end). The prototype's `rosterIndex` argument and its `{height, total, vaults}`
envelope are gone (the `client.cpp` row is now `1,2`).
**Index-wide:** the list is every Yellowback vault the index holds, whoever owns it (a node-context
call, no wallet needed, as a light client or explorer wants it). The wallet's own vaults are
`yed_listpositions`.

Result of `yed_listvaults`:

```json
[
  {
    "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    "vout": 0,
    "status": "ACTIVE",
    "ownerScheme": 1,
    "ownerHash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "ownerAddress": "yb5u8LCGfU3hYYhhAqvYzR3ZQuNFEUWzx5dmLiGjPW8Gqto3xqqCc",
    "termClass": "A",
    "lockHeight": 377,
    "claimHeight": 401,
    "collateralZat": 251889169000,
    "collateral": 2518.89169,
    "mintedCents": 100000,
    "mintHeight": 332,
    "refHeight": 329,
    "feePaidZat": 503778338,
    "pMint": 1985000,
    "closeHeight": null,
    "closingTxid": "",
    "burnedCents": 0,
    "unbacked": false,
    "cancelCount": 0,
    "cancelsRequired": 1,
    "cancelQuietUntil": null,
    "claimable": false,
    "underwaterAt": 436700,
    "voidReason": "",
    "scriptPubKey": "045945440020755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e5a6d75765187637520755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e51c0677652876375027c01b1752102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ac67765387637520755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755ec1692102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ac675488029401b1686868",
    "noticed": false,
    "noticeHeight": null,
    "emergencyOpenAt": null
  }
]
```

### `yed_listtokens <addresses> [minHeight] [count] [skip]`

Arguments: `addresses` (array of strings, 1..100; each a YED address `yb…`/`yt…`/`yr…`, the
transparent P2PKH form `s1…`/`sm…` of the same key hash — the two name one script — or, for a
post-quantum holder, its plain-YEC form `sq…`/`tq…`/`rq…`), `minHeight`
(number, default `0`: only tokens created at or above it), `count` (number, default `1000`) and
`skip` (number, default `0`): a page of the sorted result — a client that needs every token of
a busy address pages until a short page comes back. **Node context**: the `Tokens` records
(§3.6) whose `scriptPubKey` pays one of the addresses, whoever holds the keys — the authoritative
YED UTXO set of an address, which `yed_listunspent` gives only for the node's own wallet. This is
the RPC a light-client server proxies for a wallet it has never seen (lightwalletd plan D-L-7,
`GetAddressTokens`). A full scan of the live token set (spent tokens are erased by IN-1), sorted
by `(height, txid, vout)`; `address` is the YED form, `transparentAddress` the `s…` form (the
`sq…`/`tq…`/`rq…` form for a post-quantum holder; `""` before the SQ task). Refuses
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

### `yed_listclaimable [count] [skip]`

Arguments: `count` (number, default `1000`) and `skip` (number, default `0`), a page over the
listed rows in vault outpoint order (the per-vault estimate stops once the page is full).
**In-term claims (IT-7):** every ACTIVE vault whose claim branch is open — from the block after its
mint, so in term too — each with `claimable` (RED-4 would pass at the tip snapshot) — the source of
the wallet's Claim page and of its threshold warning. A row with `claimable: false` is a vault above
the threshold: `underwaterAt` is the claim price (µUSD) below which it becomes claimable, and its
`claimPath` is `""`, `residualZat` `0`. `lockHeight` tells a claim in term (`tip < lockHeight`) from
one past it. `mintedCents` is the burn a claim must carry (RED-2), `pMint` the vault's stored mint price and
`feeZat` the FEE-1′ protocol fee of the debt at it that the claim pays (RED-3′, rpcversion 8), `pClaim` the tip's claim price (never `null` on a
`claimable` row: an undefined `pClaim` makes RED-4 false; `null` on another row when the tip has no
claim price). Empty list when no vault is open.

**v3.** While armed, "claimable" means RED-4 by clause (a) under the tip's combined `pClaim`
computed with the bundle this node **would build** from its pool for that vault (selector = the
vault outpoint), **or** by clause (b) when a notice has persisted (`emergencyOpenAt ≤ tip −
REF_LAG` and the emergency inequality holds under `pEmerg`). `pClaim` is then that combined
price; `claimPath` says which clause opened it. Rows gain `noticed`, `noticeHeight`,
`emergencyOpenAt` (as `yed_getvault`), `residualZat` (RED-5's amount the claim must return to
the owner; `0` for a clause-(a) claim at the threshold) and `attestFeeZat` (AFEE-1). A vault
that is under `EMERGENCY_RATIO_BPS` but not yet claimable is listed with `claimable: false`; the
wallet offers `yed_claimnotice` for it (`yed_listpositions.canNotice` for its own).
When no bundle can be built (`bundle-insufficient` would be raised) the list is computed from
the cross-section alone and every row carries `claimPath: ""` — the wallet must expect
`yed_claim` to refuse until the pool refills.

**The per-vault cancel limit** (docs/plans/yellowback-cancel-limit-design.md, CAN-2; additive, `rpcversion`
unchanged): each row also carries `cancelCount`, `cancelsRequired` and `cancelQuietUntil`, exactly as `yed_getvault`
reports them, so a claimant sees before it claims how many distinct current attestor-set members a cancel of its claim
would need if it confirmed in the next block, and when the vault's schedule starts from one again (`null` when the
vault was never cancelled). `heldResiduals` is the owner's and stays on `yed_getvault`.

Result of `yed_listclaimable`:

```json
[
  {
    "vault": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8:0",
    "ownerAddress": "yb5u8LCGfU3hYYhhAqvYzR3ZQuNFEUWzx5dmLiGjPW8Gqto3xqqCc",
    "collateralZat": 251889169000,
    "mintedCents": 100000,
    "pMint": 1985000,
    "feeZat": 503778338,
    "claimHeight": 401,
    "lockHeight": 377,
    "claimable": true,
    "underwaterAt": 436700,
    "pClaim": 400000,
    "claimPath": "a",
    "cancelCount": 0,
    "cancelsRequired": 1,
    "cancelQuietUntil": null,
    "noticed": false,
    "noticeHeight": null,
    "emergencyOpenAt": null,
    "residualZat": 0,
    "attestFeeZat": 125944584
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
contributing attestations `C` (ascending; empty when none), `attestFeeZat` (under ARMED always
the AFEE-1 amount, even while no bundle can be built, so a wallet's `minOutZat` floor never
under-states it) and `attestPayee` (the `bondKeyAddress` paid, `null` under AFEE-0), `residualZat` (RED-5's amount, `0` when none was
due), `claimPath` (`"a"`, `"b"` or `""`), `notice` (`true` when this transaction wrote a
`Notices` record — a CLAIM_NOTICE that NOT-1 accepted), `carrierVin` (the input index of the
carrier, `-1` when none) and `bundleSource` (`"scriptsig"`, `"opreturn"` or `""`). `type` gains
`"notice"`, `"register"`, `"equivocation"`, `"revive"`; for `"register"` `seq` (**optional**)
is the assigned sequence number. **P4-b:** `"register"` is a `SET_JOIN` to the attestor set,
`"set_act"` (with `seq`) a heartbeat, removal or set equivocation of an attestor; `"revive"` is
no longer written (`ATTESTOR_REVIVE` is invalid).

**Vault upgrade** (`rpcversion` 5): `reopenedVaults` lists the vaults an attestor-set cancel
re-created as `ACTIVE` (U-24; the cancel's output 0, empty otherwise); `type` gains
`"claim_release"` (the claimant or residual intent released after `CLAIM_DELAY`) and
`"claim_cancel"`; a `"claim_cancel"` row's `assigned` is CAN-1's refund (`[{vout, cents}]`, the
claim's whole burn re-issued to the holder it came from, audit 03/H-1) and its `yedOut` that amount.
**Accounting of a `"claim_cancel"` row:** `yedOut` is re-issued, not carried from the inputs, so the
usual `yedIn = yedOut + burned` does **not** hold: `burned = yedIn` (any YED the canceller spent is
burned) and `yedOut` is the refund (supply moves by `yedOut − burned`). Index and client code that
reconciles supply from TxLog rows must special-case this type, as it does `"mint"`.
A failing transaction has no `TxLog` row: it is invalid, never confirmed.

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
  "feeZat": 629722922,
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
  "reopenedVaults": [],
  "expired": false,
  "xMint": 1990000,
  "xClaim": 2000000,
  "aMint": 1985000,
  "aClaim": 1995000,
  "pMint": 1985000,
  "pClaim": 2000000,
  "bundleSeqs": [ 1, 2 ],
  "attestFeeZat": 125944584,
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
**version-3** payload (v3 §3.3) — a MINT at **version 4** (rpcversion 7, quantum spec §3.1, C-1) — without touching state; allowed while unhealthy. `valid` is false
— with `type: "none"` and `reason` naming the defect — for anything §3.3 calls malformed or
unknown, **including a version-1 or version-2 payload** (`reason: "version"`, V23).
Type-specific fields: MINT `termClass`, `cents`, `lockHeight`, `refHeight`, `ownerScheme`, `ownerHash` (rpcversion 7),
`feeVout` (`255` = none), `attestFeeVout` (**v3**, `255` = none); TRANSFER `assignments:
[{vout, cents}]`, `assignedCents`; REDEEM `refHeight`, `feeVout`, `attestFeeVout`,
`assignments`, `assignedCents`; **v3** `register` (`0x05`) `attestorPubKey`, `bondPubKey`,
`bondAddress`, `bondKeyAddress`, `bondLocktime`, `flags {tier, pool}`; `notice` (`0x06`) `vault {txid, vout}`,
`refHeight`; `equivocation` (`0x07`) nothing; `revive` (`0x08`) `attestation {seq,
priceMicroUsd, citedHeight, sig, hex}`; `cancelcosign` (`0x09`, the cancel-limit design's CANCEL_COSIGN marker; its
co-signatures ride the carrier) `cancelCosign` (an empty object). Fields of the other types are absent (**optional** — the
checker decodes a MINT payload, the example). When `hex` is a **raw transaction** that has a
carrier-shaped input (v3 §3.4), `bundle` (**optional**) is the decoded bundle — `{vin, hash,
version, count, attestations: [{seq, priceMicroUsd, citedHeight, sig, hex}]}` — decoded only,
never verified (`yed_validaterawtransaction` verifies).

Result of `yed_decodepayload`:

```json
{
  "valid": true,
  "version": 4,
  "type": "mint",
  "reason": "",
  "termClass": "A",
  "cents": 100000,
  "lockHeight": 377,
  "refHeight": 329,
  "ownerScheme": 1,
  "ownerHash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "feeVout": 3,
  "attestFeeVout": 4
}
```

### `yed_validaterawtransaction <hex>`

Arguments: `hex` (string; a complete, normally signed transaction). Dry run of §3.8 at the tip
(`EvaluateBlock` over a one-transaction pseudo-block at `tip + 1`, exactly `MempoolCheck`'s
predicate) plus `VerifyAllInputs` for the scripts (`valid`): every input verified as the mempool would at `tip + 1` — `STANDARD_SCRIPT_VERIFY_FLAGS` plus the UPGRADE_VAULT flags (CSV, the set opcodes) once active, `OP_CHECKSETSIG`/`OP_CHECKSETDORMANT` against the set state at the tip, and the BIP68 sequence locks (an intent RELEASE whose input has not aged is `valid: false`, `invalidReason` `non-BIP68-final`). **Optional:** `invalidReason` (string) is present only when `valid` is false: `input <n> fails script verification: <script error>`, `input <n> is unknown or spent`, `non-BIP68-final` or `bad-txns-vault-timelock`. For a vault spend `blockValid` is
RED-1..5 (the rule a block carrying it must pass) and `wouldBeRejected` says whether the mempool
refuses it — `!blockValid`, or the MP-1 expiry bound (`mempoolExpiryOk` false:
`nExpiryHeight == 0` or `> refHeight + REF_WINDOW`). `unconfirmedInputs` lists inputs the index does not know (unconfirmed parents; the
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
  "feeZat": 629722922,
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
stored block and explains a rejection: `blockInvalid` is whether a transaction in it is invalid
under the Yellowback rules (the block is then refused, DoS 100, `bad-yellowback-<verdict>`),
`verdict` the first invalid transaction's verdict (`"ok"` when none), `reason`
`"<verdict>:<txid>"` of it or `""`; evaluation stops at that transaction. `enforcementOn` (ACT-5)
is gone: the rules hold at every height where the upgrade is active. `transactions` lists every Yellowback-relevant
transaction in block order with its verdict; `closedVaults` as `yed_gettxinfo`. Allowed while
unhealthy. **Precondition (N12):** refuses with `verdict-parent-not-tip` unless the block's
parent is the index tip (a candidate child, or a block the node refused on top of it) — the state
at any other parent would need an undo replay.

Result of `yed_getblockverdict`:

```json
{
  "blockInvalid": true,
  "reason": "vault-spend-short-burn:6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "verdict": "vault-spend-short-burn",
  "transactions": [
    {
      "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
      "type": "redeem",
      "path": "owner",
      "verdict": "vault-spend-short-burn",
      "yedIn": 50000,
      "yedOut": 0,
      "feeZat": 629722922,
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
was given — then `requiredZat` and `requiredZatFloored` are `null` too), `requiredZat` rounded up
to 1,000 zat, `requiredZatFloored`, `lockHeight = R + lockBlocks`, `claimHeight = lockHeight + GRACE`,
`refHeight = R`. `requiredZat` is MINT-5's ratio clause, rounded up to 1,000 zat; `requiredZatFloored`
equals it since rpcversion 8 (MINT-5′ dropped the `4 · FEE_MIN` clause, D-Q-23) and is what a mint locks
(what `yed_mint` puts in `vout[0]`). `protocolFeeCents` / `protocolFeeZat` are the mint's FEE-1′ fee of
`cents` at the estimate's `pMint` (the price the vault stores, which every later fee of it is struck at;
`null` with `pMint`). `priceMicroUsd` must lie in `[PRICE_MIN, PRICE_MAX]`. Refuses with
`mint-bad-lock` (`lockBlocks` outside every class, or `lockHeight + GRACE ≥ LOCKTIME_THRESHOLD`)
and `mint-unsatisfiable` (`requiredZat > MAX_MONEY`, K14). It never refuses for MINTPOL-1: a halted
gate still estimates, so the Mint page can show the figure next to the halt reason, and
`mintBlocked` / `mintBlockedReason` (cf. DigiByte v9.26.7 `estimatecollateral`'s
`minting_restricted`, e18654a3; additive) say whether `yed_mint` would refuse at this `R` and with
which identifier: `mintpol-not-active`, `mintpol-no-price`, `mintpol-global-ratio` (for this term
class: a class whose base ratio reaches `RECAP_RATIO_BPS` is not blocked by it), `mintpol-divergence`,
`mintpol-unarmed` or `mintpol-cap` (counting the MINT payloads in this node's mempool, audit C-3),
`""` when `mintBlocked` is false. It is the same function `yed_mint`'s gate runs, judged on the
snapshot at `R` even when a `priceMicroUsd` override priced the figure; the bundle refusals below
stay refusals.

**v3.** While `Snapshots[R]` is armed the estimate uses the **combined** `pMint = min(xMint,
aMint)` of PRICE-2 with the bundle this node would build from its pool for a MINT at `R` (empty
selector, W9): `xMint` and `aMint` are both reported, `source` says which bound (`"x"` or
`"a"`; `""` when not armed or a `priceMicroUsd` override was given), `armed` is the snapshot's
arming state, `bundleSeqs` the `seq`s the estimate used (empty when not armed), `attestFeeZat`
the AFEE-1′ fee that mint would pay on top of `protocolFeeZat` (half of it; `0` when not armed), and `divergenceBps` = `|pFast − aMint| ·
10⁴ / min(xMint, aMint)` (`null` when either is undefined). Refuses with `bundle-insufficient`
when armed and fewer than `M_SELECT` of the selected attestors have a fresh attestation in the
pool (the message names the missing `seq`s), and with `mint10-diverged` when `divergenceBps >
DIVERGE_BPS_ATTEST` — the two refusals `yed_mint` would give, surfaced before the user commits.
A `priceMicroUsd` override bypasses both sources and both refusals, as in v2.

Result of `yed_estimatecollateral`:

```json
{
  "requiredZat": 251889169000,
  "requiredZatFloored": 251889169000,
  "protocolFeeCents": 1000,
  "protocolFeeZat": 503778338,
  "termClass": "A",
  "lockHeight": 377,
  "claimHeight": 401,
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
  "attestFeeZat": 125944584,
  "divergenceBps": 25,
  "mintBlocked": false,
  "mintBlockedReason": ""
}
```

The document's sample vault was minted when class A's base ratio was 500 %; under D-IT-4 class A is 300 %
(`baseRatioBps` 30000), B 400 % and C 500 %, so a class-A mint of $1,000 at this price needs 151,133,501,260 zat today.
The sample is kept because the claim and redeem examples below are built on it.

### `yed_listattestors [height]` (v3)

Arguments: `height` (number, optional; default the index tip; `seated`/`pinned`/`weight` are
evaluated at that height's snapshot, the records are always the current table). Every
`Attestors` record (v3 §3.6), ascending `seq`; since P4-b each mirrors one `SET_JOIN` to the attestor
set (`attestorPubKey` = `bondPubKey` = the member key; `lastAct` the set's lastAct for it, i.e. the
join height + maturity or its last `SET_HEARTBEAT`; `bondFrozen` whether the set froze its bond).
`bondOutpoint` is `txid:bondVout` of the join (vout 0 from `set_join` and `yed_registerattestor`);
`bondAddress` the P2SH address of `BondScript(bondPubKey, bondLocktime)` (the bond output itself);
`bondKeyAddress` the P2PKH address of `bondPubKey` (where attestation fees are paid);
`bondLocktime` the CLTV height; `flags` the decoded registration flags; `status` one of the five
attestor statuses and `statusHeight` the height it was last set; `bondSpentHeight` `null` until
the bond outpoint is spent (IN-2); `seatedSince` the height the attestor entered `seated[]`,
`null` while unseated; `weight` the bond weight at `height` as a decimal string (`"0"` before
its `ageOrigin`); `seated` and `pinned` membership in `Snapshots[height].seated[]` /
`pinnedSeqs[]`; `lastBundleHeight` the newest `BundleLog` row whose `seqs[]` holds this `seq`
(`null` when none); `poolFresh` whether this node's pool holds an attestation of this `seq` that
a bundle for `R = height − REF_LAG` could cite (`R − ATTEST_MAX_AGE < citedHeight ≤ R`, as
`yed_getinfo`). `founding` is whether the record's age runs from `triggerHeight` (v3 §3.7
founding cohort; `false` while UNARMED). `seatWeight` (owner 2026-10-11) is the seat-ranking weight at `height` as a decimal
string, `bondZat × SeatAgeFactorQ16(height − ageOrigin)` (Q16: divide by 65,536 for zat; without the seated ×1.05 hysteresis);
`evicted` whether the record was evicted from the full set by a larger bond (status `WITHDRAWN`, bond not frozen). Empty list
before the first registration.

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
    "lastAct": 281,
    "bondFrozen": false,
    "founding": true,
    "weight": "31000000000",
    "seatWeight": "65801000000000",
    "evicted": false,
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

### `yed_estimatefee <mintedCents> [priceMicroUsd]`

Arguments: `mintedCents` (number), `priceMicroUsd` (number, optional; `[PRICE_MIN, PRICE_MAX]`). rpcversion 8
(a signature change: it was `<collateralZat>` → `{feeZat}`): FEE-1′, the protocol fee of a debt of
`mintedCents` — `feeCents` by `params.fees.protocol.bands` with the floor, `feeZat = ceil(feeCents · 10⁴ ·
COIN / pMint)` at `pMint` = `priceMicroUsd` when given, else the cross-section `xMint` at `R = tip −
REF_LAG` (a mint's price; a redeem converts at the vault's own `pMint`, `yed_getvault`), `attestFeeZat` =
AFEE-1′'s half of `feeZat`. `pMint`, `feeZat` and `attestFeeZat` are `null` when no price is defined.

Result of `yed_estimatefee`:

```json
{
  "feeCents": 1000,
  "feeZat": 503778338,
  "pMint": 1985000,
  "attestFeeZat": 125944584
}
```

### `yed_gethistory <from> <to>`

Arguments: `from`, `to` (numbers; `startHeight ≤ from ≤ to ≤ tip`, at most 2,016 rows per call,
else `RPC_INVALID_PARAMETER`). The `Snapshots` records (§3.6) for `from ≤ h ≤ to`, ascending,
`haltMask` decoded to names, undefined prices and ratio `null` (`signalCount` and `activation`
left with ACT-1..7, upgrade plan §6).
`tagged` is whether the block carried a valid tag, `quote` whether that tag carried a quote
(`priceMicroUsd ≠ 0`). `openDebtCents` is `Snapshots[h].openDebtCents` (SCHEMA_VERSION 15), the
denominator of that row's `globalRatioBps`; `globalRatioDenominator` is always `"openDebt"` (see
`yed_getstats`). `yellowback_model.py` compares every field of every row.

Result of `yed_gethistory`:

```json
[
  {
    "height": 331,
    "blockHash": "0f3a9c1e5b7d2a4c6e8f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f",
    "tagged": true,
    "quote": true,
    "pFast": 2000000,
    "pMid": 2000000,
    "pSlow": 1990000,
    "pMint": 1990000,
    "pClaim": 2000000,
    "sigmaMultBps": 10000,
    "issuedZat": 1656250000000,
    "supplyCents": 250000,
    "collateralZat": 62500000000,
    "openDebtCents": 250000,
    "globalRatioBps": 49750,
    "globalRatioDenominator": "openDebt",
    "haltMask": []
  }
]
```

### `getblocktemplate` (stock command; the `yellowback` object)

On a node where Yellowback is live (the vault upgrade configured with a YED attestor set, U-22)
— and only then; otherwise the response is v4.5.0's key for key (N10, `yellowback_stockparity.py`) — `getblocktemplate` returns `coinbasetxn` with the tag in its
scriptSig, `coinbaseaux.flags` = the tag push in hex (it begins with the `0x24` push opcode; a
pool that assembles its own coinbase appends these bytes verbatim after the BIP34 height push,
§5), `"coinbase/append"` in `mutable`, and `TemplateInfo()`:

```
"yellowback": { "tag": "<hex>", "kind": "quote"|"none", "priceMicroUsd": n,
                "quoteAgeSeconds": n, "payoutAddress": "s1…",
                "registered": bool, "eligible": bool, "healthy": bool }
```

The command refuses outright while the index is unhealthy (K24; `-yellowbackrequirehealthy` is
retired and this is always on — an unhealthy node cannot tell a valid template from an invalid
one). The template carries only transactions valid under the Yellowback rules (TPL-1). Regtest `generate` goes
through the same `CreateNewBlock`, so a regtest node with a payout address and a quote mines
tagged blocks with no further code (V25).

---

## Wallet context (`src/rpc/yellowbackwallet.cpp`)

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

### `yed_getnewaddress [type]`

Arguments: `type` (string, optional; rpcversion 7; `null` or `""` = the default below), then
`label` (string, optional; see below — the heading keeps `[type]` because the workspace's quantum
contract delta §4.10 pins this command's argument list, so the generated contract's `args` names
`type` alone until that delta is updated): `"p2pkh"` a fresh keypool key (35 characters),
`"pq"` a fresh post-quantum holder key (FN-DSA-512 once Falcon is active, SLH-DSA-SHA2-128s before),
`"pqowner"` a fresh SLH-DSA key, as `vault_getnewowner` (53 characters each); PQ keys derive from the HD
seed (the wallet must be unlocked); a `"pq"` holder key goes into the address book under its plain-YEC
`sq…`/`tq…`/`rq…` form (keys issued by a build before the SQ follow-ups are not added retroactively), a
`"pqowner"` key stays out of it; the default
follows the holder policy (quantum plan D-Q-2, A-13): `"p2pkh"` while `params.pq.falconActive` is
false, `"pq"` once it is true. `label` (string, optional, default `""`; cf. DigiByte v9.26.7
5539554c): stored with the address in the wallet's address book, so it travels with `wallet.dat`
(`yed_listaddresses` reports it); refused (`RPC_INVALID_PARAMETER`) with `"pqowner"`, whose key
stays out of the address book. The address-book purpose of a key this command issues is
`yellowback-receive` (was `receive`), which is how `yed_listaddresses includeEmpty` finds the unused
ones. A Yellowback address string (`yb…` mainnet, `yt…` testnet, `yr…` regtest). The result is a
bare string.

**ycashd 6.20.0:** the transparent keypool is gone (keys are HD, drawn by `GenerateNewKey` as
stock `getnewaddress` does), so this command — and every builder that draws a fresh owner, token,
collateral or change key (`yed_mint`, `yed_send`, `yed_sendmany`, `yed_redeem`, `yed_claim`,
`yed_sweep`, `yed_registerattestor`, `yed_withdrawbond`) — **requires an unlocked wallet** and
refuses a locked one with `wallet-locked` (the stock `EnsureWalletIsUnlocked` text may precede it,
`RPC_WALLET_UNLOCK_NEEDED`). `keypool-empty` can no longer be raised by a fresh-key draw on
6.20.0; it survives only on the `CReserveKey` change paths. On v4.5.0 the command draws from the
keypool and works on a locked wallet. The contract JSON is unchanged (audit B-6).

Result of `yed_getnewaddress`:

```json
"yrExampleOwnerAddress111111111111111"
```

### `yed_validateaddress <address>`

Arguments: `address` (string). `isvalid` false — and the other fields absent (**optional**) —
with `not-a-yellowback-address` in `reason` when the string is not a `yb…`/`yt…`/`yr…` address of
this network (the command itself does not throw, so the wallet can validate as the user types;
`yed_send` throws the same identifier). `transparentAddress` is the same key hash as an `s1…`/
`sm…` address. rpcversion 7: `type` is `p2pkh` or `pq`; for a post-quantum (53-character)
address `keyid` is the 66-hex `scheme ‖ keyHash`, `transparentAddress` is the plain-YEC PQ address
of the same key (`sq…`/`tq…`/`rq…`, D-Q-20) and `pqscheme`
(**optional**, present only for `pq`) is the scheme.

Result of `yed_validateaddress`:

```json
{
  "isvalid": true,
  "address": "yrExampleOwnerAddress111111111111111",
  "type": "p2pkh",
  "keyid": "1f2e3d4c5b6a79880706050403020100f1e2d3c4",
  "ismine": true,
  "transparentAddress": "smExampleTransparentTwin111111111111",
  "reason": ""
}
```

### `yed_getbalance`

Arguments: none. `confirmedCents` from the index's `Tokens` that are mine, `unconfirmedCents`
the mempool's payload assignments to this wallet (a dry run per transaction), `height` the index
tip the confirmed figure was read at. `spendableCents` (cf. DigiByte v9.26.7 75d82a6e) is
`confirmedCents` less the tokens this wallet's own unconfirmed transactions already spend (the
`spentUnconfirmed` rows of `yed_listunspent`): what `yed_send`, `yed_redeem` and `yed_claim` can
select now. After sending $40 from a $100 token the figures are `confirmedCents` 10000,
`spendableCents` 0 and `unconfirmedCents` 6000 (the change) until the send confirms; gate a send or
a redeem on `spendableCents`, not `confirmedCents`.

Result of `yed_getbalance`:

```json
{
  "confirmedCents": 100000,
  "spendableCents": 100000,
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

### `yed_mint <cents> <lockBlocks> [from] [bundleHex] [wait] [maxCollateralZat]`

Arguments: `cents` (number, `MIN_MINT ≤ cents ≤ MAX_MINT`), `lockBlocks` (number; the class
follows from it, V19), `from` (string, optional; a `ys1…` Sapling address to fund the collateral
from that address's confirmed notes, largest-first — blocks for the proving time; default, or
`""`: transparent YEC via `AvailableCoins`), **v3** `bundleHex` (string, optional; `""` or absent
= build from the pool; else a `yed_buildbundle`-shaped bundle used verbatim, the manual path),
**v3** `wait` (boolean, optional, default `true`; see *v3 two-step commands*), `maxCollateralZat`
(number, optional, default `0` = no bound: the caller's ceiling on `collateralZat`, the figure it
confirmed from `yed_estimatecollateral`; the node refuses `collateral-above-max` at preflight,
before the carrier, and again when the MINT is built on the confirmed carrier — then the carrier
lapses and `yed_sweepcarriers` reclaims it — so a block or a price move between the estimate and
the call never locks more than was agreed). Builds the §3.5
MINT at `R = tip − REF_LAG` after the MINTPOL-1 gate (`Snapshots[R].activation == ACTIVE`,
`haltMask == 0`, the cap has room — or, under a `GLOBAL_RATIO` halt or above the cap, the class
is at or over `RECAP_RATIO_BPS`; W16, W20), draws one fresh key for the vault owner and the token output,
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
unchanged: `mintpol-not-active`, `mintpol-no-price`,
`mintpol-global-ratio`, `mintpol-divergence`, `mintpol-cap`, `mint-unsatisfiable`; hardening:
`mintpol-unarmed` (H-1, `mintRequiresArmed` and `R` not ARMED);
`mint-bad-lock`, `RPC_INVALID_PARAMETER` for `cents` out of range, `RPC_WALLET_ERROR` for
insufficient YEC (the carrier's `CARRIER_VALUE` plus two network fees are part of the need) or a
locked wallet; `collateral-above-max` (`RPC_WALLET_ERROR`) when `maxCollateralZat` is set and
too small; `carrier-wait-busy` when `wait = true` and half of `-rpcthreads` such calls are
already waiting (before any transaction).

**`wait = false` and restarts.** The pending completion lives in memory only. If the node restarts
before the carrier confirms, nobody builds the MINT: the carrier (`CARRIER_VALUE` plus its fee)
stays outstanding in `carriers.dat` until its window (`REF_WINDOW` blocks past `refHeight`)
lapses and `yed_sweepcarriers` — also run at startup — reclaims it. Call `yed_mint` again after
the restart; no YED was issued and no collateral was locked.

Result of `yed_mint`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "vault": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8:0",
  "ownerAddress": "yb5u8LCGfU3hYYhhAqvYzR3ZQuNFEUWzx5dmLiGjPW8Gqto3xqqCc",
  "termClass": "A",
  "lockHeight": 377,
  "claimHeight": 401,
  "collateralZat": 251889169000,
  "feeZat": 629722922,
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
  "attestFeeZat": 125944584,
  "attestPayee": "smExampleBondAddress11111111111111111"
}
```

### `yed_send <yedaddress> <cents>`

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
workable amounts below and above, H2), `too-many-inputs`, `insufficient-yec`, `too-many-coins`,
`RPC_INVALID_PARAMETER` for an amount outside `[MIN_OUTPUT, MAX_OUTPUT]`. **YED cannot pay the
network fee** (cf. DigiByte v9.26.7 65744b63): it is paid in YEC from the wallet's confirmed
transparent coins, so a wallet holding YED and no YEC is refused `insufficient-yec`;
`yed_estimatesend.networkFeeZat` quotes it.

Result of `yed_send`:

```json
{
  "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
  "changeCents": 50000,
  "expiryHeight": 371
}
```

### `yed_sendmany <{yedaddress: cents, …}>`

Arguments: one object of at most 14 recipients, `{"yedaddress": cents, …}`. As `yed_send`, with
the same selector, locking and refusals; returns the same shape.

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
`networkFeeZat` (cf. DigiByte v9.26.7 65744b63; additive) is the YEC network fee the send pays —
YED cannot pay it — priced as `yed_send` prices it on the selected YED inputs (the Yellowback
size-priced fee, `params.fees.network`); a post-quantum YEC coin chosen to fund it can raise it by
its size. *null when* `workable` is false (there are no inputs to price). A wallet shows it in the
send confirmation.

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
  "networkFeeZat": 12500000,
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

- On an **ACTIVE** vault at any height after its mint (IT-1: the V template's `ownerHeight` is
  `refHeight + 1`): the §3.5 owner-path REDEEM (the V template's
  owner path, selector 2: scriptSig `<sig> OP_2`, `nLockTime ≥ ownerHeight`, U-23) — burns
  `mintedCents` of the wallet's YED, pays the FEE-1 fee to `payee(R, vaultOutpoint)`, sends the
  rest of the collateral to `to`. **Before `lockHeight`** (the redeem confirming at `tip + 1 <
  lockHeight`) the fee output also carries the early-redeem fee, `earlyRedeemFeeBps[class]` of the
  debt at the vault's mint price `pMint` (IT-9′: 5 % class A, 2.5 % B, 1 % C; `bad-redeem-early-fee` when a transaction does not
  carry it); `earlyRedeemFeeZat` is that part of `feeZat` (`0` at or past `lockHeight` and under
  FEE-0). A wallet quotes it with `yed_estimateredeem` before the owner confirms. Runs `MempoolCheck` first and refuses (`mempool-check-failed:
  <verdict>`) rather than commit anything MP-1 would refuse (K7); on success `CommitTransaction`
  puts it in the node's own mempool.
- On a **VOID** vault at or past its owner height (`lockHeight` for every VOID vault, L14): the §3.5 VOID RELEASE — owner path, no
  burn, no fee, no payload. Returns `burnedCents: 0`, `feeZat: 0`, `payee: null`. The GUI calls
  this **Release**. Since the vault upgrade no VOID vault is produced (a failing mint is invalid),
  so this branch only serves a chain indexed before it.

`collateralOut` is the zat paid to `to`. `extraBurnCents` (H4) is a sub-dollar YED remainder the
selector burned rather than refuse: it is `0` whenever a selection with change of `0` or
`≥ MIN_OUTPUT` exists (those are always preferred) and otherwise lies in `[1, MIN_OUTPUT − 1]`,
i.e. at most $0.99. `burnedCents` stays the vault's debt; `extraBurnCents` is burned on top of it.
Refusals: `vault-not-found`, `vault-not-owned`,
`vault-not-active` (CLOSED or CLAIMED only), `vault-locked` (tip below the vault's `ownerHeight`:
in practice a VOID vault before `lockHeight`, or a vault minted before the in-term rule), `insufficient-yed`, `change-floor`, `mempool-check-failed:<verdict>`,
`vault-spend-pending` (a spend of the vault is already in the mempool — `yed_getvault.spendTxid`;
checked before any coin is selected, so a second click is not answered with `insufficient-yed`; cf.
DigiByte v9.26.7 00136af6), `RPC_WALLET_ERROR` for a locked wallet.

Result of `yed_redeem`:

```json
{
  "txid": "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
  "burnedCents": 100000,
  "feeZat": 3022670026,
  "earlyRedeemFeeZat": 2518891688,
  "payee": "smQvTmAz2ExamplePayoutAddress1111111",
  "collateralOut": 248866488974,
  "to": "smExampleTransparentTwin111111111111",
  "extraBurnCents": 0
}
```

### `yed_estimateredeem <vaultTxid>`

Arguments: `vaultTxid` (string; the vault is its output 0). **In-term claims (IT-9).** The quote of
`yed_redeem` for a vault, which a wallet shows before the owner confirms: what a redeem
confirming in the next block (`height` = tip + 1) burns and pays. `early` is `height < lockHeight`
on an ACTIVE vault; `earlyRedeemFeeZat` is then `earlyRedeemFeeBps[class]` (`earlyRedeemFeeBps`) of
the **debt** at the vault's `pMint` (rpcversion 8, IT-9′; `earlyRedeemFeeCents` is the same in cents),
`protocolFeeCents` / `protocolFeeZat` the FEE-1′ fee of the debt at `pMint` and `feeZat` the whole fee
output, the protocol fee plus the early fee, exactly `yed_redeem`'s `feeZat`
(all `0` under FEE-0; `payee` is *null when* no pool is eligible or the vault is not ACTIVE; a VOID
release pays nothing and burns nothing). Signs
nothing, locks nothing, commits nothing. It refuses only `vault-not-found`; for every other reason
`yed_redeem` would refuse now, `canRedeem` is `false` and `error` carries that identifier
(`vault-not-active`, `vault-not-owned`, `vault-locked`, `vault-spend-pending`, `insufficient-yed`;
`""` otherwise). `insufficient-yed` is judged on the **spendable** YED (`yed_getbalance.spendableCents`:
tokens an own unconfirmed transaction already spends do not count), as the selector judges it. The
network fee and any H4 sub-dollar remainder are not part of the quote (`yed_redeem` reports them).

Result of `yed_estimateredeem`:

```json
{
  "vault": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8:0",
  "status": "ACTIVE",
  "termClass": "A",
  "lockHeight": 377,
  "height": 360,
  "early": true,
  "burnedCents": 100000,
  "collateralZat": 251889169000,
  "pMint": 1985000,
  "protocolFeeCents": 1000,
  "protocolFeeZat": 503778338,
  "feeZat": 3022670026,
  "earlyRedeemFeeBps": 500,
  "earlyRedeemFeeCents": 5000,
  "earlyRedeemFeeZat": 2518891688,
  "payee": "smQvTmAz2ExamplePayoutAddress1111111",
  "canRedeem": true,
  "error": ""
}
```

### `yed_claim <vaultTxid> [to] [bundleHex] [wait] [minOutZat] [maxBurnCents]`

Arguments as `yed_redeem`, plus **v3** `bundleHex` and `wait` as `yed_mint` (`to` may be `""`
for the default), and `minOutZat` (number, optional, default `0` = no bound: the claimant's floor
on what reaches `to`; refused `claim-out-below-min` at preflight — the collateral less the
RED-5 residual, the claimant intent's value (U-23: the fees come from the claimant's YEC) — and again at build against the exact
`collateralOut`, nothing signed either time), and `maxBurnCents` (number, optional, default `0` =
no bound, hardening H-9.3: the claimant's cap on the YED the claim burns; refused
`claim-burn-above-max` at preflight when the vault's `mintedCents` exceeds it and again at build
against the exact burn — the debt plus any H4 sub-dollar remainder — nothing signed either time).
The §3.5 CLAIM of somebody else's underwater vault (a `claimable` row of `yed_listclaimable`; in
term as well as past it, IT-2):
the V template's claim path (selector 4: scriptSig `OP_4`, U-23), `nLockTime = claimHeight`,
burns `mintedCents` of the claimant's own YED and moves the collateral into a **claimant intent**
(the primitive's I template, output 0, paying `to`, delay `CLAIM_DELAY`) of the
collateral less the RED-5 residual; the fees are paid from YEC the wallet selects (a claim
input carries no collateral to pay them from: `yed_claim` funds them), with its own change. `to`
must be transparent (an intent pays a key; `bad-address` otherwise). The vault becomes
`CLAIMING`; after `CLAIM_DELAY` blocks the primitive's **`vault_release <intentTxid> 0`** pays the
intent to `to` and the vault becomes `CLAIMED`. Until then any `cancelThreshold` members of the
YED attestor set may cancel it (`yed_buildcancel` + `set_signcancel` + `vault_send`), which
re-creates the vault as `ACTIVE` at the cancel's output 0 and refunds the burn to the YED holder it
came from (CAN-1, audit 03/H-1; U-24 revised): a cancel returns the claimant's YED, not its YEC fees.
**Refund holder (CAN-1).** If the attestor set cancels the claim, the whole burn is refunded to the holder of
the claim's lowest-index YED input; `yed_claim` therefore orders its YED inputs so that the first is one of the
wallet's plain holder scripts (P2PKH, or TX_PQPKH from the Falcon height) whenever it has one. An external builder
should do the same: a channel, HTLC or swap-script token as the first YED input would receive the refund under
that script's spending conditions.
`collateralOut` is the claimant intent's value. The v2 fields of `yed_redeem` (including
`extraBurnCents`, H4, and `earlyRedeemFeeZat`, always `0` on a claim) plus the **v3** fields below. Refusals: `vault-not-found`,
`vault-not-active`, `claim-not-yet` (tip below the vault's `appHeight`: only a vault minted before
the in-term rule, in term), `claim-not-underwater` (RED-4
would fail at the reference snapshot by both clauses), `insufficient-yed`, `change-floor`,
`mempool-check-failed:<verdict>`, `vault-spend-pending` (before the carrier step: a spend of the
vault is already in the mempool), **v3** `bundle-insufficient`, `bundle-malformed`,
`claim-out-below-min`, `claim-burn-above-max`, `carrier-wait-busy`, `carrier-record-failed`.

**v3.** The carrier step first (selector = the vault outpoint), then the CLAIM with the carrier
input (never `vin[0]`), the attestor fee output when armed and `A ≠ ∅`, and — when
`residualZat ≥ RESIDUAL_MIN_ZAT` — the **residual intent** (an I template paying
the owner's `TX_PQPKH` (`20 <ownerHash> 51|52 c2`, quantum spec F-3) at least `residualZat`, RED-5; anyone may `vault_release` it to the owner
after `CLAIM_DELAY`, and a cancel never touches it). The wallet dry-runs RED-1..5
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
  "feeZat": 629722922,
  "earlyRedeemFeeZat": 0,
  "payee": "smQvTmAz2ExamplePayoutAddress1111111",
  "collateralOut": 251889169000,
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
  "attestFeeZat": 125944584,
  "attestPayee": "smExampleBondAddress11111111111111111",
  "residualZat": 0
}
```

### `yed_buildcancel <intentOutpoint> [cosigs]`

Arguments: `intentOutpoint` (string, `"txid:n"`): a YED **claimant** intent (a `CLAIMING` vault's
`intents[]` row with `role` `"claimant"`), confirmed or still in the mempool (a mempool claim only once
every one of its inputs is confirmed and the index is at the chain tip: the index sees confirmed tokens
only, and the holder must be exactly the one consensus will record; refused otherwise, `RPC_MISC_ERROR`). The attestor set's
CANCEL of that intent before it matures (U-23, I-2), with **CAN-1's refund** (audit 03/H-1): the
primitive's `vault_buildcancel` transaction — the claimed vault's V re-created at output 0 with the
intent's value — plus, at output 1, a token carrier (`TOKEN_VALUE`) paying `refundHolder`, the
scriptPubKey the claim's burned YED came from (the token at the claim's lowest-index YED input),
then this wallet's fee inputs and change; unsigned. Collect the attestor set's signature with
`set_signcancel` (one member: the module pins `cancelThreshold` 1, 03/I-3), then `vault_send`.
When it confirms the vault is `ACTIVE` again at the cancel's output 0 and the claim's whole burn
(`burnedCents`, any over-burn included) is a YED token at output 1 of the holder of the claim's
**lowest-index YED input** -- one holder gets the whole burn, whoever held the other inputs -- and
`supplyCents` is credited. The refund token may exceed `MAX_OUTPUT` (it is re-issued, not assigned by a
payload; XFER-1 applies when it is next spent, so split it with a TRANSFER). A cancel returns the
claimant's YED; it does not return the claim's YEC costs (the protocol fee -- half of it to an attestor
when one is paid -- and the network fees), which a claimant loses per cancelled round. A cancel
without the refund is invalid (`intent-cancel-no-refund`), which is why `vault_buildcancel` refuses
a YED intent. Called again for the same intent it returns the same transaction — remembered in the
wallet database across restarts with its fee inputs locked, and re-funded with the same sighash when a
fee input was spent meanwhile (the set signature is over `SIGHASH_ALL|SIGHASH_ANYONECANPAY`, so
`vault_refee` also re-funds a signed one; doc/vault-rpc.md) — so members sign once. The fee never
comes from the intent's value. `refund.cents` is the amount re-issued; `refund.vout` is always 1.
Refusals: `RPC_INVALID_PARAMETER` for a residual intent (it is never cancelled,
`intent-cancel-residual`), an outpoint that is not a YED claim intent, or a vault that is not
`CLAIMING`; `vault_buildcancel`'s own (`not an unspent intent output`, `can no longer be cancelled`).

**The per-vault cancel limit** (CAN-2 + C4b, docs/plans/yellowback-cancel-limit-design.md, owner 2026-10-13):
`cosigs` (array of strings, optional) are `yed_signcancelcosign` results (`cosig`, 69 bytes of hex each: a member's
co-signature of this cancel and its price statement at the claim's `refHeight`). The cancel needs at least
`cancelsRequired` (`yed_getvault`) of them from **distinct current members** of the attestor set: 1 for a position's
first cancel (so the first response stays one watcher), one more for each cancel within `CANCEL_QUIET`, at most
`CANCEL_SIGNERS_MAX`. Each statement's price must say the vault was **not** claimable at that height. With fewer the
call is refused before anything is built (`cancel-cosign-needed`, naming the number); entries that would not count are dropped with a warning (below). With enough, a
carrier holding them (`"YC" ‖ 1 ‖ count ‖ count × (price ‖ sig65)`) is broadcast (`CARRIER_VALUE`, `carrierTxid`; an
outstanding carrier of this wallet with the same bytes is reused, so the same co-signatures give the same
transaction) and the cancel spends it as its **last input, already signed**; the CANCEL_COSIGN marker (`0x09`, an
empty-bodied payload) is its last output before the change. The set signature (`SIGHASH_ALL|ANYONECANPAY`) covers
the outputs only, so it is the same whatever co-signatures arrive — members still sign once. **Add spare
co-signatures** (round 2, review M-2): consensus counts the distinct valid entries and ignores the rest, so spares keep
the cancel valid when a co-signer leaves, is evicted or ejected before it confirms, or a reorg adds an earlier cancel
that raises the count. An entry this RPC can already see would not count (malformed, over another intent, a repeat, not
a current member, a price outside `[PRICE_MIN, PRICE_MAX]` or a claimable one) is **dropped and named** in
**`warnings`** (**optional**, absent when nothing was dropped; `cosigs[i] dropped: <identifier>: <why>`), and the cancel is
built from the rest; the call is refused (`cancel-cosign-needed`, the dropped entries' reasons appended) only when fewer
than `cancelsRequired` remain. `vault_refee` replaces every
non-template input, the carrier included: after it, call `yed_buildcancel` again with the same `cosigs` to re-attach
the carrier. `cancelsRequired` and `cosigners` (the co-signers' `seq`s, carrier order) report what was built.

Result of `yed_buildcancel`:

```json
{
  "hex": "0400008085202f89...",
  "required": 1,
  "cancelsetid": "755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e",
  "deadline": 980,
  "intentconfirmed": true,
  "refund": {
    "vout": 1,
    "script": "76a914a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d488ac",
    "cents": 100000
  },
  "cancelsRequired": 1,
  "cosigners": [0],
  "carrierTxid": "c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1c1a1"
}
```

### `yed_signcancelcosign <intentOutpoint> [priceMicroUsd] [seq]`

Arguments: `intentOutpoint` (string, `"txid:n"`, as `yed_buildcancel`), `priceMicroUsd` (number, optional), `seq`
(number, optional; default the first current member whose key this wallet holds). CAN-2 + C4b (the cancel-limit
design): one 65-byte recoverable signature, with the attestor member key this wallet holds, over
`SHA256d("YedCancelCosign" ‖ attestorSetId ‖ intent txid ‖ n ‖ refHeight ‖ price ‖ blockHash(refHeight))` (`refHeight`
the claim's) — the member's co-signature of the cancel **and** its signed price statement at that height. EQV-1 ejects
a member and freezes its bond when its regular attestation at that height carries another price, so the price is
locked through the equivocation guard (`attest-signed.dat`, as `yed_signattestation`): by default it is the price this
key already signed for `refHeight`; a different price is refused (`equivocation-guard`); with no prior signature the
price must be given (`price-required`) and is recorded for that height. The price must say the vault was not
claimable (`collateralZat · price ≥ mintedCents · CLAIM_THRESHOLD_BPS · COIN`), else `cancel-statement-claimable`.
Round 2 (review): it co-signs only a **confirmed** claim (`claim-unconfirmed` otherwise: a template spend's txid is
malleable until it confirms; re-sign after a reorg re-mines the claim); the guard is looked up **by key** across every
`seq` the key ever held (a member that left and rejoined with the same hot key cannot contradict an attestation of its
old seq at that height); and the block hash is the index's `Snapshots[refHeight].blockHash`, which must equal the
active chain's at that height (else retry).
Refuses also `attest-unknown-seq`, `attest-not-eligible` (not a current member), `attest-key-not-held`,
`attest-range`, and `yed_buildcancel`'s intent refusals. `cosig` is what `yed_buildcancel` takes (69 bytes: price LE32
‖ sig65); `reused` whether the guard already held the price.

Result of `yed_signcancelcosign`:

```json
{
  "cosig": "50c300001f5a1c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9001",
  "seq": 0,
  "priceMicroUsd": 50000,
  "citedHeight": 978,
  "reused": false
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

Arguments: `bondYec` (number, decimal YEC, `≥` `yed_getinfo` `params.attest.bondMinZat`, D-Q-30), `lockBlocks` (number, `≥
BOND_MIN_LOCK`; `bondLocktime = tip + 1 + lockBlocks`), `flags` (number, optional, default `0`;
accepted and ignored since P4-b; it was the raw `u8` of proposal §5.2). **P4-b:** this is
`set_join <attestorSetId> bondYec (tip + 1 + lockBlocks)` with a fresh wallet key as the member
key: `vout[0]` = `P2SH(<bondLocktime> CLTV DROP <memberKey> CHECKSIG)` of `bondYec` (the set's bond
B, the same script as v3's bond script), `vout[1]` = the `SET_JOIN` act signed by the member key,
change. The member key is `attestorPubKey` and the bond key at once (back up `wallet.dat`
afterwards). The bond is **not** `IsMine` (R6): the wallet finds it through `Attestors` by
`bondPubKey` and nothing is written to `wallet.dat`. `seq` is `null` in the result — it is assigned
when the join confirms; read it from `yed_listattestors` by `attestorPubKey`; `flags` is always
`{tier 0, pool false}`; `warning` is `""`, or (D-Q-30 review B2) `"bond-near-min: …"` when `bondYec` is below `bondMinCapZat` and within 10 % of `params.attest.bondMinZat`: the join is judged at the snapshot before its own block, so if YED vault collateral grows before it confirms it becomes invalid (`attestor-bond-below-min`) and is not mined; post 10 % headroom, or `bondMinCapZat`, which always qualifies; `maturesAt` is `tip + 1 + max(set maturity,
BOND_MATURITY)`. Refusals: `bond-below-min`, `lock-below-min` (the module's floor; also for
`bondLocktime ≥ LOCKTIME_THRESHOLD`), `yellowback-no-attestor-set` (the network has none),
`register-needs-admission` (`RPC_WALLET_ERROR`: the set is not open; the message carries the
partly signed hex for `set_signact` / `set_sendact`), the `set_join` refusals (insufficient
confirmed transparent YEC, the set's own `bondmin` / `bondlockmin` / seats as
`bad-vault-act-*`).

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
hand as the vault owner path is. **The bond exit delay (owner 2026-10-11):** only a `WITHDRAWN` record (the
member left with `set_leave`, doc/vault-rpc.md, or was evicted) whose bond is not frozen, from `statusHeight +` the
attestor set's maturity (`BOND_MATURITY`, 16,128; 8 on regtest), which is when the vault primitive releases the bond
(`bad-vault-bond-locked` before); the record keeps its `statusHeight` and gains `bondSpentHeight`. `bondOut` is
the zat paid to `to` net of the network fee. Refusals: `attest-unknown-seq`, `attest-key-not-held`
(the bond key is not in this wallet), `bond-locked` (tip `< bondLocktime`; still a member; a frozen bond; or the
next block `< statusHeight + BOND_MATURITY`), `bond-spent` (the outpoint is already spent), `bad-address`.

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
explicit here). **P4-b:** the revival is a `SET_HEARTBEAT` of the member key to the attestor set
(`set_heartbeat`; `txid` is that transaction's; `ATTESTOR_REVIVE` is invalid); the record is
ELIGIBLE again at the SNAP of the heartbeat's block, with its age preserved. The command still
signs one attestation for `citedHeight = tip − REF_LAG` through the same guard as
`yed_signattestation` and returns it in `hex` (feed it with `yed_addattestation`). Refusals:
`attest-unknown-seq`, `not-dormant` (any status but DORMANT), `attest-key-not-held`,
`attest-range`, `equivocation-guard`, the `set_heartbeat` refusals (`RPC_WALLET_ERROR` for
insufficient confirmed YEC).

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
EQV-1's conditions itself: same `seq` (whose bond is unspent and not frozen, P4-b), same `citedHeight`
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

### `yed_listpositions [status]`

Arguments: `status` (string, optional; as `yed_listvaults`). The wallet's own vaults (a vault is
mine iff the wallet holds the owner's post-quantum key, `HavePQKey(ownerScheme ‖ ownerHash)`): every `yed_getvault` field plus `canRedeem` (true for an
ACTIVE or VOID vault at or past its `ownerHeight` — in term too since IT-1; for VOID it is the
Release, L14), `canClaim` (true when `claimable` and the wallet can spend `≥ mintedCents` now,
`yed_getbalance.spendableCents`) and
`earlyRedeemFeeZat` (IT-9: what a redeem confirming in the next block adds to the pool fee, `0` at
or past `lockHeight`, for a vault that is not ACTIVE, and under FEE-0 — the Positions page shows it
beside `underwaterAt`). `scriptPubKey` and, while
`CLAIMING`, `intents` as `yed_getvault` (`canSweep` and `sweepBefore` left with the sweep, upgrade
plan §6).

**v3.** `noticed`, `noticeHeight`, `emergencyOpenAt` as `yed_getvault` (the Positions page's
"notice posted; emergency claim opens at …" badge); `canNotice` (true when the vault is ACTIVE,
the tip snapshot is armed, no notice stands, and the vault is under `EMERGENCY_RATIO_BPS` under
this node's `pEmerg` but not claimable — the wallet offers "post notice", v3 §4.8); `canClaim`
is now RED-4 by either clause.

`spendPending` and **`spendTxid`** (**optional**) as `yed_getvault`: while a spend of the vault is in
the mempool `canRedeem` and `canClaim` are `false` (the Positions page shows "redemption pending
(txid)" and disables Redeem; cf. DigiByte v9.26.7 00136af6).

Result of `yed_listpositions`:

```json
[
  {
    "txid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    "vout": 0,
    "status": "ACTIVE",
    "ownerScheme": 1,
    "ownerHash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "ownerAddress": "yb5u8LCGfU3hYYhhAqvYzR3ZQuNFEUWzx5dmLiGjPW8Gqto3xqqCc",
    "termClass": "A",
    "lockHeight": 377,
    "claimHeight": 401,
    "collateralZat": 251889169000,
    "collateral": 2518.89169,
    "mintedCents": 100000,
    "mintHeight": 332,
    "refHeight": 329,
    "feePaidZat": 503778338,
    "pMint": 1985000,
    "closeHeight": null,
    "closingTxid": "",
    "burnedCents": 0,
    "unbacked": false,
    "cancelCount": 0,
    "cancelsRequired": 1,
    "cancelQuietUntil": null,
    "claimable": false,
    "underwaterAt": 436700,
    "voidReason": "",
    "scriptPubKey": "045945440020755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e5a6d75765187637520755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e51c0677652876375027c01b1752102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ac67765387637520755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755ec1692102a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ac675488029401b1686868",
    "noticed": false,
    "noticeHeight": null,
    "emergencyOpenAt": null,
    "spendPending": false,
    "canRedeem": false,
    "earlyRedeemFeeZat": 0,
    "canClaim": false,
    "canNotice": false
  }
]
```

### `yed_listtransactions [count] [skip]`

Arguments: `count` (number, default `100`), `skip` (number, default `0`). Newest first; every
wallet transaction that is in `TxLog` with an own token or vault involved (N21: filtered on
`spentTokens`/`assigned`/`closedVaults` that are mine), plus own unconfirmed and expired
Yellowback transactions. `type` is the wallet's view: `mint`, `send`, `receive`, `burn` (a
transfer that burned), `redeem` (own owner-path redemption), `claim` (this wallet claimed, its
own vault included; `amountCents` is minus the burned debt), `claimed` (an own vault was claimed by
someone else; `amountCents` 0), **upgrade (U-23)** `claim_release` / `claim_cancel` (the claimant
intent of this wallet's claim was released to it, the vault CLAIMED, or cancelled by the attestor
set, the vault ACTIVE again and the burn refunded to the holder it came from, CAN-1) and `claim_released` / `claim_cancelled` (the
same two, seen by the owner of a vault someone else claimed) — on these four `path` is `"claim"`,
`amountCents` is 0 and `burned` 0 (the claim row carries the burn), except that a `claim_cancel` row's
`amountCents` is the refund this wallet received (CAN-1: the claim's burn re-issued to the holder it
came from); the release of the owner's
RED-5 residual intent has no row (it moves no Yellowback record), `sweep` (an own vault swept under the
retired abandonment rule; only on a chain indexed before the upgrade), **v3** `notice` (a CLAIM_NOTICE this wallet posted), `noticed` (a notice was
posted on an own vault), `register`, `withdraw` (an own bond withdrawn), `revive`,
`equivocation` (a report this wallet posted), `carrier` (an own carrier funding or sweep
transaction). `amountCents` is the signed effect on this wallet. `unbacked` is true on a row that
closed an own vault without its burn; `expired` rows have `height: -1`, `confirmations: 0`,
`verdict: "expired"`. `payee` `null` where there is no fee output.

**DigiByte v9.26.7 follow-ups** (additive, `rpcversion` unchanged). `time` is the block time of the
row's `height` in UTC seconds (cf. DigiByte v9.26.7 ea78ad18 / 3f09a4a9; *null when* the row has no
block: an expired or unconfirmed row). An `expired` row is typed by its payload (cf. 77a5b156): `mint`,
`send`, `redeem` (`claim` when it spends a vault this wallet does not own), `register`, `notice`,
`equivocation`, `revive` or `cancel`, never a blanket `send`. **Two-step actions (v3 plan A6):**
`carrierTxid` and `mainTxid` join the rows of one carrier-bearing action — a MINT, CLAIM, CLAIM_NOTICE
or EQUIVOCATION row names the carrier it spends and itself; every other row carries `""` in both —
and `carrierOutcome` is what became of that carrier: `completed` (its main transaction, confirmed or
in the mempool, spent it), `swept` (`yed_sweepcarriers` reclaimed it), `lapsed` (the tip passed the
carrier's expiry height `R + REF_WINDOW`: the main transaction can no longer be built and the sweep
will reclaim it) or `pending` (waiting for its confirmation and the main transaction); `""` on a row
without a carrier. A carrier that did **not** complete gets a row of its own, `type: "carrier"`, with
`carrierTxid` its txid, `mainTxid` the main transaction that tried to spend it (`""` when none was
built), `height` / `confirmations` / `time` of the carrier funding transaction (`-1` / `0` / `null`
while unconfirmed) and every amount `0` — so a mint whose second step never happened shows as
pending or failed across a restart (the outstanding records are `carriers.dat`'s, plus the carriers an
own transaction spent). A completed carrier has no row of its own.

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
    "feeZat": 629722922,
    "payee": "smQvTmAz2ExamplePayoutAddress1111111",
    "unbacked": false,
    "expired": false,
    "time": 1792540800,
    "carrierTxid": "5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c",
    "mainTxid": "6a1f2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8",
    "carrierOutcome": "completed"
  }
]
```

### `yed_listaddresses [includeEmpty]`

Arguments: `includeEmpty` (boolean, optional, default `false`). This wallet's Yellowback (YED)
addresses (cf. DigiByte v9.26.7 `listdigidollaraddresses`, 5539554c, b3cb2482): every address that
holds YED now or appears in the indexed history (a token assigned to it or spent from it), plus,
with `includeEmpty`, every unused address `yed_getnewaddress` issued (address-book purpose
`yellowback-receive`; addresses issued by a build before this command are listed once used). Sorted
by `address`. `label` is the address-book label (`yed_getnewaddress`'s `label`, `""` when none),
`confirmedCents` the YED it holds in the index's `Tokens`, `txCount` how many indexed transactions
assigned YED to it or spent YED from it, and `lastUsed` the block time (UTC seconds) of the last of
them, *null when* it was never used. A P2PKH holder is listed in its 35-character form, a post-quantum
holder in its 53-character form.

Result of `yed_listaddresses`:

```json
[
  {
    "address": "yrExampleOwnerAddress111111111111111",
    "label": "savings",
    "confirmedCents": 100000,
    "txCount": 1,
    "lastUsed": 1792540800
  }
]
```

---

## Error identifiers (M8)

The identifier is the first token of the message, followed by `: ` and free text. Provocations are
what `yellowback_rpc_contract.py` uses.

| Identifier | Raised by | When (provocation) |
|---|---|---|
| `yellowback-unhealthy` | every gated command | the index is unhealthy (`unhealthyReason` follows); provoke with `-yellowbacktestfault=storage:commit` then any non-allow-listed command. Also the storage boundary of `yed_addattestation` and `yed_buildbundle` (audit A-3): a storage exception under either marks the index unhealthy and the call fails with `yellowback-unhealthy: storage failure in AddAttestation: …` / `… in BuildBundle: …` |
| `mintpol-not-active`, `mintpol-no-price`, `mintpol-global-ratio`, `mintpol-divergence`, `mintpol-cap` | `yed_mint` | MINTPOL-1, one per halt bit and the cap: mint before activation; with no quote tags in the windows; with the global ratio below `GLOBAL_RATIO_HALT_BPS` and the class's base ratio below `RECAP_RATIO_BPS` (W16, IT-5: only a class whose base ratio reaches it mints through a global-ratio halt — class C with the in-term parameter set; the message names the classes that can); with `P_fast`/`P_slow` diverging by more than `DIVERGENCE_BPS`; with `-yellowbacksupplycapbps` low and supply at the cap — counting the MINT payloads already in this node's mempool toward it (audit C-3; the message then says "after N cents of mints in the mempool"). W20, IT-5 (replacing H-10's class-A rule): above the cap only a class whose base ratio is at or over `RECAP_RATIO_BPS` mints (class C with the in-term parameter set); the message says whether it can. **Residual race:** MINT-6 is judged at inclusion against live totals, so a competing mint this node has not seen (or one paying more) can still land first and make a mint that passed the gate confirm VOID; the collateral is then released by `yed_redeem` at `lockHeight`, no YED is issued and the fee is not refunded. Keep well inside the headroom when the cap is nearly reached. |
| `mintpol-unarmed` | `yed_mint` | MINTPOL-1 for H-1: `yed_getinfo.mintRequiresArmed` is `true` and the reference height `R` is not ARMED, so the mint would confirm VOID with `mint-halted-unarmed` (MINT-4); provoke on regtest with `-yellowbackmintrequiresarmed` before arming |
| `mint-supply-cap` | `yed_mint` | the wallet's dry run of MINT-1..10 refused the built mint under MINT-6 (a mint raced it to the cap after the `mintpol-cap` gate; `RPC_VERIFY_REJECTED`); `yellowback_void_mint.py` shows the consensus verdict |
| `mint-vault-share` | `yed_mint` | the wallet's dry run refused the built mint under MINT-6b (D-Q-23a): its debt exceeds max(`maxVaultShareBps` of the MINT-6 cap, `vaultShareFloorCents`) (`params.supplyCap.maxVaultCents`); silent while the cap is undefined (regtest's `supplyCapBps` 0), so provoke on a network parameter set with a cap (`RPC_VERIFY_REJECTED`) |
| `mint-unsatisfiable` | `yed_mint`, `yed_estimatecollateral` | `requiredZat > MAX_MONEY` (K14): `MAX_MINT` cents at `priceMicroUsd = PRICE_MIN` |
| `mint-bad-lock` | `yed_mint`, `yed_estimatecollateral` | `lockBlocks` outside every class, or `lockHeight + GRACE ≥ LOCKTIME_THRESHOLD` |
| `too-many-addresses` | `yed_listtokens` | an empty array, or more than 100 addresses |
| `invalid-address` | `yed_listtokens` | a string that is neither a YED, a transparent P2PKH nor a plain-YEC post-quantum address of this network |
| `vault-not-found`, `vault-not-active`, `vault-not-owned` | `yed_redeem`, `yed_claim`, `yed_getvault` | an unknown txid; a CLOSED or CLAIMED vault (a VOID vault is releasable by `yed_redeem`, L14); another wallet's vault |
| `vault-locked` | `yed_redeem` | tip below the vault's `ownerHeight` (`refHeight + 1` since IT-1; `lockHeight` for a VOID vault and a vault minted before the in-term rule) |
| `claim-not-yet` | `yed_claim` | tip below the vault's `appHeight` (`refHeight + 1` since IT-1; `claimHeight` for a vault minted before the in-term rule) |
| `claim-not-underwater` | `yed_claim` | RED-4 would fail at the reference snapshot (the price did not fall) |
| `change-floor` | `yed_send`, `yed_sendmany`, `yed_redeem`, `yed_claim` | no selection leaves YED change of `0` or `≥ MIN_OUTPUT` (H2; a REDEEM or CLAIM burns a sub-dollar remainder instead, H4, so it reaches this only when even that is impossible): send `cents − 50` from a single `cents` output. The message is structured and always has this shape: `change-floor: <requested> cents cannot be sent from these coins without change below the $1.00 minimum output; nearest workable amounts: below <n\|none>, above <n\|none>` — the GUI reads the two numbers with that grammar and `yed_estimatesend.alternatives` returns them as fields |
| `unlock-acknowledgement-missing` | `yed_unlockcoin` | the third argument is not exactly `I understand this burns YED` |
| `yed-locked-outpoint` | `lockunspent` (the stock RPC) | `lockunspent false\|true [{txid,vout}]` naming an outpoint the Yellowback wallet layer holds: use `yed_unlockcoin` |
| `yed-burn-refused` | `sendrawtransaction` (the stock RPC) | with `-yellowback`, a raw transaction that spends a `Tokens` outpoint of this wallet without a payload that reassigns it (no payload, or a TRANSFER that assigns nothing): pass `allowyedburn = true` to send it anyway |
| `not-a-yellowback-address` | `yed_send`, `yed_sendmany`, `yed_validateaddress` (in `reason`, no throw) | the recipient is not a `yb…`/`yt…`/`yr…` address of this network: pass an `s1…`/`sm…` address |
| `verdict-parent-not-tip` | `yed_getblockverdict` | the block's parent is not the index tip and the block is not a rejected child of it (N12): pass the tip's grandparent |
| `insufficient-yed` | `yed_redeem`, `yed_claim`, `yed_send`, `yed_sendmany` | wallet YED below the burn or amount (the spendable YED: tokens an own unconfirmed transaction spends do not count) |
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
| `bond-below-min` | `yed_registerattestor` | `bondYec <` the module's floor for a join in the next block (`params.attest.bondMinZat`, D-Q-30; 5 YEC on regtest with no vaults): register with 4 |
| `lock-below-min` | `yed_registerattestor` | `lockBlocks < BOND_MIN_LOCK` (0 since the bond exit delay: a negative `lockBlocks`), or the resulting `bondLocktime ≥ LOCKTIME_THRESHOLD` |
| `bond-locked` | `yed_withdrawbond` | still a member, a frozen bond, or within `BOND_MATURITY` of leaving (the bond exit delay): withdraw right after registering |
| `bond-spent` | `yed_withdrawbond` | the bond outpoint is already spent (`bondSpentHeight` set): withdraw twice |
| `not-dormant` | `yed_revive` | the record's status is not DORMANT: revive an ELIGIBLE attestor |
| `not-equivocation` | `yed_reportequivocation` | any EQV-1 condition fails — different `seq`s, different `citedHeight`s, equal prices, a bad signature, a `seq` whose bond is spent or already frozen (P4-b), or a `citedHeight` whose hash is not in the index (two sides of a fork): report the same attestation twice |
| `attest-key-not-held` | `yed_signattestation`, `yed_revive` (the hot key), `yed_withdrawbond` (the bond key) | the wallet does not hold the key the command needs: sign for a `seq` registered by another node |
| `equivocation-guard` | `yed_signattestation`, `yed_revive`, `yed_signcancelcosign` | `attest-signed.dat` holds a signature for `(seq, citedHeight)` at a different price (S16): sign twice for one height at two prices, also across a restart. Since the cancel-limit review it is looked up **by key**: a signature at that height under any seq the key ever held counts (a member that left and rejoined with the same hot key; EQV-1 binds the key). Message grammar: `equivocation-guard: seq <n> already signed <p₀> for height <h>`, or `equivocation-guard: this key already signed <p₀> for height <h> under seq <n>` |

The wallet builder's own refusals (`src/yellowback/txbuilder.cpp`; Phase 6) carry identifiers
the same way, so the GUI can match them too. They are not rule refusals: `RPC_INVALID_PARAMETER`
for a bad argument, `RPC_WALLET_ERROR` otherwise.

| Identifier | Raised by | When (provocation) |
|---|---|---|
| `bad-address` | `yed_mint` (`from`), `yed_redeem`, `yed_claim` (`to`; a claim's must be transparent) | the address is not an `s1…`/`sm…` or `ys1…` address of this network (a `yb…` YED address, a Sprout address, nonsense), or its Sapling spending key is not in this wallet: pass a `yed_getnewaddress` result as `from` |
| `bad-mint-amount` | `yed_mint` | `cents` outside `[MIN_MINT, MAX_MINT]` |
| `bad-xfer-amount` | `yed_send`, `yed_sendmany` | an amount outside `[MIN_OUTPUT, MAX_OUTPUT]` |
| `insufficient-yec` | `yed_mint`, `yed_send`, `yed_sendmany`, `yed_claim` | the wallet (or the named `from` address) cannot cover collateral + fees from confirmed, unlocked outputs or notes (YED never pays the network fee): `yed_mint … <an empty s1… address>` |
| `too-many-coins` | `yed_mint`, `yed_send`, `yed_sendmany`, `yed_claim`, `yed_claimnotice`, `yed_reportequivocation` | covering the YEC the transaction needs would take more than 400 plain YEC inputs or 75,000 estimated bytes of them even largest-first (the selector goes smallest-first and falls back to largest-first when that would cross either cap; cf. DigiByte v9.26.7 b54e3861). Message grammar: `too-many-coins: covering <amount> YEC would take more than 400 coins (or 75000 bytes of inputs); combine small coins first by sending them to yourself, then retry`: a wallet of 1,000 pool payouts of 0.00001 YEC funding a 0.005 YEC fee |
| `vault-spend-pending` | `yed_redeem`, `yed_claim`, `yed_estimateredeem` (in `error`, no throw) | a transaction in this node's mempool already spends the vault (`yed_getvault.spendPending`; the message names its txid); checked before any coin is selected (cf. DigiByte v9.26.7 00136af6): `yed_redeem` twice before a block |
| `carrier-record-failed` | `yed_mint`, `yed_claim`, `yed_claimnotice`, `yed_reportequivocation` | the carrier record could not be written to `<datadir>/yellowback/carriers.dat`, which is written **before** the carrier is committed (cf. DigiByte v9.26.7 38895edb): nothing was sent. A record whose commit then fails is removed again. Provoke with an unwritable `<datadir>/yellowback` |
| `wallet-locked` | every signing command; on 6.20.0 also `yed_getnewaddress` and every fresh-key draw | the wallet is encrypted and locked (`walletpassphrase` first); the stock `EnsureWalletIsUnlocked` message may precede it |
| `keypool-empty` | `yed_mint`, `yed_send`, `yed_redeem`, `yed_claim` | no fresh key could be drawn (`keypoolrefill`); on 6.20.0 only the `CReserveKey` change paths can raise it (see `yed_getnewaddress`) |
| `too-many-inputs`, `too-many-notes` | `yed_send`, `yed_redeem`, `yed_claim` / `yed_mint` | more than 250 YED inputs / more than 20 Sapling notes would be spent: consolidate first |
| `expiring-too-soon`, `index-below-start` | every builder | the index is far enough behind the chain that `R + REF_WINDOW` would expire the transaction at once, or the index has not reached `startHeight + REF_LAG` |
| `vault-value-too-small` | `yed_redeem`, `yed_claim` | the vault does not cover the network fee (at the floor rate on the owner path) plus the enforcement fee (cannot happen for a vault MINT-5 accepted) |
| `collateral-above-max` | `yed_mint` | maxCollateralZat > 0 and the collateral vout[0] the mint needs exceeds it — at preflight (before the carrier) and again when the MINT is built on the confirmed carrier (RPC_WALLET_ERROR; nothing signed): pass maxCollateralZat = 1 |
| `claim-out-below-min` | `yed_claim` | minOutZat > 0 and what reaches the destination (the claimant intent: the collateral less the RED-5 residual, U-23; the exact collateralOut at build) is below it (RPC_WALLET_ERROR; nothing signed): pass minOutZat = collateralZat |
| `claim-burn-above-max` | `yed_claim` | maxBurnCents > 0 and the YED the claim burns (the vault's mintedCents at preflight; the exact burn, the debt plus any H4 sub-dollar remainder, at build) exceeds it (hardening H-9.3; RPC_WALLET_ERROR; nothing signed): pass maxBurnCents = 1 |
| `carrier-wait-busy` | `yed_mint`, `yed_claim`, `yed_claimnotice`, `yed_reportequivocation` | wait = true while half of -rpcthreads (at least one) wait=true calls are already waiting for a carrier (RPC_WALLET_ERROR, before any transaction): retry or pass wait = false |
| `carrier-timeout` | `yed_mint`, `yed_claim`, `yed_claimnotice`, `yed_reportequivocation` | wait = true and the carrier did not confirm within -yellowbackcarriertimeout seconds (default 600, max 3600); the carrier stays outstanding and is swept once its window lapses |
| `cancel-cosign-needed` | `yed_buildcancel` | fewer co-signatures of distinct current members than `cancelsRequired` (the cancel-limit design, CAN-2; `RPC_INVALID_PARAMETER`, before any transaction). Message grammar: `cancel-cosign-needed: this cancel needs <n> co-signature(s) of distinct current members (cancelsRequired), <m> given`: call it with no `cosigs` |
| `cancel-cosign-malformed`, `cancel-cosign-not-member` | `yed_buildcancel` (in `warnings`, or appended to `cancel-cosign-needed`) | a `cosigs` entry that is not 69 bytes of hex or does not recover over this intent's cancel; one whose key is not a current member of the attestor set: the entry is dropped |
| `cancel-statement-claimable` | `yed_buildcancel` (dropped, in `warnings`), `yed_signcancelcosign` | the statement's price says the vault was claimable at the claim's `refHeight` (C4b): co-sign at the vault's `underwaterAt − 1` |
| `price-required` | `yed_signcancelcosign` | no `priceMicroUsd` given and the guard holds no price of this key for the claim's `refHeight` |
| `claim-unconfirmed` | `yed_signcancelcosign` | the claim is still in the mempool (co-sign only a confirmed claim, design A-6) |

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
| `yed_getfeepayee` | 0 (rpcversion 8: `collateralZat` is gone) |
| `yed_listvaults` | 1, 2 (was 1, 2, 3) |
| `yed_estimatecollateral` | 0, 1, 2 |
| `yed_estimatefee` | 0, 1 (rpcversion 8: `mintedCents`, `priceMicroUsd`) |
| `yed_gethistory` | 0, 1 |
| `yed_mint` | 0, 1 |
| `yed_listtransactions` | 0, 1 (unchanged) |
| `yed_listaddresses` | 0 (`includeEmpty`) |
| `yed_send` | 1 (unchanged) |
| `yed_sendmany` | 0 (unchanged; the object) |
| `yed_estimatesend` | 0 (Phase 8; the recipients object or the plain cents number) |
| `yed_unlockcoin` | 1 (Phase 8; the vout) |
| `yed_gettag`, `yed_getvault`, `yed_gettxinfo`, `yed_decodepayload`, `yed_validaterawtransaction`, `yed_getblockverdict`, `yed_validateaddress`, `yed_redeem`, `yed_listpositions`, `yed_estimateredeem`, `yed_getnewaddress` | none (all strings; `yed_getnewaddress` takes `type` and `label`) |
| `yed_claim` | 3, 4, 5 (**v3**; `wait`; `minOutZat` since the 2026-10-01 audit; `maxBurnCents` since rpcversion 4) |
| `yed_mint` | 0, 1, 4, 5 (**v3**: `wait` joins `cents`, `lockBlocks`; `maxCollateralZat` since the 2026-10-01 audit) |
| `yed_listtokens` | 2, 3 (`count`, `skip`; 2026-10-01 audit) |
| `yed_listclaimable` | 0, 1 (`count`, `skip`; 2026-10-01 audit) |
| `yed_listattestors` | 0 (**v3**) |
| `yed_buildbundle`, `yed_getselection` | 0 (**v3**; `selectorHex` is a string) |
| `yed_claimnotice` | 2 (**v3**; `wait`) |
| `yed_registerattestor` | 0, 1, 2 (**v3**) |
| `yed_withdrawbond` | 0 (**v3**) |
| `yed_revive` | 0, 1 (**v3**) |
| `yed_reportequivocation` | 2 (**v3**; `wait`) |
| `yed_signattestation` | 0, 1, 2 (**v3**) |
| `yed_buildcancel` | 1 (the cancel-limit design: the `cosigs` array) |
| `yed_signcancelcosign` | 1, 2 (the cancel-limit design: `priceMicroUsd`, `seq`) |
| `yed_getattestations`, `yed_addattestation`, `yed_getnotice`, `yed_sweepcarriers` | none (**v3**) |

## Configuration the contract depends on

Yellowback is live where the vault upgrade (`UPGRADE_VAULT`, branch `6d5b7a31`) has an activation
height and the network has a YED attestor set (U-22): on regtest `-nuparams=6d5b7a31:<h>` and
`-yellowbackattestorset=<setid>` (a `set_create` result; hashed); mainnet and testnet have none
yet. `-yellowback` and `-experimentalfeatures` no longer gate anything (`-yellowback=0` is still
accepted, as the H6 acknowledgement); `-yellowbackenforce`, `-yellowbacksignal`,
`-yellowbacktemplatepolicy` and `-yellowbackrequirehealthy` are retired (logged and ignored),
and `-yellowbackstartheight` and `-yellowbackenforceuntil` are refused at init (the start height
is the activation height). `-yellowbackpayoutaddress=<s1…>` (P2PKH; defaults
to a P2PKH `-mineraddress`); `-yellowbackquotemaxage=<sec>` (default
1800); `-yellowbackpreferredpayee=<s1…>`; `-yellowbackpayeepenaltyblocks`, `-yellowbackpayeeaccuracywindow`,
`-yellowbackpayeetiltbps` (FEE-W overrides, L6; reported in `yed_getinfo.params.policy` and
`yed_getfeepayee.policy`); `-reindex-yellowback`; `-yellowbackfee`
(clamped to `≥ DEFAULT_FEE`); `-yellowbackmintlag` (`REF_LAG`, 0..36); `-debug=yellowback`;
regtest only: `-yellowbackattestorset`, `-yellowbacksigmaref`, `-yellowbacksupplycapbps` (with
the activation height, all four in `yed_getinfo.params` and the state hash); test only:
`-yellowbacktestfault=storage:<check|commit|undo>[:<height>]|crash:<height>|template|schema`. `-prune` is refused
where Yellowback is live.

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
