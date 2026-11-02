# Vault primitive RPCs (`set_*`, `vault_*`)

<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

The RPC surface of the Ycash vault primitive (`UPGRADE_VAULT`, branch ID `0x6d5b7a31`;
`docs/plans/yellowback-upgrade-plan.md` §3, §15). The primitive is application-agnostic: signer
sets (`set_*`) and vaults / intents (`vault_*`). Yellowback (YED) and the bridge (wYEC) are
applications on top of it; nothing here is YED-specific.

Every node has these RPCs and the set-state database `<datadir>/vaults/`; no flag enables them.
The database is empty until the upgrade activates (regtest: `-nuparams=6d5b7a31:<height>`).

The machine-readable form of this document is `doc/vault-rpc-contract.json`, generated from it by
`qa/vault-rpc-contract.py` (`--check` verifies the committed copy, the RPC table in
`src/rpc/vault.cpp` and the conversions in `src/rpc/client.cpp`); `qa/rpc-tests/vault_rpc_contract.py`
checks live answers against it. Edit this document, then regenerate.

## Conventions

- **Set id**: the txid of the set's `SET_CREATE` transaction, as a txid hex string.
- **Outpoint**: `"txid:n"` or `{"txid": "...", "vout": n}`.
- **Tag**: 1–4 ASCII characters (zero-padded to 4 bytes) or 8 hex digits. `WYEC` is the bridge
  tag; `YED\0` is reserved for the YED module (P4). An unregistered tag is governed by the
  primitive alone.
- **Keys**: 33-byte compressed public keys in hex. RPCs that sign (member and admit signatures)
  use the private key of that public key in **this node's wallet**; where a key parameter is
  optional, a new wallet key is generated.
- **Owners**: a vault's owner is a post-quantum key (docs/plans/yellowback-quantum-plan.md §4.3),
  named by its `pqkeyid` (`scheme || SHA256(scheme || pk)`, scheme 1 SLH-DSA-SHA2-128s or 2
  FN-DSA-512) or, as a parameter, by its PQ Yellowback address (`yb…`/`yt…`/`yr…`, 53
  characters) or its plain-YEC PQ address (`sq…`/`tq…`/`rq…`, 53 characters, D-Q-20). The node
  wallet holds post-quantum keys (`vault_getnewowner`, `getnewaddress "" "pq"`, or one imported
  with `z_importpqkey`) and signs owner spends; an external owner is named explicitly.
- **Addresses**: every `address` parameter (recipients, `vault_release`, `vault_ownerspend`) takes
  a transparent `s1…`/`t…` address or a plain-YEC PQ address `sq…`/`tq…`/`rq…` (a `TX_PQPKH`
  output, the same script as the PQ `yb…` of that key). A 66-hex `pqkeyid` is not an address:
  `vault_release` refuses one as its recipient ("pass the address or the script, not a pqkeyid").
  Inputs spending such outputs carry no address in `getblockdeltas`/`getspentinfo`/
  `getrawtransaction` (the insight index keys spends by Hash160; `getaddressdeltas` names them), and
  a `-insightexplorer`/`-lightwalletd` node synced before this build needs one `-reindex` to index
  them (doc/yellowback-rpc.md, "Plain-YEC PQ addresses").
- **Amounts** are YEC (decimal) like every other Ycash RPC, the set's rate fields
  (`lockedvalue`, `epochbasis`, `epochused`, `unlockavailable`) and `bondmin` included, although
  the set state stores zatoshi (plan §15.4); `valuezat` fields are zatoshi.
- **Fees**: every transaction these RPCs build pays a flat 10,000 zatoshi from the wallet's
  confirmed transparent P2PKH coins (change to a new wallet address). Coins chosen are locked in
  the wallet (`lockunspent` semantics) so that a following build does not reuse them before the
  first transaction confirms. `vault_ownerspend` prices its owner spend instead (below). Every
  transaction these RPCs broadcast must pay a network fee within the vault/Yellowback cap,
  min(max(`-maxtxfee`, `-yellowbackmaxtxfeeusd` (default $2) at the attested price),
  `-yellowbackmaxtxfee` (default 10 YEC)), never below max(`-yellowbackfee`, 10,000 zat); the
  node submits them without the `-maxtxfee` absurd-fee check, so it enforces that cap itself and
  refuses one above it with `-26` `absurdly-high-fee: … exceeds the vault/Yellowback cap …`.
- **Heights**: unless stated, rules are evaluated at the next block (`tip + 1`) against the set
  state after the tip, exactly as the mempool does (plan U-17).
- **Errors**: RPC error `-8` (invalid parameter), `-5` (unknown set / outpoint / address),
  `-4` (wallet: key not in the wallet, signing failed), `-6` (insufficient funds), `-1` (misc:
  the upgrade is not active, a branch is not open yet), `-26` (rejected by the mempool, with
  `"<code>: <reason>"`, e.g. `"16: bad-vault-act-seats"`), `-25` (missing inputs). The reasons a
  client can rely on are listed under *Error reasons*.

## Contract notation

Each command below has a `Params:` line and a `Result:` line in this notation, which the
contract generator reads (the prose around them is not part of the contract).

| type | JSON | meaning |
|---|---|---|
| `str` | string | text |
| `hex` | string | hex-encoded bytes (a transaction, a script, a signature, a tag) |
| `hash` | string | 32 bytes, 64 hex digits (a txid or set id in RPC byte order; a sighash in raw order) |
| `key` | string | a 33-byte compressed public key, 66 hex digits |
| `pqkeyid` | string | a post-quantum key id, 66 hex digits: the scheme byte (`01` or `02`) then the 32-byte key hash as pushed in the template |
| `outpoint` | string | `"txid:n"` in results; parameters also accept `{"txid", "vout"}` |
| `address` | string | a transparent address of this network |
| `int` | number | an integer |
| `height` | number | a block height (integer) |
| `bool` | boolean | |
| `yec` | number | an amount in YEC, decimal with up to 8 places (1 YEC = 100,000,000 zatoshi) |
| `zat` | number | an amount in zatoshi (integer) |
| `any` | any | a JSON value |

`{"k": T, "k"?: T}` is an object (`?`: the field may be absent; the prose says when), `[T]` an
array of `T`, `T|U` either (`null` is the JSON null), `"text"` that exact string, and `...Name`
inside an object adds the fields of the named shape below (a shape that is a choice of objects
makes the object that choice). Parameters are listed in order, `name?` marks an optional one.
Undocumented result fields are a contract violation; so is a missing field not marked `?`.

### Shapes

- `SetParams` = `{"seats": int, "unlockthreshold": int, "cancelthreshold": int, "slashthreshold": int, "open": bool, "ratelimitbps": int, "ratewindow": int, "livenesswindow": int, "bondmin": yec, "bondlockmin": int, "maturity": int, "admitkey": key}`
- `Set` = `{"setid": hash, "height": height, ...SetParams, "createheight": height, "winddownheight": height, "lockedvalue": yec, "epoch": int, "epochbasis": yec, "epochused": yec, "unlockavailable"?: yec, "members": int, "active": int, "current": int, "dormant": bool, "released": bool}`
- `Member` = `{"key": key, "status": "active"|"removed"|"ejected"|"withdrawn", "current": bool, "live": bool, "joinheight": height, "lastact": height, "bondoutpoint": outpoint, "bondvalue": yec, "bondlocktime": height, "bondfrozen": bool, "exitheight"?: height, "unlockheight"?: height, "wallet": bool}`
- `VaultFields` = `{"tag": hex, "tagtext": str, "setid": hash, "cancelsetid": hash, "delay": int, "ownerheight": height, "appheight": height, "owner": pqkeyid, "ownerscheme": int}`
- `IntentFields` = `{"tag": hex, "tagtext": str, "setid": hash, "cancelsetid": hash, "delay": int, "owner": pqkeyid, "ownerscheme": int, "recipienthash": hash, "vaulthash": hash}`
- `TemplateOut` = `{"txid": hash, "vout": int, "outpoint": outpoint, "kind": "vault", "value": yec, "valuezat": zat, "height": height, "script": hex, ...VaultFields, "wallet": bool}|{"txid": hash, "vout": int, "outpoint": outpoint, "kind": "intent", "value": yec, "valuezat": zat, "height": height, "script": hex, ...IntentFields, "matureheight": height, "mature": bool, "cancellable": bool, "origin": hex, "wallet": bool}`
- `ActType` = `"create"|"join"|"heartbeat"|"remove"|"equivocation"|"winddown"`
- `Proof` = `{"setid": hash, "prevout": outpoint, "rolea": int, "sighasha": hash, "siga": hex, "roleb": int, "sighashb": hash, "sigb": hex}`
- `ActBody` = `{"acttype": "create", ...SetParams}|{"acttype": "join", "setid": hash, "memberkey": key, "bondlocktime": height, "bondvout": int}|{"acttype": "heartbeat", "setid": hash, "memberkey": key}|{"acttype": "remove", "setid": hash, "memberkey": key, "burn": int}|{"acttype": "equivocation", ...Proof}|{"acttype": "winddown", "setid": hash}`
- `ActResult` = `{"hex": hex, "type": ActType, "complete": bool, "signatures": int, "required": int}`
- `SetSigResult` = `{"hex": hex, "complete": bool, "signatures": int, "required": int, "sighash": hash, "setsigs": [{"key": key, "sig": hex}]}`
- `IntentOut` = `{"vout": int, "amount": yec, "recipient": hex, "recipienthash": hash}`
- `Recipient` = `{"address"?: address, "script"?: hex, "amount": yec}`
- `HandoffCoin` = `{"vin": int, "outpoint": outpoint, "amount": yec}`
- `HandoffOutput` = `{"n": int, "amount": yec, "address"?: address, "script"?: hex, "mine": bool, "kind": str}`
- `HandoffPreview` = `{"template": {"outpoint": outpoint, "kind": "vault"|"intent", "selector": int|null}|null, "act": any|null, "sign": [HandoffCoin], "foreign": [HandoffCoin], "outputs": [HandoffOutput], "fee": yec|null, "outflow": yec, "wouldrefuse": str|null}`

## Read RPCs (no wallet needed)

### `vault_getinfo`
Params: `[]`

Result: `{"branchid": str, "activationheight": int, "active": bool, "height": height, "attestorsetid": hash|null, "moduleactive": bool, "dbtip": {"hash": hash, "height": height}|null, "sets"?: int, "vaults"?: int, "intents"?: int, "lockedvalue"?: yec, "statehash"?: hash}`

`branchid` is this network's Vault branch ID: `"6d5b7a31"`, but testnet-yb-slow's own `"e1f1cc08"` (doc/yellowback-testnet-shadow-fork.md); `activationheight` is -1 if unscheduled; `active` is at the next
block; `height` is the tip. `attestorsetid` is the set the registered module (YED) governs on this
node, null when it governs none, and `moduleactive` whether it governs one: until the release that
makes the attestor set a chain parameter (upgrade plan P8) it is the node parameter
`-yellowbackattestorset` on regtest and unset elsewhere, and the module's hooks (ejections, the
liveness `lastact`, displacement, its spend rule) are inert where it is null, so two nodes that
report different values compute different set state for the same blocks. `dbtip` is the block the
set state is at (null before the first active block). `statehash` is SHA256d over every state
record (sets, members, bonds, the template-output index) in key order: two nodes on the same chain
with the same `attestorsetid` report the same value. The counts, `lockedvalue` and `statehash` are
absent only when the vault database is not open.

### `set_list`
Params: `[]`

Result: `[Set]`

Every set: the `set_getinfo` fields without `memberlist`.

### `set_getinfo "setid" ( height )`
Params: `["setid": hash, "height"?: height]`

Result: `{...Set, "memberlist": [Member]}`

The set's `SET_CREATE` parameters, `createheight`, `winddownheight` (0 = none), the rate fields
(`lockedvalue`, `epoch`, `epochbasis`, `epochused`, and `unlockavailable` only when the set is
rate limited), counts (`members`, `active`, `current`), the §15.4 predicates `dormant` and
`released`, and `memberlist` (`wallet`: this wallet holds the key; `exitheight` and `unlockheight` =
`exitheight + maturity`, the first block its bond may be spent in, only while the member has left and its bond is
unspent -- the bond exit delay). Predicates are evaluated at
`height` (default: the next block) over the state at the tip. Error `-5` for an unknown set.

### `vault_list ( {"tag", "setid", "owner", "kind": "vault"|"intent", "mine": bool} )`
Params: `["filter"?: {"tag"?: str, "setid"?: hash, "owner"?: pqkeyid, "kind"?: "vault"|"intent", "mine"?: bool}]`

Result: `[TemplateOut]`

The unspent V and I outputs confirmed since activation (the database's template-output index),
optionally filtered (`setid` matches either set of the template; `owner` is a pqkeyid or a PQ
address; `mine` = the owner key is in this wallet, never true before the wallet holds PQ keys). For an intent, `origin` is the script of the vault it was unlocked from.

### `vault_decodescript "hex"`
Params: `["hex": hex]`

Result: `{"type": "vault", ...VaultFields}|{"type": "intent", ...IntentFields}|{"type": "malformed"}|{"type": "act", ...ActBody, "signatures": [{"sig": hex}], "payload": hex}|{"type": "act", "error": str}|{"type": "bond", "locktime": height, "memberkey": key, "scriptpubkey": hex, "address": address}|{"type": "none"}`

Decodes a V or I scriptPubKey, a `YV` act OP_RETURN (the act's own type as `acttype`, the
decoded body, `payload`, `signatures`; or `error` with the decode reason), a bond redeem script
(its P2SH `scriptpubkey` and `address`), `malformed` (a template skeleton with a non-minimal push
or out-of-range field), or `none`.

## Act RPCs (wallet)

Acts are `YV` OP_RETURN outputs (plan §15.5). Their signatures bind the payload and `vin[0]`'s
outpoint, and they are part of the output, so the order is always: **build** (funding fixes
`vin[0]`), **sign the act** (on each signer's node), **sign the inputs and send** (on the node
that funded it).

### `set_create {params}`
Params: `["params": {"seats": int, "unlockthreshold": int, "cancelthreshold"?: int, "slashthreshold"?: int, "open"?: bool, "ratelimitbps"?: int, "ratewindow"?: int, "livenesswindow"?: int, "bondmin"?: yec, "bondlockmin"?: int, "maturity"?: int, "admitkey"?: key}]`

Result: `{"txid": hash, "setid": hash, "admitkey": key}`

`seats` 1–15; defaults: `cancelthreshold` 1, `slashthreshold` = `unlockthreshold`, `open`
false, `ratelimitbps` 0 (no limit), `ratewindow` 144, `livenesswindow` 1000, `bondmin` 1,
`bondlockmin` 0, `maturity` the network's minimum, `admitkey` a new wallet key. Funded, signed, broadcast. The set
exists from the block after the one it confirms in.

**D-Q-31 (owner, 2026-10-11): every set has at least a 14-day exit window.** `maturity` (the bond exit delay and
the joiners' wait) must be at least `MIN_SET_MATURITY` = 16,128 blocks on mainnet and testnet (2 on regtest);
a smaller value is refused here (`RPC_INVALID_PARAMETER`) and a `SET_CREATE` carrying one is
`bad-vault-act-params`. A bridge set's members therefore wait at least 14 days for their bonds after leaving,
and stay slashable for those 14 days. Regtest's 2 is a scaling value so the functional suites fit (the
floor itself is exercised there: `vault_primitive.py` sends a maturity-1 `SET_CREATE` to the mempool and in a
block, `vault_rpc_contract.py` calls `set_create` with 1 and without `maturity`); the 14-day mainnet floor is
pinned by the unit test `vault_state_tests/min_set_maturity`.

### `set_join "setid" bondamount bondlocktime ( "memberkey" )`
Params: `["setid": hash, "bondamount": yec, "bondlocktime": height, "memberkey"?: key]`

Result: `{"txid"?: hash, ...ActResult, "memberkey": key, "bondoutpoint": outpoint}`

Builds the `SET_JOIN` with the bond `P2SH(<bondlocktime> CLTV DROP <memberkey> CHECKSIG)` at
`vout 0`, adds the member's signature and whatever admission signatures this wallet holds (the
admit key while the set has fewer than `slashthreshold` current members, current members'
keys after that; none for an open set). Complete → signed and broadcast (`txid` present);
otherwise the partially signed `hex` is returned. That build is remembered in the wallet;
`set_sendact` on this node signs only the coins it chose for those outputs.

A join into a set that already has `seats` ACTIVE members is refused (`bad-vault-act-seats`) —
unless a registered module governs the set (the module displacement hook, owner 2026-10-11) and
names a member to displace: that member becomes `REMOVED` in `set_getinfo` (its bond **not**
frozen, still spendable at its locktime) and the join is admitted in the same transaction. Only the
YED module governs a set (the network's attestor set, when OPEN with 15 seats); its rule is in
`doc/yellowback-attestor.md`. Every other set refuses a join when full, as before.

### `set_heartbeat "setid" ( "memberkey" )`
Params: `["setid": hash, "memberkey"?: key]`

Result: `{"txid": hash, "memberkey": key}`

A `SET_HEARTBEAT` for a current member key of this wallet (default: the first), broadcast.

### `set_leave "setid" ( "memberkey" )`
Params: `["setid": hash, "memberkey"?: key]`

Result: `{"txid": hash, "memberkey": key, "exitheight": height, "bondspendableat": height}`

**The bond exit delay (owner 2026-10-11).** A member bond is spendable only after its member has left
the set without a freeze and the set's `maturity` has passed since: from `exitHeight + maturity`
(`bad-vault-bond-locked` before; a frozen bond never). A member leaves by its own `SET_REMOVE`
(signed by its key alone, `burn` 0, no cosigners: the one removal a member can do alone), by a
`SET_REMOVE` of the set without burn, or by the module displacement hook (`set_join`); each records
`exitHeight` on the bond. During the delay the member is still slashable (`SET_EQUIVOCATION`, the
module ejection hook) and the bond is then frozen. `set_leave` builds, signs and broadcasts the
member's own `SET_REMOVE` for an ACTIVE member key of this wallet (default the first one);
`exitheight` is the next block, `bondspendableat` = `exitheight + maturity`. The bond script's CLTV
(`bondlockmin`) still applies on top, so a set may keep it at 0.

**No slash escape through the delay (seats review B1/A1, 2026-10-11).** A key whose previous bond in the set is
still unspent (in its exit delay, or frozen) cannot join that set again (`bad-vault-act-join`), so the member
record always names the key's one unspent bond and every slash reaches it. A `SET_REMOVE` with burn, cosigned by
`slashthreshold` current members, of a member that already left (`REMOVED`) and whose bond is in its exit delay
freezes that bond (the member stays `REMOVED`); a frozen key never rejoins the set.

### `set_buildact "type" {params}`
Params: `["type": ActType, "params": {"setid"?: hash, "memberkey"?: key, "bondamount"?: yec, "bondlocktime"?: height, "burn"?: bool, "prevout"?: outpoint, "rolea"?: int, "sighasha"?: hash, "siga"?: hex, "roleb"?: int, "sighashb"?: hash, "sigb"?: hex, "seats"?: int, "unlockthreshold"?: int, "cancelthreshold"?: int, "slashthreshold"?: int, "open"?: bool, "ratelimitbps"?: int, "ratewindow"?: int, "livenesswindow"?: int, "bondmin"?: yec, "bondlockmin"?: int, "maturity"?: int, "admitkey"?: key}]`

Result: `ActResult`

An unsigned, funded act transaction. Types and params: `create` (as `set_create`), `join`
(`setid`, `bondamount`, `bondlocktime`, `memberkey` — any key), `heartbeat` (`setid`,
`memberkey`), `remove` (`setid`, `memberkey` = the member removed, `burn` bool: freeze its bond),
`equivocation` (as `set_equivocation`), `winddown` (`setid`). `complete` is false (unless no
signature is needed) and `signatures` 0. The build is remembered; `set_sendact` on this node
signs only its coins, for these outputs.

### `set_signact "hex" ( "setid" )`
Params: `["hex": hex, "setid"?: hash]`

Result: `ActResult`

Adds this wallet's act signatures: the member's own first signature (join, heartbeat), then
admission / co-signer signatures up to what the act needs at the next block (a remove never by
its target). The inputs must still be unsigned.

### `set_sendact "hex" ( {"dryrun", "allowinputs", "allowoutflow"} )`
Params: `["hex": hex, "options"?: {"dryrun"?: bool, "allowinputs"?: [outpoint], "allowoutflow"?: yec}]`

Result: `hash|HandoffPreview`

Signs this wallet's inputs of an act transaction this wallet built (`set_buildact`, or `set_join`
when it returned a hex) and broadcasts. Without `dryrun`, the result is the txid. Only the coins
that build chose are signed, and only while the outputs are the ones it chose (act signatures
added later do not make a different output). Any other spendable coin of this wallet is refused
(`vault-send-foreign-input`) unless `allowinputs` names that outpoint, and nothing is signed.
The wallet's net outflow — the value of the inputs it would sign, minus outputs it can spend, and
minus a `SET_JOIN` bond when this wallet holds that act's member key — above the fee cap is refused
(`vault-send-outflow`) unless `allowoutflow` is at least that outflow. `dryrun: true` signs and
broadcasts nothing and returns `HandoffPreview` (`sign` is the inputs it would sign, `foreign` the
wallet coins the build did not choose, `outflow` the net, `wouldrefuse` the refusal or null).

### `set_equivocation {proof}`
Params: `["proof": Proof]`

Result: `hash`

Roles 1 unlock / 2 cancel; sighashes as 32 raw bytes in hex, as `set_signunlock` /
`set_signcancel` report them; signatures 65-byte recoverable. Anyone may submit; the member is
EJECTED and its bond frozen. Result: the txid.

## Vault RPCs (wallet)

### `vault_getnewowner ( scheme )`
Params: `["scheme"?: int]`

Result: `{"scheme": int, "keyhash": hex, "owner": pqkeyid, "address": str}`

A new post-quantum key of this wallet, derived from its HD seed (HKDF-SHA256, quantum plan §4.6),
for a vault owner. `scheme` 1 (SLH-DSA-SHA2-128s, the default) or 2 (FN-DSA-512, only once Falcon
is active at the next block). `keyhash` is the 32 bytes the V pushes, `owner` = scheme ‖ keyhash,
`address` the 53-character PQ Yellowback address. The wallet must be unlocked.

### `vault_lock {params}`
Params: `["params": {"tag": str, "setid": hash, "cancelsetid"?: hash, "delay": int, "ownerheight": height, "appheight"?: height, "amount": yec, "owner"?: pqkeyid}]`

Result: `{"txid": hash, "vout": int, "outpoint": outpoint, "script": hex, "owner": pqkeyid}`

`delay` 1–65535; `cancelsetid` defaults to `setid`, `appheight` to 0 (no APP branch). A non-zero
`appheight` is accepted only on a tag a registered module governs (`YED\0`): the APP branch has no
signer, and consensus refuses a V with an APP branch on any other tag (V-1, `bad-txns-vault-app`;
audit 01/V-5). Registered is not governed: on a node where the module has no set (`YED\0` without
`-yellowbackattestorset`, so its rules are unconfigured) such a V is consensus-valid but its APP
branch is open to anyone from `appheight`; `vault_lock` therefore also requires the module to
govern a set here (`GovernedSet`). `owner` is
a pqkeyid, a PQ address or `{"scheme": int, "keyhash": hex}` (any key: an external owner is
allowed); without it the wallet draws a new SLH-DSA owner (as `vault_getnewowner`). The former
`ownerkey` is refused. Both sets must be confirmed. `vout` is 0.

### `vault_buildunlock "outpoint" [{"address"|"script", "amount"}, ...] ( rebuild )`
Params: `["outpoint": outpoint, "recipients": [Recipient], "rebuild"?: bool]`

Result: `{"hex": hex, "intents": [IntentOut], "required": int, "sighash": hash, "build": "new"|"reused"|"refunded"}`

The UNLOCK spend (selector 1) of a vault: an intent per recipient (exactly one of `address` or
`script`), the remainder re-locked in a byte-identical vault (S-2), fee inputs from this wallet
(unsigned). **The fee is never taken from the vault's value**: S-2 (re-lock + intents ≥ the
vault), I-1 and I-2 make that consensus-illegal, so it always comes from other inputs. The rate
limit (S-3) is checked when it is sent. `sighash` is the set-signature sighash the members will
sign (`set_signunlock` reports the same).
**Call once.** The build is remembered in the wallet database per vault outpoint, across
restarts, with its fee inputs locked (07/N-2): called again with the same recipients it returns
the same transaction (`build` `"reused"`), or, when a fee input was spent meanwhile, the same
transaction re-funded as `vault_refee` does (`"refunded"`, same `sighash`). Other recipients are
refused while the build exists (members sign once); `rebuild` `true` discards it and builds anew
— only before any member signed it, since a signature over the old build makes a signature over
the new one an equivocation. The wallet picks the smallest single coin that covers the fee, so
the change output, which the set signatures bind and a re-funder must pay, stays small.

### `set_signunlock "hex" ( {"acknowledgerestore": true} )`
Params: `["hex": hex, "options"?: {"acknowledgerestore"?: bool}]`

Result: `SetSigResult`

Adds this wallet's current-member signatures over the set-signature message (plan §15.2 step 4)
for the vault's `setid`, up to `unlockthreshold`. Signing two different spends of one outpoint
is provable equivocation: sign only the transaction you mean. The sighash is ZIP-243
`SignatureHash(scriptCode, tx, nIn, SIGHASH_ALL|SIGHASH_ANYONECANPAY, amount, branch)` (01/V-2):
it binds the vault input (prevout, amount, sequence, script) and every output, not the other
inputs, so the fee inputs may be replaced by anyone (`vault_refee`) without a new signature, and a
re-funded transaction has the same sighash.
**Sign once:** before handing out a signature the wallet records, in its wallet database, the
role and sighash its members signed for `(setid, prevout)`, and refuses a different role or
sighash for that pair with `set-sign-once` (`RPC_WALLET_ERROR`), across restarts; re-signing the
identical transaction, or the same transaction re-funded, is idempotent. There is no override.
**Validated first:** a build the vault rules would refuse at the next block (an intent's cancel past
its delay, a release that does not pay its recipient, an existing signature not by a distinct current
member) is refused with `set-sign-invalid` (`RPC_INVALID_PARAMETER`) and its reason before anything
is recorded or signed. Only `bad-txns-vault-rate`, which the next epoch clears, is let through, and a
spent fee input is checked with the template input alone.
**The record lives only in this `wallet.dat`** (07/F-5). Nothing derives it from the chain, and
a wallet restored from its seed (`-hdseedfile`; `-mnemonicfile` on 6.20.0), a wallet that
imports the member key (`importwallet`, `z_importwallet`, `importprivkey`) or a second host with
the same key has no record: asked to sign a different spend of an outpoint the key already
signed, it would sign, and anyone can then submit `set_equivocation` — the member is EJECTED
and its bond frozen. The rules: **a member key lives in exactly one wallet on one signing host;
back up `wallet.dat` after every `set_signunlock` / `set_signcancel` (the seed is not enough);
never sign on a restored wallet before importing the record and confirming it is complete** —
`set_listsigned` on the old wallet (or its `dumpwallet` / `z_exportwallet` dump, whose
`vaultsetsig=` lines carry it) and `set_importsigned` (or `importwallet` / `z_importwallet` of the
dump) on the new one, check with `set_listsigned`, then `set_acknowledgerestore`.
`-salvagewallet`, or a startup that reports "data salvaged", also sets the restore marker (a salvage can lose records), and keeps the surviving `vault*` and `pqissued` rows: the same procedure applies, using a dump or `set_listsigned` taken before the damage (the original file is kept as `wallet.<timestamp>.bak`).
A bridge attestor backs `wallet.dat` up together with its sidecar's own ledger and never runs two copies
(`hawkeye/docs/operations.md`).

The node enforces what it can see. A wallet created from a seed, or one that imports a key that is
a member of a set at the tip, carries a **restore marker**; a key imported while it is not (yet)
a member — during IBD or `-reindex`, or before its `SET_JOIN` is mined — is remembered as pending,
and when a `SET_JOIN` of it connects the marker is set then. While the marker is set the sign
RPCs refuse with `set-sign-restored` (`RPC_WALLET_ERROR`) any `(setid, prevout)` the wallet has no
record for, unless the call passes `{"acknowledgerestore": true}` — the operator's statement that
this key never signed a set spend of that outpoint; a prevout with a record follows the record
(`set-sign-once`, or idempotent re-signing). **Importing a history never clears the marker** (a
dump may be stale: taken before the old host's last signature): only `set_acknowledgerestore`
does, the operator's confirmation that no other host, wallet copy or backup has signed with these
keys since the imported history was taken (review S2). The node logs a warning at startup while
the marker is set and the wallet holds a member key. **Not protected:** a `wallet.dat` restored by
copying the file (an old backup carries an old record and no marker) and two live wallets sharing
a member key (an HA pair) — the node cannot tell either from the original; the
one-wallet-per-key rule is the only defence. With SIGHASH_ALL|ANYONECANPAY a re-funded build has
the same sighash, so the record stays valid across re-funding; the hazard is a *different* build.

### `vault_buildcancel "intentoutpoint" ( rebuild )`
Params: `["intentoutpoint": outpoint, "rebuild"?: bool]`

Result: `{"hex": hex, "required": int, "cancelsetid": hash, "deadline": height, "intentconfirmed": bool, "sighash": hash, "build": "new"|"reused"|"refunded"}`

The CANCEL spend (selector 2) of an unmatured intent: its value back into the vault it was
unlocked from (I-2). `deadline` is the last height a cancel can confirm at. An intent still in
the mempool can be cancelled too: its originating vault script is read from the vault coin its
transaction spends, `intentconfirmed` is false and `deadline` assumes the intent confirms in the
next block. The mempool accepts the cancel as the intent's child (a mempool parent counts as
confirming in the next block, so I-2 holds), and both may confirm in one block; a cancel signed
before the intent confirms stays valid after it. So a watcher can build and sign a cancel the
moment an intent appears. Called again for the same intent it returns the same transaction
(mempool or confirmed), remembered in the wallet database across restarts with its fee inputs
locked; when a fee input was spent meanwhile it returns the same transaction re-funded
(`vault_refee`, same `sighash`), so every member signs one sighash. `rebuild` and the fee: as
`vault_buildunlock` (the fee never comes from the intent's value: I-2). A pre-built spend that
chains on a re-funded parent (a cancel of a mempool intent whose unlock was re-funded) must be
rebuilt: re-funding changes the parent's txid, not its sighash.
An intent of the YED module (tag `YED\0`) is refused: the module's
CAN-1 rule (audit 03/H-1) also requires the cancel to refund the claim's burn, so it is built with
`yed_buildcancel` (doc/yellowback-rpc.md), and a member never signs a cancel the module rejects
(`RPC_INVALID_PARAMETER`, "a YED claim intent is cancelled with yed_buildcancel"; provoked by the Yellowback
contract test, which has the module configured, so it is not in this file's error table).

### `set_signcancel "hex" ( {"acknowledgerestore": true} )`
Params: `["hex": hex, "options"?: {"acknowledgerestore"?: bool}]`

Result: `SetSigResult`

As `set_signunlock`, for the intent's `cancelsetid` and `cancelthreshold`, under the same
sign-once record and restore marker.

### `vault_refee "hex"`
Params: `["hex": hex]`

Result: `{"hex": hex, "sighash": hash, "fee": yec, "replaced": [outpoint]}`

Re-funds a vault UNLOCK or CANCEL spend (01/V-2): every input but the vault/intent input is
replaced by this wallet's coins; the template input — with any set signatures already on it —
and every output stay byte-identical, so the signatures stay valid and `sighash` is unchanged.
Use it when a fee input of a built or signed spend was spent elsewhere (the builder spent its own
coin, a lock was released). **Anyone may re-fund**: the set signatures bind the template input
and the outputs only. The outputs, the builder's change included, are bound, so there can be no
new change output: the new input is one coin worth exactly what the outputs need beyond the
template coin plus the fee (the 10,000-zatoshi vault fee) — an existing confirmed coin within
1,000 zatoshi of it, else a self-send of exactly that amount that this call broadcasts and the
re-funded spend chains on in the mempool (the old fee inputs this wallet locked are released
first, so a still-unspent one can fund it). The fee never comes from the vault's value (S-2, I-1,
I-2). Coins are taken only when unspent in the node's own UTXO view (chain tip and mempool), never
from the wallet's view alone, which can lag a block by the wallet's notification; the new input is
never one it replaces, and the call refuses (nothing changed) unless the resulting fee is above 0
and at most the vault/Yellowback cap. The builders choose their fee coins the same way. The new
input is unsigned and locked; `vault_send` on this node signs it. When this wallet built the spend, its remembered build
follows the re-funded transaction. Re-funding changes the txid (third-party malleability by
input replacement, as the selector case 01/V-4).
**Pinning (review S1):** because anyone may re-fund, a third party can also broadcast its own
variant of a signed spend first — for example a wrong-price claimant re-funding the attestors'
cancel from a low-fee, unconfirmed parent — and without replace-by-fee the first variant a node
sees is the one it keeps, possibly until the intent's `delay` has passed. Cancel signers should
broadcast a cancel early, send it directly to well-connected peers and miners, and watch it
confirm; if it lingers, re-fund it with `vault_refee` from a confirmed coin and send that.

### `set_listsigned`
Params: `[]`

Result: `{"restored": bool, "records": [{"setid": hash, "prevout": outpoint, "role": int, "sighash": hash}]}`

The wallet's set sign-once records (07/F-5): for each `(setid, prevout)` its member keys signed
a spend of, the role (1 unlock, 2 cancel) and the sighash. `restored` is the restore marker:
while it is true the sign RPCs refuse with `set-sign-restored`. Back the records up with
`wallet.dat`; `dumpwallet` / `z_exportwallet` write them as `vaultsetsig=` lines (with the
remembered vault builds, `vaultbuild=`, and intent recipients, `vaultrecipient=`).

### `set_importsigned [{"setid", "prevout", "role", "sighash"}, ...]`
Params: `["records": [{"setid": hash, "prevout": outpoint, "role": int, "sighash": hash}]]`

Result: `{"imported": int, "present": int}`

Imports sign-once records as `set_listsigned` printed them on the wallet that signed. A record
that differs from one this wallet holds for the same `(setid, prevout)` refuses the whole import
(`set-sign-once`, nothing imported): two signing histories for one key are never merged
silently. Identical records count as `present`. Importing a dump with `importwallet` /
`z_importwallet` applies the same rule to its `vaultsetsig=` lines. Neither clears the restore
marker (an imported history may be stale); `set_acknowledgerestore` does. There is no RPC that
deletes a record.

### `set_acknowledgerestore`
Params: `[]`

Result: `{"restored": bool, "pendingkeys": int}`

Clears the restore marker: the operator confirms that the wallet's sign-once history
(`set_listsigned`) is complete — no other host, wallet copy or backup has signed with its member
keys since that history was taken. `restored` is then false; `pendingkeys` counts imported keys
still watched for a `SET_JOIN` (one connecting sets the marker again).

### `vault_send "hex" ( {"dryrun", "allowinputs", "allowoutflow"} )`
Params: `["hex": hex, "options"?: {"dryrun"?: bool, "allowinputs"?: [outpoint], "allowoutflow"?: yec}]`

Result: `hash|HandoffPreview`

Signs this wallet's inputs of a built vault spend (the template input's scriptSig is kept) and
broadcasts. Without `dryrun`, the result is the txid. The node that funded the spend must send it:
only coins this wallet's builders (`vault_buildunlock`, `vault_buildcancel`, `yed_buildcancel`,
`vault_app`, `set_buildact`, `vault_refee`) chose for these exact outputs are signed. Any other
spendable coin of this wallet is refused (`vault-send-foreign-input`) unless `allowinputs` names
that outpoint, and nothing is signed. The same net-outflow cap as `set_sendact` applies
(`vault-send-outflow`, overridden by `allowoutflow`). `dryrun: true` returns `HandoffPreview` and
signs nothing. A transaction with no unspent vault or intent input is refused: `vault_send` is not
a general signer. The coins a build chose are the wallet's `vaultbuild` record (dumped, imported,
and kept by salvage); there is no separate fee-input record.

### `vault_release "intentoutpoint" ( "address"|"script" )`
Params: `["intentoutpoint": outpoint, "recipient"?: str]`

Result: `hash`

The RELEASE (selector 1, `nSequence = delay`) of a matured intent, paying its value to the
recipient (an address or a script in hex), fee from this wallet. The intent commits only
`SHA256(recipient script)`, so the recipient is the argument, or a script this node built the
intent for, or one of this wallet's P2PKH scripts, or the `TX_PQPKH` script of a post-quantum
key this wallet holds — so an owner releases its own residual (quantum spec F-3) without passing
the script, e.g. after a restart. Error `-1` "matures at height h" before
`coinHeight + delay`; error `-8` "pass the address or the script, not a pqkeyid" when the argument
is a 66-hex pqkeyid that is not the recipient script. Result: the txid.

### `vault_ownerspend "outpoint" "address"`
Params: `["outpoint": outpoint, "address": address]`

Result: `{"txid": hash, "selector": int}`

Spends a vault with its owner key (in this wallet) to `address`, less the fee: selector 2 with
`nLockTime = ownerheight` once the next block is above `ownerheight`, else selector 3 when the
set is released (dormant or wound down). An intent has only selector 3. The owner is a
post-quantum key this wallet must hold (an external owner signs outside the node); the fee is
max(10,000 zat, the vault/Yellowback rate × size), capped at the vault/Yellowback cap (above):
the rate is `-yellowbackfeeusdperkb` (default $0.05/KB) at the attested price -- the highest of the
Yellowback index tip's window medians, none while the price is not trusted (HALT-1 or HALT-3; HALT-2
alone keeps it, fees spec §5.1 amendment 2026-10-28) -- never below
max(5,000 zat/KB, `-pqfeerate`); without an attested price (no Yellowback index, below its start,
under HALT-1 or HALT-3) it is `-pqfeerate` (quantum plan §4.5, D-Q-23 (b), D-Q-26;
`yed_getinfo.params.fees.network` reports the values in force). On 6.20.0 the fee is never below
the transaction's ZIP-317 conventional fee (an SLH-DSA owner spend is ~54 logical actions, 27,000
zat), so a node with `-txunpaidactionlimit=0` relays it. When the priced fee would leave a dust
output (a small vault after a price crash), it is clamped to max(10,000 zat, the floor rate × size,
the conventional fee); an output still dust after that is refused (`-8`). `-yellowbackmaxtxfee`
may not be set below 0.001 YEC.

### `vault_app "outpoint" ( [{"address"|"script", "amount"}, ...] )`
Params: `["outpoint": outpoint, "recipients"?: [Recipient]]`

Result: `{"hex": hex, "intents": [IntentOut]}`

The APP spend skeleton (selector 4, `nLockTime = appheight`) with intents and re-lock as
`vault_buildunlock`, fee inputs unsigned, for a module to complete; the build is remembered, and
`vault_send` on this node signs only the coins it chose for these outputs.

## Error reasons

The error messages a client may match on (a substring of the RPC error's `message`), with their
code. `qa/rpc-tests/vault_rpc_contract.py` provokes each one.

| code | message | raised by | provoked by |
|---|---|---|---|
| -1 | `is not active at the next block` | every act and vault RPC | `set_create` before activation |
| -8 | `the set parameters are out of range` | `set_create`, `set_buildact` | `seats` 16 |
| -5 | `unknown set` | `set_getinfo`, `set_join`, `set_heartbeat`, `set_buildact`, `vault_lock` | `set_getinfo` of a random id |
| -4 | `this wallet holds no current member key of the set` | `set_heartbeat` | a heartbeat for a set with no members |
| -26 | `bad-vault-act-seats` | `set_join`, `set_sendact` | a join to a full set (a set a registered module governs may instead displace a member, below) |
| -8 | `unknown act type` | `set_buildact` | type `"bogus"` |
| -8 | `the transaction carries no YV act` | `set_signact`, `set_sendact` | `set_signact` of a vault spend |
| -8 | `kind must be vault or intent` | `vault_list` | `{"kind": "coin"}` |
| -8 | `vault parameters out of range` | `vault_lock` | `delay` 0 |
| -8 | `ownerkey-removed` | `vault_lock` | the former `ownerkey` parameter |
| -8 | `appheight on a tag no module governs` | `vault_lock` | `appheight` on tag `TEST` (or on `YED\0` where no attestor set is configured) |
| -8 | `unknown post-quantum scheme` | `vault_getnewowner` | `scheme` 3 |
| -8 | `unregistered post-quantum scheme` | `vault_lock`, `vault_list` | an `owner` with scheme `03` |
| -8 | `a scheme-2 (FN-DSA-512) owner before Falcon is active` | `vault_lock` | an `owner` with scheme `02` while Falcon is inactive at the next block |
| -4 | `not a post-quantum key of this wallet` | `vault_ownerspend` | a vault with an external owner |
| -8 | `not an unspent vault output` | `vault_buildunlock`, `vault_app` | a spent vault outpoint |
| -8 | `the recipients' amounts exceed the vault's value` | `vault_buildunlock`, `vault_app` | more than the vault holds |
| -8 | `the template input is not an intent` | `set_signcancel` | an unlock spend |
| -8 | `the template input is not a vault` | `set_signunlock` | a cancel spend |
| -8 | `no unspent vault or intent input` | `set_signunlock`, `set_signcancel`, `vault_refee`, `vault_send` | `vault_send` of a transaction with no template input |
| -4 | `vault-send-foreign-input` | `vault_send`, `set_sendact` | a spend that names a wallet coin this wallet did not fund for these outputs, and `allowinputs` does not name it |
| -4 | `vault-send-outflow` | `vault_send`, `set_sendact` | the wallet's net outflow exceeds the fee cap and `allowoutflow` does not cover it |
| -4 | `set-sign-once` | `set_signunlock`, `set_signcancel`, `set_importsigned` | a second, different unlock of a vault this wallet already signed |
| -4 | `set-sign-restored` | `set_signunlock`, `set_signcancel` | signing on a wallet that imported a member key, before `set_importsigned` |
| -8 | `set-sign-invalid` | `set_signunlock`, `set_signcancel` | `set_signcancel` of an intent's cancel after the intent matured |
| -8 | `already built a different unlock` | `vault_buildunlock` | a second build of one vault with other recipients, without `rebuild` |
| -8 | `not an unspent intent output` | `vault_buildcancel`, `vault_release` | a released intent |
| -1 | `can no longer be cancelled` | `vault_buildcancel` | an intent past its delay |
| -1 | `matures at height` | `vault_release` | an intent before its delay |
| -1 | `owner branch opens at height` | `vault_ownerspend` | a vault before `ownerheight` |
| -8 | `has no APP branch` | `vault_app` | a vault with `appheight` 0 |
| -1 | `the APP branch opens at height` | `vault_app` | a vault before `appheight` |

## Example flow (regtest, three nodes A, B, C)

```
A: set_create '{"seats":3,"unlockthreshold":2,"cancelthreshold":1,"slashthreshold":2,"maturity":8}'
   -> {"setid": S, "admitkey": K}                                   ; mine 1
A: set_join S 1 <h+500>                       -> complete (A holds the admit key)
B: set_join S 1 <h+500>                       -> {"hex": J, "complete": false}
A: set_signact J S                            -> {"hex": J2, "complete": true}
B: set_sendact J2                                                    ; same for C; mine 1 + maturity
A, B, C: set_heartbeat S                                             ; mine 1
A: vault_lock '{"tag":"TEST","setid":S,"delay":5,"ownerheight":<h+40>,"amount":10,"owner":<pqkeyid>}' -> V
A: vault_buildunlock V '[{"address":"<C addr>","amount":4}]' -> U    ; mine 1 first
B: set_signunlock U -> U1 ; C: set_signunlock U1 -> U2 (complete)
A: vault_send U2                                                     ; mine 1: intent I (4) + re-lock (6)
C: vault_release I            (after 5 blocks)
C: vault_buildcancel I' -> X ; C: set_signcancel X -> X1 ; C: vault_send X1   (a cancel by one member)
(owner) the SLH-DSA owner spend of V' (after ownerheight), signed outside the node until Q5
```

`qa/rpc-tests/vault_rpc.py` runs this flow, a reorg across an act and restart reconciliation.

## Node behaviour behind the RPCs

- `<datadir>/vaults/` commits each connected block (state, undo, tip marker) after the block's
  script checks; `-reindex` wipes it; on start it is reconciled with the active chain
  (disconnected with its own undo, replayed from the block files). Replay needs every block and
  undo file from the activation height, so `-prune` is refused wherever the upgrade has an
  activation height, with or without Yellowback (audit 01/N-1): a node that pruned before its
  network set a height must re-download the chain without `-prune`. Undo records are kept for
  4,096 blocks (`UNDO_KEEP`, `src/vault/db.h`); a crash-time walk-back deeper than that is a wipe
  and replay from the activation height (minutes to hours), as a `VAULT_DB_VERSION` change is
  (audit 07/F-7, 07/F-8); a node killed during a long initial sync with a large `-dbcache` can take
  it too (time, not soundness). After connecting block H the undo of H − 4,095 … H is kept. Live
  reorgs stop at 99 blocks (`MAX_REORG_LENGTH`); an `invalidateblock` that would disconnect a block
  below H − 4,095 stops the node, a plain restart stops again, and `-reindex` (which forgets the
  invalidation) recovers.
- Rules S-0 and V-1's APP clause (2026-10-12) apply to every block from activation, so a regtest,
  devnet or kind chain built by an earlier binary that holds a pre-activation template spend or a
  module-less APP vault fails Reconcile's replay (the error names the cause) and splits from a fresh
  node: restart such a chain from scratch. No public network has an activation height, so mainnet
  and testnet are unaffected. A smaller `-dbcache` flushes the chainstate more often and
  keeps a crash within the walk-back.
- A template input whose coin was created below the activation height is invalid (S-0,
  `bad-txns-vault-preactivation`, audit 01/V-1): a V or I a miner put in a block before the
  rules existed is never a template input, in the mempool, in a block or on replay (which reads
  height 0 for a coin the template-output index does not hold).
- The mempool applies the vault rules for the next block and re-checks vault transactions on
  every tip change; the miner applies acts and the rate limit to a running copy and skips a
  transaction that fails.
- Policy: V and I outputs are standard, and a `YV` OP_RETURN may be up to 1,200 bytes, once the
  upgrade is active at the next block.
- `signrawtransaction` verifies with the upgrade's script flags at the next block, so a template
  input with complete set signatures reports `complete: true`.
