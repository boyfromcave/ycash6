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
  FN-DSA-512) or, as a parameter, by its PQ Yellowback address (`ye…`/`yt…`/`yr…`, 53
  characters). Until the node wallet holds post-quantum keys the owner is named explicitly and
  owner spends are signed outside the node.
- **Amounts** are YEC (decimal) like every other Ycash RPC, the set's rate fields
  (`lockedvalue`, `epochbasis`, `epochused`, `unlockavailable`) and `bondmin` included, although
  the set state stores zatoshi (plan §15.4); `valuezat` fields are zatoshi.
- **Fees**: every transaction these RPCs build pays a flat 10,000 zatoshi from the wallet's
  confirmed transparent P2PKH coins (change to a new wallet address). Coins chosen are locked in
  the wallet (`lockunspent` semantics) so that a following build does not reuse them before the
  first transaction confirms.
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
- `Member` = `{"key": key, "status": "active"|"removed"|"ejected"|"withdrawn", "current": bool, "live": bool, "joinheight": height, "lastact": height, "bondoutpoint": outpoint, "bondvalue": yec, "bondlocktime": height, "bondfrozen": bool, "wallet": bool}`
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

## Read RPCs (no wallet needed)

### `vault_getinfo`
Params: `[]`

Result: `{"branchid": str, "activationheight": int, "active": bool, "height": height, "dbtip": {"hash": hash, "height": height}|null, "sets"?: int, "vaults"?: int, "intents"?: int, "lockedvalue"?: yec, "statehash"?: hash}`

`branchid` is `"6d5b7a31"`; `activationheight` is -1 if unscheduled; `active` is at the next
block; `height` is the tip. `dbtip` is the block the set state is at (null before the first
active block). `statehash` is SHA256d over every state record (sets, members, bonds, the
template-output index) in key order: two nodes on the same chain report the same value. The
counts, `lockedvalue` and `statehash` are absent only when the vault database is not open.

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
`released`, and `memberlist` (`wallet`: this wallet holds the key). Predicates are evaluated at
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
`bondlockmin` 0, `maturity` 0, `admitkey` a new wallet key. Funded, signed, broadcast. The set
exists from the block after the one it confirms in.

### `set_join "setid" bondamount bondlocktime ( "memberkey" )`
Params: `["setid": hash, "bondamount": yec, "bondlocktime": height, "memberkey"?: key]`

Result: `{"txid"?: hash, ...ActResult, "memberkey": key, "bondoutpoint": outpoint}`

Builds the `SET_JOIN` with the bond `P2SH(<bondlocktime> CLTV DROP <memberkey> CHECKSIG)` at
`vout 0`, adds the member's signature and whatever admission signatures this wallet holds (the
admit key while the set has fewer than `slashthreshold` current members, current members'
keys after that; none for an open set). Complete → signed and broadcast (`txid` present);
otherwise the partially signed `hex` is returned.

### `set_heartbeat "setid" ( "memberkey" )`
Params: `["setid": hash, "memberkey"?: key]`

Result: `{"txid": hash, "memberkey": key}`

A `SET_HEARTBEAT` for a current member key of this wallet (default: the first), broadcast.

### `set_buildact "type" {params}`
Params: `["type": ActType, "params": {"setid"?: hash, "memberkey"?: key, "bondamount"?: yec, "bondlocktime"?: height, "burn"?: bool, "prevout"?: outpoint, "rolea"?: int, "sighasha"?: hash, "siga"?: hex, "roleb"?: int, "sighashb"?: hash, "sigb"?: hex, "seats"?: int, "unlockthreshold"?: int, "cancelthreshold"?: int, "slashthreshold"?: int, "open"?: bool, "ratelimitbps"?: int, "ratewindow"?: int, "livenesswindow"?: int, "bondmin"?: yec, "bondlockmin"?: int, "maturity"?: int, "admitkey"?: key}]`

Result: `ActResult`

An unsigned, funded act transaction. Types and params: `create` (as `set_create`), `join`
(`setid`, `bondamount`, `bondlocktime`, `memberkey` — any key), `heartbeat` (`setid`,
`memberkey`), `remove` (`setid`, `memberkey` = the member removed, `burn` bool: freeze its bond),
`equivocation` (as `set_equivocation`), `winddown` (`setid`). `complete` is false (unless no
signature is needed) and `signatures` 0.

### `set_signact "hex" ( "setid" )`
Params: `["hex": hex, "setid"?: hash]`

Result: `ActResult`

Adds this wallet's act signatures: the member's own first signature (join, heartbeat), then
admission / co-signer signatures up to what the act needs at the next block (a remove never by
its target). The inputs must still be unsigned.

### `set_sendact "hex"`
Params: `["hex": hex]`

Result: `hash`

Signs this wallet's inputs and broadcasts. Result: the txid.

### `set_equivocation {proof}`
Params: `["proof": Proof]`

Result: `hash`

Roles 1 unlock / 2 cancel; sighashes as 32 raw bytes in hex, as `set_signunlock` /
`set_signcancel` report them; signatures 65-byte recoverable. Anyone may submit; the member is
EJECTED and its bond frozen. Result: the txid.

## Vault RPCs (wallet)

### `vault_lock {params}`
Params: `["params": {"tag": str, "setid": hash, "cancelsetid"?: hash, "delay": int, "ownerheight": height, "appheight"?: height, "amount": yec, "owner": pqkeyid}]`

Result: `{"txid": hash, "vout": int, "outpoint": outpoint, "script": hex, "owner": pqkeyid}`

`delay` 1–65535; `cancelsetid` defaults to `setid`, `appheight` to 0 (no APP branch). `owner` is
a pqkeyid or a PQ address (required until the wallet holds post-quantum keys); the former
`ownerkey` is refused. Both sets must be confirmed. `vout` is 0.

### `vault_buildunlock "outpoint" [{"address"|"script", "amount"}, ...]`
Params: `["outpoint": outpoint, "recipients": [Recipient]]`

Result: `{"hex": hex, "intents": [IntentOut], "required": int}`

The UNLOCK spend (selector 1) of a vault: an intent per recipient (exactly one of `address` or
`script`), the remainder re-locked in a byte-identical vault (S-2), fee inputs from this wallet
(unsigned). The rate limit (S-3) is checked when it is sent.

### `set_signunlock "hex"`
Params: `["hex": hex]`

Result: `SetSigResult`

Adds this wallet's current-member signatures over the set-signature message (plan §15.2 step 4)
for the vault's `setid`, up to `unlockthreshold`. Signing two different spends of one outpoint
is provable equivocation: sign only the transaction you mean.
**Sign once:** before handing out a signature the wallet records, in its wallet database, the
role and sighash its members signed for `(setid, prevout)`, and refuses a different role or
sighash for that pair with `set-sign-once` (`RPC_WALLET_ERROR`), across restarts; re-signing the
identical transaction is idempotent. There is no override.

### `vault_buildcancel "intentoutpoint"`
Params: `["intentoutpoint": outpoint]`

Result: `{"hex": hex, "required": int, "cancelsetid": hash, "deadline": height, "intentconfirmed": bool}`

The CANCEL spend (selector 2) of an unmatured intent: its value back into the vault it was
unlocked from (I-2). `deadline` is the last height a cancel can confirm at. An intent still in
the mempool can be cancelled too: its originating vault script is read from the vault coin its
transaction spends, `intentconfirmed` is false and `deadline` assumes the intent confirms in the
next block. The mempool accepts the cancel as the intent's child (a mempool parent counts as
confirming in the next block, so I-2 holds), and both may confirm in one block; a cancel signed
before the intent confirms stays valid after it. So a watcher can build and sign a cancel the
moment an intent appears. Called again for the same intent it returns the same transaction
(mempool or confirmed) while its fee inputs are unspent (remembered in memory until restart), so
every member signs one sighash.

### `set_signcancel "hex"`
Params: `["hex": hex]`

Result: `SetSigResult`

As `set_signunlock`, for the intent's `cancelsetid` and `cancelthreshold`, under the same
sign-once record.

### `vault_send "hex"`
Params: `["hex": hex]`

Result: `hash`

Signs this wallet's inputs of a built vault spend (the template input's scriptSig is kept) and
broadcasts. Result: the txid. The node that funded the spend must send it.

### `vault_release "intentoutpoint" ( "address"|"script" )`
Params: `["intentoutpoint": outpoint, "recipient"?: str]`

Result: `hash`

The RELEASE (selector 1, `nSequence = delay`) of a matured intent, paying its value to the
recipient (an address or a script in hex), fee from this wallet. The intent commits only
`SHA256(recipient script)`, so the recipient is the argument, or a script this node built the
intent for, or one of this wallet's P2PKH scripts. Error `-1` "matures at height h" before
`coinHeight + delay`. Result: the txid.

### `vault_ownerspend "outpoint" "address"`
Params: `["outpoint": outpoint, "address": address]`

Result: `{"txid": hash, "selector": int}`

Spends a vault with its owner key (in this wallet) to `address`, less the fee: selector 2 with
`nLockTime = ownerheight` once the next block is above `ownerheight`, else selector 3 when the
set is released (dormant or wound down). An intent has only selector 3. The owner is a
post-quantum key: until the wallet holds post-quantum keys the command answers `not yet
supported` once the branch is open, and the spend is signed outside the node.

### `vault_app "outpoint" ( [{"address"|"script", "amount"}, ...] )`
Params: `["outpoint": outpoint, "recipients"?: [Recipient]]`

Result: `{"hex": hex, "intents": [IntentOut]}`

The APP spend skeleton (selector 4, `nLockTime = appheight`) with intents and re-lock as
`vault_buildunlock`, fee inputs unsigned, for a module to complete; send with `vault_send`.

## Error reasons

The error messages a client may match on (a substring of the RPC error's `message`), with their
code. `qa/rpc-tests/vault_rpc_contract.py` provokes each one.

| code | message | raised by | provoked by |
|---|---|---|---|
| -1 | `is not active at the next block` | every act and vault RPC | `set_create` before activation |
| -8 | `the set parameters are out of range` | `set_create`, `set_buildact` | `seats` 16 |
| -5 | `unknown set` | `set_getinfo`, `set_join`, `set_heartbeat`, `set_buildact`, `vault_lock` | `set_getinfo` of a random id |
| -4 | `this wallet holds no current member key of the set` | `set_heartbeat` | a heartbeat for a set with no members |
| -26 | `bad-vault-act-seats` | `set_join`, `set_sendact` | a join to a full set |
| -8 | `unknown act type` | `set_buildact` | type `"bogus"` |
| -8 | `the transaction carries no YV act` | `set_signact`, `set_sendact` | `set_signact` of a vault spend |
| -8 | `kind must be vault or intent` | `vault_list` | `{"kind": "coin"}` |
| -8 | `vault parameters out of range` | `vault_lock` | `delay` 0 |
| -8 | `ownerkey-removed` | `vault_lock` | the former `ownerkey` parameter |
| -8 | `owner (pqkeyid or PQ address) is required` | `vault_lock` | no `owner` |
| -8 | `unregistered post-quantum scheme` | `vault_lock`, `vault_list` | an `owner` with scheme `03` |
| -4 | `not yet supported` | `vault_ownerspend` | an open owner branch (the wallet holds no PQ keys) |
| -8 | `not an unspent vault output` | `vault_buildunlock`, `vault_app` | a spent vault outpoint |
| -8 | `the recipients' amounts exceed the vault's value` | `vault_buildunlock`, `vault_app` | more than the vault holds |
| -8 | `the template input is not an intent` | `set_signcancel` | an unlock spend |
| -8 | `the template input is not a vault` | `set_signunlock` | a cancel spend |
| -4 | `set-sign-once` | `set_signunlock`, `set_signcancel` | a second, different unlock of a vault this wallet already signed |
| -8 | `not an unspent intent output` | `vault_buildcancel`, `vault_release` | a released intent |
| -1 | `can no longer be cancelled` | `vault_buildcancel` | an intent past its delay |
| -1 | `matures at height` | `vault_release` | an intent before its delay |
| -1 | `owner branch opens at height` | `vault_ownerspend` | a vault before `ownerheight` |
| -8 | `has no APP branch` | `vault_app` | a vault with `appheight` 0 |
| -1 | `the APP branch opens at height` | `vault_app` | a vault before `appheight` |

## Example flow (regtest, three nodes A, B, C)

```
A: set_create '{"seats":3,"unlockthreshold":2,"cancelthreshold":1,"slashthreshold":2,"maturity":2}'
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
  (disconnected with its own undo, replayed from the block files). A pruned node that lacks the
  undo data of a block after activation cannot replay and asks for `-reindex`.
- The mempool applies the vault rules for the next block and re-checks vault transactions on
  every tip change; the miner applies acts and the rate limit to a running copy and skips a
  transaction that fails.
- Policy: V and I outputs are standard, and a `YV` OP_RETURN may be up to 1,200 bytes, once the
  upgrade is active at the next block.
- `signrawtransaction` verifies with the upgrade's script flags at the next block, so a template
  input with complete set signatures reports `complete: true`.
