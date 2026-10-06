# Vault primitive RPCs (`set_*`, `vault_*`)

<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

The RPC surface of the Ycash vault primitive (`UPGRADE_VAULT`, branch ID `0x6d5b7a31`;
`docs/plans/yellowback-upgrade-plan.md` §3, §15). The primitive is application-agnostic: signer
sets (`set_*`) and vaults / intents (`vault_*`). Yellowback (YED) and the bridge (wYEC) are
applications on top of it; nothing here is YED-specific.

Every node has these RPCs and the set-state database `<datadir>/vaults/`; no flag enables them.
The database is empty until the upgrade activates (regtest: `-nuparams=6d5b7a31:<height>`).

## Conventions

- **Set id**: the txid of the set's `SET_CREATE` transaction, as a txid hex string.
- **Outpoint**: `"txid:n"` or `{"txid": "...", "vout": n}`.
- **Tag**: 1–4 ASCII characters (zero-padded to 4 bytes) or 8 hex digits. `WYEC` is the bridge
  tag; `YED\0` is reserved for the YED module (P4). An unregistered tag is governed by the
  primitive alone.
- **Keys**: 33-byte compressed public keys in hex. RPCs that sign (member, admit and owner
  signatures) use the private key of that public key in **this node's wallet**; where a key
  parameter is optional, a new wallet key is generated.
- **Amounts** are YEC (decimal) like every other Ycash RPC; `valuezat` fields are zatoshi.
- **Fees**: every transaction these RPCs build pays a flat 10,000 zatoshi from the wallet's
  confirmed transparent P2PKH coins (change to a new wallet address). Coins chosen are locked in
  the wallet (`lockunspent` semantics) so that a following build does not reuse them before the
  first transaction confirms.
- **Heights**: unless stated, rules are evaluated at the next block (`tip + 1`) against the set
  state after the tip, exactly as the mempool does (plan U-17).
- **Errors**: RPC error `-8` (invalid parameter), `-5` (unknown set / outpoint / address),
  `-4` (wallet: key not in the wallet, signing failed), `-6` (insufficient funds), `-1` (misc:
  the upgrade is not active, a branch is not open yet), `-26` (rejected by the mempool, with
  `"<code>: <reason>"`, e.g. `"16: bad-vault-act-seats"`), `-25` (missing inputs).

## Read RPCs (no wallet needed)

### `vault_getinfo`
Result: `{"branchid": "6d5b7a31", "activationheight": n (-1 if unscheduled), "active": bool (at
the next block), "height": tip, "dbtip": {"hash","height"} | null, "sets": n, "vaults": n,
"intents": n, "lockedvalue": x, "statehash": "hex"}`. `dbtip` is the block the set state is at
(null before the first active block). `statehash` is SHA256d over every state record (sets,
members, bonds, the template-output index) in key order: two nodes on the same chain report the
same value.

### `set_list`
Every set: the `set_getinfo` fields without `memberlist`.

### `set_getinfo "setid" ( height )`
The set's `SET_CREATE` parameters (`seats`, `unlockthreshold`, `cancelthreshold`,
`slashthreshold`, `open`, `ratelimitbps`, `ratewindow`, `livenesswindow`, `bondmin`,
`bondlockmin`, `maturity`, `admitkey`), `createheight`, `winddownheight` (0 = none), the rate
fields (`lockedvalue`, `epoch`, `epochbasis`, `epochused`, and `unlockavailable` when rate
limited), counts (`members`, `active`, `current`), the §15.4 predicates `dormant` and
`released`, and `memberlist`: `[{"key", "status": active|removed|ejected|withdrawn, "current",
"live", "joinheight", "lastact", "bondoutpoint", "bondvalue", "bondlocktime", "bondfrozen",
"wallet" (this wallet holds the key)}]`. Predicates are evaluated at `height` (default: the
next block) over the state at the tip. Error `-5` for an unknown set.

### `vault_list ( {"tag", "setid", "owner", "kind": "vault"|"intent", "mine": bool} )`
The unspent V and I outputs confirmed since activation (the database's template-output index),
optionally filtered (`setid` matches either set of the template; `mine` = the owner key is in
this wallet). Each entry: `txid`, `vout`, `outpoint`, `kind`, `value`, `valuezat`, `height`,
`script`, the template fields (`tag`, `tagtext`, `setid`, `cancelsetid`, `delay`, `ownerkey`;
V: `ownerheight`, `appheight`; I: `recipienthash`, `vaulthash`, `matureheight`, `mature`,
`cancellable`, `origin` = the script of the vault it was unlocked from), `wallet`.

### `vault_decodescript "hex"`
Decodes a V or I scriptPubKey (`type` `vault` / `intent` with its fields), a `YV` act OP_RETURN
(`type` `act`, the act's own type as `acttype`, the decoded body, `payload`, `signatures`; or `error` with the decode reason), a
bond redeem script (`type` `bond`, `locktime`, `memberkey`, its P2SH `scriptpubkey` and
`address`), `malformed` (a template skeleton with a non-minimal push or out-of-range field), or
`none`.

## Act RPCs (wallet)

Acts are `YV` OP_RETURN outputs (plan §15.5). Their signatures bind the payload and `vin[0]`'s
outpoint, and they are part of the output, so the order is always: **build** (funding fixes
`vin[0]`), **sign the act** (on each signer's node), **sign the inputs and send** (on the node
that funded it).

### `set_create {params}`
Params: `seats` (1–15), `unlockthreshold`, `cancelthreshold` (default 1), `slashthreshold`
(default `unlockthreshold`), `open` (default false), `ratelimitbps` (0 = no limit), `ratewindow`
(default 144), `livenesswindow` (default 1000), `bondmin` (default 1), `bondlockmin` (default 0),
`maturity` (default 0), `admitkey` (default a new wallet key). Funded, signed, broadcast.
Result: `{"txid", "setid", "admitkey"}`. The set exists from the block after the one it confirms in.

### `set_join "setid" bondamount bondlocktime ( "memberkey" )`
Builds the `SET_JOIN` with the bond `P2SH(<bondlocktime> CLTV DROP <memberkey> CHECKSIG)` at
`vout 0`, adds the member's signature and whatever admission signatures this wallet holds (the
admit key while the set has fewer than `slashthreshold` current members, current members'
keys after that; none for an open set). Complete → signed and broadcast (`txid` present);
otherwise the partially signed `hex` is returned. Result: `{"txid"?, "hex", "type", "complete",
"signatures", "required", "memberkey", "bondoutpoint"}`.

### `set_heartbeat "setid" ( "memberkey" )`
A `SET_HEARTBEAT` for a current member key of this wallet (default: the first), broadcast.
Result: `{"txid", "memberkey"}`.

### `set_buildact "type" {params}`
An unsigned, funded act transaction. Types and params: `create` (as `set_create`), `join`
(`setid`, `bondamount`, `bondlocktime`, `memberkey` — any key), `heartbeat` (`setid`,
`memberkey`), `remove` (`setid`, `memberkey` = the member removed, `burn` bool: freeze its bond),
`equivocation` (as `set_equivocation`), `winddown` (`setid`). Result: `{"hex", "type",
"complete": false (unless no signature is needed), "signatures": 0, "required"}`.

### `set_signact "hex" ( "setid" )`
Adds this wallet's act signatures: the member's own first signature (join, heartbeat), then
admission / co-signer signatures up to what the act needs at the next block (a remove never by
its target). The inputs must still be unsigned. Result: as `set_buildact`.

### `set_sendact "hex"`
Signs this wallet's inputs and broadcasts. Result: txid.

### `set_equivocation {proof}`
Proof: `{"setid", "prevout", "rolea", "sighasha", "siga", "roleb", "sighashb", "sigb"}` (roles
1 unlock / 2 cancel; sighashes as 32 raw bytes in hex, as `set_signunlock` / `set_signcancel`
report them; signatures 65-byte recoverable). Anyone may submit; the member is EJECTED and its
bond frozen. Result: txid.

## Vault RPCs (wallet)

### `vault_lock {params}`
`{"tag", "setid", "cancelsetid" (default setid), "delay" (1–65535), "ownerheight", "appheight"
(default 0 = no APP branch), "amount", "ownerkey" (default a new wallet key)}`. Both sets must be
confirmed. Result: `{"txid", "vout": 0, "outpoint", "script", "ownerkey"}`.

### `vault_buildunlock "outpoint" [{"address"|"script", "amount"}, ...]`
The UNLOCK spend (selector 1) of a vault: an intent per recipient, the remainder re-locked in a
byte-identical vault (S-2), fee inputs from this wallet (unsigned). Result: `{"hex", "intents":
[{"vout", "amount", "recipient", "recipienthash"}], "required"}`. The rate limit (S-3) is checked
when it is sent.

### `set_signunlock "hex"`
Adds this wallet's current-member signatures over the set-signature message (plan §15.2 step 4)
for the vault's `setid`, up to `unlockthreshold`. Result: `{"hex", "complete", "signatures",
"required", "sighash", "setsigs": [{"key", "sig"}]}`. Signing two different spends of one
outpoint is provable equivocation: sign only the transaction you mean.

### `vault_buildcancel "intentoutpoint"`
The CANCEL spend (selector 2) of an unmatured intent: its value back into the vault it was
unlocked from (I-2). Result: `{"hex", "required", "cancelsetid", "deadline"}` (`deadline` = the
last height a cancel can confirm at).

### `set_signcancel "hex"`
As `set_signunlock`, for the intent's `cancelsetid` and `cancelthreshold`.

### `vault_send "hex"`
Signs this wallet's inputs of a built vault spend (the template input's scriptSig is kept) and
broadcasts. Result: txid. The node that funded the spend must send it.

### `vault_release "intentoutpoint" ( "address"|"script" )`
The RELEASE (selector 1, `nSequence = delay`) of a matured intent, paying its value to the
recipient, fee from this wallet. The intent commits only `SHA256(recipient script)`, so the
recipient is the argument, or a script this node built the intent for, or one of this wallet's
P2PKH scripts. Error `-1` "matures at height h" before `coinHeight + delay`. Result: txid.

### `vault_ownerspend "outpoint" "address"`
Spends a vault with its owner key (in this wallet) to `address`, less the fee: selector 2 with
`nLockTime = ownerheight` once the next block is above `ownerheight`, else selector 3 when the
set is released (dormant or wound down). An intent has only selector 3. Result: `{"txid",
"selector"}`.

### `vault_app "outpoint" ( [{"address"|"script", "amount"}, ...] )`
The APP spend skeleton (selector 4, `nLockTime = appheight`) with intents and re-lock as
`vault_buildunlock`, fee inputs unsigned, for a module to complete; send with `vault_send`.
Result: `{"hex", "intents"}`.

## Example flow (regtest, three nodes A, B, C)

```
A: set_create '{"seats":3,"unlockthreshold":2,"cancelthreshold":1,"slashthreshold":2,"maturity":2}'
   -> {"setid": S, "admitkey": K}                                   ; mine 1
A: set_join S 1 <h+500>                       -> complete (A holds the admit key)
B: set_join S 1 <h+500>                       -> {"hex": J, "complete": false}
A: set_signact J S                            -> {"hex": J2, "complete": true}
B: set_sendact J2                                                    ; same for C; mine 1 + maturity
A, B, C: set_heartbeat S                                             ; mine 1
A: vault_lock '{"tag":"TEST","setid":S,"delay":5,"ownerheight":<h+40>,"amount":10}' -> V
A: vault_buildunlock V '[{"address":"<C addr>","amount":4}]' -> U    ; mine 1 first
B: set_signunlock U -> U1 ; C: set_signunlock U1 -> U2 (complete)
A: vault_send U2                                                     ; mine 1: intent I (4) + re-lock (6)
C: vault_release I            (after 5 blocks)
C: vault_buildcancel I' -> X ; C: set_signcancel X -> X1 ; C: vault_send X1   (a cancel by one member)
A: vault_ownerspend V' <addr> (after ownerheight)
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
