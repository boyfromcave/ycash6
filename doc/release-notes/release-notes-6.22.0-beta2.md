ycashd v6.22.0-beta2 — the vault upgrade and Ycash Yellowback (YED), beta 2
===========================================================================

This is a **beta** for testing, not for production. It is ycashd 6.20.0 (the Ycash rebase onto the
Zcash 6.x line) with a proposed Ycash network upgrade, **the vault upgrade** (consensus branch ID
`0x6d5b7a31`), and Ycash Yellowback (YED), the one rule module built on it: lock YEC in a vault to
mint YED (`1 YED = 1 US dollar`), return the YED to get the YEC back.

The vault upgrade and Yellowback are proposed, not adopted by the Ycash Foundation, and not
audited. `doc/release-notes/release-notes-6.22.0-rc1.md` describes what they add; `doc/vault-rpc.md`
and `doc/yellowback-rpc.md` list the RPCs.

The tag `v6.22.0-beta1` exists, but its release run failed before any package was published. These
notes list what changed since that tag. This release changes no consensus rule: every change is in
the wallet, the RPCs, the address text and the build.

Networks
--------

- **Mainnet**: no activation height is set. This node runs mainnet as a normal Ycash node; nothing
  of the vault upgrade or Yellowback is active there.
- **Testnets**: three shadow-fork testnets, chosen with `-testnet -testnetprofile=<profile>`
  (`doc/yellowback-testnet-shadow-fork.md`):
  - `fast` (`testnet-yb-fast`, P2P port 18833, RPC port 18832): the vault upgrade activates at
    height 510400;
  - `slow` (`testnet-yb-slow`, P2P 18933, RPC 18932): no Vault activation height yet;
  - `legacy` (`testnet-legacy`, P2P 19033, RPC 19032): never activates Vault.
- **Testnet peers**: this build has no testnet seed addresses compiled in. Seed nodes run at
  `fastnet-seed.ycash.team`, `slownet-seed.ycash.team` and `legacy-seed.ycash.team`; name the one
  for your profile with `-addnode=<host>`.
- **Regtest**: `-regtest -nuparams=6d5b7a31:<h>` activates the upgrade at `<h>`
  (`doc/yellowback-devnet.md`).

Before you upgrade
------------------

- **Back up `wallet.dat`.** At its first start this build rewrites the wallet's post-quantum
  address-book entries in the new address form (below). An earlier build cannot read the rewritten
  entries: it still shows the keys and coins, but without their labels.
- **Clients must speak RPC contract version 9.** `yed_getinfo.rpcversion` is 9. lightwalletd-dd and
  YEW require the exact version. See "Post-quantum addresses show their scheme".
- **`sendtoaddress`, `sendmany`, `sendfrom` and `fundrawtransaction` no longer spend post-quantum
  coins.** Spend them with `z_sendmany` from their address. See below.
- **Do not leave `-yellowback=0` in a configuration file.** It only acknowledges that a wallet that
  has held YED may spend its YED outputs as plain YEC. See "The has-held-YED guard".

Changes since beta 1
--------------------

### Send YEC between every address type

- `z_sendmany` takes an ECC (`s1…`), Sapling (`ys1…`) or post-quantum from address, and any mix of
  ECC, Sapling and post-quantum recipients.
- A post-quantum from address spends only its own coins. Its change returns to the same address.
- The fee of a transaction with a post-quantum input is priced on its size: about 27,000 zat for one
  SLH-DSA input and 5,500 zat for one FN-DSA-512 input. A lower default fee is raised to it; an
  explicit fee below it is refused with `Fee <x> is below the <y> this post-quantum spend needs`.
- At most 100 post-quantum inputs fit one transaction.
- `ANY_TADDR` still selects ECC coins only.
- `z_mergetoaddress` merges a named post-quantum address's coins (at most 100 inputs per call) and
  pays a post-quantum destination.
- **Privacy policy**: a post-quantum party counts as a transparent party. The default
  `LegacyCompat` allows every direction. Under a stricter policy, Sapling → post-quantum needs
  `AllowRevealedRecipients`, and post-quantum → Sapling needs `AllowRevealedSenders`
  (`AllowFullyTransparent` when the send has change).
- Limits and every error string: `doc/yellowback-rpc.md`.

### `sendtoaddress`, `sendmany`, `sendfrom` and `fundrawtransaction` spend ECC coins only

This is the beta2 decision, confirmed by the Yellowback lead architect on 2026-11-12: the stock
transparent sends are the ECC calls, and `z_sendmany` is the road for every coin type.

- `sendtoaddress`, `sendmany` and `sendfrom` never select a post-quantum coin. In beta 1 they did,
  and sent the change to a new ECC key.
- `fundrawtransaction` adds ECC coins only. A post-quantum input stays only when the transaction
  already names it.
- When the ECC coins do not cover the amount and the wallet holds post-quantum coins, the call is
  refused with `Insufficient funds in ordinary transparent addresses; this wallet also holds
  <amount> YEC at post-quantum addresses: send from one with z_sendmany, which returns the change
  to it`. The amount counts only coins `z_sendmany` would spend (confirmed, FN-DSA-512 only once
  Falcon is active, no Yellowback outpoint); when every one is a Yellowback outpoint, the
  Yellowback refusal naming them is given instead. A coinbase shortfall is added to the message:
  `; its coinbase funds can only be spent after they have been sent to a zaddr`.
- Spend a post-quantum coin with `z_sendmany` from its address; its change returns to that address.
  Funds spread over several post-quantum addresses: merge them first with `z_mergetoaddress`, or
  send from each address in turn.
- `z_shieldcoinbase` from a post-quantum address is refused with `z_shieldcoinbase cannot spend
  from a post-quantum address; use z_sendmany`.
- Not changed by this rule: `z_sendmany` / `z_mergetoaddress` from a post-quantum address,
  `vault_lock "from"` a post-quantum address, the `yed_*` YEC funding (which can still select
  post-quantum coins), inputs a raw transaction names.

### Fund a vault from any address type

- `vault_lock` takes an optional `"from"`: an ECC, post-quantum or Sapling address of this wallet.
  Change returns to it. Without `"from"` the funding is unchanged.
- `yed_mint`'s funding address is unchanged (ECC or Sapling).

### Balances and listings by address type

- `z_gettotalbalance` adds `transparent_ecc`, `transparent_pq` and `pq_by_scheme`.
- `getwalletinfo` adds `balance_ecc`, `balance_pq`, `unconfirmed_balance_ecc`,
  `unconfirmed_balance_pq` and `pq_by_scheme`.
- Existing fields keep their meaning.
- `listreceivedbyaddress` adds `pqscheme` and `pqschemename` to a post-quantum address.
  `listaddresses` has a `pq` list with the same fields.
- `z_getbalance` now takes a post-quantum address of either scheme.
- A post-quantum key of this wallet is filed in the address book (purpose `receive`) when it is
  first paid, so a seed-only restore treats its receipts as receipts, not change. A vault, intent or
  channel owner key stays out. Keys paid before this release are filed once when the wallet
  loads. Where Yellowback is live, `listreceivedbyaddress`, `listaddresses`
  and `validateaddress` mark a YED holder key with `"yed_holder": true`.
- `z_validateaddress` answers for a post-quantum address. It said
  `isvalid: false`; it now gives `address_type` (and the deprecated `type`) `"pq"`, `ismine`, and
  `validateaddress`'s `pqscheme`, `pqschemename` and `pqkeyhash`.

### Post-quantum addresses show their scheme (D-9, `rpcversion` 9)

- A post-quantum address names its signature scheme in its third character. Mainnet: `sqf…`
  (FN-DSA-512) and `sqs…` (SLH-DSA-SHA2-128s) for YEC, `ybf…` and `ybs…` for YED. Testnet: `tqf`,
  `tqs`, `ytf`, `yts`. Regtest: `rqf`, `rqs`, `yrf`, `yrs`. Still 53 characters.
- The key, the script it pays and every balance are unchanged. Only the text differs.
- **The earlier form is refused** by every RPC. To get the new string for a key you hold, use
  `listreceivedbyaddress 0 true`. For a key in a wallet dump, `z_importpqkey` with the dump's whole
  `pqseed=` line returns it. `z_importpqkey` still accepts a dump line whose `addr=`/`yecaddr=` are
  in the earlier form.
- `yed_getinfo.params.pqAddressVersion` and `.params.pq.plainAddressVersion` change from hex strings
  to objects keyed by scheme number (`{"1": "<hex>", "2": "<hex>"}`), one 3-byte version each.
  `rpcversion` is 9.
- The address index needs no reindex: it is keyed by the key hash, not the text.
- Test vectors: `src/test/data/pq_address_vectors.json`.

### Keeping YED from being spent as plain YEC

Yellowback is **live** where the vault upgrade and a YED attestor set are configured for the network
(regtest: `-yellowbackattestorset`). `-yellowback=0` does not turn a configured Yellowback off; it
only acknowledges a leftover index or a wallet that has held YED.

- Where Yellowback is live, every send that selects coins itself (`z_sendmany`, `z_mergetoaddress`,
  `sendtoaddress`, `sendmany`, `vault_lock "from"`, the vault fee funding) leaves out a coin that
  the Yellowback index knows as a YED token, vault or carrier. This holds even when its coin lock
  was removed with `yed_unlockcoin`. Naming one is refused with `refusing to spend a Yellowback
  outpoint as plain YEC: <txid>:<n> (its YED would burn; lock it again with yed_lockcoins)`.
- While the Yellowback index is unhealthy, a send from a post-quantum address is refused.
- **Outputs the index has not judged yet.** An output of this wallet in a
  transaction the index has not judged (unconfirmed, its block above the index tip, a disconnected
  block, or any transaction while the index is unhealthy) is read by the transaction's own
  Yellowback payload: a MINT's vault and token, the outputs a TRANSFER or REDEEM assigns, and for a
  claim cancel the re-created vault and every output that can be its refund token. Such an output
  is locked and refused with `refusing to spend an output that may carry YED as plain YEC before
  the Yellowback index judges its transaction: <txid>:<n>[, …] (its transaction's payload may give
  it YED, which would burn; wait for its block to be judged, or name the outpoint in a raw
  transaction sent with allowyedburn)`. Once the index has judged the block, its own records
  decide: an output it gave YED stays locked; every other output is released, including a payment
  in a transaction that carries a copied payload but touched no Yellowback state.
- **Blocks below the start height count as judged.** A transaction confirmed
  below the Yellowback start height (the `UPGRADE_VAULT` activation height), which the index never
  evaluates, counts as judged with no YED: a copied payload mined before activation does not keep
  a coin refused.
- **Where Yellowback is not live**, no coin-selecting send spends an output its
  transaction's payload may give YED (`sendtoaddress`, `sendmany`, `sendfrom`, the coins
  `fundrawtransaction` adds, `z_sendmany`, `z_mergetoaddress`, the vault fee funding,
  `vault_lock "from"`), whether or not the wallet carries the has-held-YED mark. The stock sends
  leave such an output out and, short of funds, say `Insufficient funds; this wallet also holds <n>
  output(s) that may carry YED, which no send spends as plain YEC while Yellowback is not live:
  <txid>:<n>[, …] (its transaction's payload may give it YED, which would burn; to spend it
  deliberately, name the outpoint in a raw transaction)`. The others refuse with `refusing to spend
  an output that may carry YED as plain YEC while Yellowback is not live: <txid>:<n>[, …] (its
  transaction's payload may give it YED, which would burn; to spend it deliberately, name the
  outpoint in a raw transaction)`. With no index to judge it, this reading is conservative: a
  claim cancel's own YEC change, or a payment in a transaction that carries a copied payload, is
  kept out of every coin-selecting send for good there; spend it with a raw transaction (or
  `fundrawtransaction`) that names it.
- **The raw-send check.** `sendrawtransaction` without `allowyedburn` now also
  counts an output of this wallet that the index has not judged and whose payload may give it YED,
  at the payload's figure; before, an unconfirmed incoming YED output could be burned by a raw
  transaction with no flag. When the figure is unknown (a claim cancel's refund before its block is
  judged) it refuses with `yed-burn-refused: this transaction spends output(s) of this wallet whose
  transaction the Yellowback index has not judged yet and whose payload may give them YED
  (<outpoints>); whatever YED they carry would be destroyed. Pass allowyedburn = true to send it
  anyway.` The check also acts while the index is unhealthy (before, it then let every raw
  transaction through).
- `vault_send` and `set_sendact` refuse a coin named in `allowinputs` that is a
  YED token, vault or carrier of this wallet, with the Yellowback refusal; a deliberate burn goes
  through `sendrawtransaction … allowyedburn`.

### The has-held-YED guard

- A wallet that has held YED, or issued a YED holder key, carries a mark in `wallet.dat`.
  `getwalletinfo` shows it as `yed_held`.
- Where Yellowback is not live, such a wallet refuses to load: `This wallet has held YED, but
  Yellowback is not live with these options, so its YED outputs cannot be locked. Start with the
  network's attestor set (regtest -yellowbackattestorset) to keep those outputs locked, or with
  -yellowback=0 to acknowledge that they are spendable as plain YEC.`
- With `-yellowback=0` it loads with a warning, shown in `getinfo` `errors` for the life of the
  process, and `getwalletinfo` `yed_unlocked` is true.

### Vault and YEC coin locks

- **No lock outlives a vault transaction.** `vault_lock "from"` a transparent or post-quantum
  address used to lock the coins of an accepted lock until a restart, so a lock that expired or was
  evicted unmined left them out of `listunspent`, `z_gettotalbalance` and every send. The vault RPCs
  now record an accepted transaction in the wallet at once, as a send does, and keep no coin lock
  for it: its inputs count as spent while it is in the mempool or the chain, and are spendable again
  when it leaves the mempool unmined. The same holds for the coins the default funding picks
  (`vault_lock` without `"from"`, `set_*`, `vault_release`, …). The Sapling notes of a lock
  `"from"` a `ys1…` address are released at the end of the call and kept spent by the recorded
  transaction. A pending vault transaction now survives a restart.
- The YEC inputs the Yellowback wallet locks for a YED transaction are handed back within about a
  second once it is mined or has left the mempool unmined (they used to wait for the next YED
  build).
- The default vault funding skips coinbase that must be shielded and releases the coins it locked
  when the call fails for any reason (an unknown `setid`, a signing failure, a conflicting build, a
  refused broadcast). A coin locked with `lockunspent` is never released. Two coins stay locked as
  before: a fee input of a remembered build that `vault_refee` re-locks after a failed re-funding,
  and the fee coins of a build returned by `rebuild=true` after this wallet signed the earlier one.
  The coinbase refusal names the route: `z_shieldcoinbase, then z_sendmany to a transparent
  address, or vault_lock "from" the shielded address`.

### Other wallet changes

- `yed_mint` checks the whole mint before its carrier. A wallet that cannot fund the collateral,
  the fees and the carrier from the source is refused before anything is broadcast:
  `insufficient-yec: the mint needs <total> YEC (collateral <c>, fees <f> with its carrier's),
  checked before its carrier is broadcast; nothing was sent: need …, have …`. It used to broadcast
  the carrier and fail at the MINT. `yed_mint` and its carrier lock the Sapling notes they spend
  until they commit or fail.
- `vault_lock "from"`: `from: not an address of this wallet` and `from: an FN-DSA-512 (scheme 2)
  address cannot be spent before Falcon is active at the next block` now answer -5
  (`RPC_INVALID_ADDRESS_OR_KEY`), as `z_sendmany` does (were -4 and -8).
- `getbalance … asOfHeight` counts each transaction at that height and no longer reads or writes
  the per-transaction credit cache. Before, a later plain `getbalance` could count a coin spent
  since that height.
- `walletconfirmbackup` accepts its optional `acknowledge_imports` argument. Before, a wallet with
  imported keys under `-walletrequirebackup` could not confirm its backup.
- The first help line of `getnewaddress`, `signrawtransaction` (`branchid`), `stop` (`detach`,
  ignored), `yed_getbalance` and `yed_listunspent`, `z_listoperationids` (`status`) and
  `zcbenchmark` names every argument the call accepts. The `getnewaddress` help no longer says that
  the `z_*` calls never pay or spend a post-quantum address.

### Address and help changes

- `getnewaddress` takes the address type first: `getnewaddress pq`, `getnewaddress pqslh`,
  `getnewaddress p2pkh`. `getnewaddress "" pq` still works.
- The RPCs that upstream marks deprecated (`getnewaddress`, `z_getnewaddress`, `z_gettotalbalance`,
  the legacy account calls and others) now say "Supported on Ycash" and why, instead of "is
  DEPRECATED and will be removed". `-allowdeprecated=none` still turns them off.
- `getunconfirmedbalance` can be called. In beta 1 it failed with "Unknown RPC method" because its
  argument-table row was missing.

### Seed-only restore finds transparent coins

- A restore with `-mnemonicfile` now finds the seed's transparent coins: those of the addresses
  `getnewaddress` handed out, and its change and mining keys. It does so as long as no more than
  `-keypool` (default 100) unused addresses in a row were handed out. Restore with the original
  wallet's `-keypool` or larger.
- The restore re-reads the chain until no new key is found. Expect about two reads of the chain from
  genesis on mainnet, more when addresses were used out of order.
- An interrupted restore resumes: every start scans from genesis until a complete scan has finished.
  `getwalletinfo` `restore_in_progress` is true until then. A restore started before the node has the
  chain completes at the first restart after the sync; `getinfo` `errors` then says `Wallet restore
  in progress: restart the node after it has synced to finish scanning for older coins`.
- An encrypted wallet that is locked watches its next `-keypool` + 1 addresses per chain by key ID
  only. `wallet.dat` stores those key IDs in clear, and nothing else from which keys could be
  derived. `getwalletinfo` `lookahead_incomplete` is set when a payment arrives while locked that
  could leave a later payment beyond the watched addresses.
- Recover keys beyond the gap by issuing addresses past it (`getnewaddress`, `getnewaddress pq`,
  `z_getnewaddress`) and restarting with `-rescan`. This line has no `rescanblockchain`.
- Details: `doc/yellowback-release.md`.

### Build and packages

- The Windows package builds again: the `-yellowbacktestfault` crash path ends the process with
  `TerminateProcess` on Windows (there is no `SIGKILL`), and unit-test locals that collided with
  `windows.h` macros (`near`, `far`, `small`) are renamed.
- The `macos_aarch64` package is built on GitHub's `macos-15` runner (`macos-14` is retired).

Defects fixed that were present in beta 1
-----------------------------------------

- **The node could stop after an erased send.** Erasing a wallet transaction (the Yellowback orphan
  removal) left its entries in the spend index. A second send of the same coins then created an
  empty wallet transaction, and the next re-broadcast stopped ycashd on an assertion. No funds were
  at risk. One erase function now clears every index.
- **`getunconfirmedbalance` could not be called** (see above).
- **A seed-only restore missed transparent coins.** Every coin paid to a `getnewaddress` address
  after the first was missed.
- **An interrupted seed restore skipped history.** After a stop during the restore, the node resumed
  scanning near the tip.
- **An unconfirmed claim-cancel refund could be spent as plain YEC**, burning its
  YED, because the wallet's pre-lock did not cover it; and where Yellowback is not live, a
  coin-selecting send could burn a cancel's refund token.

Hardened (not a beta 1 defect on this line): a post-quantum send whose fee is above the mempool's
cap is refused before it is signed, and a send the mempool refuses is erased from the wallet, so it
cannot be broadcast again at the next start.

Behaviour changes for existing callers
--------------------------------------

| Call | Before | Now |
|---|---|---|
| `getnewaddress "<non-empty>"` | -8 `dummy first argument must be excluded or set to "".` | the string is read as the type; any other string: -11 `Accounts are unsupported; the first argument is the address type, …` |
| `z_getbalance <post-quantum address>` | -5 `Invalid from address, should be a taddr or zaddr.` | the balance (own address); -5 `From address does not belong to this node, transparent or post-quantum key or watch-only script not found.` (not the wallet's) |
| `z_getbalance <transparent address not in the wallet>` | -5 `From address does not belong to this node.` | -5 with the longer message above |
| `z_sendmany` from or to a post-quantum address | refused | built (see above) |
| a wallet with `yed_held` where Yellowback is not live | loads | refuses to load unless `-yellowback=0` |
| any RPC given a post-quantum address in the earlier form | accepted | -5, invalid address |
| `yed_getinfo` | `rpcversion` 8; `pqAddressVersion` a hex string | `rpcversion` 9; objects keyed by scheme |
| `sendtoaddress`, `sendmany`, `sendfrom`, `fundrawtransaction` | could select post-quantum coins | ECC coins only; refused when only post-quantum coins would cover the amount |
| `z_validateaddress <post-quantum address>` | `isvalid: false` | valid, `address_type` `"pq"` |
| `vault_lock "from"` foreign / FN-DSA-before-Falcon | -4 / -8 | -5 |
| a coin spent by an accepted `vault_*`/`set_*` transaction | locked until restart | spent while the transaction lives; spendable again if it drops |
| `sendrawtransaction` spending an unjudged YED-payload output of this wallet | sent (YED burned) | `yed-burn-refused` without `allowyedburn`, also while the index is unhealthy |

Known limitations
-----------------

- **No YED attestor set on any public network.** YED cannot be minted on the fast testnet with this
  build; Yellowback is live only on regtest with `-yellowbackattestorset`. Sends, balances and
  `vault_lock` work on the fast testnet.
- **A seed restore does not restore the has-held-YED mark.** A wallet restored from its recovery
  phrase on a node where Yellowback is not live loads without the guard, and `listunspent` lists its
  YED outputs as ordinary YEC. The coin-selecting sends leave those outputs out,
  but a raw transaction that names one spends it as plain YEC and burns its YED. Restore a wallet
  that has held YED only on a node where Yellowback is live.
- **`-yellowback=0` with a wallet that has held YED** lets a raw transaction spend a YED output as
  plain YEC, which burns the YED.
- **The mark does not cover** a rescan or key import done where Yellowback is not live, nor a wallet
  last used by a build before this mark existed.
- **A raw spend in the first moment after a YED payment arrives.** The raw-send
  check reads the wallet's own record of the incoming transaction, which the wallet writes a moment
  (normally under a second) after the mempool accepts it. A hand-built raw transaction that spends
  such an output inside that window is not counted.
- **The mint pre-check's figure is for the current coins.** The `need` the
  `insufficient-yec` refusal names includes the fees for the coins it would take now. Topping the
  address up with a new coin adds one more input and its fee, so funding exactly the named figure
  can be refused once more; add a margin.
- **The `yed_*` YEC funding can still spend post-quantum coins** (the ECC-only
  rule covers the stock sends only).
- **The seed-only restore's gap limits.** Transparent keys are found up to `-keypool` unused
  addresses in a row; post-quantum keys up to 20 unused keys per scheme.
- **Wallet encryption is experimental** (`-experimentalfeatures -developerencryptwallet`).
  `getnewaddress` refuses while the wallet is locked.
- No release parameters beyond the fast testnet's activation height; an rc adds them.
- Not for production funds.

Getting started
---------------

1. Download `ycashd_v6.22.0-beta2_<platform>.tar.gz` (Windows: `.zip`) and verify it (below).
   Platforms: `linux_x86_64`, `linux_aarch64`, `macos_aarch64` and `windows`; best effort:
   `ubuntu_18.04_x86_64` and `macos_x86_64`.
2. Unpack it. It holds `ycashd`, `ycash-cli`, `ycash-tx` and `ycashd-wallet-tool`.
3. Run a node:
   - mainnet: `./ycashd`
   - a testnet: `./ycashd -testnet -testnetprofile=fast -addnode=fastnet-seed.ycash.team` (or
     `slow`, `legacy` with their seed host); `-testnet` without a profile is refused.
4. Query it: `./ycash-cli getblockchaininfo` (add the same `-testnet -testnetprofile=<profile>`
   flags for a testnet).
5. On the fast testnet (the vault upgrade is active there), try the new calls:
   `getnewaddress pq`, `z_gettotalbalance`, and
   `z_sendmany <from> '[{"address": "<to>", "amount": 0.1}]'`. On mainnet `getnewaddress pq` is
   refused: post-quantum addresses need the vault upgrade active at the next block.
