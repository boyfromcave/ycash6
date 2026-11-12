(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Wallet follow-ups, second round (beta2)
---------------------------------------

- **No lock outlives a vault transaction (audit L-1).** `vault_lock` "from" a transparent or post-quantum address
  locked the coins of an accepted lock for good (until a restart or `lockunspent true`), so a lock that expired or
  was evicted unmined left them out of `listunspent`, `z_gettotalbalance` and every send. The vault RPCs now record
  an accepted transaction in the wallet at once, as a send does, and keep no coin lock for it: its inputs are spent
  by an unconfirmed transaction while it is in the mempool or the chain, and spendable again when it leaves the
  mempool unmined. The same holds for the coins the default funding picks (`vault_lock` without "from", `set_*`,
  `vault_release`, ...); the Sapling notes of a lock "from" a `ys1…` address, kept locked until a restart once the lock was accepted, are released at the end of the call and kept spent by the recorded transaction. A coin locked with `lockunspent` is never unlocked. The YEC inputs the
  Yellowback wallet locks for a YED transaction (F-1) are handed back within about a second once it is mined or has
  left the mempool unmined; they used to wait for the next YED build.
- **`yed_mint` checks the whole mint before its carrier (YEW-FIX item 5).** A wallet that cannot fund the mint's
  collateral, its fees and its carrier from the source (the default transparent coins, an `s1…` "from" or a `ys1…`
  "from") is refused before anything is broadcast: `insufficient-yec: the mint needs <total> YEC (collateral <c>,
  fees <f> with its carrier's), checked before its carrier is broadcast; nothing was sent: need …, have …`. It used
  to broadcast the carrier and fail at the MINT.
- **`z_validateaddress` answers for a post-quantum address (audit L-4).** It said `isvalid: false`; it now gives
  ``address_type` (and the deprecated `type`) "pq"`, `ismine`, and `validateaddress`'s `pqscheme`, `pqschemename` and `pqkeyhash`. Its answers for
  Sprout, Sapling, unified, P2PKH and P2SH addresses are unchanged.
- **Help signatures.** The first help line of `getnewaddress`, `signrawtransaction` (`branchid`), `stop` (`detach`,
  ignored), `yed_getbalance` and `yed_listunspent` (an ignored argument), `z_listoperationids` (`status`) and
  `zcbenchmark` (its third argument) now names every argument the call accepts.

Post-quantum addresses show their scheme (D-9, `rpcversion` 9)
-------------------------------------------------------------

- **New prefixes.** A post-quantum address now names its signature scheme in its third character:
  `sqf…` (FN-DSA-512, Falcon) and `sqs…` (SLH-DSA-SHA2-128s) on mainnet, `tqf…`/`tqs…` on testnet,
  `rqf…`/`rqs…` on regtest; the YED form is `ybf…`/`ybs…` (mainnet), `ytf…`/`yts…`, `yrf…`/`yrs…`. Still 53
  characters. The key, the script it pays and every balance are unchanged: only the text differs.
- **The earlier text form is no longer accepted.** An address in the form used before this release
  (`sq…`/`tq…`/`rq…` or `yb…`/`yt…`/`yr…` at 53 characters, whose third character did not name the scheme) is
  refused by `sendtoaddress`, `validateaddress`, `yed_send` and every other RPC. Get the new string for a key
  you already hold with `listreceivedbyaddress 0 true` (or `getaddressesbyaccount ""` where
  `-allowdeprecated=accounts` is set; the wallet lists it in the new form); for a key in a
  wallet dump, `z_importpqkey` with the dump's whole `pqseed=` line returns it (`address`). The one exception:
  `z_importpqkey` still accepts a dump line whose `addr=`/`yecaddr=` are in the earlier form, so old dumps import.
- **Wallets upgrade their address book once.** A wallet's post-quantum address-book entries written by an
  earlier build are rewritten under the new form at the first start (labels kept; logged once).
- **Nothing prints the earlier form.** A wallet or data directory carried over from an earlier build shows its
  post-quantum addresses only in the new form, in every RPC result and in the address book; the keys, coins,
  balances and the address index are untouched (they are keyed by the key hash, not by the text). Going back to an
  earlier build after the first start is not supported for the address book: that build cannot read the rewritten
  entries, so it shows the post-quantum addresses (in the earlier form) without their labels, while keys and coins
  stay spendable. Keep a backup of `wallet.dat` from before the upgrade if you may need to go back.
- **`rpcversion` 9.** `yed_getinfo.params.pqAddressVersion` and `.params.pq.plainAddressVersion` were hex
  strings and are now objects keyed by scheme number (`{"1": "<hex>", "2": "<hex>"}`), one 3-byte version
  each. Clients that build or check post-quantum addresses must read them this way or use
  `src/test/data/pq_address_vectors.json`.

`sendtoaddress` and `sendmany` spend ordinary (ECC) coins only
--------------------------------------------------------------

They never select a post-quantum coin (beta2, audit M-1; they used to, and sent its change to a new ECC key); a
post-quantum coin is spent with `z_sendmany` from its post-quantum address, which returns the change to it and signs
with no wallet lock held. When the ECC coins do not cover the amount and the wallet holds post-quantum coins,
the call is refused with `Insufficient funds in ordinary transparent addresses; this wallet also holds <amount>
YEC at post-quantum addresses: send from one with z_sendmany, which returns the change to it`.
`z_shieldcoinbase` from a post-quantum address now points to `z_sendmany`.

`fundrawtransaction` adds ordinary (ECC) coins only (beta2 review LOW-1): a post-quantum input stays only when
the transaction already names it; with too few ECC coins it is refused with the message above.

The amount in that refusal counts only post-quantum coins `z_sendmany` would spend (confirmed, FN-DSA only once
Falcon is active, no Yellowback outpoint); when every one is a Yellowback outpoint the Yellowback refusal naming
them is given instead. A coinbase shortfall is added to the message (`; its coinbase funds can only be spent
after they have been sent to a zaddr`) instead of hiding it (review LOW-2, LOW-3).

Where Yellowback is not live (no YED attestor set configured for the network; `-yellowback=0` does not turn a
configured Yellowback off, it only acknowledges a leftover index or a wallet that has held YED), no coin-selecting
send spends an output the Yellowback rules give YED (`sendtoaddress`, `sendmany`, `sendfrom`, the coins
`fundrawtransaction` adds, `z_sendmany`, `z_mergetoaddress`, the vault fee funding, `vault_lock "from"`), whether or not
the wallet carries the "has held YED" mark: a wallet restored from its seed phrase where Yellowback is not live has no
mark and was not protected before (beta2 item 9). The wallet recognises such an output from its transaction alone, with
no index: a MINT's vault and token outputs, the outputs a TRANSFER or REDEEM payload assigns, and for a claim cancel
(CANCEL_COSIGN) the re-created vault and every output that can be its refund token (the refund goes to a holder only
the index records, so each non-zero output at index 1 or above that is the first to pay its script is counted: the
cancel's own YEC change is treated as YED too). The same list pre-locks this wallet's outputs of a transaction the index
has not judged yet where Yellowback is live (the claim cancel's refund was missing from it: an unconfirmed refund could
be spent). The stock sends leave such an output out and, short of funds, say so: `Insufficient funds; this wallet also
holds <n> output(s) that may carry YED, which no send spends as plain YEC while Yellowback is not live: <txid>:<n>[, …]
(its transaction's payload may give it YED, which would burn; to spend it deliberately, name the outpoint in a raw
transaction)`; the others refuse with `refusing to spend an output that may carry YED as plain YEC while Yellowback is
not live: <txid>:<n>[, …] (its transaction's payload may give it YED, which would burn; to spend it deliberately, name
the outpoint in a raw transaction)`. Because the check reads only the transaction, it is conservative: an output a
payload names that the index would not have given YED (an invalid or over-assigned transfer, a payment from a third
party in a transaction that carries a copied payload, a claim cancel's YEC change) is kept out of every coin-selecting
send for good where Yellowback is not live (there is no index to judge it); such an output is spent by a raw
transaction, or `fundrawtransaction`, that names it. Where Yellowback is live the same reading applies only until the
index judges the transaction (unconfirmed, its block above the index tip, a disconnected block, any transaction while
the index is unhealthy): those outputs are pre-locked and refused with `refusing to spend an output that may carry YED
as plain YEC before the Yellowback index judges its transaction: <txid>:<n>[, …] (…)`. Once the index has applied the
transaction's block, its own records decide: an output it gave YED stays locked, and every other output is released and
spendable, including the outputs of a transaction that carries a payload but touched no Yellowback state (before, such a
payment stayed locked, and after a restart a send that selected it was refused). `sendrawtransaction` without
`allowyedburn` reads the same way: besides this wallet's YED tokens it now counts an output of this wallet that the
index has not judged and whose transaction's payload may give it YED (before, an unconfirmed incoming YED output could
be burned by a raw transaction with no flag); when the amount is unknown (a claim cancel's refund before its block is
judged) it refuses with `yed-burn-refused: this transaction spends output(s) of this wallet whose transaction the
Yellowback index has not judged yet and whose payload may give them YED (<outpoints>); whatever YED they carry would be
destroyed. Pass allowyedburn = true to send it anyway.`

`vault_send` and `set_sendact` refuse a coin named by `allowinputs` that is a Yellowback outpoint (a YED token,
vault or carrier of this wallet), with the Yellowback refusal; a deliberate burn goes through
`sendrawtransaction … allowyedburn` (beta2 audit L-3).

`vault_lock "from"`: `from: not an address of this wallet` and `from: an FN-DSA-512 (scheme 2) address cannot be
spent before Falcon is active at the next block` now answer -5 (`RPC_INVALID_ADDRESS_OR_KEY`), the code
`z_sendmany` gives the same conditions (were -4 and -8; beta2 audit L-5).

The vault RPCs release the coins their default funding locked when the call fails for any reason (an unknown
`setid`, a signing failure, a conflicting build, a refused broadcast), and only those: a coin locked with
`lockunspent` is never released (beta2 review LOW-4). Two coins stay locked as before: a fee input of a remembered build that
`vault_refee` re-locks after a failed re-funding, and the fee coins of a build returned by `rebuild=true` after
this wallet signed the earlier one (locked until spent, released with `lockunspent`, or a restart). The coinbase refusal of that funding names the full route:
`z_shieldcoinbase, then z_sendmany to a transparent address, or vault_lock "from" the shielded address` (LOW-5).

`getbalance … asOfHeight` counts each transaction afresh at that height: it no longer reads, or writes, the
per-transaction credit cache, which holds the tip's value (upstream wrote the past value into it, so a later
plain `getbalance` could count a coin spent since that height; beta2 review LOW-8).

`walletconfirmbackup` accepts its optional `acknowledge_imports` argument (its argument-table row allowed none,
so a wallet with imported keys under `-walletrequirebackup` could never confirm its backup; beta2 item 14).

Post-quantum addresses show their scheme (D-9, `rpcversion` 9)
-------------------------------------------------------------

- **New prefixes.** A post-quantum address now names its signature scheme in its third character:
  `sqf…` (FN-DSA-512, Falcon) and `sqs…` (SLH-DSA-SHA2-128s) on mainnet, `tqf…`/`tqs…` on testnet,
  `rqf…`/`rqs…` on regtest; the YED form is `ybf…`/`ybs…` (mainnet), `ytf…`/`yts…`, `yrf…`/`yrs…`. Still 53
  characters. The key, the script it pays and every balance are unchanged: only the text differs.
- **The earlier text form is no longer accepted.** An address in the form used before this release
  (`sq…`/`tq…`/`rq…` or `yb…`/`yt…`/`yr…` at 53 characters, whose third character did not name the scheme) is
  refused by `sendtoaddress`, `validateaddress`, `yed_send` and every other RPC. Get the new string for a key
  you already hold with `listreceivedbyaddress 0 true` (or `getaddressesbyaccount ""` where
  `-allowdeprecated=accounts` is set; the wallet lists it in the new form); for a key in a
  wallet dump, `z_importpqkey` with the dump's whole `pqseed=` line returns it (`address`). The one exception:
  `z_importpqkey` still accepts a dump line whose `addr=`/`yecaddr=` are in the earlier form, so old dumps import.
- **Wallets upgrade their address book once.** A wallet's post-quantum address-book entries written by an
  earlier build are rewritten under the new form at the first start (labels kept; logged once).
- **Nothing prints the earlier form.** A wallet or data directory carried over from an earlier build shows its
  post-quantum addresses only in the new form, in every RPC result and in the address book; the keys, coins,
  balances and the address index are untouched (they are keyed by the key hash, not by the text). Going back to an
  earlier build after the first start is not supported for the address book: that build cannot read the rewritten
  entries, so it shows the post-quantum addresses (in the earlier form) without their labels, while keys and coins
  stay spendable. Keep a backup of `wallet.dat` from before the upgrade if you may need to go back.
- **`rpcversion` 9.** `yed_getinfo.params.pqAddressVersion` and `.params.pq.plainAddressVersion` were hex
  strings and are now objects keyed by scheme number (`{"1": "<hex>", "2": "<hex>"}`), one 3-byte version
  each. Clients that build or check post-quantum addresses must read them this way or use
  `src/test/data/pq_address_vectors.json`.

`z_sendmany` and `z_mergetoaddress` move plain YEC between every address type
------------------------------------------------------------------------------

`z_sendmany` now pays post-quantum (`sq…`) recipients and spends from an `sq…` address, alone or mixed
with ECC (`s1…`) and Sapling (`ys1…`) parties; `z_mergetoaddress` merges a named `sq…` address's coins and
pays an `sq…` destination (beta2 D-2, D-4, D-6; quantum spec A-15 reversed). A PQ party is a transparent
party for the privacy policy. PQ change returns to its source address. The fee of a transaction with a PQ
input is priced on its size and is never below the ZIP-317 conventional fee. `z_shieldcoinbase` still
refuses a PQ source. Details, limits and error strings: `doc/yellowback-rpc.md`.

`z_getbalance` refuses an address the wallet does not hold; post-quantum keys filed when paid
-------------------------------------------------------------------------------------------

`z_getbalance` refuses a transparent address the wallet does not hold (ECC or post-quantum: no key and no watch-only
script) with `From address does not belong to this node, transparent or post-quantum key or watch-only script not
found.` (`RPC_INVALID_ADDRESS_OR_KEY`); a watch-only address still answers, and a foreign shielded address is refused
with `From address does not belong to this node, spending key or viewing key not found.`. A post-quantum key of the
wallet that receives a `TX_PQPKH` output without an address-book entry is filed (purpose `receive`), so a seed-only
restore treats its receipts as receipts, not change; a fresh YED holder key is filed when drawn. Where Yellowback is
live, `listreceivedbyaddress`, `listaddresses` and `validateaddress` mark a YED holder key with `"yed_holder": true`.

