(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

`sendtoaddress` and `sendmany` spend ordinary (ECC) coins only
--------------------------------------------------------------

They never select a post-quantum coin (beta2, audit M-1; they used to, and sent its change to a new ECC key); a
post-quantum coin is spent with `z_sendmany` from its `sq…` address, which returns the change to it and signs
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

Where Yellowback is not live (`-yellowback=0`, or no attestor set), no coin-selecting send spends an output its
Yellowback payload gives YED (`sendtoaddress`, `sendmany`, the coins `fundrawtransaction` adds, `z_sendmany`,
`z_mergetoaddress`, the vault fee funding), whether or not the wallet carries the "has held YED" mark: a wallet
restored from its seed phrase where Yellowback is not live has no mark and was not protected before. The stock
sends leave such an output out; the others refuse with `refusing to spend an output that carries YED as plain YEC while Yellowback is not live:
<txid>:<n>[, …] (its YED would burn; to destroy it deliberately, name the outpoint in a raw transaction)` (beta2
item 9).

`vault_send` and `set_sendact` refuse a coin named by `allowinputs` that is a Yellowback outpoint (a YED token,
vault or carrier of this wallet), with the Yellowback refusal; a deliberate burn goes through
`sendrawtransaction … allowyedburn` (beta2 audit L-3).

`vault_lock "from"`: `from: not an address of this wallet` and `from: an FN-DSA-512 (scheme 2) address cannot be
spent before Falcon is active at the next block` now answer -5 (`RPC_INVALID_ADDRESS_OR_KEY`), the code
`z_sendmany` gives the same conditions (were -4 and -8; beta2 audit L-5).

The vault RPCs release the coins their default funding locked when the call fails for any reason (an unknown
`setid`, a signing failure, a conflicting build, a refused broadcast), and only those: a coin locked with
`lockunspent` is never released (beta2 review LOW-4). The coinbase refusal of that funding names the full route:
`z_shieldcoinbase, then z_sendmany to a transparent address, or vault_lock "from" the shielded address` (LOW-5).

`getbalance … asOfHeight` counts each transaction afresh at that height: it no longer reads, or writes, the
per-transaction credit cache, which holds the tip's value (upstream wrote the past value into it, so a later
plain `getbalance` could count a coin spent since that height; beta2 review LOW-8).

`walletconfirmbackup` accepts its optional `acknowledge_imports` argument (its argument-table row allowed none,
so a wallet with imported keys under `-walletrequirebackup` could never confirm its backup; beta2 item 14).

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

