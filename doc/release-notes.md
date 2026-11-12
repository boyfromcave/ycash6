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
`fundrawtransaction` (coin control) is unchanged; `z_shieldcoinbase` from a post-quantum address now points to
`z_sendmany`.

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

