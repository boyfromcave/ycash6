(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

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

