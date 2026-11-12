(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

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

