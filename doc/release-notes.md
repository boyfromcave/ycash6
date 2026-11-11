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
