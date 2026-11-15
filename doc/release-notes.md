(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Inputs spending post-quantum coins name their address
-----------------------------------------------------

- On a `-insightexplorer` node, `getrawtransaction` (verbose `vin[].address`), `getblock` verbosity 2
  and `getblockdeltas` now name the address of an input that spends a post-quantum output, in the
  D-9 form (`sqf…`/`sqs…`, `tqf…`/`tqs…`, `rqf…`/`rqs…`); they carried only `value`/`valueSat` before.
  The insight index keys a spent output by a Hash160 that cannot be inverted, so the node reads the
  address from the spent output and checks it against the index key. No reindex is needed.
