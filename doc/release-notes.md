(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Mining: the development-fund donation is opt-in (`-ydf`, default 0)
-------------------------------------------------------------------

- **The default changes from 5 to 0.** After the Ycash Development Fund mandate ends (mainnet height
  2,275,000), a block this node mines pays the whole subsidy and every fee to the miner and carries
  no fund output. A miner who wants to keep donating sets `-ydf=5` (any whole percentage from 0 to
  100 is accepted, as before).
- **Not a consensus change.** Past the mandate a block is valid with or without the fund output;
  `DEFAULT_YDF_FEE_PERCENTAGE` is read by the miner, `getblocksubsidy`, the metrics screen and the
  option check, never by block validation.
- **The mandate period is unchanged:** below the mandate's end (mainnet 2,275,000, testnet 900,000)
  the 5 % output is required by consensus and the miner still pays it whatever `-ydf` says.
- `getblocksubsidy`'s `founders` past the mandate is the share this node's `-ydf` setting donates
  (0 by default); the metrics screen counts the reward the same way.

Inputs spending post-quantum coins name their address
-----------------------------------------------------

- On a `-insightexplorer` node, `getrawtransaction` (verbose `vin[].address`), `getblock` verbosity 2
  and `getblockdeltas` now name the address of an input that spends a post-quantum output, in the
  D-9 form (`sqf…`/`sqs…`, `tqf…`/`tqs…`, `rqf…`/`rqs…`); they carried only `value`/`valueSat` before.
  The insight index keys a spent output by a Hash160 that cannot be inverted, so the node reads the
  address from the spent output and checks it against the index key. No reindex is needed.

Mining: a coinbase for each miner's own address (`getcoinbasetemplatefor`)
--------------------------------------------------------------------------

- **New RPC** `getcoinbasetemplatefor "address" {"previousblockhash": …, "txids": […]}`: a complete
  coinbase that pays `address` (transparent, Sapling or post-quantum) for the block template the
  caller names by its previous block hash and transaction ids. A pool pairs it with the header
  fields and transactions of the `getblocktemplate` reply it holds, so each miner is paid in the
  block it finds, at its own address, shielded addresses included
  (`doc/yellowback-mining.md` §13).
- **The node derives the amount; there is no amount argument.** The address receives the block
  subsidy plus the fee of every named transaction, less the development-fund output this node's own
  coinbase carries at that height (required during the mandate; afterwards the `-ydf` share, 0 by
  default). A reference that no longer holds is refused (`template-stale: …`), and so is a coinbase
  the block has no room for (`coinbase-does-not-fit: …`).
- **Not a consensus change**, and `getblocktemplate` and `submitblock` are untouched: the node
  keeps nothing between calls. The same call, answers and error strings as on ycash-dd.
