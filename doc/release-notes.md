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

Chain value pools by address type (`transparentPools`)
------------------------------------------------------

- **New field.** `getblockchaininfo` and `getblock` (verbosity 1 and 2) carry `transparentPools`: the transparent
  value pool split into `transparent_ecc`, `transparent_pq` (with `pq_by_scheme`), `pq_channel`, `vault` and
  `vault_intent`, plus `vault_by_module` (the YED module's part of the vault entries). The ids match the wallet's
  `z_gettotalbalance` fields. Details: `doc/yellowback-rpc.md`, "`getblock` and `getblockchaininfo`".
- **`valuePools` and `chainSupply` are unchanged**, entries and order alike; `transparentPools.transparent` equals
  `valuePools`' `transparent`. Clients should find pools by `id`, never by position.
- **No reindex.** The figures come from a node-side index under `blocks/valuepools/`. On the first start of this
  build a node fills it once from the block and undo files it has (a read, no validation; progress in the log
  every 10,000 blocks). On mainnet and the shadow testnets the fill starts from a compiled seed at the chain-supply
  checkpoint (height 2,800,000; no output below it is a post-quantum, channel or vault template), so it reads
  about 300,000 blocks; on such a node blocks below the seed report `"monitored": false` (a node that syncs or
  reindexes with this build covers them all). A pruned node that lacks old undo data
  reports `"monitored": false` until it is reindexed. `-reindex` and `-reindex-chainstate` rebuild the index from
  genesis and check the seed on the way. Downgrading ignores the directory.
- **Not a consensus change.** The index is written after a block has passed every check, never rejects a block and
  never stops the node; a failure is logged and the index stops covering the blocks after it.
