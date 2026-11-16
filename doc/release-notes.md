(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Next release (beta3), changes since 6.22.0-beta2
------------------------------------------------

- **`gettransaction` shows the real fee for every funding shape.** `fee` was the value out less the
  wallet's transparent debit, so a send funded from Sapling showed the sum of its transparent (ECC
  and post-quantum) outputs as its fee, and a Sapling to Sapling send showed `0`. The fee is now
  the transaction's own, still negative: transparent value in (read from the wallet's records of
  each input's funding transaction) plus shielded value in (Sapling `valueBalance`, Sprout
  `vpub_new`) less transparent outputs and value moved into a shielded pool. It is shown whenever
  an input (transparent, post-quantum or shielded) is the wallet's, as before. `amount` is
  unchanged (upstream's figure), and so are `listtransactions`, `listsinceblock` and `details[]`:
  for a Sapling-funded send the top-level `fee` can differ from `details[].fee`, which counts the
  transparent debit only. When the wallet does not hold the funding transaction of every
  transparent input (a jointly built transaction, or after `-zapwallettxes`), `fee` is left out
  rather than shown too small (it was shown before, wrong). ycash-dd now
  shows the same fee (it showed none for a Sapling-funded send). Display only: balances, coin
  selection and consensus never read these figures. The defect was inherited from upstream zcashd
  (unchanged through 6.20.0).

Mining: the development-fund donation is opt-in (`-ydf`, default 0)
-------------------------------------------------------------------

- **The default changes from 5 to 0.** After the Ycash Development Fund mandate ends (mainnet height
  2,275,000), a block this node mines pays the whole subsidy and every fee to the miner and carries
  no fund output. A miner who wants to keep donating sets `-ydf=5` (any whole percentage from 0 to
  100 is accepted, as before). A value outside that range (`-ydf=-1`, `-ydf=101`) is reset to the
  default, so it now means 0 where it used to mean 5.
- **Not a consensus change.** Past the mandate a block is valid with or without the fund output;
  `DEFAULT_YDF_FEE_PERCENTAGE` is read by the miner, `getblocksubsidy`, the metrics screen and the
  option check, never by block validation.
- **The mandate period is unchanged:** below the mandate's end (2,275,000 on mainnet, testnet-yb-slow
  and testnet-legacy; testnet-yb-fast has its own end, see the next section) the 5 % output is
  required by consensus and the miner still pays it whatever `-ydf` says.
- `getblocksubsidy`'s `founders` past the mandate is the share this node's `-ydf` setting donates
  (0 by default); the metrics screen counts the reward the same way.

Inputs spending post-quantum coins name their address
-----------------------------------------------------

- On a `-insightexplorer` node, `getrawtransaction` (verbose `vin[].address`), `getblock` verbosity 2
  and `getblockdeltas` now name the address of an input that spends a post-quantum output, in the
  D-9 form (`sqf…`/`sqs…`, `tqf…`/`tqs…`, `rqf…`/`rqs…`); they carried only `value`/`valueSat` before.
  The insight index keys a spent output by a Hash160 that cannot be inverted, so the node reads the
  address from the spent output and checks it against the index key. No reindex is needed.

Fast testnet: the development-fund mandate ends (consensus, testnet-yb-fast only)
---------------------------------------------------------------------------------

- **A scheduled rule change on the fast testnet.** The fast profile gets its own mandate end,
  `TESTNET_FAST_YDF_MANDATE_END_HEIGHT`. The tree carries a provisional 600,000, deliberately far
  above the tip so that a build made before the cut stays strict; the final height is set when the
  release candidate is cut (the fast-testnet tip then, plus 400 blocks), and the release guard refuses
  an rc or final tag that still carries 600,000. From that height a fast-testnet block is valid with
  or without the 5 % fund output, as on mainnet since 2,275,000; below it the output stays required.
  Until now the fast profile inherited the 900,000 of the original Ycash testnet, about 389,000 blocks
  away.
- **Every fast-testnet node must run this build before the chain reaches the height.** A node on an
  earlier build rejects the first block without the fund output and stops following the chain. It
  also bans the peer that sent the block (24 hours, kept in `banlist.dat`), so a node upgraded late
  needs `clearbanned` after the upgrade to reconnect to its peers.
- **The safe setting while nodes upgrade:** a pool that sets `-ydf=5` mines blocks that every build
  accepts (the 5 % output stays valid after the height). Keep it until every node has upgraded.
- Mainnet, the slow and legacy testnet profiles and regtest are unchanged.

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
  about 300,000 blocks: **startup waits about 30 seconds on a mainnet node** (28.5 s measured on 2026-11-15 on a
  copy of a mainnet data directory at height 3,100,949, on a loaded Apple M-series laptop; a fill from genesis took
  726 s). Until the fill ends the RPC server answers -28 (warming up) with the fill's progress. The seed was checked
  once against a fill from genesis on that copy (`valuepools: the compiled seed at height 2800000 matches the
  totals computed from genesis`). On such a node blocks below the seed report `"monitored": false` (a node that syncs or
  reindexes with this build covers them all). A pruned node that lacks old undo data
  reports `"monitored": false` until it is reindexed. `-reindex` and `-reindex-chainstate` rebuild the index from
  genesis and check the seed on the way. Downgrading ignores the directory.
- **Not a consensus change.** The index is written after a block has passed every check and never rejects a block; a
  failure is logged and the index stops covering the blocks after it. A failed write (a full disk) turns the index
  off until the next restart, which resumes the fill. The one case in which the node refuses to start is a fill from
  genesis (`-valuepoolsseed=0` on an empty index) whose totals contradict the compiled seed: the message says to
  delete `blocks/valuepools`, which rebuilds the index from the seed (`-reindex` would repeat the check).

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
