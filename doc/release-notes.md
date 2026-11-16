(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

6.22.0-beta3 (next release), changes since 6.22.0-beta2
-------------------------------------------------------

**Two things to act on first.**

1. **A miner who wants to keep donating to the Ycash Development Fund sets `-ydf=5`.** The default
   is now 0: past the mandate's end a block this build mines pays the whole subsidy and every fee to
   the miner. Nothing changes during the mandate, which consensus still enforces.
2. **Every fast-testnet (testnet-yb-fast) node must run this build before the chain reaches the
   fund mandate's end there** (`TESTNET_FAST_YDF_MANDATE_END_HEIGHT`, set when the release candidate
   is cut: the fast-testnet tip then plus 400 blocks). A node on an earlier build stops following
   the chain at that height. Mainnet, the other testnet profiles and regtest are unchanged.

In this section, in order: the fast testnet's mandate end (item 5, the one consensus change), the
`-ydf` default (item 4), `getcoinbasetemplatefor` (item 3), `transparentPools` (item 2),
`gettransaction`'s fee (item 1), the address of a post-quantum input (item 6), snapshot restores
(items 8 and 9), and `rpcversion` 10, which covers every RPC change listed here. The item numbers
are the beta3 plan's.

### Fast testnet: the development-fund mandate ends (consensus, testnet-yb-fast only; item 5)

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

### Mining: the development-fund donation is opt-in (`-ydf`, default 0; item 4)

- **The default changes from 5 to 0.** After the Ycash Development Fund mandate ends (mainnet height
  2,275,000), a block this node mines pays the whole subsidy and every fee to the miner and carries
  no fund output. A miner who wants to keep donating sets `-ydf=5` (any whole percentage from 0 to
  100 is accepted, as before). A value outside that range (`-ydf=-1`, `-ydf=101`) is reset to the
  default, so it now means 0 where it used to mean 5.
- **Not a consensus change.** Past the mandate a block is valid with or without the fund output;
  `DEFAULT_YDF_FEE_PERCENTAGE` is read by the miner, `getblocksubsidy`, the metrics screen and the
  option check, never by block validation.
- **The mandate period is unchanged:** below the mandate's end (2,275,000 on mainnet, testnet-yb-slow
  and testnet-legacy; testnet-yb-fast has its own end, see above) the 5 % output is
  required by consensus and the miner still pays it whatever `-ydf` says.
- `getblocksubsidy`'s `founders` past the mandate is the share this node's `-ydf` setting donates
  (0 by default); the metrics screen counts the reward the same way.

### Mining: a coinbase for each miner's own address (`getcoinbasetemplatefor`; item 3)

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

### Chain value pools by address type (`transparentPools`; item 2)

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

### `gettransaction` shows the real fee for every funding shape (item 1)

- `fee` was the value out less the wallet's transparent debit, so a send funded from Sapling showed the sum of its transparent (ECC
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

### Inputs spending post-quantum coins name their address (item 6)

- On a `-insightexplorer` node, `getrawtransaction` (verbose `vin[].address`), `getblock` verbosity 2,
  `getblockdeltas` and REST `/rest/tx/<txid>.json` now name the address of an input that spends a post-quantum output, in the
  D-9 form (`sqf…`/`sqs…`, `tqf…`/`tqs…`, `rqf…`/`rqs…`); they carried only `value`/`valueSat` before.
  The insight index keys a spent output by a Hash160 that cannot be inverted, so the node reads the
  address from the spent output and checks it against the index key. No reindex is needed. The same answers as ycash-dd.

### Snapshot restores (`contrib/bootstrap/ycash-bootstrap`; items 8 and 9)

- **A restore cannot fail silently** (item 8). A restore that is refused or fails exits non-zero and
  leaves `DATADIR/<network>.bootstrap-incomplete`, which the container entrypoint will not start past
  (`contrib/bootstrap/README.md`, "The marker"). The import node ignores peers whatever `ycash.conf`
  says, and the restore fails if it ever has a connection. A 403 for an absent `SHA256SUMS.minisig`
  counts as absent exactly where a 404 does, never as verified.
- **State bundles in parts** (item 9). `ycash-bootstrap` reads `ycash-state/2` and `ycash-state/3`
  (the tar.gz stream stored in 1 GiB parts), so bundles above 50 GB can be published, and restores
  mainnet (`--network main`, a state bundle only). Each part is fetched, checked against its signed
  `SHA256SUMS` line before any of it reaches the extractor, resumed after a broken download and
  deleted once extracted (`--keep-parts` keeps them): one part of extra disk. Free disk is checked up
  front. A source ending in `latest/` now works (it is read for the height, then every file comes
  from `../<height>/`).
- **Signatures.** On mainnet the signature is always required and `--allow-unsigned` is refused
  before any request; elsewhere a state bundle over http(s) and an unpinned prefix need it too, and
  `--allow-unsigned` accepts an unsigned one with a warning. The "not signed" message names the HTTP
  status of the missing `.minisig`.
- **The container image restores mainnet**: on mainnet `YCASHD_BOOTSTRAP` is a state bundle's URL or
  directory (never `prefix`), and the marker is `main.bootstrap-incomplete`. ycash-dd's image refuses
  a mainnet bundle, which is a ycash6 data directory.
- While `YCASHD_BOOTSTRAP` is set, the entrypoint refuses a network directory whose `blocks/` holds data
  but has no `bootstrap.json` (an image before beta3 started on a failed restore), unless
  `YCASHD_BOOTSTRAP_ACCEPT_DATADIR=1`.
- Tooling only: no node, RPC or consensus change.

### `rpcversion` 10: what changed

`yed_getinfo.rpcversion` is 10 (was 9), one step for the whole run (decision B3-D5). No `yed_*` field
changes shape; every change is an addition to a stock call, and the number tells a client the node has
all of them. Clients that require an exact version must accept 10.

| Item | Call or field | Change |
|---|---|---|
| 3 | `getcoinbasetemplatefor` | new call; result `data`, `hash`, `height`, `previousblockhash`, `addresstype`, `subsidy`, `fund`, `fundrule`, `fees`, `amount`, `txcount`, `flags`, `sigops`; errors `template-stale: …`, `coinbase-does-not-fit: …` |
| 2 | `getblockchaininfo`, `getblock` (verbosity 1, 2) | new `transparentPools` object; `valuePools` unchanged |
| 6 | `getrawtransaction` (verbose), `getblock` verbosity 2, `getblockdeltas`, REST `/rest/tx` | `vin[].address` (`inputs[].address`) for an input spending a post-quantum output |
| 1 | `gettransaction` | `fee` for every funding shape; left out when the funding transaction of a transparent input is not held |
| 4 | `-ydf`, `getblocksubsidy` `founders`, `getblocktemplate` `coinbasetxn.ydfpercentage` | default 0; past the mandate they report this node's `-ydf` share |
