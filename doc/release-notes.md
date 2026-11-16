(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

6.22.0-beta3 (next release), changes since 6.22.0-beta2
-------------------------------------------------------

### What you must do when upgrading

1. **Clients: accept `rpcversion` 10.** `yed_getinfo.rpcversion` is 10 (beta2 was 9). No `yed_*`
   field changes shape; a client that checks `rpcversion >= 10` knows the node has every addition
   below. A client that requires exactly 9 must be changed to accept 10.
2. **Miners and pools: the development-fund donation now defaults to 0 %.** Past the mandate's end
   (mainnet height 2,275,000) a block this build mines pays the whole subsidy and every fee to the
   miner. A miner or pool that wants to keep donating sets `-ydf=5`. Nothing changes during the
   mandate, which consensus still enforces. A pool needs no other change: `getblocktemplate` and
   `submitblock` are unchanged, and `getcoinbasetemplatefor` (below) is optional.
3. **Fast testnet (testnet-yb-fast): every node must run this build before the chain reaches the
   fund mandate's end there**, at height **(set at the release candidate)**. This is one-way: a node
   on an earlier build stops following the chain at that height and bans the peer that sent the
   block, so a node upgraded late needs `clearbanned` afterwards. Until every node has upgraded, a
   fast-testnet pool keeps `-ydf=5`, whose blocks every build accepts. Mainnet, the slow and legacy
   testnet profiles and regtest are unchanged.
4. **The first start takes longer.** The node fills its new value-pool index once (about 30
   seconds on a mainnet node; the RPC server answers -28, warming up, until it is done). No reindex.
5. **Containers that restore a snapshot (`YCASHD_BOOTSTRAP`).** The entrypoint now refuses a
   network directory whose `blocks/` holds data but has no `bootstrap.json` (a datadir an earlier
   image started on after a failed restore). If you know that datadir is good, set
   `YCASHD_BOOTSTRAP_ACCEPT_DATADIR=1`, or unset `YCASHD_BOOTSTRAP`. A failed restore now leaves
   `<network>.bootstrap-incomplete` in the datadir, and the container will not start past it until
   you clear it (`contrib/bootstrap/README.md`, "The marker"). On mainnet a restore needs a signed
   bundle; `--allow-unsigned` is refused there.

The changes, in order: the fast testnet's mandate end (the one consensus change), the `-ydf`
default, `getcoinbasetemplatefor`, `transparentPools`, `gettransaction`'s fee, the address of a
post-quantum input, snapshot restores, and what `rpcversion` 10 covers; then the known limitations.

### Fast testnet: the development-fund mandate ends (consensus, testnet-yb-fast only)

- **A scheduled rule change on the fast testnet.** The fast profile gets its own mandate end,
  `TESTNET_FAST_YDF_MANDATE_END_HEIGHT`, at height **(set at the release candidate)**: the
  fast-testnet tip when the release candidate is cut, plus 400 blocks. From that height a fast-testnet block is valid with
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

### Mining: the development-fund donation is opt-in (`-ydf`, default 0)

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

### Mining: a coinbase for each miner's own address (`getcoinbasetemplatefor`)

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
- **A miner paid at a post-quantum address shields its reward with `z_sendmany`.** Where coinbase
  must be shielded (mainnet, the testnets) no wallet call could spend such a reward. `z_sendmany`
  from the address now selects its mature coinbase (101 confirmations) when every recipient is
  shielded and the address's other coins do not cover the send. Such a send makes no change: the
  amounts must add up to the selected coins less the fee, and a send that would leave change is
  refused with the exact amount to send in the message. With a transparent recipient the coinbase
  is never selected and the refusal says so (`doc/yellowback-rpc.md`, "A post-quantum miner shields
  its coinbase"). **Pay a post-quantum reward to an address held in a ycashd or yewd wallet**: the YEW app
  and the web wallet cannot tell that a coin is a coinbase, show it as spendable, and the node refuses
  their sends until it is 100 blocks deep and the send has only shielded recipients and no change. To
  move rewards, name an amount, read the exact amount in the refusal and send that: coins are taken
  largest first, so a call moves one reward unless the amount is above the largest one
  (`doc/yellowback-mining.md` §13, "A reward paid to a post-quantum address", has a worked example;
  one FN-DSA input pays 0.000065 on regtest). `z_shieldcoinbase` and `z_mergetoaddress` do not move it.
  A transparent (ECC) or Sapling reward is unchanged. A wallet change only; the same rule, strings and test as on ycash-dd.

### Chain value pools by address type (`transparentPools`)

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
  genesis and check the seed on the way (with a wallet, its balances read low until a `-reindex-chainstate` completes,
  and `-rescan` is refused with it: see below). Downgrading ignores the directory.
- **Not a consensus change.** The index is written after a block has passed every check and never rejects a block; a
  failure is logged and the index stops covering the blocks after it. A failed write (a full disk) turns the index
  off until the next restart, which resumes the fill. The one case in which the node refuses to start is a fill from
  genesis (`-valuepoolsseed=0` on an empty index) whose totals contradict the compiled seed: the message says to
  delete `blocks/valuepools`, which rebuilds the index from the seed (`-reindex` would repeat the check).
- **An unclean stop does not restart the fill.** After a kill, an out-of-memory kill or a power loss the block index
  can come back older than the index's last block; the fill now resumes from the highest block of the restored chain
  that has a record (two log lines say so: the unknown last block, then the height it resumes from), in seconds, instead of refilling from the compiled seed.

### `gettransaction` shows the real fee for every funding shape

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

### Inputs spending post-quantum coins name their address

- On a `-insightexplorer` node, `getrawtransaction` (verbose `vin[].address`), `getblock` verbosity 2,
  `getblockdeltas` and REST `/rest/tx/<txid>.json` now name the address of an input that spends a post-quantum output, in the
  scheme-visible form of beta2 (`sqf…`/`sqs…`, `tqf…`/`tqs…`, `rqf…`/`rqs…`); they carried only `value`/`valueSat` before.
  The insight index keys a spent output by a Hash160 that cannot be inverted, so the node reads the
  address from the spent output and checks it against the index key. No reindex is needed. The same answers as ycash-dd.

### Snapshot restores (`contrib/bootstrap/ycash-bootstrap`)

- **A restore cannot fail silently**. A restore that is refused or fails exits non-zero and
  leaves `DATADIR/<network>.bootstrap-incomplete`, which the container entrypoint will not start past
  (`contrib/bootstrap/README.md`, "The marker"). The import node ignores peers whatever `ycash.conf`
  says, and the restore fails if it ever has a connection. A 403 for an absent `SHA256SUMS.minisig`
  counts as absent exactly where a 404 does, never as verified.
- **State bundles in parts**. `ycash-bootstrap` reads `ycash-state/2` and `ycash-state/3`
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
- **No restore hangs**: the node check after a state restore fails after `--stall-timeout` (default
  1800 s) also when the restored `ycashd` never leaves warm-up (it used to wait forever), and a full
  disk during a part's download fails at once with "no space left on the disk" instead of being
  retried as a broken connection.
- **The container image restores mainnet**: on mainnet `YCASHD_BOOTSTRAP` is a state bundle's URL or
  directory (never `prefix`), and the marker is `main.bootstrap-incomplete`. ycash-dd's image refuses
  a mainnet bundle, which is a ycash6 data directory.
- While `YCASHD_BOOTSTRAP` is set, the entrypoint refuses a network directory whose `blocks/` holds data
  but has no `bootstrap.json` (an image before beta3 started on a failed restore), unless
  `YCASHD_BOOTSTRAP_ACCEPT_DATADIR=1`.
- Tooling only: no node, RPC or consensus change.

### `-reindex-chainstate` with a wallet no longer stops the node

- A node with a wallet (the default) started with `-reindex-chainstate` stopped at an assert in the wallet
  notifier (`pindexFork != nullptr`, `init.cpp`, inherited from Zcash): the chainstate is emptied, so the active
  chain is empty when the notifier first looks. The notifier now waits for the chain to be reconnected, as it
  already did for a block missing after an unclean stop, and the wallet follows from where it was. The log says
  when it starts waiting and when it resumes.
- **With a wallet, balances read low until the reindex completes**: the wallet is not rescanned, and transactions in
  blocks not yet reconnected count as unconfirmed. **`-reindex-chainstate` with `-rescan` is refused at startup** (also when
  `-salvagewallet` or `-zapwallettxes` implies `-rescan`): `-rescan` clears the wallet's note witness cache while the
  chain is still empty, so no scan rebuilds it, and Sapling notes mined at or below the wallet's last saved block
  became unspendable ("Missing witness"); disconnecting a block then stopped the node at an assert. Start with
  `-reindex-chainstate` alone and use `-rescan` on a later start if one is needed. The `-reindex-chainstate` help no
  longer says it implies `-rescan`.

### `rpcversion` 10: what changed

`yed_getinfo.rpcversion` is 10 (was 9), one step for every change of this release. No `yed_*` field
changes shape; every change is an addition to a stock call, and the number tells a client the node has
all of them. Clients that require an exact version must accept 10.

| Call or field | Change |
|---|---|
| `getcoinbasetemplatefor` | new call; result `data`, `hash`, `height`, `previousblockhash`, `addresstype`, `subsidy`, `fund`, `fundrule`, `fees`, `amount`, `txcount`, `flags`, `sigops`; errors `template-stale: …`, `coinbase-does-not-fit: …` |
| `getblockchaininfo`, `getblock` (verbosity 1, 2) | new `transparentPools` object; `valuePools` unchanged |
| `getrawtransaction` (verbose), `getblock` verbosity 2, `getblockdeltas`, REST `/rest/tx` | `vin[].address` (`inputs[].address`) for an input spending a post-quantum output |
| `gettransaction` | `fee` for every funding shape; left out when the funding transaction of a transparent input is not held |
| `-ydf`, `getblocksubsidy` `founders` | default 0; past the mandate `founders` is this node's `-ydf` share. This line's `getblocktemplate` has no `coinbasetxn.ydfpercentage` (ycash-dd's has) and shows `foundersreward` only while the mandate runs |

### Known limitations

- **`gettransaction`'s `fee` and `details[].fee` can differ** for a Sapling-funded send (the second
  counts the transparent debit only), and `fee` is left out when the wallet does not hold the funding
  transaction of every transparent input.
- **Value pools below the seed.** On a node that filled the index from the compiled seed, blocks
  below height 2,800,000 report `"monitored": false` in `transparentPools`; a pruned node that lacks
  old undo data reports `"monitored": false` until it is reindexed.
- **`getcoinbasetemplatefor` checks that each named transaction is in the mempool, not that the set
  is complete or in order.** Name `getblocktemplate`'s list verbatim, or the block is invalid.
- **No YED attestor set on any public network**, as in beta2: YED cannot be minted on the fast
  testnet with this build. The other limitations of beta2 stand
  (`doc/release-notes/release-notes-6.22.0-beta2.md`, "Known limitations").
- Not for production funds.
