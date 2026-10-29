# Releasing ycashd with Ycash Yellowback (YED)

How a tagged version of this fork (`boyfromcave/ycash6`) becomes a GitHub release with one binary
package per platform, in the layout of upstream Ycash's releases
(<https://github.com/ycashfoundation/ycash/releases>). This branch, `upgrade/vault`, carries the
vault upgrade (a network upgrade, `UPGRADE_VAULT`, branch ID `0x6d5b7a31`) and releases the
**6.22.x** series; the `harden/yellowback` branch, which needs no network upgrade, releases
**6.21.x**. The automation is
[`.github/workflows/yellowback-release.yml`](../.github/workflows/yellowback-release.yml); this file
is the procedure around it.

## What a release contains

| Asset | Built on | Tier |
|---|---|---|
| `ycashd_v<V>_linux_x86_64.tar.gz` | ubuntu-22.04, native (glibc 2.35 floor) | 1 |
| `ycashd_v<V>_linux_aarch64.tar.gz` | ubuntu-22.04-arm, native | 1 |
| `ycashd_v<V>_macos_aarch64.tar.gz` | macos-14, native, `MACOSX_DEPLOYMENT_TARGET=11.0` | 1 |
| `ycashd_v<V>_windows.zip` | ubuntu-22.04, cross (`HOST=x86_64-w64-mingw32`, llvm-mingw from depends) | 1 |
| `ycashd_v<V>_ubuntu_18.04_x86_64.tar.gz` | `contrib/legacy-glibc-build` (18.04 image, glibc ≤ 2.27) | 2 |
| `ycashd_v<V>_macos_x86_64.tar.gz` | macos-15-intel, native | 2 |
| `SHA256SUMS` | | |

Each package is a directory `ycashd_v<V>_<platform>/` holding stripped `ycashd`, `ycash-cli`,
`ycash-tx`, `ycashd-wallet-tool` (`.exe` on Windows) and `COPYING`. No zk parameters ship or need
fetching: 6.20.0 builds the Sapling parameters and the Sprout verifying key into `ycashd`. Tier 1 must build and pass its smoke test for a
release to be drafted. Tier 2 jobs may fail; their asset is then missing from the release.

Every build runs `qa/yellowback-release-smoke.sh` on the packaged binaries: each binary's version
banner must be `v<V>`, and a throwaway regtest node must start on the vault upgrade, create a YED
attestor set, restart naming it (so Yellowback is live), answer `getnetworkinfo` and `yed_getinfo`
(`rpcversion` equal to `YELLOWBACK_RPC_VERSION` in `src/rpc/yellowback.cpp`, 8 today; upgrade active), and stop. The Windows `.exe` files are run on windows-latest
(version banners only). The 18.04 package's smoke test runs inside an `ubuntu:18.04` container,
which also proves its glibc floor.

There is **no separate mining-pool package** (see "Mining pools" below).

Binaries are unsigned, as upstream's are, and builds are not reproducible (the inherited gitian
descriptors are not maintained).

## Version numbers

`configure.ac` encodes the stage in `_CLIENT_VERSION_BUILD`: 0–24 is `-beta<BUILD+1>`, 25–49 is
`-rc<BUILD−24>`, 50 is the final release, above 50 is `-<BUILD−50>`. `src/clientversion.h` carries
the same four numbers. There is one release series per node line, and the release workflow refuses
a tag from the wrong one (it tells them apart by `src/vault/`):

- **6.22.x** — this line, `upgrade/vault`: the vault upgrade and YED as its rule module.
- **6.21.x** — the `harden/yellowback` line, the fallback that needs no network upgrade.

Both are minor bumps over 6.20.0 because 6.20.x patch numbers belong to the upstream 6.20 line
(miodragpop/ycash).

| Release | MINOR | REVISION | BUILD | Tag |
|---|---|---|---|---|
| 6.22.0-rc1 | 22 | 0 | 25 | `v6.22.0-rc1` |
| 6.22.0-rc2 | 22 | 0 | 26 | `v6.22.0-rc2` |
| 6.22.0 | 22 | 0 | 50 | `v6.22.0` |
| 6.22.1 | 22 | 1 | 50 | `v6.22.1` |

`configure.ac` is in the frozen set. `qa/yellowback-audit.sh` allows exactly the four
`_CLIENT_VERSION_*` defines to change there and fails on any other line.

## Procedure

1. **Bump the version** on a branch off `upgrade/vault`: the four numbers in `configure.ac`
   and `src/clientversion.h`, plus the title line of `README.md`. Run `qa/yellowback-audit.sh`.
2. **Write the notes** at `doc/release-notes/release-notes-<V>.md`. The release job refuses to run
   without them. Start from the previous one.
3. **Proving run.** Push the branch and merge it to `upgrade/vault` once `yellowback tests`
   is green. Then run the workflow by hand: Actions → *yellowback release* → *Run workflow* on
   `upgrade/vault`. It builds, smoke-tests and uploads every package as a workflow artifact,
   but creates no release. Download and spot-check at least one package.
4. **Tag and push.**
   ```
   git tag -a v<V> -m "ycashd v<V> (Yellowback)" <commit>
   git push origin v<V>
   ```
   The `version` job fails if the tag differs from what `configure.ac` renders, or if it is not a
   6.22 version.
5. **Review the draft.** The workflow creates a **draft** release (marked pre-release for
   `-rc`/`-beta`) with every asset, `SHA256SUMS`, and the notes from step 2. Check the asset list
   and checksums, then publish it by hand.

A bad tag is fixed with a new number, never by moving a published tag.

## Mining pools (the former "wr" build)

Upstream's `_MINING_POOLS_ycashd_wr_*` packages were a "witness rework" build. For pools, it added
wallet transaction deletion, a witness-cache rework and Sapling note consolidation. In ycashd
6.20.0 these became runtime options of the one binary, all off by default (miodragpop commits
`ae23774b3`, `9aa430aa3`). The witness-cache half was dropped as obsolete. A pool runs the normal
package and sets:

| Option | Effect |
|---|---|
| `-deletetx=1` | periodically purge fully-spent, deeply-confirmed wallet transactions |
| `-deletetxinterval=<n>` | purge every n blocks (default 2000) |
| `-keeptxfornblocks=<n>` | minimum depth before purge (default 10000) |
| `-keeptxnum=<n>` | always keep the n newest transactions (default 200) |
| `-deletetxconflict` | also purge conflicted/expired transactions (default on under `-deletetx`) |
| `-bdbcache=<MiB>` | BerkeleyDB cache for large wallets (1..1024) |
| `-consolidation=1` | sweep many small Sapling notes of an address into one (built at height ≡ 45, committed at ≡ 49 mod 100) |
| `-consolidatesaplingaddress=<zaddr>` | restrict consolidation to these addresses |

Deleted transactions are recorded as `extx` tombstones in `wallet.dat`, so a rescan does not
re-add them. A wallet opened by an older build loses the tombstones.

**With Yellowback.** Yellowback's balances, coins, positions and confirmed history come from the
Yellowback index and `<datadir>/yellowback/`, never from `wallet.dat`, so a purge does not touch
them. `qa/rpc-tests/yellowback_wr_flags.py` runs a Yellowback wallet with all of these options on.
It covers consolidation racing Sapling-funded mints in both directions, purges under open
positions, a restart, and redeeming afterwards. One accepted difference: under
`-deletetxconflict`, a purged *expired* Yellowback transaction is no longer listed as `"expired"`
by `yed_listtransactions` / `yed_gettxinfo`. It never confirmed, so it left nothing in the index;
the operation is simply re-run.

A second accepted difference: a consolidation batch takes a random 10–44 notes, so it can hold
every note of an address. While it is unconfirmed, a Yellowback operation funded from that address
is refused with `insufficient-yec` (never built on a note the mempool already spends) and goes
through one block later. A pool that funds Yellowback from a Sapling address should list only its
other addresses with `-consolidatesaplingaddress`.

Pools reach the node only through the stock mining RPCs (`getblocktemplate`, `submitblock`), which
none of these options affect.

## Network parameters (the UPGRADE_VAULT height and the YED attestor set)

Yellowback is live on a network from its `UPGRADE_VAULT` activation height (`src/chainparams.cpp`)
once that network names its YED attestor set (`attestorSetId` in `src/yellowback/params.cpp`). Both
are consensus parameters, so they ship only in a release, never as an operator flag. Neither is set
on mainnet yet: they are set by the release that passes the launch gates. The re-forked testnet
(testnet plan §2.1, §2.2) has a placeholder height (510,400) and no set: the launch ceremony fixes
the height and creates the set, and rc1 names it (until then R7 refuses a tag).

When setting them in a release:
- The activation height leaves time for every node to upgrade: a node that has not upgraded by
  then stops following the chain. Take the tip from a live node or
  <https://explorer.ycash.xyz/api/v1/network/info>, and leave slack for the time between the
  commit and the tag.
- The attestor set must exist on chain before the release can name it.
- Set the same Vault parameters on `ycash-dd`. Tag `ycash-dd` `vault-params/v6.22.N` first. Its guard
  (`.github/workflows/yellowback-release-guard.yml`) runs `qa/yellowback-release-heights.sh` and
  refuses the tag unless the version is 6.22.x and release rules R1–R7 hold: a positive mainnet
  activation height (R1), a non-zero mainnet attestor set (R2), `UPGRADE_VAULT.nProtocolVersion`
  above 270013 (R3), `PROTOCOL_VERSION` at least that value (R4), `MIN_PEER_PROTO_VERSION` at or
  below 270013 (R5), mainnet `pqFalconHeight` 0 (R6), and testnet height and attestor set both set
  or both unset (R7). It also refuses any compared Vault field that differs from ycash6
  (`v6.22.N` when that tag already exists, otherwise `upgrade/vault`).
- Then tag ycash6 `v6.22.N`. This release workflow refuses the tag when
  `vault-params/v6.22.N` is missing on ycash-dd, when R1–R7 fail, or when any compared Vault
  field differs (`qa/yellowback-release-heights.sh`). A `workflow_dispatch` run only warns, and
  compares with ycash-dd `upgrade/vault`.
- Protocol version stays deferred (audit W3-P-1 part D). The table is in the upgrade plan's P8
  checklist. R3–R5 are enforced at the tag, so a tag cannot ship until the bump. When it is taken,
  raise `UPGRADE_VAULT.nProtocolVersion` and `PROTOCOL_VERSION` to the same value on both lines
  together. Do not raise `MIN_PEER_PROTO_VERSION` to the Vault version.

| Network | `UPGRADE_VAULT` height | `attestorSetId` | Set in |
|---|---|---|---|
| main | unset | unset | not yet: the release that passes the launch gates |
| test | 510,400 (placeholder, N1) | unset | the launch ceremony; rc1 names the set |

Release notes for the vault rules tightened on 2026-10-12 (audit 01/V-1, 01/V-5, 01/N-1, both node lines):
- **S-0 and V-1's APP clause are retroactive on private chains.** They apply from the activation
  block, so a regtest, devnet or kind chain built by an earlier build that holds a template spend of
  a pre-activation coin, or a V with an APP branch on a tag no module governs, fails the vault
  database's replay on restart (the error names the cause) and a fresh node splits from it: restart
  such a chain from scratch. Mainnet has no activation height, so nothing there changes; the re-forked
  testnet starts after these rules.
- **`-prune` is refused** wherever `UPGRADE_VAULT` has an activation height: a node that pruned
  before its network set one must re-download the chain without `-prune` (there is no `-reindex` on a
  pruned node).

## Parameter changes

A YED parameter set is consensus from the activation height and has no end height: there is no
sunset, no renewal release and no freeze. Changing a consensus value is a network upgrade like any
other, coordinated through a new consensus branch ID. Until one ships, a defect is contained by the
rules themselves: a claim at a wrong price is cancelled by the YED attestor set within
`CLAIM_DELAY`, and an owner can always redeem by the owner branch.

## Release notes: plain-YEC post-quantum addresses (`sq…`)

The quantum line's releases (D-Q-20) carry the chain-wide `sq…`/`tq…`/`rq…` address. Say in the
release notes:

- **Inputs spending PQ coins carry no address** in `getblockdeltas`, `getspentinfo` and
  `getrawtransaction` (verbose `vin[].address`): the insight index keys a spent output by its
  Hash160, and a `TX_PQPKH` key hash is 32 bytes, so the index cannot name it from the input side.
  `getaddressdeltas` (and `getaddressutxos`/`getaddressbalance`/`getaddresstxids`) name them as
  requested, by `sq…`/`tq…`/`rq…` or the PQ `yb…`/`yt…`/`yr…` form.
- **`-reindex` once** on a node with `-insightexplorer` or `-lightwalletd` that synced before this
  build: the address index of earlier blocks holds no `TX_PQPKH` outputs until it is rebuilt.
- **`createrawtransaction` takes an `sq…` output** without the wallet's payability checks (Falcon
  activation, the PQ dust threshold); relay policy still refuses a non-standard or dust output. Prefer `sendtoaddress`/`sendmany`, which check.
- **`yed_getnewaddress "pq"` now files holder keys in the address book** (under the `sq…` form, so
  the YEC their token outputs carry is not taken for change); holder keys issued by an earlier build
  are not added retroactively (`getnewaddress "" "pq"` files plain-YEC PQ keys; `"pqowner"` keys stay
  out).
- **`z_sendmany` / `z_mergetoaddress` refuse an `sq…` recipient** on this line (their recipients are `libzcash::PaymentAddress`, which has no post-quantum alternative): pay an `sq…` address with `sendtoaddress` or `sendmany`.
- **Seed-only restore (`-mnemonicfile`)** restores the seed's first legacy Sapling address and its
  post-quantum keys up to a gap of `PQ_KEY_LOOKAHEAD` = 20 unused keys per scheme: a key beyond 20
  unused ones in a row is not re-found. Recover such keys by issuing PQ addresses past the gap
  (`getnewaddress "" "pq"`) and running `rescanblockchain`; further Sapling addresses likewise with
  `z_getnewaddress` before `rescanblockchain`. On an existing wallet the option is ignored when the
  seed matches (checked by fingerprint, so a locked wallet starts too) and refused when it does not.
- **`-sendchangeback=1`** returns a PQ input's change to its `sq…` address; the change's dust check
  uses the PQ spend size (`GetPQDustThreshold`), as relay policy does.
- **`z_importpqkey`** takes a dump's whole `pqseed=` line and refuses it when its `owner=`/`addr=`/
  `yecaddr=` do not name the key the seed makes under the line's scheme (the scheme decides the key;
  both schemes take a 48-byte seed). **`vault_release`** refuses a 66-hex pqkeyid as the recipient
  (pass the address or the script).

## Release notes: post-quantum fees and the ZIP-317 opt-in (audit 04/N-1)

Say in the release notes, and in the operator section of the announcement:

- **Relays and pools keep `-txunpaidactionlimit` / `-blockunpaidactionlimit` at their defaults**
  (`SIZE_MAX`, ZIP-317's unpaid-action rule off; `doc/yellowback-mining.md` §2, §3.2). A node that opts
  in (`=0`) refuses a post-quantum spend paying less than its ZIP-317 conventional fee (~27,000 zat for
  an SLH-DSA input, ~5,500 for a Falcon one), which every other node relays; and the ZIP-401 limiter
  ranks such spends first for eviction under `-mempooltxcostlimit` pressure on every 6.20.0 node.
- **Wallets pay at least the conventional fee for a PQ input on both lines** (6.20.0 since the quantum
  line; ycash-dd since audit 04/N-1). Clients that build their own PQ spends (YEW, Hawkeye; x402 already
  does) should pay `max(their fee, the ZIP-317 conventional fee)`.

## Wallet (YecWallet) releases

YecWallet bundles `ycashd`. Its release should take these packages as inputs rather than rebuild
the node, so a node release comes first.
