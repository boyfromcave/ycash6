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
| `ycashd_v<V>_<platform>.spdx.json` | an SPDX SBOM of each package (syft) | |
| `SHA256SUMS` | the sha256 of every package and SBOM | |
| `SHA256SUMS.cosign.bundle` | a keyless Sigstore signature of `SHA256SUMS` | |
| `SHA256SUMS.minisig` | the owner's minisign signature of `SHA256SUMS`, added on the draft (below) | |

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

Binaries are not code-signed, as upstream's are not, and builds are not reproducible (the inherited
gitian descriptors are not maintained; Guix builds are a mainnet-launch item, testnet plan T-11).

## Signatures and provenance (testnet plan §5.2, T-6)

In plain words: anyone can check that a download is the file this repository's release workflow
built, and that the owner vouched for it, without trusting the download site.

- **Build provenance.** Every package, every SBOM and `SHA256SUMS` carries a GitHub build
  provenance attestation (SLSA build level 2): `gh attestation verify <file> -R boyfromcave/ycash6`.
- **Keyless cosign.** `SHA256SUMS.cosign.bundle` signs `SHA256SUMS`; its certificate names this
  workflow at the tag:

  ```
  cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
    --certificate-identity https://github.com/boyfromcave/ycash6/.github/workflows/yellowback-release.yml@refs/tags/v<V> \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
  ```
- **The owner's minisign key** (key id `02C923A6C593AF18`, public key
  `RWQYr5PFpiPJAigk86vf89bPYrJCXj5tskgRAPRYFsEXyciZo8dveOGQ`, also ycash-infra
  `keys/ycash-release.pub`) signs `SHA256SUMS` on the draft. The signature is not made here: the
  private ycash-ops repository's `sign-release` workflow (repo `ycash6`, tag `v<V>`, asset
  `SHA256SUMS`) checks the file's provenance, signs it, verifies the signature against the pinned
  key and uploads `SHA256SUMS.minisig`; its `scripts/sign-release.sh` does the same by hand. Check:
  `minisign -Vm SHA256SUMS -P RWQYr5PFpiPJAigk86vf89bPYrJCXj5tskgRAPRYFsEXyciZo8dveOGQ`.
- **SBOMs.** `ycashd_v<V>_<platform>.spdx.json` lists what syft finds in each package. The C++
  depends are linked statically and carry no metadata syft can read; the Rust crates are pinned in
  the tag's `Cargo.lock`.

The draft release's notes carry these commands, after the notes of step 2.

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
4. **Release train.** Add `releases/v<V>.yaml` to the workspace (`boyfromcave/yellowback`,
   its `releases/README.md`) by pull request: every component at the commit this release is
   qualified with, ycash6 at the commit you are about to tag. Its `release-train` check must pass.
5. **Tag and push**, ycash-dd's pairing tag first (Network parameters, below):
   ```
   git tag -a v<V> -m "ycashd v<V> (Yellowback)" <commit>
   git push origin v<V>
   ```
   The `version` job fails if the tag differs from what `configure.ac` renders, if it is not a
   6.22 version, or if the rules of its stage fail.
6. **Draft and qualification (automatic).** The workflow drafts the release (pre-release for
   `-rc`/`-beta`) with every package, SBOM, `SHA256SUMS`, `SHA256SUMS.cosign.bundle` and the notes
   from step 2, then starts `rc-qualify` on the tag (below). Wait for its record.
7. **Owner's signature.** In ycash-ops: Actions → *sign-release* → repo `ycash6`, tag `v<V>`,
   asset `SHA256SUMS`. It checks the provenance, signs and uploads `SHA256SUMS.minisig` to the draft.
8. **Testnets (release candidates; manual, from ycash-ops).** Deploy the rc image to
   testnet-yb-fast, then testnet-yb-slow; testnet-legacy runs the same rc with Vault off (below).
9. **Publish** the draft by hand once the testnets hold.

A bad tag is fixed with a new number, never by moving a published tag; a red `rc-qualify` also
means a new rc number.

## Release candidates (testnet plan §5.3, Revision 3)

In plain words: a release candidate is tested as released, with every other Yellowback program, and
then run on the three practice networks before anyone is asked to install it.

**Qualification.** [`.github/workflows/rc-qualify.yml`](../.github/workflows/rc-qualify.yml) runs on
the tag (the release workflow dispatches it; by hand: Actions → *rc-qualify* → *Run workflow* on the
tag `v<V>`, or `gh workflow run rc-qualify.yml --ref v<V>`). It downloads the files **from the
release**, checks them against `SHA256SUMS`, the cosign signature at the tag and the build provenance,
reads the train from the workspace, and runs:

| Step | What | Where |
|---|---|---|
| 1 | the node's functional shards and nightly suites against the package's binaries (the unit tier and the instrumented variants are CI builds) | `yellowback-tests.yml` called with `release_package` |
| 2 | upgrade-walk with chain-viz, lightwalletd fork and baseline and yolo; YEW's devnet suites; x402's `test:devnet`; Hawkeye's `scenario demo` on anvil; YecWallet's QTest devnet cases; each client at its train pin | `qa/yellowback-rc-qualify.sh walk\|yew\|x402\|hawkeye\|yecwallet` |
| 3 | two ycash-dd nodes (built at the train's `vault-params` commit) on the devnet; block hash, vault and YED state hashes equal at every 100th height | `qa/yellowback-rc-qualify.sh cross-line`, `qa/yellowback-rc-crossline.py` |
| 4 | the launch ceremony rehearsed on regtest with the fast and slow profiles' maturity | `qa/yellowback-rc-qualify.sh ceremony` (needs `contrib/testnet/ceremony`, N2) |

The record, `rc-qualify-<run id>.json`, is uploaded to the release: each step's result, the train,
the package's sha256, and `qualified` (true only when every step passed). Step 5, the 24-hour
canary from rc2 on, needs the live testnet and is part of the deploy below.

**Testnets (manual gate; deploys run from the private ycash-ops).** After a qualified record and
the owner's signature:
1. Build the rc's node image at the tag's commit (ycash-infra `node-image`, until the release image
   of §5.5 exists) and pin its digest in ycash-ops.
2. ycash-ops *deploy*: network `yb-fast`, action `upgrade`. Watch it: no fork, no state-hash
   divergence between our nodes, peers kept; from rc2 on, the 24-hour canary.
3. Then network `yb-slow`, the soak the gates read. The rc that first sets testnet-yb-slow's
   `UPGRADE_VAULT` height rehearses the activation there; its attestor set is created after the
   activation and named by a later rc.
4. Network `legacy` runs the same rc with Vault off (no height, ever): the upgrade code, inactive,
   must not change today's rules.
5. Publish the pre-release. A failure at any point means a new rc number.

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
(testnet plan §2.1, §2.2) has three compiled-in profiles (`-testnet -testnetprofile=fast|slow|legacy`,
Revision 3). testnet-yb-fast has a placeholder height (510,400) and no set: its launch ceremony fixes
the height and creates the set, and its rc1 names it (until then R7 refuses a tag). testnet-yb-slow
has neither until its first rc sets both. testnet-legacy never activates Vault.

When setting them in a release:
- The activation height leaves time for every node to upgrade: a node that has not upgraded by
  then stops following the chain. Take the tip from a live node or
  <https://explorer.ycash.xyz/api/v1/network/info>, and leave slack for the time between the
  commit and the tag.
- The attestor set must exist on chain before the release can name it.
- Set the same Vault parameters on `ycash-dd`. Tag `ycash-dd` `vault-params/v<V>` first. Its guard
  (`.github/workflows/yellowback-release-guard.yml`) runs `qa/yellowback-release-heights.sh` and
  refuses the tag unless the version is a 6.22.x release version and the rules of its stage hold
  (below). It also refuses any compared Vault field that differs from ycash6 (`v<V>` when that tag
  already exists, otherwise `upgrade/vault`).
- Then tag ycash6 `v<V>`. This release workflow refuses the tag when `vault-params/v<V>` is
  missing on ycash-dd, when the stage's rules fail, or when any compared Vault field differs
  (`qa/yellowback-release-heights.sh --release-version <V>`). A `workflow_dispatch` run only
  warns, and compares with ycash-dd `upgrade/vault`.

The rules (audit W3-P-1; testnet plan §5.1, T-8):

| Rule | What it requires |
|---|---|
| R1 | a positive mainnet `UPGRADE_VAULT` activation height |
| R2 | a non-zero mainnet attestor set (`MainParams` `attestorSetId`) |
| R3 | mainnet `UPGRADE_VAULT.nProtocolVersion` above 270013, the live network's protocol version |
| R4 | `PROTOCOL_VERSION` at least that value |
| R5 | `MIN_PEER_PROTO_VERSION` at or below 270013 (never the Vault version: it would refuse every stock peer before activation) |
| R6 | mainnet `pqFalconHeight` 0 |
| R7 | per testnet profile, the height and that network's own attestor set both set or both unset; testnet-legacy never has a height |

Which rules a tag needs depends on the stage its version names:

| Tag | Required | Not required |
|---|---|---|
| `v6.22.N-betaM` | parity with ycash-dd, the mainnet set maturity, the 6.22 line; testnet-legacy without a height | heights, sets, protocol version |
| `v6.22.N-rcM` | the above; R3–R6; R7 for the testnet: testnet-yb-fast's height **and** set; testnet-yb-slow's set only with its height (a height alone is its pending activation, T-15); mainnet's height and set both or neither | R1 and R2: mainnet's height and set stay unset on an rc unless the owner sets both |
| `v6.22.N` (final) | R1–R7 | — |

`qa/yellowback-release-heights.sh` reads the stage from `--release-version` (or `--stage`); with
neither it applies the final rules, the strictest.

**Protocol version (taken with rc1, T-8; upgrade plan P8 part D).** `UPGRADE_VAULT.nProtocolVersion`
is 270200 on main, every testnet profile and regtest, and `PROTOCOL_VERSION` is 270200, on both
lines. `MIN_PEER_PROTO_VERSION` stays at the live floor (270013 here; 170002 on ycash-dd, which R5
allows). Before Vault activates nothing changes for peers. Once Vault is the current epoch a node
disconnects a peer below 270200, so the testnets are the first place the epoch gate drops a stale
peer: a drill before mainnet.

| Network | `UPGRADE_VAULT` height | `attestorSetId` | Set in |
|---|---|---|---|
| main | unset | unset | not yet: the release that passes the launch gates |
| test, profile fast | 510,400 (placeholder, N1) | unset (`TestFastParams`) | its launch ceremony; its rc1 names the set (an rc refuses to tag until then) |
| test, profile slow | unset | unset (`TestParams`) | its first rc sets the height, about a week of blocks after launch (T-15); a later rc names the set, created after the activation |
| test, profile legacy | never | none | never: the control network, YED off |

Release notes for the vault rules tightened on 2026-10-12 (audit 01/V-1, 01/V-5, 01/N-1, both node lines):
- **S-0 and V-1's APP clause are retroactive on private chains.** They apply from the activation
  block, so a regtest, devnet or kind chain built by an earlier build that holds a template spend of
  a pre-activation coin, or a V with an APP branch on a tag no module governs, fails the vault
  database's replay on restart (the error names the cause) and a fresh node splits from it: restart
  such a chain from scratch. Mainnet has no activation height, so nothing there changes; the re-forked
  testnet starts after these rules.
- **`-prune` is refused** wherever `UPGRADE_VAULT` has an activation height: a node that pruned
  before its network set one must re-download the chain without `-prune` (there is no `-reindex` on a
  pruned node). That includes a testnet-yb-slow node that prunes before the rc that sets its height;
  testnet-legacy may prune.

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
