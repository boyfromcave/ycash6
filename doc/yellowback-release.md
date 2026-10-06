# Releasing ycashd with Ycash Yellowback (YED)

How a tagged version of this fork (`boyfromcave/ycash6`, branch `feature/yellowback`) becomes a
GitHub release with one binary package per platform, in the layout of upstream Ycash's releases
(<https://github.com/ycashfoundation/ycash/releases>). The automation is
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
banner must be `v<V>`, and a throwaway regtest node with `-yellowback` must start, answer
`getnetworkinfo` and `yed_getinfo`, and stop. The Windows `.exe` files are run on windows-latest
(version banners only). The 18.04 package's smoke test runs inside an `ubuntu:18.04` container,
which also proves its glibc floor.

There is **no separate mining-pool package** (see "Mining pools" below).

Binaries are unsigned, as upstream's are, and builds are not reproducible (the inherited gitian
descriptors are not maintained).

## Version numbers

`configure.ac` encodes the stage in `_CLIENT_VERSION_BUILD`: 0–24 is `-beta<BUILD+1>`, 25–49 is
`-rc<BUILD−24>`, 50 is the final release, above 50 is `-<BUILD−50>`. `src/clientversion.h` carries
the same four numbers. The release line is **6.21.x**: Yellowback is a feature addition on 6.20.0,
and 6.20.x patch numbers belong to the upstream 6.20 line (miodragpop/ycash).

| Release | MINOR | REVISION | BUILD | Tag |
|---|---|---|---|---|
| 6.21.0-rc1 | 21 | 0 | 25 | `v6.21.0-rc1` |
| 6.21.0-rc2 | 21 | 0 | 26 | `v6.21.0-rc2` |
| 6.21.0 | 21 | 0 | 50 | `v6.21.0` |
| 6.21.1 | 21 | 1 | 50 | `v6.21.1` |

`configure.ac` is in the frozen set. `qa/yellowback-audit.sh` allows exactly the four
`_CLIENT_VERSION_*` defines to change there and fails on any other line.

## Procedure

1. **Bump the version** on a branch off `feature/yellowback`: the four numbers in `configure.ac`
   and `src/clientversion.h`, plus the title line of `README.md`. Run `qa/yellowback-audit.sh`.
2. **Write the notes** at `doc/release-notes/release-notes-<V>.md`. The release job refuses to run
   without them. Start from the previous one.
3. **Proving run.** Push the branch and merge it to `feature/yellowback` once `yellowback tests`
   is green. Then run the workflow by hand: Actions → *yellowback release* → *Run workflow* on
   `feature/yellowback`. It builds, smoke-tests and uploads every package as a workflow artifact,
   but creates no release. Download and spot-check at least one package.
4. **Tag and push.**
   ```
   git tag -a v<V> -m "ycashd v<V> (Yellowback)" <commit>
   git push origin v<V>
   ```
   The `version` job fails if the tag differs from what `configure.ac` renders.
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

## Network parameters (START_HEIGHT, ENFORCE_UNTIL_HEIGHT)

`src/yellowback/params.cpp` carries one start height and one sunset per public network. They are
consensus parameters (K10): hashed into the state hash, and they decide which tags, registrations
and vault references exist. So they ship only in a release, never as an operator flag. A network
whose `startHeight` is 0 refuses `-yellowback` at init.

When setting them in a release:
- `startHeight` at least two weeks of blocks (16,128 at 75 s) past the release date (M14). Take the
  tip from a live node or <https://explorer.ycash.xyz/api/v1/network/info>, and leave slack for the
  time between the commit and the tag.
- `enforceUntilHeight` = `startHeight` + 420,480 (one year, L8), and never past the next scheduled
  Ycash network upgrade (`chainparams.cpp`).
- A set that replaces a released one starts at or after that set's `enforceUntilHeight` (L8), and
  above every height a released node has validated (M12).
- Make the same change on the other node line (`ycash-dd`): both lines must agree.
- The release workflow refuses a tag while the mainnet `startHeight` is 0 or `enforceUntilHeight`
  is not above it (`qa/yellowback-release-heights.sh`; a `workflow_dispatch` run only warns).

| Network | startHeight | enforceUntilHeight | abandonBlocks | Set in |
|---|---|---|---|---|
| main | 0 (unset) | 0 | 34,560 (= `grace`, W21) | not yet: the 6.21.0-rc1 set (3,075,000 / 3,495,480) was withdrawn on 2026-10-05 (hardening plan F-5, H-8); the release that passes the launch gates sets it |
| test | 0 (unset) | 0 | 34,560 (= `grace`, W21) | not yet: testnet had no reachable peers on 2026-10-02 (no fixed seeds; `testseed.ycash.xyz` not answering) |

`abandonBlocks` (`ABANDON_BLOCKS`, W21) is compiled in with the other §3.1 values and is not set
per release: it equals `grace` (thirty days) on mainnet and testnet, 128 on regtest, and the unit
tests hold `abandonBlocks >= grace` on every network. It is the floor on how long the module waits
for its developers after any halt before pools stop filtering vault spends and wallets offer
`yed_sweep` — the time budget of the "Freeze, then fix" runbook below.

## Renewal releases (W18)

`ENFORCE_UNTIL_HEIGHT` is a sunset, not a deadline for new values. A release that carries **the
same parameter set with only a later `enforceUntilHeight`** is a *renewal*: it cannot make two
enforcing releases disagree at one height (a node left on the old release stops rejecting at the
old sunset and becomes permissive, and a permissive node follows whatever the stricter majority
builds), so it is exempt from the "start at or after the previous sunset" rule above and may ship
at any time before the sunset. `ParamsHash` sees it as a different set only in `enforceUntilHeight`.

**Obligation:** the renewal for each year ships **no later than six months before the sunset**
(for the 6.21.0-rc1 set, before height ≈ 3,285,000, 2027-04), so a missed date costs a warning,
not an enforcement gap. Put the next renewal's due height in the release notes of every release
that sets or renews a sunset. A release that changes any other value is a *parameter change* and
follows the rule above or the runbook below.

## Freeze, then fix (W19)

Roughly seventy consensus-shaped values go to mainnet for the first time with 6.21.0. If one is
wrong, the rule "a replacement set starts at or after the previous sunset" would leave it in force
for up to a year. The sanctioned shortcut is to make the chain itself show that no node is
enforcing the old set: a replacement set may start at height `X` when either `X ≥` the previous
set's `enforceUntilHeight`, **or** `Snapshots[h].haltMask` has had `ENFORCEMENT` set for every
`h` in `[X − SIGNAL_WINDOW, X − 1]` — enforcement has been off for a full window (2,016 blocks,
≈ 1.75 days), so no node validated a vault spend under the old set in that stretch. The predicate
is `yellowback::ParamSetStartAdmissible` (`src/yellowback/params.cpp`, `// Rule: ACT-5`), a
release-time check with a unit case over a synthetic halt; `SelectParams` itself does not change,
sets are chosen by height as before.

The runbook:

1. **Freeze.** Ask the pools to restart with `-yellowbackenforce=0` (the existing kill switch;
   signalling stops with it). Within one signal window the share of signalling blocks falls under
   `ENFORCEMENT_FLOOR` (50 %) and `Snapshots[h].haltMask` gains `ENFORCEMENT`; `PARTICIPATION`
   sets first, at 60 %, and minting stops (`yed_getstats.mintableClasses` empty,
   `yed_getactivation.mintHalted`). Confirm the bit on a node of record with
   `yed_gethistory <h> <h>` for the first halted height; call it `F`.
2. **Wait one signal window** after `F` so the earliest admissible start is `F + SIGNAL_WINDOW`.
   Meanwhile ship the corrected set with `startHeight = X ≥ F + SIGNAL_WINDOW` and a new sunset
   (`X + 420,480`), on both node lines, with the `ACT-5` unit case extended for the real `F` and
   the usual release procedure above. Lead time M14 still applies to `X` from the release date.
3. **Upgrade and re-signal.** Pools install the release and restart with enforcement on. The signal
   count climbs over a window, enforcement resumes at `ENFORCEMENT_RESUME` (60 %); from `X` the
   index applies the corrected set. Activation (ACT-1..3) does not run again: the module stays
   ACTIVE throughout, only its halts move.

What is and is not at risk during the freeze:

- **No YED can be created.** Evaluation never stops; every MINT in the stretch is VOID
  (`mint-halted-participation`) and its collateral comes back by `yed_redeem` at its lock height.
- **Existing vaults stay script-locked** until their own `lockHeight` (owner) and `claimHeight`
  (anyone). The claim branch is open to anyone past `claimHeight`, and with enforcement off nobody
  refuses a claim without its burn — but the pools on the release still *filter* rule-breaking
  vault spends from their own templates and mempools (TPL-1, MP-1) until abandonment, so leakage
  is bounded by stock hashpower and by the vaults whose `claimHeight` falls inside the freeze.
  Owners redeem before the freeze if they can; a wallet should warn on any vault within `GRACE`
  of its claim height.
- **YED transfers and redemptions continue** as ordinary transactions; the index records them.
- **Abandonment is the clock.** `ABANDON_BLOCKS` = `GRACE` = 34,560 blocks (≈ 30 days, W21) of
  the `ENFORCEMENT` halt is where the pools' filtering stands down and wallets offer `yed_sweep`.
  Thirty days is the floor on how long the module waits for its developers; a freeze that takes
  longer than that has become abandonment, and what leaks meanwhile is the cost. Abandonment is a
  rolling predicate: enforcement resuming ends it.

Rejected for now: set-version signalling in the coinbase tag (a live switch with no freeze, a real
design addition) and miner-voted parameters (a different design).

## Wallet (YecWallet) releases

YecWallet bundles `ycashd`. Its release should take these packages as inputs rather than rebuild
the node, so a node release comes first.
