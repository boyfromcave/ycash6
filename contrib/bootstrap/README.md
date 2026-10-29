# `contrib/bootstrap/` — restore a checkpoint bundle (`ycash-bootstrap`)

<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

## In plain words

A new node on one of the Ycash testnets has to load more than half a million old blocks before it
is useful. Downloading them from peers takes hours. This tool loads them from one published copy
instead (a "bundle"), but it does not trust that copy: it compares the copy's fingerprint with
the one written into this release, checks the owner's signature when there is one, re-checks
every block's link to the one before it, and lets the node itself validate every block while it
loads them, cut off from the network. If any check fails, nothing is started. When it finishes,
you start the node as usual and it carries on from there.

## The two layers

- The **prefix** (testnet plan §4.0, the default): Zcash testnet blocks 0..510,247, shared by
  `testnet-yb-fast`, `testnet-yb-slow` and `testnet-legacy` because it carries no network magic.
  Its format is frozen as `ycash-prefix/1` (`ycash-infra` `bundles/prefix/FORMAT.md`); it is
  published as the `ycash-infra` release `testnet-prefix-v1`, and this release pins the sha256 of
  its `SHA256SUMS` (`c7b55a2a…cc403`) in the network profiles (`contrib/yellowback/profiles/`).
- The **state bundle** (§4.1, `--state --source DIR|URL`): a ycash6 datadir at a height H_B above
  the fork, in the format `ycash-state/1` that `ycash-infra` `bundles/state/FORMAT.md` defines and
  its snapshotter produces (draft ycash-infra#17 at the time of writing). This tool is its
  consumer and follows that file; it does not define the format. A ycash-dd node does not start
  from a state bundle (FORMAT.md: the two lines' on-disk formats are not promised to agree); it
  syncs from peers, which is what makes it an independent verifier.

## Usage

```bash
contrib/bootstrap/ycash-bootstrap --network testnet-yb-fast --datadir ~/.ycash \
    --ycashd src/ycashd --cli src/ycash-cli                    # the pinned prefix, from the release
contrib/bootstrap/ycash-bootstrap --network testnet-yb-slow --datadir DIR --source /path/to/bundle --ycashd … --cli …
contrib/bootstrap/ycash-bootstrap --network testnet-legacy --datadir DIR --reset --ycashd … --cli …   # a testnet reset (T-7)
contrib/bootstrap/ycash-bootstrap --network regtest --datadir NODE_DATADIR --rpcport P --cli src/ycash-cli \
    --pack OUT --last-height N                                   # a regtest bundle from a running node (tests, the ceremony rehearsal)
```

| Option | Meaning |
|---|---|
| `--network` | `regtest`, `testnet-yb-fast`, `testnet-yb-slow`, `testnet-legacy`: the profile (magic, genesis, datadir, pins) |
| `--datadir` | the node's `-datadir`; the network's subdirectory (`testnet-yb-fast`, …) must hold no chain yet |
| `--source` | `prefix` (default: the profile's release URL), an `https://` or `file://` URL, or a directory; a trailing `manifest.json` is accepted |
| `--state` | restore a `ycash-state/1` bundle from `--source` instead of the prefix |
| `--reset` | move the network's `wallet.dat` aside (`DATADIR/wallet-before-reset-<net>-<time>.dat`), remove its subdirectory, restore |
| `--verify-full` | import with `-checkpoints=0`: every block's scripts are validated, not only those above the checkpoint |
| `--ycashd`, `--cli` | the binaries the import runs (default: on `PATH`) |
| `--conf`, `--node-arg` | the node's `ycash.conf`, and extra `ycashd` arguments for the import (regtest's `-nuparams=…`) |
| `--require-signature` | refuse a `SHA256SUMS` without `SHA256SUMS.minisig` |
| `--allow-unpinned` | accept a `SHA256SUMS` this release does not pin (a newer bundle, checked by its signature and the format alone) |
| `--frame-only DIR` | check and frame only; print the `-loadblock=` arguments and start nothing |
| `--work`, `--keep` | the download and framing directory (default `DATADIR/bootstrap-work`, removed when done) |

Exit status: 0 restored; 2 refused (the message says which check) or a usage error.

## The checks, in order

1. The network's subdirectory holds no `blocks/` or `chainstate/` data (unless `--reset`).
2. `SHA256SUMS`: its sha256 equals the profile's `prefix.sha256sums_sha256`; every line is
   `<sha256>  <name>` with a name of the format, sorted. A `SHA256SUMS.minisig` beside it must
   verify with the owner's key, `keys/ycash-release.pub` (`RWQYr5PF…dveOGQ`, key id
   `02C923A6C593AF18`, decision T-6), using `minisign`; without a signature the tool says so and
   relies on the pin (optional until the bundle is signed).
3. `manifest.json` matches its sum, then the format (`ycash-prefix/1`, the profile's network
   name, the 50,000-block chunk rule, file names, sizes) and the release: `last_height` and its hash
   equal the compiled checkpoint (510,247 `0000ec90…fb31`), the compiled earlier checkpoints
   (38,000, 207,500, 280,000) and the genesis.
4. Each chunk is downloaded (or reused when its sha256 already matches) and checked against
   `SHA256SUMS` and the manifest, then framed for `-loadblock` as
   `<network magic> <LE u32 length> <block>` (fast `f77962d3`, slow `f77962d4`, legacy `f77962d5`,
   regtest `aae83f5f`), checking the hash chain, the genesis, every listed hash, the raw size and
   raw sha256.
5. `ycashd` imports the framed files with `-connect=0 -listen=0 -dnsseed=0 -disablewallet=1` on a
   free local RPC port (`--conf` supplies the credentials; otherwise the cookie). The wallet is left
   for the node's first normal start, so a `-mnemonicfile` restore still applies there.
6. The node reaches the last height; `getblockhash` equals the manifest at every listed height and
   the checkpoint at the last; the node is stopped, the framed files are removed, and
   `<network>/bootstrap.json` records what was restored (sums sha256, pinned, signed, tip, timings).

A refused block shows up as an import that read every file and stopped below the last height; the
tool then fails and names the node's `debug.log`.

## The state bundle's checks

1. `SHA256SUMS` (every line `<sha256>  <name>`, sorted bytewise) and its signature as above; no
   pin (state bundles roll), so the anchors are the statements and the node's own check (§4.2).
2. `manifest.json`: canonical; `format` `ycash-state/1`, `network` the profile's datadir name,
   `profile` its `-testnetprofile`, `line` `ycash6`, H_B at or above the fork, the tarball's name
   rule and sum; `verifiers` at least two, sorted; `SHA256SUMS` names exactly the manifest, the
   tarball and one `statement-<verifier>.json` each. A compiled checkpoint at H_B must match.
3. Every statement is canonical, byte-identical to the others and equal to the manifest's fields.
4. The tarball matches the manifest's sha256 and size; only directories and regular files under
   `<network>/{blocks,chainstate,vaults,yellowback}` are extracted (no absolute paths, `..`,
   links, `wallet.dat`, `yellowback/carriers.dat`, LevelDB `LOCK`/`LOG`; the insight index only in
   the `full-insight` flavour).
5. The node starts offline (`-connect=0 -listen=0 -dnsseed=0 -disablewallet`, plus
   `-experimentalfeatures -insightexplorer -txindex` for `full-insight`) and settles. The bundle's
   block files may hold blocks above H_B (`-stopatheight` stops the chain state, not the
   download), so when the tip is above H_B the tool runs `invalidateblock` on H_B + 1, computes
   every statement field itself (`getblockhash`, `getblockheader`.chainwork,
   `gettxoutsetinfo`.hash_serialized, `vault_getinfo`.statehash at `dbtip` = H_B,
   `yed_getstatehash H_B`), compares, and `reconsiderblock`s the same block so the datadir keeps no
   failed-block mark. Any failure removes what was extracted.

## Relation to `ycash-infra`

The format and the framing are the ones `ycash-infra` `bundles/prefix/FORMAT.md` freezes and
`bundles/prefix/import/frame.py` implements for its CI import check. This is a second, independent
implementation written from that contract (FORMAT.md allows one), not a copy: the node release must
not depend on the infrastructure repository's source, and it adds what that script does not need —
the per-network profile and pins, the signature, `--reset`, regtest bundles (`--pack`) and running
the import itself. `testdata/testnet-prefix-v1/` holds the release's own `SHA256SUMS` and
`manifest.json`, so the unit tests check the pins against the published files offline.

## Tests

- `python3 -m unittest contrib/bootstrap/test_ycash_bootstrap.py` (offline): the format round
  trip, every refusal, the signature path with a stand-in `minisign`, an HTTP source, a whole
  restore with a stand-in `ycashd`/`ycash-cli`, and the published prefix against the three profiles.
- The state path in the same file: a bundle built to `bundles/state/FORMAT.md` (it passes
  ycash-infra's `verify.py`) restored against a stand-in node that holds blocks above H_B: the
  rollback, the comparison, the `reconsiderblock`, and the refusals (paths outside the format, a
  left-out file, another network, a changed statement, a height below the fork). No functional
  test restores a real state bundle yet: that needs a ycash6 datadir from the snapshotter.
- `qa/rpc-tests/ycash_bootstrap.py` (CI, needs `ycashd`): a regtest chain packed with `--pack`,
  restored into a fresh datadir by a real `ycashd`, which then starts at the same tip; a tampered
  chunk refused before any node starts.
- `contrib/testnet/ceremony --rehearse` (`qa/rpc-tests/testnet_ceremony.py`) restores a regtest
  prefix the same way before its private mining.
