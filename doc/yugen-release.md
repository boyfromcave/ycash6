# Yugen release build (6.23.x)

The Yugen line (`upgrade/yugen`, `src/yugen/` present) releases **6.23.x** (first: 6.23.0-beta4,
`_CLIENT_VERSION_BUILD 3`). It builds as the vault line does (`doc/yellowback-release.md`,
`.github/workflows/yellowback-release.yml`), plus the three Yugen helpers
(`src/Makefile.yugen.include`, `doc/yugen-node.md` "Helper build").

## Version guard

- The release workflow's version step selects the line from the tree: `src/yugen/` gives 6.23,
  else `src/vault/` gives 6.22, else 6.21. A tag must equal configure.ac's version and lie on the
  line; otherwise it is refused (a strict proving run likewise).
- `qa/yellowback-release-heights.sh --release-version` applies the same rule to the tree it reads
  (`qa/test_yellowback_release_heights.py`, `test_yugen_tree_releases_6_23`).
- Activation: `UPGRADE_YUGEN` is `NO_ACTIVATION_HEIGHT` on mainnet and testnet
  (`src/chainparams.cpp`); regtest only by `-nuparams=59474e30:<h>`. A height is set only by a
  gate-passing release, as for `UPGRADE_VAULT`. The release workflow's version job refuses, at every
  stage and on a proving run, a tree in which any chain-parameter class gives `UPGRADE_YUGEN` a
  height (`qa/yugen/release-activation.py`): known issue K-1 (`doc/yugen-node.md`) must land on every
  node line before one is set, and that release changes the guard with it.
- The Vault fields are compared with ycash-dd's pairing tag `vault-params/v<V>` as on the vault line
  (`doc/yellowback-release.md`, Network parameters), so that tag must exist before `v<V>` is pushed.

## Platforms

The helpers are built with the runner's own rustup toolchain and are not cross-built, so the Yugen
line packages the native builds only:

| Asset | Built on | Tier |
|---|---|---|
| `ycashd_v<V>_linux_x86_64.tar.gz` | ubuntu-22.04, native (glibc 2.35 floor) | 1 |
| `ycashd_v<V>_linux_aarch64.tar.gz` | ubuntu-22.04-arm, native | 1 |
| `ycashd_v<V>_macos_aarch64.tar.gz` | macos-15, native, `MACOSX_DEPLOYMENT_TARGET=11.0` | 1 |
| `ycashd_v<V>_macos_x86_64.tar.gz` | macos-15-intel, native | 2 |

No Windows and no Ubuntu 18.04 package (the version job renders the matrix per line). Each package
holds `ycashd`, `ycash-cli`, `ycash-tx`, `ycashd-wallet-tool`, `yugen-leafverify`, `yugen-sendbuild`,
`yewd-yugen` and `COPYING`; ycashd takes the first two from its own directory as the defaults of
`-yugenverifier` and `-yugenbuilder`, and `-yugenprover=<dir>/yewd-yugen` turns on the wallet's Yugen
account. The signing job refuses a package without the three helpers. Not packaged: System B's
`b2verify` and its verifying plan (`-yugenb2verify`, `-yugenbplan`), which only a node verifying real
bundle proofs needs; regtest runs without them (a warning), and no public network has a Yugen height.

The smoke test (`qa/yellowback-release-smoke.sh`) also starts each helper (usage exit), restarts the
node with `-nuparams=59474e30:<h>`, and checks that Yugen activates with the packaged verifier
(`yugen_getinfo`: active, `tree_size` 1, a root).

## Sources

Every source is a public URL at an exact commit:

| what | where pinned | repository |
|---|---|---|
| librustzcash6 (`zcash_*`, `f4jumble`) | `Cargo.toml` `[patch.crates-io]`, `Cargo.lock`, `.cargo/config.toml.offline` | `https://github.com/boyfromcave/librustzcash6.git` @ `057511f1d355` (contains bfd5027b) |
| Yugen specification and `yugen-ref` | `contrib/yugen-*/PINS` | `https://github.com/boyfromcave/yugen-spec.git` @ `e93f9775c017` |
| Falcon | same | `https://github.com/boyfromcave/yugen-falcon.git` @ `874438b9f6c1` |
| proof system A | same | `https://github.com/boyfromcave/yugen-proof-a.git` @ `bbe5c5f6441a` |
| proof system B2 | same | `https://github.com/boyfromcave/yugen-proof-b2.git` @ `3e7a5d061285` |
| wallet (yew, `upgrade/yugen`) | `contrib/yugen-sendbuild/PINS` | `https://github.com/boyfromcave/yew.git` @ the commit on the `clones/yew` line of that file (the one place it is set) |

When the librustzcash6 commit moves, change it in all three files together.

## Offline build

1. `make -C depends` (online): builds the toolchain, checks out the PINS repositories into
   `contrib/yugen-*/deps/`, and runs `cargo vendor --locked` over ycashd's lock and the three
   helper locks (`contrib/yugen-leafverify`, `contrib/yugen-sendbuild`,
   `contrib/yugen-sendbuild/deps/clones/yew/yewd/yugen`) into `depends/<host>/vendored-sources`.
2. `./configure` (no `--enable-online-rust`) and `make`: `.cargo/config.toml` maps crates.io and the
   librustzcash6 git source to that directory; ycashd and the helpers build with `--locked --offline`.
   Proof run: an empty `CARGO_HOME`, `CARGO_NET_OFFLINE=true` (`target/logs/cold-build.sh` in a
   working tree).

The helpers need rustup with the toolchain in `contrib/yugen-*/rust-toolchain.toml` installed.

## Building before publication

Until the repositories above are public, local builds redirect them:

- helpers: `export YUGEN_LOCAL_ROOT=<directory holding local checkouts>` (the PINS paths under it);
- librustzcash6 (depends' `cargo vendor`, or `--enable-online-rust`):
  `export CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_CONFIG_COUNT=1
  GIT_CONFIG_KEY_0=url.file://<local librustzcash6 clone>.insteadOf
  GIT_CONFIG_VALUE_0=https://github.com/boyfromcave/librustzcash6.git`.

Neither changes a tracked file; `cargo vendor --locked` under them checks `Cargo.lock` against the
public URL form.
