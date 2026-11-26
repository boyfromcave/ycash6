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
  gate-passing release, as for `UPGRADE_VAULT`.

## Sources

Every source is a public URL at an exact commit:

| what | where pinned | repository |
|---|---|---|
| librustzcash6 (`zcash_*`, `f4jumble`) | `Cargo.toml` `[patch.crates-io]`, `Cargo.lock`, `.cargo/config.toml.offline` | `https://github.com/boyfromcave/librustzcash6.git` @ `057511f1d355` (contains bfd5027b) |
| Yugen specification and `yugen-ref` | `contrib/yugen-*/PINS` | `https://github.com/boyfromcave/yugen-spec.git` @ `77af00586e66` |
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
