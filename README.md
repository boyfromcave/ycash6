Ycash 6.22.0-rc1 with the vault upgrade and Ycash Yellowback (YED)
<img align="right" width="100" height="100" src="doc/imgs/logo.png">
===========

This is the Ycash node on the Zcash 6.20.0 code base, plus a proposed network upgrade. Everything
below up to [What is Ycash?](#what-is-ycash) is about that upgrade; the rest is the Ycash README.

## What this is

This branch adds a proposed **Ycash network upgrade, the vault upgrade**. It gives Ycash one new,
general-purpose feature: **vaults**, YEC locked under rules that every node enforces, released
only with the approval of a bonded **signer set**, after a delay during which the release can be
cancelled, and always recoverable by its owner if the signers go silent. Two applications are
built on it: **Ycash Yellowback (YED)**, a dollar token backed by YEC in vaults, and **wYEC**,
wrapped YEC for Ethereum, backed by YEC in vaults.

The Ycash v4.5.0 line ([boyfromcave/ycash-dd](https://github.com/boyfromcave/ycash-dd)) carries the
same upgrade with the same rules.

## Status

**Status: proposed, not live.** It runs on a local test network (regtest) only. It has not been
adopted by the Ycash Foundation, has not been audited, and has no activation height on mainnet
or testnet.

The vault upgrade is a **hard fork**: every node must upgrade before the activation height; a node
that does not stops following the chain.

## What the upgrade adds

- **Vaults.** YEC (Ycash's coin) locked on chain under rules that every Ycash node enforces.
  Taking YEC out of a vault is a **release**. A release approved by a signer set first becomes a
  **pending release** that waits for a fixed delay and can be cancelled during it. The vault's
  **owner** can always recover the YEC if the signer set goes silent.
- **Signer sets.** A group of bonded members (they lock YEC as a bond) that can approve releasing
  a vault. Members who cheat lose their bond; a set whose members go silent is treated as gone.
  The upgrade is general-purpose: it knows nothing about dollars or Ethereum.
- **Ycash Yellowback (YED)**, a dollar token built on vaults. Lock YEC in a vault to mint YED
  (`1 YED = 1 US dollar`); return the YED to get the YEC back (always, even if the attestors go silent: a
  YED vault is only ever released by burning its YED). If a vault's YEC becomes worth less
  than the YED it backs, others can claim it; the claim waits as a pending release that
  Yellowback's signer set can cancel if it is wrong. The YEC/USD price comes from mining pools and
  from **attestors** (members of Yellowback's signer set who sign prices). YED moves in ordinary
  transparent Ycash transactions, and its rules are enforced by every upgraded node.
- **wYEC (wrapped YEC)**, YEC represented as a token on Ethereum, backed 1:1 by YEC locked in
  Ycash vaults; a signer set releases the YEC when wYEC is burned. Ycash never reads Ethereum.
  This repository holds only the Ycash side of the bridge.

## Try it

This brings up a local test network of eight regtest nodes on one machine, mints YED, and makes a
wYEC bridge round trip with a mock Ethereum. You need `src/ycashd` and `src/ycash-cli` built (see
[Building](#building)), the attestor agent built (`cargo build --release` in
`contrib/yellowback/attest`), and Python 3 (on Python 3.12 or later with `pyasyncore` installed).
From the repository root:

```bash
export PATH="$PWD/contrib/yellowback/devnet:$PATH"

yellowback-devnet up                                     # ~2 min: 8 nodes, upgrade active, prices flowing
yellowback-devnet cli -- yed_mint 10000 48 "" "" false   # mint 100 YED (amounts in cents), YEC locked 48 blocks
yellowback-devnet mine 30                                # confirms the mint; matures coins the bridge needs
yellowback-devnet cli -- yed_getbalance                  # "confirmedCents": 10000

yellowback-devnet bridge up --shape relayer              # a bridge signer set and its daemon
yellowback-devnet bridge lock 20                         # lock 20 YEC in a bridge vault
yellowback-devnet mine 20                                # a new set releases nothing in its first 20 blocks
yellowback-devnet bridge burn 3 $(yellowback-devnet cli -- getnewaddress)   # a mock wYEC burn of 3
yellowback-devnet mine 1                                 # the signers post the pending release
yellowback-devnet mine 7                                 # the 6-block delay passes; the YEC is paid out
yellowback-devnet bridge status                          # the burn, its pending release, the release txid

yellowback-devnet bridge down && yellowback-devnet down --wipe
```

`yellowback-devnet --help` lists every command. `contrib/yellowback/devnet/upgrade-walk` walks
the whole system end to end (claims, cancels, a reorg, both bridge shapes); see
[contrib/yellowback/devnet/README.md](contrib/yellowback/devnet/README.md), section 6.

## For developers

- **The upgrade:** `Consensus::UPGRADE_VAULT`, consensus branch ID `0x6d5b7a31` ("Vault"),
  in `src/consensus/upgrades.cpp`; `src/chainparams.cpp` gives it no height on mainnet or testnet.
- **Script:** BIP68 relative lock-times (height-based) with `OP_CHECKSEQUENCEVERIFY` (`0xb2`),
  and two new opcodes, `OP_CHECKSETSIG` (`0xc0`) and `OP_CHECKSETDORMANT` (`0xc1`). A vault is
  the output template **V**; a pending release is the template **I** (the code calls it an
  *intent*). Signer-set acts (`SET_CREATE`, `SET_JOIN`, `SET_HEARTBEAT`, …) travel in a `YV`
  `OP_RETURN`; set state lives in `<datadir>/vaults/` with per-block undo.
- **YED** is the one registered rule module on the primitive (tag `YED\0`). Its ledger is an index
  under `<datadir>/yellowback/`; because its rules are consensus, a node whose index is unhealthy
  stops. The bridge needs no module.
- **RPCs:** 21 `set_*` / `vault_*` calls on every node ([doc/vault-rpc.md](doc/vault-rpc.md),
  machine-readable in `doc/vault-rpc-contract.json`); the `yed_*` calls, `rpcversion` 5
  ([doc/yellowback-rpc.md](doc/yellowback-rpc.md)).
- **Regtest by hand:** `-nuparams=6d5b7a31:<height>` activates the upgrade; YED also needs
  `-yellowbackattestorset=<setid>`, the txid of its signer set's `SET_CREATE` (sendable only after
  activation, so start with the first option, create the set, restart with both). Both go on top
  of the `-nuparams` for Ycash's earlier upgrades (`yellowback_node_args` in
  `qa/rpc-tests/test_framework/yellowback_util.py`).
- **librustzcash:** `Cargo.toml`'s `[patch.crates-io]` points every `zcash_*` crate at
  [boyfromcave/librustzcash6](https://github.com/boyfromcave/librustzcash6), which adds
  `NetworkUpgrade::Vault` / `BranchId::Vault = 0x6d5b7a31` so the Rust side knows the new epoch.
- **Releases** of this line are tagged 6.22.x by `.github/workflows/yellowback-release.yml`
  ([doc/yellowback-release.md](doc/yellowback-release.md)).
- **The fork delta:** `git diff ycash6-legacy...upgrade/vault` (`ycash6-legacy` is ycashd 6.20.0
  as published). Host build notes are in [doc/yellowback.md](doc/yellowback.md), *Build and test
  baseline (ycashd 6.20.0)*, and [doc/yellowback-baseline.md](doc/yellowback-baseline.md).

| Path | Contents |
|---|---|
| `src/vault/` | The primitive: acts, set-signature checker, set state and its database, V / I templates, module table, block and mempool glue |
| `src/script/`, `src/primitives/transaction.h` | The opcodes, the V and I standard templates, BIP68 sequence locks |
| `src/main.cpp`, `src/txmempool.cpp`, `src/miner.cpp`, `src/rpc/mining.cpp` | Block connect / disconnect, mempool acceptance, block templates (built against a running copy of the set state, `vault::TemplateRun`) |
| `src/yellowback/` | YED: parameters, payload, prices and attestation, index, the rule module, wallet glue |
| `src/rpc/vault.cpp`, `src/rpc/yellowback.cpp`, `src/rpc/yellowbackwallet.cpp` | The RPCs |
| `contrib/yellowback/` | The pool quote agent, the attestor agent (`attest/`), the devnet (`devnet/`) |

Tests:

```
src/test/test_bitcoin --run_test='vault_*'
src/test/test_bitcoin --run_test='yellowback_*'
qa/pull-tester/rpc-tests.py -j4 --nozmq vault_upgrade vault_primitive vault_bridge yellowback_upgrade \
    yellowback_lifecycle yellowback_claim yellowback_void_mint yellowback_wallet_restore yellowback_sapling
python3 -m unittest contrib/yellowback/test_yellowback_price.py contrib/yellowback/test_yellowback_quote.py
```

## Documentation

| Document | What it covers |
|---|---|
| [doc/yellowback.md](doc/yellowback.md) | Using YED from `ycash-cli`, backups, how activation works (*Activation and enforcement since the vault upgrade*) |
| [doc/vault-rpc.md](doc/vault-rpc.md) | The vault and signer-set RPCs |
| [doc/yellowback-rpc.md](doc/yellowback-rpc.md) | The `yed_*` RPCs |
| [doc/yellowback-attestor.md](doc/yellowback-attestor.md), [doc/yellowback-mining.md](doc/yellowback-mining.md) | Running an attestor; mining pools |
| [contrib/yellowback/devnet/README.md](contrib/yellowback/devnet/README.md) | The local test network in full |
| [doc/yellowback-spec.md](doc/yellowback-spec.md) | The YED protocol and its trust statement |
| [doc/yellowback-review.md](doc/yellowback-review.md) | A review guide to the fork's changes |
| [doc/yellowback-release.md](doc/yellowback-release.md) | How releases are built and tagged |

Earlier designs: the `harden/yellowback` branch keeps a version of Yellowback that needs no
network upgrade; the design history is in the project workspace.

What is Ycash?
--------------

Ycash is a digital currency. For more information, see [y.cash](https://y.cash).

For a comparison of Ycash to Bitcoin, see the [Ycash fact sheet](https://y.cash/fact-sheet).

Ycash is a chain fork of Zcash: it shares Zcash's history up to the fork and
its privacy technology (shielded Sapling transactions built on zero-knowledge
proofs), and has followed its own chain since.

## The `ycashd` Full Node

This repository hosts `ycashd`, the Ycash consensus node, together with
`ycash-cli` (its RPC client) and `ycash-gtest` (its unit tests). It downloads
and stores the entire history of Ycash transactions; depending on the speed of
your computer and network connection, the synchronization process could take
a day or more. The node reads its settings from `ycash.conf` in its data
directory (`~/.ycash` on Linux, `~/Library/Application Support/Ycash` on macOS,
`%APPDATA%\Ycash` on Windows). If you are upgrading from Ycash 4.4.4 or 4.5.0,
the binaries (`ycashd`, `ycash-cli`), `ycash.conf` and the data directory
locations are unchanged.

<p align="center">
  <img src="doc/imgs/ycashd_screen.gif" height="500" alt="ycashd startup screen">
  <br>
  <em>The startup screen, captured from <code>ycashd</code> v6.20.0 on a fresh, unconnected mainnet data directory.</em>
</p>

This is the Ycash node rebased by the Ycash developers onto the Zcash 6.20.0
code base. The Zcash code is in turn derived from a source fork of
[Bitcoin Core](https://github.com/bitcoin/bitcoin), initially from Bitcoin Core
v0.11.2; the codebases have since diverged substantially.

**Ycash is experimental and a work in progress.** Use it at your own risk.

## Getting Started

Ycash is a chain fork of Zcash, so for most topics, including `zcashd`
internals, the Zcash documentation applies: see the
[zcashd user guide](https://zcash.readthedocs.io/en/latest/rtd_pages/zcashd.html).
Read `zcashd` as `ycashd`, `zcash-cli` as `ycash-cli` and `zcash.conf` as
`ycash.conf`.

### Need Help?

* Visit [y.cash](https://y.cash).
* Ask for help in one of the [Ycash forums](https://y.cash/forums).

Participation in the Ycash project is subject to a
[Code of Conduct](code_of_conduct.md).

### Building

Build Ycash along with most dependencies from source by running the following command:

```
./zcutil/build.sh -j$(nproc)
```

This produces `src/ycashd` and `src/ycash-cli`; `make check` also builds and
runs `src/ycash-gtest`. The build prerequisites are those of `zcashd`; see the
[zcashd install instructions](https://zcash.readthedocs.io/en/latest/rtd_pages/zcashd.html#install).

### Deprecation Policy

Unlike upstream Zcash, Ycash does not shut a node down at a deprecation
height: the automatic deprecation shutdown is disabled (see
[src/deprecation.h](src/deprecation.h)), and the RPC features upstream
deprecates stay enabled by default (`-allowdeprecated`).

License
-------

For license information see the file [COPYING](COPYING).
