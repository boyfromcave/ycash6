Ycash 6.21.0-rc1
<img align="right" width="100" height="100" src="doc/imgs/logo.png">
===========

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

**This branch (`upgrade/vault`) also carries a network upgrade**, the Vault upgrade, and Ycash
Yellowback (YED) on top of it; see [Ycash Yellowback (YED)](#ycash-yellowback-yed) below. It is not
activated on mainnet or testnet.

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

## Ycash Yellowback (YED)

This branch adds a **network upgrade** to Ycash, `UPGRADE_VAULT` with the new consensus branch ID
`0x6d5b7a31` ("Vault"), which follows NU6.2 in the upgrade table. It adds a generic,
application-agnostic vault primitive to consensus, and two applications on it: a bridge template
for wrapped YEC (wYEC) and Ycash Yellowback (YED), an over-collateralised US-dollar stablecoin
(`1 YED = $1`): YEC is locked in a vault to mint YED, and YED moves in ordinary transparent Ycash
transactions.

* **A hard fork.** From the activation height a node that has not upgraded, such as a stock
  ycashd 6.20.0, can no longer follow the chain. **No public network has an activation height:**
  mainnet and testnet leave `UPGRADE_VAULT` unset and name no YED attestor set, so today the
  upgrade runs only on regtest and the one-laptop devnet.
* **The primitive** (`src/vault/`): BIP68 relative lock-times (height-based only),
  `OP_CHECKSEQUENCEVERIFY`, and two new opcodes, `OP_CHECKSETSIG` and `OP_CHECKSETDORMANT`;
  **signer sets** as a consensus object (bonds, unlock / cancel / slash thresholds, a rate limit,
  slashing on equivocation, liveness and dormancy), whose acts travel in a `YV` `OP_RETURN` and
  whose state lives in `<datadir>/vaults/` with per-block undo; the **vault (V)** and **intent (I)**
  templates with unlock, cancel and owner-recovery branches; 21 `set_*` / `vault_*` RPCs on every
  node, no flag needed ([doc/vault-rpc.md](doc/vault-rpc.md)).
* **The wYEC bridge template** (Ycash side only): lock, an intent signed by the bridge's set,
  release after a delay, cancel during it, owner recovery if the set goes silent; one relayer with
  challengers or a guardian set, both as configurations of the primitive. No bridge code is in
  consensus.
* **Yellowback is the one registered rule module** (`YED\0`): from the activation height its block
  verdict is **consensus** on every upgraded node. The YED vault is a V vault: the owner redeems by
  burning the debt; an underwater vault is claimed into a claimant intent that the YED attestor
  set may cancel during `CLAIM_DELAY` and anyone may release after it; if the attestor set goes
  dormant the owner recovers the collateral without a burn. Prices combine pool quotes with bonded
  attestors (v3 price attestation), who register by joining the YED attestor set (`SET_JOIN`) and
  send heartbeats. The `yed_*` RPCs report `rpcversion` 5.
* **Retired on this branch:** pool signalling and lock-in, the work valve, the kill switch, the
  sunset, abandonment, `yed_sweep`, and the `-experimentalfeatures -yellowback` gate (the old
  enforcement flags are ignored or refused at startup). A node whose Yellowback index is
  unhealthy stops rather than validate without it.

**What is specific to ycashd 6.20.0.** The Rust side learns the new epoch from the patched
librustzcash: `Cargo.toml`'s `[patch.crates-io]` points every `zcash_*` crate at
`boyfromcave/librustzcash6`, which adds `NetworkUpgrade::Vault` / `BranchId::Vault = 0x6d5b7a31`.
The miner applies set acts, template rules and the YED module to a block template through
`vault::TemplateRun`, a running copy of the set state over the vault database. The Ycash v4.5.0
node line (`boyfromcave/ycash-dd`, branch `upgrade/vault`) carries the same upgrade with the same
rules, checked by golden test vectors shared by both lines. Releases of this branch are tagged
6.22.x (`.github/workflows/yellowback-release.yml`); none is tagged yet. The branch
`harden/yellowback` is the no-upgrade fallback line, a miner-enforced soft fork released as 6.21.x.

**Running it.** YED is live wherever `UPGRADE_VAULT` has a height and the YED attestor set is
known. On regtest, on top of the `-nuparams` the regtest harness passes for Ycash's own upgrades
(`qa/rpc-tests/test_framework/yellowback_util.py`), that is `-nuparams=6d5b7a31:<height>` and
`-yellowbackattestorset=<setid>` (the txid of the set's `SET_CREATE`, which can only be sent once
the upgrade is active). The devnet does all of it: `contrib/yellowback/devnet/yellowback-devnet up`
starts eight regtest nodes with the upgrade active, the attestor set created and YED armed, and
`upgrade-walk` and `yellowback-devnet bridge` walk the whole ecosystem and the bridge persona
([contrib/yellowback/devnet/README.md](contrib/yellowback/devnet/README.md), section 6).

**Status.** Implemented and tested on regtest and the devnet on both node lines. **Not adopted by
the Ycash Foundation, not audited, and not activated on any public network.** The launch gates
and the parameter calibration are open; the release that passes them sets the mainnet activation
height and attestor set.

Read more:

* [doc/yellowback.md](doc/yellowback.md): the user guide (*Activation and enforcement since the vault upgrade* is current; v2/v3 text elsewhere is history);
* [doc/vault-rpc.md](doc/vault-rpc.md): the `set_*` / `vault_*` RPC contract;
* [doc/yellowback-rpc.md](doc/yellowback-rpc.md): the `yed_*` RPC contract;
* [doc/yellowback-devnet.md](doc/yellowback-devnet.md): a local devnet or a regtest node in a few minutes;
* [doc/yellowback-release.md](doc/yellowback-release.md): how releases are built and tagged;
* [doc/yellowback-review.md](doc/yellowback-review.md): what the overlay changes in ycashd 6.20.0 and the evidence that it is safe;
* [doc/yellowback-baseline.md](doc/yellowback-baseline.md): the 6.20.0 baseline the overlay is built on, and what it took to build and run it.

License
-------

For license information see the file [COPYING](COPYING).
