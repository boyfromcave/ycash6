ycashd v6.23.0-beta4 — Yugen, beta 4
====================================

This is a **beta** for testing on regtest and private devnets, not for production. It is the
first release of the **Yugen line** (6.23.x): ycashd 6.20.0 with the vault upgrade and Ycash
Yellowback (YED), as on the 6.22 line, plus **Yugen**, a proposed post-quantum shielded pool,
as a further network upgrade (consensus branch ID `0x59474e30`).

**Yugen has no activation height on any public network.** Mainnet and every testnet profile keep
`UPGRADE_YUGEN` at no height, so on those networks this build follows the same rules as the
6.22 line. Yugen runs only where you turn it on yourself: regtest or a private devnet, with
`-nuparams=59474e30:<height>` (which needs the vault upgrade active at or below that height). The
release workflow refuses any tag of this line that gives Yugen a height (known issue K-1, below).

Yugen, the vault upgrade and Yellowback are proposed, not adopted by the Ycash Foundation, and not
audited. The design notes are `doc/yugen-node.md`; the build and sources are `doc/yugen-release.md`.

What you must do when upgrading
-------------------------------

1. **Nothing, on mainnet and the public testnets.** Yugen is inactive there, and the vault-line
   rules are the same as on the 6.22 line at the commit this line was cut from (below).
2. **Clients: accept `rpcversion` 12.** `yed_getinfo.rpcversion` is 12 on this line (11 on the
   6.22 line's beta4, 10 on 6.22.0-beta3). No `yed_*` field changes shape for Yugen; 12 says the
   node also has the Yugen RPCs below. A client that requires exactly 10 or 11 must accept 12.
3. **Keep the helper binaries next to `ycashd`.** The package holds `yugen-leafverify`,
   `yugen-sendbuild` and `yewd-yugen` beside `ycashd`. ycashd uses the first two from its own
   directory by default; a node with a Yugen height refuses to start without the verifier.
4. **macOS:** the binaries are not code-signed. Clear the quarantine flag on the unpacked
   directory (`xattr -dr com.apple.quarantine ycashd_v6.23.0-beta4_macos_aarch64`) and check the
   signatures below instead.

Platforms
---------

Linux x86_64 and aarch64 (glibc 2.35 or later), macOS on Apple silicon (11.0 or later), and, as a
tier-2 build, macOS on Intel. **No Windows and no Ubuntu 18.04 package in this line:** the Yugen
helpers are built natively and are not cross-built. Use the 6.22 line on those systems.

What Yugen adds
---------------

- **A shielded pool with post-quantum spend authority.** Yugen transfers ("leaves") carry their
  proofs inline and are verified by `yugen-leafverify`, a helper process ycashd runs (never linked
  into ycashd). Value enters and leaves the pool through the turnstile, which consensus keeps at or
  above zero. Bundles aggregate transfers under one proof; bundling is optional.
- **Node RPCs:** `yugen_getinfo`, `yugen_getblockdata`, `yugen_getanchor`, `gettransferstatus`,
  `submittransfer`, `submitbundle`.
- **The wallet's Yugen account**, run through `yewd-yugen` (`-yugenprover=<path>`; without it the
  node keeps no Yugen account and behaves as stock): `z_getnewaddress yugen` gives the account's
  short address (`yqrf…` on regtest; `yqf…` and `yqtf…` are the mainnet and testnet forms), `z_sendmany` pays a Yugen address, a transparent address or a Sapling
  address from the account in one call, and `z_getbalance`, `z_gettotalbalance`, `z_listunspent`,
  `z_listreceivedbyaddress`, `listtransactions` and `gettransaction` include Yugen rows. The account
  seed comes from the wallet's seed; `dumpwallet` / `z_exportwallet` write a `yugenseed=` line and
  the import RPCs restore from it. Resolving a short address needs two mailbox hosts
  (`-yugenhosts`). The transfer fee is fixed at 255,600 zat.
- **Options:** `-yugenverifier`, `-yugenbuilder`, `-yugenprover`, `-yugenwallet`, `-yugenhosts`,
  `-yugensyncdelay`, `-yugenprovetimeout`, `-yugenverifytimeout`, `-yugenmempoolverifytimeout`,
  `-yugenpeerverifyrate`, `-yugenb2verify`, `-yugenbplan`, and the regtest-only test switch
  `-yugenteststubproofs` (`ycashd -help`).
- **Not in the package:** System B's root verifier `b2verify` and its verifying plan
  (`-yugenb2verify`, `-yugenbplan`). Only a node that verifies real bundle proofs needs them; a
  regtest node starts without them, with a warning. Build them from `yugen-proof-b2` at the commit in
  `contrib/yugen-leafverify/PINS` (its `docs/b2verify.md`).

Sources
-------

Every Yugen dependency is a public repository at an exact commit (`contrib/yugen-*/PINS`,
`Cargo.toml` `[patch.crates-io]`, `doc/yugen-release.md`): librustzcash6 `057511f1d355`,
yugen-spec `e93f9775c017` (specification 0.5.5), yugen-falcon `874438b9f6c1`, yugen-proof-a
`bbe5c5f6441a`, yugen-proof-b2 `3e7a5d061285`, and the wallet engine from yew `ab5007faa753`.

From the vault line
-------------------

This line was cut from the 6.22 line's `upgrade/vault` after 6.22.0-beta3 and carries its changes
since then: tag v2 (a post-quantum payout key; `rpcversion` 11 there), the fast-testnet attestor-set
slot (still unset), `z_shieldcoinbase` moving post-quantum mining rewards at the exact amount, a
seed restore that completes on a chain no new block extends, the pool quote agent's one fetch per
block, and the snapshot-restore fix. `doc/release-notes.md` lists them.

Known issues
------------

- **K-1, consensus, not built: withdrawal classification (specification §13.3.5, §15.6 B6).** A
  node of the specification classifies each withdrawal as immediate, maturing or queued and keeps a
  window's outflow state; this build makes every withdrawal's outputs immediate. The two would split
  on the first withdrawal they classify differently. It must land, on every node line, **before any
  activation height is set**; until then no public network activates Yugen (and §13.3.1 forbids an
  activation with the provisional safety parameters in any case).
- **K-3, wallet and indexes do not track a bundle's VB coins.** A bundle's deposits and withdrawals
  are records, not `vin`/`vout`, and the wallet and the insight indexes read only those. A withdrawal
  to this wallet that a bundle carries is not credited (`getbalance`, `listunspent` and coin
  selection do not see it, and the leaf it superseded stays unconfirmed); a wallet coin a bundle
  deposits still counts as unspent; `getaddressbalance`, `getaddressutxos`, `getaddressdeltas` and
  `getspentinfo` list neither. The coins are not lost: they are in the UTXO set at the bundle's txid
  (`gettxout`, `yugen_getblockdata` `bundles`) and spend with `createrawtransaction`,
  `signrawtransaction` and `sendrawtransaction`. A later release reads the applied records.
- **K-4, a helper run can hold `cs_main` for up to 120 seconds.** A mempool candidate's verifier run
  happens under `cs_main` with the deadline `-yugenmempoolverifytimeout` (default 120). Many peers
  sending transactions that stall the helper could keep block connection and RPCs waiting, within
  the shared budget `-yugenpeerverifyrate` (default 6 a minute). Running the helper outside the lock
  comes after this beta.
- **Specification 0.5.5 vectors for the new rules are not published yet.** The tests run every
  vector the pinned yugen-spec carries; the rules new in 0.5.5 are covered by this repository's own
  tests until the specification's vectors for them exist.
- **DoS scores of two new rejections.** The Yugen transaction-version clause in
  `ContextualCheckTransaction` and the transparent value-delta range check after a bundle's VB coins
  score 100 on every path, where stock consensus checks take the mempool and block levels; aligning
  them is a follow-up. Only nodes with a Yugen height are affected, so no public network.
- **No public activation height** (above): on mainnet and the public testnets Yugen is inactive and
  its RPCs report it inactive.
