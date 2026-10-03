ycashd v6.21.0-rc1 — Ycash Yellowback (YED), release candidate 1
================================================================

This is a **release candidate** for testing. It is ycashd 6.20.0 (the Ycash rebase onto the
Zcash 6.x line) with the Ycash Yellowback (YED) overlay: a decentralized dollar on Ycash, where
YED is minted against locked YEC and enforced by miners.

Yellowback on mainnet: start height 3,075,000
---------------------------------------------

Yellowback is off unless a node is started with `-experimentalfeatures -yellowback`. Without
those flags, this node follows the network as the 6.20.0 line does.

This release sets the mainnet parameters:

| | Height | About |
|---|---|---|
| `START_HEIGHT`: the Yellowback index starts reading the chain | 3,075,000 | 2026-10-22 |
| `ENFORCE_UNTIL_HEIGHT`: enforcement sunset, one year of blocks later | 3,495,480 | 2027-10 |

A mainnet node started with `-yellowback` indexes from the start height and waits there. Nothing
is enforced until miners signal and the soft fork activates, and minting arms only once at least
five attestors are bonded (plus a 1,152-block delay). Before the start height, `yed_getinfo`
reports an empty, healthy index.

These heights are consensus parameters, not options. Every node running Yellowback on mainnet must
use the same values, so they ship only in releases. A later release can change them only to a set
that starts at or after this set's sunset.

**Testnet is not configured yet.** With `-testnet`, `-yellowback` still refuses to start ("no
start height for this network yet").

A release that keeps these values and only moves the sunset later is a *renewal* and may ship
at any time before the sunset; one is due no later than six months before it (height ≈ 3,285,000).
A release that changes any other value starts at or after the sunset, or after a deliberate
freeze (`doc/yellowback-release.md`, "Freeze, then fix").

Supply cap is soft above 500 %
------------------------------

The supply cap (`SUPPLY_CAP_BPS`, 15 % of the issued market cap) is no longer a ceiling. When a
mint would take YED supply over the cap it is accepted if the ratio it locks — the class minimum
after the volatility multiplier — is at least `RECAP_RATIO_BPS` (500 %): class A always, class B
at a multiplier of 1.25× or more. Every YED minted above the cap locks five times its value in
YEC. A mint below that ratio is still refused (`mint-supply-cap`, VOID at inclusion;
`mintpol-cap` from `yed_mint`, whose message names the classes that can mint).
`yed_getinfo.supplyCapReached` reports the state and `yed_getstats.mintableClasses` lists the
classes open above the cap.

Abandonment now takes thirty days: `ABANDON_BLOCKS` is 34,560 blocks (= `GRACE`), was 4,032.
Pools on this release filter rule-breaking vault spends, and wallets refuse `yed_sweep`, for at
least that long after enforcement halts.

The 6.20.0 baseline's own notes (`doc/release-notes/release-notes-6.20.0.md`) apply unchanged.

Downloads
---------

| Platform | File |
|---|---|
| Linux x86_64 (glibc 2.35+, e.g. Ubuntu 22.04+, Debian 12+) | `ycashd_v6.21.0-rc1_linux_x86_64.tar.gz` |
| Linux x86_64, older distributions (Ubuntu 18.04+, glibc 2.27+) | `ycashd_v6.21.0-rc1_ubuntu_18.04_x86_64.tar.gz` |
| Linux ARM64 | `ycashd_v6.21.0-rc1_linux_aarch64.tar.gz` |
| macOS Apple silicon (11+) | `ycashd_v6.21.0-rc1_macos_aarch64.tar.gz` |
| macOS Intel (11+) | `ycashd_v6.21.0-rc1_macos_x86_64.tar.gz` |
| Windows x86_64 | `ycashd_v6.21.0-rc1_windows.zip` |

Check the download against `SHA256SUMS` (`sha256sum -c SHA256SUMS --ignore-missing`).

The binaries are not code-signed. On macOS, clear the quarantine flag after extracting:
`xattr -dr com.apple.quarantine ycashd_v6.21.0-rc1_macos_*`. On Windows, SmartScreen asks before
the first run.

No zk parameter download is needed: the Sapling parameters and the Sprout verifying key are
built into `ycashd`. Each package also contains `ycashd-wallet-tool` (new in the 6.20.0 line,
used to confirm a wallet's emergency recovery phrase).

Mining pools
------------

There is no separate `_MINING_POOLS_` package any more. The pool features of the former "witness
rework" build are options of this binary, all off by default: `-deletetx`, `-deletetxinterval`,
`-keeptxfornblocks`, `-keeptxnum`, `-deletetxconflict`, `-bdbcache`, `-consolidation`,
`-consolidatesaplingaddress`, `-consolidationtxfee`. See `ycashd -help`, and
`doc/yellowback-release.md` ("Mining pools") for what each one does and how it interacts with
Yellowback. Pools upgrading a wallet from a v4.5.0 "wr" build should ask in the Ycash Discord
first, as before.

Known limitations
-----------------

- Under `-deletetx` (with the default `-deletetxconflict`), a purged *expired* Yellowback
  transaction disappears from `yed_listtransactions` instead of being listed as `"expired"`.
- Under `-consolidation`, a consolidation transaction may take every note of an address while it
  is unconfirmed. A Yellowback operation funded from that address is then refused with
  `insufficient-yec` until the next block. To avoid this, keep consolidation off the address that
  funds Yellowback: list only the addresses to consolidate with `-consolidatesaplingaddress`.
- The macOS Intel and Ubuntu 18.04 packages are best-effort. They are absent from the release if
  their build failed.
