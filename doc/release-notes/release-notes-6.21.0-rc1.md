ycashd v6.21.0-rc1 — Ycash Yellowback (YED), release candidate 1
================================================================

This is a **release candidate** for testing. It is ycashd 6.20.0 (the Ycash rebase onto the
Zcash 6.x line) with the Ycash Yellowback (YED) overlay: a decentralized dollar on Ycash, where
YED is minted against locked YEC and enforced by miners.

Yellowback cannot be turned on for mainnet or testnet in this release
------------------------------------------------------------------------

`-yellowback` needs a start height for the network, and this release sets one only for regtest:
on mainnet or testnet the node refuses to start with `-yellowback` ("Yellowback has no start
height for this network yet"). Without the flag, this node follows the network as the 6.20.0
line does. Yellowback is for regtest and devnet testing here. Every Yellowback option also needs
`-experimentalfeatures -yellowback`.

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
- The macOS Intel and Ubuntu 18.04 packages are best-effort. They are absent from the release if
  their build failed.
