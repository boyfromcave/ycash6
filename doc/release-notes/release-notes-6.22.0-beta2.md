ycashd v6.22.0-beta2 — the vault upgrade and Ycash Yellowback (YED), beta 2
===========================================================================

This is a **beta** for testing, not for production. It is ycashd 6.20.0 (the Ycash rebase onto the
Zcash 6.x line) with a proposed Ycash network upgrade, **the vault upgrade** (consensus branch ID
`0x6d5b7a31`), and Ycash Yellowback (YED), the one rule module built on it: lock YEC in a vault to
mint YED (`1 YED = 1 US dollar`), return the YED to get the YEC back.

The vault upgrade and Yellowback are proposed, not adopted by the Ycash Foundation, and not
audited. `doc/release-notes/release-notes-6.22.0-rc1.md` describes what they add; `doc/vault-rpc.md`
and `doc/yellowback-rpc.md` list the RPCs.

Networks
--------

- **Mainnet**: no activation height is set. This node runs mainnet as a normal Ycash node; nothing
  of the vault upgrade or Yellowback is active there.
- **Testnets**: three shadow-fork testnets, chosen with `-testnet -testnetprofile=<profile>`
  (`doc/yellowback-testnet-shadow-fork.md`):
  - `fast` (`testnet-yb-fast`, RPC port 18832): the vault upgrade activates at height 510400;
  - `slow` (`testnet-yb-slow`, RPC port 18932): no Vault activation height yet;
  - `legacy` (`testnet-legacy`, RPC port 19032): never activates Vault.
- **Regtest**: `-regtest -nuparams=6d5b7a31:<h>` activates the upgrade at `<h>`
  (`doc/yellowback-devnet.md`).

Changes since beta 1
--------------------

- The Windows build compiles. An address-kind name collided with a Windows header macro.
- The release smoke test waits until the wallet has a spendable coin before creating a vault set.
  On the Linux release runners the wallet had not yet seen the matured coinbases, so the smoke
  test failed before any package was published.

What a beta does not have
-------------------------

- No testnet seed nodes yet: connect to known peers with `-addnode=<host>`.
- No YED attestor set on any network, so YED minting is not armed outside regtest.
- No release parameters beyond the fast testnet's activation height; an rc adds them.
- Not for production funds.

Getting started
---------------

1. Download `ycashd_v6.22.0-beta2_<platform>.tar.gz` (Windows: `.zip`) and verify it (below).
   Platforms: `linux_x86_64`, `linux_aarch64`, `macos_aarch64` and `windows`; best effort:
   `ubuntu_18.04_x86_64` and `macos_x86_64`.
2. Unpack it. It holds `ycashd`, `ycash-cli`, `ycash-tx` and `ycashd-wallet-tool`.
3. Run a node:
   - mainnet: `./ycashd`
   - a testnet: `./ycashd -testnet -testnetprofile=fast` (or `slow`, `legacy`); `-testnet` without
     a profile is refused.
4. Query it: `./ycash-cli getblockchaininfo` (add the same `-testnet -testnetprofile=<profile>`
   flags for a testnet).
