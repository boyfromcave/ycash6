ycashd v6.22.0-rc1 — the vault upgrade and Ycash Yellowback (YED), release candidate 1
=====================================================================================

This is a **release candidate** for testing. It is ycashd 6.20.0 (the Ycash rebase onto the
Zcash 6.x line) with a proposed Ycash network upgrade, **the vault upgrade**, and Ycash Yellowback
(YED) built on it.

**Status: proposed, not live.** The vault upgrade has no activation height on mainnet or testnet
and no YED attestor set. It has not been adopted by the Ycash Foundation and has not been audited.
On mainnet and testnet this node follows the network as the 6.20.0 line does; everything below
runs on regtest only.

The vault upgrade
-----------------

A network upgrade (a hard fork): `Consensus::UPGRADE_VAULT`, consensus branch ID `0x6d5b7a31`
("Vault"). Once a release sets its activation height, every node must upgrade before that height;
a node that does not stops following the chain there.

It adds one general-purpose feature, **vaults**: YEC locked under rules that every node enforces,
released only with the approval of a bonded **signer set**, after a delay during which the release
can be cancelled, and recoverable by its owner if the signers go silent.

- Script: BIP68 sequence locks and `OP_CHECKSEQUENCEVERIFY`, `OP_CHECKSETSIG` (0xc0) and
  `OP_CHECKSETDORMANT` (0xc1), active from the upgrade height.
- Signer sets as a consensus object: bonded members, thresholds to unlock, cancel and slash, an
  optional rate limit, liveness and dormancy; a member that signs two conflicting releases loses
  its bond.
- Vault (V) and intent (I) templates with unlock, cancel and owner-recovery branches; set acts in a
  `YV` `OP_RETURN`; a vault database with undo.
- 21 new RPCs, `set_*` and `vault_*` (`doc/vault-rpc.md`).

Two applications use it: the **wYEC bridge** template (Ycash side only; no application code in
consensus) and **Ycash Yellowback (YED)**, the one registered rule module.

Ycash Yellowback (YED) on the vault upgrade
-------------------------------------------

YED is a dollar token: lock YEC in a vault to mint YED (`1 YED = 1 US dollar`), return the YED to
get the YEC back. From the activation height its rules are consensus rules on every upgraded node.

- The YED vault is the V template. The owner redeems with the owner branch; an underwater vault's
  claim moves the collateral into a pending release that the YED attestor set can cancel during
  `CLAIM_DELAY` (one day on mainnet), after which anyone releases it.
- Attestors are the members of the YED attestor set (`SET_JOIN`, heartbeats). Prices combine the
  pools' coinbase quotes with the attestors' signed prices.
- Launch parameters: class A (30–90 days) only, minting requires an armed attestation layer,
  $2,500 largest mint, pool fee 15 bps with half again to the attestor, global-ratio halt 300 %,
  recapitalisation floor 600 %.
- `yed_*` RPCs are at `rpcversion` 5 (`doc/yellowback-rpc.md`).

Configuration
-------------

There is no flag to turn Yellowback on. It is live where `UPGRADE_VAULT` has an activation height
and the network names its YED attestor set: on regtest
`-nuparams=6d5b7a31:<h> -yellowbackattestorset=<setid>` (`doc/yellowback.md`, *Configuration*;
`doc/yellowback-devnet.md` walks through it). `-yellowback` is accepted and ignored;
`-yellowbackenforce`, `-yellowbacksignal`, `-yellowbacktemplatepolicy` and
`-yellowbackrequirehealthy` are logged and ignored; `-yellowbackstartheight` and
`-yellowbackenforceuntil` are init errors.

Versions
--------

6.22.x is the release series of this line (`upgrade/vault`). 6.21.x is the series of
`harden/yellowback`, the version of Yellowback that needs no network upgrade.

The 6.20.0 baseline's own notes (`doc/release-notes/release-notes-6.20.0.md`) apply unchanged.
