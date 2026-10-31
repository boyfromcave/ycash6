# The testnet shadow fork: testnet-yb-slow and testnet-legacy

## In plain words

Ycash runs three practice networks ("testnets") whose coins are worthless. testnet-yb-fast borrows
its old history from Zcash's public testnet. testnet-yb-slow (the dress rehearsal for mainnet) and
testnet-legacy (the control network, today's rules, no Yellowback) are instead a **copy of real Ycash
mainnet** up to one block, H_S, and testnets after it. That is called a shadow fork.

Copying mainnet copies everyone's balances, so the testnets must make sure that nothing signed on
them can ever be replayed on real mainnet, and the reverse. Every Ycash signature commits to the ID
of the network upgrade it was made under (the "branch ID"). From block H_S + 1 on, slow and legacy
sign under branch IDs of their own, which mainnet has never had and never will, and which differ
between the two. slow's Yellowback (Vault) upgrade has its own branch ID too, never mainnet's.

Never import a wallet that holds real YEC into a shadow testnet. Use fresh testnet keys and the
faucet. Copied balances show as TAY and are worthless there.

## What is mainnet's and what is not

`CTestNetShadowParams` (`src/chainparams.cpp`) derives from `CMainParams`, so the copied blocks
validate under exactly mainnet's rules: genesis, upgrade heights and activation hashes, Equihash,
`powLimit` and the Ycash fork's difficulty rule, checkpoints (those above H_S are dropped),
`nMinimumChainWork`, the Sprout-pool checkpoint (and on the 6.20.0 line the chain-supply
checkpoint), and the founders-reward and YDF addresses and mandate. Those addresses are resolved with mainnet's key constants
(`FoundersRewardKeyConstants`), because the network itself displays testnet prefixes. Nothing is
owed after H_S: the YDF mandate ends at 2,275,000, below it.

What differs: the network ID (`"test"`), the testnet address prefixes (`yt…`, `sm…`), the unit
(TAY), BIP44 coin type 1, the magic, ports, data directory and seeds of each profile, the deprecated
`testnet` RPC field, and from H_S + 1 the shadow upgrade.

| | testnet-yb-slow | testnet-legacy |
|---|---|---|
| History | Ycash mainnet 0..H_S (`mainnet-prefix-v1`) | the same |
| `UPGRADE_SHADOW` | H_S + 1, branch ID `0x57a24d5d` | H_S + 1, branch ID `0x35706728` |
| `UPGRADE_VAULT` | set by its first rc (T-15), branch ID `0xe1f1cc08` | never |
| Magic, P2P / RPC ports, datadir | `f7 79 62 d4`, 18933 / 18932, `testnet-yb-slow` | `f7 79 62 d5`, 19033 / 19032, `testnet-legacy` |

H_S is one value for both (`TESTNET_SHADOW_SPLIT_HEIGHT`), fixed by the mainnet history harvest.
Until it is set the networks have no blocks of their own, and the release guard refuses a tag
(`qa/yellowback-vault-params.py`, rule R8).

## The shadow upgrade

`UPGRADE_SHADOW` is a network upgrade (`src/consensus/params.h`, between NU6.2 and Vault on the
6.20.0 line and between NU5 and Vault on the 4.5.0 line) that changes no rule except:

- **the branch ID**: each network sets its own through `NetworkUpgrade::nBranchId`, read only through
  `NetworkBranchId()` (`src/consensus/upgrades.h`). `CurrentEpochBranchId`, `PrevEpochBranchId`,
  `IsConsensusBranchId(id, params)`, `getblockchaininfo` (`upgrades` keys, `consensus.chaintip` and
  `nextblock`), `vault_getinfo.branchid` and `yed_getinfo.upgrade.branchId` all report the
  network's own IDs. `-nuparams` keeps the global IDs (regtest only).
- **the difficulty**: the activation block and the next `nPowAveragingWindow` (17) blocks are at the
  PoW limit (`src/pow.cpp`), as at the testnet's Ycash fork. The averaging window after them holds only
  post-split blocks. From H_S + 1 a block more than 6 × 75 s after its parent may be at the limit
  (`nPowAllowMinDifficultyBlocksAfterHeight = H_S`). The limit is mainnet's (`0007ff…`): copied blocks
  were checked against it, so it cannot change.
- **a new epoch**: as at every upgrade, the ZIP 221 history tree restarts at the activation block.

The copied tip is old when the network launches. Block times may lead the median of the last 11 by
at most 90 minutes, so the first blocks after the split catch up with the clock about 15 minutes
of chain time per block. Every one of them may be a minimum-difficulty block. The first miner needs
`-maxtipage`, because the copied tip is older than the node's sync-age limit.

## Replay safety, end to end

1. Through H_S the shadow testnets are mainnet, branch IDs included. Nothing is signed there.
2. From H_S + 1 every signature on slow or legacy commits to that network's own shadow ID (ZIP 243
   `consensusBranchId`, every input, every hash type, the Sprout JoinSplit and Sapling signatures
   too). Mainnet verifies under Canopy's ID and rejects it. Mainnet's signatures fail on the testnets
   the same way, and slow and legacy refuse each other's.
3. slow's Vault epoch uses `0xe1f1cc08`, so after mainnet activates Vault (`0x6d5b7a31`) the two
   still differ. legacy never leaves its shadow epoch.
4. librustzcash6's `BranchId` knows the three IDs as their own variants (`SlowShadow`,
   `LegacyShadow`, `SlowVault`), so the Rust side signs and hashes under the ID itself and applies
   the rules of the epoch each stands for (`BranchId::rules()`: Canopy, Canopy, Vault).
5. Tested: `src/test/sighash_tests.cpp` `shadow_fork_replay` signs a v4 transaction on each of
   mainnet, slow and legacy, before and after a Vault activation, and verifies it under every other.
   `src/test/testnet_params_tests.cpp` checks the parameters, the IDs and the difficulty reset.

Clients sign under the branch ID the node reports (`getblockchaininfo` → `consensus.nextblock`),
never a hardcoded one.
