(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Mining: the development-fund donation is opt-in (`-ydf`, default 0)
-------------------------------------------------------------------

- **The default changes from 5 to 0.** After the Ycash Development Fund mandate ends (mainnet height
  2,275,000), a block this node mines pays the whole subsidy and every fee to the miner and carries
  no fund output. A miner who wants to keep donating sets `-ydf=5` (any whole percentage from 0 to
  100 is accepted, as before). A value outside that range (`-ydf=-1`, `-ydf=101`) is reset to the
  default, so it now means 0 where it used to mean 5.
- **Not a consensus change.** Past the mandate a block is valid with or without the fund output;
  `DEFAULT_YDF_FEE_PERCENTAGE` is read by the miner, `getblocksubsidy`, the metrics screen and the
  option check, never by block validation.
- **The mandate period is unchanged:** below the mandate's end (2,275,000 on mainnet, testnet-yb-slow
  and testnet-legacy; testnet-yb-fast has its own end, see the next section) the 5 % output is
  required by consensus and the miner still pays it whatever `-ydf` says.
- `getblocksubsidy`'s `founders` past the mandate is the share this node's `-ydf` setting donates
  (0 by default); the metrics screen counts the reward the same way.

Fast testnet: the development-fund mandate ends (consensus, testnet-yb-fast only)
---------------------------------------------------------------------------------

- **A scheduled rule change on the fast testnet.** The fast profile gets its own mandate end,
  `TESTNET_FAST_YDF_MANDATE_END_HEIGHT`. The tree carries a provisional 600,000, deliberately far
  above the tip so that a build made before the cut stays strict; the final height is set when the
  release candidate is cut (the fast-testnet tip then, plus 400 blocks), and the release guard refuses
  an rc or final tag that still carries 600,000. From that height a fast-testnet block is valid with
  or without the 5 % fund output, as on mainnet since 2,275,000; below it the output stays required.
  Until now the fast profile inherited the 900,000 of the original Ycash testnet, about 389,000 blocks
  away.
- **Every fast-testnet node must run this build before the chain reaches the height.** A node on an
  earlier build rejects the first block without the fund output and stops following the chain. It
  also bans the peer that sent the block (24 hours, kept in `banlist.dat`), so a node upgraded late
  needs `clearbanned` after the upgrade to reconnect to its peers.
- **The safe setting while nodes upgrade:** a pool that sets `-ydf=5` mines blocks that every build
  accepts (the 5 % output stays valid after the height). Keep it until every node has upgraded.
- Mainnet, the slow and legacy testnet profiles and regtest are unchanged.
