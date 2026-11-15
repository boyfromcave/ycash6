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
- **The mandate period is unchanged:** below the mandate's end (mainnet 2,275,000, testnet 900,000)
  the 5 % output is required by consensus and the miner still pays it whatever `-ydf` says (the fast
  testnet's own end: see the next section).
- `getblocksubsidy`'s `founders` past the mandate is the share this node's `-ydf` setting donates
  (0 by default); the metrics screen counts the reward the same way.

Fast testnet: the development-fund mandate ends (consensus, testnet-yb-fast only)
---------------------------------------------------------------------------------

- **A scheduled rule change on the fast testnet.** The fast profile gets its own mandate end,
  `TESTNET_FAST_YDF_MANDATE_END_HEIGHT` (provisional 512,000; the final height is set when the release
  candidate is cut: the fast-testnet tip then, plus 400 blocks). From that height a fast-testnet block is
  valid with or without the 5 % fund output, as on mainnet since 2,275,000; below it the output stays
  required. Until now the fast testnet inherited testnet's 900,000, about 389,000 blocks away.
- **Every fast-testnet node must run this build before the chain reaches the height:** a node on an
  earlier build rejects the first block without the fund output and stops following the chain. A block
  that still pays the output stays valid on every build, so a miner who sets `-ydf=5` mines blocks that
  old and new nodes both accept.
- Mainnet, the slow and legacy testnet profiles and regtest are unchanged.
