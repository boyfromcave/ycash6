(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Next release (beta3), changes since 6.22.0-beta2
------------------------------------------------

- **`gettransaction` shows the real fee for every funding shape.** `fee` was the value out less the
  wallet's transparent debit, so a send funded from Sapling showed the sum of its transparent (ECC
  and post-quantum) outputs as its fee, and a Sapling to Sapling send showed `0`. The fee is now
  the transaction's own, still negative: transparent value in (read from the wallet's records of
  each input's funding transaction) plus shielded value in (Sapling `valueBalance`, Sprout
  `vpub_new`) less transparent outputs and value moved into a shielded pool. It is shown whenever
  an input (transparent, post-quantum or shielded) is the wallet's, as before. `amount` keeps its
  meaning, the net change to the wallet's transparent balance excluding the fee: a send funded by
  transparent or post-quantum inputs shows minus what left for others (as before); a Sapling-funded
  send now shows the transparent value it paid this wallet (`0` for a send to others, `+x` for a
  send of `x` to an own ECC or post-quantum address) instead of minus its transparent outputs; a
  send with both transparent and shielded inputs shows the plain transparent net. Both node lines
  now give the same figures (ycash-dd showed no fee for a Sapling-funded send). `listtransactions`
  and `listsinceblock` are unchanged. Display only: balances, coin selection and consensus never
  read these figures. The defect was inherited from upstream zcashd (unchanged through 6.20.0).
