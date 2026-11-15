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
  an input (transparent, post-quantum or shielded) is the wallet's, as before. `amount` is
  unchanged (upstream's figure), and so are `listtransactions` and `listsinceblock`. ycash-dd now
  shows the same fee (it showed none for a Sapling-funded send). Display only: balances, coin
  selection and consensus never read these figures. The defect was inherited from upstream zcashd
  (unchanged through 6.20.0).
