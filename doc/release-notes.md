(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

`z_sendmany` and `z_mergetoaddress` move plain YEC between every address type
------------------------------------------------------------------------------

`z_sendmany` now pays post-quantum (`sq…`) recipients and spends from an `sq…` address, alone or mixed
with ECC (`s1…`) and Sapling (`ys1…`) parties; `z_mergetoaddress` merges a named `sq…` address's coins and
pays an `sq…` destination (beta2 D-2, D-4, D-6; quantum spec A-15 reversed). A PQ party is a transparent
party for the privacy policy. PQ change returns to its source address. The fee of a transaction with a PQ
input is priced on its size and is never below the ZIP-317 conventional fee. `z_shieldcoinbase` still
refuses a PQ source. Details, limits and error strings: `doc/yellowback-rpc.md`.
