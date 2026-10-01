# Scenario 2b — "I am an attestor": operation (headless, the `attestor` seat, node 8)

## Before you start

`yellowback-devnet` is a script in `contrib/yellowback/devnet/`, not a command on your PATH, and
its `#!/usr/bin/env python3` must find the **workspace venv's** Python: it imports the inherited
test framework from `qa/rpc-tests/`, which needs `simplejson` — present in the venv, absent from
the system Python 3.9 that macOS ships. Three lines, once per terminal, make every command below
work verbatim from any directory:

```bash
cd <workspace>/ycash-dd
source ../.venv/bin/activate
export PATH="$PWD/contrib/yellowback/devnet:$PATH"
```

Or skip them and spell each command out from the `ycash-dd` directory: `../.venv/bin/python
contrib/yellowback/devnet/yellowback-devnet <command>`.

You also need `src/ycashd` built and the attestor agent built (`cd contrib/yellowback/attest &&
cargo build --release`; `YELLOWBACK_ATTEST_BIN` points at it if the search does not find it). If a
devnet already exists in `~/yb-devnet`, `up` refuses and tells you to pass `--force`, which
rebuilds over it.

Close the GUI. From here on, **follow `doc/yellowback-attestor.md` literally**, using only
`ycash-cli` and the agent. This half is as much a test of that document as of the software: a
missing step, an ambiguity, an assumption the reader does not share — that is the finding. Its
"Quick reference" table is the checklist.

```bash
yellowback-devnet cli --node 8 -- yed_listattestors        # your seq: the newest registration
yellowback-devnet cli --node 8 -- yed_getinfo               # attest.status, seatedCount
```

Your agent's configuration was written for you at `<dir>/attest-8.toml` with `seq = 0` and a
comment telling you to replace it; the mock price file is `<dir>/attest-price-8`. Everything
else — the RPC port, the `dir` transport path the other three agents use — is already filled
in. (The devnet's `attestor 8 …` command refuses to touch your seat.)

## Walk-through

1. **Configure and start your own agent** against the mock price, so *you* choose what you
   attest. As the doc says: `sources` and `check-config` before `attest`.
   ```bash
   A=$(yellowback-devnet status | sed -n 's/.*conf template //p')      # or: <dir>/attest-8.toml
   $EDITOR $A                                                            # seq = <yours>
   yellowback-attest check-config --conf $A
   yellowback-attest sources --conf $A                                   # exits 1: no live sources on regtest — is that explained?
   echo 50 > $(dirname $A)/attest-price-8
   yellowback-attest attest --conf $A --mock-price $(dirname $A)/attest-price-8
   ```
   - notes:

2. **Watch your `seq` get selected** for real transactions (`yed_getselection <tip-2> ""`) and
   the attest fee arrive when it is (`yed_listattestors` → your `lastBundleHeight`; the fee goes
   to your `bondKeyAddress`: `listunspent` / `getreceivedbyaddress`). Is the connection between
   "I signed" and "I was paid" visible from the command line alone?
   - notes:

3. **Stop signing** (Ctrl-C the agent). Watch DORMANT arrive after `DORMANCY_BLOCKS` (16
   blocks ≈ 4 min, once `DORMANCY_MIN_BUNDLES` = 2 bundles have selected you and found nothing),
   then revive with `yed_revive <seq> <priceMicroUsd>`. **Does anything warn you *before*
   dormancy, or only after?**
   - notes:

4. **Attest 20 % away from the others** (`echo 60 > attest-price-8` while the walk is near
   $50; `yellowback-devnet price --walk stop` first if you want a steady comparison) and watch
   your attestations dropped from selections while the honest three carry on
   (`yed_getselection`, `yed_buildbundle <tip-2> ""` → `seqs` vs `selected`).
   - notes:

5. **`yed_withdrawbond <seq>` before the locktime** (`bond-locked`), then — if you have the
   patience — after (200 blocks ≈ 50 min at 15 s; `yellowback-devnet heartbeat rate 3` hurries
   it).
   - notes:

6. **Kill the agent uncleanly and restart it** (`kill -9`), then restart with a *different*
   mock price inside the same interval: the equivocation guard (S16) must refuse to sign a
   second price for a height you already signed (`equivocation-guard` in the agent log).
   **This is the failure that ejects a real attestor**, so provoke it deliberately.
   - notes:

## What we want to know

- Is the economic proposition legible — what you risk, what you earn, what gets you ejected?
- Would a competent operator run this for a year?
- Which step of `doc/yellowback-attestor.md` did you have to read twice?

This scenario is the dress rehearsal for A7 recruiting; its output should shape the pitch.

```bash
yellowback-devnet report
yellowback-devnet down --wipe
```
