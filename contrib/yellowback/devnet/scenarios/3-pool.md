# Scenario 3 — "I am a mining pool" (the `pool` seat, node 4)

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

```bash
yellowback-devnet up --role pool        # ~3 min; node 4 is a plain miner: no payout, no signal
yellowback-devnet up --role pool --stratum [--stratum-text TEXT]   # the same, with real pool software beside node 4 (step 0)
yellowback-devnet cli --node 4 -- yed_getinfo
```

No GUI: pools are headless, which is the point (D-2). This is how a pool operator meets
Yellowback — one more process, one more config file, one more thing that can page them at 3 a.m.

**Automated around you:** 2 other pools (nodes 2 and 3) quoting and signalling, 4 attestors,
the heartbeat on *those two pools only* (your blocks are always yours to mine), the price walk,
the simulated population and the liquidator.

## Walk-through

0. **The real pool.** No Ycash pool mines with `generate`. With `--stratum`, `up` starts
   **yolo** (the Rust rewrite of `yecdev/yolo`, `<workspace>/yolo/target/release/yolo` or
   `YOLO_BIN`) beside node 4 with node 4's RPC credentials, and every `mine N 4` below runs
   `stratum-miner --blocks N` against it: node → `getblocktemplate` → `mining.notify` →
   the miner's 48/5 solver → `mining.submit` → `submitblock`. The heartbeat still never
   touches your blocks. What to look at:
   - `yellowback-devnet status` prints one line from yolo's `GET /status`: payout address,
     coinbase text, connected miners, template height and age, the **tag kind yolo decoded in the coinbase it built**
     (`none` now, `signal` after step 2, `quote` after step 3), the last `submitblock` verdict
     and the accepted/rejected counts. `pool 4 stratum status` prints the same line alone.
   - `<dir>/stratum-4.log` (yolo: one `work <height> … tag: …` line per template, one
     `accepted`/`rejected: <verdict>` per submit) and `<dir>/stratum-miner-4.log` (every
     `mine`). `report` bundles both.
   - yolo has no modes (P-6), two flags. The seat runs `yolo --payout <node 4's payout
     address>`: every block pays that address whatever the miner sends as username (here the
     worker name `devnet-worker`), so the reward stays in node 4's wallet; without `--payout`
     the username itself must be a t-address and is paid. `--stratum-text TEXT` (on `up`, or
     `pool 4 stratum stop` then `start --stratum-text TEXT`) passes yolo `--text`: the
     scriptSig is rebuilt as height ‖ `coinbaseaux.flags` ‖ text — the carrier a
     self-assembling stack must use; without it the node's scriptSig is used untouched. The
     Perl `cenote` drops the tag on that path (Y-F1); `qa/rpc-tests/yellowback_stratum.py`
     pins the fixed behaviour on all four payout × text cells.
   - Cadence: a stratum `mine N 4` is about one block per second, the heartbeat one per 30 s
     under `--lean`, so `mine 25 4` makes node 4 the whole 64-block window (`share 10000`).
     Steps 4 and 5 assume a *share*; with `--stratum` mine one or two blocks at a time between
     heartbeat ticks, or the pause and the pin never show.
   - notes:

1. **A plain miner.** Mine a few blocks (`yellowback-devnet mine 3 4`). Observe that your blocks
   carry no quote (`cli -- yed_gettag <height>` → `found: false`; MINER-2) and you earn no
   Yellowback fees (`yed_listminers` does not know you).
   - with `--stratum`: `check-coinbase <height> -regtest -datadir=<dir>/node4` (in
     `contrib/yellowback/pool/`) exits 1 with `scriptSigBytes: 4` — the height push and
     nothing else; `getblock <height> 2` shows vout 0 paying node 4's payout address (yolo's
     `--payout`) and vout 1 the founders' reward. With `--stratum-text` the scriptSig ends in
     the text: `check-coinbase`'s `scriptSigBytes` grows by its length and `getblock <height>
     2` → `tx[0].vin[0].coinbase` ends in its hex.
   - notes:

2. **Become a pool.** `yellowback-devnet pool 4 configure` restarts node 4 with its payout
   address and `-yellowbacksignal=1` (what an operator does by editing `ycash.conf` — read
   `doc/yellowback-mining.md` §2 and check the two lines match). Mine again. Watch
   `yed_listminers` move you to registered (`N_REG` = 24 tagged blocks) and then eligible, and
   watch fees start arriving (`getbalance` on node 4; a mint's `payee`).
   - with `--stratum`: yolo logs `node down` / `node back` across the restart and keeps
     serving. `check-coinbase <height> -regtest -datadir=<dir>/node4` now exits 0 with `kind:
     signal` and your `payoutAddress`, line for line with `yed_gettag`; yolo's `/status` says
     `tag "signal"`. Registration counts **quote** tags: you become registered only once step 3's
     agent runs and 24 more of your blocks carry a price.
   - notes:

3. **The real quote agent.** `yellowback-devnet pool 4 quote start` runs `yellowback-quote
   --mock-price` beside your node — the path an actual pool runs — instead of `yed_setquote`
   by hand. `cli --node 4 -- yed_getinfo` → `miner.quoteKind` "quote", `quoteAgeSeconds`.
   Then `pool 4 quote stop` and watch the quote go stale past `-yellowbackquotemaxage`
   (120 s here): `quoteKind` falls back to "signal".
   - with `--stratum`: the very next `mine 1 4` carries the quote (`check-coinbase` → `kind:
     quote`, `priceMicroUsd` = the mock price; `status` → `tag "quote"`). yolo re-issues work
     when `coinbaseaux.flags` changes (Y-F2), so a template fetched before the agent published
     is not what gets mined.
   - notes:

4. **Stop signalling.** `yellowback-devnet pool 4 signal off` (you keep mining and quoting,
   your tags carry no signal bit). With 2 of 3 still signalling you stay above the 60 %
   threshold. Now `pool 3 signal off` and watch: minting pauses below 60 %
   (`yed_getstats.mintingAllowed`, `haltMask` PARTICIPATION), rejection pauses below 50 %
   (`yed_getactivation.enforcementSuspended`), then recovery at 75 % / 60 % once you `signal
   on` again. Mine your share while you watch (`mine 5 4`); the window is 64 blocks.
   - with `--stratum`: `check-coinbase` on your next block shows `signal: false` with the
     quote intact. Mine one block per heartbeat tick, not `mine 20 4`: at one block per
     second you *are* the window and the 60 % line never moves.
   - notes:

5. **Get pinned.** Stop your agent and quote a constant: `cli --node 4 -- yed_setquote
   50000000 1` while the walk moves the attestors; after `PIN_WINDOW` (16) blocks with the
   cross-section 5 % away, PIN-1 marks you pinned (`yed_getprice.pinnedKeys`, `yed_listminers`)
   and drops you from the medians. `pool 4 quote start` to recover.
   - with `--stratum`: `check-coinbase` shows the constant `priceMicroUsd` on every block you
     mine; the pin needs the other pools' quote tags in the window (the cross-section), so
     again one block per tick.
   - notes:

6. **Read `doc/yellowback-mining.md`** as a pool operator would. Does it answer the questions
   this exercise raised? Which section did you need that was not there? Then `yolo --help` and
   `contrib/yellowback/pool/README.md` (the three carriers and the per-stack notes): do the
   flags you would run on mainnet (`--payout`, `--text`) tell you which carrier you are on?
   - notes:

## What we want to know

- Is the operational burden on a pool acceptable — one more agent, one more config, one more
  thing to monitor?
- Are the failure modes discoverable from `yed_getinfo` alone, without a dashboard, since that
  is what a daemon operator has? If **no**, the fix is more likely better fields and a clearer
  mining runbook than a GUI — the finding R8 is waiting on before anything is built.
- A pool that finds this annoying simply will not run it, and the whole design rests on pools
  running it.

```bash
yellowback-devnet report
yellowback-devnet down --wipe
```
