# Scenario 1 — "I want to mint" (the `user` seat, node 0)

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
yellowback-devnet up --role user        # ~3 min; prints your seed
yellowback-devnet wallet                # opens YecWallet on node 0, your seat
yellowback-devnet status                # the seat banner, the heartbeat, the price, the personas
```

**Automated around you:** 3 pools quoting and signalling, 4 attestors signing, a heartbeat
mining one block every 15 s, a price walking gently, and six personas on nodes 9 and 10
minting, redeeming, trading and liquidating (`yellowback-devnet sim stats`).

Half an hour. The value is in the noticing: write against the step.

## Walk-through

1. **Read before touching.** Open the Yellowback tab and read the Overview. Is it obvious the
   system is live, activated and armed? Is it obvious what YED *is*?
   - notes:

2. **Mint 100 YED against YEC.** Watch the two-step carrier: **does the wallet explain the
   pause, or does it just look stuck?** This is the single most suspicious moment in the
   product. (The heartbeat mines the carrier's block within 15 s.)
   - notes:

3. **Three prices are in play** — the pool median, the attested quantile, and the `min` of the
   two the mint was offered. Does the GUI make the relationship legible, or present one number
   and hope? (`yellowback-devnet cli -- yed_getprice` shows `xMint`, `pMint`; the mint result
   shows `aMint`.)
   - notes:

4. **Let the walk run.** Watch Positions as your collateral ratio moves. Does the number mean
   anything to you without the docs?
   - notes:

5. **Redeem one vault at maturity** (your class A vault unlocks 48 blocks ≈ 12 min after the
   mint). **Send YED** to another address (`yed_getnewaddress` on any node gives one).
   - notes:

6. **Let the price fall.** `yellowback-devnet price --shock -40%` then, a few minutes later,
   `--shock=-40%` again (the walk continues from each). Watch your own vault approach
   liquidation. **Does the wallet warn you early enough to act?** Note: class A vaults are
   500 % collateralised at mint, so a claim needs roughly a 78 % fall; the personas' class C
   vaults (300 %) go under at roughly 65 %. Expect the Mint page to say minting is *limited*
   once the global ratio is under 250 %: class A still mints (and each such mint raises the
   ratio), B and C are greyed out. Is that legible, or does it look broken?
   - notes:

7. **Watch someone else be claimed.** The liquidator (node 10) posts a notice on a persona's
   underwater vault and claims it four blocks later (`yellowback-devnet sim stats`;
   `cli -- yed_listvaults CLAIMED`). What, if anything, do you learn about it as a bystander?
   - notes:

## What we want to know

- Where does a first-time minter hesitate?
- Is the collateral ratio comprehensible without reading the docs?
- Does the emergency path frighten people appropriately, without frightening them away?

## When you are done

```bash
yellowback-devnet report                # bundles this file, every log and the personas' tally
yellowback-devnet down --wipe
```
