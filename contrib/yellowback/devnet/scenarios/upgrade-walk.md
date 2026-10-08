# Scenario U — the whole ecosystem on the vault upgrade (`upgrade-walk`)

<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

`docs/plans/yellowback-upgrade-plan.md` §4 (the bridge), §5 (YED on the primitive), §15.8 (the
`set_*` / `vault_*` RPCs) and §15.10 (U-21..U-24), walked on the one-laptop devnet with every
client it runs: chain-viz, lightwalletd (the fork with `--yellowback`, beside the baseline
server) and yolo beside pool 4. `upgrade-walk` runs this checklist unattended and writes each
step's calls and results to a transcript; `upgrade-walk-transcript.txt` beside this directory is
the recorded run. Every step can also be done by hand with `yellowback-devnet cli --node N -- …`.

```bash
yellowback-devnet up --role attestor --no-heartbeat --no-walk --no-sim --seed 480   # ~3 min, deterministic: nothing mines but you
../.venv/bin/python contrib/yellowback/devnet/upgrade-walk [--transcript PATH] [--skip STEP,...] [--only STEP,...]
```

Binaries: `ZCASHD` (or `up --bitcoind`), `YELLOWBACK_ATTEST_BIN`, `CHAINVIZ_BIN`, `YOLO_BIN`,
`YELLOWBACK_LWD_BIN` and `YELLOWBACK_LWD_REPO` (the lightwalletd-dd checkout whose `lwdinfo` and
`go test -tags devnet` the walk runs). Without a client the walk skips its checks (`--skip clients`).

Nodes: 0 minter and bridge owner, 1 stock (no `-yellowbackattestorset`: no `yed_*`, but the
primitive runs there and its vault state hash must agree), 2–4 pools (real quote agents), 5–7
attestors, 8 the attestor seat the walk fills, 9 a YED holder, 10 the claimant.

| Step | What happens | Evidence the walk records |
|---|---|---|
| `clients` | lightwalletd (fork on 9480, baseline on 9481), `pool 4 stratum start`, two blocks through yolo, chain-viz `/api/health` | `yed_gettag` of yolo's block names pool 4; `lwdinfo -yellowback` answers GetVaultInfo / ListSets / GetSet / ListVaultOutputs |
| `members` | node 8 `yed_registerattestor` (a `SET_JOIN`), current in the set after its maturity, PENDING in the module until `BOND_MATURITY`; its agent starts; `set_heartbeat`. Node 6's agent stops; mints keep selecting it; S15 makes it DORMANT; `attestor 6 start` heartbeats and it is ELIGIBLE again | join and heartbeat txids, `lastact`, the DORMANT and ELIGIBLE `statusHeight`s |
| `mint` | ARMED; mints A..E | `vault_decodescript` of A: tag `59454400`, set = cancel set = attestor set, delay `CLAIM_DELAY`, ownerHeight = lockHeight, appHeight = claimHeight |
| `transfer` | `yed_send` 200 YED to node 10, 10 YED to node 9 | balances |
| `redeem` | before lockHeight: `vault-locked` on a pre-plan node, or (in-term claims) `yed_estimateredeem` quoting the early-redeem fee; A redeemed with selector 2 confirming at lockHeight (no early fee); renew = redeem B + mint B' of the same debt | scriptSig ends `OP_2`; A and B CLOSED, B' ACTIVE; A's `earlyRedeemFeeZat` 0 |
| `claim` | `price 5` for a slow window; node 10 claims C (selector 4) into a claimant intent; invalidate/reconsider the claim block on every node; release after `CLAIM_DELAY` | CLAIMING / ACTIVE / CLAIMING per node, state hashes before and after equal, chain-viz shows the intent, `TestDevnetVaultUpgradeThroughServer` passes with the intent outstanding, CLAIMED |
| `cancel` | node 10 claims D; `price 50`; attestor node 5 cancels it alone (`vault_buildcancel` + `set_signcancel` + `vault_send`) | the position ACTIVE at the cancel's output 0, byte-identical V, supply not refunded (U-24), `claim_cancel` |
| `interm` | **in-term claims only** (`yed_getinfo.params.inTermClaims`; `SKIP` otherwise): mints F, G and H (class A, lock 96); `appheight = refHeight + 1`; the computed threshold price equals `underwaterAt`; above θ every Yellowback node says not claimable and node 10's `yed_claim` is refused `claim-not-underwater`; the owner redeems G in term above θ (D-IT-15), `yed_estimateredeem` quoting and `yed_redeem` paying `earlyRedeemFeeZat` = 5 % of the collateral through the FEE-1 output (IT-9); `price` to 90 % of the threshold for a slow window; the owner redeems H in term under θ, the same fee, ahead of any claimant (IT-8 "redeeming stops it"), and node 10's claim of H is refused `vault-not-active`; node 10 claims F in term with `minOutZat`/`maxBurnCents`; release after `claimDelay`; the residual intent released to the owner when there is one | `claimedAt < claimHeightWouldHaveBeen`, the refusals, the early fee amounts, CLAIMING → CLAIMED, state hashes, G and H CLOSED |
| `invalid` | a $50 mint: every Yellowback mempool refuses it; a block carrying it (solved in Python) is rejected by every Yellowback node | `bad-yellowback-bad-mint-amount` ×10 and ×10, no tip moved |
| `bridge` | `bridge up --shape guardians`, then `--shape relayer`: two locks, a burn in the feed, intent, release; `bridge rogue`; `bridge silence` until the set is DORMANT; `bridge recover` | set parameters, the bytes32 destination OP_RETURN, the release paying the burn's recipient, the watcher's cancel (selector 2) and the value back in a V, the owner's selector-3 recoveries |
| `final` | | one YED state hash on the ten Yellowback nodes, one vault state hash on all eleven, chain-viz and lightwalletd equal to the node |

## The bridge persona by hand

```bash
yellowback-devnet bridge up --shape guardians        # or --shape relayer
yellowback-devnet bridge lock 20 --dest 0x<20-byte Ethereum address>
yellowback-devnet mine 20                            # nothing unlocks in the set's creation epoch (rate window 20)
yellowback-devnet bridge burn 3 <node 9 t-address>   # a mock Ethereum burn: the daemon posts the intent ...
yellowback-devnet mine 7                             # ... and releases it after the delay (6)
yellowback-devnet bridge rogue 2; yellowback-devnet mine 1   # an intent with no burn: the watcher cancels it
yellowback-devnet bridge silence; yellowback-devnet mine 31; yellowback-devnet bridge recover
yellowback-devnet bridge status; yellowback-devnet bridge down
```

`<dir>/bridge-sim.log` is the daemon's log; `bridge-burns.jsonl` the feed; `bridge.json` the sets
and members; `bridge-daemon.json` what the daemon has done.
