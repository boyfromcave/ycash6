# Scenario 5 — an in-term claim (the `user` seat, node 0, with YecWallet)

<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

`docs/plans/yellowback-in-term-claims-plan.md` (IT-1, IT-2, IT-7, IT-8), clicked through on the
devnet: the explainer's example — a vault minted at 300 % that falls under 125 % on day 10 of a
90-day term and is closed by a third party that day, not on day 90. You are the minter in the
wallet; the simulated liquidator (node 10) is the third party; the attestors and the price are
automated. About twenty minutes.

**Needs a node whose `yed_getinfo.params.inTermClaims` is `true`.** On a node without the feature
the claim path opens only after the term (`claimHeight`), step 6 below never happens, and
`yellowback-devnet cli -- yed_getinfo` shows no `inTermClaims` key: stop there and note it.

## Before you start

```bash
cd <workspace>/ycash-dd && source ../.venv/bin/activate && export PATH="$PWD/contrib/yellowback/devnet:$PATH"
yellowback-devnet up --role user --seed 880      # ~3 min; prints your seed
yellowback-devnet price --walk stop               # hold the price: this scenario moves it by hand
yellowback-devnet wallet                          # YecWallet on node 0, your seat
yellowback-devnet cli -- yed_getinfo | grep -E 'inTermClaims|claimThresholdBps|claimDelay'
```

Expect `"inTermClaims": true`, `"claimThresholdBps": 12500` (θ = 125 %) and `"claimDelay": 10`
(the regtest cancel window; one day, 1,152 blocks, on mainnet). The price starts at `$50`.

## Walk-through

1. **Read the disclosure.** Before minting, find in the wallet the sentence that says a vault
   can be closed early: *"A vault whose collateral falls below 125 % of its debt at the attested
   price may be closed by anyone at once, by paying its debt; the owner receives any collateral
   above 125 % of the debt. Redeem before that point to avoid it."* Is it where you would look
   before locking YEC? Is "at once" understood as *in term*?
   - notes:

2. **Mint 100 YED, class A, the longest lock (96 blocks).** Class A is 300 % under this plan
   (D-IT-4), so the mint locks **6 YEC** at $50. In the mint result (or
   `cli -- yed_getvault <txid>`) note `lockHeight` (your term end), `claimHeight` (what the term
   end used to mean for claimants) and **`underwaterAt`**: the price at which this vault becomes
   claimable, `100 × 12 500 × 10⁸ / 600 000 000 = 20 833 333` µUSD, i.e. **$20.83**. Does the
   Positions page show that price next to the vault? (IT-8: "wallets show the claimable price
   per vault".)
   - notes:

3. **Check the template.** `cli -- vault_decodescript <scriptPubKey from yed_getvault>`:
   `appheight` equals `refHeight + 1`, the block after your mint — the claim branch is spendable
   from now on, and only RED-4 (the threshold test) decides whether a claim is valid (IT-1).
   - notes:

4. **A claim above θ is refused.** Nothing is underwater at $50. From the liquidator's side,
   `yellowback-devnet cli --node 10 -- yed_listclaimable` lists your vault with
   `"claimable": false` (or not at all), and `cli --node 10 -- yed_claim <txid> "" "" false`
   is refused with `claim-not-underwater`. Watch the simulator too: `tail -f ~/yb-devnet/sim.log`
   shows the liquidator's line `vault <id> (class A, 100 YED, 6 YEC): claimable at $20.8333
   (theta 125 %, now)`. Is the wallet's own warning as clear as that line?
   - notes:

5. **Try to redeem in term.** Redeem the vault from the wallet now: expect `vault-locked`. The
   owner path is unchanged (ownerHeight = lockHeight), so *"redeem before that point"* is only
   possible once your lock has passed. Does the wallet say so, or does it look like a bug?
   - notes:

6. **Let the price fall under the threshold.** `yellowback-devnet price 18.75` (your collateral is
   now worth 112.5 % of the debt, under 125 %). The attested claim price follows as the slow
   window fills: about 66 blocks, ≈ 16 min at the 15 s heartbeat (`cli -- yed_getprice` shows
   `pClaim` descending; `yellowback-devnet mine 60` hurries it). Watch the Positions page as the
   ratio crosses 125 %: **does the wallet warn you before the liquidator moves?**
   - notes:

7. **Watch yourself be claimed, in term.** The moment `pClaim` is under $20.83 the liquidator
   claims (`sim.log`: `CLAIMED vault <id> by clause (a) at pClaim $…: burned 100 YED (max
   100.99), collateral out … zat (min …)`). `cli -- yed_getvault <txid>` says `CLAIMING` with a
   claimant intent and its `releaseHeight`; your term is nowhere near its end (`lockHeight`).
   Ten blocks later the liquidator releases (`RELEASED claim … margin …`) and the vault is
   `CLAIMED`. What does the wallet show you, the owner, at each of those three moments?
   - notes:

8. **The residual.** At the claim price the collateral was worth 112.5 % of the debt — *below*
   125 % — so nothing lies above θ and there is no residual intent for you: the claimant takes
   it all, and that is the 12.5 % the plan calls the claimant's margin and slippage budget. The
   explainer's "owner receives the collateral above 125 %" case arises when the claim is judged
   at a price other than the one the vault crossed at. Did you expect to get something back?
   - notes:

9. **Pre-empt the next one.** Mint again (class A, lock 48), `yellowback-devnet mine 50`, then
   `price 18.75` again — and redeem from the wallet as soon as `lockHeight` passes, before the
   slow window fills. The redeem has no price test; it closes the vault under the liquidator's
   nose. Is that race legible in the wallet?
   - notes:

10. **Everyone agrees.** `cli -- yed_getstatehash` on nodes 0, 5 and 10 return one hash; the stock
    node 1 has no `yed_*`, but `cli --node 1 -- vault_getinfo` carries the same vault state hash
    as the others.
    - notes:

## By hand, without the wallet (the `upgrade-walk` step `interm`)

```bash
yellowback-devnet up --role attestor --no-heartbeat --no-walk --no-sim --seed 480
../.venv/bin/python contrib/yellowback/devnet/upgrade-walk --only members,mint,transfer,interm
```

The step prints `SKIP` with the reason on a node whose `inTermClaims` is not true, and otherwise
the computed threshold price, the refusals above θ on every Yellowback node, the claim at θ, the
release, the residual (or why there is none), the owner redeem and the state hashes.

## What we want to know

- Does a minter understand, before minting, that the lock is conditional on the price?
- Is the claimable price per vault visible and understood, or is it one more number?
- Does the owner learn about the claim while there is still something to do (redeem at
  lockHeight), or only afterwards?
