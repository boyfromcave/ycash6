# Yellowback devnet and regtest — a crash course

Two ways to run Yellowback on one machine.

| | What it is | Use it for |
|---|---|---|
| **devnet** | `yellowback-devnet up` — eight regtest nodes, funded, activated and **ARMED** (three attestors with real agents) | GUI demos, a wallet to click at, a chain that already works |
| **devnet, one seat empty** | `yellowback-devnet up --role {user,attestor,pool}` — eleven nodes, a heartbeat, a price walk, six simulated personas, and *you* in one seat | walking a participant's shoes for feedback (`docs/plans/role-based-regtest-plan.md`); the four checklists are in `contrib/yellowback/devnet/scenarios/` |
| **by hand** | one `ycashd -regtest` node you drive with `ycash-cli` | understanding the v3 price-attestation path one RPC at a time |

The devnet's full command set, the role presets, the personas and the regression suite are
documented in `contrib/yellowback/devnet/README.md`; this page is the crash course.

Every command below was run on 2026-09-20 against `feature/yellowback-price-attest`.

---

## 0. Build once

```bash
cd ycash-dd
export PATH="/opt/homebrew/opt/libtool/libexec/gnubin:/opt/homebrew/opt/coreutils/libexec/gnubin:/opt/homebrew/bin:$PATH"
export CARGO_TARGET_DIR="$PWD/target"
make -C src -j8 ycashd ycash-cli test/test_bitcoin     # ~2 min incremental
```

A failed `make` leaves the old binaries in place — check the exit code, not the test output.
Python is always the workspace venv (`../.venv/bin/python`), never the system interpreter.

---

## 1. The devnet, in one command

```bash
../.venv/bin/python contrib/yellowback/devnet/yellowback-devnet up          # ~2 min: 8 nodes, funded, activated, ARMED
```

Node 0 is the funded wallet, node 1 is a stock (unpatched) node, nodes 2–4 are signalling pools,
nodes 5–7 attestor nodes. `up` mines 101 blocks to fund node 0, sets a $50 quote on each pool,
mines 131 signalling blocks so the chain is **active**, registers the three attestors
(`yed_registerattestor 10 200`), mines through `BOND_MATURITY` and `ATTEST_ARM_DELAY` so the
layer is **ARMED**, and starts one real `yellowback-attest attest` per attestor plus a
`subscribe` beside node 0 on the `dir` transport. The first mint builds its bundle from that
pool. `up --no-attest` is the five-node v2 devnet.

```bash
yellowback-devnet status          # activation, prices, each pool's eligibility
yellowback-devnet check           # exit 0 iff active, minting allowed, pools eligible — the machine-checkable gate
yellowback-devnet price 12.50     # move the YEC/USD price (pools and every attestor together)
yellowback-devnet attestor 6 stop # ...or an outage / a divergence demo: attestor N {stop|start|price USD}
yellowback-devnet mine 5          # mine 5 blocks (optionally: mine 5 <node>)
yellowback-devnet wallet          # launch YecWallet against it
yellowback-devnet cli -- yed_getinfo          # ycash-cli on node 0
yellowback-devnet cli --node 2 -- yed_gettag  # ...or any other node
yellowback-devnet down            # stop; --wipe also deletes ~/yb-devnet
```

Flags worth knowing: `up --price 3.25` (starting price), `up --portseed N` and `--dir PATH` (run
two devnets side by side), `up --force` (rebuild over an existing one).

**With real quote agents.** By default `up` pushes quotes with `yed_setquote`. To exercise the
path a real pool runs instead:

```bash
yellowback-devnet up --agents     # one yellowback-quote --mock-price process per pool
```

Each pool then runs the actual agent against a shared mock price file, and the pools are started
with `-yellowbackquotemaxage=120` so a stopped agent becomes visible within two minutes.

---

## 2. The v3 attestation path, by hand

One node is enough. The regtest constants are small on purpose: bond floor 10 YEC, bond maturity
8 blocks, 3 attestors trigger arming, then 8 more blocks.

**Start a node.** The six `-nuparams` are required — regtest activates no upgrade by itself.

```bash
D=~/yb-rt && mkdir -p $D && cat > $D/ycash.conf <<'EOF'
regtest=1
server=1
rpcuser=rt
rpcpassword=rt
experimentalfeatures=1
yellowback=1
yellowbackstartheight=1
yellowbacksigmaref=0
yellowbackattestarmmin=3
nuparams=5ba81b19:1
nuparams=76b809bb:1
nuparams=374d694f:1
nuparams=8e471bd6:1
nuparams=66314da3:1
nuparams=19bd2d2f:1
EOF
src/ycashd -datadir=$D -daemon
alias C="src/ycash-cli -datadir=$D"
C yed_getinfo          # rpcversion 3; attest.status "UNARMED"
```

**Fund, then register three attestors.** Mine past coinbase maturity first.

```bash
C generate 141                       # ~260 YEC mature
C yed_registerattestor 10 200 0      # bond 10 YEC, CLTV 200 blocks, flags 0
C generate 1 && sleep 2              # see the gotcha below: let the wallet settle
# repeat twice more
C yed_listattestors                  # seq 0,1,2 — PENDING until registerHeight + 8
```

**Arm it.** The layer arms itself: 3 eligible attestors trigger it, then `ATTEST_ARM_DELAY`.

```bash
C generate 10 && C yed_getinfo       # -> "TRIGGERED", armHeight = triggerHeight + 8
C generate 10 && C yed_getinfo       # -> "ARMED", seatedCount 3
```

**Sign, pool, bundle.** `yed_signattestation` signs with the node's own key; `yed_addattestation`
puts a signature into this node's pool (the pool is **per node** and is not relayed).

```bash
for s in 0 1 2; do
  H=$(C yed_signattestation $s 50000 | python3 -c 'import json,sys;print(json.load(sys.stdin)["hex"])')
  C yed_addattestation $H
done
C yed_getattestations                # what this node holds
R=$(( $(C getblockcount) - 2 ))
C yed_getselection $R ""             # which attestors a mint at R must use ("" = the mint selector)
C yed_buildbundle $R ""              # the bundle the node would build: seqs, aMint, hex
```

From here `yed_mint` works with no `bundleHex`: it takes the bundle from the pool, publishes a
carrier transaction, waits one block, then sends the mint (see the gotcha on the two-step flow).

```bash
C stop                               # done
```

---

## 3. The two agents

Both are optional for a devnet and both read a **mock price file in dollars** (`0.50`, not µUSD).

**Pool quote agent (v2, Python).** What a mining pool runs:

```bash
contrib/yellowback/yellowback-quote --conf contrib/yellowback/pool/yellowback-quote.toml.sample --dry-run --mock-price /dev/stdin <<< 0.05
```

`--dry-run` aggregates and prints without touching the node; `--once` publishes one quote and
exits; `sources` shows what each configured source resolves to.

**Attestor agent (v3, Rust).** Never holds a key: it asks its own node to sign and publishes the
74 bytes. Build and run it from its own directory so the pinned toolchain is selected:

```toml
# ~/yb-rt/attest.toml — minimal regtest config
[node]
rpc_url = "http://127.0.0.1:18832"    # regtest RPC port
rpc_user = "rt"
rpc_password = "rt"

[attest]
seq = 0                # your registration's seq, from yed_listattestors
every_blocks = 1
ref_lag = 2
poll_seconds = 2

[transport]
kind = "dir"           # a shared directory instead of gossip — the test/devnet transport
path = "/Users/you/yb-rt/bus"
```

```bash
cd contrib/yellowback/attest
echo 0.50 > ~/yb-rt/mock-price
cargo run -q -- check-config --conf ~/yb-rt/attest.toml         # validate before running
cargo run -q -- attest    --conf ~/yb-rt/attest.toml --mock-price ~/yb-rt/mock-price &
cargo run -q -- subscribe --conf ~/yb-rt/attest.toml &
```

`attest` logs `published seq 0 500000 µUSD ($0.500000) citing height 169 from mock via dir` and
writes `bus/0-169.att`; `subscribe` reads the bus and logs `accepted seq 0 500000 µUSD citing 169`,
which is the signature landing in that node's pool. For production use `kind = "iroh"` instead —
see `contrib/yellowback/attest/attest.toml.sample`, which documents every field.

---

## 4. Gotchas that will cost you an hour

- **Let the wallet settle between commands.** Two `yed_registerattestor` calls back to back, even
  with a `generate 1` between them, can fail with `transaction commit failed: the transaction was
  rejected by the mempool` — the wallet built on a view the block had already invalidated. A
  `sleep 2` after mining fixes it.
- **Do not hand-sign and run an agent on the same `seq`.** The node remembers what it signed: a
  second signature for the same height at a different price is refused with `equivocation-guard`.
  That is the safety rule working — signing two prices for one height is what ejects an attestor.
- **The mock price file is in dollars**, and `yed_signattestation` takes **µUSD** (`50000` =
  $0.05).
- **Mints and claims are two transactions** once armed: a carrier that commits to the bundle, then
  the mint one block later. A script that calls `yed_mint` and never mines will wait forever —
  mine from another shell, or pass `wait=false`.
- **The attestation pool is per node.** A claimant needs its own pool fed (or an explicit
  `bundleHex`); attestations are not relayed like transactions.
- **A constant quote gets pinned.** If your pools hold one price while attestations move more than
  5 %, PIN-1 marks those pools pinned and drops them from the medians. Jitter the price, or expect
  `xMint` to go undefined.
- **Ports:** regtest RPC is 18832. Use `--portseed`/`--dir` to run two devnets at once.

---

## 5. Walking the roles

```bash
yellowback-devnet up --role user        # you mint on node 0; wallet opens there
yellowback-devnet up --role attestor    # you register and run an attestor on node 8 (GUI for the bond, then ycash-cli + your agent)
yellowback-devnet up --role pool        # you run a pool on node 4, headless
yellowback-devnet status                # the seat banner first: which node is yours
yellowback-devnet sim stats             # what the six personas did, and what was refused
yellowback-devnet price --shock=-70%    # watch the liquidator claim the personas' class C vaults
yellowback-devnet report                # bundle NOTES.md, every log and the tally
```

The rules, the node map, the heartbeat, the walk, the personas and the pool/attestor seat
commands are in `contrib/yellowback/devnet/README.md` §2; the plan is
`docs/plans/role-based-regtest-plan.md`. The regression suite for all of it is
`qa/rpc-tests/yellowback_devnet_roles.py` (nightly).

For the full automated coverage, the functional suite exercises the attestation path:

```bash
cd qa/rpc-tests
BITCOIND=$PWD/../../src/ycashd ../../../.venv/bin/python -u yellowback_attest.py \
    --srcdir=$PWD/../../src --tmpdir=/tmp/yb1 --portseed=9001
```

`yellowback_attest.py` (the node path), `yellowback_attest_wallet.py` (the wallet RPCs) and
`yellowback_attest_enforcement.py` (rejection against a stock miner) are the three that cover v3
in the merge gate; `yellowback_attest_agent.py` (the real Rust agent) and
`yellowback_devnet_roles.py` (the devnet's role presets) run nightly. Give each run a unique
`--portseed`.

See also: `doc/yellowback.md` (user guide), `doc/yellowback-attestor.md` (running an attestor for
real), `doc/yellowback-mining.md` (running a pool).
