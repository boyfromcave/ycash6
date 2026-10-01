# `contrib/yellowback/devnet/` — the one-laptop Yellowback network, and walking the roles

Two scripts and four checklists:

| File | Role |
|---|---|
| `yellowback-devnet` | the network: `up` builds a regtest chain that is activated and **ARMED** when it returns; every other command drives it |
| `yellowback-sim` | six personas that inhabit it (started by `up --role`; `sim start|stop|stats`) |
| `stratum-miner` | a headless stratum client at regtest's Equihash 48,5 (the framework's Python solver): the GPU rig's stand-in for the pool seat (`docs/plans/role-pool-regtest-plan.md` §3.3); `--record` writes the wire exchange as JSONL |
| `yellowback_stratum.py` (in `qa/rpc-tests/`) | the functional test of the stratum path: yolo on every payout × text cell, the miner, the tag on every accepted block, `--text --no-flags` dropping it; SKIPs without `YOLO_BIN` |
| `stratum-perl-check` | proves `stratum-miner` against the Perl reference pools in `ref/yolo` on a two-node regtest and records `fixtures/stratum-perl-*.jsonl`; `YCASHD`/`YCASH_CLI` name the binaries |
| `scenarios/*.md` | the four walk-throughs of `docs/plans/role-based-regtest-plan.md` §4 as runnable checklists; `up --role` copies the role's into the session's `NOTES.md` |

## 0. Before you start

Neither script is on your PATH, and their `#!/usr/bin/env python3` must find the **workspace
venv's** Python: they import the inherited test framework from `qa/rpc-tests/`, which needs
`simplejson` — present in the venv, absent from the system Python macOS ships. Three lines, once
per terminal, make every command in this file work verbatim from any directory:

```bash
cd <workspace>/ycash-dd
source ../.venv/bin/activate
export PATH="$PWD/contrib/yellowback/devnet:$PATH"
```

Or skip them and spell each command out from the `ycash-dd` directory: `../.venv/bin/python
contrib/yellowback/devnet/yellowback-devnet <command>`. Running `./yellowback-devnet` from this
directory does **not** work on its own — the shebang then picks the system Python and dies on
`ModuleNotFoundError: simplejson`.

You also need `src/ycashd` built and `contrib/yellowback/attest` built (`cargo build --release`;
`YELLOWBACK_ATTEST_BIN` names the binary if the search does not find it).

## 1. The plain devnet (v2 demo and v3 arming)

```bash
yellowback-devnet up                # ~2 min: 8 nodes, node 0 funded, 3 pools quoting, 3 attestors registered, ARMED
yellowback-devnet up --agents       # the pools quote through real yellowback-quote --mock-price agents
yellowback-devnet up --no-attest    # the five-node v2 devnet: never ARMED
yellowback-devnet up --no-viz       # do not start chain-viz (section 5)
yellowback-devnet status | check | mine N [node] [--untagged] | price USD | attestor N {stop|start|price USD} | notice VAULTTXID
yellowback-devnet wallet | cli [--node N] -- yed_getinfo | down [--wipe]
yellowback-devnet lightwalletd [start|stop|status] [--baseline] [--port 9067] [--extra=-yellowback]   # lightwalletd-dd against node0 (docs/plans/yellowback-lightwalletd-plan.md)
yellowback-devnet vectors [--out DIR] [--seed N] [--count N]   # JSON signing/address/template vectors for the YEW core (docs/plans/yellowback-wallet-plan.md, W0c)
```

`vectors` writes four JSON files (default `DIR/vectors`) that `yew/core/tests/vectors/` carries: `transparent.json` (N transparent v4 transactions with `unsignedHex`, `prevouts`, per-input `keys`, `branchId`, `sighashPerInput`, the node's `signedHex`, `txid` and `pythonMatches`: whether pure-Python RFC 6979 signing reproduces the node's bytes), `addresses.json` (WIF, pubkey, HASH160, the `sm…`/`s1…` and `yr…`/`ye…` renderings of ~5 keys), `templates.json` (a node-built MINT with its carrier when ARMED, TRANSFER and REDEEM: `hex`, `decoded`, `yed_gettxinfo`, `payloadHex`, `yed_decodepayload`) and `params.json` (`yed_getinfo`, upgrades and branch ids, fees, the protocol constants, the address version bytes of all three networks). `--seed` fixes the structure; the keys come from node 0's keypool. It mines on the automated pools round-robin (blocks node 0 mines carry no quote tag and would drain the price windows) and needs node 0 to hold ~5x the minimum mint in YEC (`--fund-from N` tops it up from node N).

`check` exits 0 iff activation is active, minting is allowed, every automated pool is eligible, the layer is ARMED with `poolFresh ≥ M_SELECT`, and every automated agent and process is alive. It is the machine-checkable gate; `status` is the human one.

## 2. Walking the roles: `up --role`

> **Exactly one seat is manual. Everything else runs on a timer, including the chain itself.**

Yellowback has three participants whose incentives only make sense in relation to each other: minters and holders, mining pools, bonded attestors. The plain devnet automates all three, which is right for a demo and wrong for feedback. `up --role` leaves **one** seat empty for you and keeps the world moving while you think — blocks arrive, the price drifts, other people's vaults are minted, redeemed and liquidated.

```bash
yellowback-devnet up --role user        # you: a minter on node 0.  GUI: `wallet`
yellowback-devnet up --role attestor    # you: an attestor on node 8, funded and UNREGISTERED. GUI for the bond, then ycash-cli + your own agent
yellowback-devnet up --role pool        # you: a pool on node 4, a plain miner at first. No GUI: pools are headless
```

| Node | `user` | `attestor` | `pool` |
|---|---|---|---|
| 0 | **you** (minter) | funding + subscriber | funding + subscriber |
| 1 | stock (no `-yellowback`) | stock | stock |
| 2–3 | pools, automated | pools, automated | pools, automated |
| 4 | pool, automated | pool, automated | **you**: no payout, no signal, no quote |
| 5–7 | attestors, automated | attestors, automated | attestors, automated |
| 8 | 4th attestor, automated | **you**: 13 YEC, unregistered, no agent | 4th attestor, automated |
| 9 | simulated population | simulated population | simulated population |
| 10 | simulated liquidator | simulated liquidator | simulated liquidator |

Eleven nodes, ten agent processes, a heartbeat, a price walk and the simulator — `up` prints the footprint first; `--lean` drops the walk and halves the heartbeat rate. `status` opens with a banner naming your seat and your node, because driving the wrong node is the single most likely mistake. `wallet` opens on your seat (`--node N` for another; `YELLOWBACK_WALLET_BIN` names the GUI binary). Each `up --role` prints its **seed**; `up --role R --seed N` replays the personas and the walk exactly.

### The heartbeat (`heartbeat`)

Mines one block every 15 s (`--heartbeat-rate N`, `heartbeat rate N` live), round-robin across the **automated** pools only — in the pool preset your blocks are always yours to mine. `heartbeat {start|stop|status}`. It halts itself, and says why in `<dir>/heartbeat.log`, when the devnet is no longer live (a dead node, a lost arming, a crashed automated agent); a halted mint after a price shock is weather, not death, and does not stop it. Agents you stop deliberately (`attestor N stop`, `pool N quote stop`) are recorded as such and do not stop it either.

15 s per block against the regtest windows (`REF_LAG = 2`, `ATTEST_MAX_AGE = 8`, `attestInterval = 4`, `DORMANCY_CHECK = 4`) makes an attestation tick about every minute — slow enough to watch, fast enough to feel alive.

### The price (`price`)

```bash
yellowback-devnet price 12.50                    # a step to a value
yellowback-devnet price --walk                   # a seeded random walk: --drift %/min (0), --vol %/tick (1), --tick s (5)
yellowback-devnet price --walk stop              # freeze
yellowback-devnet price --shock=-40%             # a step change; the walk, if running, continues from it (the `=` keeps the minus from reading as a flag)
yellowback-devnet attestor 6 price 60            # ONE attestor diverges: an attack, not weather (stop the walk first to hold it)
```

The walk writes the pools' mock price and every **automated** attestor's mock price together, so the two populations move honestly in agreement; your own attestor's price file (`attestor` preset) is never touched. Liquidation needs a real fall: class C vaults (300 %) go under the 110 % claim threshold at about −64 %, class A (500 %) at about −78 %. A crash also halts minting for a while: `DIVERGENCE` between the price windows stops every mint until they agree again, and `GLOBAL_RATIO` then *limits* minting to the classes whose minimum ratio reaches the recapitalisation floor — class A (500 %) — so the book can be rebuilt rather than left to the price (v3 plan W16). `status` says "limited to class A" and `yed_getstats.mintableClasses` lists what can mint; `check` still treats a limited state as not-allowed.

### The personas (`sim`, `yellowback-sim`)

Six strategies, each with its own cadence and characteristic failure, seeded, on two wallets: the **population** (node 9) hosts the five minter/holder personas, the **liquidator** (node 10) owns none of their vaults — because claiming someone else's underwater vault is a different path (RED-4, a third party) from an owner redeeming, and it is the one the attested price governs. Risk appetite is the term class: `yed_mint` always locks exactly the class minimum, so "leveraged" means class C (300 %, the longest terms) and "conservative" means class A (500 %, the shortest).

| Persona | Does | Characteristic failure |
|---|---|---|
| leveraged | class C mints, holds two, never redeems early | the first liquidated on a downswing |
| conservative | class A mints, one at a time, redeems at maturity | the happy path |
| exiter | redeems the moment `lockHeight` passes; releases VOID vaults; runs `yed_sweepcarriers` | `vault-locked`, `insufficient-yed` when the trader moved its YED |
| trader | never mints; `yed_send` / `yed_sendmany` between its addresses and to the liquidator | `insufficient-yec` on a wallet whose change is unconfirmed |
| absentee | mints once, then nothing | an abandoned vault seen from outside |
| liquidator | mints its own YED inventory; claims whatever `yed_listclaimable` lists; posts `yed_claimnotice` on a foreign vault under the emergency ratio near its claim height and claims after `EMERGENCY_PERSIST` | `claim-not-yet`, `notice-not-underwater`, `bundle-insufficient` |

Every bundle-carrying call is two-step and made with `wait=true`, so the personas rely on the heartbeat to mine their carriers; without it they block. A refusal is logged (`<dir>/sim.log`) and tallied by its stable identifier, never retried blindly: `sim stats` prints the tally per persona and shouts when a persona's every action is failing. Cadences: `--sim-profile demo` (a half-hour walk-through at 15 s blocks) or `fast` (the regression suite at 2 s blocks).

### The pool seat (`pool`)

```bash
yellowback-devnet pool 4 configure       # restart node 4 with its payout address and -yellowbacksignal=1 (scenario 3 step 2)
yellowback-devnet pool 4 quote start     # the real yellowback-quote agent beside it; `stop` lets the quote go stale past 120 s
yellowback-devnet pool 3 signal off      # a pool keeps mining and quoting but its tags carry no signal bit; two silent pools of three cross the 60 % pause
yellowback-devnet mine 3 4               # your blocks are yours to mine
```

`mine N` with no node mines round-robin on the automated pools, exactly as the heartbeat does, so
every block carries a quote tag. `mine N <node>` refuses a node whose blocks would carry no tag —
the user seat (node 0), the stock node (node 1), a pool without a payout key — because 50 tagless
blocks in the 64-block window empty the price windows (`NO_PRICE`), halt minting
(`PARTICIPATION`) and suspend block rejection (`ENFORCEMENT`, ACT-6): one command impersonating a
hashpower majority walking away (chain-viz plan C-F34). `--untagged` does it on purpose, which is
how to rehearse that outage.

```bash
```

#### The stratum seat (`--stratum`)

```bash
yellowback-devnet up --role pool --stratum [--stratum-text TEXT]   # yolo beside node 4; `mine N 4` goes through it
yellowback-devnet pool 4 stratum start [--stratum-text TEXT] | stop | status   # the same on a running devnet
yellowback-devnet status                 # one line from yolo's GET /status: payout, text, miners, template age, tag kind, last verdict
```

No Ycash pool mines with `generate`, so the pool seat can run real pool software:
**yolo** (`<workspace>/yolo`, the Rust rewrite of `yecdev/yolo`; `YOLO_BIN`, then
`yolo/target/release/yolo`, then `PATH`) is started beside node 4 with node 4's RPC
credentials from `devnet.json`, on a stratum port and a `/status` port derived from the
portseed (21000 + the seat's rpc-port offset, and +5000; below 32768 so Linux's ephemeral range cannot take them), recorded in `devnet.json` with its pid,
payout address and text. `mine N 4` then runs `stratum-miner --blocks N --user devnet-worker`
against it — node → `getblocktemplate` → `mining.notify` → the Python 48/5 solver →
`mining.submit` → `submitblock`, about one block per second — instead of `generate`; the
heartbeat never mines the seat's blocks either way. yolo has no modes (P-6), two flags: the
seat always runs `--payout <node 4's payout address>`, so every block pays node 4's wallet and
the miner's username is a free worker name (without `--payout` the username must be a t-address
and is paid); `--stratum-text TEXT` passes `--text`, and the scriptSig is rebuilt as height ‖
`coinbaseaux.flags` ‖ text (the carrier a self-assembling stack must use) instead of being used
as the node built it. The tag's payout key comes from `-yellowbackpayoutaddress` (MINER-2), not from the coinbase
output, so `yed_listminers` sees node 4 whichever address the coinbase pays. No `setmocktime`
is needed for the burst-generated chain: yolo stamps `max(template.curtime, now)` and the
node's `curtime` is already `max(MTP + 1, now)`. `down` stops yolo and any miner still solving;
`report` bundles `stratum-4.log` (yolo) and `stratum-miner-4.log`; `check` fails when yolo has
died or stopped answering `/status`. `qa/rpc-tests/yellowback_stratum.py` runs the same path
unattended for every payout × text cell. Scenario 3 step 0 says what to look at.

### The attestor seat

Node 8 is funded (13 YEC) and unregistered; `<dir>/attest-8.toml` is your agent's configuration with `seq` left for you to fill in once `yed_registerattestor` confirms, and `<dir>/attest-price-8` your mock price. The devnet's `attestor 8 …` refuses to touch your seat; scenario 2b is walked by following `doc/yellowback-attestor.md` literally.

### Sessions and reports

`up --role` creates `<dir>/session-<role>-<date>/NOTES.md`, seeded with the role's checklist(s) from `scenarios/` and a header carrying the seed, your node and both fork commits, so an observation is typed against the step that prompted it. `yellowback-devnet report` writes `REPORT.md` (chain state, `yed_getinfo.params`, the personas' tally) beside it and bundles the session, `devnet.json`, every agent and process log and every node's `debug.log` into `<dir>/report-<role>-<date>.tar.gz`. `scenario [NAME]` prints a checklist on its own.

## 3. The regression suite

`qa/rpc-tests/yellowback_devnet_roles.py` (nightly, `EXTENDED_SCRIPTS`) drives this script as a subprocess — `up --role` for each preset — and asserts, per preset: the seat is empty and the node map is the one above; the heartbeat advances the chain on the automated pools only, with no help from the test; every persona performs its characteristic action, a vault is redeemed at maturity, and after a −70 % shock **the liquidator claims a leveraged vault**; the walk keeps the pools' and attestors' prices byte-equal and nothing ends pinned; `check` passes before the shock, and the state hash agrees across every enforcing node after. Fixed seed; SKIPs without the Rust binary; about 30 minutes for the three presets (`--presets user` for one).

## 4. Two devnets at once

`YELLOWBACK_DEVNET_DIR` / `--dir` and `YELLOWBACK_DEVNET_PORTSEED` / `--portseed` (a `PORTBASE` is folded into a seed). The inherited port helper caps a run at 8 nodes; this script raises the cap once and **publishes every node's RPC URL in `devnet.json`**, which is what `yellowback-sim` and the regression suite read — never recompute a port.

### The port table

Every port follows the portseed `s` (node `n`, `MAX_NODES` = 12 after the raise). `offset(s)` is the inherited framework's spread, `(12 * s) % 4991`, so the p2p, rpc, stratum and status bands each take 5000 ports; the two bands added for chain-viz fold the seed modulo a small period instead, because no 5000-wide band is left below 32768, where Linux's ephemeral range begins (a 30000 base once collided with client sockets on CI). Two devnets whose seeds agree modulo 140 share zmq ports, and modulo 88 the chain-viz port — pick seeds a few apart.

| Port | Formula | Range | Recorded in `devnet.json` |
|---|---|---|---|
| p2p, node `n` | `11000 + offset(s) + n` | 11000–16000 | (the framework's) |
| rpc, node `n` | `16000 + offset(s) + n` | 16000–21000 | `rpc[n].port` |
| stratum, pool seat `n` | `21000 + offset(s) + n` | 21000–26000 | `stratum[n].port` |
| yolo `/status`, seat `n` | stratum + 5000 | 26000–31000 | `stratum[n].status_port` |
| zmq, node `n` (`hashblock` and `hashtx` on one socket) | `31000 + 12 * (s % 140) + n` | 31000–32679 | `nodes[n].zmq.hashblock`, `.hashtx` |
| chain-viz HTTP | `32680 + s % 88` | 32680–32767 | `chainviz.port`, `.url` |
| lightwalletd gRPC | fixed | 9067 | — |

## 5. chain-viz: the chain and Yellowback visualizer (`docs/plans/chain-viz-plan.md`, C-11)

Every node started by `up` publishes ZMQ notifications: `-zmqpubhashblock` and `-zmqpubhashtx` on one `tcp://127.0.0.1:<port>` endpoint per node (ycashd binds a single PUB socket per address and publishes both topics on it), the port from the table above, the URLs under `nodes[n].zmq` in `devnet.json` (the `rpc` map is unchanged). The node logs its zmq activity only under `-debug=zmq`; a subscriber, or `lsof -iTCP:<port>`, is the check.

`up` then starts **chain-viz** on the finished `devnet.json` — the binary is `CHAINVIZ_BIN`, else `chain-viz` on `PATH`, else `<workspace>/chain-viz/target/release/chain-viz`, then `target/debug/chain-viz` — as

```
chain-viz --devnet <dir> --listen 127.0.0.1:<port> --record <dir>/chain-viz --pid-file <dir>/chain-viz.pid
```

with its output in `<dir>/chain-viz.log`, waits up to 15 s for its `listening on http://…` line and prints that URL as the last-but-one line of `up`'s summary; `devnet.json` records `chainviz = {pid, url, port, log, binary, pid_file, record}`. No binary found is one dim line and the devnet continues without it; `--no-viz` skips it. `status` prints the URL and whether the process is alive, `down` stops it (SIGTERM, SIGKILL after 5 s; by the record or the pid file), and `report` bundles `<dir>/chain-viz/session.jsonl` when the recording exists. chain-viz is strictly read-only against the nodes (plan §4.2); it is never part of `check`, so a dead visualizer does not fail the devnet.
