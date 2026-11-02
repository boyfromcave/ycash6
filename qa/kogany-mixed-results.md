# kogany mixed-line results (W9-b)

Kogany plan W9-b (`docs/plans/kogany/kogany-yellowback-plan.md` §3 W9, §4.2 rule 4): the whole
Yellowback functional suite in mixed mode (a kogany `zakurad` follower beside the unchanged ycash6
scripts), and three-way devnet rounds (ycash6, kogany, `yellowback_model.py`). Run 2026-11-02 on
one macOS arm64 machine shared with other agents.

## What ran

| | |
|---|---|
| kogany | `zakurad 1.7.0+421.g0d036908d` (kogany `kc/w9-mixed` = `vaults/kogany-compat` `eaac2b78d`), `cargo build -p zakura --bin zakurad --features ycash` (dev profile, as `kogany-bin.yml`) |
| ycashd | ycash6 `kc/w9-mixed`, `src/` = `vaults/kogany-compat` (65cb4ae0f + the `-lightwalletd` insight DB and `z_validateaddress -disablewallet` fixes: `lightwalletd_only` and `z_validateaddress_nowallet` hang node 0 on the 65cb4ae0f binary) |
| harness | ycash6 `kc/w9-mixed` (`vaults/kogany-compat` `9db96a75b` + the fixes below) |
| yolo / chain-viz | built at the pins of `yellowback-tests.yml` (`YOLO_COMMIT` with `--features regtest`, `CHAINVIZ_COMMIT`) |
| environment | `KOGANY_BIN=<zakurad> KOGANY_LIVE=W1-Y1,W2-b KOGANY_STRICT=1 KOGANY_STATS_FILE=<run>/stats.jsonl` |

Each pass, one group after the other (never two runners at once: `rpc-tests.py` seeds its ports
from the clock modulo 625, so two runners started a multiple of 625 ms apart share every port):

    python3 qa/kogany_mixed_shards.py run <group> --state report --jobs 2   # node: --jobs 3

for `node vault fees yed attest`, the manifest's `mirror`/`mempool` flags applied by the runner,
`KOGANY_STRICT=1` on every script. Pass r5: 13:14–17:12Z; pass r6: 17:12–21:01Z.

## Per script (passes r5 and r6)

`sync` = sync points, `statehash vault/yed` = the points where `vault_getinfo.statehash` and
`yed_getstatehash` were compared equal (kogany = ycash6; the YED hash also equals
`yellowback_model.py`'s inside the YED scripts' own model checks), `verdicts/classes` = blocks and
transactions offered to both lines and compared by verdict class, `mempool` = `getrawmempool` set
equality points. Counters from r6.

| group | script | wave | flags | r5 | r6 | sync | statehash vault/yed | verdicts/classes | mempool | note |
|---|---|---|---|---|---|---|---|---|---|---|
| node | kogany_mixed_smoke | W1 | direct | pass | pass | 5 | 5/5 | 2/2 | 0 |  |
| node | stopatheight | W9 | - | FAIL | FAIL | 2 | 1/0 | 0/0 | 0 | known exclusion (new class): pre-Ycash regtest chain |
| node | ycash_bootstrap | W9 | - | FAIL | FAIL | 0 | - | - | - | known exclusion (new class): pre-Ycash regtest chain (also: its peer, node 1, starts after setup_network) |
| node | testnet_ceremony | W9 | - | pass | pass | 0 | - | - | - | passes; starts no framework node, so no follower (0 sync points) |
| node | lightwalletd_only | W9 | - | FAIL | FAIL | 2 | 1/0 | 0/0 | 0 | known exclusion (new class): pre-Ycash regtest chain |
| node | z_validateaddress_nowallet | W9 | - | pass | pass | 1 | 1/0 | 0/0 | 0 | passes at genesis only (pre-Ycash chain never grows) |
| vault | vault_activation_restart | W2 | mirror | pass | pass | 1 | 1/0 | 0/0 | 0 |  |
| vault | vault_upgrade | W2 | mirror | pass | pass | 41 | 41/0 | 11/11 | 0 |  |
| vault | vault_primitive | W4 | mirror | pass | pass | 71 | 71/0 | 13/13 | 0 |  |
| vault | vault_slashing | W4 | mirror | pass | pass | 23 | 23/0 | 4/4 | 0 |  |
| vault | vault_undo_prune | W4 | mirror | pass | pass | 1 | 1/0 | 0/0 | 0 |  |
| vault | vault_pq_reorg | W4 | mirror | pass | pass | 1 | 1/0 | 0/0 | 0 |  |
| vault | vault_dos | W4 | mirror | pass | pass | 42 | 42/0 | 0/0 | 0 |  |
| vault | vault_rpc | W7 | mirror | pass | pass | 50 | 50/0 | 0/0 | 0 |  |
| vault | vault_rpc_contract | W7 | - | pass | pass | 19 | 19/0 | 0/0 | 0 |  |
| vault | vault_pq_relay | W6 | - | pass | pass | 6 | 6/0 | 0/0 | 0 |  |
| vault | vault_bridge | W9 | - | pass | pass | 74 | 74/0 | 0/0 | 0 |  |
| vault | vault_pq | W9 | - | pass | pass | 19 | 19/0 | 0/0 | 0 |  |
| vault | vault_pq_wallet | W9 | - | FAIL | FAIL | 1 | 0/0 | 0/0 | 0 | known exclusion (new class): pre-Ycash cached chain (200 blocks, Vault at 205 without the Ycash upgrades) |
| vault | vault_pq_wallet_restore | W9 | - | FAIL | FAIL | 1 | 0/0 | 0/0 | 0 | known exclusion (new class): pre-Ycash cached chain |
| vault | wallet_pq_address | W9 | - | FAIL | FAIL | 1 | 0/0 | 0/0 | 0 | known exclusion (new class): pre-Ycash cached chain |
| yed | yellowback_lifecycle | W5 | - | pass | pass | 191 | 191/191 | 4/4 | 0 |  |
| yed | yellowback_activation_reorg | W5 | mirror | pass | pass | 95 | 95/95 | 0/0 | 0 |  |
| yed | yellowback_reorg_restart | W5 | mirror | pass | pass | 97 | 97/97 | 0/0 | 0 |  |
| yed | yellowback_claim | W5 | - | pass | pass | 284 | 284/284 | 2/2 | 0 |  |
| yed | yellowback_interm | W5 | - | pass | pass | 185 | 185/185 | 3/3 | 0 |  |
| yed | yellowback_index | W5 | mirror | pass | pass | 403 | 403/403 | 1/1 | 0 |  |
| yed | yellowback_upgrade | W5 | mirror | pass | pass | 78 | 78/70 | 0/0 | 0 |  |
| yed | yellowback_rpc_contract | W7 | - | pass | pass | 548 | 548/548 | 1/1 | 0 |  |
| yed | yellowback_redeem_boundary | W9 | - | pass | pass | 83 | 83/83 | 8/8 | 0 |  |
| yed | yellowback_cancel_limit | W9 | - | pass | pass | 235 | 235/235 | 0/0 | 0 |  |
| yed | yellowback_pq | W9 | - | pass | pass | 254 | 254/254 | 2/2 | 0 |  |
| yed | yellowback_pq_dayone | W9 | - | pass | pass | 173 | 173/173 | 1/1 | 0 |  |
| yed | yellowback_void_mint | W9 | - | pass | pass | 223 | 223/223 | 13/13 | 0 |  |
| yed | yellowback_mint_armed | W9 | - | pass | pass | 85 | 85/85 | 1/1 | 0 |  |
| yed | yellowback_wallet_restore | W9 | - | pass | pass | 177 | 177/177 | 0/0 | 0 |  |
| yed | yellowback_sapling | W9 | - | pass | pass | 141 | 141/141 | 0/0 | 0 |  |
| yed | yellowback_wallet_lifecycle | W9 | - | pass | pass | 129 | 129/129 | 0/0 | 0 |  |
| yed | yellowback_hardening | W9 | - | pass | pass | 126 | 126/126 | 0/0 | 0 |  |
| yed | yellowback_stock_node | W9 | mirror | pass | pass | 86 | 86/86 | 1/1 | 0 |  |
| fees | yellowback_fees | W5 | mempool | pass | pass | 254 | 254/254 | 0/0 | 54 |  |
| fees | yellowback_fees_reaccept | W5 | mempool | pass | pass | 89 | 89/89 | 0/0 | 11 |  |
| fees | yellowback_fee | W6 | mempool | pass | pass | 135 | 135/135 | 0/0 | 8 |  |
| fees | yellowback_mempool_limits | W6 | mempool | pass | pass | 195 | 195/195 | 12/12 | 10 |  |
| fees | vault_policy | W6 | mempool | pass | pass | 13 | 13/0 | 18/18 | 0 |  |
| fees | vault_refee | W6 | mempool | pass | pass | 44 | 44/0 | 0/0 | 42 |  |
| fees | yellowback_wr_flags | W9 | mempool | pass | FAIL | 80 | 80/80 | 0/0 | 5 | kogany relay (flaky): r6 lost 2 of a 7-transaction z_sendmany burst to MAX_INBOUND_CONCURRENCY_PER_PEER = 5; r7 (fees group) and r8 (alone) pass; stays report |
| attest | yellowback_attest_evict | W5 | - | pass | pass | 141 | 141/141 | 0/0 | 0 |  |
| attest | yellowback_attest_rejoin | W5 | - | pass | pass | 105 | 105/105 | 0/0 | 0 |  |
| attest | yellowback_attest_live | W5 | - | pass | pass | 113 | 113/113 | 0/0 | 0 |  |
| attest | yellowback_pricefeed | W5 | - | pass | pass | 677 | 677/677 | 40/40 | 0 |  |
| attest | yellowback_mining | W8 | mirror | pass | pass | 222 | 222/222 | 45/45 | 0 |  |
| attest | yellowback_stratum | W8 | - | pass | pass | 7 | 7/7 | 0/0 | 0 |  |
| attest | yellowback_attest | W9 | - | pass | pass | 504 | 504/504 | 3/3 | 0 |  |
| attest | yellowback_attest_wallet | W9 | mirror | pass | pass | 442 | 442/442 | 0/0 | 0 |  |
| attest | yellowback_attest_bond | W9 | - | pass | pass | 391 | 391/391 | 0/0 | 0 |  |
| attest | yellowback_quote | W9 | - | pass | pass | 14 | 14/14 | 0/0 | 0 |  |
| attest | yellowback_chainviz | W9 | mirror | pass | pass | 82 | 82/82 | 0/0 | 0 |  |

**51 of 58 green in both passes** and flipped to `gate` in `qa/kogany-mixed-shards.txt`.
`yellowback_wr_flags` failed once (r6) and passed in r5, r7 and r8; it stays `report`.

## The seven that are not green

**Pre-Ycash regtest chains (six scripts; a new exclusion class, kogany design).** ycashd's regtest
leaves Ycash, Blossom, Heartwood and Canopy unscheduled unless a script passes them, so these
scripts' chains pay the inherited founders' reward from height 1 (`stopatheight`,
`ycash_bootstrap`, `lightwalletd_only`), or build on the 200-block framework cache, which is such a
chain, and activate only Vault at 205 (`vault_pq_wallet`, `vault_pq_wallet_restore`,
`wallet_pq_address`). kogany cannot follow them: Zakura's regtest puts Blossom, Heartwood and Canopy
at Sapling's height when unset (`zakura-chain testnet.rs` `ConfiguredActivationHeights::for_regtest`),
it validates pre-Canopy blocks only through a checkpoint list (`check_checkpoint_coverage`: "checkpoints
must be provided for block heights below the mandatory checkpoint height"), and under the `ycash`
feature Canopy carries the Ycash rules, so the follower asks for the YDF output at height 1 where
ycashd paid the founders' reward (`FoundersRewardNotFound`, the follower stays at genesis). Upgrades
are cumulative in kogany (K-6), so "Vault without Ycash" is not representable either. Proposed:
`excluded` rows for the six, reason "pre-Ycash regtest chain (Zakura validates pre-Canopy only by
checkpoints)". Side finding, not reachable while that holds: kogany's regtest founders' address list
is the testnet list (`Network::founder_address_list`), not ycashd's one regtest address
(`s2KGkT4L98ZB5bVwR68ygMFhFsFFtnzyH3i`, `chainparams.cpp:852`).

**`yellowback_wr_flags` (kogany relay, flaky).** A burst of seven `z_sendmany` transactions from node
0 within one second: the follower took five and dropped two at
`MAX_INBOUND_CONCURRENCY_PER_PEER = 5` (`zakurad mempool/downloads.rs:167`, the per-peer queue cap of
GHSA-4fc2-h7jh-287c), and nothing announces them again inside the 120 s window (ycashd announces a
transaction once; the follower's mempool crawler did not pick them up). Offered directly, kogany
accepted both ("a relay difference"). A kogany decision: re-request a txid the cap dropped once a
slot frees (keeping the cap), or accept the window as a recorded relay difference.

## Harness fixes (`qa/rpc-tests/test_framework/kogany.py`, with `test_kogany.py`)

1. W7-e reject texts: kogany answers `submitblock` with ycashd's BIP 22 reason and
   `sendrawtransaction` with `"<code>: <reason>"`; two `KOGANY_REASON_MAP` rows hand them to
   `REJECT_CODE_MAP` (`kogany_mixed_smoke`: `bad-cb-amount` was `reject-unclassified`).
2. `create_cache.py` (run first by `rpc-tests.py -j>1`, no nodes): `attach` has nothing to follow.
3. `KOGANY_STATS_FILE`: one JSON line of counters per run (rpc-tests.py prints nothing of a passing script).
4. `SCRIPT_PEER`: `vault_activation_restart` follows node 3 (node 1 runs Sapling at 10 and nothing
   else), `vault_primitive` follows node 0 (`VaultHarness.assert_connected` counts node 1's peers exactly).
5. A restarted peer is asked whether the follower reconnected (the follower's `getpeerinfo` still
   lists the dead connection after a SIGKILL, `vault_primitive` §J), and re-dials for up to 60 s
   (`max_connections_per_ip = 1` refused the first dial after `encryptwallet`'s double restart,
   `yellowback_wallet_restore`).
6. `KOGANY_MIRROR_INVALIDATE`: at a peer restart, the first follower block the restarted peer does
   not know is invalidated before the follower reconnects (a restart erases an invalidated branch,
   which the follower then served back: `vault_activation_restart` 13 for 9).
7. A bare `-flag` is `-flag=1` (`yellowback_mint_armed`'s `-yellowbackmintrequiresarmed`).
8. `-yellowback` is ignored by its exact name (ycashd accepts and ignores it, `init.cpp:436`; `yellowback_hardening` h6).
9. A mempool difference carries kogany's `sendrawtransaction` answer for each missing transaction.
10. A follower port held by another process is reported as such (a mainnet node's P2P listener on
    127.0.0.1:28833 answered as the follower's RPC: `yellowback_chainviz`).
11. (superseded by `9db96a75b`'s port moves) the follower ports off `yellowback_stratum`'s yolo ports.

## kogany (findings, all superseded by `vaults/kogany-compat` `eaac2b78d`)

- Mempool refusals made against a tip that moved during verification were recorded as tip
  rejections (a child relayed 0.6 s after its parent's block: `TransparentInputNotFound`; the vault
  and YED mempool checks' "the chain tip moved, retry"), so the mempools differed until the next
  block (`yellowback_fees`, `yellowback_mempool_limits`, `vault_refee`). Fixed on `kc/w9-mixed`
  (`c115d6bf9`, re-queue by id) and then by the state-retry mempool of W9-a/F-6; the merge keeps
  that one. With it, every mempool script is green in both passes.
- Falcon (W3-c/F-1) is resolved by `eaac2b78d`: `vault_policy`, `yellowback_pq`, `yellowback_pq_dayone`
  and `vault_pq` (failing or note-only before) are green.

## Devnet: three-way rounds (`qa/yellowback-rc-crossline.py --kogany-zakurad`)

    contrib/yellowback/devnet/yellowback-devnet up --dir D --portseed 777 --no-heartbeat --no-walk --no-sim --no-viz
    qa/yellowback-rc-crossline.py --devnet-dir D --kogany-zakurad <zakurad> --rounds 5 --out D/crossline.json

The devnet: 8 ycash6 nodes, ARMED at 200 (3 attestors), Falcon active from the vault activation
(103). One kogany node takes node 0's chain arguments through the harness map (no argument left
unmapped). At each 100th height every node's block hash, vault state hash and YED state hash, and
`yellowback_model.py`'s YED state hash rebuilt from node 0's blocks, agree (9 nodes + the model):

| height | block | vault statehash | YED statehash (kogany = ycash6 = model) |
|---|---|---|---|
| 300 | 0e91a3ad5ba31104… | 328dee032c307231… | c0ab9b4ac3565378… (8 nodes with the attestor set + the model) |
| 400 | 09ca5eeaa1562ae8… | cfee0b740b531ded… | c6f80b543220c05a… (8 nodes with the attestor set + the model) |
| 500 | 0e6e2dd83afe6925… | cea0421d57ad6c06… | 261441b70a35cc76… (8 nodes with the attestor set + the model) |
| 600 | 0a9cf203456677f5… | 6538914f7879e27c… | a4acc3b4958d6bda… (8 nodes with the attestor set + the model) |
| 700 | 0a29a20cae8c2ed8… | 6538914f7879e27c… | 6591135c146304fb… (8 nodes with the attestor set + the model) |

5 rounds × 100 blocks (300–700), no disagreement (block hash and vault state hash on all 9 nodes).
