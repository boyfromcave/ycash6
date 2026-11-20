# `contrib/testnet/ceremony/` — a testnet's launch ceremony, as a script

<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

## In plain words

Before a new Ycash testnet can be published, a few facts about it have to exist that can only be
created by running it: the fingerprint of its first own block (the fork block), the identity of
its group of price attestors, and a "known good" point in its history. The release that people
download must carry those facts, so they are produced first, privately, by a handful of launch
operators, and then written into the release. This script does that work step by step and writes
the facts into one file the release is built from. It never writes a secret key into that file or
into any code repository. The same script runs on a throwaway local chain (the rehearsal), so the
real launch is a re-run of something that has already worked.

## The real ceremony (testnet plan §2.2)

Every launch operator runs the **ceremony build** (the network's parameters with its Vault height
set; the fork block's hash and the attestor set unset), restores the prefix with
`contrib/bootstrap/ycash-bootstrap`, and connects only to the other operators. One operator runs:

```bash
ycashd -testnet -testnetprofile=fast -connect=<other operator> -maxtipage=999999999 -daemon   # see "Mining" below
contrib/testnet/ceremony/ceremony --network testnet-yb-fast --datadir ~/.ycash --secrets /secure/place/keys \
    --out ceremony-testnet-yb-fast.json
```

| Step | What happens |
|---|---|
| `check` | the node is on the named network (`getblockchaininfo` chain and `testnetprofile`), holds the prefix (block 510,247 = the compiled checkpoint), has no attestor set configured, and can mine (a peer; out of initial block download) |
| `fork` | mine (or wait for) block 510,248, check it follows the prefix, record its hash |
| `vault` | mine to `H_V − 1`, so the next block activates the vault upgrade |
| `set` | `set_create`: OPEN, 15 seats, unlock/cancel/slash 1, `ratelimitbps` 0 (the P8 checklist), `maturity` = the network's BOND_MATURITY (fast 48, slow 16,128; the module adopts no other), `livenesswindow` 1,152, `bondmin` the house bond. Created once: a re-run verifies the recorded set |
| `seats` | the house seats (fast 9 on 3 hosts, beta4 D-1; slow 3) join with the profile's bond (fast 20 YEC, D-3; slow 10,000 YEC). With `--member-keys` each seat's key is **born on its host** and only its public key reaches the ceremony (below); without it the ceremony wallet makes the keys and writes each (WIF, member key, bond outpoint) to `--secrets/<network>-seat-N.json`, mode 0600, in a 0700 directory that must not be inside a git repository |
| `mature` | mine until the last join is past the set maturity |
| `record` | the checkpoint (the tip), and the release values |

### Seat keys born on the hosts (beta4, C-T7)

No seat key is ever on the ceremony host (price-feed plan D-1: 9 seats, 3 hosts, one key per seat, never a key
on two hosts). Each attestor host makes its own keys in its own node wallet and hands over only the public
member keys:

```bash
# on each seat host (a, b, c), three times: a fresh key of that host's node wallet; prints {address, memberkey}
contrib/testnet/ceremony/ceremony host-key --network testnet-yb-fast --datadir ~/.ycash
```

The ceremony operator collects them into `member-keys.json`, `{"hosts": {"a": [k1, k2, k3], "b": [...], "c": [...]}}`
(every key a compressed public key, none twice, the same number per host, the seat count in all), and runs
`--steps set,seats` with `--member-keys member-keys.json`. For every seat the `seats` step builds the `SET_JOIN`
from the ceremony wallet's coins without the member's signature (`set_buildact join`, which takes any member key; `set_join`
refuses a key its wallet lacks), locks its coins, writes `<network>-seat-N-<host>.join.json` (public: set, seat, host,
member key, bond, hex) to `--handoff` (default `<record dir>/<network>-joins`) and stops, naming the files. Seats
go round robin over the hosts (a, b, c, a, …), so host a holds seats 1, 4, 7 (seq 0, 3, 6). On each host:

```bash
contrib/testnet/ceremony/ceremony host-sign --network testnet-yb-fast --datadir ~/.ycash --join testnet-yb-fast-seat-1-a.join.json
```

adds the member's signature (`set_signact`: this wallet's act signatures only; the inputs stay unsigned; refused
if the key is not this wallet's) and writes `…-seat-1-a.signed.json`. Back on the ceremony host, a re-run of
`--steps seats,mature,record` sends each signed join (`set_sendact`, the bond allowed as outflow). The bond
`P2SH(<lock> CLTV DROP <memberkey> CHECKSIG)` is then spendable only by its host. The record's `house_seats`
carry each seat's host, member key and join txid; `seats.json` of the attestor hosts takes seq and member key
from `yed_listattestors` once the set is live. The coin locks live in the ceremony node's memory: restart it
mid-way and a re-run locks the pending joins' coins again.

`--steps a,b,…` runs a subset (`check` always runs); every step reads and extends the record, so
the ceremony can be stopped and continued. `testnet-legacy` runs `check, fork, record` (no
Yellowback). `testnet-yb-slow` launches the same way; its set steps run once a build sets its
Vault height (T-15).

**Mining.** A testnet node mines with `setgenerate` only when it has a peer, and only out of
initial block download. After the prefix import its tip is a block from 2019, so the node counts
as in IBD and will not mine: start the ceremony node with `-maxtipage=999999999`. From the fork
the proof of work is Equihash 192,7 at minimum difficulty for the fork block; a CPU solves that
slowly, so the operators may instead point a GPU miner at yolo beside the node and run the
script with `--no-mine`, which only waits. Every wait counts blocks, never seconds.

### The record (`ycash-ceremony/1`)

Canonical JSON (sorted keys, two-space indent). The `release` object is what the rc compiles:

```json
"release": {
  "UPGRADE_YCASH.hashActivationBlock": "<the fork block>",
  "UPGRADE_VAULT.nActivationHeight": 510400,
  "attestorSetId": "<the SET_CREATE txid>",
  "checkpoint": "<height>:<hash>",
  "checkpointTime": 0, "checkpointChainTx": 0,
  "nMinimumChainWork": "<chain work at the checkpoint>",
  "houseSeats": 9
}
```

Beside it: `fork`, `heights`, `prefix`, `attestor_set` (txid, height, the exact `set_create`
parameters, members at maturity), `house_seats` (seat, member key, join txid and height — no
private key), `checkpoint` (height, hash, time, chain work, transaction count = the prefix's
717,489 plus every block after it) and `node` (the build's subversion).

## The rehearsal (testnet plan §3.2)

```bash
contrib/testnet/ceremony/ceremony rehearse --profile fast|slow|legacy --dir DIR --bitcoind src/ycashd
```

`DIR/ceremony-rehearsal.json` is the record (the same format, with a `rehearsal` object);
`DIR/work/` holds the nodes, `DIR/member-keys.json` the seats' public keys and `DIR/joins/` the
handoff files (no `DIR/secrets/`: the seat keys are born on node 2). Exit 0 means it passed. On regtest:

1. a harvest node mines the prefix (heights 0..50, `--prefix-height`);
2. `ycash-bootstrap --pack` bundles it in the `ycash-prefix/1` layout;
3. two operator nodes restore it with `ycash-bootstrap` and connect only to each other;
4. the ceremony runs on them: the fork block (51), the Vault height (fork + 152, fast's distance),
   the attestor set, the house seats (the profile's count: fast 9, slow 3) with their keys born on
   the second operator's node standing in for hosts a, b, c (`host-key`, the unsigned joins,
   `host-sign`, the re-run that sends them), maturity, record;
5. an rc1-like node restores the prefix, starts with `-yellowbackattestorset=<the recorded set>`
   (regtest's stand-in for the compiled set) and syncs the whole history: it must end on the same
   tip with the recorded fork and checkpoint hashes, the module governing the set
   (`vault_getinfo`), every house seat and exactly the hosts' member keys in `yed_listattestors`,
   and no key file on the ceremony host.

Where regtest differs: the set maturity is regtest's BOND_MATURITY (8), because the module adopts
a set only at exactly that maturity and no regtest flag changes it; the bond is regtest's (10 YEC);
the "fork block" is the first block after the prefix (regtest activates the Ycash upgrade at
height 1); `generate` replaces `setgenerate`. `legacy` rehearses the fork alone, without Vault.

## Tests

- `python3 -m unittest contrib/testnet/ceremony/test_ceremony.py` (offline): every step against a
  stand-in testnet node of each profile, the refusals (wrong profile, IBD, no peer, wrong prefix,
  an unfunded wallet), re-runs that never create a second set, the key files' modes, the
  `rehearse` entry point; the born-key path (nine keys on three hosts, the unsigned joins, a
  host refusing another host's seat, the sends) and the `--member-keys` refusals (a key twice,
  uneven hosts, an uncompressed key, the wrong count).
- `qa/rpc-tests/testnet_ceremony.py` (CI, needs `ycashd`): `rehearse --profile fast` and
  `--profile legacy` against real nodes.
