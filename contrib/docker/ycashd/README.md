# `contrib/docker/ycashd/` — the ycashd container image

<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

```bash
docker build -f contrib/docker/ycashd/Dockerfile -t ycash/ycashd:local .      # 1-2 h the first time
docker compose -f contrib/docker/ycashd/docker-compose.regtest.yml up -d       # a regtest node, vault upgrade from height 1
docker compose -f contrib/docker/ycashd/docker-compose.regtest.yml exec ycashd ycash-cli -datadir=/var/lib/ycash generate 10
```

`entrypoint.sh` writes `ycash.conf` into the datadir from the environment and execs `ycashd`.
Variables (unset = default):

| Variable | Default | Meaning |
|---|---|---|
| `YCASHD_NETWORK` | `mainnet` | `mainnet` / `testnet` / `regtest` |
| `YCASHD_TESTNET_PROFILE` | required with `testnet` | `fast` / `slow` / `legacy`: which of the three testnets (`testnetprofile=`; testnet plan Revision 3) |
| `YCASHD_RPC_USER`, `YCASHD_RPC_PASSWORD` | required | lightwalletd has no cookie auth |
| `YCASHD_RPC_PORT` | 8832; testnet fast 18832, slow 18932, legacy 19032 | |
| `YCASHD_RPC_BIND`, `YCASHD_RPC_ALLOWIP` | `0.0.0.0`, RFC-1918 + loopback | space-separated list |
| `YCASHD_RPC_THREADS`, `YCASHD_RPC_WORKQUEUE` | 16, 64 | raise for a light-wallet backend |
| `YCASHD_INSIGHT` | 1 | `experimentalfeatures` + `insightexplorer` + `txindex` (needed by lightwalletd's address RPCs; set before first sync) |
| `YCASHD_LISTEN` | 1 | P2P listen |
| `YCASHD_VAULT_HEIGHT` | unset | regtest only: `nuparams=6d5b7a31:<h>`, plus Overwinter, Sapling, Ycash, Blossom, Heartwood and Canopy (`5ba81b19 76b809bb 374d694f 8e471bd6 66314da3 19bd2d2f`) at `min(1, h)`: Vault needs Sapling active at or below its height (quantum spec R-A3), or ycashd refuses to start |
| `YCASHD_YELLOWBACK_ATTESTOR_SET` | unset | regtest only: `yellowbackattestorset=<setid>` |
| `YCASHD_PQ_FALCON_HEIGHT` | `0` | regtest only: `pqfalconheight=<h>`, OP_CHECKPQSIG scheme 0x02 (FN-DSA-512) from `<h>` once the vault upgrade is active. `0` mirrors mainnet/testnet (Falcon from the vault activation, D-Q-2); `off` = SLH-DSA only |
| `YCASHD_PQ_FEERATE` | unset (= the relay floor) | `pqfeerate=<YEC/kB>`, the wallet's fallback fee rate for a post-quantum input |
| `YCASHD_MNEMONIC_FILE` | unset | path of a **mounted** secret file, passed as `-mnemonicfile=<path>` (a new wallet takes its seed from the recovery phrase in the file) |
| `YCASHD_BOOTSTRAP` | unset | before the first start, restore a checkpoint bundle into the empty datadir with `ycash-bootstrap` (testnet plan §4.4): `prefix` = the network's pinned prefix release (`testnet-prefix-v1`), or a bundle URL or directory. Testnet (with `YCASHD_TESTNET_PROFILE`) or regtest only. Skipped when the network's `blocks/` already holds data; a failed restore stops the container before `ycashd` starts |
| `YCASHD_BOOTSTRAP_ARGS` | unset | extra `ycash-bootstrap` flags, e.g. `--require-signature` or `--verify-full` (`contrib/bootstrap/README.md`) |
| `YCASHD_CONF_EXTRA` | | extra `ycash.conf` lines, verbatim |
| `YCASHD_EXTRA_ARGS` | | extra command-line flags, verbatim |
| `YCASHD_CONF` | | use this mounted `ycash.conf` instead of generating one |
| `YCASHD_DATADIR` | `/var/lib/ycash` | the volume |

The image runs as uid 2001 and holds no wallet of any user. The deployment that scales this
(a node pool behind `lightwalletd-dd` on Kubernetes) is the `ycash-infra` repository.

## The post-quantum line

This image builds the post-quantum vault line (`OP_CHECKPQSIG` 0xc2, SLH-DSA-SHA2-128s owners,
FN-DSA-512 holders). The PQ code is vendored C under `src/crypto/pq/` (slhdsa-c, PQClean
`falcon-padded-512/clean`), compiled by the ordinary autotools build: the image needs no extra
package, Rust crate or configure flag for it. `yed_getinfo` reports `rpcversion` 8 (a compiled
constant; nothing in `ycash.conf` selects it, and YED RPCs answer only once an attestor set is
configured). `-pqfalcon` / `-pqfalconheight` are refused off regtest, so the entrypoint writes
`pqfalconheight` only for `YCASHD_NETWORK=regtest`.

## Secrets: seed-only restore

A wallet seed never goes into the image, an environment variable, `ycash.conf` or the command
line. Mount it as a file and point `YCASHD_MNEMONIC_FILE` at the path; the entrypoint checks the file is readable
and passes `-mnemonicfile=<path>` (the path, not the secret). The flag acts only when the wallet is
created (a new datadir), so the mount can be dropped after the first start.

```bash
docker run -d --name ycashd -v ycashd_data:/var/lib/ycash \
  -v "$PWD/seed.txt:/run/secrets/ycash-mnemonic:ro" -e YCASHD_MNEMONIC_FILE=/run/secrets/ycash-mnemonic \
  -e YCASHD_RPC_USER=ycash -e YCASHD_RPC_PASSWORD=... ycash/ycashd:local
```

On Kubernetes, mount a `Secret` volume (`defaultMode: 0400`, pod `fsGroup: 2001`): the image runs
as uid 2001, which must be able to read the file.

## Fast start from a bundle (`YCASHD_BOOTSTRAP`)

In plain words: a new testnet node would otherwise download half a million old blocks from its
peers. With `YCASHD_BOOTSTRAP=prefix` it instead downloads one published, fingerprinted copy of
them, checks every fingerprint (and the owner's signature once the copy is signed), loads it
without talking to anyone, and only then starts normally.

```bash
docker run -d --name ycashd-fast -v ycashd_fast:/var/lib/ycash -e YCASHD_NETWORK=testnet -e YCASHD_TESTNET_PROFILE=fast \
  -e YCASHD_BOOTSTRAP=prefix -e YCASHD_RPC_USER=ycash -e YCASHD_RPC_PASSWORD=... ycash/ycashd:local
```

The entrypoint runs `ycash-bootstrap --network <net> --datadir /var/lib/ycash --conf <the generated
ycash.conf> --source "$YCASHD_BOOTSTRAP"` once, before `ycashd`; `contrib/bootstrap/README.md`
lists its checks. The image carries `python3` and `minisign` for it.

## Health

The image's `HEALTHCHECK` runs `ycash-cli getblockchaininfo` every 60 s (30 s timeout, three failures
to unhealthy, a 30-minute start period for the block-index load of a mainnet datadir). It reads the
same `ycash.conf` as ycashd (`YCASHD_CONF`, else `$YCASHD_DATADIR/ycash.conf`) and connects on
loopback, so it needs no extra setting; a syncing node reports healthy. Docker only reports the
status. A Compose file can override it (`docker-compose.regtest.yml` polls every 5 s), and Kubernetes
ignores it in favour of the pod's probes.
