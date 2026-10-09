# `contrib/docker/ycashd/` — the ycashd container image

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
| `YCASHD_RPC_USER`, `YCASHD_RPC_PASSWORD` | required | lightwalletd has no cookie auth |
| `YCASHD_RPC_PORT` | 8832 / 18832 | |
| `YCASHD_RPC_BIND`, `YCASHD_RPC_ALLOWIP` | `0.0.0.0`, RFC-1918 + loopback | space-separated list |
| `YCASHD_RPC_THREADS`, `YCASHD_RPC_WORKQUEUE` | 16, 64 | raise for a light-wallet backend |
| `YCASHD_INSIGHT` | 1 | `experimentalfeatures` + `insightexplorer` + `txindex` (needed by lightwalletd's address RPCs; set before first sync) |
| `YCASHD_LISTEN` | 1 | P2P listen |
| `YCASHD_VAULT_HEIGHT` | unset | regtest only: `nuparams=6d5b7a31:<h>` |
| `YCASHD_YELLOWBACK_ATTESTOR_SET` | unset | regtest only: `yellowbackattestorset=<setid>` |
| `YCASHD_CONF_EXTRA` | | extra `ycash.conf` lines, verbatim |
| `YCASHD_EXTRA_ARGS` | | extra command-line flags, verbatim |
| `YCASHD_CONF` | | use this mounted `ycash.conf` instead of generating one |
| `YCASHD_DATADIR` | `/var/lib/ycash` | the volume |

The image runs as uid 2001 and holds no wallet of any user. The deployment that scales this
(a node pool behind `lightwalletd-dd` on Kubernetes) is the `ycash-infra` repository.
