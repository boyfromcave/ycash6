# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# The official ycashd image, built from this tree. Build context = the repository root:
#   docker build -f contrib/docker/ycashd/Dockerfile -t ycash/ycashd:local .
# Stage 1 (ubuntu 22.04, the release matrix's tier-1 native host) runs zcutil/build.sh with the
# depends system; depends/built, depends/sources, ccache and the cargo registry live in BuildKit
# cache mounts, so the first build is 1-2 h on a laptop and a rebuild after a source change is
# minutes. Stage 2 carries only the three binaries. ycashd 6.x embeds the Sapling parameters
# (zcutil/fetch-params.sh only fetches the optional Sprout file), so nothing else is needed.
# Runs as uid 2001 with the datadir at /var/lib/ycash; contrib/docker/ycashd/entrypoint.sh
# turns YCASHD_* environment variables into ycash.conf (README.md there).
FROM ubuntu:22.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config libc6-dev m4 autoconf libtool libncurses-dev unzip git \
      python3 python3-zmq zlib1g-dev curl bsdmainutils automake libtinfo5 ccache ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
ARG JOBS=4
ENV CCACHE_DIR=/root/.cache/ccache
RUN --mount=type=cache,id=ycash6-depends-built,target=/src/depends/built \
    --mount=type=cache,id=ycash6-depends-sources,target=/src/depends/sources \
    --mount=type=cache,id=ycash6-ccache,target=/root/.cache/ccache \
    --mount=type=cache,id=ycash6-cargo,target=/root/.cargo/registry \
    ./zcutil/build.sh -j${JOBS} \
 && mkdir -p /out && cp src/ycashd src/ycash-cli src/ycash-tx /out/ && strip /out/*

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libtinfo5 curl jq netcat-openbsd \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --home-dir /srv/ycash --create-home --uid 2001 --shell /bin/sh ycash \
 && mkdir -p /var/lib/ycash && chown -R ycash:ycash /srv/ycash /var/lib/ycash
COPY --from=builder /out/ycashd /out/ycash-cli /out/ycash-tx /usr/local/bin/
COPY contrib/docker/ycashd/entrypoint.sh /usr/local/bin/ycashd-entrypoint
RUN chmod +x /usr/local/bin/ycashd-entrypoint
USER ycash
ENV HOME=/srv/ycash
VOLUME ["/var/lib/ycash"]
EXPOSE 8832 8833 18832 18833
# Liveness: the RPC server answers getblockchaininfo. It answers while the node syncs, so a syncing
# node is healthy; it errors (-28) while the block index loads, which the start period covers on a
# mainnet datadir. ycash-cli takes its credentials and port from the same ycash.conf the entrypoint
# wrote (or the mounted YCASHD_CONF; with no rpcpassword there, the datadir's .cookie), so nothing
# secret is on a command line, and reaches ycashd on loopback, which ycashd always allows. Docker
# only reports the status; Kubernetes ignores it and uses its own probes (ycash-infra).
HEALTHCHECK --interval=60s --timeout=30s --start-period=30m --retries=3 \
  CMD d="${YCASHD_DATADIR:-/var/lib/ycash}"; \
      ycash-cli -datadir="$d" -conf="${YCASHD_CONF:-$d/ycash.conf}" -rpcclienttimeout=25 getblockchaininfo >/dev/null || exit 1
ENTRYPOINT ["ycashd-entrypoint"]
