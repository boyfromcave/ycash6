# Legacy-glibc build: produce ycashd/ycash-cli/ycash-tx binaries that run on
# old Linux distributions (Ubuntu 18.04, glibc 2.27) for 3rd-party integrators
# still on legacy systems.
#
# The binary's glibc floor is set by the BUILD HOST's glibc, so we build inside
# an 18.04 image (glibc 2.27). LEGACY_GLIBC=1 makes depends fetch the Clang
# 18.1.8 ubuntu-18.04 toolchain (which runs on glibc 2.27); the default Clang 22
# requires glibc 2.34 to run and 2.38 to target, so it cannot be used here.
# Rust stays at the tree's pinned 1.96 (its binary runs on glibc 2.17).
#
# Build:
#   docker build -f contrib/legacy-glibc-build/Dockerfile -t ycash-legacy \
#       --build-arg BUILD_UID="$(id -u)" --build-arg BUILD_GID="$(id -g)" .
#   mkdir -p legacy-out
#   docker run --rm -v "$PWD/legacy-out:/out" ycash-legacy
# Binaries land in ./legacy-out/ and run on Ubuntu 18.04+. The build runs as the
# unprivileged user `builder`, whose uid/gid default to 1000 and are set to the
# caller's by the build args above so it can write the mounted ./legacy-out/.

# checkov:skip=CKV_DOCKER_2:A throwaway build container (docker run --rm, produces binaries); it runs no service
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# Build dependencies (mirrors contrib/debian/control Build-Depends; depends/
# fetches its own clang + rust, so the host needs only base tooling + fetchers).
RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake bsdmainutils build-essential ca-certificates \
        curl git g++-multilib libc6-dev libtool m4 ncurses-dev \
        pkg-config python3 unzip wget zlib1g-dev xz-utils g++-8 \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python

# depends compiles its native host tools with the plain gcc/g++. 18.04's GCC 7.5
# has no std::filesystem, which native_ccache 4.12 requires, so make GCC 8 (from
# the 18.04 archive) the default. Host tools only: the shipped binaries are built
# with depends' clang + libc++, and the glibc floor is still the image's 2.27.
RUN ln -sf gcc-8 /usr/bin/gcc && ln -sf g++-8 /usr/bin/g++ && g++ --version | head -1

# The build itself needs no root: run it as an unprivileged user that owns the
# source tree (depends/ and src/ are written in place) and the /out directory.
ARG BUILD_UID=1000
ARG BUILD_GID=1000
RUN groupadd -o -g "$BUILD_GID" builder \
    && useradd -o -m -u "$BUILD_UID" -g "$BUILD_GID" -s /bin/sh builder \
    && mkdir -p /ycash /out && chown builder:builder /ycash /out

WORKDIR /ycash
COPY --chown=builder:builder . /ycash
USER builder

# LEGACY_GLIBC=1 selects the Clang 18.1.8 ubuntu-18.04 toolchain in depends.
# -j is left to the runtime CMD so the image is reusable on any core count.
ENV LEGACY_GLIBC=1

CMD set -e; \
    LEGACY_GLIBC=1 ./zcutil/build.sh -j"$(nproc)"; \
    mkdir -p /out; \
    cp -v src/ycashd src/ycash-cli src/ycash-tx src/ycashd-wallet-tool /out/; \
    echo "=== glibc floor of produced binaries (must be <= 2.27 for 18.04) ==="; \
    objdump -T /out/ycashd 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -3
