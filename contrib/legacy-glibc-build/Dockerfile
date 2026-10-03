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
#   docker build -f contrib/legacy-glibc-build/Dockerfile -t ycash-legacy .
#   docker run --rm -v "$PWD/legacy-out:/out" ycash-legacy
# Binaries land in ./legacy-out/ and run on Ubuntu 18.04+.

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

WORKDIR /ycash
COPY . /ycash

# LEGACY_GLIBC=1 selects the Clang 18.1.8 ubuntu-18.04 toolchain in depends.
# -j is left to the runtime CMD so the image is reusable on any core count.
ENV LEGACY_GLIBC=1

CMD set -e; \
    LEGACY_GLIBC=1 ./zcutil/build.sh -j"$(nproc)"; \
    mkdir -p /out; \
    cp -v src/ycashd src/ycash-cli src/ycash-tx src/ycashd-wallet-tool /out/; \
    echo "=== glibc floor of produced binaries (must be <= 2.27 for 18.04) ==="; \
    objdump -T /out/ycashd 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -3
