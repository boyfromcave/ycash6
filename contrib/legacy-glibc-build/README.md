# Legacy-glibc build (Ubuntu 18.04 / old distros)

Produces `ycashd` / `ycash-cli` / `ycash-tx` binaries that run on old Linux
systems (Ubuntu 18.04, glibc 2.27) for 3rd-party integrators still on legacy
distributions. The normal build targets a modern glibc and will not run there.

## Why two things are needed

A binary's minimum glibc is set by **two** independent factors:

1. **The glibc it links against** = the glibc of the *build host*. To target
   18.04 (glibc 2.27) you must build **on/in** an 18.04 environment. The
   compiler version does not change this.
2. **A toolchain whose binaries run on that old host.** The default fetched
   Clang 22 needs glibc 2.34 to even execute, so it cannot run inside 18.04.
   `LEGACY_GLIBC=1` switches `depends` to the official **Clang 18.1.8
   ubuntu-18.04** build (runs on glibc 2.27). Rust stays at the tree's pinned
   1.96 — its prebuilt binary already runs on glibc 2.17, so no change.

The Clang18 <-> Rust-LLVM22 version mismatch is harmless here: only
Rust-internal thin-LTO is used, not cross-language C++/Rust LTO.

## Recommended: Docker

```sh
docker build -f contrib/legacy-glibc-build/Dockerfile -t ycash-legacy \
    --build-arg BUILD_UID="$(id -u)" --build-arg BUILD_GID="$(id -g)" .
mkdir -p legacy-out
docker run --rm -v "$PWD/legacy-out:/out" ycash-legacy
```

Binaries land in `./legacy-out/`, owned by you. The build runs as the
unprivileged user `builder`; the two build args give it your uid/gid so it can
write the mounted directory (they default to 1000). The container prints the produced binary's
glibc floor at the end — it must be `<= 2.27` to run on 18.04.

## Manual (building directly on an 18.04 host/chroot)

```sh
LEGACY_GLIBC=1 ./zcutil/build.sh -j"$(nproc)"
```

Then verify the floor:

```sh
objdump -T src/ycashd | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sort -V | tail -3
```

All values must be `<= 2.27`. If any exceed it, you are not building on a
glibc-2.27 host — `LEGACY_GLIBC=1` alone (on a modern host) is **not** enough;
the build environment must itself be glibc 2.27.

## Caching note

`LEGACY_GLIBC` changes the fetched Clang version (18.1.8 vs 22.1.2), which
changes the depends build-id, so legacy and default toolchains stage into
separate `depends/built/` and `depends/work/` directories — they do not collide
and you can switch back and forth without a manual depends clean.

## Scope / limitations

- Supported legacy target: **x86_64 native** (build on an x86_64 18.04 host for
  x86_64). This is the only path needed for the typical pool/integrator case.
- `LEGACY_GLIBC` also gates the `native_clang` / `libcxx` **x86_64 Linux** cross
  download. An **aarch64-linux** legacy cross is NOT wired (the aarch64 lines
  still use the default Clang-22 naming); add an 18.04-equivalent aarch64 pin if
  that target is ever needed.
- Only `native_clang` + `libcxx` (which auto-tracks the clang version) change.
  Rust, boost, and the rest are version-unchanged.

## Default build is unaffected

Without `LEGACY_GLIBC=1`, everything is exactly as before: Clang 22, modern
glibc target. Verified: `make -n` resolves to Clang 22.1.2 by default and
18.1.8 only with `LEGACY_GLIBC=1`. This path is strictly opt-in.
