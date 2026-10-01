#!/usr/bin/env bash
# Generate the cxx bridge headers (src/Makefile.am CXXBRIDGE_H) in a configured tree, so a
# target-only `make -C src ycashd test/test_bitcoin` works on a fresh checkout.
#
# 6.20.0 lists them in BUILT_SOURCES (src/Makefile.am, `BUILT_SOURCES = $(CXXBRIDGE_H)`), and
# automake honours BUILT_SOURCES only for `make all`, `check` and `install`, never for an explicit
# target. A fresh configure followed by `make -C src ycashd` therefore dies on the first
# `#include "rust/..."`. v4.5.0 had no generated headers, so the CI variant jobs (lockorder,
# sanitizers, coverage, weekly-fuzz) and the nightly's stock build never needed this step.
# `make -C src clean` does not remove the headers (they are not in CLEANFILES), so it is needed
# once per fresh tree, not after a clean.
#
# Usage: qa/yellowback-cxxbridge-headers.sh [repo-root] [make args...]
set -euo pipefail
root="${1:-.}"; shift || true
hdrs=$(awk '/^CXXBRIDGE_H = /{f=1;next} f&&/^ *rust\/gen/{gsub(/[ \\]/,"");print;next} f{exit}' "$root/src/Makefile.am")
test -n "$hdrs" || { echo "no CXXBRIDGE_H list in $root/src/Makefile.am" >&2; exit 1; }
# shellcheck disable=SC2086
make -C "$root/src" "$@" $hdrs
