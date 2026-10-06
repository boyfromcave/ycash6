#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# Release guard (hardening plan F-5, H-8): refuse a release while the mainnet Yellowback heights in
# src/yellowback/params.cpp (MainParams) are unset. They are withdrawn on harden/yellowback and are
# set again only by the release that passes the launch gates (doc/yellowback-release.md).
#
# Usage: qa/yellowback-release-heights.sh [--warn] [params.cpp]
#   exit 0 when startHeight > 0 and enforceUntilHeight > startHeight (L8: one year later, or
#   earlier only for a scheduled network upgrade);
#   exit 1 otherwise, or exit 0 with a warning under --warn (a workflow_dispatch proving run).
set -euo pipefail
warn=0
[ "${1:-}" = "--warn" ] && { warn=1; shift; }
file=${1:-src/yellowback/params.cpp}
[ -f "$file" ] || { echo "no $file"; exit 1; }

# The body of MainParams(): from its definition to the next function definition.
body=$(awk '/^const Params& MainParams\(\)/{on=1} on&&/^const Params& TestParams\(\)/{exit} on' "$file")
start=$(printf '%s\n' "$body" | sed -n 's/^ *m\.startHeight *= *\([0-9][0-9]*\);.*/\1/p' | tail -1)
until=$(printf '%s\n' "$body" | sed -n 's/^ *m\.enforceUntilHeight *= *\([0-9][0-9]*\);.*/\1/p' | tail -1)
start=${start:-0}; until=${until:-0}
echo "mainnet Yellowback: startHeight $start, enforceUntilHeight $until"

problem=
if [ "$start" -le 0 ]; then
  problem="the mainnet START_HEIGHT is unset (0): set it in the gate-passing release first"
elif [ "$until" -le "$start" ]; then
  problem="the mainnet ENFORCE_UNTIL_HEIGHT ($until) is not above START_HEIGHT ($start)"
fi
if [ -n "$problem" ]; then
  if [ "$warn" = 1 ]; then echo "warning: $problem (not a release: continuing)"; exit 0; fi
  echo "refusing to release: $problem (doc/yellowback-release.md, Network parameters)"
  exit 1
fi
echo "release heights: ok"
