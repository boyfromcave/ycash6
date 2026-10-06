#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# Release guard (hardening plan F-5, H-8): refuse a release while mainnet Yellowback is unset.
# Since the vault upgrade (upgrade plan U-22) YED starts at the UPGRADE_VAULT activation height
# (src/chainparams.cpp, the mainnet block) with the network's YED attestor set
# (src/yellowback/params.cpp, MainParams: attestorSetId); START_HEIGHT and ENFORCE_UNTIL_HEIGHT
# are retired. Both are set only by the release that passes the launch gates.
#
# Usage: qa/yellowback-release-heights.sh [--warn] [params.cpp] [chainparams.cpp]
#   exit 0 when the mainnet UPGRADE_VAULT height is a number and MainParams sets a non-zero
#   attestorSetId; exit 1 otherwise, or exit 0 with a warning under --warn (a proving run).
set -euo pipefail
warn=0
[ "${1:-}" = "--warn" ] && { warn=1; shift; }
file=${1:-src/yellowback/params.cpp}
chain=${2:-src/chainparams.cpp}
[ -f "$file" ] || { echo "no $file"; exit 1; }
[ -f "$chain" ] || { echo "no $chain"; exit 1; }

# The mainnet block of chainparams.cpp comes first; its UPGRADE_VAULT assignment may span two lines.
height=$(awk '/UPGRADE_VAULT\]\.nActivationHeight *=/{getline n; print $0 n; exit}' "$chain" \
         | sed -n 's/.*nActivationHeight *= *\([0-9][0-9]*\) *;.*/\1/p')
# The body of MainParams(): from its definition to the next function definition.
body=$(awk '/^const Params& MainParams\(\)/{on=1} on&&/^const Params& TestParams\(\)/{exit} on' "$file")
setid=$(printf '%s\n' "$body" | sed -n 's/.*m\.attestorSetId *= *uint256S("\([0-9a-fA-F]*\)").*/\1/p' | tail -1)
echo "mainnet Yellowback: UPGRADE_VAULT height ${height:-unset}, attestorSetId ${setid:-unset}"

problem=
if [ -z "$height" ]; then
  problem="the mainnet UPGRADE_VAULT activation height is unset: set it in the gate-passing release first"
elif [ -z "$setid" ] || [ -z "$(printf '%s' "$setid" | tr -d '0')" ]; then
  problem="the mainnet YED attestor set (MainParams attestorSetId) is unset"
fi
if [ -n "$problem" ]; then
  if [ "$warn" = 1 ]; then echo "warning: $problem (not a release: continuing)"; exit 0; fi
  echo "refusing to release: $problem (doc/yellowback-release.md, Network parameters)"
  exit 1
fi
echo "release heights: ok"
