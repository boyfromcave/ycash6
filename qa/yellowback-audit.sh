#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# Local mirror of the CI `audit` gates for the ycashd 6.20.0 port (plan §2):
# zero delta in the frozen set and the line budgets, both against the tag ycash6-baseline.
# Usage: qa/yellowback-audit.sh [--report-only] [base]   (base defaults to ycash6-baseline)
#   --report-only: the frozen-set and line-budget legs print their delta and never fail (the
#   upgrade/vault line, upgrade plan §7 G-9 / §9: the consensus review gate replaces them, and the
#   CI audit uploads the consensus-diff report for it); the rpcCvtTable leg (S1) still fails.
set -euo pipefail
cd "$(dirname "$0")/.."
report=0
[ "${1:-}" = "--report-only" ] && { report=1; shift; }
base="${1:-ycash6-baseline}"
git rev-parse --verify -q "$base^{commit}" >/dev/null || { echo "missing $base (git fetch --tags)"; exit 2; }
frozen=$(grep -v '^#' qa/yellowback-frozen-files.txt | grep -v '^$' | grep -vx 'configure.ac')
if ! git diff --quiet "$base" -- $frozen; then
  echo "FROZEN SET CHANGED vs $base:"; git --no-pager diff --stat "$base" -- $frozen
  [ "$report" = 1 ] || exit 1
  echo "(report only: the consensus review gate judges these lines)"
fi
# configure.ac is frozen except its version defines: a release (doc/yellowback-release.md) must
# bump _CLIENT_VERSION_* there and in src/clientversion.h; any other configure.ac line fails.
if git diff -U0 "$base" -- configure.ac | grep -E '^[-+]' | grep -Ev '^(\+\+\+|---) (a\/|b\/|\/dev\/null)' | grep -Eqv '^[-+]define\(_CLIENT_VERSION_(MAJOR|MINOR|REVISION|BUILD), [0-9]+\)$'; then
  echo "FROZEN SET CHANGED vs $base: configure.ac beyond the _CLIENT_VERSION_* defines"; git --no-pager diff "$base" -- configure.ac
  [ "$report" = 1 ] || exit 1
fi
[ "$report" = 1 ] || echo "frozen set: zero delta vs $base (configure.ac: version defines only)"
rc=0
for f in src/main.cpp:40 src/miner.cpp:35 src/miner.h:10 src/rpc/mining.cpp:35 src/chainparams.cpp:4; do
  p=${f%%:*}; b=${f##*:}
  n=$(git diff --numstat "$base" -- "$p" | awk '{s+=$1+$2} END {print s+0}')
  printf '%-22s %3d changed lines (budget %d)\n' "$p" "$n" "$b"
  if [ "$n" -gt "$b" ]; then
    if [ "$report" = 1 ]; then echo "  over budget (report only)"; else rc=1; fi
  fi
done
# S1: every registered yed_* RPC has an exact-arity rpcCvtTable row (the server rejects it otherwise)
../.venv/bin/python qa/yellowback-rpc-cvt.py --check 2>/dev/null || python3 qa/yellowback-rpc-cvt.py --check || rc=1
exit $rc
