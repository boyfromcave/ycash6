#!/usr/bin/env bash
# Local mirror of the CI `audit` gates for the ycashd 6.20.0 port (plan §2):
# zero delta in the frozen set and the line budgets, both against the tag ycash6-baseline.
# Usage: qa/yellowback-audit.sh [base]   (base defaults to ycash6-baseline)
set -euo pipefail
cd "$(dirname "$0")/.."
base="${1:-ycash6-baseline}"
git rev-parse --verify -q "$base^{commit}" >/dev/null || { echo "missing $base (git fetch --tags)"; exit 2; }
frozen=$(grep -v '^#' qa/yellowback-frozen-files.txt | grep -v '^$')
if ! git diff --quiet "$base" -- $frozen; then
  echo "FROZEN SET CHANGED vs $base:"; git --no-pager diff --stat "$base" -- $frozen; exit 1
fi
echo "frozen set: zero delta vs $base"
rc=0
for f in src/main.cpp:40 src/miner.cpp:35 src/miner.h:10 src/rpc/mining.cpp:35 src/chainparams.cpp:4; do
  p=${f%%:*}; b=${f##*:}
  n=$(git diff --numstat "$base" -- "$p" | awk '{s+=$1+$2} END {print s+0}')
  printf '%-22s %3d changed lines (budget %d)\n' "$p" "$n" "$b"
  [ "$n" -le "$b" ] || rc=1
done
exit $rc
