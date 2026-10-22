#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# Run the Semgrep scan the CI workflow runs (.github/workflows/semgrep.yml), on a laptop or in CI.
#
#   contrib/semgrep/scan.sh [--baseline <ref>] [--enforce] [--out <dir>]
#
#   --baseline <ref>  diff-aware: report only findings that are new versus <ref> (a PR's base)
#   --enforce         exit 1 when a bucket named in config.json "fail_on" has findings
#   --out <dir>       where results.json, results.sarif, findings.json and summary.md go
#                     (default: semgrep-out/, gitignored)
#
# Needs semgrep at exactly config.json "semgrep_version" on PATH, or docker (then the pinned image
# runs instead). The rules are semgrep/semgrep-rules at config.json "rules_commit", fetched once into
# $SEMGREP_RULES_CACHE (default ~/.cache/ycash-semgrep). Nothing is sent to semgrep.dev: no registry,
# no login, --metrics=off.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
CFG=contrib/semgrep/config.json
cfg() { python3 -c "import json,sys; v=json.load(open('$CFG'))[sys.argv[1]]; print(' '.join(v) if isinstance(v,list) else v)" "$1"; }

BASELINE= ENFORCE= OUT=semgrep-out
while [ $# -gt 0 ]; do
  case "$1" in
    --baseline) BASELINE=$2; shift 2 ;;
    --enforce) ENFORCE=--enforce; shift ;;
    --out) OUT=$2; shift 2 ;;
    -h|--help) sed -n '6,19p' "$0"; exit 0 ;;
    *) echo "scan.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done

VERSION=$(cfg semgrep_version)
COMMIT=$(cfg rules_commit)
RULES=${SEMGREP_RULES_CACHE:-$HOME/.cache/ycash-semgrep}/semgrep-rules-$COMMIT
if [ ! -d "$RULES" ]; then
  echo "scan.sh: fetching $(cfg rules_repo) at $COMMIT"
  tmp=$(mktemp -d)
  git -C "$tmp" init -q
  git -C "$tmp" fetch -q --depth 1 "$(cfg rules_repo)" "$COMMIT"
  git -C "$tmp" checkout -q FETCH_HEAD
  rm -rf "$tmp/.git"
  mkdir -p "$(dirname "$RULES")"
  mv "$tmp" "$RULES"
fi

configs=()
for p in $(cfg rule_paths); do configs+=(--config "$RULES/$p"); done
configs+=(--config "$(cfg local_rules)")
args=(scan --metrics=off --disable-version-check --error --jobs "$(nproc 2>/dev/null || echo 4)" --timeout 30
      --json --output "$OUT/results.json" --sarif-output="$OUT/results.sarif" "${configs[@]}")
[ -n "$BASELINE" ] && args+=(--baseline-commit "$(git rev-parse "$BASELINE")")

mkdir -p "$OUT"
if command -v semgrep >/dev/null && [ "$(semgrep --version 2>/dev/null)" = "$VERSION" ]; then
  semgrep_cmd=(semgrep)
elif command -v docker >/dev/null; then
  semgrep_cmd=(docker run --rm -v "$PWD:/src" -v "$RULES:$RULES:ro" -w /src "$(cfg semgrep_image)" semgrep)
else
  echo "scan.sh: need semgrep $VERSION (pip install semgrep==$VERSION) or docker" >&2
  exit 2
fi

# --error makes semgrep exit 1 on any finding; the buckets, not the raw count, decide (triage --enforce).
rc=0
"${semgrep_cmd[@]}" "${args[@]}" || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "scan.sh: semgrep failed ($rc)" >&2
  exit "$rc"
fi
python3 contrib/semgrep/triage.py triage --results "$OUT/results.json" --out "$OUT" --rules-root "$RULES" \
  ${BASELINE:+--baseline "$BASELINE"} $ENFORCE
