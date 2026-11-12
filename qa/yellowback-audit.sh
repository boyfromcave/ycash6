#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# Local mirror of the CI `audit` gates for the ycashd 6.20.0 port (plan §2): one script, so the gate a
# developer runs locally is the gate CI runs (the workflow's audit job calls it, leg by leg where a leg
# needs its own step). The legs:
#   frozen        zero delta in the frozen set and the line budgets, both against the base
#   pq-wipes      the wallet-side secret wipes in the vendored PQ C
#   ci-guards     --fail-on-skip on every rpc-tests.py run; the lockorder check's self-test
#   golden        golden-separate-commit (report-only)
#   rpc-cvt       every registered yed_* RPC has an exact-arity rpcCvtTable row (S1)
#   registration  every functional script the fork added is executable in git, registered and run by
#                 a CI job (and grouped in qa/kogany-mixed-shards.txt)
#
# Usage: qa/yellowback-audit.sh [--report-only] [--only LEG,..] [--skip LEG,..] [base]
#   base defaults to ycash6-baseline.
#   --report-only: the frozen-set and line-budget legs print their delta and never fail (the
#   upgrade/vault line, upgrade plan §7 G-9 / §9: the consensus review gate replaces them, and the
#   CI audit uploads the consensus-diff report for it); every other leg still fails.
# The functional-test lists are read from the workflow file itself (its top-level env).
# Never `cmd | grep -q` under pipefail: grep -q exits at the first match and SIGPIPEs cmd. Count with
# grep -c, or use a herestring.
# shellcheck disable=SC2086,SC2015,SC2317  # legs are called through leg(); A && B || C is meant
set -uo pipefail
cd "$(dirname "$0")/.."
report=0
only=""
skip=""
base=""
while [ $# -gt 0 ]; do
  case "$1" in
    --report-only) report=1; shift ;;
    --only) only="${2:-}"; shift 2 ;;
    --only=*) only="${1#--only=}"; shift ;;
    --skip) skip="${2:-}"; shift 2 ;;
    --skip=*) skip="${1#--skip=}"; shift ;;
    -h|--help) sed -n '6,24p' "$0"; exit 0 ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *) base="$1"; shift ;;
  esac
done
base="${base:-ycash6-baseline}"
LEGS="frozen pq-wipes ci-guards golden rpc-cvt registration"
for l in ${only//,/ } ${skip//,/ }; do
  case " $LEGS " in *" $l "*) ;; *) echo "unknown leg $l (one of: $LEGS)" >&2; exit 2 ;; esac
done
want() {
  if [ -n "$only" ] && [[ ",$only," != *",$1,"* ]]; then return 1; fi
  [[ ",$skip," != *",$1,"* ]]
}
in_ci() { [ "${GITHUB_ACTIONS:-}" = true ]; }
git rev-parse --verify -q "$base^{commit}" >/dev/null || { echo "missing $base (git fetch --tags)"; exit 2; }
py() { ../.venv/bin/python "$@" 2>/dev/null || python3 "$@"; }

wf=.github/workflows/yellowback-tests.yml
wfenv() { sed -n "s/^  $1: *//p" "$wf" | head -1 | sed 's/[[:space:]]*#.*$//'; }
YELLOWBACK_SCRIPTS=$(wfenv YELLOWBACK_SCRIPTS)
SANITIZER_SCRIPTS=$(wfenv SANITIZER_SCRIPTS)
NIGHTLY_SCRIPTS=$(wfenv NIGHTLY_SCRIPTS)
STOCK_BASELINE=$(wfenv STOCK_BASELINE)
STOCK_BASELINE_MINEBLOCK=$(wfenv STOCK_BASELINE_MINEBLOCK)

rc=0
leg() {   # leg <name> <function>: runs it unless --only/--skip leave it out; a failure sets rc
  want "$1" || return 0
  echo "=== $1"
  if ( set -e; "$2" ); then echo "PASS  $1"; else echo "FAIL  $1"; in_ci && echo "::error::audit leg failed: $1"; rc=1; fi
}

leg_frozen() {
  local frozen n p b f fail=0
  frozen=$(grep -v '^#' qa/yellowback-frozen-files.txt | grep -v '^$' | grep -vx 'configure.ac')
  if ! git diff --quiet "$base" -- $frozen; then
    echo "FROZEN SET CHANGED vs $base:"; git --no-pager diff --stat "$base" -- $frozen
    [ "$report" = 1 ] || return 1
    echo "(report only: the consensus review gate judges these lines)"
  fi
  # configure.ac is frozen except its version defines: a release (doc/yellowback-release.md) must
  # bump _CLIENT_VERSION_* there and in src/clientversion.h; any other configure.ac line fails.
  if [ "$(git diff -U0 "$base" -- configure.ac | grep -E '^[-+]' | grep -Ev '^(\+\+\+|---) (a\/|b\/|\/dev\/null)' | grep -Ecv '^[-+]define\(_CLIENT_VERSION_(MAJOR|MINOR|REVISION|BUILD), [0-9]+\)$')" -gt 0 ]; then
    echo "FROZEN SET CHANGED vs $base: configure.ac beyond the _CLIENT_VERSION_* defines"; git --no-pager diff "$base" -- configure.ac
    [ "$report" = 1 ] || return 1
  fi
  [ "$report" = 1 ] || echo "frozen set: zero delta vs $base (configure.ac: version defines only)"
  for f in src/main.cpp:40 src/miner.cpp:35 src/miner.h:10 src/rpc/mining.cpp:35 src/chainparams.cpp:4; do
    p=${f%%:*}; b=${f##*:}
    n=$(git diff --numstat "$base" -- "$p" | awk '{s+=$1+$2} END {print s+0}')
    printf '%-22s %3d changed lines (budget %d)\n' "$p" "$n" "$b"
    if [ "$n" -gt "$b" ]; then
      if [ "$report" = 1 ]; then echo "  over budget (report only)"; else fail=1; fi
    fi
  done
  return $fail
}

leg_pq_wipes() {
  # Wallet-side secret wipes in the vendored PQ C (audit 02/PQ-1, 02/PQ-2; src/crypto/pq/README.md "Local patches"
  # P3): the Falcon keygen/sign done: blocks wipe their SHAKE256 DRBG state, and every slh_var_t built from a secret
  # key in slh_dsa.c is wiped before its function returns (the same leg as ycash-dd's leg_pq_wipes).
  [ -d src/crypto/pq ] || { echo "no src/crypto/pq on this line"; return 0; }
  local fs=src/crypto/pq/falcon/ycash_falcon_sign.c sd=src/crypto/pq/slhdsa/slh_dsa.c nr nc nv ns
  nr=$(grep -c 'wipe(&rng, sizeof rng)' "$fs" || true); nc=$(grep -c 'wipe(&sc, sizeof sc)' "$fs" || true)
  nv=$(grep -c 'slh_wipe_var(&var);' "$sd" || true); ns=$(grep -c 'mk_var(&var, NULL, sk, prm)' "$sd" || true)
  echo "PQ wipes: $fs wipe(&rng) x$nr, wipe(&sc) x$nc (want 1 each); $sd slh_wipe_var(&var) x$nv (want $ns, >= 2)"
  if [ "$nr" != 1 ] || [ "$nc" != 1 ] || [ "$nv" -lt 2 ] || [ "$nv" != "$ns" ]; then echo "  PQ wipes missing"; return 1; fi
}

leg_ci_guards() {
  # Fail, never skip (audit 04/F-1, 04/N-4): every rpc-tests.py run in the workflow passes --fail-on-skip,
  # so a script that prints a line starting with SKIP fails CI instead of passing vacuously.
  local runs
  runs=$(grep -nE '^[[:space:]]*(\./)?qa/pull-tester/rpc-tests\.py' "$wf" || true)
  [ -n "$runs" ] || { echo "no rpc-tests.py run found in $wf"; return 1; }
  if [ "$(printf '%s\n' "$runs" | grep -cv -- '--fail-on-skip')" -gt 0 ]; then
    echo "rpc-tests.py runs without --fail-on-skip in $wf:"; printf '%s\n' "$runs" | grep -v -- '--fail-on-skip'; return 1
  fi
  # The lockorder check names the vault primitive's lock sites (audit 07/F-11): its self-test must pass.
  py qa/yellowback-lockorder-check.py --selftest
}

leg_golden() {
  # golden-separate-commit (doc/yellowback-testing.md, audit 03/T-1; report-only for one release cycle): a commit
  # that regenerates the YED golden vector touches nothing under src/yellowback/ and does not change yellowback_model.py.
  local gbase gbad="" gn=0 c files
  gbase=${YB_GOLDEN_BASE:-}
  if [ -z "$gbase" ]; then
    if git rev-parse --verify -q origin/upgrade/vault >/dev/null; then gbase=$(git merge-base origin/upgrade/vault HEAD); else gbase=$base; fi
  fi
  for c in $(git rev-list "$gbase..HEAD"); do
    files=$(git diff-tree --no-commit-id --name-only -r "$c")
    grep -qE '^(src/test/data|qa/rpc-tests/test_framework)/yellowback_golden\.json$' <<< "$files" || continue
    gn=$((gn + 1))
    if grep -qE '^src/yellowback/|^qa/rpc-tests/test_framework/yellowback_model\.py$' <<< "$files"; then
      gbad="$gbad
  $(git log -1 --format='%h %s' "$c")"
    fi
  done
  echo "golden-separate-commit: $gn golden regeneration commit(s) in $(git rev-parse --short "$gbase")..HEAD"
  [ -z "$gbad" ] || echo "REPORT golden-separate-commit (non-gating): regenerated with a rule or model change:$gbad"
  return 0
}

leg_rpc_cvt() {
  # S1: every registered yed_* RPC has an exact-arity rpcCvtTable row (the server rejects it otherwise)
  py qa/yellowback-rpc-cvt.py --check
}

# Fork-added functional scripts that rpc-tests.py never runs, deliberately (beta2 list items 59, 69).
# One name per line with its reason; anything not named here that the fork added under qa/rpc-tests/
# must be executable, registered and run by a CI job.
REGISTRATION_EXCLUDE=$(sed 's/[[:space:]]*#.*$//' <<'EOF_EXCLUDE' | grep -v '^$' || true
kogany_mixed_smoke     # run directly (python3 -u), not through rpc-tests.py: the `direct` row of the mixed node group
kogany_sidecar_smoke   # run directly by the sidecar-rig job ("The test rig smoke")
kogany_standin         # not a test: the stand-in koganyd for testing the mixed-line harness (KOGANY_BIN)
kogany_pruned_edge     # by hand only: needs a pruned koganyd (KOGANY_PRUNED=1); kogany pruning assessment KP-2
EOF_EXCLUDE
)

# Every functional script the fork owns: each top-level qa/rpc-tests/*.py added relative to the base
# (including what is staged, modified or untracked in the working tree), plus the yellowback_*/vault_*
# prefixes, minus REGISTRATION_EXCLUDE. Derived mechanically, so a wallet_*.py or any other new name is covered.
fork_scripts() {
  { git diff --no-renames --name-only --diff-filter=A "$(git merge-base "$base" HEAD)" -- qa/rpc-tests
    git ls-files --others --exclude-standard -- qa/rpc-tests
    git ls-files -- 'qa/rpc-tests/yellowback_*.py' 'qa/rpc-tests/vault_*.py'
  } | { grep -E '^qa/rpc-tests/[^/]+\.py$' || true; } | sort -u | while read -r f; do
    [ -e "$f" ] || continue
    grep -qx -- "$(basename "$f" .py)" <<< "$REGISTRATION_EXCLUDE" && continue
    echo "$f"
  done
}

leg_registration() {
  # rpc-tests.py exec's a script directly, so it must be executable IN GIT (a checkout takes the mode from
  # the index), and it must be run by some job: registered-but-never-run is how the v2 enforcement suite,
  # the v3 attestation suite and then wallet_yed_held_guard sat silent in CI.
  [ -n "$YELLOWBACK_SCRIPTS" ] && [ -n "$STOCK_BASELINE" ] && [ -n "$NIGHTLY_SCRIPTS" ] || {
    echo "could not read YELLOWBACK_SCRIPTS / STOCK_BASELINE / NIGHTLY_SCRIPTS from $wf"; return 1; }
  local f n mode bad="" count=0 x
  for x in $REGISTRATION_EXCLUDE; do
    [ -e "qa/rpc-tests/$x.py" ] || { echo "REGISTRATION_EXCLUDE names $x, which is not in qa/rpc-tests/"; return 1; }
  done
  while read -r f; do
    count=$((count + 1))
    n=$(basename "$f" .py)
    mode=$(git ls-files -s -- "$f" | cut -d' ' -f1)
    [ "$mode" = 100755 ] || bad="$bad
  $f is mode ${mode:-untracked} in git, not 100755 (chmod +x it, then git add it)"
    grep -qE "[\"']$n\.py[\"']" qa/pull-tester/rpc-tests.py || bad="$bad
  $n is not registered in qa/pull-tester/rpc-tests.py"
    case " $YELLOWBACK_SCRIPTS $SANITIZER_SCRIPTS $NIGHTLY_SCRIPTS $STOCK_BASELINE " in
      *" $n "*) ;;
      *) bad="$bad
  $n is in qa/rpc-tests/ but no CI job runs it (add it to YELLOWBACK_SCRIPTS or NIGHTLY_SCRIPTS in $wf, or to REGISTRATION_EXCLUDE with the reason)" ;;
    esac
  done < <(fork_scripts)
  echo "fork-owned functional scripts checked: $count (excluded by name: $(wc -w <<< "$REGISTRATION_EXCLUDE" | tr -d ' '))"
  [ -z "$bad" ] || { echo "$bad"; return 1; }
  # rpc-tests.py silently drops a named script it does not list (ALL_SCRIPTS filter), so every name a job
  # passes it must be registered there. Either quote: ZMQ_SCRIPTS registers zmq_test with double quotes.
  for n in $YELLOWBACK_SCRIPTS $SANITIZER_SCRIPTS $STOCK_BASELINE $NIGHTLY_SCRIPTS; do
    [ -f "qa/rpc-tests/$n.py" ] || { echo "$n is in a CI list but qa/rpc-tests/$n.py does not exist"; return 1; }
    grep -qE "[\"']$n\.py[\"']" qa/pull-tester/rpc-tests.py || { echo "$n is in a CI list but not in qa/pull-tester/rpc-tests.py"; return 1; }
  done
  grep -qF "'$STOCK_BASELINE_MINEBLOCK'" qa/pull-tester/rpc-tests.py || { echo "$STOCK_BASELINE_MINEBLOCK is not in qa/pull-tester/rpc-tests.py"; return 1; }
  # Every YELLOWBACK_SCRIPTS entry has its rows in the mixed shard manifest (a group or excluded; the
  # sidecar and pair rows the rig needs): the manifest's own check.
  py qa/kogany_mixed_shards.py check
}

leg frozen leg_frozen
leg pq-wipes leg_pq_wipes
leg ci-guards leg_ci_guards
leg golden leg_golden
leg rpc-cvt leg_rpc_cvt
leg registration leg_registration
exit $rc
