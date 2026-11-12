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
#   attribution   The Ycash developers on every fork file and every modified upstream file with a
#                 copyright line, no copyright line removed, no ycash6/YDollar/DigiDollar naming
#   secops        the RustSec ignores of osv-scanner.toml and contrib/secops/deny-node.toml agree
#   cross-line    the other node line: the manifest, the overlay trees and the Vault chain parameters
#
# Usage: qa/yellowback-audit.sh [--report-only] [--only LEG,..] [--skip LEG,..] [--require-cross-line] [base]
#   base defaults to ycash6-baseline.
#   --report-only: the frozen-set and line-budget legs print their delta and never fail (the
#   upgrade/vault line, upgrade plan §7 G-9 / §9: the consensus review gate replaces them, and the
#   CI audit uploads the consensus-diff report for it); every other leg still fails.
#   --require-cross-line: the cross-line leg fails instead of printing NOT CHECKED.
# The other line for the cross-line leg (the same rules as ycash-dd's audit):
#   YB_OTHER_LINE_REF    a ref in THIS repository holding ycash-dd (CI fetches it into one)
#   YB_OTHER_LINE_DIR + YB_OTHER_LINE_REV   or another local repository and a revision in it
#   neither set: the ycash-dd checkout at the conventional sibling path (../ycash-dd beside the main
#   tree, ../up-<suffix> beside a wt/up6-<suffix> worktree), at the branch of this checkout's name
#   unless it is merged already, else upgrade/vault (qa/yellowback-other-line-branch.py decides and
#   says why). NOT CHECKED only when nothing is found.
# The functional-test lists are read from the workflow file itself (its top-level env).
# Never `cmd | grep -q` under pipefail: grep -q exits at the first match and SIGPIPEs cmd. Count with
# grep -c, or use a herestring.
# shellcheck disable=SC2086,SC2015,SC2317  # legs are called through leg(); A && B || C is meant
set -uo pipefail
cd "$(dirname "$0")/.."
report=0
only=""
skip=""
require_cross_line=0
base=""
while [ $# -gt 0 ]; do
  case "$1" in
    --report-only) report=1; shift ;;
    --only) only="${2:-}"; shift 2 ;;
    --only=*) only="${1#--only=}"; shift ;;
    --skip) skip="${2:-}"; shift 2 ;;
    --skip=*) skip="${1#--skip=}"; shift ;;
    --require-cross-line) require_cross_line=1; shift ;;
    -h|--help) sed -n '6,35p' "$0"; exit 0 ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *) base="$1"; shift ;;
  esac
done
base="${base:-ycash6-baseline}"
LEGS="frozen pq-wipes ci-guards golden rpc-cvt registration attribution secops cross-line"
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

# Upstream wallet scripts that no CI list runs, and why (beta2 list item 59). The registration leg
# checks each still exists and is still in no CI list, so the list cannot go stale silently.
UPSTREAM_NOT_RUN=$(sed 's/[[:space:]]*#.*$//' <<'EOF_UPSTREAM' | grep -v '^$' || true
wallet_accounts        # Zcash NU5 unified accounts: Ycash refuses z_getnewaccount ("require the NU5 network upgrade, which is not active on Ycash")
wallet_addresses       # unified and Orchard addresses throughout (NU5 at height 2); Orchard is not part of Ycash
wallet_listreceived    # Orchard and unified receivers (NU5 at height 225)
wallet_import_export   # walletconfirmbackup's optional acknowledge_imports has no rpcCvtTable column ({{s}, {}} in src/rpc/common.h), so the call is refused; node defect, reported
show_help              # its expected text is upstream zcashd's --help; it needs a Ycash expected text
EOF_UPSTREAM
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
  for x in $UPSTREAM_NOT_RUN; do
    [ -e "qa/rpc-tests/$x.py" ] || { echo "UPSTREAM_NOT_RUN names $x, which is not in qa/rpc-tests/"; return 1; }
    case " $YELLOWBACK_SCRIPTS $SANITIZER_SCRIPTS $NIGHTLY_SCRIPTS $STOCK_BASELINE " in
      *" $x "*) echo "UPSTREAM_NOT_RUN names $x, which a CI list now runs: drop it from UPSTREAM_NOT_RUN"; return 1 ;;
    esac
  done
  grep -qF "'$STOCK_BASELINE_MINEBLOCK'" qa/pull-tester/rpc-tests.py || { echo "$STOCK_BASELINE_MINEBLOCK is not in qa/pull-tester/rpc-tests.py"; return 1; }
  # Every YELLOWBACK_SCRIPTS entry has its rows in the mixed shard manifest (a group or excluded; the
  # sidecar and pair rows the rig needs): the manifest's own check.
  py qa/kogany_mixed_shards.py check
}

leg_attribution() {
  # Attribution (rule 2026-10-01): every file the fork adds carries "The Ycash developers"; an upstream
  # file the fork modifies that has a copyright block carries a Ycash line too; no existing copyright
  # line is ever removed. Naming: the software is Ycash (no "ycash6" in src/), and no DigiDollar/ydollar
  # naming enters the code (AGENTS.md rule 6; in code DigiDollar is allowed only in comments that cite
  # the upstream file). Moved here from the workflow's audit step (beta2 list item 73), unchanged in
  # what it checks; -a where grep reads the diff stream (a NUL in it made GNU grep print "binary file
  # matches" and hide the lines).
  local fail=0 vendored d f removed hits added
  # Vendored third-party code (the quantum line's src/crypto/pq/falcon and src/crypto/pq/slhdsa,
  # briefing rule 7) keeps its own notices unchanged and is exempt from the added-file rule,
  # provided src/crypto/pq/README.md records each one's LICENSE (ycash-dd 877e49617).
  vendored='^src/crypto/pq/(falcon|slhdsa)/'
  if [ "$(git diff --name-only --diff-filter=A "$base" HEAD -- src | grep -cE "$vendored")" -gt 0 ]; then
    for d in falcon slhdsa; do
      grep -q "$d/LICENSE" src/crypto/pq/README.md 2>/dev/null || { echo "vendored src/crypto/pq/$d without a licence record ($d/LICENSE) in src/crypto/pq/README.md"; fail=1; }
    done
    echo "vendored files exempt from the added-file rule (own notices): $(git diff --name-only --diff-filter=A "$base" HEAD -- src | grep -cE "$vendored") under src/crypto/pq/{falcon,slhdsa}/"
  fi
  while read -r f; do
    grep -q 'The Ycash developers' "$f" || { echo "new file without the Ycash notice: $f"; fail=1; }
  done < <(git diff --name-only --diff-filter=A "$base" HEAD -- src qa contrib | grep -E '\.(cpp|h|c|py|sh|rs)$' | grep -v '^src/fuzzing/' | grep -Ev "$vendored")
  while read -r f; do
    if grep -q 'Copyright' "$f" && ! grep -q 'Ycash developers' "$f"; then echo "modified upstream file without a Ycash line: $f"; fail=1; fi
  done < <(git diff --name-only --diff-filter=M "$base" HEAD -- src qa contrib | grep -E '\.(cpp|h|c|py|sh|rs)$')
  removed=$(git diff "$base" HEAD | grep -aE '^-[^-].*Copyright' || true)
  [ -z "$removed" ] || { echo "copyright lines removed (never allowed):"; echo "$removed"; fail=1; }
  hits=$(git grep -n -i 'ycash6' -- src || true)
  [ -z "$hits" ] || { echo "'ycash6' in src/ (the software is Ycash):"; echo "$hits"; fail=1; }
  # This file names the patterns it looks for, so its own lines are not read as hits.
  added=$(git diff "$base" HEAD -- src qa contrib doc ':!qa/yellowback-audit.sh' | grep -aE '^\+[^+]' || true)
  hits=$(printf '%s\n' "$added" | grep -aE 'ydollar|YDollar|\byd_' || true)
  [ -z "$hits" ] || { echo "retired YDollar naming:"; echo "$hits"; fail=1; }
  # Code only (doc/ prose may name the retired `feature/digidollar` branch).
  hits=$(git diff "$base" HEAD -- src qa contrib ':!qa/yellowback-audit.sh' | grep -aE '^\+[^+]' | grep -aEi 'digidollar' | grep -avE '^\+[[:space:]]*(//|#|\*|/\*)' || true)
  [ -z "$hits" ] || { echo "DigiDollar naming outside a citing comment:"; echo "$hits"; fail=1; }
  return $fail
}

# RustSec IDs accepted in osv-scanner.toml that cargo-deny never sees, one per line with the reason
# (SECURITY-CI.md: every other RustSec ID accepted there is also in contrib/secops/deny-node.toml).
OSV_ONLY=$(sed 's/[[:space:]]*#.*$//' <<'EOF_OSV_ONLY' | grep -v '^$' || true
RUSTSEC-2024-0436   # contrib/yellowback/attest/Cargo.lock only (the agent's own deny.toml accepts it); not in the root graph
RUSTSEC-2023-0089   # atomic-polyfill: only for targets without native atomics, outside cargo-deny's target graph ([graph] targets)
EOF_OSV_ONLY
)

leg_secops() {
  # The two ignore lists cannot drift (combined security audit, 2026-11-11: RUSTSEC-2026-0486 was in
  # osv-scanner.toml only): every RustSec ID cargo-deny ignores is accepted by OSV-Scanner too, and every
  # RustSec ID OSV-Scanner accepts is ignored by cargo-deny unless OSV_ONLY names it. GHSA IDs are
  # OSV-only by nature (cargo-deny reads the RustSec database).
  local osv deny x bad=""
  osv=$(grep -oE '^id = "RUSTSEC-[0-9]{4}-[0-9]{4}"' osv-scanner.toml | cut -d'"' -f2 | sort -u)
  deny=$(grep -oE '\{ *id = "RUSTSEC-[0-9]{4}-[0-9]{4}"' contrib/secops/deny-node.toml | cut -d'"' -f2 | sort -u)
  if [ -z "$osv" ] || [ -z "$deny" ]; then echo "could not read the ignore lists"; return 1; fi
  for x in $deny; do
    grep -qx -- "$x" <<< "$osv" || bad="$bad
  $x is ignored in contrib/secops/deny-node.toml but not accepted in osv-scanner.toml"
  done
  for x in $osv; do
    grep -qx -- "$x" <<< "$deny" && continue
    grep -qx -- "$x" <<< "$OSV_ONLY" && continue
    bad="$bad
  $x is accepted in osv-scanner.toml but not ignored in contrib/secops/deny-node.toml (add it with the same reason, or to OSV_ONLY with why cargo-deny never sees it)"
  done
  for x in $OSV_ONLY; do
    grep -qx -- "$x" <<< "$osv" || bad="$bad
  OSV_ONLY names $x, which osv-scanner.toml does not accept"
  done
  echo "RustSec ignores: $(wc -l <<< "$osv" | tr -d ' ') in osv-scanner.toml, $(wc -l <<< "$deny" | tr -d ' ') in deny-node.toml, $(wc -w <<< "$OSV_ONLY" | tr -d ' ') OSV-only by name"
  [ -z "$bad" ] || { echo "$bad"; return 1; }
}

find_other_line() {   # find_other_line <other main-tree name> <other worktree prefix> <this worktree prefix>
  # The same function on both node lines. Sets YB_OTHER_LINE_DIR and YB_OTHER_LINE_REV when the other
  # line's checkout sits at the conventional sibling path; leaves them unset otherwise.
  local here me branch dir="" rev
  here=$(pwd -P); me=$(basename "$here")
  case "$me" in
    "$3"*) dir="$here/../$2${me#"$3"}" ;;
    *) dir="$here/../$1" ;;
  esac
  git -C "$dir" rev-parse --git-dir >/dev/null 2>&1 || { echo "no other line at the sibling path $dir"; return 0; }
  dir=$(cd "$dir" && pwd -P)
  branch=$(git symbolic-ref --short -q HEAD || echo upgrade/vault)
  rev=$(python3 qa/yellowback-other-line-branch.py --dir "$dir" --branch "$branch") || return 0
  YB_OTHER_LINE_DIR=$dir YB_OTHER_LINE_REV=$rev
  echo "other line found at the sibling path (committed state only; uncommitted changes there are not read)"
}

leg_cross_line() {
  # Both node lines carry identical behaviour (upgrade plan §9): the manifest's identical files, trees and
  # pinned shims, the overlay trees, and every Vault chain parameter (audit W3-P-1, W3-P-2), as the
  # workflow's cross-line step checked them before it called this leg.
  [ -d src/vault ] || { echo "not the upgrade line (no src/vault): nothing to compare"; return 0; }
  [ -n "${YB_OTHER_LINE_REF:-}" ] || [ -n "${YB_OTHER_LINE_DIR:-}" ] || find_other_line ycash-dd up- up6-
  local fail=0 tmp f
  tmp=$(mktemp -d)
  if [ -n "${YB_OTHER_LINE_REF:-}" ]; then
    echo "other line: $YB_OTHER_LINE_REF ($(git rev-parse --short "$YB_OTHER_LINE_REF^{commit}"))"
    python3 qa/yellowback-cross-line.py --this-line y6 --other-ref "$YB_OTHER_LINE_REF" || fail=1
    python3 qa/yellowback-cross-line-trees.py --this-line y6 --other-ref "$YB_OTHER_LINE_REF" || fail=1
    python3 qa/yellowback-vault-params.py extract --git-ref "$YB_OTHER_LINE_REF" > "$tmp/theirs.json" || fail=1
  elif [ -n "${YB_OTHER_LINE_DIR:-}" ] && [ -n "${YB_OTHER_LINE_REV:-}" ]; then
    echo "other line: $YB_OTHER_LINE_DIR at $YB_OTHER_LINE_REV ($(git -C "$YB_OTHER_LINE_DIR" rev-parse --short "$YB_OTHER_LINE_REV^{commit}"))"
    python3 qa/yellowback-cross-line.py --this-line y6 --other-dir "$YB_OTHER_LINE_DIR" --other-rev "$YB_OTHER_LINE_REV" || fail=1
    python3 qa/yellowback-cross-line-trees.py --this-line y6 --other-dir "$YB_OTHER_LINE_DIR" --other-rev "$YB_OTHER_LINE_REV" || fail=1
    # The extractor's FILES (qa/yellowback-vault-params.py), read from the other line's git objects.
    for f in src/chainparams.cpp src/consensus/params.h src/version.h src/yellowback/params.cpp \
             src/consensus/upgrades.h src/consensus/upgrades.cpp; do
      mkdir -p "$tmp/other/$(dirname "$f")"
      git -C "$YB_OTHER_LINE_DIR" show "$YB_OTHER_LINE_REV:$f" > "$tmp/other/$f" || fail=1
    done
    python3 qa/yellowback-vault-params.py extract --root "$tmp/other" > "$tmp/theirs.json" || fail=1
  else
    rm -rf "$tmp"
    echo "NOT CHECKED: no other node line (set YB_OTHER_LINE_REF, or YB_OTHER_LINE_DIR + YB_OTHER_LINE_REV, or check it out at the sibling path)"
    in_ci && return 1; [ "$require_cross_line" = 0 ] || { echo "--require-cross-line: NOT CHECKED is a failure"; return 1; }; return 0
  fi
  python3 qa/yellowback-vault-params.py extract --root . > "$tmp/mine.json" || fail=1
  python3 qa/yellowback-vault-params.py compare "$tmp/mine.json" "$tmp/theirs.json" || fail=1
  rm -rf "$tmp"
  return $fail
}

leg frozen leg_frozen
leg pq-wipes leg_pq_wipes
leg ci-guards leg_ci_guards
leg golden leg_golden
leg rpc-cvt leg_rpc_cvt
leg registration leg_registration
leg attribution leg_attribution
leg secops leg_secops
leg cross-line leg_cross_line
exit $rc
