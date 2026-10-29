#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# Release guard (hardening plan F-5, H-8; audit W3-P-1 part C).
# Refuses a vault release while mainnet would ship with an unset UPGRADE_VAULT activation
# height, an unset pqFalconHeight, an unset nVaultMinSetMaturity, or an unset YED attestor
# set. With --other-json, also refuses when the activation height, pqFalconHeight or
# nVaultMinSetMaturity diverges from the other node line on mainnet, testnet or regtest.
#
# Reads the tree through qa/yellowback-vault-params.py (class bodies, not a first match).
# Enforces the release rules of the tag's stage (audit W3-P-1; testnet plan §5.1, T-8):
#   beta   (6.22.N-betaM)  parity with the other line, the mainnet maturity, the 6.22 line; and
#                          testnet-legacy never activates Vault.
#   rc     (6.22.N-rcM)    the above, R3-R6 (the protocol-version bump, taken with rc1; the Falcon
#                          height), R7 for the testnet (testnet-yb-fast's height and set both set;
#                          testnet-yb-slow's set only with its height) and mainnet's height and set
#                          both or neither (unset unless the owner sets them).
#   final  (6.22.N)        R1-R7: mainnet's height and set, R3-R6, R7 per testnet profile.
# MIN_PEER_PROTO_VERSION must stay at or below the live floor (R5).
#
# Usage: qa/yellowback-release-heights.sh [--warn] [--root DIR] [--other-json FILE]
#                                         [--release-version VER] [--stage beta|rc|final]
#   --warn               exit 0 after reporting unset or divergent parameters (a proving run)
#   --root DIR           tree to read (default: .)
#   --other-json FILE    extract JSON of the other node line
#   --release-version    when set, VER must be a 6.22.x release version (the vault release line;
#                        ycash-dd pairing tags), and its suffix names the stage
#   --stage              the stage, when no version names it (default: final, the strictest)
#   exit 0 when the parameters may ship; exit 1 when they may not; exit 2 when the extractor
#   cannot parse the tree. A parse failure is never treated as "unset", including under --warn.
set -euo pipefail

# The one line that differs on ycash-dd.
where="doc/yellowback-release.md, Network parameters"

warn=0
root=.
other=
relver=
stage=
while [ $# -gt 0 ]; do
  case "$1" in
    --warn) warn=1; shift ;;
    --root) root=${2:?--root needs a directory}; shift 2 ;;
    --other-json) other=${2:?--other-json needs a file}; shift 2 ;;
    --release-version) relver=${2:?--release-version needs a version}; shift 2 ;;
    --stage) stage=${2:?--stage needs beta, rc or final}; shift 2 ;;
    *) echo "usage: qa/yellowback-release-heights.sh [--warn] [--root DIR] [--other-json FILE] [--release-version VER] [--stage beta|rc|final]" >&2; exit 1 ;;
  esac
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

case "$stage" in
  ''|beta|rc|final) ;;
  *) echo "usage: --stage is beta, rc or final, not $stage" >&2; exit 1 ;;
esac
if [ -n "$relver" ]; then
  if ! found=$(python3 "$script_dir/yellowback-vault-params.py" stage "$relver" 2>/dev/null); then
    echo "refusing to release: $relver is not a release version (6.22.N, 6.22.N-rcM, 6.22.N-betaM) ($where)"
    exit 1
  fi
  case "$found" in
    "6.22 "*) ;;
    *)
      echo "refusing to release: version $relver is not 6.22.x (the vault release line) ($where)"
      exit 1
      ;;
  esac
  named=${found#* }
  if [ -n "$stage" ] && [ "$stage" != "$named" ]; then
    echo "refusing to release: --stage $stage, but version $relver is a $named ($where)"
    exit 1
  fi
  stage=$named
fi
stage=${stage:-final}
json=$(mktemp)
trap 'rm -f "$json"' EXIT
if ! python3 "$script_dir/yellowback-vault-params.py" extract --root "$root" >"$json"; then
  echo "refusing to release: could not extract Vault parameters ($where)" >&2
  exit 2
fi
if [ -n "$other" ] && [ ! -f "$other" ]; then
  echo "no $other" >&2
  exit 1
fi

set +e
python3 - "$json" "$other" "$warn" "$where" "$script_dir" "$stage" <<'PY'
import importlib.util
import json
import os
import sys

mine_path, other_path, warn, where, script_dir, stage = sys.argv[1:7]
spec = importlib.util.spec_from_file_location(
    "yellowback_vault_params", os.path.join(script_dir, "yellowback-vault-params.py"))
vp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vp)
with open(mine_path, encoding="utf-8") as fh:
    mine = json.load(fh)


def show(value):
    return "unset" if value is None else str(value)


main = mine["main"]
att = mine["yellowback_params"].get("main_attestor_set_id")
print("mainnet Yellowback: UPGRADE_VAULT height %s, pqFalconHeight %s, nVaultMinSetMaturity %s, attestorSetId %s" % (
    show(main.get("vault_activation_height")),
    show(main.get("pq_falcon_height")),
    show(main.get("vault_min_set_maturity")),
    show(att),
))
yb = mine["yellowback_params"]
for profile, key in (("fast", "testfast_attestor_set_id"), ("slow", "test_attestor_set_id"), ("legacy", None)):
    net = mine["test"][profile]
    print("testnet-%s: UPGRADE_VAULT height %s, nVaultMinSetMaturity %s, attestorSetId %s" % (
        "legacy" if profile == "legacy" else "yb-" + profile,
        show(net.get("vault_activation_height")),
        show(net.get("vault_min_set_maturity")),
        "n/a" if key is None else show(yb.get(key)),
    ))
print("protocol: PROTOCOL_VERSION %s, UPGRADE_VAULT.nProtocolVersion %s, MIN_PEER_PROTO_VERSION %s" % (
    show(mine["version"].get("PROTOCOL_VERSION")),
    show(main.get("vault_protocol_version")),
    show(mine["version"].get("MIN_PEER_PROTO_VERSION")),
))
print("release stage: %s" % stage)

problems = list(vp.release_problems(mine, stage))
maturity = main.get("vault_min_set_maturity")
if not isinstance(maturity, int) or isinstance(maturity, bool) or maturity <= 0:
    problems.append("the mainnet nVaultMinSetMaturity is unset")

if other_path:
    with open(other_path, encoding="utf-8") as fh:
        theirs = json.load(fh)
    for diff in vp.compare(mine, theirs):
        problems.append("divergent " + diff)

for problem in problems:
    print("problem: " + problem)
if not problems:
    print("release heights: ok")
    sys.exit(0)
if warn == "1":
    print("warning: not a release: continuing (%s)" % where)
    sys.exit(0)
print("refusing to release (%s)" % where)
sys.exit(1)
PY
rc=$?
set -e
exit "$rc"
