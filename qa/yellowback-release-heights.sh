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
# Protocol version is not a release-guard input (W3-P-1 part D is deferred: this script does
# not require PROTOCOL_VERSION or MIN_PEER_PROTO_VERSION to move).
#
# Usage: qa/yellowback-release-heights.sh [--warn] [--root DIR] [--other-json FILE] [--release-version VER]
#   --warn               exit 0 after reporting unset or divergent parameters (a proving run)
#   --root DIR           tree to read (default: .)
#   --other-json FILE    extract JSON of the other node line
#   --release-version    when set, VER must be 6.22.* (the vault release line; ycash-dd pairing tags)
#   exit 0 when the parameters may ship; exit 1 when they may not; exit 2 when the extractor
#   cannot parse the tree. A parse failure is never treated as "unset", including under --warn.
set -euo pipefail

# The one line that differs on ycash-dd.
where="doc/yellowback-release.md, Network parameters"

warn=0
root=.
other=
relver=
while [ $# -gt 0 ]; do
  case "$1" in
    --warn) warn=1; shift ;;
    --root) root=${2:?--root needs a directory}; shift 2 ;;
    --other-json) other=${2:?--other-json needs a file}; shift 2 ;;
    --release-version) relver=${2:?--release-version needs a version}; shift 2 ;;
    *) echo "usage: qa/yellowback-release-heights.sh [--warn] [--root DIR] [--other-json FILE] [--release-version VER]" >&2; exit 1 ;;
  esac
done

if [ -n "$relver" ]; then
  case "$relver" in
    6.22.*) ;;
    *)
      echo "refusing to release: version $relver is not 6.22.x (the vault release line) ($where)"
      exit 1
      ;;
  esac
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
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
python3 - "$json" "$other" "$warn" "$where" <<'PY'
import json
import sys

mine_path, other_path, warn, where = sys.argv[1:5]
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

problems = []


def unset_height(value):
    return not isinstance(value, int) or value <= 0


def unset_falcon(value):
    # 0 is set: Falcon follows UPGRADE_VAULT from its first block. A missing height is unset.
    return not isinstance(value, int) or value < 0


def unset_maturity(value):
    return not isinstance(value, int) or value <= 0


if unset_height(main.get("vault_activation_height")):
    problems.append("the mainnet UPGRADE_VAULT activation height is unset")
if unset_falcon(main.get("pq_falcon_height")):
    problems.append("the mainnet pqFalconHeight is unset")
if unset_maturity(main.get("vault_min_set_maturity")):
    problems.append("the mainnet nVaultMinSetMaturity is unset")
if not isinstance(att, str) or not att or set(att) <= set("0"):
    problems.append("the mainnet YED attestor set (MainParams attestorSetId) is unset")

if other_path:
    with open(other_path, encoding="utf-8") as fh:
        theirs = json.load(fh)
    names = {
        "vault_activation_height": "UPGRADE_VAULT activation height",
        "pq_falcon_height": "pqFalconHeight",
        "vault_min_set_maturity": "nVaultMinSetMaturity",
    }
    for net in ("main", "test", "regtest"):
        for field, label in names.items():
            left = mine.get(net, {}).get(field)
            right = theirs.get(net, {}).get(field)
            if left != right:
                problems.append("divergent %s %s: %s != %s" % (net, label, show(left), show(right)))

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
