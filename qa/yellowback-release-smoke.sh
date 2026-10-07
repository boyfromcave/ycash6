#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# Release smoke test (doc/yellowback-release.md): the packaged binaries in <dir> report the
# expected version, start a throwaway regtest node on the vault upgrade, create the YED attestor
# set, restart it with that set so Yellowback is live, answer one stock RPC and one yed_* RPC, and
# stop cleanly (doc/yellowback.md, Configuration). Needs the zk parameters
# (zcutil/fetch-params.sh) unless --version-only, which is all a runner that cannot execute the
# node gets.
#
# Usage: qa/yellowback-release-smoke.sh <dir> <version> [--version-only]
#   <dir>      holds ycashd, ycash-cli (and ycash-tx), with .exe on Windows
#   <version>  e.g. 6.22.0-rc1, as rendered by configure.ac
set -euo pipefail
dir=$1; version=$2; mode=${3:-}
ext=''; [ -f "$dir/ycashd.exe" ] && ext='.exe'
ycashd="$dir/ycashd$ext"; cli="$dir/ycash-cli$ext"; tx="$dir/ycash-tx$ext"

for b in "$ycashd" "$cli" "$tx"; do
  [ -x "$b" ] || { echo "missing or not executable: $b"; exit 1; }
  # ycash-tx has no -version switch at the pin; -help prints the same version banner.
  v=$("$b" -version 2>/dev/null | head -1 || true)
  [ -n "$v" ] || v=$("$b" -help 2>/dev/null | head -1 || true)
  echo "$(basename "$b"): $v"
  case "$v" in *"v$version"*) ;; *) echo "expected v$version in the banner of $b"; exit 1 ;; esac
done
[ "$mode" = "--version-only" ] && { echo "smoke (version only): ok"; exit 0; }

datadir=$(mktemp -d "${TMPDIR:-/tmp}/ycash-smoke.XXXXXX")
rpc=(-regtest -datadir="$datadir" -rpcport=18732 -rpcuser=smoke -rpcpassword=smoke)
cleanup() { "$cli" "${rpc[@]}" stop >/dev/null 2>&1 || true; sleep 2; rm -rf "$datadir"; }
trap cleanup EXIT
touch "$datadir/ycash.conf"     # ycashd refuses to start without one
# Overwinter, Sapling and the four Ycash upgrades at 1, as the qa harness does; the vault upgrade
# (UPGRADE_VAULT, 6d5b7a31) at 103. Yellowback is live only once the node also names its YED
# attestor set, which has to exist on chain first: start, create it, restart naming it.
vault_h=103
nuparams=(-nuparams=5ba81b19:1 -nuparams=76b809bb:1 -nuparams=374d694f:1 -nuparams=8e471bd6:1
          -nuparams=66314da3:1 -nuparams=19bd2d2f:1 -nuparams=6d5b7a31:$vault_h)
pid=
start() {
  "$ycashd" "${rpc[@]}" -port=18733 -listen=0 -printtoconsole=0 "${nuparams[@]}" "$@" &
  pid=$!
  for _ in $(seq 1 120); do
    "$cli" "${rpc[@]}" getblockcount >/dev/null 2>&1 && return 0
    kill -0 $pid 2>/dev/null || { echo "ycashd exited during startup"; tail -40 "$datadir/regtest/debug.log" || true; exit 1; }
    sleep 1
  done
  echo "ycashd did not answer RPC within 120 s"; exit 1
}
start
sub=$("$cli" "${rpc[@]}" getnetworkinfo | grep '"subversion"')
echo "getnetworkinfo $sub"
# Past the upgrade height with a few mature coinbases to fund the set (set_create needs four).
"$cli" "${rpc[@]}" generate $((vault_h + 1)) >/dev/null
setid=$("$cli" "${rpc[@]}" set_create '{"seats":1,"unlockthreshold":1,"open":true}' \
        | sed -n 's/.*"setid": *"\([0-9a-f]\{64\}\)".*/\1/p')
[ -n "$setid" ] || { echo "set_create returned no setid"; exit 1; }
"$cli" "${rpc[@]}" generate 1 >/dev/null      # the set exists from the block after it confirms
"$cli" "${rpc[@]}" stop >/dev/null
wait $pid || true
start -yellowbackattestorset="$setid"
info=$("$cli" "${rpc[@]}" yed_getinfo)
echo "$info"
echo "$info" | grep -q '"rpcversion": 5' || { echo "yed_getinfo: expected rpcversion 5"; exit 1; }
echo "$info" | grep -q '"status": "active"' || { echo "yed_getinfo: expected the vault upgrade active"; exit 1; }
echo "smoke: ok"
