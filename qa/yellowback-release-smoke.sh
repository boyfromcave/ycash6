#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# Release smoke test (doc/yellowback-release.md): the packaged binaries in <dir> report the
# expected version, start a throwaway regtest node with Yellowback on, answer one stock RPC and
# one yed_* RPC, and stop cleanly. Needs the zk parameters (zcutil/fetch-params.sh) unless
# --version-only, which is all a runner that cannot execute the node gets.
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
# Overwinter + Sapling at 1, as the qa harness does; Yellowback on from height 1.
"$ycashd" "${rpc[@]}" -port=18733 -listen=0 -printtoconsole=0 \
  -nuparams=5ba81b19:1 -nuparams=76b809bb:1 \
  -experimentalfeatures -yellowback -yellowbackstartheight=1 &
for _ in $(seq 1 120); do
  "$cli" "${rpc[@]}" getblockcount >/dev/null 2>&1 && break
  kill -0 $! 2>/dev/null || { echo "ycashd exited during startup"; tail -40 "$datadir/regtest/debug.log" || true; exit 1; }
  sleep 1
done
sub=$("$cli" "${rpc[@]}" getnetworkinfo | grep '"subversion"')
echo "getnetworkinfo $sub"
"$cli" "${rpc[@]}" yed_getinfo
echo "smoke: ok"
