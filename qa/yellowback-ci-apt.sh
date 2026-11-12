#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

# apt-get update + install for the CI jobs, bounded and retried (the same file on both node lines,
# qa/yellowback-cross-line.manifest). The Ubuntu mirror outage of 2026-11-11 left jobs hanging in
# apt-get for twenty minutes and cost a day of runs; here every network wait is bounded, each command
# is retried with backoff, and a failure ends the step with one clear message.
#
# Usage: qa/yellowback-ci-apt.sh PACKAGE...
#   APT_UPDATE_TRIES (3), APT_INSTALL_TRIES (2): attempts per command
#   APT_UPDATE_TIMEOUT (120), APT_INSTALL_TIMEOUT (300): seconds per attempt (coreutils timeout)
#   APT_RETRY_WAIT (15): seconds before the first retry, tripled before each next one
# If apt-get update still fails, the install is tried once against the image's existing package lists
# (most of these packages are on the runner image already, and then nothing is downloaded).
set -uo pipefail
[ $# -gt 0 ] || { echo "usage: $0 PACKAGE..." >&2; exit 2; }

opts=(-o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o DPkg::Lock::Timeout=60)
sudo_=()
[ "$(id -u)" = 0 ] || sudo_=(sudo)

attempt() {   # attempt <tries> <seconds> <what> cmd...
  local tries=$1 secs=$2 what=$3 n=1 rc wait=${APT_RETRY_WAIT:-15}
  shift 3
  while :; do
    echo "apt: $what, attempt $n of $tries (at most ${secs}s)"
    timeout --kill-after=10 "$secs" "$@"; rc=$?
    [ $rc -eq 0 ] && return 0
    [ $rc -eq 124 ] && echo "apt: $what timed out after ${secs}s"
    [ "$n" -ge "$tries" ] && return $rc
    echo "apt: $what failed (exit $rc); retrying in ${wait}s"
    sleep "$wait"; n=$((n + 1)); wait=$((wait * 3))
  done
}

export DEBIAN_FRONTEND=noninteractive
updated=1
attempt "${APT_UPDATE_TRIES:-3}" "${APT_UPDATE_TIMEOUT:-120}" "apt-get update" \
  "${sudo_[@]}" apt-get "${opts[@]}" -q update || {
  updated=0
  echo "::warning::apt-get update failed after ${APT_UPDATE_TRIES:-3} attempts (an Ubuntu mirror outage?); trying the install with the image's package lists"
}
if [ "$updated" = 1 ]; then tries=${APT_INSTALL_TRIES:-2}; else tries=1; fi
attempt "$tries" "${APT_INSTALL_TIMEOUT:-300}" "apt-get install $*" \
  "${sudo_[@]}" apt-get "${opts[@]}" -q install -y "$@" || {
  echo "::error::apt-get install $* failed (package lists $([ "$updated" = 1 ] && echo fresh || echo NOT updated)); see the apt output above. A mirror outage is not a code failure: re-run this job once the mirror answers."
  exit 1
}
