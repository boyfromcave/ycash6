#!/bin/bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# Runs one part (1-4) of qa/rpc-tests/spend_matrix.py (optionally under a $HEAVY_SLOT wrapper), retrying
# while the slot is busy (exit 75/76). Uses the helpers the build installed in src/ unless
# YUGEN_LEAFVERIFY / YUGEN_SENDBUILD / YEWD_YUGEN are set. Output in target/logs/matrix-part<N>.{log,md}.
# Usage: qa/yugen/run-spend-matrix.sh <part>     Stop: pkill -f run-spend-matrix.sh
# Env: PYTHON (default python3), HEAVY_SLOT (a wrapper run as `$HEAVY_SLOT run <label> -- <cmd>`; unset: run directly), RETRIES (default 60).
set -u
P=${1:?usage: $0 <part 1-4>}
case $P in 1|2|3|4) ;; *) echo "part must be 1-4" >&2; exit 2 ;; esac
cd "$(dirname "$0")/../.."
L=$PWD/target/logs; T=$L/m$P-tmp
HEAVY_SLOT=${HEAVY_SLOT:-}
export ZCASHD=${ZCASHD:-$PWD/src/ycashd} SPEND_MATRIX_PART=$P SPEND_MATRIX_OUT=$L/matrix-part$P.md
export MATRIX_YCASHD_REV=$(git rev-parse --short HEAD)
W=$PWD/contrib/yugen-sendbuild/deps/clones/yew
[ -d "$W/.git" ] && export MATRIX_YEW_REV=$(git -C "$W" rev-parse --short HEAD)
for b in "$ZCASHD" "${YUGEN_LEAFVERIFY:-src/yugen-leafverify}" "${YUGEN_SENDBUILD:-src/yugen-sendbuild}" "${YEWD_YUGEN:-src/yewd-yugen}"; do
	[ -x "$b" ] || { echo "missing $b: build first (make, doc/yugen-node.md Helper build)" >&2; exit 1; }
done
mkdir -p "$T"; rm -rf "${T:?}"/*
rc=1
for _ in $(seq 1 "${RETRIES:-60}"); do
	HEAVY_UNTIMED=1 ${HEAVY_SLOT:+"$HEAVY_SLOT" run "matrix-$P" --} /usr/bin/time -l "${PYTHON:-python3}" -u qa/rpc-tests/spend_matrix.py \
		--srcdir=src --tmpdir="$T" > "$L/matrix-part$P.log" 2>&1
	rc=$?; [ $rc -ne 75 ] && [ $rc -ne 76 ] && break; sleep 60
done
echo "rc=$rc" >> "$L/matrix-part$P.log"
exit $rc
