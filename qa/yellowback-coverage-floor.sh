#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# The per-file line-coverage floors of the Yellowback module (plan §6.0 item 6, P6, §8.4 item 24):
#   >= 95 % in state.cpp, math.h, tag.cpp, payload.cpp, script.cpp
#   >= 85 % in index.cpp, policy.cpp
#   >= 80 % in txbuilder.cpp, wallet.cpp, rpc/yellowback*.cpp
# Reads an lcov tracefile (default: lcov.info) and exits 1 when any floor is not met. A file that
# is absent from the tracefile (not built into this phase yet) is reported, never counted.
#
#   usage: qa/yellowback-coverage-floor.sh [lcov.info]

set -u
info="${1:-lcov.info}"
if [ ! -f "$info" ]; then
    echo "coverage floor: tracefile $info not found" >&2
    exit 2
fi

floors=(
    "src/yellowback/state.cpp:95"
    "src/yellowback/math.h:95"
    "src/yellowback/tag.cpp:95"
    "src/yellowback/payload.cpp:95"
    "src/yellowback/script.cpp:95"
    "src/yellowback/index.cpp:85"
    "src/yellowback/policy.cpp:85"
    "src/yellowback/txbuilder.cpp:80"
    "src/yellowback/wallet.cpp:80"
    "src/rpc/yellowback.cpp:80"
    "src/rpc/yellowbackwallet.cpp:80"
)

# One line per source file: "<path> <lines found> <lines hit>" (an lcov record is SF: ... LF: ... LH: ... end_of_record).
summary=$(awk -F: '
    /^SF:/ { file = $2 }
    /^LF:/ { lf[file] = $2 }
    /^LH:/ { lh[file] = $2 }
    END { for (f in lf) print f, lf[f], lh[f] + 0 }
' "$info")

status=0
printf '%-36s %8s %8s %7s %6s\n' "file" "lines" "hit" "cover" "floor"
for entry in "${floors[@]}"; do
    path="${entry%%:*}"
    floor="${entry##*:}"
    row=$(printf '%s\n' "$summary" | awk -v p="$path" 'index($1, p) == length($1) - length(p) + 1 { print; exit }')
    if [ -z "$row" ]; then
        printf '%-36s %8s %8s %7s %6s  (not in the tracefile)\n' "$path" "-" "-" "-" "$floor"
        continue
    fi
    lf=$(printf '%s' "$row" | awk '{print $2}')
    lh=$(printf '%s' "$row" | awk '{print $3}')
    if [ "$lf" -eq 0 ]; then
        pct=0
    else
        pct=$(( 100 * lh / lf ))
    fi
    verdict="ok"
    if [ "$pct" -lt "$floor" ]; then
        verdict="BELOW FLOOR"
        status=1
    fi
    printf '%-36s %8d %8d %6d%% %5d%%  %s\n' "$path" "$lf" "$lh" "$pct" "$floor" "$verdict"
done
exit $status
