#!/bin/sh
# Monitoring snippet (plan §5 step 4): is this pool's node emitting quote tags?
#
#   monitor-quote.sh [max-age-seconds] [-- <ycash-cli options>]
#
# Reads `ycash-cli yed_getinfo` and exits 0 when `.miner.quoteKind == "quote"`,
# the quote is younger than max-age (default 900 s, half of -yellowbackquotemaxage)
# and `.miner.eligible` is true; prints one line either way, so it drops into
# cron, a systemd timer, Nagios/Icinga or a Prometheus textfile collector.
# Exit 1 = signal-only or stale (the quote agent is down or fails closed),
# exit 2 = not eligible / not registered, exit 3 = RPC failure or module off.
#
# The quote agent's own log (`journalctl -u yellowback-quote`) says why: look for
# "no aggregate" (sources below min_sources / min_venues) or "yed_setquote ... failed".
set -u
MAX_AGE=900
CLI=${YCASH_CLI:-ycash-cli}
if [ "${1:-}" != "" ] && [ "$1" != "--" ]; then MAX_AGE=$1; shift; fi
[ "${1:-}" = "--" ] && shift
INFO=$("$CLI" "$@" yed_getinfo 2>&1) || { echo "yellowback: RPC failed: $INFO"; exit 3; }
printf '%s' "$INFO" | "${PYTHON:-python3}" -c '
import json, sys
max_age = int(sys.argv[1])
i = json.load(sys.stdin)
m = i.get("miner") or {}
kind, age = m.get("quoteKind"), m.get("quoteAgeSeconds")
line = "yellowback: enabled=%s healthy=%s enforcing=%s quoteKind=%s quoteAge=%s registered=%s eligible=%s payout=%s" % (
    i.get("enabled"), i.get("healthy"), i.get("enforcing"), kind, age, m.get("registered"), m.get("eligible"), m.get("payoutAddress"))
print(line)
if not i.get("enabled"):
    sys.exit(3)
if kind != "quote" or age is None or age > max_age:
    sys.exit(1)
if not m.get("eligible"):
    sys.exit(2)
' "$MAX_AGE"
