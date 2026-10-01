#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Calibrate DIVERGE_BPS_ATTEST (proposal §16, measurement 1; v3 plan §6 Phase A4, §11 item 3).

Two subcommands:

  log      fetch the CoinGecko aggregate, SafeTrade (as CoinGecko reports it) and nonkyc.io
           through yellowback_price.py's presets and append one CSV row per tick;
  analyze  read that CSV, take the pairwise spread distribution, print the 95th percentile
           per pair and the recommended DIVERGE_BPS_ATTEST = 3 x p95 (in bps), and flag gaps.

The spread between two prices a, b is |a - b| * 10^4 / min(a, b) bps, the form MINT-10 uses.
Standard library plus yellowback_price.py; Python >= 3.11; run through the workspace venv.
`analyze` never touches the network, so it is testable offline (test_calibrate.py).
"""

import argparse
import csv
import datetime
import importlib.util
import itertools
import logging
import math
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("yellowback_price", os.path.join(HERE, "..", "..", "yellowback_price.py"))
yp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(yp)

LOG = logging.getLogger("yellowback-calibrate")

# The three sources of proposal §16 (and attest.toml.sample's [[sources]]), in column order.
SOURCES = [
    {"name": "coingecko", "kind": "coingecko_simple"},
    {"name": "safetrade", "kind": "coingecko_ticker", "market": "safe_trade", "target": "USDT"},
    {"name": "nonkyc", "kind": "nonkyc_market", "symbol": "YEC_USDT"},
]
NAMES = [s["name"] for s in SOURCES]
COLUMNS = ["ts_iso", "ts"] + ["%s_micro_usd" % n for n in NAMES] + ["errors"]
DEFAULT_INTERVAL = 300
DEFAULT_DURATION_DAYS = 14.0


# ---------------------------------------------------------------------------
# log

def build_feed(api_key=None, fetch_timeout=None):
    sources = []
    for s in SOURCES:
        s = dict(s)
        if api_key and s["kind"].startswith("coingecko"):
            s["api_key"] = api_key
        sources.append(s)
    settings = {"fetch_timeout": fetch_timeout} if fetch_timeout else None
    return yp.PriceFeed(sources, settings=settings)


def sample_once(feed, now=None):
    """One fetch of every source through PriceFeed.poll (the quote agent's own path).
    Returns ({name: micro_usd or None}, {name: error string})."""
    feed.poll(force=True)
    prices, errors = {}, {}
    for name in NAMES:
        h = feed.health[name]
        if h["state"] == "ok":
            prices[name] = h["last_price_micro_usd"]
        else:
            prices[name] = None
            errors[name] = h["last_error"] or h["state"]
    return prices, errors


def row_for(now, prices, errors):
    iso = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = [iso, "%d" % now] + ["" if prices.get(n) is None else str(prices[n]) for n in NAMES]
    row.append("; ".join("%s: %s" % (n, errors[n].replace("\n", " ")) for n in NAMES if n in errors))
    return row


def append_row(path, row):
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(COLUMNS)
        w.writerow(row)
        f.flush()


def cmd_log(args):
    feed = build_feed(args.api_key, args.fetch_timeout)
    stop = {"now": False}

    def _stop(signum, frame):
        stop["now"] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    deadline = None if args.once or args.duration <= 0 else time.time() + args.duration * 86400
    ticks = 0
    while True:
        now = time.time()
        prices, errors = sample_once(feed, now)
        append_row(args.out, row_for(now, prices, errors))
        ticks += 1
        live = sum(1 for n in NAMES if prices[n] is not None)
        LOG.info("tick %d: %s%s", ticks,
                 " ".join("%s=%s" % (n, "-" if prices[n] is None else "%.6f" % (prices[n] / yp.MICRO)) for n in NAMES),
                 (" errors: " + "; ".join("%s: %s" % kv for kv in errors.items())) if errors else "")
        if args.once:
            return 0 if live == len(NAMES) else 1
        if deadline is not None and time.time() >= deadline:
            LOG.info("duration reached; %d ticks logged to %s", ticks, args.out)
            return 0
        wake = now + args.interval
        while not stop["now"] and time.time() < wake:
            time.sleep(min(1.0, max(0.0, wake - time.time())))
        if stop["now"]:
            LOG.info("stopped; %d ticks logged to %s", ticks, args.out)
            return 0


# ---------------------------------------------------------------------------
# analyze (pure functions first, so the tests can drive them without a file)

def spread_bps(a, b):
    """|a - b| * 10^4 / min(a, b), MINT-10's form. a, b > 0."""
    return abs(a - b) * 10_000 / min(a, b)


def percentile(values, pct):
    """Nearest-rank percentile of a non-empty list (pct in (0, 100])."""
    xs = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(xs)))
    return xs[rank - 1]


def read_log(fp):
    """Rows of a spreads log: [(ts, {name: micro_usd or None})], ascending ts. Malformed rows are skipped."""
    rows = []
    for rec in csv.DictReader(fp):
        try:
            ts = int(float(rec["ts"]))
        except (KeyError, TypeError, ValueError):
            continue
        prices = {}
        for n in NAMES:
            v = (rec.get("%s_micro_usd" % n) or "").strip()
            try:
                prices[n] = int(v) if v else None
            except ValueError:
                prices[n] = None
            if prices[n] is not None and prices[n] <= 0:
                prices[n] = None
        rows.append((ts, prices))
    rows.sort(key=lambda r: r[0])
    return rows


def pair_spreads(rows):
    """{(a, b): [spread_bps, ...]} over the rows where both sources are present."""
    out = {pair: [] for pair in itertools.combinations(NAMES, 2)}
    for _, prices in rows:
        for a, b in out:
            if prices.get(a) and prices.get(b):
                out[(a, b)].append(spread_bps(prices[a], prices[b]))
    return out


def find_gaps(rows, expected_interval, factor=3.0):
    """[(ts_before, ts_after, seconds)] where consecutive rows are more than factor x interval apart."""
    gaps = []
    for (t0, _), (t1, _) in zip(rows, rows[1:]):
        if t1 - t0 > factor * expected_interval:
            gaps.append((t0, t1, t1 - t0))
    return gaps


def recommend_bps(p95_by_pair, multiple=3.0, round_to=100):
    """3 x the worst pair's p95, rounded up to `round_to` bps; None when no pair has data."""
    p95s = [v for v in p95_by_pair.values() if v is not None]
    if not p95s:
        return None
    raw = multiple * max(p95s)
    return int(math.ceil(raw / round_to) * round_to)


def analyze(rows, expected_interval, gap_factor=3.0, multiple=3.0):
    spreads = pair_spreads(rows)
    stats = {}
    for pair, xs in spreads.items():
        if xs:
            stats[pair] = {"n": len(xs), "median": percentile(xs, 50), "p90": percentile(xs, 90),
                           "p95": percentile(xs, 95), "p99": percentile(xs, 99), "max": max(xs)}
        else:
            stats[pair] = {"n": 0, "median": None, "p90": None, "p95": None, "p99": None, "max": None}
    missing = {n: sum(1 for _, p in rows if p.get(n) is None) for n in NAMES}
    coverage_days = (rows[-1][0] - rows[0][0]) / 86400.0 if len(rows) > 1 else 0.0
    return {
        "rows": len(rows),
        "coverage_days": coverage_days,
        "missing": missing,
        "stats": stats,
        "gaps": find_gaps(rows, expected_interval, gap_factor),
        "gap_factor": gap_factor,
        "recommended_bps": recommend_bps({p: s["p95"] for p, s in stats.items()}, multiple),
    }


def _fmt(v):
    return "-" if v is None else "%.0f" % v


def report(res, expected_interval, out=None):
    out = out or sys.stdout
    w = out.write
    w("rows: %d   coverage: %.1f days   expected interval: %d s\n" % (res["rows"], res["coverage_days"], expected_interval))
    w("missing per source: %s\n" % "  ".join("%s=%d" % kv for kv in res["missing"].items()))
    w("\npairwise spread (bps = |a-b| * 10^4 / min(a,b)):\n")
    w("%-22s %6s %8s %8s %8s %8s %8s\n" % ("pair", "n", "median", "p90", "p95", "p99", "max"))
    for (a, b), s in res["stats"].items():
        w("%-22s %6d %8s %8s %8s %8s %8s\n" % ("%s/%s" % (a, b), s["n"], _fmt(s["median"]), _fmt(s["p90"]),
                                               _fmt(s["p95"]), _fmt(s["p99"]), _fmt(s["max"])))
    if res["gaps"]:
        w("\ngaps (> %.0fx the interval) in the log: %d\n" % (res["gap_factor"], len(res["gaps"])))
        for t0, t1, secs in res["gaps"][:20]:
            w("  %s -> %s  (%.1f h)\n" % (_iso(t0), _iso(t1), secs / 3600.0))
        if len(res["gaps"]) > 20:
            w("  ... %d more\n" % (len(res["gaps"]) - 20))
    else:
        w("\nno gaps in the log\n")
    w("\n")
    if res["recommended_bps"] is None:
        w("recommended DIVERGE_BPS_ATTEST: no pair has data\n")
        return
    worst = max((s["p95"], p) for p, s in res["stats"].items() if s["p95"] is not None)
    w("worst-pair p95: %.0f bps (%s/%s)\n" % (worst[0], worst[1][0], worst[1][1]))
    w("recommended DIVERGE_BPS_ATTEST ~= 3 x p95 = %d bps (provisional value in the proposal: 1500)\n" % res["recommended_bps"])
    if round(res["coverage_days"], 1) < DEFAULT_DURATION_DAYS:
        w("note: %.1f days logged; the proposal asks for two weeks before the value is fixed\n" % res["coverage_days"])


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def cmd_analyze(args):
    with open(args.csv, newline="") as f:
        rows = read_log(f)
    if not rows:
        sys.stderr.write("%s: no rows\n" % args.csv)
        return 1
    res = analyze(rows, args.interval, args.gap_factor)
    report(res, args.interval)
    return 0


# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log-level", default="INFO")
    sub = p.add_subparsers(dest="cmd", required=True)

    lg = sub.add_parser("log", help="append one row per tick to --out")
    lg.add_argument("--out", required=True, help="CSV to append to (created with a header when empty)")
    lg.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="seconds between ticks (default 300)")
    lg.add_argument("--duration", type=float, default=DEFAULT_DURATION_DAYS, help="days to run; 0 = forever (default 14)")
    lg.add_argument("--once", action="store_true", help="one tick and exit (for cron); exit 1 unless every source answered")
    lg.add_argument("--api-key", help="optional CoinGecko demo API key")
    lg.add_argument("--fetch-timeout", type=float, help="per-request timeout in seconds (default 15)")
    lg.set_defaults(func=cmd_log)

    an = sub.add_parser("analyze", help="spread distribution and the recommended DIVERGE_BPS_ATTEST")
    an.add_argument("csv")
    an.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="the interval the log was taken at (default 300)")
    an.add_argument("--gap-factor", type=float, default=3.0, help="a gap is more than this many intervals between rows")
    an.set_defaults(func=cmd_analyze)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
