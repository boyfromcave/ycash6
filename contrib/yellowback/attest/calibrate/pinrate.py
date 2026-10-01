#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Calibrate PIN_WINDOW / PIN_DELTA_BPS (proposal §16, measurement 2; §10.1 responsiveness test).

Over an hourly YEC/USD history, for every rolling window of PIN_WINDOW blocks (288 x 75 s = 6 h
by default) compute whether the window "armed": PIN-1's form, (hi - lo) * 10^4 > delta * lo over
the prices inside the window. The arming rate is the fraction of windows that armed; the report
also gives the longest run of consecutive un-armed windows (the longest a pinned constant quote
could have gone unnoticed) and, for reference, PIN-2's endpoint form (the two ends of the window
differ by more than delta).

Decision rule (proposal §16): arming rate above ~20 % confirms 288 / 500; below ~5 % drop
PIN_DELTA_BPS to 200-300. The rates at 200 and 300 bps are printed alongside so the choice
between them needs no second run.

History comes from CoinGecko's market_chart (hourly for 2..90 days; `--days`) or from a CSV
(`--from-csv`, columns `ts,price_usd` or `ts_iso,ts,price_usd`; extra columns ignored), which is
also how the analysis is tested offline. `--save-csv` writes what was fetched in that shape.
Standard library plus yellowback_price.py; Python >= 3.11; run through the workspace venv.
"""

import argparse
import csv
import datetime
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("yellowback_price", os.path.join(HERE, "..", "..", "yellowback_price.py"))
yp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(yp)

DEFAULT_WINDOW_BLOCKS = 288     # PIN_WINDOW (proposal §10.1)
DEFAULT_BLOCK_SECONDS = 75      # Ycash block target
DEFAULT_DELTA_BPS = 500         # PIN_DELTA_BPS
CONFIRM_RATE = 0.20
DROP_RATE = 0.05
ALT_DELTAS = (200, 300)
CG_URL = "https://api.coingecko.com/api/v3/coins/%s/market_chart?vs_currency=usd&days=%d"


# ---------------------------------------------------------------------------
# input

def fetch_history(coin="ycash", days=90, api_key=None, timeout=30):
    """[(ts_seconds, price_usd)] from CoinGecko market_chart (hourly granularity for 2..90 days)."""
    headers = {"x-cg-demo-api-key": api_key} if api_key else {}
    raw = yp.PriceFeed._http_get(CG_URL % (coin, days), headers, timeout)
    obj = json.loads(raw.decode())
    return normalize_series([(int(ms) // 1000, float(p)) for ms, p in obj["prices"]])


def read_csv(fp):
    """[(ts, price_usd)] from a CSV with `ts` (or `ts_iso`) and `price_usd` columns. Bad rows are skipped."""
    out = []
    for rec in csv.DictReader(fp):
        try:
            if rec.get("ts"):
                ts = int(float(rec["ts"]))
            else:
                ts = int(datetime.datetime.fromisoformat(rec["ts_iso"].replace("Z", "+00:00")).timestamp())
            price = float(rec["price_usd"])
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
        if price > 0:
            out.append((ts, price))
    return normalize_series(out)


def write_csv(fp, series):
    w = csv.writer(fp)
    w.writerow(["ts_iso", "ts", "price_usd"])
    for ts, p in series:
        w.writerow([_iso(ts), ts, repr(p)])


def normalize_series(series):
    """Ascending, one sample per timestamp."""
    return sorted({ts: p for ts, p in series}.items())


# ---------------------------------------------------------------------------
# analysis (pure)

def rolling_windows(series, window_seconds):
    """For every sample as the window's end: (end_ts, [prices in (end - window, end]], price at the
    window's start) -- the start price is the last sample at or before end - window, PIN-2's other
    endpoint. Windows that do not yet reach back a full window (the first `window_seconds` of data)
    are skipped."""
    out = []
    start = 0
    for i, (t_end, _) in enumerate(series):
        while series[start][0] <= t_end - window_seconds:
            start += 1
        if start == 0:
            continue
        out.append((t_end, [p for _, p in series[start:i + 1]], series[start - 1][1]))
    return out


def armed_range(prices, delta_bps):
    """PIN-1: (hi - lo) * 10^4 > delta * lo."""
    lo, hi = min(prices), max(prices)
    return (hi - lo) * 10_000 > delta_bps * lo


def armed_endpoints(p_start, p_end, delta_bps):
    """PIN-2: the prices one window apart differ by more than delta (relative to the lesser)."""
    return abs(p_start - p_end) * 10_000 > delta_bps * min(p_start, p_end)


def longest_run(flags):
    """Longest run of consecutive False values."""
    best = cur = 0
    for f in flags:
        cur = 0 if f else cur + 1
        best = max(best, cur)
    return best


def analyze(series, window_blocks=DEFAULT_WINDOW_BLOCKS, block_seconds=DEFAULT_BLOCK_SECONDS,
            delta_bps=DEFAULT_DELTA_BPS, alt_deltas=ALT_DELTAS):
    window_seconds = window_blocks * block_seconds
    windows = rolling_windows(series, window_seconds)
    res = {"samples": len(series), "windows": len(windows), "window_seconds": window_seconds,
           "delta_bps": delta_bps, "coverage_days": 0.0, "step_seconds": None, "rates": {}, "decision": None}
    if len(series) > 1:
        res["coverage_days"] = (series[-1][0] - series[0][0]) / 86400.0
        res["step_seconds"] = (series[-1][0] - series[0][0]) / (len(series) - 1)
    if not windows:
        return res
    for d in (delta_bps,) + tuple(x for x in alt_deltas if x != delta_bps):
        flags = [armed_range(ps, d) for _, ps, _ in windows]
        ends = [armed_endpoints(p0, ps[-1], d) for _, ps, p0 in windows]
        run = longest_run(flags)
        res["rates"][d] = {
            "armed": sum(flags), "rate": sum(flags) / len(flags),
            "rate_endpoints": sum(ends) / len(ends),
            "longest_quiet_windows": run,
            # consecutive windows step by one sample, so a quiet run spans run x step (+ the window itself)
            "longest_quiet_seconds": (run * res["step_seconds"] if res["step_seconds"] else None),
        }
    rate = res["rates"][delta_bps]["rate"]
    if rate > CONFIRM_RATE:
        res["decision"] = "confirm"
    elif rate < DROP_RATE:
        res["decision"] = "drop"
    else:
        res["decision"] = "inconclusive"
    return res


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def report(res, window_blocks, block_seconds, out=None):
    out = out or sys.stdout
    w = out.write
    w("samples: %d   coverage: %.1f days   step: %s   window: %d blocks x %d s = %.1f h   rolling windows: %d\n" % (
        res["samples"], res["coverage_days"],
        "-" if res["step_seconds"] is None else "%.0f s" % res["step_seconds"],
        window_blocks, block_seconds, res["window_seconds"] / 3600.0, res["windows"]))
    if not res["rates"]:
        w("not enough history for one window\n")
        return
    w("\n%-10s %8s %10s %14s %20s\n" % ("delta_bps", "armed", "rate", "rate(PIN-2)", "longest quiet run"))
    for d, r in sorted(res["rates"].items()):
        quiet = "%d windows" % r["longest_quiet_windows"]
        if r["longest_quiet_seconds"] is not None:
            quiet += " (%.1f h)" % (r["longest_quiet_seconds"] / 3600.0)
        w("%-10d %8d %9.1f%% %13.1f%% %20s\n" % (d, r["armed"], 100 * r["rate"], 100 * r["rate_endpoints"], quiet))
    d = res["delta_bps"]
    rate = res["rates"][d]["rate"]
    w("\n")
    if res["decision"] == "confirm":
        w("arming rate %.1f%% at %d bps > %.0f%%: PIN_WINDOW = %d / PIN_DELTA_BPS = %d confirmed\n" % (
            100 * rate, d, 100 * CONFIRM_RATE, window_blocks, d))
    elif res["decision"] == "drop":
        w("arming rate %.1f%% at %d bps < %.0f%%: drop PIN_DELTA_BPS to 200-300 (rates above)\n" % (
            100 * rate, d, 100 * DROP_RATE))
    else:
        w("arming rate %.1f%% at %d bps is between %.0f%% and %.0f%%: inconclusive; the proposal biases larger, "
          "so keep %d unless the longest quiet run is unacceptable\n" % (
              100 * rate, d, 100 * DROP_RATE, 100 * CONFIRM_RATE, d))
    if res["coverage_days"] < 14:
        w("note: %.1f days of history; use at least two weeks (--days 90 gives CoinGecko's full hourly range)\n" % res["coverage_days"])


# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group()
    src.add_argument("--from-csv", help="hourly history CSV (ts,price_usd) instead of CoinGecko")
    src.add_argument("--days", type=int, default=90, help="CoinGecko market_chart range, 2..90 for hourly points (default 90)")
    p.add_argument("--coin", default="ycash", help="CoinGecko coin id (default ycash)")
    p.add_argument("--api-key", help="optional CoinGecko demo API key")
    p.add_argument("--save-csv", help="write the fetched (or read) history here in --from-csv's shape")
    p.add_argument("--window-blocks", type=int, default=DEFAULT_WINDOW_BLOCKS, help="PIN_WINDOW (default 288)")
    p.add_argument("--block-seconds", type=int, default=DEFAULT_BLOCK_SECONDS, help="block target (default 75)")
    p.add_argument("--delta-bps", type=int, default=DEFAULT_DELTA_BPS, help="PIN_DELTA_BPS under test (default 500)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.window_blocks < 1 or args.block_seconds < 1 or args.delta_bps < 1:
        sys.stderr.write("window-blocks, block-seconds and delta-bps must be >= 1\n")
        return 2
    if args.from_csv:
        with open(args.from_csv, newline="") as f:
            series = read_csv(f)
    else:
        if not 2 <= args.days <= 90:
            sys.stderr.write("--days must be 2..90 for hourly granularity\n")
            return 2
        series = fetch_history(args.coin, args.days, args.api_key)
    if len(series) < 2:
        sys.stderr.write("fewer than two samples\n")
        return 1
    if args.save_csv:
        with open(args.save_csv, "w", newline="") as f:
            write_csv(f, series)
    res = analyze(series, args.window_blocks, args.block_seconds, args.delta_bps)
    report(res, args.window_blocks, args.block_seconds)
    return 0


if __name__ == "__main__":
    sys.exit(main())
