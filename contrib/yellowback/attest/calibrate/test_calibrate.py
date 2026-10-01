#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for the two calibration scripts (proposal §16). No network: `spreads.py log` is
driven with PriceFeed._http_get replaced by canned replies, and both analyses run on synthetic
CSVs written to a temporary directory.

Run:  python3 -m unittest contrib/yellowback/attest/calibrate/test_calibrate.py
"""

import importlib.util
import io
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


spreads = _load("spreads")
pinrate = _load("pinrate")
MICRO = spreads.yp.MICRO
HOUR = 3600


def spreads_csv(path, rows):
    """rows: [(ts, cg, st, nk)] in USD floats (None = missing)."""
    with open(path, "w", newline="") as f:
        f.write(",".join(spreads.COLUMNS) + "\n")
        for ts, cg, st, nk in rows:
            cells = ["x", str(ts)] + ["" if v is None else str(int(round(v * MICRO))) for v in (cg, st, nk)] + [""]
            f.write(",".join(cells) + "\n")


class SpreadMath(unittest.TestCase):
    def test_spread_bps_is_relative_to_the_lesser(self):
        self.assertAlmostEqual(spreads.spread_bps(100, 110), 1000.0)
        self.assertAlmostEqual(spreads.spread_bps(110, 100), 1000.0)
        self.assertEqual(spreads.spread_bps(5, 5), 0)

    def test_percentile_nearest_rank(self):
        xs = list(range(1, 101))
        self.assertEqual(spreads.percentile(xs, 95), 95)
        self.assertEqual(spreads.percentile(xs, 50), 50)
        self.assertEqual(spreads.percentile(xs, 100), 100)
        self.assertEqual(spreads.percentile([7], 95), 7)

    def test_recommendation_rounds_up_from_the_worst_pair(self):
        self.assertEqual(spreads.recommend_bps({"a": 120.0, "b": 410.0, "c": None}), 1300)
        self.assertEqual(spreads.recommend_bps({"a": 100.0}), 300)
        self.assertIsNone(spreads.recommend_bps({"a": None}))


class SpreadsAnalyze(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "spreads.csv")

    def tearDown(self):
        self.tmp.cleanup()

    def _rows(self, n, interval=300, st_bps=100, nk_bps=300):
        # coingecko 0.40; safetrade +1 %; nonkyc +3 %; constant spreads so the percentiles are exact
        return [(1_700_000_000 + i * interval, 0.40, 0.40 * (1 + st_bps / 1e4), 0.40 * (1 + nk_bps / 1e4)) for i in range(n)]

    def test_constant_spreads_and_recommendation(self):
        spreads_csv(self.path, self._rows(50))
        with open(self.path, newline="") as f:
            rows = spreads.read_log(f)
        res = spreads.analyze(rows, 300)
        self.assertEqual(res["rows"], 50)
        st = res["stats"][("coingecko", "safetrade")]
        nk = res["stats"][("coingecko", "nonkyc")]
        both = res["stats"][("safetrade", "nonkyc")]
        self.assertEqual(st["n"], 50)
        self.assertAlmostEqual(st["p95"], 100.0, places=6)
        self.assertAlmostEqual(nk["p95"], 300.0, places=6)
        self.assertAlmostEqual(both["p95"], 200 / 1.01, places=6)   # relative to the lesser (safetrade)
        self.assertEqual(res["gaps"], [])
        self.assertEqual(res["recommended_bps"], 900)                # 3 x 300, already a multiple of 100

    def test_missing_sources_are_excluded_not_zero(self):
        rows = self._rows(10)
        rows[3] = (rows[3][0], rows[3][1], None, rows[3][3])         # safetrade down for one tick
        rows[4] = (rows[4][0], None, None, None)                     # everything down
        spreads_csv(self.path, rows)
        with open(self.path, newline="") as f:
            res = spreads.analyze(spreads.read_log(f), 300)
        self.assertEqual(res["missing"], {"coingecko": 1, "safetrade": 2, "nonkyc": 1})
        self.assertEqual(res["stats"][("coingecko", "safetrade")]["n"], 8)
        self.assertEqual(res["stats"][("coingecko", "nonkyc")]["n"], 9)

    def test_gaps_are_flagged(self):
        rows = self._rows(20)
        rows = rows[:10] + [(t + 7200, a, b, c) for t, a, b, c in rows[10:]]   # two hours missing
        spreads_csv(self.path, rows)
        with open(self.path, newline="") as f:
            res = spreads.analyze(spreads.read_log(f), 300)
        self.assertEqual(len(res["gaps"]), 1)
        self.assertEqual(res["gaps"][0][2], 7200 + 300)
        # A 2x interval delay is not a gap at the default factor
        with open(self.path, newline="") as f:
            self.assertEqual(spreads.find_gaps(spreads.read_log(f), 300, factor=30), [])

    def test_p95_takes_the_tail(self):
        rows = self._rows(100)
        # 4 wild ticks (4 %) do not move p95; the 5th (5 %) does under nearest-rank
        for i in range(4):
            rows[i] = (rows[i][0], 0.40, 0.60, 0.40 * 1.03)
        spreads_csv(self.path, rows)
        with open(self.path, newline="") as f:
            res = spreads.analyze(spreads.read_log(f), 300)
        self.assertAlmostEqual(res["stats"][("coingecko", "safetrade")]["p95"], 100.0, places=6)
        self.assertAlmostEqual(res["stats"][("coingecko", "safetrade")]["max"], 5000.0, places=6)

    def test_cli_analyze_end_to_end(self):
        spreads_csv(self.path, self._rows(30))
        out = io.StringIO()
        import contextlib
        with contextlib.redirect_stdout(out):
            rc = spreads.main(["analyze", self.path])
        self.assertEqual(rc, 0)
        self.assertIn("recommended DIVERGE_BPS_ATTEST ~= 3 x p95 = 900 bps", out.getvalue())
        self.assertIn("no gaps", out.getvalue())

    def test_empty_log(self):
        with open(self.path, "w") as f:
            f.write(",".join(spreads.COLUMNS) + "\n")
        self.assertEqual(spreads.main(["analyze", self.path]), 1)


CG_SIMPLE = {"ycash": {"usd": 0.40, "last_updated_at": 1_788_673_030}}
CG_TICKERS = {"tickers": [
    {"market": {"identifier": "safe_trade"}, "target": "USDT", "last": 0.404, "converted_last": {"usd": 0.404},
     "bid_ask_spread_percentage": 1.0, "last_traded_at": "2026-09-05T12:00:00+00:00",
     "is_stale": False, "is_anomaly": False, "volume": 1000.0},
]}
NONKYC = {"lastPriceNumber": 0.412, "bestBidNumber": 0.41, "bestAskNumber": 0.414,
          "lastTradeAt": 1_788_673_030_000, "volumeNumber": 500.0}


class SpreadsLog(unittest.TestCase):
    """`log --once` with the HTTP layer replaced: one row, the three columns, errors recorded."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "log.csv")
        self.orig = spreads.yp.PriceFeed._http_get

    def tearDown(self):
        spreads.yp.PriceFeed._http_get = self.orig
        self.tmp.cleanup()

    def _canned(self, replies):
        def _get(url, headers, timeout):
            for key, obj in replies.items():
                if key in url:
                    if isinstance(obj, Exception):
                        raise obj
                    return json.dumps(obj).encode()
            raise AssertionError("unexpected fetch %s" % url)
        spreads.yp.PriceFeed._http_get = staticmethod(_get)

    def test_once_writes_header_and_row(self):
        self._canned({"simple/price": CG_SIMPLE, "/tickers": CG_TICKERS, "nonkyc": NONKYC})
        self.assertEqual(spreads.main(["--log-level", "WARNING", "log", "--out", self.path, "--once"]), 0)
        self.assertEqual(spreads.main(["--log-level", "WARNING", "log", "--out", self.path, "--once"]), 0)
        with open(self.path, newline="") as f:
            lines = f.read().splitlines()
        self.assertEqual(lines[0], ",".join(spreads.COLUMNS))
        self.assertEqual(len(lines), 3)                              # header once, two rows
        with open(self.path, newline="") as f:
            rows = spreads.read_log(f)
        self.assertEqual(rows[0][1], {"coingecko": 400_000, "safetrade": 404_000, "nonkyc": 412_000})
        res = spreads.analyze(rows, 300)
        self.assertAlmostEqual(res["stats"][("coingecko", "safetrade")]["p95"], 100.0, places=6)

    def test_once_with_a_failed_source_exits_1_and_logs_the_error(self):
        self._canned({"simple/price": CG_SIMPLE, "/tickers": CG_TICKERS, "nonkyc": OSError("connection refused")})
        self.assertEqual(spreads.main(["--log-level", "ERROR", "log", "--out", self.path, "--once"]), 1)
        with open(self.path, newline="") as f:
            raw = f.read().splitlines()
        self.assertIn("nonkyc: fetch: connection refused", raw[1])
        with open(self.path, newline="") as f:
            rows = spreads.read_log(f)
        self.assertIsNone(rows[0][1]["nonkyc"])
        self.assertEqual(rows[0][1]["coingecko"], 400_000)


def series(prices, step=HOUR, t0=1_700_000_000):
    return [(t0 + i * step, p) for i, p in enumerate(prices)]


class PinRate(unittest.TestCase):
    def test_windows_cover_exactly_six_hours(self):
        s = series([1.0] * 24)
        wins = pinrate.rolling_windows(s, 6 * HOUR)
        # the first full window ends at the 7th sample (t0 + 6 h) and holds 6 samples (t0 + 1 h .. t0 + 6 h]
        self.assertEqual(len(wins), 24 - 6)
        self.assertEqual(wins[0][0], s[6][0])
        self.assertEqual(len(wins[0][1]), 6)
        self.assertEqual(wins[0][2], s[0][1])                        # PIN-2's other endpoint: the sample 6 h back
        self.assertEqual(pinrate.rolling_windows(s[:6], 6 * HOUR), [])

    def test_flat_history_never_arms(self):
        res = pinrate.analyze(series([0.40] * 100))
        self.assertEqual(res["windows"], 94)
        self.assertEqual(res["rates"][500]["rate"], 0.0)
        self.assertEqual(res["rates"][500]["longest_quiet_windows"], 94)
        self.assertEqual(res["decision"], "drop")
        self.assertEqual(set(res["rates"]), {500, 200, 300})

    def test_sawtooth_always_arms(self):
        # +8 % every other hour: every 6-hour window spans both levels
        res = pinrate.analyze(series([0.40, 0.432] * 50))
        self.assertEqual(res["rates"][500]["rate"], 1.0)
        self.assertEqual(res["rates"][500]["longest_quiet_windows"], 0)
        self.assertEqual(res["decision"], "confirm")
        # the endpoint form (PIN-2) compares prices exactly 6 h apart: same parity, so never
        self.assertEqual(res["rates"][500]["rate_endpoints"], 0.0)
        # ... and with a 5-hour window it always does
        res = pinrate.analyze(series([0.40, 0.432] * 50), window_blocks=240)
        self.assertEqual(res["rates"][500]["rate_endpoints"], 1.0)

    def test_one_step_arms_a_window_of_windows_and_the_quiet_run_is_the_rest(self):
        prices = [0.40] * 50 + [0.44] * 50                          # one +10 % step at hour 50
        res = pinrate.analyze(series(prices))
        # windows ending at hours 50..54 hold both levels (a window is (end-6h, end], six hourly samples)
        self.assertEqual(res["rates"][500]["armed"], 5)
        # 94 windows end at hours 6..99: 44 quiet before the step, 45 quiet after it
        self.assertEqual(res["rates"][500]["longest_quiet_windows"], 45)
        self.assertEqual(res["rates"][500]["longest_quiet_seconds"], 45 * HOUR)
        # PIN-2 (endpoints 6 h apart) arms for the six windows whose start is before the step and end at or after it
        self.assertAlmostEqual(res["rates"][500]["rate_endpoints"], 6 / 94)
        self.assertEqual(res["decision"], "inconclusive")           # 5 / 94 = 5.3 %, just above the drop line
        self.assertEqual(pinrate.analyze(series(prices + [0.44] * 100))["decision"], "drop")   # 5 / 194
        # a 3 % step arms at 200 but not at 300 or 500
        res = pinrate.analyze(series([0.40] * 50 + [0.412] * 50))
        self.assertEqual(res["rates"][200]["armed"], 5)
        self.assertEqual(res["rates"][300]["armed"], 0)
        self.assertEqual(res["rates"][500]["armed"], 0)

    def test_window_is_parameterised_in_blocks(self):
        prices = [0.40] * 50 + [0.44] * 50
        res = pinrate.analyze(series(prices), window_blocks=96, block_seconds=75)   # 2 h
        self.assertEqual(res["window_seconds"], 7200)
        self.assertEqual(res["rates"][500]["armed"], 1)              # only the window ending at hour 50 holds both levels

    def test_inconclusive_band(self):
        # one step every 40 hours arms 5 of every 40 windows: 12.5 %
        prices = []
        for k in range(10):
            prices += [0.40 if k % 2 == 0 else 0.44] * 40
        res = pinrate.analyze(series(prices))
        self.assertEqual(res["decision"], "inconclusive")
        self.assertTrue(0.05 <= res["rates"][500]["rate"] <= 0.20)

    def test_csv_round_trip_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "hist.csv")
            saved = os.path.join(d, "saved.csv")
            s = series([0.40, 0.432] * 20)
            with open(path, "w", newline="") as f:
                f.write("ts,price_usd,ignored\n")
                for ts, p in reversed(s):                            # unsorted on purpose
                    f.write("%d,%r,x\n" % (ts, p))
                f.write("garbage,row\n")
            with open(path, newline="") as f:
                self.assertEqual(pinrate.read_csv(f), s)
            out = io.StringIO()
            import contextlib
            with contextlib.redirect_stdout(out):
                rc = pinrate.main(["--from-csv", path, "--save-csv", saved])
            self.assertEqual(rc, 0)
            self.assertIn("confirmed", out.getvalue())
            with open(saved, newline="") as f:
                self.assertEqual(pinrate.read_csv(f), s)             # ts_iso,ts,price_usd shape reads back
            with open(saved, newline="") as f:
                self.assertTrue(f.readline().startswith("ts_iso,ts,price_usd"))

    def test_too_short_history(self):
        res = pinrate.analyze(series([0.4, 0.5, 0.6]))
        self.assertEqual(res["windows"], 0)
        self.assertEqual(res["rates"], {})
        self.assertIsNone(res["decision"])


if __name__ == "__main__":
    unittest.main()
