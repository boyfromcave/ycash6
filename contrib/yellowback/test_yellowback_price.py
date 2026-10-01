#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Unit tests for the price-source layer and the coinbase-tag codec (plan §5, §3.2).

No node, no network: every HTTP fetch is replaced by a table of canned
replies. The CoinGecko and Nonkyc fixtures are trimmed copies of real
replies captured on 2026-09-05, the SafeTrade (Peatio) fixture likewise.

Run:  python3 -m unittest contrib/yellowback/test_yellowback_price.py
"""

import copy
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("yellowback_price", os.path.join(HERE, "yellowback_price.py"))
yp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(yp)

MICRO = yp.MICRO
NOW = 1_788_673_100.0

CG_SIMPLE = {"ycash": {"usd": 0.432007, "btc": 5.41e-06, "last_updated_at": 1788673030}}

CG_TICKERS = {"name": "Ycash", "tickers": [
    {"base": "YEC", "target": "USDT", "market": {"name": "SafeTrade", "identifier": "safe_trade"},
     "last": 0.43, "volume": 16077.362, "converted_last": {"btc": 5.38e-06, "usd": 0.429996},
     "bid_ask_spread_percentage": 14.891806, "last_traded_at": "2026-09-06T05:34:00+00:00",
     "is_anomaly": False, "is_stale": False},
    {"base": "YEC", "target": "USDT", "market": {"name": "Nonkyc.io", "identifier": "nonkyc_io"},
     "last": 0.4374, "volume": 6835.5782, "converted_last": {"btc": 5.47e-06, "usd": 0.437398},
     "bid_ask_spread_percentage": 1.281171, "last_traded_at": "2026-09-06T05:35:24Z",
     "is_anomaly": False, "is_stale": False},
    {"base": "YEC", "target": "BTC", "market": {"name": "Nonkyc.io", "identifier": "nonkyc_io"},
     "last": 5.356e-06, "volume": 1022.5283, "converted_last": {"btc": 5.356e-06, "usd": 0.428},
     "bid_ask_spread_percentage": 0.354742, "last_traded_at": "2026-09-06T05:35:24+00:00",
     "is_anomaly": False, "is_stale": False},
]}

NONKYC = {"symbol": "YEC/USDT", "lastPrice": "0.4426", "lastPriceNumber": 0.4426,
          "bestBidNumber": 0.4425, "bestAskNumber": 0.4466, "spreadPercent": "0.918",
          "spreadPercentNumber": 0.918, "lastTradeAt": 1788673068806, "updatedAt": 1788673069029}

PEATIO = {"id": "yecusdt", "name": "YEC/USDT", "base_unit": "yec", "quote_unit": "usdt", "avg_price": "0.41406",
          "high": "0.43", "last": "0.43", "low": "0.38", "open": "0.4", "price_change_percent": "+7.50%",
          "volume": "6613.51997911", "amount": "16041.975"}

NONKYC_BTC = {"symbol": "YEC/BTC", "lastPriceNumber": 5.57e-06, "bestBidNumber": 5.51e-06, "bestAskNumber": 5.586e-06,
              "lastTradeAt": 1788673915214, "volumeNumber": 989.3724}
NONKYC_BTCUSDT = {"symbol": "BTC/USDT", "lastPriceNumber": 79990.24, "bestBidNumber": 79453.71, "bestAskNumber": 80200,
                  "lastTradeAt": 1788674017285}
CG_BTC = {"bitcoin": {"usd": 79993, "last_updated_at": 1788673920}}
KRAKEN = {"error": [], "result": {"XXBTZUSD": {"a": ["79997.30000", "1", "1.000"], "b": ["79997.20000", "1", "1.000"],
                                               "c": ["79997.30000", "0.00008394"]}}}
COINBASE = {"price": "79996.81", "bid": "79996.8", "ask": "79996.81", "time": "2026-09-06T05:53:57.841478937Z"}
BTC_REF_USD = sorted([79993, 79990.24, 79997.30, 79996.81])
BTC_REF_USD = (BTC_REF_USD[1] + BTC_REF_USD[2]) / 2      # median of four

BTC_SOURCES = [
    {"name": "coingecko-btc", "kind": "coingecko_simple", "coin": "bitcoin", "max_age": 900},
    {"name": "nonkyc-btc", "kind": "nonkyc_market", "symbol": "BTC_USDT", "max_age": 3600},
    {"name": "kraken", "kind": "kraken_ticker"},
    {"name": "coinbase", "kind": "coinbase_ticker", "max_age": 600},
]
BTC_TABLE = {
    "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin": CG_BTC,
    "https://api.nonkyc.io/api/v2/market/getbysymbol/BTC_USDT": NONKYC_BTCUSDT,
    "https://api.kraken.com/0/public/Ticker?pair=XBTUSD": KRAKEN,
    "https://api.exchange.coinbase.com/products/BTC-USD/ticker": COINBASE,
    "https://api.nonkyc.io/api/v2/market/getbysymbol/YEC_BTC": NONKYC_BTC,
}

THREE = [
    {"name": "coingecko", "kind": "coingecko_simple", "max_age": 900},
    {"name": "safetrade", "kind": "coingecko_ticker", "market": "safe_trade", "target": "USDT", "max_age": 3600},
    {"name": "nonkyc", "kind": "nonkyc_market", "max_age": 3600, "max_spread_bps": 500},
]
TABLE = {
    "https://api.coingecko.com/api/v3/simple/price?ids=ycash": CG_SIMPLE,
    "https://api.coingecko.com/api/v3/coins/ycash/tickers": CG_TICKERS,
    "https://api.nonkyc.io/api/v2/market/getbysymbol/YEC_USDT": NONKYC,
}
NONKYC_URL = "https://api.nonkyc.io/api/v2/market/getbysymbol/YEC_USDT"


class FakeHTTP:
    """Maps URL -> JSON object or bytes or Exception."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, headers))
        for prefix, reply in self.table.items():
            if url.startswith(prefix):
                if isinstance(reply, Exception):
                    raise reply
                if isinstance(reply, bytes):
                    return reply
                return yp.json.dumps(reply).encode()
        raise OSError("no fixture for %s" % url)


def make_feed(sources, table, btc_sources=None, **settings):
    feed = yp.PriceFeed(sources, None, dict(yp.FEED_DEFAULTS, **settings), btc_sources)
    http = FakeHTTP(table)
    feed._http_get = http
    feed.http = http
    return feed


class ExtractTests(unittest.TestCase):
    def test_dotted_and_index(self):
        self.assertEqual(yp.extract(CG_SIMPLE, "ycash.usd"), 0.432007)
        self.assertEqual(yp.extract(CG_TICKERS, "tickers.1.target"), "USDT")

    def test_selector_is_order_independent(self):
        path = "tickers.[market.identifier=nonkyc_io,target=USDT].converted_last.usd"
        self.assertEqual(yp.extract(CG_TICKERS, path), 0.437398)
        reordered = copy.deepcopy(CG_TICKERS)
        reordered["tickers"].reverse()
        self.assertEqual(yp.extract(reordered, path), 0.437398)
        self.assertEqual(yp.extract(reordered, "tickers.[market.identifier=nonkyc_io,target=BTC].last"), 5.356e-06)

    def test_shape_errors(self):
        with self.assertRaises(yp.ShapeError):
            yp.extract(CG_SIMPLE, "ycash.eur")
        with self.assertRaises(yp.ShapeError):
            yp.extract(CG_TICKERS, "tickers.[market.identifier=binance,target=USDT].last")
        with self.assertRaises(yp.ShapeError):
            yp.extract(CG_TICKERS, "tickers.[market.identifier=nonkyc_io].converted_last.usd.deeper")
        with self.assertRaises(yp.ShapeError):
            yp.extract_number(CG_TICKERS, "tickers.0.market.name")

    def test_timestamps(self):
        self.assertEqual(yp.extract_timestamp(CG_SIMPLE, "ycash.last_updated_at", "s"), 1788673030)
        self.assertAlmostEqual(yp.extract_timestamp(NONKYC, "lastTradeAt", "ms"), 1788673068.806, places=3)
        iso_plus = yp.extract_timestamp(CG_TICKERS, "tickers.0.last_traded_at", "iso")
        iso_z = yp.extract_timestamp(CG_TICKERS, "tickers.1.last_traded_at", "iso")
        self.assertEqual(iso_z - iso_plus, 84)
        self.assertAlmostEqual(yp.extract_timestamp(COINBASE, "time", "iso") % 1, 0.841478, places=5)

    def test_spread(self):
        sel = "tickers.[market.identifier=safe_trade,target=USDT]"
        src = yp.normalize_source({"name": "x", "url": "u", "path": "p", "spread_path": sel + ".bid_ask_spread_percentage"})
        self.assertAlmostEqual(yp.spread_bps(CG_TICKERS, src), 1489.18, places=1)
        src = yp.normalize_source({"name": "x", "url": "u", "path": "p", "bid_path": "bestBidNumber", "ask_path": "bestAskNumber"})
        self.assertAlmostEqual(yp.spread_bps(NONKYC, src), 92.2, places=0)
        src = yp.normalize_source({"name": "x", "url": "u", "path": "p"})
        self.assertIsNone(yp.spread_bps(NONKYC, src))


class ConfigTests(unittest.TestCase):
    def test_presets_expand_and_override(self):
        s = yp.normalize_source({"name": "cg", "kind": "coingecko_simple"})
        self.assertIn("ids=ycash&vs_currencies=usd", s["url"])
        self.assertEqual((s["path"], s["timestamp_path"], s["venue"], s["quote"]), ("ycash.usd", "ycash.last_updated_at", "coingecko", "USD"))
        s = yp.normalize_source({"name": "cg-btc", "kind": "coingecko_simple", "vs": "btc"})
        self.assertEqual((s["path"], s["quote"]), ("ycash.btc", "BTC"))
        s = yp.normalize_source({"name": "st", "kind": "coingecko_ticker", "market": "safe_trade", "target": "USDT", "api_key": "k"})
        self.assertEqual(s["path"], "tickers.[market.identifier=safe_trade,target=USDT].converted_last.usd")
        self.assertEqual(s["venue"], "safe_trade")
        self.assertEqual(s["headers"], {"x-cg-demo-api-key": "k"})
        self.assertEqual(len(s["reject_paths"]), 2)
        self.assertEqual(s["volume_path"], "tickers.[market.identifier=safe_trade,target=USDT].volume")
        s = yp.normalize_source({"name": "st-btc", "kind": "coingecko_ticker", "market": "safe_trade", "target": "BTC"})
        self.assertEqual((s["path"], s["quote"]), ("tickers.[market.identifier=safe_trade,target=BTC].last", "BTC"))
        s = yp.normalize_source({"name": "kr", "kind": "kraken_ticker"})
        self.assertEqual((s["url"], s["path"], s["bid_path"], s["venue"]), ("https://api.kraken.com/0/public/Ticker?pair=XBTUSD", "result.XXBTZUSD.c.0", "result.XXBTZUSD.b.0", "kraken"))
        s = yp.normalize_source({"name": "cb", "kind": "coinbase_ticker"})
        self.assertEqual((s["path"], s["timestamp_path"], s["timestamp_unit"]), ("price", "time", "iso"))
        with self.assertRaises(ValueError):                       # a BTC/USD reference must be USD-quoted
            yp.normalize_btc_sources([{"name": "x", "kind": "nonkyc_market", "symbol": "YEC_BTC"}])
        s = yp.normalize_source({"name": "nk", "kind": "nonkyc_market", "symbol": "YEC_BTC", "path": "bestBidNumber"})
        self.assertEqual((s["quote"], s["path"], s["timestamp_unit"], s["volume_path"]), ("BTC", "bestBidNumber", "ms", "volumeNumber"))
        s = yp.normalize_source({"name": "st", "kind": "peatio_ticker", "base_url": "https://mirror.example"})
        self.assertEqual(s["url"], "https://mirror.example/api/v2/trade/public/tickers/yecusdt")
        self.assertEqual((s["path"], s["quote"], s.get("timestamp_path")), ("last", "USD", None))
        with self.assertRaises(ValueError):                       # no timestamp in this API: max_age is refused
            yp.normalize_source({"name": "st", "kind": "peatio_ticker", "max_age": 60})
        s = yp.normalize_source({"name": "g", "url": "https://x", "path": "a.b", "venue": "v"})
        self.assertEqual((s["kind"], s["venue"], s["scale"]), ("generic", "v", 1))

    def test_rejects(self):
        bad = [
            {"name": "a"},                                                     # no url/path
            {"name": "a", "url": "u", "path": "p", "kind": "binance"},         # unknown kind
            {"name": "a", "url": "u", "path": "p", "quote": "EUR"},
            {"name": "a", "url": "u", "path": "p", "timestamp_unit": "ns", "timestamp_path": "t"},
            {"name": "a", "url": "u", "path": "p", "max_age": 60},             # needs timestamp_path
            {"name": "a", "url": "u", "path": "p", "max_spread_bps": 10},      # needs spread or bid/ask
            {"name": "a", "url": "u", "path": "p", "typo": 1},
            {"name": "a", "url": "u", "path": "p", "mask_bit": 16},            # registry is 16 bits
            {"name": "a", "url": "u", "path": "p", "mask_bit": "3"},
            {"url": "u", "path": "p"},                                         # no name
        ]
        for b in bad:
            with self.assertRaises(ValueError, msg=repr(b)):
                yp.normalize_source(b)
        with self.assertRaises(ValueError):
            yp.normalize_sources([{"name": "a", "url": "u", "path": "p"}, {"name": "a", "url": "v", "path": "p"}])

    def test_feed_settings(self):
        st = yp.feed_settings({"min_sources": "2", "poll_seconds": 5})
        self.assertEqual((st["min_sources"], st["poll_seconds"], st["min_venues"], st["twap_seconds"]), (2, 5, 2, 900))
        with self.assertRaises(ValueError):
            yp.feed_settings({"min_venues": 0})
        with self.assertRaises(ValueError):
            yp.feed_settings({"twap_seconds": 0})


class MaskTests(unittest.TestCase):
    # Rule: §5 source-mask bit registry
    def test_registry(self):
        self.assertEqual(yp.MASK_BITS, {"safe_trade": 0, "coingecko": 1, "coinmarketcap": 2, "nonkyc_io": 3})
        srcs = yp.normalize_sources(THREE)
        self.assertEqual([yp.mask_bit_for(s) for s in srcs], [1, 0, 3])
        self.assertEqual(yp.source_mask(srcs), 0b1011)

    def test_override_and_unregistered(self):
        g = yp.normalize_source({"name": "g", "url": "u", "path": "p"})
        self.assertIsNone(yp.mask_bit_for(g))                     # an unknown venue sets no bit
        self.assertEqual(yp.source_mask([g]), 0)
        g = yp.normalize_source({"name": "g", "url": "u", "path": "p", "mask_bit": 7})
        self.assertEqual(yp.source_mask([g]), 1 << 7)
        nk = yp.normalize_source({"name": "nk", "kind": "nonkyc_market", "mask_bit": 5})   # override beats the preset
        self.assertEqual(yp.mask_bit_for(nk), 5)
        # the same venue read twice (CoinGecko's Nonkyc ticker and Nonkyc's API) sets one bit
        both = yp.normalize_sources([{"name": "a", "kind": "nonkyc_market"},
                                     {"name": "b", "kind": "coingecko_ticker", "market": "nonkyc_io"}])
        self.assertEqual(yp.source_mask(both), 1 << 3)


class FeedTests(unittest.TestCase):
    def setUp(self):
        self._time = yp.time.time
        yp.time.time = lambda: NOW

    def tearDown(self):
        yp.time.time = self._time

    def test_three_sources_two_venues(self):
        feed = make_feed(THREE, TABLE)
        feed.poll(force=True)
        r = feed.report()
        self.assertEqual([r["sources"][n]["state"] for n in ("coingecko", "safetrade", "nonkyc")], ["ok"] * 3)
        self.assertEqual((r["live_sources"], r["live_venues"]), (3, 3))
        expected = sorted([432007, 429996, 442600])[1]
        self.assertEqual(feed.median_micro_usd(), expected)
        self.assertEqual(feed.aggregate(), (expected, 0b1011, ["coingecko", "safetrade", "nonkyc"]))
        self.assertEqual((r["median_micro_usd"], r["source_mask"]), (expected, 0b1011))
        self.assertAlmostEqual(r["sources"]["nonkyc"]["last_spread_bps"], 92.2, places=0)
        self.assertEqual(r["sources"]["coingecko"]["last_age_seconds"], NOW - 1788673030)

    def test_poll_interval_and_force(self):
        feed = make_feed(THREE, TABLE, poll_seconds=30)
        feed.poll()
        feed.poll()
        self.assertEqual(len(feed.http.calls), 3)
        feed.poll(force=True)
        self.assertEqual(len(feed.http.calls), 6)

    def test_reordered_tickers_still_resolve(self):
        table = dict(TABLE)
        reordered = copy.deepcopy(CG_TICKERS)
        reordered["tickers"].reverse()
        table["https://api.coingecko.com/api/v3/coins/ycash/tickers"] = reordered
        feed = make_feed(THREE, table)
        feed.poll(force=True)
        self.assertEqual(feed.report()["sources"]["safetrade"]["last_price_micro_usd"], 429996)

    def test_stale_source_is_dropped(self):
        table = dict(TABLE)
        old = copy.deepcopy(NONKYC)
        old["lastTradeAt"] = int((NOW - 2 * 3600) * 1000)
        table[NONKYC_URL] = old
        feed = make_feed(THREE, table)
        feed.poll(force=True)
        r = feed.report()
        self.assertEqual(r["sources"]["nonkyc"]["state"], "stale")
        self.assertEqual(r["live_sources"], 2)
        self.assertIsNone(feed.median_micro_usd())               # below min_sources = 3
        feed2 = make_feed(THREE, table, min_sources=2)
        feed2.poll(force=True)
        self.assertEqual(feed2.median_micro_usd(), (432007 + 429996) // 2 + ((432007 + 429996) % 2))
        self.assertEqual(feed2.aggregate()[1], 0b0011)           # the mask names only the contributors

    def test_spread_guard(self):
        srcs = copy.deepcopy(THREE)
        srcs[1]["max_spread_bps"] = 1000                          # SafeTrade's fixture spread is 1489 bps
        feed = make_feed(srcs, TABLE, min_sources=2)
        feed.poll(force=True)
        r = feed.report()
        self.assertEqual(r["sources"]["safetrade"]["state"], "spread")
        self.assertEqual(r["live_sources"], 2)

    def test_flagged_ticker_is_rejected(self):
        table = dict(TABLE)
        flagged = copy.deepcopy(CG_TICKERS)
        flagged["tickers"][0]["is_anomaly"] = True
        table["https://api.coingecko.com/api/v3/coins/ycash/tickers"] = flagged
        feed = make_feed(THREE, table, min_sources=2)
        feed.poll(force=True)
        self.assertEqual(feed.report()["sources"]["safetrade"]["state"], "flagged")

    def test_shape_change_is_classified(self):
        table = dict(TABLE)
        table[NONKYC_URL] = {"symbol": "YEC/USDT", "last": "0.44"}
        table["https://api.coingecko.com/api/v3/simple/price?ids=ycash"] = b"<!DOCTYPE html><title>Attention Required! | Cloudflare</title>"
        feed = make_feed(THREE, table)
        feed.poll(force=True)
        r = feed.report()
        self.assertEqual(r["sources"]["nonkyc"]["state"], "shape")
        self.assertIn("lastPriceNumber", r["sources"]["nonkyc"]["last_error"])
        self.assertEqual(r["sources"]["coingecko"]["state"], "shape")
        self.assertIn("not JSON", r["sources"]["coingecko"]["last_error"])
        self.assertIsNone(feed.median_micro_usd())

    def test_fetch_failure_and_recovery(self):
        table = dict(TABLE)
        table[NONKYC_URL] = OSError("connection refused")
        feed = make_feed(THREE, table)
        feed.poll(force=True)
        self.assertEqual(feed.report()["sources"]["nonkyc"]["state"], "fetch")
        feed.http.table = dict(TABLE)
        feed.poll(force=True)
        h = feed.report()["sources"]["nonkyc"]
        self.assertEqual((h["state"], h["ok"], h["failed"]), ("ok", 1, 1))

    def test_min_venues(self):
        srcs = [dict(s, venue="one") for s in THREE]
        feed = make_feed(srcs, TABLE)
        feed.poll(force=True)
        self.assertEqual(feed.report()["live_venues"], 1)
        self.assertIsNone(feed.median_micro_usd())
        feed = make_feed(srcs, TABLE, min_venues=1)
        feed.poll(force=True)
        self.assertIsNotNone(feed.median_micro_usd())

    def test_outlier_filter(self):
        table = dict(TABLE)
        wild = copy.deepcopy(NONKYC)
        wild["lastPriceNumber"] = 0.60                              # +39 % against the others
        table[NONKYC_URL] = wild
        srcs = copy.deepcopy(THREE)
        srcs[2].pop("max_spread_bps")
        feed = make_feed(srcs, table, min_sources=2)
        feed.poll(force=True)
        self.assertEqual(feed.aggregate(), ((432007 + 429996 + 1) // 2, 0b0011, ["coingecko", "safetrade"]))

    def test_safetrade_direct(self):
        srcs = THREE + [{"name": "safetrade-direct", "kind": "peatio_ticker", "market": "yecusdt"}]
        table = dict(TABLE)
        table["https://safe.trade/api/v2/trade/public/tickers/yecusdt"] = PEATIO
        feed = make_feed(srcs, table)
        feed.poll(force=True)
        h = feed.report()["sources"]["safetrade-direct"]
        self.assertEqual((h["state"], h["last_price_micro_usd"], h["last_age_seconds"], h["last_spread_bps"]), ("ok", 430000, None, None))
        self.assertEqual(feed.report()["live_venues"], 3)

    def test_btc_pairs_convert_with_reference_median(self):
        srcs = THREE + [
            {"name": "nonkyc-btc-pair", "kind": "nonkyc_market", "symbol": "YEC_BTC", "max_age": 3600, "max_spread_bps": 300},
            {"name": "nonkyc-btc-via-coingecko", "kind": "coingecko_ticker", "market": "nonkyc_io", "target": "BTC", "max_age": 3600},
        ]
        feed = make_feed(srcs, dict(TABLE, **BTC_TABLE), btc_sources=BTC_SOURCES)
        feed.poll(force=True)
        r = feed.report()
        self.assertEqual(r["btc_usd"]["live"], 4)
        self.assertAlmostEqual(r["btc_usd"]["reference_usd"], BTC_REF_USD, places=6)
        self.assertEqual([h["state"] for h in r["btc_usd"]["sources"].values()], ["ok"] * 4)
        self.assertAlmostEqual(r["btc_usd"]["sources"]["kraken"]["last_spread_bps"], 0.0125, places=3)
        nk = r["sources"]["nonkyc-btc-pair"]
        self.assertEqual((nk["state"], nk["quote"]), ("ok", "BTC"))
        self.assertEqual(nk["last_price_micro_usd"], int(round(5.57e-06 * BTC_REF_USD * MICRO)))
        cg = r["sources"]["nonkyc-btc-via-coingecko"]
        self.assertEqual(cg["last_price_micro_usd"], int(round(5.356e-06 * BTC_REF_USD * MICRO)))
        self.assertEqual((r["live_sources"], r["live_venues"]), (5, 3))   # the BTC pairs share nonkyc_io
        self.assertIsNotNone(feed.median_micro_usd())

    def test_btc_pairs_dropped_without_reference(self):
        srcs = THREE + [{"name": "nonkyc-btc-pair", "kind": "nonkyc_market", "symbol": "YEC_BTC"}]
        table = dict(TABLE, **BTC_TABLE)
        table["https://api.kraken.com/0/public/Ticker?pair=XBTUSD"] = OSError("down")
        table["https://api.exchange.coinbase.com/products/BTC-USD/ticker"] = {"message": "NotFound"}
        table["https://api.nonkyc.io/api/v2/market/getbysymbol/BTC_USDT"] = OSError("down")
        feed = make_feed(srcs, table, btc_sources=BTC_SOURCES)          # one of four references live, need 2
        feed.poll(force=True)
        r = feed.report()
        self.assertEqual(r["btc_usd"]["live"], 1)
        self.assertIsNone(r["btc_usd"]["reference_usd"])
        self.assertEqual(r["btc_usd"]["sources"]["coinbase"]["state"], "shape")
        self.assertEqual(r["sources"]["nonkyc-btc-pair"]["state"], "btcref")
        self.assertEqual(r["live_sources"], 3)                           # the USD sources are unaffected
        feed = make_feed(srcs, table, btc_sources=BTC_SOURCES, min_btc_sources=1)
        feed.poll(force=True)
        r = feed.report()
        self.assertEqual(r["sources"]["nonkyc-btc-pair"]["state"], "ok")
        self.assertEqual(r["sources"]["nonkyc-btc-pair"]["last_price_micro_usd"], int(round(5.57e-06 * 79993 * MICRO)))

    def test_btc_references_not_fetched_without_btc_pairs(self):
        feed = make_feed(THREE, dict(TABLE, **BTC_TABLE), btc_sources=BTC_SOURCES)
        feed.poll(force=True)
        self.assertEqual(len(feed.http.calls), 3)
        self.assertEqual(feed.report()["btc_usd"]["live"], 0)

    def _nonkyc_at(self, feed, t, price, volume=None):
        later = copy.deepcopy(NONKYC)
        later["lastPriceNumber"] = price
        later["lastTradeAt"] = int(t * 1000)
        if volume is not None:
            later["volumeNumber"] = volume
        feed.http.table = dict(TABLE, **{NONKYC_URL: later})
        yp.time.time = lambda: t
        feed.poll(force=True)

    def test_twap_and_silence(self):
        feed = make_feed(THREE, TABLE, poll_seconds=0)
        feed.poll(force=True)
        self._nonkyc_at(feed, NOW + 100, 0.4626)                         # no volume in the fixture: time-weighted
        self.assertEqual(feed.report()["sources"]["nonkyc"]["twap_micro_usd"], (442600 + 462600) // 2)
        yp.time.time = lambda: NOW + 100 + yp.SOURCE_SILENCE_SECONDS + 1
        self.assertEqual(feed.report()["live_sources"], 0)

    def test_window_is_fifteen_minutes(self):
        feed = make_feed(THREE, TABLE, poll_seconds=0)
        feed.poll(force=True)
        self._nonkyc_at(feed, NOW + 800, 0.4626)
        self.assertEqual(feed.report()["sources"]["nonkyc"]["twap_micro_usd"], (442600 + 462600) // 2)
        self._nonkyc_at(feed, NOW + 901, 0.4626)                         # the first sample has left the window
        self.assertEqual(feed.report()["sources"]["nonkyc"]["twap_micro_usd"], 462600)

    def test_vwap_where_volume_is_reported(self):
        # Rule: §10.1 volume-weighted where the venue reports trade volume
        feed = make_feed(THREE, TABLE, poll_seconds=0)
        self._nonkyc_at(feed, NOW, 0.40, volume=1000.0)                    # first sample: no delta yet
        self._nonkyc_at(feed, NOW + 30, 0.50, volume=1001.0)               # 1 YEC traded at 0.50
        self._nonkyc_at(feed, NOW + 60, 0.40, volume=1004.0)               # 3 YEC traded at 0.40
        self.assertEqual(feed.report()["sources"]["nonkyc"]["twap_micro_usd"], int(round((500000 * 1 + 400000 * 3) / 4)))
        # a non-positive delta (24 h roll-off) turns the whole window time-weighted, never a wild weight
        self._nonkyc_at(feed, NOW + 90, 0.60, volume=900.0)
        self.assertEqual(feed.report()["sources"]["nonkyc"]["twap_micro_usd"], (400000 + 500000 + 400000 + 600000) // 4)

    def test_mock_mode(self):
        path = os.path.join(HERE, ".test-mock-price")
        try:
            with open(path, "w") as f:
                f.write("50")
            feed = yp.PriceFeed([], path, dict(yp.FEED_DEFAULTS))
            feed.poll()
            self.assertEqual(feed.aggregate(), (50 * MICRO, 0, ["mock"]))
            with open(path, "w") as f:
                f.write("75")
            feed.poll()
            self.assertEqual(feed.median_micro_usd(), 75 * MICRO)
            with open(path, "w") as f:
                f.write("not a price")
            feed.poll()
            self.assertIsNone(feed.aggregate())                            # unreadable mock = failed aggregate
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Coinbase tag codec (§3.2)

KEY = bytes(range(20))


def tag(price=432007, mask=0b1011, signal=True, version=1, key=KEY):
    return yp.encode_tag_push(price, mask, key, signal=signal, version=version)


class TagTests(unittest.TestCase):
    def test_height_push_matches_cscript(self):
        # Rule: TAG-1
        self.assertEqual(yp.height_push(0), b"\x00")
        self.assertEqual(yp.height_push(1), b"\x51")
        self.assertEqual(yp.height_push(16), b"\x60")
        self.assertEqual(yp.height_push(17), b"\x01\x11")
        self.assertEqual(yp.height_push(128), b"\x02\x80\x00")             # sign bit needs a padding byte
        self.assertEqual(yp.height_push(600000), b"\x03\xc0\x27\x09")
        self.assertEqual(yp.height_push(1_000_000), b"\x03\x40\x42\x0f")
        for h in (0, 1, 16, 17, 128, 600000):
            self.assertEqual(yp.skip_height_push(yp.height_push(h) + b"xyz"), len(yp.height_push(h)))
        self.assertIsNone(yp.skip_height_push(b""))
        self.assertIsNone(yp.skip_height_push(b"\x05\x01"))                # truncated push
        self.assertIsNone(yp.skip_height_push(b"\xac"))                    # not a push

    def test_tag_right_after_height(self):
        # Rule: TAG-1
        ss = yp.height_push(600000) + tag()
        t = yp.decode_coinbase_tag(ss)
        self.assertEqual((t["kind"], t["priceMicroUsd"], t["sourceMask"], t["signal"], t["payoutKeyHex"], t["offset"]),
                         ("quote", 432007, 0b1011, True, KEY.hex(), 4))
        self.assertEqual(len(ss), 4 + 37)

    def test_tag_after_extranonce_and_text(self):
        # Rule: TAG-1 the scan is byte-level, never a script parse (V4)
        ss = yp.height_push(700001) + b"\x08" + b"\xde\xad\xbe\xef\x00\x00\x00\x01" + tag() + b"/pool text/"
        t = yp.decode_coinbase_tag(ss)
        self.assertEqual((t["kind"], t["offset"]), ("quote", 4 + 9))
        # raw extranonce bytes that are not a valid push do not stop the scan
        ss = yp.height_push(700001) + b"\x4c\xff\x00" + tag()
        self.assertEqual(yp.decode_coinbase_tag(ss)["kind"], "quote")

    def test_signal_only(self):
        # Rule: TAG-3
        t = yp.decode_coinbase_tag(yp.height_push(5) + tag(price=0))
        self.assertEqual((t["kind"], t["priceMicroUsd"], t["signal"]), ("signal", 0, True))
        t = yp.decode_coinbase_tag(yp.height_push(5) + tag(price=0, signal=False))
        self.assertEqual((t["kind"], t["signal"]), ("signal", False))

    def test_invalid_is_no_tag(self):
        # Rule: TAG-2
        h = yp.height_push(300)
        self.assertIsNone(yp.decode_coinbase_tag(h + tag(version=2)))
        self.assertIsNone(yp.decode_coinbase_tag(h + tag(version=0)))
        ss = bytearray(h + tag())
        ss[len(h) + 6] = 0x03                                              # flags bit 1 set (reserved)
        self.assertIsNone(yp.decode_coinbase_tag(bytes(ss)))
        self.assertIsNone(yp.decode_coinbase_tag(h + tag(price=yp.PRICE_MIN - 1)))
        self.assertIsNone(yp.decode_coinbase_tag(h + tag(price=yp.PRICE_MAX + 1)))
        self.assertIsNone(yp.decode_coinbase_tag(h + tag(price=-5)))
        self.assertIsNotNone(yp.decode_coinbase_tag(h + tag(price=yp.PRICE_MIN)))
        self.assertIsNotNone(yp.decode_coinbase_tag(h + tag(price=yp.PRICE_MAX)))
        self.assertIsNone(yp.decode_coinbase_tag(h + tag()[:-1]))         # fewer than 32 bytes follow
        self.assertIsNone(yp.decode_coinbase_tag(h))                       # no occurrence
        self.assertIsNone(yp.decode_coinbase_tag(b""))                     # no height push at all

    def test_five_byte_pattern_rule(self):
        # Rule: P10 the magic without its push opcode is not a tag
        h = yp.height_push(300)
        self.assertIsNone(yp.decode_coinbase_tag(h + tag()[1:]))           # "YED!" without 0x24
        self.assertIsNone(yp.decode_coinbase_tag(h + b"\x25" + tag()[1:])) # a 37-byte push is not the pattern
        # the pattern inside the height push itself does not count: only bytes after the prefix are scanned
        ss = b"\x05" + b"\x24YED!" + tag()
        self.assertEqual(yp.decode_coinbase_tag(ss)["offset"], 6)
        ss = b"\x05" + b"\x24YED!" + b"\x00" * 31
        self.assertIsNone(yp.decode_coinbase_tag(ss))

    def test_first_occurrence_decides(self):
        # Rule: TAG-5
        h = yp.height_push(300)
        bad_then_good = h + tag(version=9) + tag()
        self.assertIsNone(yp.decode_coinbase_tag(bad_then_good))
        good_then_other = h + tag(price=1000) + tag(price=2000)
        self.assertEqual(yp.decode_coinbase_tag(good_then_other)["priceMicroUsd"], 1000)
        # a first occurrence whose 32-byte body fails TAG-2 (here: the price bytes are the second tag's
        # pattern, out of range) is no tag, and the scan never continues to the valid second one (M2)
        garbage_then_good = h + b"\x24YED!" + b"\x01\x01" + tag()
        self.assertIsNone(yp.decode_coinbase_tag(garbage_then_good))

    def test_encode_roundtrip_layout(self):
        body = yp.encode_tag(1_000_000, 0x8001, KEY, signal=False)
        self.assertEqual(len(body), 36)
        self.assertEqual(body[:4], b"YED!")
        self.assertEqual(body[4], 1)
        self.assertEqual(body[5], 0)
        self.assertEqual(int.from_bytes(body[6:14], "little", signed=True), 1_000_000)
        self.assertEqual(int.from_bytes(body[14:16], "little"), 0x8001)
        self.assertEqual(body[16:], KEY)
        self.assertEqual(yp.decode_tag_body(body[4:])["sourceMask"], 0x8001)


class FixtureCrossCheck(unittest.TestCase):
    """The Rust agent's aggregator (contrib/yellowback/attest, plan §5) and this module must agree
    on the recorded exchange replies under attest/fixtures/. expected.json was written by this
    module (fixtures/expected.py); this test proves the file still matches the Python behaviour,
    the Rust test `fixtures::tests` proves the port matches the file."""

    FIXTURES = os.path.join(HERE, "attest", "fixtures")

    def _run(self, scenario, now):
        sources = yp.normalize_sources(scenario["sources"])
        btc = yp.normalize_btc_sources(scenario.get("btc_usd_sources", []))
        table = {}
        for s in sources + btc:
            f = scenario["replies"][s["name"]]
            if f is None:
                table[s["url"]] = OSError("no reply (fixture: connection refused)")
            else:
                with open(os.path.join(self.FIXTURES, f), "rb") as fh:
                    table[s["url"]] = fh.read()
        feed = make_feed(scenario["sources"], table, scenario.get("btc_usd_sources", []), **scenario.get("settings", {}))
        yp.time.time = lambda: float(now)
        feed.poll(force=True)
        return feed.aggregate(), feed.report()

    def test_expected_json_is_this_modules_answer(self):
        # Rule: plan §5 cross-test on recorded fixtures
        import json
        with open(os.path.join(self.FIXTURES, "scenarios.json")) as f:
            spec = json.load(f)
        with open(os.path.join(self.FIXTURES, "expected.json")) as f:
            expected = json.load(f)
        self.assertEqual(spec["now"], expected["now"])
        self.assertEqual([s["name"] for s in spec["scenarios"]], [s["name"] for s in expected["scenarios"]])
        real_time = yp.time.time
        try:
            for sc, ex in zip(spec["scenarios"], expected["scenarios"]):
                agg, r = self._run(sc, spec["now"])
                with self.subTest(scenario=sc["name"]):
                    self.assertEqual(None if agg is None else agg[0], ex["median_micro_usd"])
                    self.assertEqual(None if agg is None else agg[1], ex["source_mask"])
                    self.assertEqual([] if agg is None else agg[2], ex["contributing"])
                    self.assertEqual((r["live_sources"], r["live_venues"]), (ex["live_sources"], ex["live_venues"]))
                    self.assertEqual((r["btc_usd"]["reference_usd"], r["btc_usd"]["live"]), (ex["btc_reference_usd"], ex["btc_live"]))
                    for name, e in ex["sources"].items():
                        h = r["sources"][name]
                        self.assertEqual(h["state"], e["state"], name)
                        self.assertEqual(h["last_price_micro_usd"] if h["state"] == "ok" else None, e["micro_usd"], name)
                    for name, e in ex["btc_usd_sources"].items():
                        h = r["btc_usd"]["sources"][name]
                        self.assertEqual(h["state"], e["state"], name)
                        self.assertEqual(h["last_price_micro_usd"] if h["state"] == "ok" else None, e["micro_usd"], name)
        finally:
            yp.time.time = real_time


if __name__ == "__main__":
    unittest.main()
