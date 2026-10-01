#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .

"""
Yellowback price-source layer and coinbase-tag codec (plan §5, §3.2).

Imported by the `yellowback-quote` daemon, `pool/check-coinbase` and the unit
tests; nothing here talks to a node on its own. Standard library only,
Python >= 3.11.

Contents:
  * `Node` / `RpcError`: the minimal JSON-RPC client (moved from the
    prototype's yellowback_fed.py; `rpc_user`/`rpc_password` or a cookie file);
  * presets per venue (`coingecko_simple`, `coingecko_ticker`, `nonkyc_market`,
    `peatio_ticker`, `kraken_ticker`, `coinbase_ticker`, `generic`), every
    field overridable, per-source `max_age` / `max_spread_bps` / `reject_paths`
    guards, BTC-pair conversion with a median of `[[btc_usd_sources]]`;
  * `PriceFeed`: a 15-minute per-source window (`twap_seconds = 900`),
    volume-weighted where the venue reports trade volume and time-weighted
    otherwise (§10.1), silence drop, outlier filter, median over
    `min_sources` / `min_venues`, fail closed below either;
  * the source-mask bit registry of §5 (`MASK_BITS`) and `source_mask()`;
  * `decode_coinbase_tag()`: TAG-1..5 of §3.2 over a raw coinbase scriptSig.
"""

import base64
import datetime
import json
import logging
import re
import statistics
import struct
import threading
import time
import urllib.error
import urllib.request

LOG = logging.getLogger("yellowback-price")

MICRO = 1_000_000
PRICE_MIN = 100                 # µUSD; plan §3.1 (as DigiByte primitives/oracle.h:23-24)
PRICE_MAX = 100_000_000
OUTLIER_BPS = 1000              # sources more than 10 % from the median are dropped
TWAP_SECONDS = 900              # the proposal's 15-minute window (§5, §10.1)
SOURCE_SILENCE_SECONDS = 120
MIN_SOURCES = 3


# ---------------------------------------------------------------------------
# JSON-RPC client (stdlib only)

class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__("%s (code %s)" % (message, code))
        self.code = code
        self.message = message


def read_cookie(path):
    """The node's `.cookie` file holds `user:password`; returns that string."""
    with open(path) as f:
        return f.read().strip()


class Node:
    """Minimal JSON-RPC 1.0 client. `call(method, *params)` returns the result or raises RpcError
    for a JSON-RPC error and OSError/urllib errors for transport failures."""

    def __init__(self, url, timeout=60, user=None, password=None, cookie=None):
        self.url = url
        self.timeout = timeout
        creds = None
        if "@" in url:
            scheme, rest = url.split("://", 1)
            creds, host = rest.rsplit("@", 1)
            self.url = "%s://%s" % (scheme, host)
        if cookie:
            creds = read_cookie(cookie)
        elif user is not None:
            creds = "%s:%s" % (user, password or "")
        self.auth = base64.b64encode(creds.encode()).decode() if creds else None
        self._id = 0

    def call(self, method, *params):
        self._id += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self._id, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        if self.auth:
            req.add_header("Authorization", "Basic " + self.auth)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                reply = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            try:
                reply = json.loads(raw)
            except ValueError:
                raise RpcError(e.code, "HTTP %d: %s" % (e.code, raw.strip()[:120] or e.reason))
        if reply.get("error"):
            raise RpcError(reply["error"].get("code"), reply["error"].get("message"))
        return reply["result"]

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *p: self.call(name, *p)


# ---------------------------------------------------------------------------
# Source-mask bit registry (plan §5; §3.2 `sourceMask`, informational)
#
# A pool sets the bits of the sources that contributed to the published quote.
# Bits 4-15 are unassigned and allocated by spec revision (M9). A source's bit
# is its `venue`'s registry entry unless the [[sources]] row sets `mask_bit`.

MASK_BITS = {
    "safe_trade": 0,       # SafeTrade (proposal Appendix A)
    "coingecko": 1,        # CoinGecko
    "coinmarketcap": 2,    # CoinMarketCap
    "nonkyc_io": 3,        # Nonkyc (M9)
}
MASK_BIT_MAX = 15


def mask_bit_for(src):
    """The registry bit of a normalised source, or None when it has none."""
    if src.get("mask_bit") is not None:
        return int(src["mask_bit"])
    return MASK_BITS.get(src.get("venue"))


def source_mask(sources):
    """OR of the registry bits of the given normalised sources (sources without a bit add nothing)."""
    mask = 0
    for s in sources:
        b = mask_bit_for(s)
        if b is not None:
            mask |= 1 << b
    return mask


# ---------------------------------------------------------------------------
# Price sources
#
# Every source is a [[sources]] table in the operator's TOML. `kind` names a
# preset that fills in the URL and the JSON paths for a known API; the operator
# may override any field, and kind = "generic" (the default) takes the fields
# verbatim. A venue changing the shape of its reply is therefore a config edit
# (or a preset edit here), never a node release. A source that stops resolving
# is dropped from the median and reported by `sources`, and the agent's own
# checks (outlier filter, fail closed below min_sources / min_venues) bound
# what a wrong number can do.
#
# Paths are dotted. A segment `[field=value,field2=value2]` selects the element
# of a list whose fields equal the given values, so a list whose order is not
# stable (CoinGecko's tickers) is still addressable; a bare integer indexes.
#
# BTC-quoted pairs (quote = "BTC") are converted with the median of the
# [[btc_usd_sources]] fetched in the same poll; below min_btc_sources live
# references every BTC-quoted source is dropped ("btcref"), never guessed.
#
# `volume_path` (optional) names the venue's cumulative traded base volume
# (every known venue reports a rolling 24 h figure). Within the window a
# sample is weighted by the volume traded since the previous sample when that
# delta is positive, so the per-source average is a VWAP over the window's
# trades; a source without `volume_path`, its first sample, and any sample
# whose delta is not positive (rolling window roll-off) weigh one poll
# interval each (time-weighted). §12 Q12 tracks which venues report volume
# reliably enough for this.

FEED_DEFAULTS = {
    "poll_seconds": 30,          # fetch cadence; CoinGecko's public API allows ~30 calls/min and caches 30 s
    "twap_seconds": TWAP_SECONDS,
    "silence_seconds": SOURCE_SILENCE_SECONDS,
    "outlier_bps": OUTLIER_BPS,
    "min_sources": MIN_SOURCES,  # distinct live sources after the outlier filter
    "min_venues": 2,             # distinct `venue` values among them (CoinGecko aggregates the same venues)
    "min_btc_sources": 2,        # live BTC/USD references needed before a BTC-quoted pair is converted
    "fetch_timeout": 15,
}
FEED_KEYS = tuple(FEED_DEFAULTS)

SOURCE_FIELDS = {
    "name", "kind", "venue", "url", "path", "quote", "scale",
    "timestamp_path", "timestamp_unit", "max_age",
    "spread_path", "spread_unit", "bid_path", "ask_path", "max_spread_bps",
    "reject_paths", "headers", "volume_path", "mask_bit",
    # preset parameters
    "coin", "vs", "market", "target", "symbol", "base_url", "api_key", "pair", "key", "product",
}


def _quote_for(symbol):
    return "BTC" if symbol.upper().endswith("BTC") else "USD"


def _preset_coingecko_simple(s):
    # Verified 2026-09-05: {"ycash":{"usd":0.432007,"last_updated_at":1788673030}}
    coin, vs = s.get("coin", "ycash"), s.get("vs", "usd").lower()
    d = {
        "venue": "coingecko",
        "url": "https://api.coingecko.com/api/v3/simple/price?ids=%s&vs_currencies=%s&include_last_updated_at=true" % (coin, vs),
        "path": "%s.%s" % (coin, vs),
        "quote": "BTC" if vs == "btc" else "USD",
        "timestamp_path": "%s.last_updated_at" % coin,
        "timestamp_unit": "s",
    }
    if s.get("api_key"):
        d["headers"] = {"x-cg-demo-api-key": s["api_key"]}
    return d


def _preset_coingecko_ticker(s):
    # Verified 2026-09-05: tickers[] with market.identifier ("safe_trade", "nonkyc_io"), target
    # ("USDT", "USDC", "BTC"), converted_last.usd, bid_ask_spread_percentage, last_traded_at (ISO),
    # is_stale, is_anomaly, volume (24 h, base units). The list order is not stable: select by fields.
    # target = "BTC" reads the venue's own last (BTC) and converts with our BTC/USD reference,
    # not CoinGecko's converted_last.
    coin = s.get("coin", "ycash")
    market, target = s.get("market", "safe_trade"), s.get("target", "USDT")
    sel = "tickers.[market.identifier=%s,target=%s]" % (market, target)
    btc = target.upper() == "BTC"
    d = {
        "venue": market,
        "url": "https://api.coingecko.com/api/v3/coins/%s/tickers" % coin,
        "path": sel + (".last" if btc else ".converted_last.usd"),
        "quote": "BTC" if btc else "USD",
        "timestamp_path": sel + ".last_traded_at",
        "timestamp_unit": "iso",
        "spread_path": sel + ".bid_ask_spread_percentage",
        "spread_unit": "percent",
        "reject_paths": [sel + ".is_stale", sel + ".is_anomaly"],
        "volume_path": sel + ".volume",
    }
    if s.get("api_key"):
        d["headers"] = {"x-cg-demo-api-key": s["api_key"]}
    return d


def _preset_nonkyc_market(s):
    # Verified 2026-09-05: lastPriceNumber, bestBidNumber, bestAskNumber, spreadPercentNumber,
    # lastTradeAt (ms since epoch), volumeNumber (24 h, base units).
    symbol = s.get("symbol", "YEC_USDT")
    return {
        "venue": "nonkyc_io",       # CoinGecko's market identifier, so both readings of the venue count once
        "url": "%s/api/v2/market/getbysymbol/%s" % (s.get("base_url", "https://api.nonkyc.io"), symbol),
        "path": "lastPriceNumber",
        "quote": _quote_for(symbol),
        "timestamp_path": "lastTradeAt",
        "timestamp_unit": "ms",
        "bid_path": "bestBidNumber",
        "ask_path": "bestAskNumber",
        "volume_path": "volumeNumber",
    }


def _preset_peatio_ticker(s):
    # SafeTrade (Peatio/OpenDAX API). Verified 2026-09-05 with this client's headers (Cloudflare
    # answered curl and a browser user agent with 403; `yellowback-quote sources` from the operator
    # host is the check): {"id":"yecusdt","base_unit":"yec","quote_unit":"usdt","last":"0.43",
    # "avg_price","high","low","open","volume","amount","price_change_percent"}. No timestamp and no
    # bid/ask: freshness and spread for this venue come from the coingecko_ticker preset instead.
    market = s.get("market", "yecusdt")
    return {
        "venue": "safe_trade",
        "url": "%s/api/v2/trade/public/tickers/%s" % (s.get("base_url", "https://safe.trade"), market),
        "path": "last",
        "quote": _quote_for(market),
        "volume_path": "volume",
    }


def _preset_kraken_ticker(s):
    # Verified 2026-09-05: {"error":[],"result":{"XXBTZUSD":{"a":[ask,..],"b":[bid,..],"c":[last,vol],..}}}.
    # Kraken keys the result by its internal pair name (XBTUSD -> XXBTZUSD); `key` overrides it.
    pair = s.get("pair", "XBTUSD")
    key = s.get("key", "XXBTZUSD" if pair == "XBTUSD" else pair)
    return {
        "venue": "kraken",
        "url": "%s/0/public/Ticker?pair=%s" % (s.get("base_url", "https://api.kraken.com"), pair),
        "path": "result.%s.c.0" % key,
        "quote": "USD",
        "bid_path": "result.%s.b.0" % key,
        "ask_path": "result.%s.a.0" % key,
    }


def _preset_coinbase_ticker(s):
    # Verified 2026-09-05: {"price","bid","ask","time":"2026-09-06T05:53:57.841478937Z",...}.
    product = s.get("product", "BTC-USD")
    return {
        "venue": "coinbase",
        "url": "%s/products/%s/ticker" % (s.get("base_url", "https://api.exchange.coinbase.com"), product),
        "path": "price",
        "quote": "USD",
        "timestamp_path": "time",
        "timestamp_unit": "iso",
        "bid_path": "bid",
        "ask_path": "ask",
    }


PRESETS = {
    "generic": lambda s: {},
    "kraken_ticker": _preset_kraken_ticker,
    "coinbase_ticker": _preset_coinbase_ticker,
    "coingecko_simple": _preset_coingecko_simple,
    "coingecko_ticker": _preset_coingecko_ticker,
    "nonkyc_market": _preset_nonkyc_market,
    "peatio_ticker": _preset_peatio_ticker,
}


def normalize_source(src):
    """Expand a [[sources]] table through its preset and validate it. Raises ValueError."""
    if not isinstance(src, dict) or not src.get("name"):
        raise ValueError("every source needs a name")
    name = src["name"]
    unknown = set(src) - SOURCE_FIELDS
    if unknown:
        raise ValueError("source %s: unknown field(s) %s" % (name, ", ".join(sorted(unknown))))
    kind = src.get("kind", "generic")
    if kind not in PRESETS:
        raise ValueError("source %s: unknown kind %r (known: %s)" % (name, kind, ", ".join(sorted(PRESETS))))
    out = dict(PRESETS[kind](src))
    out.update({k: v for k, v in src.items() if k in SOURCE_FIELDS})
    out["kind"] = kind
    out.setdefault("venue", name)
    out.setdefault("quote", "USD")
    out.setdefault("scale", 1)
    out.setdefault("timestamp_unit", "s")
    out.setdefault("spread_unit", "percent")
    out.setdefault("headers", {})
    out.setdefault("reject_paths", [])
    if not out.get("url") or not out.get("path"):
        raise ValueError("source %s: url and path are required (kind %s)" % (name, kind))
    if out["quote"] not in ("USD", "BTC"):
        raise ValueError("source %s: quote must be USD or BTC" % name)
    if out["timestamp_unit"] not in ("s", "ms", "iso"):
        raise ValueError("source %s: timestamp_unit must be s, ms or iso" % name)
    if out["spread_unit"] not in ("percent", "bps", "ratio"):
        raise ValueError("source %s: spread_unit must be percent, bps or ratio" % name)
    if out.get("max_age") is not None and not out.get("timestamp_path"):
        raise ValueError("source %s: max_age needs timestamp_path" % name)
    if out.get("max_spread_bps") is not None and not (out.get("spread_path") or (out.get("bid_path") and out.get("ask_path"))):
        raise ValueError("source %s: max_spread_bps needs spread_path or bid_path+ask_path" % name)
    if out.get("mask_bit") is not None:
        b = out["mask_bit"]
        if isinstance(b, bool) or not isinstance(b, int) or not 0 <= b <= MASK_BIT_MAX:
            raise ValueError("source %s: mask_bit must be an integer 0..%d" % (name, MASK_BIT_MAX))
    return out


def normalize_sources(sources, what="sources"):
    out = [normalize_source(s) for s in sources or []]
    names = [s["name"] for s in out]
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        raise ValueError("duplicate %s name(s): %s" % (what, ", ".join(dups)))
    return out


def normalize_btc_sources(sources):
    out = normalize_sources(sources, "btc_usd_sources")
    for s in out:
        if s["quote"] != "USD":
            raise ValueError("btc_usd_sources %s: must be USD-quoted" % s["name"])
    return out


def feed_settings(cfg):
    st = dict(FEED_DEFAULTS)
    for k in FEED_KEYS:
        if cfg.get(k) is not None:
            st[k] = type(FEED_DEFAULTS[k])(cfg[k])
    if st["min_sources"] < 1 or st["min_venues"] < 1 or st["min_btc_sources"] < 1:
        raise ValueError("min_sources, min_venues and min_btc_sources must be >= 1")
    if st["twap_seconds"] < 1 or st["poll_seconds"] < 0:
        raise ValueError("twap_seconds must be >= 1 and poll_seconds >= 0")
    return st


class ShapeError(Exception):
    """The reply parsed as JSON but the configured path did not resolve."""


def _parse_selector(segment):
    body = segment[1:-1]
    conds = []
    for part in body.split(","):
        if "=" not in part:
            raise ValueError("bad selector %r" % segment)
        k, v = part.split("=", 1)
        conds.append((k.strip(), v.strip()))
    return conds


def _walk(obj, dotted):
    for part in dotted.split("."):
        if isinstance(obj, list):
            obj = obj[int(part)]
        else:
            obj = obj[part]
    return obj


def split_path(path):
    """Split a dotted path into segments; dots inside a [selector] do not split."""
    segs, cur, depth = [], "", 0
    for ch in path:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "." and depth == 0:
            segs.append(cur)
            cur = ""
        else:
            cur += ch
    segs.append(cur)
    if depth != 0:
        raise ShapeError("unbalanced brackets in path %s" % path)
    return segs


def extract(obj, path):
    """Resolve a dotted path with list selectors. Raises ShapeError when it does not resolve."""
    try:
        for seg in split_path(path):
            if seg.startswith("[") and seg.endswith("]"):
                if not isinstance(obj, list):
                    raise ShapeError("selector %s applied to a non-list" % seg)
                conds = _parse_selector(seg)
                match = None
                for el in obj:
                    try:
                        if all(str(_walk(el, k)) == v for k, v in conds):
                            match = el
                            break
                    except (KeyError, IndexError, TypeError, ValueError):
                        continue
                if match is None:
                    raise ShapeError("no list element matches %s" % seg)
                obj = match
            elif isinstance(obj, list):
                obj = obj[int(seg)]
            elif isinstance(obj, dict):
                obj = obj[seg]
            else:
                raise ShapeError("cannot descend into %r at %s" % (type(obj).__name__, seg))
    except ShapeError:
        raise
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise ShapeError("%s at path %s" % (e.__class__.__name__, path))
    return obj


def extract_number(obj, path):
    v = extract(obj, path)
    try:
        return float(v)
    except (TypeError, ValueError):
        raise ShapeError("value at %s is not a number: %r" % (path, v))


def extract_timestamp(obj, path, unit):
    v = extract(obj, path)
    try:
        if unit == "iso":
            s = str(v)
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            s = re.sub(r"(\.\d{6})\d+", r"\1", s)   # fromisoformat takes at most microseconds
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.timestamp()
        f = float(v)
        return f / 1000.0 if unit == "ms" else f
    except (TypeError, ValueError) as e:
        raise ShapeError("timestamp at %s unreadable (%s): %r" % (path, e, v))


def spread_bps(obj, src):
    """Spread in basis points from spread_path or bid/ask, or None when the source has neither."""
    if src.get("spread_path"):
        v = extract_number(obj, src["spread_path"])
        unit = src["spread_unit"]
        return v * 100 if unit == "percent" else v * 10000 if unit == "ratio" else v
    if src.get("bid_path") and src.get("ask_path"):
        bid, ask = extract_number(obj, src["bid_path"]), extract_number(obj, src["ask_path"])
        mid = (bid + ask) / 2
        if mid <= 0:
            raise ShapeError("bid/ask not positive")
        return (ask - bid) / mid * 10000
    return None


class PriceFeed:
    """Per-source windowed average (VWAP/TWAP), freshness/spread guards, silence drop, outlier
    filter, median (plan §5)."""

    def __init__(self, sources, mock_file=None, settings=None, btc_sources=None):
        self.sources = normalize_sources(sources)
        self.btc_sources = normalize_btc_sources(btc_sources)
        self.settings = dict(FEED_DEFAULTS, **(settings or {}))
        self.mock_file = mock_file
        self.samples = {}               # name -> [(t, micro_usd, weight)]
        self.last_volume = {}           # name -> last cumulative volume figure
        self.health = self._fresh_health(self.sources)
        self.btc_health = self._fresh_health(self.btc_sources)
        self.btc_reference = {"usd": None, "live": 0, "at": None}
        self.last_poll = 0.0
        self.lock = threading.Lock()

    @staticmethod
    def _fresh_health(sources):
        return {s["name"]: {"venue": s["venue"], "kind": s["kind"], "quote": s["quote"], "state": "never",
                            "ok": 0, "failed": 0, "last_ok": None, "last_error": None,
                            "last_price_micro_usd": None, "last_age_seconds": None,
                            "last_spread_bps": None, "mask_bit": mask_bit_for(s)} for s in sources}

    # ---- fetching
    @staticmethod
    def _http_get(url, headers, timeout):
        req = urllib.request.Request(url, headers=dict({"User-Agent": "yellowback-quote/2", "Accept": "application/json"}, **headers))
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    def _fetch_json(self, url, headers):
        try:
            raw = self._http_get(url, headers, self.settings["fetch_timeout"])
        except Exception as e:
            raise RuntimeError("fetch: %s" % e)
        try:
            return json.loads(raw.decode())
        except (UnicodeDecodeError, ValueError):
            head = raw[:60].decode("utf-8", "replace").strip()
            raise ShapeError("reply is not JSON (starts %r)" % head)

    def _sample(self, src, now, btc_median):
        """One fetch of a source. Returns (micro_usd, age_seconds, spread_bps, volume); raises on any refusal."""
        obj = self._fetch_json(src["url"], src["headers"])
        for p in src["reject_paths"]:
            if bool(extract(obj, p)):
                raise RuntimeError("flagged: %s is true" % p)
        price = extract_number(obj, src["path"]) * float(src["scale"])
        if price <= 0:
            raise ShapeError("price not positive: %r" % price)
        age = None
        if src.get("timestamp_path"):
            age = now - extract_timestamp(obj, src["timestamp_path"], src["timestamp_unit"])
            if src.get("max_age") is not None and age > float(src["max_age"]):
                raise RuntimeError("stale: last trade %.0f s ago > max_age %s" % (age, src["max_age"]))
        spread = spread_bps(obj, src)
        if spread is not None and src.get("max_spread_bps") is not None and spread > float(src["max_spread_bps"]):
            raise RuntimeError("spread: %.0f bps > max_spread_bps %s" % (spread, src["max_spread_bps"]))
        if src["quote"] == "BTC":
            if btc_median is None:
                raise RuntimeError("btcref: no BTC/USD reference (%d live, need %d)" % (self.btc_reference["live"], self.settings["min_btc_sources"]))
            price *= btc_median
        volume = None
        if src.get("volume_path"):
            try:
                volume = extract_number(obj, src["volume_path"])
            except ShapeError as e:
                LOG.debug("source %s: volume unreadable, time-weighting this sample (%s)", src["name"], e)
        return int(round(price * MICRO)), age, spread, volume

    def _weight(self, name, volume):
        """VWAP weight: the base volume traded since the previous sample when the venue reports a
        cumulative figure and the delta is positive; otherwise one poll (time-weighted)."""
        prev = self.last_volume.get(name)
        if volume is not None:
            self.last_volume[name] = volume
        if volume is None or prev is None or volume <= prev:
            return None
        return volume - prev

    def _record(self, name, ok, error=None, price=None, age=None, spread=None, now=None, health=None):
        h = (self.health if health is None else health)[name]
        prev = h["state"]
        if ok:
            h.update(ok=h["ok"] + 1, state="ok", last_ok=now, last_error=None,
                     last_price_micro_usd=price, last_age_seconds=age, last_spread_bps=spread)
            if prev not in ("ok", "never"):
                LOG.warning("source %s recovered", name)
        else:
            state = "shape" if isinstance(error, ShapeError) else str(error).split(":", 1)[0] if isinstance(error, RuntimeError) else "error"
            h.update(failed=h["failed"] + 1, state=state, last_error=str(error))
            msg = "source %s dropped (%s): %s" % (name, state, error)
            if state == "shape":
                msg += " -- reply parsed but the configured path did not resolve: did the API change shape? Check with `yellowback-quote sources`"
            (LOG.warning if prev != state else LOG.debug)(msg)

    def _btc_reference_usd(self, now):
        """Median of the live BTC/USD references, or None below min_btc_sources. Records their health."""
        values = []
        for s in self.btc_sources:
            try:
                micro, age, spread, _ = self._sample(s, now, None)
            except Exception as e:
                self._record(s["name"], False, error=e, health=self.btc_health)
                continue
            self._record(s["name"], True, price=micro, age=age, spread=spread, now=now, health=self.btc_health)
            values.append(micro)
        usd = statistics.median(values) / MICRO if len(values) >= self.settings["min_btc_sources"] else None
        self.btc_reference = {"usd": usd, "live": len(values), "at": now}
        return usd

    def read_mock(self):
        """The mock file's USD price in µUSD, or None when unreadable (logged)."""
        try:
            with open(self.mock_file) as f:
                usd = float(f.read().strip())
        except (OSError, ValueError) as e:
            LOG.warning("mock price unreadable: %s", e)
            return None
        return int(round(usd * MICRO))

    def poll(self, force=False):
        now = time.time()
        if self.mock_file:
            micro = self.read_mock()
            with self.lock:
                if micro is None:
                    self.samples.pop("mock", None)          # an unreadable mock is a failed aggregate
                else:
                    self.samples.setdefault("mock", []).append((now, micro, None))
            return
        if not force and now - self.last_poll < self.settings["poll_seconds"]:
            return
        self.last_poll = now
        btc_median = self._btc_reference_usd(now) if any(s["quote"] == "BTC" for s in self.sources) else None
        for s in self.sources:
            try:
                micro, age, spread, volume = self._sample(s, now, btc_median)
            except Exception as e:
                self._record(s["name"], False, error=e)
                continue
            with self.lock:
                self.samples.setdefault(s["name"], []).append((now, micro, self._weight(s["name"], volume)))
            self._record(s["name"], True, price=micro, age=age, spread=spread, now=now)

    # ---- aggregation
    @staticmethod
    def _window_average(samples):
        """Volume-weighted when every sample but possibly the first carries a volume weight;
        otherwise the plain (time-weighted, one poll each) average."""
        weights = [w for _, _, w in samples]
        if len(samples) > 1 and all(w is not None for w in weights[1:]):
            tot = sum(weights[1:])
            return sum(v * w for _, v, w in samples[1:]) / tot
        return sum(v for _, v, _ in samples) / len(samples)

    def _live_twaps(self, now):
        """(name, venue, average) for every source with fresh samples."""
        venues = {s["name"]: s["venue"] for s in self.sources}
        out = []
        with self.lock:
            for name, samples in self.samples.items():
                samples[:] = [s for s in samples if now - s[0] <= self.settings["twap_seconds"]]
                if not samples or now - samples[-1][0] > self.settings["silence_seconds"]:
                    continue
                out.append((name, venues.get(name, name), self._window_average(samples)))
        return out

    def aggregate(self):
        """(median_micro_usd, source_mask, [contributing source names]) or None below
        min_sources / min_venues. In mock mode the file is the whole market (mask 0)."""
        now = time.time()
        if self.mock_file:
            with self.lock:
                # Test mode: the file is the whole market; no averaging, so a test's price change is immediate.
                s = self.samples.get("mock")
                return (s[-1][1], 0, ["mock"]) if s else None
        live = self._live_twaps(now)
        if len(live) < self.settings["min_sources"]:
            return None
        med = statistics.median(t for _, _, t in live)
        kept = [(n, v, t) for n, v, t in live if abs(t - med) * 10000 <= self.settings["outlier_bps"] * med]
        if len(kept) < self.settings["min_sources"] or len({v for _, v, _ in kept}) < self.settings["min_venues"]:
            return None
        by_name = {s["name"]: s for s in self.sources}
        names = [n for n, _, _ in kept]
        return int(round(statistics.median(t for _, _, t in kept))), source_mask(by_name[n] for n in names if n in by_name), names

    def median_micro_usd(self):
        """Median of the per-source averages, or None below min_sources / min_venues."""
        agg = self.aggregate()
        return None if agg is None else agg[0]

    def report(self):
        """Per-source health plus the aggregate, for the `sources` command."""
        now = time.time()
        live = {n: t for n, _, t in self._live_twaps(now)}
        srcs = {}
        for name, h in self.health.items():
            d = dict(h)
            d["live"] = name in live
            d["twap_micro_usd"] = int(round(live[name])) if name in live else None
            srcs[name] = d
        agg = self.aggregate()
        return {"settings": dict(self.settings), "sources": srcs,
                "live_sources": len(live), "live_venues": len({v for _, v, _ in self._live_twaps(now)}),
                "btc_usd": {"reference_usd": self.btc_reference["usd"], "live": self.btc_reference["live"],
                            "sources": {n: dict(h) for n, h in self.btc_health.items()}},
                "median_micro_usd": None if agg is None else agg[0],
                "source_mask": None if agg is None else agg[1],
                "contributing": [] if agg is None else agg[2]}


# ---------------------------------------------------------------------------
# Coinbase tag codec (plan §3.2, TAG-1..5). Mirrors src/yellowback/tag.cpp; the
# functional tests and `check-coinbase` use this copy.

TAG_MAGIC = b"YED!"
TAG_PATTERN = b"\x24" + TAG_MAGIC     # direct push of 36 bytes followed by the magic (P10)
TAG_SIZE = 36
TAG_BODY_SIZE = TAG_SIZE - len(TAG_MAGIC)
TAG_VERSION = 1


def skip_height_push(script):
    """Length of the BIP34 height prefix (`CScript() << nHeight`, ref/ycash/src/script/script.h:389),
    or None when the script does not start with a well-formed push."""
    if not script:
        return None
    op = script[0]
    if op == 0x00 or 0x51 <= op <= 0x60 or op == 0x4f:       # OP_0, OP_1..OP_16, OP_1NEGATE
        return 1
    if 1 <= op <= 0x4b:
        n, hdr = op, 1
    elif op == 0x4c and len(script) >= 2:                      # OP_PUSHDATA1
        n, hdr = script[1], 2
    elif op == 0x4d and len(script) >= 3:                      # OP_PUSHDATA2
        n, hdr = struct.unpack_from("<H", script, 1)[0], 3
    elif op == 0x4e and len(script) >= 5:                      # OP_PUSHDATA4
        n, hdr = struct.unpack_from("<I", script, 1)[0], 5
    else:
        return None
    return hdr + n if len(script) >= hdr + n else None


def decode_tag_body(body):
    """TAG-2 over the 32 bytes after the pattern: the decoded fields or None (invalid tag = no tag)."""
    if len(body) < TAG_BODY_SIZE:
        return None
    version, flags, price, mask = struct.unpack_from("<BBqH", body, 0)
    payout = body[12:32]
    if version != TAG_VERSION or flags & 0xFE:
        return None
    if price != 0 and not PRICE_MIN <= price <= PRICE_MAX:
        return None
    return {"version": version, "flags": flags, "signal": bool(flags & 1), "priceMicroUsd": price,
            "sourceMask": mask, "payoutKeyHex": payout.hex(),
            "kind": "quote" if price > 0 else "signal"}


def decode_coinbase_tag(script_sig):
    """TAG-1/TAG-5: skip the height push, scan the rest for the first 5-byte pattern, decode the
    32 bytes that follow. Returns the field dict (with `offset`) or None."""
    start = skip_height_push(bytes(script_sig))
    if start is None:
        return None
    rest = bytes(script_sig)[start:]
    i = rest.find(TAG_PATTERN)
    if i < 0:
        return None
    tag = decode_tag_body(rest[i + len(TAG_PATTERN):])
    if tag is None:
        return None
    tag["offset"] = start + i
    return tag


def encode_tag(price_micro_usd, source_mask_bits, payout_key20, signal=True, version=TAG_VERSION):
    """The 36-byte tag body (magic included) for tests and tools; `encode_tag_push` adds the 0x24."""
    if len(payout_key20) != 20:
        raise ValueError("payoutKey must be 20 bytes")
    return TAG_MAGIC + struct.pack("<BBqH", version, 1 if signal else 0, price_micro_usd, source_mask_bits) + bytes(payout_key20)


def encode_tag_push(*args, **kw):
    return b"\x24" + encode_tag(*args, **kw)


def height_push(height):
    """`CScript() << nHeight` for the heights a coinbase can carry."""
    if 1 <= height <= 16:
        return bytes([0x50 + height])
    if height == 0:
        return b"\x00"
    n, out = height, bytearray()
    while n:
        out.append(n & 0xff)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes([len(out)]) + bytes(out)
