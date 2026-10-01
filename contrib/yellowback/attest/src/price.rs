//! Price-source layer: a port of `contrib/yellowback/yellowback_price.py` (plan §5).
//!
//! The Python module is the behavioural reference; the two are cross-checked on the recorded
//! replies under `fixtures/` (`fixtures/expected.json` is read by both test suites). Where the
//! arithmetic is floating point the operations are performed in the same order as the Python so
//! the rounded µUSD agree bit for bit.
//!
//! Fetching is separated from aggregation so the aggregator is pure: `PriceFeed::requests()`
//! lists what to fetch, `PriceFeed::ingest(now, replies)` consumes the bodies (or fetch errors),
//! `PriceFeed::aggregate(now)` gives the median. The async fetcher lives in `attest.rs`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

pub const MICRO: f64 = 1_000_000.0;
pub const OUTLIER_BPS: f64 = 1000.0; // sources more than 10 % from the median are dropped
pub const TWAP_SECONDS: f64 = 900.0; // the proposal's 15-minute window
pub const SOURCE_SILENCE_SECONDS: f64 = 120.0;
pub const MIN_SOURCES: usize = 3;
pub const MASK_BIT_MAX: u32 = 15;

/// The source-mask bit registry (plan §5; informational). The Rust agent keeps it so the
/// `sources` command and the fixtures report the same mask as the Python aggregator.
fn registry_bit(venue: &str) -> Option<u32> {
    match venue {
        "safe_trade" => Some(0),
        "coingecko" => Some(1),
        "coinmarketcap" => Some(2),
        "nonkyc_io" => Some(3),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Feed settings

#[derive(Debug, Clone, PartialEq)]
pub struct FeedSettings {
    pub twap_seconds: f64,
    pub silence_seconds: f64,
    pub outlier_bps: f64,
    pub min_sources: usize,
    pub min_venues: usize,
    pub min_btc_sources: usize,
    pub fetch_timeout: u64,
}

impl Default for FeedSettings {
    fn default() -> Self {
        FeedSettings {
            twap_seconds: TWAP_SECONDS,
            silence_seconds: SOURCE_SILENCE_SECONDS,
            outlier_bps: OUTLIER_BPS,
            min_sources: MIN_SOURCES,
            min_venues: 2,
            min_btc_sources: 2,
            fetch_timeout: 15,
        }
    }
}

/// The feed keys as they appear in TOML (all optional; `[attest]` in the agent's file).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSettingsToml {
    pub twap_seconds: Option<f64>,
    pub silence_seconds: Option<f64>,
    pub outlier_bps: Option<f64>,
    pub min_sources: Option<usize>,
    pub min_venues: Option<usize>,
    pub min_btc_sources: Option<usize>,
    pub fetch_timeout: Option<u64>,
}

impl FeedSettingsToml {
    pub fn resolve(&self) -> Result<FeedSettings, String> {
        let d = FeedSettings::default();
        let st = FeedSettings {
            twap_seconds: self.twap_seconds.unwrap_or(d.twap_seconds),
            silence_seconds: self.silence_seconds.unwrap_or(d.silence_seconds),
            outlier_bps: self.outlier_bps.unwrap_or(d.outlier_bps),
            min_sources: self.min_sources.unwrap_or(d.min_sources),
            min_venues: self.min_venues.unwrap_or(d.min_venues),
            min_btc_sources: self.min_btc_sources.unwrap_or(d.min_btc_sources),
            fetch_timeout: self.fetch_timeout.unwrap_or(d.fetch_timeout),
        };
        if st.min_sources < 1 || st.min_venues < 1 || st.min_btc_sources < 1 {
            return Err("min_sources, min_venues and min_btc_sources must be >= 1".into());
        }
        if st.twap_seconds < 1.0 {
            return Err("twap_seconds must be >= 1".into());
        }
        Ok(st)
    }
}

// ---------------------------------------------------------------------------
// Sources: the `[[sources]]` row as written, and the normalised form after its preset.

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceToml {
    pub name: String,
    pub kind: Option<String>,
    pub venue: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
    pub quote: Option<String>,
    pub scale: Option<f64>,
    pub timestamp_path: Option<String>,
    pub timestamp_unit: Option<String>,
    pub max_age: Option<f64>,
    pub spread_path: Option<String>,
    pub spread_unit: Option<String>,
    pub bid_path: Option<String>,
    pub ask_path: Option<String>,
    pub max_spread_bps: Option<f64>,
    pub reject_paths: Option<Vec<String>>,
    pub headers: Option<BTreeMap<String, String>>,
    pub volume_path: Option<String>,
    pub mask_bit: Option<i64>,
    // preset parameters
    pub coin: Option<String>,
    pub vs: Option<String>,
    pub market: Option<String>,
    pub target: Option<String>,
    pub symbol: Option<String>,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub pair: Option<String>,
    pub key: Option<String>,
    pub product: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    Usd,
    Btc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampUnit {
    Seconds,
    Millis,
    Iso,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpreadUnit {
    Percent,
    Bps,
    Ratio,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Source {
    pub name: String,
    pub kind: String,
    pub venue: String,
    pub url: String,
    pub path: String,
    pub quote: Quote,
    pub scale: f64,
    pub timestamp_path: Option<String>,
    pub timestamp_unit: TimestampUnit,
    pub max_age: Option<f64>,
    pub spread_path: Option<String>,
    pub spread_unit: SpreadUnit,
    pub bid_path: Option<String>,
    pub ask_path: Option<String>,
    pub max_spread_bps: Option<f64>,
    pub reject_paths: Vec<String>,
    pub headers: BTreeMap<String, String>,
    pub volume_path: Option<String>,
    pub mask_bit: Option<u32>,
}

impl Source {
    pub fn mask_bit(&self) -> Option<u32> {
        self.mask_bit.or_else(|| registry_bit(&self.venue))
    }
}

/// The preset's contribution: a partial `Source` (every field the operator may override).
#[derive(Default)]
struct Preset {
    venue: Option<String>,
    url: Option<String>,
    path: Option<String>,
    quote: Option<&'static str>,
    timestamp_path: Option<String>,
    timestamp_unit: Option<&'static str>,
    spread_path: Option<String>,
    spread_unit: Option<&'static str>,
    bid_path: Option<String>,
    ask_path: Option<String>,
    reject_paths: Option<Vec<String>>,
    headers: Option<BTreeMap<String, String>>,
    volume_path: Option<String>,
}

fn quote_for(symbol: &str) -> &'static str {
    if symbol.to_uppercase().ends_with("BTC") {
        "BTC"
    } else {
        "USD"
    }
}

fn cg_headers(s: &SourceToml) -> Option<BTreeMap<String, String>> {
    s.api_key
        .as_ref()
        .filter(|k| !k.is_empty())
        .map(|k| BTreeMap::from([("x-cg-demo-api-key".to_string(), k.clone())]))
}

fn preset(kind: &str, s: &SourceToml) -> Option<Preset> {
    let p = match kind {
        "generic" => Preset::default(),
        "coingecko_simple" => {
            let coin = s.coin.clone().unwrap_or_else(|| "ycash".into());
            let vs = s.vs.clone().unwrap_or_else(|| "usd".into()).to_lowercase();
            Preset {
                venue: Some("coingecko".into()),
                url: Some(format!(
                    "https://api.coingecko.com/api/v3/simple/price?ids={coin}&vs_currencies={vs}&include_last_updated_at=true"
                )),
                path: Some(format!("{coin}.{vs}")),
                quote: Some(if vs == "btc" { "BTC" } else { "USD" }),
                timestamp_path: Some(format!("{coin}.last_updated_at")),
                timestamp_unit: Some("s"),
                headers: cg_headers(s),
                ..Default::default()
            }
        }
        "coingecko_ticker" => {
            let coin = s.coin.clone().unwrap_or_else(|| "ycash".into());
            let market = s.market.clone().unwrap_or_else(|| "safe_trade".into());
            let target = s.target.clone().unwrap_or_else(|| "USDT".into());
            let sel = format!("tickers.[market.identifier={market},target={target}]");
            let btc = target.to_uppercase() == "BTC";
            Preset {
                venue: Some(market.clone()),
                url: Some(format!("https://api.coingecko.com/api/v3/coins/{coin}/tickers")),
                path: Some(format!("{sel}{}", if btc { ".last" } else { ".converted_last.usd" })),
                quote: Some(if btc { "BTC" } else { "USD" }),
                timestamp_path: Some(format!("{sel}.last_traded_at")),
                timestamp_unit: Some("iso"),
                spread_path: Some(format!("{sel}.bid_ask_spread_percentage")),
                spread_unit: Some("percent"),
                reject_paths: Some(vec![format!("{sel}.is_stale"), format!("{sel}.is_anomaly")]),
                volume_path: Some(format!("{sel}.volume")),
                headers: cg_headers(s),
                ..Default::default()
            }
        }
        "nonkyc_market" => {
            let symbol = s.symbol.clone().unwrap_or_else(|| "YEC_USDT".into());
            let base = s.base_url.clone().unwrap_or_else(|| "https://api.nonkyc.io".into());
            Preset {
                venue: Some("nonkyc_io".into()),
                url: Some(format!("{base}/api/v2/market/getbysymbol/{symbol}")),
                path: Some("lastPriceNumber".into()),
                quote: Some(quote_for(&symbol)),
                timestamp_path: Some("lastTradeAt".into()),
                timestamp_unit: Some("ms"),
                bid_path: Some("bestBidNumber".into()),
                ask_path: Some("bestAskNumber".into()),
                volume_path: Some("volumeNumber".into()),
                ..Default::default()
            }
        }
        "peatio_ticker" => {
            let market = s.market.clone().unwrap_or_else(|| "yecusdt".into());
            let base = s.base_url.clone().unwrap_or_else(|| "https://safe.trade".into());
            Preset {
                venue: Some("safe_trade".into()),
                url: Some(format!("{base}/api/v2/trade/public/tickers/{market}")),
                path: Some("last".into()),
                quote: Some(quote_for(&market)),
                volume_path: Some("volume".into()),
                ..Default::default()
            }
        }
        "kraken_ticker" => {
            let pair = s.pair.clone().unwrap_or_else(|| "XBTUSD".into());
            let key = s.key.clone().unwrap_or_else(|| {
                if pair == "XBTUSD" {
                    "XXBTZUSD".into()
                } else {
                    pair.clone()
                }
            });
            let base = s.base_url.clone().unwrap_or_else(|| "https://api.kraken.com".into());
            Preset {
                venue: Some("kraken".into()),
                url: Some(format!("{base}/0/public/Ticker?pair={pair}")),
                path: Some(format!("result.{key}.c.0")),
                quote: Some("USD"),
                bid_path: Some(format!("result.{key}.b.0")),
                ask_path: Some(format!("result.{key}.a.0")),
                ..Default::default()
            }
        }
        "coinbase_ticker" => {
            let product = s.product.clone().unwrap_or_else(|| "BTC-USD".into());
            let base = s
                .base_url
                .clone()
                .unwrap_or_else(|| "https://api.exchange.coinbase.com".into());
            Preset {
                venue: Some("coinbase".into()),
                url: Some(format!("{base}/products/{product}/ticker")),
                path: Some("price".into()),
                quote: Some("USD"),
                timestamp_path: Some("time".into()),
                timestamp_unit: Some("iso"),
                bid_path: Some("bid".into()),
                ask_path: Some("ask".into()),
                ..Default::default()
            }
        }
        _ => return None,
    };
    Some(p)
}

pub const PRESET_KINDS: [&str; 7] = [
    "coinbase_ticker",
    "coingecko_simple",
    "coingecko_ticker",
    "generic",
    "kraken_ticker",
    "nonkyc_market",
    "peatio_ticker",
];

/// Expand a `[[sources]]` row through its preset and validate it (`normalize_source` in Python).
pub fn normalize_source(s: &SourceToml) -> Result<Source, String> {
    if s.name.is_empty() {
        return Err("every source needs a name".into());
    }
    let name = &s.name;
    let kind = s.kind.clone().unwrap_or_else(|| "generic".into());
    let p = preset(&kind, s).ok_or_else(|| {
        format!(
            "source {name}: unknown kind {kind:?} (known: {})",
            PRESET_KINDS.join(", ")
        )
    })?;
    let venue = s.venue.clone().or(p.venue).unwrap_or_else(|| name.clone());
    let url = s.url.clone().or(p.url).filter(|u| !u.is_empty());
    let path = s.path.clone().or(p.path).filter(|u| !u.is_empty());
    let (Some(url), Some(path)) = (url, path) else {
        return Err(format!("source {name}: url and path are required (kind {kind})"));
    };
    let quote = match s.quote.as_deref().or(p.quote).unwrap_or("USD") {
        "USD" => Quote::Usd,
        "BTC" => Quote::Btc,
        _ => return Err(format!("source {name}: quote must be USD or BTC")),
    };
    let timestamp_unit = match s.timestamp_unit.as_deref().or(p.timestamp_unit).unwrap_or("s") {
        "s" => TimestampUnit::Seconds,
        "ms" => TimestampUnit::Millis,
        "iso" => TimestampUnit::Iso,
        _ => return Err(format!("source {name}: timestamp_unit must be s, ms or iso")),
    };
    let spread_unit = match s.spread_unit.as_deref().or(p.spread_unit).unwrap_or("percent") {
        "percent" => SpreadUnit::Percent,
        "bps" => SpreadUnit::Bps,
        "ratio" => SpreadUnit::Ratio,
        _ => return Err(format!("source {name}: spread_unit must be percent, bps or ratio")),
    };
    let timestamp_path = s.timestamp_path.clone().or(p.timestamp_path);
    if s.max_age.is_some() && timestamp_path.is_none() {
        return Err(format!("source {name}: max_age needs timestamp_path"));
    }
    let spread_path = s.spread_path.clone().or(p.spread_path);
    let bid_path = s.bid_path.clone().or(p.bid_path);
    let ask_path = s.ask_path.clone().or(p.ask_path);
    if s.max_spread_bps.is_some() && !(spread_path.is_some() || (bid_path.is_some() && ask_path.is_some())) {
        return Err(format!(
            "source {name}: max_spread_bps needs spread_path or bid_path+ask_path"
        ));
    }
    let mask_bit = match s.mask_bit {
        None => None,
        Some(b) if (0..=MASK_BIT_MAX as i64).contains(&b) => Some(b as u32),
        Some(_) => return Err(format!("source {name}: mask_bit must be an integer 0..{MASK_BIT_MAX}")),
    };
    Ok(Source {
        name: name.clone(),
        kind,
        venue,
        url,
        path,
        quote,
        scale: s.scale.unwrap_or(1.0),
        timestamp_path,
        timestamp_unit,
        max_age: s.max_age,
        spread_path,
        spread_unit,
        bid_path,
        ask_path,
        max_spread_bps: s.max_spread_bps,
        reject_paths: s.reject_paths.clone().or(p.reject_paths).unwrap_or_default(),
        headers: s.headers.clone().or(p.headers).unwrap_or_default(),
        volume_path: s.volume_path.clone().or(p.volume_path),
        mask_bit,
    })
}

pub fn normalize_sources(rows: &[SourceToml], what: &str) -> Result<Vec<Source>, String> {
    let out = rows.iter().map(normalize_source).collect::<Result<Vec<_>, _>>()?;
    let mut seen = HashSet::new();
    let mut dups: Vec<&str> = out
        .iter()
        .filter(|s| !seen.insert(s.name.as_str()))
        .map(|s| s.name.as_str())
        .collect();
    dups.sort_unstable();
    dups.dedup();
    if !dups.is_empty() {
        return Err(format!("duplicate {what} name(s): {}", dups.join(", ")));
    }
    Ok(out)
}

pub fn normalize_btc_sources(rows: &[SourceToml]) -> Result<Vec<Source>, String> {
    let out = normalize_sources(rows, "btc_usd_sources")?;
    if let Some(s) = out.iter().find(|s| s.quote != Quote::Usd) {
        return Err(format!("btc_usd_sources {}: must be USD-quoted", s.name));
    }
    Ok(out)
}

pub fn source_mask<'a>(sources: impl IntoIterator<Item = &'a Source>) -> u32 {
    sources
        .into_iter()
        .filter_map(Source::mask_bit)
        .fold(0, |m, b| m | (1 << b))
}

// ---------------------------------------------------------------------------
// Path extraction (dotted paths with `[field=value,...]` list selectors)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeError(pub String);

impl fmt::Display for ShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn split_path(path: &str) -> Result<Vec<String>, ShapeError> {
    let mut segs = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for ch in path.chars() {
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            _ => {}
        }
        if ch == '.' && depth == 0 {
            segs.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    segs.push(cur);
    if depth != 0 {
        return Err(ShapeError(format!("unbalanced brackets in path {path}")));
    }
    Ok(segs)
}

/// Python's `str()` of a JSON scalar, as the selector comparison sees it.
fn py_str(v: &Value) -> Option<String> {
    Some(match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 && f.abs() < 1e16 {
                    format!("{f:.1}")
                } else {
                    format!("{f}")
                }
            } else {
                n.to_string()
            }
        }
        Value::String(s) => s.clone(),
        _ => return None,
    })
}

fn walk<'a>(mut obj: &'a Value, dotted: &str) -> Option<&'a Value> {
    for part in dotted.split('.') {
        obj = match obj {
            Value::Array(a) => a.get(part.parse::<usize>().ok()?)?,
            Value::Object(o) => o.get(part)?,
            _ => return None,
        };
    }
    Some(obj)
}

fn parse_selector(segment: &str) -> Result<Vec<(String, String)>, ShapeError> {
    let body = &segment[1..segment.len() - 1];
    body.split(',')
        .map(|part| {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| ShapeError(format!("bad selector {segment:?}")))?;
            Ok((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

pub fn extract<'a>(obj: &'a Value, path: &str) -> Result<&'a Value, ShapeError> {
    let mut cur = obj;
    for seg in split_path(path)? {
        if seg.starts_with('[') && seg.ends_with(']') {
            let Value::Array(list) = cur else {
                return Err(ShapeError(format!("selector {seg} applied to a non-list")));
            };
            let conds = parse_selector(&seg)?;
            let found = list.iter().find(|el| {
                conds
                    .iter()
                    .all(|(k, v)| walk(el, k).and_then(py_str).is_some_and(|s| s == *v))
            });
            cur = found.ok_or_else(|| ShapeError(format!("no list element matches {seg}")))?;
        } else {
            cur = match cur {
                Value::Array(a) => seg
                    .parse::<usize>()
                    .ok()
                    .and_then(|i| a.get(i))
                    .ok_or_else(|| ShapeError(format!("IndexError at path {path}")))?,
                Value::Object(o) => o
                    .get(&seg)
                    .ok_or_else(|| ShapeError(format!("KeyError at path {path}")))?,
                other => {
                    return Err(ShapeError(format!("cannot descend into {} at {seg}", type_name(other))));
                }
            };
        }
    }
    Ok(cur)
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

/// Python `float(v)`: numbers, numeric strings and bools.
fn to_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

pub fn extract_number(obj: &Value, path: &str) -> Result<f64, ShapeError> {
    let v = extract(obj, path)?;
    to_f64(v).ok_or_else(|| ShapeError(format!("value at {path} is not a number: {v}")))
}

/// Python truthiness of a JSON value (`bool(extract(obj, p))`).
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Seconds since the epoch for `YYYY-MM-DD[T ]HH:MM[:SS[.frac]][Z|±HH[:MM]]`; a naive time is UTC.
pub fn parse_iso8601(s: &str) -> Option<f64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 16 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b' ') || b[13] != b':' {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: u32 = s[5..7].parse().ok()?;
    let day: u32 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let minute: i64 = s[14..16].parse().ok()?;
    let mut rest = &s[16..];
    let mut second: i64 = 0;
    let mut frac = 0.0;
    if let Some(r) = rest.strip_prefix(':') {
        second = r.get(0..2)?.parse().ok()?;
        rest = &r[2..];
        if let Some(r) = rest.strip_prefix('.') {
            let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                return None;
            }
            let kept = &digits[..digits.len().min(6)]; // fromisoformat keeps microseconds
            frac = kept.parse::<f64>().ok()? / 10f64.powi(kept.len() as i32);
            rest = &r[digits.len()..];
        }
    }
    let offset: i64 = match rest {
        "" | "Z" | "z" => 0,
        tz if tz.starts_with('+') || tz.starts_with('-') => {
            let sign = if tz.starts_with('-') { -1 } else { 1 };
            let t = &tz[1..];
            let (hh, mm) = match t.len() {
                2 => (t.parse::<i64>().ok()?, 0),
                4 => (t[0..2].parse::<i64>().ok()?, t[2..4].parse::<i64>().ok()?),
                5 if &t[2..3] == ":" => (t[0..2].parse::<i64>().ok()?, t[3..5].parse::<i64>().ok()?),
                _ => return None,
            };
            sign * (hh * 3600 + mm * 60)
        }
        _ => return None,
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some((days * 86400 + hour * 3600 + minute * 60 + second - offset) as f64 + frac)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn extract_timestamp(obj: &Value, path: &str, unit: TimestampUnit) -> Result<f64, ShapeError> {
    let v = extract(obj, path)?;
    let bad = || ShapeError(format!("timestamp at {path} unreadable: {v}"));
    match unit {
        TimestampUnit::Iso => {
            let s = match v {
                Value::String(s) => s.clone(),
                other => py_str(other).ok_or_else(bad)?,
            };
            parse_iso8601(&s).ok_or_else(bad)
        }
        TimestampUnit::Millis => Ok(to_f64(v).ok_or_else(bad)? / 1000.0),
        TimestampUnit::Seconds => to_f64(v).ok_or_else(bad),
    }
}

pub fn spread_bps(obj: &Value, src: &Source) -> Result<Option<f64>, ShapeError> {
    if let Some(p) = &src.spread_path {
        let v = extract_number(obj, p)?;
        return Ok(Some(match src.spread_unit {
            SpreadUnit::Percent => v * 100.0,
            SpreadUnit::Ratio => v * 10000.0,
            SpreadUnit::Bps => v,
        }));
    }
    if let (Some(bp), Some(ap)) = (&src.bid_path, &src.ask_path) {
        let (bid, ask) = (extract_number(obj, bp)?, extract_number(obj, ap)?);
        let mid = (bid + ask) / 2.0;
        if mid <= 0.0 {
            return Err(ShapeError("bid/ask not positive".into()));
        }
        return Ok(Some((ask - bid) / mid * 10000.0));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// The feed

/// Why a sample was refused. `state()` is the short word the Python health table shows.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    Fetch(String),
    Shape(ShapeError),
    Flagged(String),
    Stale(f64, f64),
    Spread(f64, f64),
    BtcRef(usize, usize),
}

impl Refusal {
    pub fn state(&self) -> &'static str {
        match self {
            Refusal::Fetch(_) => "fetch",
            Refusal::Shape(_) => "shape",
            Refusal::Flagged(_) => "flagged",
            Refusal::Stale(..) => "stale",
            Refusal::Spread(..) => "spread",
            Refusal::BtcRef(..) => "btcref",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Fetch(e) => write!(f, "fetch: {e}"),
            Refusal::Shape(e) => write!(f, "shape: {e}"),
            Refusal::Flagged(p) => write!(f, "flagged: {p} is true"),
            Refusal::Stale(age, max) => write!(f, "stale: last trade {age:.0} s ago > max_age {max}"),
            Refusal::Spread(s, max) => write!(f, "spread: {s:.0} bps > max_spread_bps {max}"),
            Refusal::BtcRef(live, need) => write!(f, "btcref: no BTC/USD reference ({live} live, need {need})"),
        }
    }
}

impl From<ShapeError> for Refusal {
    fn from(e: ShapeError) -> Self {
        Refusal::Shape(e)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Health {
    pub state: String, // "never", "ok" or a Refusal::state()
    pub ok: u64,
    pub failed: u64,
    pub last_ok: Option<f64>,
    pub last_error: Option<String>,
    pub last_price_micro_usd: Option<i64>,
    pub last_age_seconds: Option<f64>,
    pub last_spread_bps: Option<f64>,
}

/// What one accepted reply yields.
struct Sampled {
    micro: i64,
    age: Option<f64>,
    spread: Option<f64>,
    volume: Option<f64>,
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    t: f64,
    micro: i64,
    weight: Option<f64>,
}

/// One fetch to perform: the `attest` loop's HTTP client resolves these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
}

/// One reply keyed by source name (a body, or the fetch error text).
pub type Replies = HashMap<String, Result<Vec<u8>, String>>;

#[derive(Debug, Clone)]
pub struct Aggregate {
    pub micro_usd: i64,
    pub source_mask: u32,
    pub contributing: Vec<String>,
}

pub struct PriceFeed {
    pub sources: Vec<Source>,
    pub btc_sources: Vec<Source>,
    pub settings: FeedSettings,
    samples: Vec<(String, Vec<Sample>)>, // insertion order, as the Python dict
    last_volume: HashMap<String, f64>,
    pub health: BTreeMap<String, Health>,
    pub btc_health: BTreeMap<String, Health>,
    pub btc_reference_usd: Option<f64>,
    pub btc_live: usize,
    pub mock_micro: Option<i64>,
}

fn fresh_health(sources: &[Source]) -> BTreeMap<String, Health> {
    sources
        .iter()
        .map(|s| {
            (
                s.name.clone(),
                Health {
                    state: "never".into(),
                    ..Default::default()
                },
            )
        })
        .collect()
}

/// Python's `statistics.median` over floats.
pub fn median(values: &[f64]) -> f64 {
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in prices"));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
}

/// Python's `int(round(x))`: round half to even.
pub fn py_round(x: f64) -> i64 {
    x.round_ties_even() as i64
}

impl PriceFeed {
    pub fn new(sources: Vec<Source>, btc_sources: Vec<Source>, settings: FeedSettings) -> Self {
        PriceFeed {
            health: fresh_health(&sources),
            btc_health: fresh_health(&btc_sources),
            sources,
            btc_sources,
            settings,
            samples: Vec::new(),
            last_volume: HashMap::new(),
            btc_reference_usd: None,
            btc_live: 0,
            mock_micro: None,
        }
    }

    pub fn needs_btc_reference(&self) -> bool {
        self.sources.iter().any(|s| s.quote == Quote::Btc)
    }

    /// Everything one poll fetches: the BTC/USD references (when any source is BTC-quoted) and the sources.
    pub fn requests(&self) -> Vec<Request> {
        let btc = if self.needs_btc_reference() {
            &self.btc_sources[..]
        } else {
            &[]
        };
        btc.iter()
            .chain(self.sources.iter())
            .map(|s| Request {
                name: s.name.clone(),
                url: s.url.clone(),
                headers: s.headers.clone(),
            })
            .collect()
    }

    /// One reply of a source, or the refusal.
    fn sample(
        src: &Source,
        body: &Result<Vec<u8>, String>,
        now: f64,
        btc_median: Option<f64>,
        btc_live: usize,
        min_btc: usize,
    ) -> Result<Sampled, Refusal> {
        let raw = body.as_ref().map_err(|e| Refusal::Fetch(e.clone()))?;
        let obj: Value = serde_json::from_slice(raw).map_err(|_| {
            let head: String = String::from_utf8_lossy(&raw[..raw.len().min(60)]).trim().to_string();
            ShapeError(format!("reply is not JSON (starts {head:?})"))
        })?;
        for p in &src.reject_paths {
            if truthy(extract(&obj, p)?) {
                return Err(Refusal::Flagged(p.clone()));
            }
        }
        let mut price = extract_number(&obj, &src.path)? * src.scale;
        if price <= 0.0 {
            return Err(ShapeError(format!("price not positive: {price}")).into());
        }
        let mut age = None;
        if let Some(tp) = &src.timestamp_path {
            let a = now - extract_timestamp(&obj, tp, src.timestamp_unit)?;
            if let Some(max) = src.max_age {
                if a > max {
                    return Err(Refusal::Stale(a, max));
                }
            }
            age = Some(a);
        }
        let spread = spread_bps(&obj, src)?;
        if let (Some(s), Some(max)) = (spread, src.max_spread_bps) {
            if s > max {
                return Err(Refusal::Spread(s, max));
            }
        }
        if src.quote == Quote::Btc {
            let m = btc_median.ok_or(Refusal::BtcRef(btc_live, min_btc))?;
            price *= m;
        }
        let volume = src.volume_path.as_ref().and_then(|vp| extract_number(&obj, vp).ok());
        Ok(Sampled {
            micro: py_round(price * MICRO),
            age,
            spread,
            volume,
        })
    }

    fn weight(&mut self, name: &str, volume: Option<f64>) -> Option<f64> {
        let prev = self.last_volume.get(name).copied();
        if let Some(v) = volume {
            self.last_volume.insert(name.to_string(), v);
        }
        match (volume, prev) {
            (Some(v), Some(p)) if v > p => Some(v - p),
            _ => None,
        }
    }

    fn record(
        health: &mut BTreeMap<String, Health>,
        name: &str,
        result: Result<(i64, Option<f64>, Option<f64>), &Refusal>,
        now: f64,
    ) {
        let Some(h) = health.get_mut(name) else { return };
        let prev = h.state.clone();
        match result {
            Ok((micro, age, spread)) => {
                h.ok += 1;
                h.state = "ok".into();
                h.last_ok = Some(now);
                h.last_error = None;
                h.last_price_micro_usd = Some(micro);
                h.last_age_seconds = age;
                h.last_spread_bps = spread;
                if prev != "ok" && prev != "never" {
                    tracing::warn!("source {name} recovered");
                }
            }
            Err(e) => {
                h.failed += 1;
                h.state = e.state().into();
                h.last_error = Some(e.to_string());
                let mut msg = format!("source {name} dropped ({}): {e}", e.state());
                if e.state() == "shape" {
                    msg.push_str(" -- reply parsed but the configured path did not resolve: did the API change shape? Check with `yellowback-attest sources`");
                }
                if prev != h.state {
                    tracing::warn!("{msg}");
                } else {
                    tracing::debug!("{msg}");
                }
            }
        }
    }

    /// Median of the live BTC/USD references (USD), or None below `min_btc_sources`.
    fn btc_reference(&mut self, replies: &Replies, now: f64) -> Option<f64> {
        let missing = Err("not fetched".to_string());
        let mut values: Vec<i64> = Vec::new();
        let btc_sources = std::mem::take(&mut self.btc_sources);
        for s in &btc_sources {
            let body = replies.get(&s.name).unwrap_or(&missing);
            match Self::sample(s, body, now, None, 0, 0) {
                Ok(r) => {
                    Self::record(&mut self.btc_health, &s.name, Ok((r.micro, r.age, r.spread)), now);
                    values.push(r.micro);
                }
                Err(e) => Self::record(&mut self.btc_health, &s.name, Err(&e), now),
            }
        }
        self.btc_sources = btc_sources;
        self.btc_live = values.len();
        self.btc_reference_usd = if values.len() >= self.settings.min_btc_sources {
            values.sort_unstable();
            let n = values.len();
            // statistics.median over ints: the middle int, or the true-division mean of the two middles.
            let med = if n % 2 == 1 {
                values[n / 2] as f64
            } else {
                (values[n / 2 - 1] + values[n / 2]) as f64 / 2.0
            };
            Some(med / MICRO)
        } else {
            None
        };
        self.btc_reference_usd
    }

    /// Consume one poll's replies at time `now` (`PriceFeed.poll` in Python, minus the HTTP).
    pub fn ingest(&mut self, now: f64, replies: &Replies) {
        let missing = Err("not fetched".to_string());
        let btc_median = if self.needs_btc_reference() {
            self.btc_reference(replies, now)
        } else {
            None
        };
        let sources = std::mem::take(&mut self.sources);
        for s in &sources {
            let body = replies.get(&s.name).unwrap_or(&missing);
            match Self::sample(s, body, now, btc_median, self.btc_live, self.settings.min_btc_sources) {
                Ok(r) => {
                    let weight = self.weight(&s.name, r.volume);
                    self.push_sample(
                        &s.name,
                        Sample {
                            t: now,
                            micro: r.micro,
                            weight,
                        },
                    );
                    Self::record(&mut self.health, &s.name, Ok((r.micro, r.age, r.spread)), now);
                }
                Err(e) => Self::record(&mut self.health, &s.name, Err(&e), now),
            }
        }
        self.sources = sources;
    }

    fn push_sample(&mut self, name: &str, sample: Sample) {
        match self.samples.iter_mut().find(|(n, _)| n == name) {
            Some((_, v)) => v.push(sample),
            None => self.samples.push((name.to_string(), vec![sample])),
        }
    }

    /// Test/devnet mode: the file's USD price is the whole market (no averaging, mask 0).
    pub fn ingest_mock(&mut self, usd: Option<f64>) {
        self.mock_micro = usd.map(|u| py_round(u * MICRO));
    }

    fn window_average(samples: &[Sample]) -> f64 {
        if samples.len() > 1 && samples[1..].iter().all(|s| s.weight.is_some()) {
            let tot: f64 = samples[1..].iter().map(|s| s.weight.unwrap_or(0.0)).sum();
            return samples[1..]
                .iter()
                .map(|s| s.micro as f64 * s.weight.unwrap_or(0.0))
                .sum::<f64>()
                / tot;
        }
        samples.iter().map(|s| s.micro as f64).sum::<f64>() / samples.len() as f64
    }

    /// `(name, venue, average)` for every source with fresh samples; prunes the window.
    pub fn live_twaps(&mut self, now: f64) -> Vec<(String, String, f64)> {
        let venues: HashMap<&str, &str> = self
            .sources
            .iter()
            .map(|s| (s.name.as_str(), s.venue.as_str()))
            .collect();
        let (twap, silence) = (self.settings.twap_seconds, self.settings.silence_seconds);
        let mut out = Vec::new();
        for (name, samples) in &mut self.samples {
            samples.retain(|s| now - s.t <= twap);
            match samples.last() {
                Some(last) if now - last.t <= silence => {}
                _ => continue,
            }
            let venue = venues.get(name.as_str()).copied().unwrap_or(name.as_str()).to_string();
            out.push((name.clone(), venue, Self::window_average(samples)));
        }
        out
    }

    /// The median over the live per-source averages after the outlier filter, or None below
    /// `min_sources` / `min_venues`.
    pub fn aggregate(&mut self, now: f64) -> Option<Aggregate> {
        if let Some(m) = self.mock_micro {
            return Some(Aggregate {
                micro_usd: m,
                source_mask: 0,
                contributing: vec!["mock".into()],
            });
        }
        let live = self.live_twaps(now);
        let st = &self.settings;
        if live.len() < st.min_sources {
            return None;
        }
        let med = median(&live.iter().map(|(_, _, t)| *t).collect::<Vec<_>>());
        let kept: Vec<_> = live
            .iter()
            .filter(|(_, _, t)| (t - med).abs() * 10000.0 <= st.outlier_bps * med)
            .collect();
        let venues: HashSet<&str> = kept.iter().map(|(_, v, _)| v.as_str()).collect();
        if kept.len() < st.min_sources || venues.len() < st.min_venues {
            return None;
        }
        let names: Vec<String> = kept.iter().map(|(n, _, _)| n.clone()).collect();
        let mask = source_mask(names.iter().filter_map(|n| self.sources.iter().find(|s| s.name == *n)));
        Some(Aggregate {
            micro_usd: py_round(median(&kept.iter().map(|(_, _, t)| *t).collect::<Vec<_>>())),
            source_mask: mask,
            contributing: names,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(name: &str, kind: &str) -> SourceToml {
        SourceToml {
            name: name.into(),
            kind: Some(kind.into()),
            ..Default::default()
        }
    }

    #[test]
    fn dotted_index_and_selector() {
        let obj = json!({"a": {"b": [10, {"c": "x"}]}, "tickers": [{"market": {"identifier": "n"}, "target": "BTC", "last": 1},
                                                                  {"market": {"identifier": "s"}, "target": "USDT", "last": 2}]});
        assert_eq!(extract_number(&obj, "a.b.0").unwrap(), 10.0);
        assert_eq!(extract(&obj, "a.b.1.c").unwrap(), "x");
        assert_eq!(
            extract_number(&obj, "tickers.[market.identifier=s,target=USDT].last").unwrap(),
            2.0
        );
        assert!(extract(&obj, "tickers.[market.identifier=q].last").is_err());
        assert!(extract(&obj, "a.z").is_err());
        assert!(extract(&obj, "a.b.9").is_err());
        assert!(extract_number(&obj, "a.b.1.c").is_err());
        assert!(split_path("a.[b").is_err());
    }

    #[test]
    fn iso_timestamps_match_python() {
        // datetime.fromisoformat("2026-09-06T05:53:57.841478937Z") -> 1788674037.841478
        let t = parse_iso8601("2026-09-06T05:53:57.841478937Z").unwrap();
        assert!((t - 1_788_674_037.841_478).abs() < 1e-6, "{t}");
        assert_eq!(parse_iso8601("2026-09-06T05:34:00+00:00").unwrap(), 1_788_672_840.0);
        assert_eq!(parse_iso8601("2026-09-06T07:34:00+02:00").unwrap(), 1_788_672_840.0);
        assert_eq!(parse_iso8601("1970-01-01T00:00:00Z").unwrap(), 0.0);
        assert!(parse_iso8601("yesterday").is_none());
    }

    #[test]
    fn presets_expand_and_override() {
        let s = normalize_source(&row("cg", "coingecko_simple")).unwrap();
        assert_eq!(s.venue, "coingecko");
        assert_eq!(s.path, "ycash.usd");
        assert_eq!(s.mask_bit(), Some(1));
        let mut r = row("st", "coingecko_ticker");
        r.market = Some("nonkyc_io".into());
        r.target = Some("BTC".into());
        let s = normalize_source(&r).unwrap();
        assert_eq!(s.venue, "nonkyc_io");
        assert_eq!(s.quote, Quote::Btc);
        assert_eq!(s.path, "tickers.[market.identifier=nonkyc_io,target=BTC].last");
        assert_eq!(s.reject_paths.len(), 2);
        let mut r = row("k", "kraken_ticker");
        r.pair = Some("ETHUSD".into());
        assert_eq!(normalize_source(&r).unwrap().path, "result.ETHUSD.c.0");
        let mut r = row("g", "generic");
        r.url = Some("http://x/".into());
        r.path = Some("p".into());
        r.venue = Some("custom".into());
        let s = normalize_source(&r).unwrap();
        assert_eq!((s.venue.as_str(), s.mask_bit()), ("custom", None));
    }

    #[test]
    fn rejects() {
        assert!(normalize_source(&row("x", "nope")).is_err());
        assert!(normalize_source(&row("g", "generic")).is_err()); // url/path missing
        let mut r = row("cg", "coingecko_simple");
        r.max_spread_bps = Some(100.0);
        assert!(normalize_source(&r).is_err()); // no spread source
        let mut r = row("p", "peatio_ticker");
        r.max_age = Some(10.0);
        assert!(normalize_source(&r).is_err()); // no timestamp
        let mut r = row("cg", "coingecko_simple");
        r.mask_bit = Some(16);
        assert!(normalize_source(&r).is_err());
        assert!(normalize_sources(&[row("a", "coingecko_simple"), row("a", "nonkyc_market")], "sources").is_err());
        let mut r = row("b", "nonkyc_market");
        r.symbol = Some("YEC_BTC".into());
        assert!(normalize_btc_sources(&[r]).is_err());
        assert!(FeedSettingsToml {
            min_sources: Some(0),
            ..Default::default()
        }
        .resolve()
        .is_err());
    }

    #[test]
    fn rounding_is_half_even_like_python() {
        assert_eq!(py_round(2.5), 2);
        assert_eq!(py_round(3.5), 4);
        assert_eq!(py_round(-2.5), -2);
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 2.0, 3.0]), 2.5);
    }

    fn feed(settings: FeedSettings) -> PriceFeed {
        let mut nk = row("nonkyc", "nonkyc_market");
        nk.max_spread_bps = Some(500.0);
        let mut g = row("gen", "generic");
        g.url = Some("http://g/".into());
        g.path = Some("p".into());
        let srcs = normalize_sources(&[row("cg", "coingecko_simple"), nk, g], "sources").unwrap();
        PriceFeed::new(srcs, vec![], settings)
    }

    fn replies(cg: f64, nk: f64, gen: f64, now: f64) -> Replies {
        let mut r = Replies::new();
        r.insert(
            "cg".into(),
            Ok(json!({"ycash": {"usd": cg, "last_updated_at": now}})
                .to_string()
                .into_bytes()),
        );
        r.insert(
            "nonkyc".into(),
            Ok(json!({"lastPriceNumber": nk, "bestBidNumber": nk * 0.999, "bestAskNumber": nk * 1.001, "lastTradeAt": now * 1000.0}).to_string().into_bytes()),
        );
        r.insert("gen".into(), Ok(json!({"p": gen.to_string()}).to_string().into_bytes()));
        r
    }

    #[test]
    fn median_outliers_and_min_venues() {
        let now = 1_789_341_900.0;
        let mut f = feed(FeedSettings::default());
        f.ingest(now, &replies(0.50, 0.52, 0.51, now));
        let a = f.aggregate(now).unwrap();
        assert_eq!((a.micro_usd, a.source_mask), (510_000, 0b1010));
        assert_eq!(a.contributing, vec!["cg", "nonkyc", "gen"]);
        // an outlier is dropped and the aggregate falls below min_sources
        let mut f = feed(FeedSettings::default());
        f.ingest(now, &replies(0.50, 0.52, 0.90, now));
        assert!(f.aggregate(now).is_none());
        let mut f = feed(FeedSettings {
            min_sources: 2,
            ..Default::default()
        });
        f.ingest(now, &replies(0.50, 0.52, 0.90, now));
        assert_eq!(f.aggregate(now).unwrap().micro_usd, 510_000);
        // a fetch failure drops the source; the health table says why
        let mut f = feed(FeedSettings::default());
        let mut r = replies(0.50, 0.52, 0.51, now);
        r.insert("gen".into(), Err("connection refused".into()));
        f.ingest(now, &r);
        assert!(f.aggregate(now).is_none());
        assert_eq!(f.health["gen"].state, "fetch");
        // guards: spread and staleness
        let mut f = feed(FeedSettings::default());
        let mut r = replies(0.50, 0.52, 0.51, now);
        r.insert("nonkyc".into(), Ok(json!({"lastPriceNumber": 0.52, "bestBidNumber": 0.40, "bestAskNumber": 0.60, "lastTradeAt": now * 1000.0}).to_string().into_bytes()));
        f.ingest(now, &r);
        assert_eq!(f.health["nonkyc"].state, "spread");
        f.sources[0].max_age = Some(60.0);
        let mut r = replies(0.50, 0.52, 0.51, now);
        r.insert(
            "cg".into(),
            Ok(json!({"ycash": {"usd": 0.5, "last_updated_at": now - 61.0}})
                .to_string()
                .into_bytes()),
        );
        f.ingest(now, &r);
        assert_eq!(f.health["cg"].state, "stale");
        assert_eq!(f.health["gen"].state, "ok");
    }

    #[test]
    fn window_silence_and_vwap() {
        let now = 1_789_341_900.0;
        let mut f = feed(FeedSettings::default());
        f.ingest(now, &replies(0.40, 0.40, 0.40, now));
        f.ingest(now + 30.0, &replies(0.60, 0.60, 0.60, now + 30.0));
        assert_eq!(f.aggregate(now + 30.0).unwrap().micro_usd, 500_000); // time-weighted mean
        assert!(f.aggregate(now + 30.0 + 121.0).is_none()); // silence
        f.ingest(now + 1000.0, &replies(0.70, 0.70, 0.70, now + 1000.0));
        assert_eq!(f.aggregate(now + 1000.0).unwrap().micro_usd, 700_000); // 15-minute window pruned the old
                                                                           // VWAP where the venue reports cumulative volume
        let mut f = feed(FeedSettings::default());
        let nk = |p: f64, vol: f64, t: f64| {
            json!({"lastPriceNumber": p, "bestBidNumber": p, "bestAskNumber": p, "lastTradeAt": t * 1000.0, "volumeNumber": vol}).to_string().into_bytes()
        };
        for (i, (p, vol)) in [(0.40, 1000.0), (0.50, 1001.0), (0.40, 1004.0)].iter().enumerate() {
            let t = now + 30.0 * i as f64;
            let mut r = replies(0.45, 0.45, 0.45, t);
            r.insert("nonkyc".into(), Ok(nk(*p, *vol, t)));
            f.ingest(t, &r);
        }
        let tw = f.live_twaps(now + 60.0);
        let nk_avg = tw.iter().find(|(n, _, _)| n == "nonkyc").unwrap().2;
        assert_eq!(py_round(nk_avg), py_round((500_000.0 + 400_000.0 * 3.0) / 4.0));
        let mut r = replies(0.45, 0.45, 0.45, now + 90.0);
        r.insert("nonkyc".into(), Ok(nk(0.60, 900.0, now + 90.0)));
        f.ingest(now + 90.0, &r);
        let tw = f.live_twaps(now + 90.0);
        let nk_avg = tw.iter().find(|(n, _, _)| n == "nonkyc").unwrap().2;
        assert_eq!(py_round(nk_avg), (400_000 + 500_000 + 400_000 + 600_000) / 4);
    }

    #[test]
    fn mock_mode_is_the_whole_market() {
        let mut f = feed(FeedSettings::default());
        f.ingest_mock(Some(0.05));
        let a = f.aggregate(0.0).unwrap();
        assert_eq!(
            (a.micro_usd, a.source_mask, a.contributing.as_slice()),
            (50_000, 0, &["mock".to_string()][..])
        );
        f.ingest_mock(None);
        assert!(f.aggregate(0.0).is_none());
    }
}
