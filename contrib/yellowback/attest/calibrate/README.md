# Calibration scripts (proposal §16, "Measurements")

Two measurements precede the first mainnet attestor registration; both are fixed in the release
that opens registration (v3 plan §6 "Launch", §11 item 3). Neither touches a node. Python
≥ 3.11 from the workspace venv, standard library plus `contrib/yellowback/yellowback_price.py`
(imported for its presets and fetcher — the scripts read the exchanges exactly as the quote and
attestor agents do). No new dependencies.

| Script | Constant | Input | Output |
|---|---|---|---|
| `spreads.py` | `DIVERGE_BPS_ATTEST` (MINT-10, provisional 1,500 bps) | two weeks of CoinGecko / SafeTrade / nonkyc.io prices at a five-minute cadence, logged by the script itself | the pairwise spread distribution, the worst pair's p95 and `3 × p95` rounded up to 100 bps |
| `pinrate.py` | `PIN_WINDOW` / `PIN_DELTA_BPS` (PIN-1/PIN-2, provisional 288 / 500) | hourly YEC/USD history (CoinGecko `market_chart`, or a CSV) | the arming rate over rolling 6-hour windows, the longest quiet run, the decision |

## 1. `spreads.py` — two weeks of logging, then `analyze`

```
V=../../.venv/bin/python           # from ycash-dd/; the scripts also run as executables
# a) one process for two weeks (SIGTERM/SIGINT stop it cleanly; the CSV is appended, never rewritten)
$V contrib/yellowback/attest/calibrate/spreads.py log --out spreads.csv --interval 300 --duration 14
# b) or from cron, one row per invocation (exit 1 when a source failed; the row is still written)
*/5 * * * *  /path/.venv/bin/python /path/contrib/yellowback/attest/calibrate/spreads.py log --out /var/lib/yellowback/spreads.csv --once
# c) after two weeks
$V contrib/yellowback/attest/calibrate/spreads.py analyze spreads.csv --interval 300
```

`log` fetches the three sources of `attest.toml.sample` — `coingecko` (`coingecko_simple`, the
aggregate), `safetrade` (`coingecko_ticker`, `market = safe_trade`: SafeTrade's own API answers
scripts with a Cloudflare 403, so its price is read as CoinGecko reports it) and `nonkyc`
(`nonkyc_market`, `YEC_USDT`) — through `PriceFeed.poll`, so freshness and shape checks are the
agents' own. A row is written on every tick even when a source failed (the column is empty and
the `errors` column says why), so the log also records outages. `--api-key` passes a CoinGecko
demo key; the public API allows the default cadence without one. Run it somewhere that will stay
up (the attestor's own host is fine — it is read-only traffic, ~3 requests per five minutes).

`analyze` prints, per pair, `n`, median, p90, p95, p99 and max of `|a − b| · 10⁴ / min(a, b)` in
bps (MINT-10's form), the rows missing per source, the gaps (consecutive rows more than
`--gap-factor` × `--interval` apart; a restart or an outage of the logging host — inspect them,
they are not excluded), the worst pair's p95 and the recommendation:

```
worst-pair p95: 179 bps (safetrade/nonkyc)
recommended DIVERGE_BPS_ATTEST ~= 3 x p95 = 600 bps (provisional value in the proposal: 1500)
```

"Under normal conditions" is a judgement the script does not make for you: if the fortnight held
an exchange outage or a listing event, look at the p99/max columns and the gap list and decide
whether to drop those days (`analyze` on a trimmed copy of the CSV) or to keep them as the
conditions the threshold must survive. The proposal biases larger; never set the constant below
the recommendation, and keep the CSV with the release notes.

## 2. `pinrate.py` — the arming rate

```
$V contrib/yellowback/attest/calibrate/pinrate.py --days 90 --save-csv yec-hourly.csv      # CoinGecko, hourly
$V contrib/yellowback/attest/calibrate/pinrate.py --from-csv yec-hourly.csv                 # offline re-run
$V contrib/yellowback/attest/calibrate/pinrate.py --from-csv yec-hourly.csv --window-blocks 288 --block-seconds 75 --delta-bps 500
```

For every sample as a window's end, the window is `(end − PIN_WINDOW · 75 s, end]`. PIN-1's form —
`(hi − lo) · 10⁴ > PIN_DELTA_BPS · lo` over the prices in the window — decides whether it armed;
the **arming rate** is the fraction of windows that did. The **longest quiet run** is the longest
sequence of consecutive un-armed windows: the longest a stuck quote could have gone un-pinned in
that history. PIN-2's form (the price one window back against the price at the end) is printed
beside it for reference. The table repeats the figures at 200 and 300 bps so the fallback needs
no second run:

```
delta_bps     armed       rate    rate(PIN-2)    longest quiet run
200            2086      96.8%          68.4%    5 windows (5.0 h)
300            1812      84.1%          55.6%   13 windows (13.0 h)
500            1043      48.4%          31.9%   40 windows (40.0 h)

arming rate 48.4% at 500 bps > 20%: PIN_WINDOW = 288 / PIN_DELTA_BPS = 500 confirmed
```

The decision line applies the proposal's rule: above ~20 % confirms; below ~5 % drop
`PIN_DELTA_BPS` to 200–300 (pick the smaller of the two whose rate clears 20 % and whose quiet
run you can live with); between them, keep 500 unless the quiet run is unacceptable. The CSV
shape is `ts,price_usd` (or `ts_iso,ts,price_usd`, what `--save-csv` writes); any hourly source
will do, CoinGecko is just the one with a free 90-day hourly endpoint.

## Tests

```
../../.venv/bin/python -m unittest contrib/yellowback/attest/calibrate/test_calibrate.py
../../.venv/bin/python -m pyflakes contrib/yellowback/attest/calibrate/*.py
```

Offline: `log --once` runs against canned exchange replies, both analyses against synthetic
CSVs. The CI `python` job runs both.
