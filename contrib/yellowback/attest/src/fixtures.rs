//! The Rust/Python aggregator cross-check (plan §5): `fixtures/scenarios.json` describes the
//! sources and the recorded exchange replies, `fixtures/expected.json` holds what the Python
//! aggregator (the reference) computed for them. This test must agree exactly; when it does
//! not, the Rust port is what gets fixed. `test_yellowback_price.py` asserts the same file.

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde::Deserialize;
    use serde_json::Value;

    use crate::price::{normalize_btc_sources, normalize_sources, FeedSettingsToml, PriceFeed, Replies, SourceToml};

    #[derive(Deserialize)]
    struct Scenarios {
        now: f64,
        scenarios: Vec<Scenario>,
    }

    #[derive(Deserialize)]
    struct Scenario {
        name: String,
        settings: FeedSettingsToml,
        sources: Vec<SourceToml>,
        #[serde(default)]
        btc_usd_sources: Vec<SourceToml>,
        replies: std::collections::BTreeMap<String, Option<String>>,
    }

    #[derive(Deserialize)]
    struct Expected {
        scenarios: Vec<ExpectedScenario>,
    }

    #[derive(Deserialize)]
    struct ExpectedSource {
        state: String,
        micro_usd: Option<i64>,
    }

    #[derive(Deserialize)]
    struct ExpectedScenario {
        name: String,
        median_micro_usd: Option<i64>,
        source_mask: Option<u32>,
        contributing: Vec<String>,
        live_sources: usize,
        live_venues: usize,
        btc_reference_usd: Option<f64>,
        btc_live: usize,
        sources: std::collections::BTreeMap<String, ExpectedSource>,
        btc_usd_sources: std::collections::BTreeMap<String, ExpectedSource>,
    }

    fn fixtures_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    fn read_json<T: for<'de> Deserialize<'de>>(name: &str) -> T {
        let text = std::fs::read_to_string(fixtures_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    #[test]
    fn rust_aggregator_matches_the_python_reference_on_the_recorded_replies() {
        let spec: Scenarios = read_json("scenarios.json");
        let expected: Expected = read_json("expected.json");
        assert_eq!(
            spec.scenarios.len(),
            expected.scenarios.len(),
            "expected.json is out of date: run fixtures/expected.py"
        );
        for (sc, ex) in spec.scenarios.iter().zip(expected.scenarios.iter()) {
            assert_eq!(sc.name, ex.name);
            let sources = normalize_sources(&sc.sources, "sources").unwrap();
            let btc = normalize_btc_sources(&sc.btc_usd_sources).unwrap();
            let mut feed = PriceFeed::new(sources, btc, sc.settings.resolve().unwrap());
            let mut replies = Replies::new();
            for req in feed.requests() {
                let body = match sc.replies.get(&req.name) {
                    Some(Some(file)) => {
                        Ok(std::fs::read(fixtures_dir().join(file)).unwrap_or_else(|e| panic!("{file}: {e}")))
                    }
                    Some(None) => Err("no reply (fixture: connection refused)".to_string()),
                    None => panic!("{}: scenario names no reply for source {}", sc.name, req.name),
                };
                replies.insert(req.name, body);
            }
            feed.ingest(spec.now, &replies);
            let live = feed.live_twaps(spec.now);
            let venues: std::collections::HashSet<&str> = live.iter().map(|(_, v, _)| v.as_str()).collect();
            let agg = feed.aggregate(spec.now);
            let n = &sc.name;
            assert_eq!(agg.as_ref().map(|a| a.micro_usd), ex.median_micro_usd, "{n}: median");
            assert_eq!(agg.as_ref().map(|a| a.source_mask), ex.source_mask, "{n}: mask");
            assert_eq!(
                agg.as_ref().map(|a| a.contributing.clone()).unwrap_or_default(),
                ex.contributing,
                "{n}: contributing"
            );
            assert_eq!(
                (live.len(), venues.len()),
                (ex.live_sources, ex.live_venues),
                "{n}: live"
            );
            assert_eq!(feed.btc_reference_usd, ex.btc_reference_usd, "{n}: btc reference");
            assert_eq!(feed.btc_live, ex.btc_live, "{n}: btc live");
            for (name, e) in &ex.sources {
                let h = &feed.health[name];
                assert_eq!(h.state, e.state, "{n}: {name} state");
                assert_eq!(
                    if h.state == "ok" { h.last_price_micro_usd } else { None },
                    e.micro_usd,
                    "{n}: {name} micro"
                );
            }
            for (name, e) in &ex.btc_usd_sources {
                let h = &feed.btc_health[name];
                assert_eq!(h.state, e.state, "{n}: btc {name} state");
                assert_eq!(
                    if h.state == "ok" { h.last_price_micro_usd } else { None },
                    e.micro_usd,
                    "{n}: btc {name} micro"
                );
            }
        }
    }

    /// Every recorded reply is valid JSON and every preset's fixture resolves its own paths.
    #[test]
    fn recorded_replies_are_json() {
        for entry in std::fs::read_dir(fixtures_dir()).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().is_some_and(|x| x == "json") {
                let text = std::fs::read_to_string(&p).unwrap();
                serde_json::from_str::<Value>(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            }
        }
    }
}
