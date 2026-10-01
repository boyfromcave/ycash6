//! `attest`: poll the node for the tip every `poll_seconds`; every `every_blocks` new blocks
//! aggregate the sources, ask the node to sign (`yed_signattestation`, the key never leaves the
//! node) and publish the 74 bytes. After `fail_polls` consecutive failed aggregates publish
//! nothing until a good one (plan §5; L5's rule). RPC failures are logged and retried on the
//! next tick; the loop never exits on its own.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::{AttestConfig, Config};
use crate::framing::Attestation;
use crate::price::{PriceFeed, Replies, Request};
use crate::rpc::{Node, RpcError};
use crate::transport::{self, Transport};

pub struct Fetcher {
    client: reqwest::Client,
}

impl Fetcher {
    pub fn new(timeout_seconds: u64) -> anyhow::Result<Self> {
        crate::tls::install();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .user_agent("yellowback-attest/3")
            .build()?;
        Ok(Fetcher { client })
    }

    pub async fn fetch_all(&self, requests: &[Request]) -> Replies {
        let futs = requests.iter().map(|r| async move {
            let mut req = self.client.get(&r.url).header("Accept", "application/json");
            for (k, v) in &r.headers {
                req = req.header(k, v);
            }
            let result = match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    match resp.bytes().await {
                        Ok(b) if status.is_success() => Ok(b.to_vec()),
                        Ok(_) => Err(format!("HTTP {}", status.as_u16())),
                        Err(e) => Err(e.to_string()),
                    }
                }
                Err(e) => Err(e.to_string()),
            };
            (r.name.clone(), result)
        });
        n0_future::join_all(futs).await.into_iter().collect()
    }
}

pub fn now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// The mock file's USD price (tests and devnet), or None when unreadable (logged).
pub fn read_mock(path: &Path) -> Option<f64> {
    match std::fs::read_to_string(path)
        .map_err(|e| e.to_string())
        .and_then(|s| s.trim().parse::<f64>().map_err(|e| e.to_string()))
    {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!("mock price unreadable: {e}");
            None
        }
    }
}

/// One poll of the sources followed by the aggregate; shared by `attest` and `sources`.
pub async fn poll_and_aggregate(
    feed: &mut PriceFeed,
    fetcher: &Fetcher,
    mock: Option<&Path>,
) -> Option<crate::price::Aggregate> {
    let now = now_seconds();
    match mock {
        Some(p) => feed.ingest_mock(read_mock(p)),
        None => {
            let replies = fetcher.fetch_all(&feed.requests()).await;
            feed.ingest(now, &replies);
        }
    }
    feed.aggregate(now)
}

/// The decision logic of one tick, separated from the clock and the RPC for the tests.
pub struct Cadence {
    pub every_blocks: u32,
    pub fail_polls: u32,
    pub last_attested_height: Option<u32>,
    pub failures: u32,
}

impl Cadence {
    pub fn new(cfg: &AttestConfig) -> Self {
        Cadence {
            every_blocks: cfg.every_blocks,
            fail_polls: cfg.fail_polls,
            last_attested_height: None,
            failures: 0,
        }
    }

    /// Whether `height` is a tick at which to attest: the first height seen, then every
    /// `every_blocks` new blocks after the last attested one.
    pub fn due(&self, height: u32) -> bool {
        match self.last_attested_height {
            None => true,
            Some(last) => height >= last.saturating_add(self.every_blocks),
        }
    }

    /// Record a failed aggregate at a due tick; true once `fail_polls` have failed in a row (L5).
    pub fn failed(&mut self) -> bool {
        self.failures = self.failures.saturating_add(1);
        self.failures >= self.fail_polls
    }

    pub fn succeeded(&mut self) {
        self.failures = 0;
    }
}

pub struct Attestor {
    pub cfg: Config,
    pub node: Node,
    pub feed: PriceFeed,
    pub fetcher: Fetcher,
    pub cadence: Cadence,
    pub mock: Option<PathBuf>,
    pub seq: u16,
    pub published: u64,
}

impl Attestor {
    pub fn new(cfg: Config, mock: Option<PathBuf>) -> anyhow::Result<Self> {
        let seq = cfg
            .attest
            .seq
            .ok_or_else(|| anyhow::anyhow!("[attest] seq is required for `attest`"))?;
        if mock.is_none() && cfg.sources.is_empty() {
            anyhow::bail!("no [[sources]] configured (or pass --mock-price)");
        }
        let node = Node::new(&cfg.node)?;
        let feed = PriceFeed::new(
            cfg.sources.clone(),
            cfg.btc_usd_sources.clone(),
            cfg.attest.feed.clone(),
        );
        let fetcher = Fetcher::new(cfg.attest.feed.fetch_timeout)?;
        let cadence = Cadence::new(&cfg.attest);
        Ok(Attestor {
            cfg,
            node,
            feed,
            fetcher,
            cadence,
            mock,
            seq,
            published: 0,
        })
    }

    /// `yed_getinfo` until the node answers; returns `(network, height)`.
    pub async fn getinfo(&self) -> Result<(String, i64), RpcError> {
        let v = self.node.call("yed_getinfo", vec![]).await?;
        let network = v
            .get("network")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let height = v.get("height").and_then(Value::as_i64).unwrap_or(-1);
        Ok((network, height))
    }

    pub async fn wait_network(&self) -> String {
        loop {
            match self.getinfo().await {
                Ok((network, _)) => return network,
                Err(e) => {
                    tracing::error!(
                        "yed_getinfo failed ({e}); retrying in {} s",
                        self.cfg.attest.poll_seconds
                    );
                    tokio::time::sleep(Duration::from_secs(self.cfg.attest.poll_seconds)).await;
                }
            }
        }
    }

    /// One poll at `height`: the sources are polled every time (so the window of §10.1 fills at
    /// `poll_seconds`, as the quote agent's does); signing happens only at a due tick. A failed
    /// aggregate at a due tick does not consume the tick — the next poll tries again.
    pub async fn tick(&mut self, height: u32, transport: &mut dyn Transport) -> Tick {
        let agg = poll_and_aggregate(&mut self.feed, &self.fetcher, self.mock.as_deref()).await;
        if !self.cadence.due(height) {
            return Tick::NotDue;
        }
        let Some(agg) = agg else {
            let suppressed = self.cadence.failed();
            let live = self.feed.health.values().filter(|h| h.state == "ok").count();
            let msg = format!(
                "no aggregate at height {height} ({}/{} failed polls): {live} live source(s), need {}/{}; nothing published",
                self.cadence.failures, self.cadence.fail_polls, self.feed.settings.min_sources, self.feed.settings.min_venues
            );
            if suppressed && self.cadence.failures == self.cadence.fail_polls {
                tracing::warn!("{msg} — publishing nothing until a good aggregate (L5)");
            } else if suppressed {
                tracing::debug!("{msg}");
            } else {
                tracing::warn!("{msg}");
            }
            return Tick::NoAggregate;
        };
        self.cadence.succeeded();
        let cited = height.saturating_sub(self.cfg.attest.ref_lag);
        if agg.micro_usd < 0 || agg.micro_usd > u32::MAX as i64 {
            tracing::error!("aggregate {} µUSD is outside u32; not signed", agg.micro_usd);
            return Tick::NoAggregate;
        }
        let reply = match self
            .node
            .call(
                "yed_signattestation",
                vec![json!(self.seq), json!(agg.micro_usd), json!(cited)],
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    "yed_signattestation {} {} {cited} failed: {e}; retrying next tick",
                    self.seq,
                    agg.micro_usd
                );
                return Tick::RpcError;
            }
        };
        let hex_str = reply.get("hex").and_then(Value::as_str).unwrap_or("");
        let att = match Attestation::decode_hex(hex_str) {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("yed_signattestation returned something that is not an attestation: {e}");
                return Tick::RpcError;
            }
        };
        let reused = reply.get("reused").and_then(Value::as_bool).unwrap_or(false);
        if let Err(e) = transport.publish(&att.encode()).await {
            tracing::error!("publish on {} failed: {e}; retrying next tick", transport.name());
            return Tick::PublishError;
        }
        self.cadence.last_attested_height = Some(height);
        self.published += 1;
        tracing::info!(
            "published seq {} {} µUSD (${:.6}) citing height {}{} from {} via {}",
            att.seq,
            att.price_micro_usd,
            att.price_micro_usd as f64 / crate::price::MICRO,
            att.cited_height,
            if reused {
                " (node reused its earlier signature)"
            } else {
                ""
            },
            agg.contributing.join(","),
            transport.name()
        );
        Tick::Published(att)
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let network = self.wait_network().await;
        let mut transport = transport::open(&self.cfg.transport, &network).await?;
        tracing::info!(
            "yellowback-attest attest: seq {}, network {network}, every {} blocks, ref_lag {}, poll {} s, transport {}{}",
            self.seq,
            self.cfg.attest.every_blocks,
            self.cfg.attest.ref_lag,
            self.cfg.attest.poll_seconds,
            transport.name(),
            self.mock.as_ref().map(|p| format!(" (mock price {})", p.display())).unwrap_or_default()
        );
        let poll = Duration::from_secs(self.cfg.attest.poll_seconds);
        loop {
            match self.getinfo().await {
                Ok((_, h)) if h >= 0 => {
                    self.tick(h as u32, transport.as_mut()).await;
                }
                Ok(_) => tracing::warn!("node index is empty (height -1); waiting"),
                Err(e) => tracing::error!("yed_getinfo failed: {e}; retrying"),
            }
            tokio::select! {
                _ = tokio::time::sleep(poll) => {}
                _ = tokio::signal::ctrl_c() => { tracing::info!("stopping"); return Ok(()); }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tick {
    NotDue,
    NoAggregate,
    RpcError,
    PublishError,
    Published(Attestation),
}

/// `sources`: fetch every source once and print what resolved. Exit 1 when no aggregate results.
pub async fn sources_command(cfg: &Config) -> anyhow::Result<i32> {
    if cfg.sources.is_empty() {
        eprintln!("no [[sources]] configured");
        return Ok(1);
    }
    let mut feed = PriceFeed::new(
        cfg.sources.clone(),
        cfg.btc_usd_sources.clone(),
        cfg.attest.feed.clone(),
    );
    let fetcher = Fetcher::new(cfg.attest.feed.fetch_timeout)?;
    let agg = poll_and_aggregate(&mut feed, &fetcher, None).await;
    let table = |title: &str, sources: &[crate::price::Source], health: &BTreeMap<String, crate::price::Health>| {
        if sources.is_empty() {
            return;
        }
        println!("{title}");
        println!(
            "  {:<18} {:<12} {:<16} {:<7} {:<5} {:>12} {:>7} {:>9}  detail",
            "source", "venue", "kind", "state", "quote", "micro_usd", "age_s", "spread"
        );
        for s in sources {
            let h = &health[&s.name];
            let ok = h.state == "ok";
            println!(
                "  {:<18} {:<12} {:<16} {:<7} {:<5} {:>12} {:>7} {:>9}  {}",
                s.name,
                s.venue,
                s.kind,
                h.state,
                match s.quote {
                    crate::price::Quote::Usd => "USD",
                    crate::price::Quote::Btc => "BTC",
                },
                if ok {
                    h.last_price_micro_usd.map(|m| m.to_string()).unwrap_or_default()
                } else {
                    String::new()
                },
                if ok {
                    h.last_age_seconds.map(|a| format!("{a:.0}")).unwrap_or_default()
                } else {
                    String::new()
                },
                if ok {
                    h.last_spread_bps.map(|b| format!("{b:.0} bps")).unwrap_or_default()
                } else {
                    String::new()
                },
                h.last_error.clone().unwrap_or_default()
            );
        }
    };
    if feed.needs_btc_reference() {
        table(
            "BTC/USD references (for BTC-quoted pairs):",
            &cfg.btc_usd_sources,
            &feed.btc_health,
        );
        println!(
            "  reference: {} ({} live, need min_btc_sources={})",
            feed.btc_reference_usd
                .map(|u| format!("${u:.2}"))
                .unwrap_or_else(|| "none".into()),
            feed.btc_live,
            feed.settings.min_btc_sources
        );
    }
    table("YEC/USD sources:", &cfg.sources, &feed.health);
    let live = feed.live_twaps(now_seconds());
    let venues: std::collections::HashSet<&str> = live.iter().map(|(_, v, _)| v.as_str()).collect();
    println!(
        "live: {} source(s) from {} venue(s); need min_sources={}, min_venues={}; outlier_bps={}",
        live.len(),
        venues.len(),
        feed.settings.min_sources,
        feed.settings.min_venues,
        feed.settings.outlier_bps
    );
    match agg {
        None => {
            println!("median: none (nothing would be attested)");
            Ok(1)
        }
        Some(a) => {
            println!(
                "median: {} micro-USD (${:.6}), sourceMask 0x{:04x} from {}",
                a.micro_usd,
                a.micro_usd as f64 / crate::price::MICRO,
                a.source_mask,
                a.contributing.join(",")
            );
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::rpc::mock::MockNode;
    use crate::transport::dir::DirTransport;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn signed(seq: u16, price: u32, cited: u32) -> Attestation {
        Attestation {
            seq,
            price_micro_usd: price,
            cited_height: cited,
            sig: [0x5a; 64],
        }
    }

    #[test]
    fn cadence() {
        let cfg =
            config::parse("[node]\nrpc_url = \"http://h:1\"\n[attest]\nevery_blocks = 4\nfail_polls = 2\n").unwrap();
        let mut c = Cadence::new(&cfg.attest);
        assert!(c.due(100));
        c.last_attested_height = Some(100);
        assert!(!c.due(103));
        assert!(c.due(104));
        assert!(c.due(150));
        assert!(!c.failed());
        assert!(c.failed());
        assert!(c.failed());
        c.succeeded();
        assert_eq!(c.failures, 0);
    }

    /// The attest loop against a mock node and the dir transport: signs at cited = height - ref_lag,
    /// publishes the node's bytes, skips ticks that are not due, and goes quiet after fail_polls.
    #[tokio::test]
    async fn tick_signs_publishes_and_suppresses() {
        let sign_calls = Arc::new(AtomicU32::new(0));
        let sc = sign_calls.clone();
        let m = MockNode::start(None, move |method, params| match method {
            "yed_getinfo" => Ok(json!({"network": "regtest", "height": 200})),
            "yed_signattestation" => {
                sc.fetch_add(1, Ordering::SeqCst);
                let seq = params[0].as_u64().unwrap() as u16;
                let price = params[1].as_u64().unwrap() as u32;
                let cited = params[2].as_u64().unwrap() as u32;
                Ok(
                    json!({"hex": signed(seq, price, cited).to_hex(), "seq": seq, "citedHeight": cited, "reused": false}),
                )
            }
            _ => Err((-32601, "Method not found".into())),
        });
        let dir = tempfile::tempdir().unwrap();
        let mock = dir.path().join("price");
        std::fs::write(&mock, "0.5\n").unwrap();
        let text = format!(
            "[node]\nrpc_url = \"{}\"\n[attest]\nseq = 3\nevery_blocks = 4\nfail_polls = 2\nref_lag = 2\n[transport]\nkind = \"dir\"\npath = \"{}\"\n",
            m.url,
            dir.path().join("bus").display()
        );
        let cfg = config::parse(&text).unwrap();
        let mut a = Attestor::new(cfg.clone(), Some(mock.clone())).unwrap();
        assert_eq!(a.wait_network().await, "regtest");
        let mut t = DirTransport::open(&dir.path().join("bus")).unwrap();
        let mut sub = DirTransport::open(&dir.path().join("bus"))
            .unwrap()
            .with_poll(Duration::from_millis(10));

        let r = a.tick(200, &mut t).await;
        assert_eq!(r, Tick::Published(signed(3, 500_000, 198)));
        assert_eq!(
            Attestation::decode(&sub.recv().await.unwrap()).unwrap(),
            signed(3, 500_000, 198)
        );
        assert_eq!(a.tick(203, &mut t).await, Tick::NotDue);
        std::fs::write(&mock, "0.6\n").unwrap();
        assert_eq!(a.tick(204, &mut t).await, Tick::Published(signed(3, 600_000, 202)));
        assert!(dir.path().join("bus/3-202.att").exists());

        // two failed aggregates: nothing published, nothing signed; the next good one publishes again
        std::fs::remove_file(&mock).unwrap();
        assert_eq!(a.tick(208, &mut t).await, Tick::NoAggregate);
        assert_eq!(a.tick(212, &mut t).await, Tick::NoAggregate);
        assert_eq!(a.cadence.failures, 2);
        assert_eq!(sign_calls.load(Ordering::SeqCst), 2);
        std::fs::write(&mock, "0.55\n").unwrap();
        assert_eq!(a.tick(216, &mut t).await, Tick::Published(signed(3, 550_000, 214)));
        assert_eq!(a.published, 3);
        assert_eq!(a.cadence.failures, 0);
    }

    #[tokio::test]
    async fn rpc_failure_is_retried_next_tick_not_fatal() {
        let m = MockNode::start(None, |method, _| match method {
            "yed_signattestation" => Err((-8, "attest-key-not-held".into())),
            _ => Ok(json!({"network": "regtest", "height": 10})),
        });
        let dir = tempfile::tempdir().unwrap();
        let mock = dir.path().join("price");
        std::fs::write(&mock, "1.0").unwrap();
        let cfg = config::parse(&format!(
            "[node]\nrpc_url = \"{}\"\n[attest]\nseq = 1\n[transport]\nkind = \"dir\"\npath = \"{}\"\n",
            m.url,
            dir.path().display()
        ))
        .unwrap();
        let mut a = Attestor::new(cfg, Some(mock)).unwrap();
        let mut t = DirTransport::open(dir.path()).unwrap();
        assert_eq!(a.tick(10, &mut t).await, Tick::RpcError);
        // the tick was not consumed: the next poll at the same height tries again
        assert_eq!(a.tick(10, &mut t).await, Tick::RpcError);
        assert_eq!(a.published, 0);
    }

    #[test]
    fn attest_needs_seq_and_sources() {
        let cfg = config::parse("[node]\nrpc_url = \"http://h:1\"\n[transport]\nkind = \"dir\"\npath = \"/tmp/x\"\n")
            .unwrap();
        assert!(Attestor::new(cfg.clone(), None).is_err());
        let cfg = config::parse(
            "[node]\nrpc_url = \"http://h:1\"\n[attest]\nseq = 1\n[transport]\nkind = \"dir\"\npath = \"/tmp/x\"\n",
        )
        .unwrap();
        assert!(Attestor::new(cfg.clone(), None).is_err());
        assert!(Attestor::new(cfg, Some(PathBuf::from("/dev/null"))).is_ok());
    }
}
