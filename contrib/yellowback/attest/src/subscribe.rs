// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! `subscribe`: join the topic and feed the node's attestation pool. Each message is dropped
//! unless it is 74 bytes (or that as hex) and its `seq` is in the last `yed_listattestors`
//! (refreshed every `listattestors_seconds`); then, since the topic is public and anyone can
//! broadcast on it (audit D-5), before the RPC: frames already handed to the node are dropped
//! (an LRU keyed by SHA-256 of the 74 bytes), `citedHeight` must lie in a window around the
//! node's tip (cached from `yed_getinfo` at every refresh), each `seq` has a token bucket, and
//! an RPC transport failure backs the loop off (bounded, 1..60 s). Everything else goes to
//! `yed_addattestation`, which verifies the signature. Acceptances are counted. Optional
//! `[subscribe] endpoints` are HTTPS URLs polled as a second path (plan §5, proposal §13).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::framing::{parse_message, Attestation};
use crate::rpc::{Node, RpcError};
use crate::transport;

/// Frames already handed to the node that are still remembered (74 bytes each is cheap).
pub const DEDUP_CAPACITY: usize = 4096;
/// `citedHeight` may trail the cached tip by this much (the node's own ATTEST_MAX_AGE is 20
/// blocks; the cache is at most `listattestors_seconds` old) ...
pub const CITED_BEHIND_MAX: u32 = 64;
/// ... and lead it by this much (a block found since the cache was taken).
pub const CITED_AHEAD_MAX: u32 = 8;
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Not 74 bytes / not hex of 74 bytes.
    Malformed,
    /// `seq` not in the last `yed_listattestors`.
    UnknownSeq(u16),
    /// The same 74 bytes were already handed to the node.
    Duplicate(u16),
    /// `citedHeight` is not within `[tip - CITED_BEHIND_MAX, tip + CITED_AHEAD_MAX]`.
    OutOfWindow(u16, u32),
    /// This `seq` has sent more frames than its token bucket allows.
    RateLimited(u16),
    /// The node's RPC failed recently; nothing is pushed until the backoff lapses.
    BackingOff(u16),
    /// The node accepted it (`accepted: true`).
    Accepted(u16, bool),
    /// The node refused it (`attest-stale`, `attest-bad-sig`, ...).
    Refused(u16, String),
    /// RPC transport failure; the message is dropped (the attestor publishes again next tick).
    RpcError(String),
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct Subscriber {
    pub cfg: Config,
    pub node: Node,
    pub known_seqs: HashSet<u16>,
    /// The node's height at the last refresh; None until `yed_getinfo` has answered (no window
    /// filter until then).
    pub tip: Option<u32>,
    seen_set: HashSet<[u8; 32]>,
    seen_order: VecDeque<[u8; 32]>,
    buckets: HashMap<u16, Bucket>,
    backoff_until: Option<Instant>,
    backoff_steps: u32,
    pub accepted: u64,
    pub seen: u64,
    /// Frames dropped before the RPC by the D-5 filters, for the stop line.
    pub filtered: u64,
}

impl Subscriber {
    pub fn new(cfg: Config) -> anyhow::Result<Self> {
        let node = Node::new(&cfg.node)?;
        Ok(Subscriber {
            cfg,
            node,
            known_seqs: HashSet::new(),
            tip: None,
            seen_set: HashSet::new(),
            seen_order: VecDeque::new(),
            buckets: HashMap::new(),
            backoff_until: None,
            backoff_steps: 0,
            accepted: 0,
            seen: 0,
            filtered: 0,
        })
    }

    /// `yed_listattestors` → the set of registered `seq` values. On failure the previous set stays.
    pub async fn refresh_attestors(&mut self) -> Result<usize, RpcError> {
        let v = self.node.call("yed_listattestors", vec![]).await?;
        let seqs: HashSet<u16> = v
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| r.get("seq").and_then(Value::as_u64))
                    .filter_map(|s| u16::try_from(s).ok())
                    .collect()
            })
            .unwrap_or_default();
        self.known_seqs = seqs;
        Ok(self.known_seqs.len())
    }

    /// `yed_getinfo.height` → the cached tip for the window filter. On failure the previous stays.
    pub async fn refresh_tip(&mut self) -> Result<Option<u32>, RpcError> {
        let v = self.node.call("yed_getinfo", vec![]).await?;
        if let Some(h) = v
            .get("height")
            .and_then(Value::as_i64)
            .and_then(|h| u32::try_from(h).ok())
        {
            self.tip = Some(h);
        }
        Ok(self.tip)
    }

    fn in_window(&self, cited: u32) -> bool {
        match self.tip {
            None => true,
            Some(tip) => cited <= tip.saturating_add(CITED_AHEAD_MAX) && cited.saturating_add(CITED_BEHIND_MAX) >= tip,
        }
    }

    fn take_token(&mut self, seq: u16, now: Instant) -> bool {
        let burst = self.cfg.subscribe.seq_burst as f64;
        let refill = self.cfg.subscribe.seq_refill_seconds as f64;
        let b = self.buckets.entry(seq).or_insert(Bucket {
            tokens: burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed / refill).min(burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn remember(&mut self, digest: [u8; 32]) {
        if self.seen_set.insert(digest) {
            self.seen_order.push_back(digest);
            while self.seen_order.len() > DEDUP_CAPACITY {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen_set.remove(&old);
                }
            }
        }
    }

    /// Filter one message and push it to the node.
    pub async fn handle(&mut self, body: &[u8]) -> Outcome {
        self.handle_at(body, Instant::now()).await
    }

    pub async fn handle_at(&mut self, body: &[u8], now: Instant) -> Outcome {
        self.seen += 1;
        let att = match parse_message(body) {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!("dropped: {e}");
                return Outcome::Malformed;
            }
        };
        if !self.known_seqs.contains(&att.seq) {
            tracing::debug!("dropped: seq {} is not a registered attestor", att.seq);
            return Outcome::UnknownSeq(att.seq);
        }
        let digest: [u8; 32] = Sha256::digest(att.encode()).into();
        if self.seen_set.contains(&digest) {
            self.filtered += 1;
            tracing::debug!(
                "dropped: seq {} citing {} already handed to the node",
                att.seq,
                att.cited_height
            );
            return Outcome::Duplicate(att.seq);
        }
        if !self.in_window(att.cited_height) {
            self.filtered += 1;
            tracing::debug!(
                "dropped: seq {} cites height {} but the node is at {:?}",
                att.seq,
                att.cited_height,
                self.tip
            );
            return Outcome::OutOfWindow(att.seq, att.cited_height);
        }
        if self.backoff_until.is_some_and(|t| now < t) {
            self.filtered += 1;
            return Outcome::BackingOff(att.seq);
        }
        if !self.take_token(att.seq, now) {
            self.filtered += 1;
            tracing::debug!("dropped: seq {} is over its rate limit", att.seq);
            return Outcome::RateLimited(att.seq);
        }
        let outcome = self.push(&att).await;
        match outcome {
            Outcome::RpcError(_) => {
                let wait = Duration::from_secs(1u64 << self.backoff_steps.min(6)).min(BACKOFF_MAX);
                self.backoff_until = Some(now + wait);
                self.backoff_steps = self.backoff_steps.saturating_add(1);
                tracing::warn!("node RPC failed; not pushing for {} s", wait.as_secs());
            }
            _ => {
                self.backoff_until = None;
                self.backoff_steps = 0;
                self.remember(digest);
            }
        }
        outcome
    }

    async fn push(&mut self, att: &Attestation) -> Outcome {
        match self.node.call("yed_addattestation", vec![json!(att.to_hex())]).await {
            Ok(v) => {
                let accepted = v.get("accepted").and_then(Value::as_bool).unwrap_or(false);
                let replaced = v.get("replaced").and_then(Value::as_bool).unwrap_or(false);
                if accepted {
                    self.accepted += 1;
                    tracing::info!(
                        "accepted seq {} {} µUSD citing {}{} (total {})",
                        att.seq,
                        att.price_micro_usd,
                        att.cited_height,
                        if replaced { ", replaced an older one" } else { "" },
                        self.accepted
                    );
                    Outcome::Accepted(att.seq, replaced)
                } else {
                    tracing::debug!("node did not pool seq {} citing {}", att.seq, att.cited_height);
                    Outcome::Refused(att.seq, "not accepted".into())
                }
            }
            Err(RpcError::Node { message, .. }) => {
                tracing::info!("node refused seq {} citing {}: {message}", att.seq, att.cited_height);
                Outcome::Refused(att.seq, message)
            }
            Err(e) => {
                tracing::error!("yed_addattestation failed: {e}");
                Outcome::RpcError(e.to_string())
            }
        }
    }

    async fn wait_network(&mut self) -> String {
        loop {
            match self.node.call("yed_getinfo", vec![]).await {
                Ok(v) => {
                    self.tip = v
                        .get("height")
                        .and_then(Value::as_i64)
                        .and_then(|h| u32::try_from(h).ok());
                    return v
                        .get("network")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string();
                }
                Err(e) => {
                    tracing::error!("yed_getinfo failed ({e}); retrying in 15 s");
                    tokio::time::sleep(Duration::from_secs(15)).await;
                }
            }
        }
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let network = self.wait_network().await;
        let mut transport = transport::open(&self.cfg.transport, &network).await?;
        match self.refresh_attestors().await {
            Ok(n) => tracing::info!(
                "yellowback-attest subscribe: network {network}, {n} registered attestor(s), transport {}, per-seq {} frames then 1 per {} s",
                transport.name(),
                self.cfg.subscribe.seq_burst,
                self.cfg.subscribe.seq_refill_seconds
            ),
            Err(e) => tracing::error!("yed_listattestors failed: {e}; nothing is accepted until it answers"),
        }
        let http = crate::http::client(Duration::from_secs(15))?;
        let mut refresh = tokio::time::interval(Duration::from_secs(self.cfg.subscribe.listattestors_seconds));
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut endpoints = tokio::time::interval(Duration::from_secs(self.cfg.subscribe.endpoints_seconds));
        endpoints.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let urls = self.cfg.subscribe.endpoints.clone();
        let no_headers = std::collections::BTreeMap::new();
        loop {
            tokio::select! {
                msg = transport.recv() => match msg {
                    Ok(body) => { self.handle(&body).await; }
                    Err(e) => {
                        tracing::error!("transport {}: {e}; reopening in 5 s", transport.name());
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        match transport::open(&self.cfg.transport, &network).await {
                            Ok(t) => transport = t,
                            Err(e) => tracing::error!("reopen failed: {e}"),
                        }
                    }
                },
                _ = refresh.tick() => {
                    if let Err(e) = self.refresh_attestors().await {
                        tracing::error!("yed_listattestors failed: {e}; keeping the previous set");
                    }
                    if let Err(e) = self.refresh_tip().await {
                        tracing::debug!("yed_getinfo failed: {e}; keeping the previous tip");
                    }
                },
                _ = endpoints.tick(), if !urls.is_empty() => {
                    for u in &urls {
                        match crate::http::get_capped(&http, u, &no_headers, crate::http::VENUE_BODY_CAP).await {
                            Ok(b) => { self.handle(&b).await; }
                            Err(e) => tracing::debug!("endpoint {u}: {e}"),
                        }
                    }
                },
                _ = tokio::signal::ctrl_c() => { tracing::info!("stopping: {} accepted of {} seen, {} filtered before the node", self.accepted, self.seen, self.filtered); return Ok(()); }
            }
        }
    }

    /// Tests: pretend a bucket last refilled `by` ago.
    #[cfg(test)]
    fn backdate_bucket(&mut self, seq: u16, by: Duration) {
        if let Some(b) = self.buckets.get_mut(&seq) {
            b.last -= by;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::rpc::mock::MockNode;

    fn att(seq: u16, cited: u32) -> Attestation {
        Attestation {
            seq,
            price_micro_usd: 567_585,
            cited_height: cited,
            sig: [1; 64],
        }
    }

    #[tokio::test]
    async fn filters_then_pushes_and_counts() {
        let m = MockNode::start(None, |method, params| match method {
            "yed_listattestors" => {
                Ok(json!([{"seq": 1, "status": "ACTIVE"}, {"seq": 2, "status": "ACTIVE"}, {"seq": 70000}]))
            }
            "yed_addattestation" => {
                let a = Attestation::decode_hex(params[0].as_str().unwrap()).unwrap();
                if a.cited_height < 100 {
                    Err((-8, "attest-stale".into()))
                } else {
                    Ok(json!({"accepted": true, "seq": a.seq, "replaced": a.cited_height > 100}))
                }
            }
            _ => Err((-32601, "Method not found".into())),
        });
        let cfg = config::parse(&format!(
            "[node]\nrpc_url = \"{}\"\n[transport]\nkind = \"dir\"\npath = \"/tmp/x\"\n",
            m.url
        ))
        .unwrap();
        let mut s = Subscriber::new(cfg).unwrap();
        // nothing is accepted before the attestor set is known
        assert_eq!(s.handle(&att(1, 100).encode()).await, Outcome::UnknownSeq(1));
        assert_eq!(s.refresh_attestors().await.unwrap(), 2);
        assert_eq!(s.handle(b"short").await, Outcome::Malformed);
        assert_eq!(s.handle(&[0u8; 75]).await, Outcome::Malformed);
        assert_eq!(s.handle(&att(9, 100).encode()).await, Outcome::UnknownSeq(9));
        assert_eq!(s.handle(&att(1, 100).encode()).await, Outcome::Accepted(1, false));
        assert_eq!(
            s.handle(att(2, 104).to_hex().as_bytes()).await,
            Outcome::Accepted(2, true)
        ); // hex body from an endpoint
        assert_eq!(
            s.handle(&att(1, 50).encode()).await,
            Outcome::Refused(1, "attest-stale".into())
        );
        assert_eq!((s.accepted, s.seen), (2, 7));
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|(m, _)| m == "yed_addattestation").count(), 3);
    }

    #[tokio::test]
    async fn rpc_failure_keeps_the_previous_attestor_set() {
        let m = MockNode::start(None, |_, _| Ok(json!([{"seq": 5}])));
        // rpc_timeout 2: after the mock is dropped the pooled connection is dead and the call times out.
        let cfg = config::parse(&format!(
            "[node]\nrpc_url = \"{}\"\nrpc_timeout = 2\n[transport]\nkind = \"dir\"\npath = \"/tmp/x\"\n",
            m.url
        ))
        .unwrap();
        let mut s = Subscriber::new(cfg.clone()).unwrap();
        assert_eq!(s.refresh_attestors().await.unwrap(), 1);
        drop(m);
        assert!(s.refresh_attestors().await.is_err());
        assert!(s.known_seqs.contains(&5));
        assert!(matches!(s.handle(&att(5, 1).encode()).await, Outcome::RpcError(_)));
    }

    fn cfg_for(m: &MockNode, extra: &str) -> Config {
        config::parse(&format!(
            "[node]\nrpc_url = \"{}\"\n[transport]\nkind = \"dir\"\npath = \"/tmp/x\"\n[subscribe]\n{extra}",
            m.url
        ))
        .unwrap()
    }

    fn addattestation_calls(m: &MockNode) -> usize {
        m.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == "yed_addattestation")
            .count()
    }

    /// Audit D-5: a frame already handed to the node is not pushed again, whatever path it came by.
    #[tokio::test]
    async fn duplicate_frames_are_dropped_before_the_rpc() {
        let m = MockNode::start(None, |method, _| match method {
            "yed_listattestors" => Ok(json!([{"seq": 1}])),
            "yed_addattestation" => Err((-8, "attest-bad-sig".into())),
            _ => Err((-32601, "Method not found".into())),
        });
        let mut s = Subscriber::new(cfg_for(&m, "")).unwrap();
        s.refresh_attestors().await.unwrap();
        let f = att(1, 100);
        assert_eq!(
            s.handle(&f.encode()).await,
            Outcome::Refused(1, "attest-bad-sig".into())
        );
        assert_eq!(s.handle(&f.encode()).await, Outcome::Duplicate(1));
        assert_eq!(s.handle(f.to_hex().as_bytes()).await, Outcome::Duplicate(1));
        let mut other = f.clone();
        other.sig[0] ^= 1;
        assert!(matches!(s.handle(&other.encode()).await, Outcome::Refused(1, _)));
        assert_eq!(addattestation_calls(&m), 2);
        assert_eq!(s.filtered, 2);
        // the LRU is bounded: after DEDUP_CAPACITY newer frames the first one is forgotten
        for i in 0..DEDUP_CAPACITY as u32 {
            let mut a = att(1, 200 + i % 50);
            a.sig[1..5].copy_from_slice(&i.to_le_bytes());
            s.backdate_bucket(1, Duration::from_secs(3600));
            assert!(matches!(
                s.handle_at(&a.encode(), Instant::now()).await,
                Outcome::Refused(1, _)
            ));
        }
        s.backdate_bucket(1, Duration::from_secs(3600));
        assert!(matches!(s.handle(&f.encode()).await, Outcome::Refused(1, _)));
    }

    /// Audit D-5: per-seq token bucket; refill with time; one seq's flood does not touch another's.
    #[tokio::test]
    async fn per_seq_rate_limit() {
        let m = MockNode::start(None, |method, _| match method {
            "yed_listattestors" => Ok(json!([{"seq": 1}, {"seq": 2}])),
            "yed_addattestation" => Ok(json!({"accepted": true})),
            _ => Err((-32601, "Method not found".into())),
        });
        let mut s = Subscriber::new(cfg_for(&m, "seq_burst = 3\nseq_refill_seconds = 10\n")).unwrap();
        s.refresh_attestors().await.unwrap();
        let t0 = Instant::now();
        for i in 0..3u32 {
            assert_eq!(
                s.handle_at(&att(1, 100 + i).encode(), t0).await,
                Outcome::Accepted(1, false)
            );
        }
        assert_eq!(s.handle_at(&att(1, 110).encode(), t0).await, Outcome::RateLimited(1));
        assert_eq!(
            s.handle_at(&att(2, 110).encode(), t0).await,
            Outcome::Accepted(2, false)
        );
        // 10 s later one token is back; 100 s later the bucket is full again (and not fuller)
        assert_eq!(
            s.handle_at(&att(1, 111).encode(), t0 + Duration::from_secs(10)).await,
            Outcome::Accepted(1, false)
        );
        assert_eq!(
            s.handle_at(&att(1, 112).encode(), t0 + Duration::from_secs(10)).await,
            Outcome::RateLimited(1)
        );
        let later = t0 + Duration::from_secs(110);
        for i in 0..3u32 {
            assert_eq!(
                s.handle_at(&att(1, 120 + i).encode(), later).await,
                Outcome::Accepted(1, false)
            );
        }
        assert_eq!(s.handle_at(&att(1, 130).encode(), later).await, Outcome::RateLimited(1));
        assert_eq!(addattestation_calls(&m), 8);
        // a rate-limited frame was never handed over, so it is not a duplicate later
        assert_eq!(
            s.handle_at(&att(1, 130).encode(), later + Duration::from_secs(10))
                .await,
            Outcome::Accepted(1, false)
        );
    }

    /// Audit D-5: citedHeight far from the node's tip is dropped locally; no tip, no filter.
    #[tokio::test]
    async fn cited_height_window() {
        let m = MockNode::start(None, |method, _| match method {
            "yed_listattestors" => Ok(json!([{"seq": 1}])),
            "yed_getinfo" => Ok(json!({"network": "regtest", "height": 1000})),
            "yed_addattestation" => Ok(json!({"accepted": true})),
            _ => Err((-32601, "Method not found".into())),
        });
        let mut s = Subscriber::new(cfg_for(&m, "seq_burst = 100\n")).unwrap();
        s.refresh_attestors().await.unwrap();
        assert_eq!(s.handle(&att(1, 5).encode()).await, Outcome::Accepted(1, false)); // tip unknown yet
        assert_eq!(s.refresh_tip().await.unwrap(), Some(1000));
        assert_eq!(
            s.handle(&att(1, 1000 - CITED_BEHIND_MAX - 1).encode()).await,
            Outcome::OutOfWindow(1, 935)
        );
        assert_eq!(
            s.handle(&att(1, 1000 + CITED_AHEAD_MAX + 1).encode()).await,
            Outcome::OutOfWindow(1, 1009)
        );
        assert_eq!(
            s.handle(&att(1, 1000 - CITED_BEHIND_MAX).encode()).await,
            Outcome::Accepted(1, false)
        );
        assert_eq!(
            s.handle(&att(1, 1000 + CITED_AHEAD_MAX).encode()).await,
            Outcome::Accepted(1, false)
        );
        assert_eq!(s.handle(&att(1, 1000).encode()).await, Outcome::Accepted(1, false));
        assert_eq!(addattestation_calls(&m), 4);
    }

    /// Audit D-5: an RPC transport failure backs the loop off, doubling to BACKOFF_MAX, reset on success.
    #[tokio::test]
    async fn rpc_failure_backs_off_boundedly() {
        let m = MockNode::start(None, |method, _| match method {
            "yed_listattestors" => Ok(json!([{"seq": 1}])),
            "yed_addattestation" => Ok(json!({"accepted": true})),
            _ => Err((-32601, "Method not found".into())),
        });
        let mut s = Subscriber::new(cfg_for(&m, "seq_burst = 100\n")).unwrap();
        s.refresh_attestors().await.unwrap();
        let t0 = Instant::now();
        assert_eq!(s.handle_at(&att(1, 1).encode(), t0).await, Outcome::Accepted(1, false));
        let url = m.url.clone();
        drop(m);
        // the node is gone: one RpcError, then BackingOff for 1 s, 2 s, 4 s ... capped at 60 s
        let dead = config::parse(&format!(
            "[node]\nrpc_url = \"{url}\"\nrpc_timeout = 2\n[transport]\nkind = \"dir\"\npath = \"/tmp/x\"\n[subscribe]\nseq_burst = 100\n"
        ))
        .unwrap();
        s.node = Node::new(&dead.node).unwrap();
        let mut t = t0;
        let mut waits = vec![];
        for i in 0..8u32 {
            assert!(
                matches!(s.handle_at(&att(1, 10 + i).encode(), t).await, Outcome::RpcError(_)),
                "{i}"
            );
            let until = s.backoff_until.unwrap();
            waits.push((until - t).as_secs());
            assert_eq!(s.handle_at(&att(1, 10 + i).encode(), t).await, Outcome::BackingOff(1));
            t = until;
        }
        assert_eq!(waits, vec![1, 2, 4, 8, 16, 32, 60, 60]);
        // after the wait lapses the next frame is tried again (and fails again here)
        assert!(matches!(
            s.handle_at(&att(1, 99).encode(), t).await,
            Outcome::RpcError(_)
        ));
    }
}
