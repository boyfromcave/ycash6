//! `subscribe`: join the topic and feed the node's attestation pool. Each message is dropped
//! unless it is 74 bytes (or that as hex) and its `seq` is in the last `yed_listattestors`
//! (refreshed every `listattestors_seconds`); everything else goes to `yed_addattestation`,
//! which re-verifies the signature. Acceptances are counted. Optional `[subscribe] endpoints`
//! are HTTPS URLs polled as a second path (plan §5, proposal §13).

use std::collections::HashSet;
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::Config;
use crate::framing::{parse_message, Attestation};
use crate::rpc::{Node, RpcError};
use crate::transport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Not 74 bytes / not hex of 74 bytes.
    Malformed,
    /// `seq` not in the last `yed_listattestors`.
    UnknownSeq(u16),
    /// The node accepted it (`accepted: true`).
    Accepted(u16, bool),
    /// The node refused it (`attest-stale`, `attest-bad-sig`, ...).
    Refused(u16, String),
    /// RPC transport failure; the message is dropped (the attestor publishes again next tick).
    RpcError(String),
}

pub struct Subscriber {
    pub cfg: Config,
    pub node: Node,
    pub known_seqs: HashSet<u16>,
    pub accepted: u64,
    pub seen: u64,
}

impl Subscriber {
    pub fn new(cfg: Config) -> anyhow::Result<Self> {
        let node = Node::new(&cfg.node)?;
        Ok(Subscriber {
            cfg,
            node,
            known_seqs: HashSet::new(),
            accepted: 0,
            seen: 0,
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

    /// Filter one message and push it to the node.
    pub async fn handle(&mut self, body: &[u8]) -> Outcome {
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
        self.push(&att).await
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

    async fn wait_network(&self) -> String {
        loop {
            match self.node.call("yed_getinfo", vec![]).await {
                Ok(v) => {
                    return v
                        .get("network")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_string()
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
                "yellowback-attest subscribe: network {network}, {n} registered attestor(s), transport {}",
                transport.name()
            ),
            Err(e) => tracing::error!("yed_listattestors failed: {e}; nothing is accepted until it answers"),
        }
        crate::tls::install();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("yellowback-attest/3")
            .build()?;
        let mut refresh = tokio::time::interval(Duration::from_secs(self.cfg.subscribe.listattestors_seconds));
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut endpoints = tokio::time::interval(Duration::from_secs(self.cfg.subscribe.endpoints_seconds));
        endpoints.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let urls = self.cfg.subscribe.endpoints.clone();
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
                },
                _ = endpoints.tick(), if !urls.is_empty() => {
                    for u in &urls {
                        match http.get(u).send().await {
                            Ok(r) if r.status().is_success() => match r.bytes().await {
                                Ok(b) => { self.handle(&b).await; }
                                Err(e) => tracing::debug!("endpoint {u}: {e}"),
                            },
                            Ok(r) => tracing::debug!("endpoint {u}: HTTP {}", r.status().as_u16()),
                            Err(e) => tracing::debug!("endpoint {u}: {e}"),
                        }
                    }
                },
                _ = tokio::signal::ctrl_c() => { tracing::info!("stopping: {} accepted of {} seen", self.accepted, self.seen); return Ok(()); }
            }
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
}
