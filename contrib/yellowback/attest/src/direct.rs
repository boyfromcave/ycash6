// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Direct, members-only delivery of cancel co-signatures (docs/plans/yellowback-attest-gossip-evaluation.md, option
//! E1; owner decision 1, 2026-10-13).
//!
//! The agent runs one dedicated iroh endpoint for it (its own key, `[cancel] direct_secret_key_file`), separate from
//! the gossip endpoint, so the members-only rules never sit next to iroh-gossip's connection management (the note's
//! iroh-gossip #155 concern). On it:
//!
//! - **One ALPN**, [`ALPN`]. A connection on it is refused right after the TLS handshake ([`Gate`], an iroh
//!   `EndpointHooks::after_handshake`) unless the authenticated remote endpoint id is bound to a current member by a
//!   valid [`crate::binding::Binding`]; the agent never dials an id that is not (`before_connect`).
//! - **Frames on uni streams**: `0x01 ‖ cosig::Frame` (115 bytes) or `0x02 ‖ binding::Announce` (the table exchange).
//!   A frame is accepted only if its `seq` is the seq the connection's endpoint id is bound to: the author is the
//!   authenticated peer, so the per-author quota here is a per-member quota, and a member can exhaust only its own.
//!   Frames are never forwarded.
//! - **Sending** ([`DirectNode::spawn_sender`]): every frame the agent publishes goes to every other bound member over
//!   a cached connection (dialled by id with the address hints of its binding), on a fresh uni stream.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use iroh::endpoint::{presets, Connection, VarInt};
use iroh::endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, EndpointHooks};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl, TransportAddr};

pub const ALPN: &[u8] = b"yellowback/cancel-cosig/1";
/// The QUIC application close code of a refused (non-member) connection.
pub const REFUSED: u32 = 0x5946;
pub const KIND_FRAME: u8 = 0x01;
pub const KIND_ANNOUNCE: u8 = 0x02;
/// A stream is at most this long (an announce is at most 1,024 bytes).
pub const STREAM_MAX: usize = 1_100;
/// The per-author quota: a burst, then this many frames a second. A member co-signs a handful of claims at most.
pub const AUTHOR_BURST: f64 = 64.0;
pub const AUTHOR_RATE: f64 = 4.0;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// One bound member: its seq and the address hints of its binding.
#[derive(Clone, Debug)]
pub struct Peer {
    pub seq: u16,
    pub addrs: Vec<SocketAddr>,
    pub relay: Option<RelayUrl>,
}

/// The bound members, shared between the agent (writer), the gate and the handler (readers).
#[derive(Clone, Debug, Default)]
pub struct Members(Arc<RwLock<HashMap<EndpointId, Peer>>>);

impl Members {
    pub fn seq_of(&self, id: &EndpointId) -> Option<u16> {
        self.0.read().ok()?.get(id).map(|p| p.seq)
    }

    pub fn set(&self, map: HashMap<EndpointId, Peer>) {
        if let Ok(mut m) = self.0.write() {
            *m = map;
        }
    }

    pub fn snapshot(&self) -> HashMap<EndpointId, Peer> {
        self.0.read().map(|m| m.clone()).unwrap_or_default()
    }
}

/// The members-only gate (an `EndpointHooks`): on [`ALPN`] only, an endpoint id that is not bound to a current member
/// is refused after the handshake and never dialled. Other ALPNs pass untouched.
#[derive(Debug)]
pub struct Gate {
    members: Members,
}

impl EndpointHooks for Gate {
    async fn before_connect<'a>(&'a self, remote: &'a EndpointAddr, alpn: &'a [u8]) -> BeforeConnectOutcome {
        if alpn == ALPN && self.members.seq_of(&remote.id).is_none() {
            return BeforeConnectOutcome::Reject;
        }
        BeforeConnectOutcome::Accept
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if conn.alpn() == ALPN && self.members.seq_of(&conn.remote_id()).is_none() {
            tracing::info!(
                "cancel direct: refused {} (not bound to a current member)",
                conn.remote_id().fmt_short()
            );
            return AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(REFUSED),
                reason: b"not a bound member".to_vec(),
            };
        }
        AfterHandshakeOutcome::Accept
    }
}

/// The receive side of [`ALPN`].
#[derive(Debug)]
struct Handler {
    members: Members,
    frames: tokio::sync::mpsc::Sender<(Vec<u8>, u16)>,
    announces: tokio::sync::mpsc::Sender<Vec<u8>>,
    quotas: Arc<Mutex<BTreeMap<u16, Quota>>>,
}

#[derive(Debug)]
struct Quota(f64, Instant);

impl Handler {
    fn take(&self, seq: u16, now: Instant) -> bool {
        let Ok(mut q) = self.quotas.lock() else {
            return false;
        };
        let b = q.entry(seq).or_insert(Quota(AUTHOR_BURST, now));
        let elapsed = now.saturating_duration_since(b.1).as_secs_f64();
        b.0 = (b.0 + elapsed * AUTHOR_RATE).min(AUTHOR_BURST);
        b.1 = now;
        if b.0 >= 1.0 {
            b.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        loop {
            // the gate admitted it; a member removed meanwhile is dropped at its next stream
            let Some(seq) = self.members.seq_of(&remote) else {
                conn.close(VarInt::from_u32(REFUSED), b"no longer a bound member");
                return Ok(());
            };
            let mut recv = match conn.accept_uni().await {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };
            let Ok(data) = recv.read_to_end(STREAM_MAX).await else {
                continue;
            };
            let Some((&kind, body)) = data.split_first() else {
                continue;
            };
            if !self.take(seq, Instant::now()) {
                tracing::debug!("cancel direct: seq {seq} over its quota; stream dropped");
                continue;
            }
            match kind {
                KIND_FRAME => {
                    if self.frames.try_send((body.to_vec(), seq)).is_err() {
                        tracing::debug!("cancel direct: frame queue full");
                    }
                }
                KIND_ANNOUNCE => {
                    let _ = self.announces.try_send(body.to_vec());
                }
                _ => {}
            }
        }
    }
}

/// What the sender sends to every bound member.
#[derive(Clone, Debug)]
pub enum Out {
    Frame(Vec<u8>),
    Announce(Vec<u8>),
}

pub struct DirectNode {
    pub endpoint: Endpoint,
    router: Router,
    pub members: Members,
}

/// The endpoint builder: n0's preset (its relays and pkarr/DNS address lookup), or -- with `relays = ["none"]` --
/// the minimal one: no relay and no lookup service at all, the address hints of the bindings only (a devnet, a test).
fn builder(relays: &[String]) -> iroh::endpoint::Builder {
    if relays.len() == 1 && relays[0].eq_ignore_ascii_case("none") {
        Endpoint::builder(presets::Minimal)
    } else {
        Endpoint::builder(presets::N0)
    }
}

/// `relays` empty: n0's public relays, plus `fallback` (the project's relays) when given; `["none"]`: no relay.
pub fn relay_mode(relays: &[String], fallback: &[String]) -> anyhow::Result<iroh::RelayMode> {
    crate::transport::iroh::relay_mode_with_fallback(relays, fallback)
}

impl DirectNode {
    /// Bind the endpoint (the key file is created 0600 on first use) and mount the handler. Returns the node and
    /// the receivers of member frames (with the author's seq) and of announces.
    pub async fn open(
        secret_key_file: Option<&Path>,
        relays: &[String],
        fallback: &[String],
    ) -> anyhow::Result<(
        Self,
        tokio::sync::mpsc::Receiver<(Vec<u8>, u16)>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    )> {
        let secret = crate::transport::iroh::load_or_create_secret(secret_key_file)?;
        let mode = relay_mode(relays, fallback)?;
        let members = Members::default();
        let endpoint = builder(relays)
            .secret_key(secret)
            .relay_mode(mode.clone())
            .hooks(Gate {
                members: members.clone(),
            })
            .bind()
            .await
            .context("iroh bind (cancel direct)")?;
        let (ftx, frx) = tokio::sync::mpsc::channel(1024);
        let (atx, arx) = tokio::sync::mpsc::channel(256);
        let handler = Handler {
            members: members.clone(),
            frames: ftx,
            announces: atx,
            quotas: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let router = Router::builder(endpoint.clone()).accept(ALPN, handler).spawn();
        tracing::info!(
            "cancel direct: endpoint id {} (bound by this member's signed binding)",
            endpoint.id()
        );
        Ok((
            DirectNode {
                endpoint,
                router,
                members,
            },
            frx,
            arx,
        ))
    }

    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// The address hints for this endpoint's binding announce.
    pub fn hints(&self) -> (Vec<String>, Option<String>) {
        let addr = self.endpoint.addr();
        let ips = addr.ip_addrs().map(|a| a.to_string()).collect();
        let relay = addr.relay_urls().next().map(|u| u.to_string());
        (ips, relay)
    }

    /// Send every item to every bound member but this one, over cached connections, each member concurrently.
    pub fn spawn_sender(&self, mut rx: tokio::sync::mpsc::Receiver<Out>) -> tokio::task::JoinHandle<()> {
        let endpoint = self.endpoint.clone();
        let members = self.members.clone();
        tokio::spawn(async move {
            let conns: Arc<tokio::sync::Mutex<HashMap<EndpointId, Connection>>> = Default::default();
            while let Some(item) = rx.recv().await {
                let (kind, body) = match &item {
                    Out::Frame(b) => (KIND_FRAME, b.clone()),
                    Out::Announce(b) => (KIND_ANNOUNCE, b.clone()),
                };
                let mut msg = Vec::with_capacity(body.len() + 1);
                msg.push(kind);
                msg.extend_from_slice(&body);
                let me = endpoint.id();
                let targets: Vec<(EndpointId, Peer)> =
                    members.snapshot().into_iter().filter(|(id, _)| *id != me).collect();
                let sends = targets.into_iter().map(|(id, peer)| {
                    let (endpoint, conns, msg) = (endpoint.clone(), conns.clone(), msg.clone());
                    async move {
                        if let Err(e) = send_one(&endpoint, &conns, id, &peer, &msg).await {
                            tracing::debug!("cancel direct: to seq {} ({}): {e:#}", peer.seq, id.fmt_short());
                            conns.lock().await.remove(&id);
                        }
                    }
                });
                n0_future::join_all(sends).await;
            }
        })
    }

    #[allow(dead_code)]
    pub async fn shutdown(self) {
        let _ = self.router.shutdown().await;
    }
}

async fn send_one(
    endpoint: &Endpoint,
    conns: &tokio::sync::Mutex<HashMap<EndpointId, Connection>>,
    id: EndpointId,
    peer: &Peer,
    msg: &[u8],
) -> anyhow::Result<()> {
    let cached = conns.lock().await.get(&id).cloned();
    let conn = match cached {
        Some(c) if c.close_reason().is_none() => c,
        _ => {
            let mut addr = EndpointAddr::new(id);
            for a in &peer.addrs {
                addr = addr.with_ip_addr(*a);
            }
            if let Some(r) = &peer.relay {
                addr = addr.with_relay_url(r.clone());
            }
            let c = tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, ALPN))
                .await
                .context("connect timed out")?
                .context("connect")?;
            conns.lock().await.insert(id, c.clone());
            c
        }
    };
    let mut s = conn.open_uni().await.context("open_uni")?;
    s.write_all(msg).await.context("write")?;
    s.finish().context("finish")?;
    Ok(())
}

/// Parse "ip:port" hints (bad ones are skipped) and a relay URL.
pub fn peer_from_hints(seq: u16, addrs: &[String], relay: Option<&str>) -> Peer {
    Peer {
        seq,
        addrs: addrs.iter().filter_map(|a| a.parse().ok()).collect(),
        relay: relay.and_then(|r| r.parse().ok()),
    }
}

/// `direct-probe`: dial `target` on [`ALPN`] with this (unbound) endpoint and report whether the members-only gate
/// refused it. Ok(true): refused; Ok(false): admitted (the target treats this id as a bound member).
pub async fn probe(target: EndpointAddr, relays: &[String]) -> anyhow::Result<bool> {
    let endpoint = builder(relays)
        .relay_mode(relay_mode(relays, &[])?)
        .bind()
        .await
        .context("iroh bind (probe)")?;
    let conn = match tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(target, ALPN)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            let text = format!("{e:#}");
            endpoint.close().await;
            // a refusal can surface on the dialler as a failed connect carrying the close code
            return Ok(text.contains(&REFUSED.to_string()) || text.contains("not a bound member"));
        }
        Err(_) => anyhow::bail!("no answer from the target within {CONNECT_TIMEOUT:?}"),
    };
    let refused = match tokio::time::timeout(Duration::from_secs(5), conn.closed()).await {
        Ok(reason) => {
            let text = format!("{reason:?}");
            text.contains(&REFUSED.to_string()) || text.contains("not a bound member")
        }
        Err(_) => false, // still open after 5 s: admitted
    };
    endpoint.close().await;
    Ok(refused)
}

pub fn endpoint_addr(id: EndpointId, addrs: &[SocketAddr], relay: Option<RelayUrl>) -> EndpointAddr {
    let mut a = EndpointAddr::from_parts(id, addrs.iter().map(|s| TransportAddr::Ip(*s)));
    if let Some(r) = relay {
        a = a.with_relay_url(r);
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn node() -> (DirectNode, tokio::sync::mpsc::Receiver<(Vec<u8>, u16)>) {
        let (n, frames, _ann) = DirectNode::open(None, &["none".to_string()], &[]).await.unwrap();
        (n, frames)
    }

    fn local(n: &DirectNode) -> Vec<SocketAddr> {
        n.endpoint
            .addr()
            .ip_addrs()
            .copied()
            .filter(|a| a.ip().is_loopback() || a.is_ipv4())
            .collect()
    }

    /// A member's frame arrives with its seq; a non-member is refused at the handshake; a frame claiming another
    /// seq is attributed to its sender (the agent's verifier then drops it).
    #[tokio::test]
    async fn members_deliver_outsiders_are_refused() {
        let (a, mut a_frames) = node().await;
        let (b, _b_frames) = node().await;
        let (outsider, _) = node().await;
        let a_addrs = local(&a);
        let b_addrs = local(&b);
        // a and b know each other as seqs 1 and 2
        let mut am = HashMap::new();
        am.insert(
            b.id(),
            Peer {
                seq: 2,
                addrs: b_addrs.clone(),
                relay: None,
            },
        );
        am.insert(
            a.id(),
            Peer {
                seq: 1,
                addrs: a_addrs.clone(),
                relay: None,
            },
        );
        a.members.set(am.clone());
        b.members.set(am);
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        b.spawn_sender(rx);
        tx.send(Out::Frame(vec![0x42; 115])).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), a_frames.recv())
            .await
            .expect("a member's frame within 20 s")
            .unwrap();
        assert_eq!(got, (vec![0x42; 115], 2));
        // the outsider: refused by a's gate
        let target = endpoint_addr(a.id(), &a_addrs, None);
        let refused = {
            let conn = tokio::time::timeout(CONNECT_TIMEOUT, outsider.endpoint.connect(target.clone(), ALPN)).await;
            match conn {
                Ok(Ok(c)) => {
                    let r = tokio::time::timeout(Duration::from_secs(5), c.closed()).await;
                    matches!(r, Ok(ref e) if format!("{e:?}").contains(&REFUSED.to_string()))
                }
                Ok(Err(_)) => true,
                Err(_) => false,
            }
        };
        assert!(refused, "a non-member is refused on the members-only ALPN");
        assert!(probe(target, &["none".to_string()]).await.unwrap());
        // nothing from the outsider reached a's frame queue
        assert!(a_frames.try_recv().is_err());
        // the gate also refuses to dial an unbound id
        let unbound = endpoint_addr(outsider.id(), &local(&outsider), None);
        assert!(a.endpoint.connect(unbound, ALPN).await.is_err());
        a.shutdown().await;
        b.shutdown().await;
        outsider.shutdown().await;
    }
}
