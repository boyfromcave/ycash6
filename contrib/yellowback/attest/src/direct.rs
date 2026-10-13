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
    announces: tokio::sync::mpsc::Sender<(Vec<u8>, u16)>,
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
                    let _ = self.announces.try_send((body.to_vec(), seq));
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
    /// the receivers of member frames and of announces, each with the seq of the member that delivered it.
    pub async fn open(
        secret_key_file: Option<&Path>,
        relays: &[String],
        fallback: &[String],
    ) -> anyhow::Result<(
        Self,
        tokio::sync::mpsc::Receiver<(Vec<u8>, u16)>,
        tokio::sync::mpsc::Receiver<(Vec<u8>, u16)>,
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
        // the outsider: refused by a's gate. It dials from a plain endpoint (no gate of its own: a DirectNode would
        // refuse to dial an unbound id itself, which would prove nothing about a's gate)
        let target = endpoint_addr(a.id(), &a_addrs, None);
        let plain_outsider = plain().await;
        let refused = {
            let conn = tokio::time::timeout(CONNECT_TIMEOUT, plain_outsider.connect(target.clone(), ALPN)).await;
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
        plain_outsider.close().await;
    }

    // ---- M5 adversarial tests (docs/plans/yellowback-attest-gossip-evaluation.md §7 M5)

    /// A plain iroh endpoint on loopback with no gate: what an outsider runs.
    async fn plain() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .unwrap()
    }

    /// This process's CPU time (user + system) in seconds, from `ps` (macOS and Linux).
    fn cpu_seconds() -> Option<f64> {
        let out = std::process::Command::new("ps")
            .args(["-o", "time=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // [[dd-]hh:]mm:ss[.ff]
        let (days, rest) = match text.split_once('-') {
            Some((d, r)) => (d.parse::<f64>().ok()?, r.to_string()),
            None => (0.0, text),
        };
        let mut secs = 0.0;
        for part in rest.split(':') {
            secs = secs * 60.0 + part.parse::<f64>().ok()?;
        }
        Some(days * 86_400.0 + secs)
    }

    /// Two bound members (a = seq 1 receiving, b = seq 2 sending), plus extra bound members.
    async fn pair(
        extra: &[(u16, &DirectNode)],
    ) -> (DirectNode, tokio::sync::mpsc::Receiver<(Vec<u8>, u16)>, DirectNode) {
        let (a, a_frames) = node().await;
        let (b, _) = node().await;
        let mut m = HashMap::new();
        m.insert(
            a.id(),
            Peer {
                seq: 1,
                addrs: local(&a),
                relay: None,
            },
        );
        m.insert(
            b.id(),
            Peer {
                seq: 2,
                addrs: local(&b),
                relay: None,
            },
        );
        for (seq, n) in extra {
            m.insert(
                n.id(),
                Peer {
                    seq: *seq,
                    addrs: local(n),
                    relay: None,
                },
            );
        }
        a.members.set(m.clone());
        b.members.set(m.clone());
        for (_, n) in extra {
            n.members.set(m.clone());
        }
        (a, a_frames, b)
    }

    /// Normal traffic at a member is the other members' connections: 14 with a full 15-seat set. The flood is
    /// `factor` × 14 handshakes from unbound endpoints, all at once, while member b keeps delivering.
    async fn outsider_flood(factor: usize) -> (usize, Duration, f64) {
        let (a, mut a_frames, b) = pair(&[]).await;
        let target = endpoint_addr(a.id(), &local(&a), None);
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        b.spawn_sender(rx);
        // warm b's connection, as a live member's is
        tx.send(Out::Frame(vec![0; 115])).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(20), a_frames.recv())
                .await
                .unwrap()
                .unwrap()
                .1,
            2
        );
        let handshakes = factor * 14;
        let endpoints = handshakes.div_ceil(10).min(70);
        let mut outsiders = Vec::new();
        for _ in 0..endpoints {
            outsiders.push(plain().await);
        }
        let cpu0 = cpu_seconds();
        let t0 = Instant::now();
        // outcome of each outsider connection: refused by the gate's close code, failed otherwise (no connection,
        // or closed for another reason under load), or still open after 30 s -- admitted, which must never happen
        let refused = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for i in 0..handshakes {
            let ep = outsiders[i % endpoints].clone();
            let (target, refused, failed, admitted) =
                (target.clone(), refused.clone(), failed.clone(), admitted.clone());
            tasks.push(tokio::spawn(async move {
                use std::sync::atomic::Ordering::SeqCst;
                match tokio::time::timeout(Duration::from_secs(30), ep.connect(target, ALPN)).await {
                    Ok(Ok(c)) => {
                        // try to push a frame through anyway: the gate closed the connection after the handshake
                        if let Ok(mut s) = c.open_uni().await {
                            let _ = s.write_all(&[KIND_FRAME; 116]).await;
                            let _ = s.finish();
                        }
                        match tokio::time::timeout(Duration::from_secs(30), c.closed()).await {
                            Ok(e) if format!("{e:?}").contains(&REFUSED.to_string()) => refused.fetch_add(1, SeqCst),
                            Ok(_) => failed.fetch_add(1, SeqCst),
                            Err(_) => admitted.fetch_add(1, SeqCst),
                        };
                    }
                    Ok(Err(_)) | Err(_) => {
                        failed.fetch_add(1, SeqCst);
                    }
                }
            }));
        }
        // the honest member delivers throughout: 5 frames, one every 200 ms ("every block"), each must arrive
        let mut worst = Duration::ZERO;
        for k in 1..=5u8 {
            let sent = Instant::now();
            tx.send(Out::Frame(vec![k; 115])).await.unwrap();
            loop {
                let (body, seq) = tokio::time::timeout(Duration::from_secs(20), a_frames.recv())
                    .await
                    .expect("the honest member's frame within 20 s under the flood")
                    .unwrap();
                assert_eq!(seq, 2, "only bound members reach the handler");
                if body[0] == k {
                    worst = worst.max(sent.elapsed());
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        for t in tasks {
            let _ = t.await;
        }
        let elapsed = t0.elapsed();
        let cpu = match (cpu0, cpu_seconds()) {
            (Some(x), Some(y)) => y - x,
            _ => 0.0,
        };
        // nothing an outsider sent reached the handler
        while let Ok((_, seq)) = a_frames.try_recv() {
            assert_eq!(seq, 2);
        }
        let n = refused.load(std::sync::atomic::Ordering::SeqCst);
        let f = failed.load(std::sync::atomic::Ordering::SeqCst);
        let adm = admitted.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(adm, 0, "no outsider connection may stay open");
        assert_eq!(n + f, handshakes);
        assert!(
            n * 10 >= handshakes * 9,
            "most handshakes end in the gate's refusal ({n} of {handshakes})"
        );
        eprintln!(
            "outsider flood {factor}x: {handshakes} handshakes, {n} refused by the gate, {f} failed otherwise, 0 \
             admitted, in {elapsed:?}; honest worst latency {worst:?}; process CPU {cpu:.2} s (attacker and member in \
             one process)"
        );
        for o in outsiders {
            o.close().await;
        }
        a.shutdown().await;
        b.shutdown().await;
        (handshakes, worst, cpu)
    }

    /// M5: an outsider flood at 10x and 100x a member's normal connection count. Every handshake is refused by the
    /// gate, nothing reaches the frame handler, the honest member's frames keep arriving within seconds (well inside
    /// one block), and the CPU spent is bounded by the handshakes (one TLS handshake each: no stream, no signature).
    /// The measurement itself, run in a child process of this test binary (env YB_OUTSIDER_FLOOD = factor) so the
    /// process CPU it reads is the flood's alone, not that of the tests running beside it. A no-op otherwise.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn outsider_flood_probe() {
        let Ok(factor) = std::env::var("YB_OUTSIDER_FLOOD") else {
            return;
        };
        let factor: usize = factor.parse().unwrap();
        let (handshakes, worst, cpu) = outsider_flood(factor).await;
        println!("FLOOD_RESULT {factor} {handshakes} {} {cpu:.3}", worst.as_millis());
    }

    #[test]
    fn an_outsider_flood_is_refused_at_the_handshake() {
        for factor in [10usize, 100] {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "direct::tests::outsider_flood_probe",
                    "--nocapture",
                    "--test-threads",
                    "1",
                ])
                .env("YB_OUTSIDER_FLOOD", factor.to_string())
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "{factor}x: the flood run failed:\n{text}{}",
                String::from_utf8_lossy(&out.stderr)
            );
            // libtest prints "test <name> ... " before the test's own output, on the same line
            let line = text
                .lines()
                .find_map(|l| l.find("FLOOD_RESULT").map(|k| &l[k..]))
                .unwrap_or_else(|| {
                    panic!(
                        "{factor}x: no result line in:\n{text}{}",
                        String::from_utf8_lossy(&out.stderr)
                    )
                });
            let f: Vec<&str> = line.split_whitespace().collect();
            let (handshakes, worst_ms, cpu): (usize, u64, f64) =
                (f[2].parse().unwrap(), f[3].parse().unwrap(), f[4].parse().unwrap());
            eprintln!("{line}");
            assert!(worst_ms < 10_000, "{factor}x: honest latency {worst_ms} ms");
            // a generous bound (debug build, both sides of every handshake in the one child process): 20 ms each
            assert!(
                cpu < 2.0 + 0.02 * handshakes as f64,
                "{factor}x: {cpu:.2} s of CPU for {handshakes} handshakes"
            );
        }
    }

    /// M5: one bound member floods at 10x and 100x its quota. Its frames beyond the quota are dropped at the
    /// handler (before any signature work); the other members' frames keep arriving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_member_flood_spends_only_its_own_quota() {
        for factor in [10usize, 100] {
            let (m, _) = node().await;
            let (a, mut a_frames, b) = pair(&[(3, &m)]).await;
            let (btx, brx) = tokio::sync::mpsc::channel(64);
            b.spawn_sender(brx);
            let (mtx, mrx) = tokio::sync::mpsc::channel(10_000);
            m.spawn_sender(mrx);
            let flood = factor * AUTHOR_BURST as usize;
            let t0 = Instant::now();
            let feeder = tokio::spawn(async move {
                for i in 0..flood {
                    let mut f = vec![0x33; 115];
                    f[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                    if mtx.send(Out::Frame(f)).await.is_err() {
                        break;
                    }
                }
                mtx
            });
            // the honest member sends 5 frames while the flood runs; all must arrive
            let mut honest = 0;
            let mut from_m = 0usize;
            for k in 1..=5u8 {
                btx.send(Out::Frame(vec![k; 115])).await.unwrap();
                let deadline = Instant::now() + Duration::from_secs(20);
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    let (body, seq) = tokio::time::timeout(left, a_frames.recv())
                        .await
                        .unwrap_or_else(|_| panic!("{factor}x: honest frame {k} did not arrive under the member flood"))
                        .unwrap();
                    match seq {
                        2 if body[0] == k => {
                            honest += 1;
                            break;
                        }
                        3 => from_m += 1,
                        _ => {}
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let _mtx = feeder.await.unwrap();
            // let the flood drain, then count what of m's got through
            tokio::time::sleep(Duration::from_secs(2)).await;
            while let Ok((_, seq)) = a_frames.try_recv() {
                if seq == 3 {
                    from_m += 1;
                }
            }
            let elapsed = t0.elapsed().as_secs_f64();
            let allowed = AUTHOR_BURST + AUTHOR_RATE * elapsed + 1.0;
            eprintln!(
                "member flood {factor}x: {flood} frames sent, {from_m} passed the quota (allowed {allowed:.0} in \
                 {elapsed:.1} s), honest {honest}/5"
            );
            assert_eq!(honest, 5);
            assert!(
                (from_m as f64) <= allowed,
                "{factor}x: {from_m} of m's frames passed, quota {allowed:.0}"
            );
            a.shutdown().await;
            b.shutdown().await;
            m.shutdown().await;
        }
    }
}
