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
use std::net::{IpAddr, SocketAddr};
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
/// The first stream of an unbound connection: its own binding announce (review N-A, self-introduction).
pub const KIND_INTRO: u8 = 0x03;
/// An unbound connection must introduce itself within this.
pub const INTRO_DEADLINE: Duration = Duration::from_secs(3);
/// Self-introductions per source -- an IPv4 address, an IPv6 /64, or for a relay arrival its endpoint id (the relay
/// URL is shared by everyone behind it) -- a burst, then one per this many seconds ...
pub const INTRO_SOURCE_BURST: f64 = 4.0;
pub const INTRO_SOURCE_SECONDS: f64 = 10.0;
/// ... relay arrivals together under a ceiling (endpoint ids cost nothing to mint) ...
pub const INTRO_RELAY_BURST: f64 = 200.0;
pub const INTRO_RELAY_PER_SECOND: f64 = 50.0;
/// ... every self-introduction under a global one ...
pub const INTRO_GLOBAL_BURST: f64 = 400.0;
pub const INTRO_GLOBAL_PER_SECOND: f64 = 100.0;
/// ... and at most this many unverified connections held at once, counted until each verifies or closes; a new one
/// past it evicts (closes) the oldest, so holding connections open cannot shut newcomers out (review 5, note 2).
pub const INTRO_PENDING_MAX: usize = 64;
/// A verified self-introduction stands in for the binding this long, until the agent has taken it into its table.
pub const INTRO_VERIFIED_FOR: Duration = Duration::from_secs(120);
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

/// What a self-introduction is verified against: the agent's view, published after every poll.
#[derive(Clone, Debug, Default)]
pub struct IntroCtx {
    pub network: String,
    pub set_hex: String,
    pub tip: u32,
    pub ttl: u32,
    pub members: BTreeMap<u16, [u8; 33]>,
    /// The `issued` height of the binding held per seat: an introduction with an older binding is refused, so an
    /// endpoint key retired by a rotation cannot introduce itself again (review 5, note 3).
    pub held: BTreeMap<u16, u32>,
}

/// Where a self-introduction came from, as the limiter keys it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// An IPv4 address, or an IPv6 /64 (`ip6:<first four groups>::/64`).
    Ip(String),
    /// By a relay: keyed by the arriving endpoint id, under the relay ceiling.
    Relay(EndpointId),
}

impl Source {
    pub fn of(addr: Option<&TransportAddr>, id: EndpointId) -> Source {
        match addr {
            Some(TransportAddr::Ip(a)) => Source::Ip(ip_key(a.ip())),
            Some(TransportAddr::Relay(_)) => Source::Relay(id),
            _ => Source::Ip("unknown".to_string()),
        }
    }

    fn key(&self) -> String {
        match self {
            Source::Ip(k) => k.clone(),
            Source::Relay(id) => format!("relay:{id}"),
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Ip(k) => write!(f, "{k}"),
            Source::Relay(id) => write!(f, "a relay (endpoint {})", id.fmt_short()),
        }
    }
}

/// An IPv4 address as is (an IPv4-mapped IPv6 one too); an IPv6 address by its /64.
pub fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let g = v6.segments();
                format!("ip6:{:x}:{:x}:{:x}:{:x}::/64", g[0], g[1], g[2], g[3])
            }
        },
    }
}

/// Refill a token bucket of `burst` at `per_second` to `now`.
fn refill(q: &mut Quota, burst: f64, per_second: f64, now: Instant) {
    let elapsed = now.saturating_duration_since(q.1).as_secs_f64();
    q.0 = (q.0 + elapsed * per_second).min(burst);
    q.1 = now;
}

#[derive(Debug)]
struct Pending {
    since: Instant,
    generation: u64,
    evict: Arc<tokio::sync::Notify>,
}

#[derive(Debug)]
struct Limits {
    sources: HashMap<String, Quota>,
    relay: Quota,
    global: Quota,
}

/// Self-introduction state shared by the gate and the handler (review N-A): the view, the connections admitted
/// unverified, and a token bucket per source address.
#[derive(Debug, Default)]
pub struct Intro {
    ctx: RwLock<Option<IntroCtx>>,
    pending: Mutex<(u64, HashMap<EndpointId, Pending>)>,
    verified: Mutex<HashMap<EndpointId, (u16, Instant)>>,
    limits: Mutex<Option<Limits>>,
}

/// An unverified connection's place in the pending table, released when the handler is done with it (verified or
/// refused) -- and only its own entry, should the same id have been admitted again since.
pub struct PendingGuard<'a> {
    intro: &'a Intro,
    id: EndpointId,
    generation: u64,
    pub evict: Arc<tokio::sync::Notify>,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut p) = self.intro.pending.lock() {
            if p.1.get(&self.id).is_some_and(|e| e.generation == self.generation) {
                p.1.remove(&self.id);
            }
        }
    }
}

impl Intro {
    pub fn set_ctx(&self, ctx: IntroCtx) {
        if let Ok(mut c) = self.ctx.write() {
            *c = Some(ctx);
        }
    }

    /// Admit `id` from `source` unverified: a view exists, and the source's bucket, the relay ceiling (a relay
    /// arrival) and the global ceiling each have a token -- all checked before any is spent. A full pending table
    /// evicts its oldest entry.
    pub fn admit(&self, id: EndpointId, source: &Source, now: Instant) -> bool {
        if self.ctx.read().map(|c| c.is_none()).unwrap_or(true) {
            return false;
        }
        let Ok(mut limits) = self.limits.lock() else {
            return false;
        };
        let l = limits.get_or_insert_with(|| Limits {
            sources: HashMap::new(),
            relay: Quota(INTRO_RELAY_BURST, now),
            global: Quota(INTRO_GLOBAL_BURST, now),
        });
        if l.sources.len() > 4_096 {
            l.sources.retain(|_, q| {
                now.saturating_duration_since(q.1).as_secs_f64() < INTRO_SOURCE_SECONDS * INTRO_SOURCE_BURST
            });
        }
        let relay = matches!(source, Source::Relay(_));
        refill(&mut l.global, INTRO_GLOBAL_BURST, INTRO_GLOBAL_PER_SECOND, now);
        refill(&mut l.relay, INTRO_RELAY_BURST, INTRO_RELAY_PER_SECOND, now);
        let q = l.sources.entry(source.key()).or_insert(Quota(INTRO_SOURCE_BURST, now));
        refill(q, INTRO_SOURCE_BURST, 1.0 / INTRO_SOURCE_SECONDS, now);
        if q.0 < 1.0 || l.global.0 < 1.0 || (relay && l.relay.0 < 1.0) {
            return false;
        }
        q.0 -= 1.0;
        l.global.0 -= 1.0;
        if relay {
            l.relay.0 -= 1.0;
        }
        drop(limits);
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };
        let (generation, table) = &mut *pending;
        // an entry whose handler never ran (the connection died before it) is stale after twice the deadline
        table.retain(|_, e| now.saturating_duration_since(e.since) < INTRO_DEADLINE * 2);
        if table.len() >= INTRO_PENDING_MAX {
            if let Some(oldest) = table.iter().min_by_key(|(_, e)| e.since).map(|(k, _)| *k) {
                if let Some(e) = table.remove(&oldest) {
                    e.evict.notify_one();
                }
            }
        }
        *generation += 1;
        table.insert(
            id,
            Pending {
                since: now,
                generation: *generation,
                evict: Arc::new(tokio::sync::Notify::new()),
            },
        );
        true
    }

    /// Unverified connections held now.
    #[cfg(test)]
    pub fn pending_len(&self) -> usize {
        self.pending.lock().map(|p| p.1.len()).unwrap_or(0)
    }

    /// The seat of a connection admitted by a verified self-introduction within INTRO_VERIFIED_FOR.
    pub fn verified_seq(&self, id: &EndpointId, now: Instant) -> Option<u16> {
        let mut v = self.verified.lock().ok()?;
        v.retain(|_, (_, t)| now.saturating_duration_since(*t) < INTRO_VERIFIED_FOR);
        v.get(id).map(|(seq, _)| *seq)
    }

    /// The pending entry of `id`, held (counted) until the guard drops.
    fn hold_pending(&self, id: &EndpointId) -> Option<PendingGuard<'_>> {
        let p = self.pending.lock().ok()?;
        let e = p.1.get(id)?;
        Some(PendingGuard {
            intro: self,
            id: *id,
            generation: e.generation,
            evict: e.evict.clone(),
        })
    }

    /// Verify a self-introduction from `remote`: a valid binding of a current member's seat to exactly this
    /// endpoint id, with its proof of possession (one recovery, once per connection), not older than the binding
    /// held for that seat. The seat on success.
    pub fn verify(&self, remote: &EndpointId, announce: &crate::binding::Announce) -> Option<u16> {
        let ctx = self.ctx.read().ok()?.clone()?;
        let st = announce
            .binding
            .precheck(&ctx.network, &ctx.set_hex, ctx.tip, ctx.ttl, &ctx.members)
            .ok()?;
        if st.endpoint != *remote.as_bytes() || ctx.held.get(&st.seq).is_some_and(|h| st.issued < *h) {
            return None;
        }
        let st = announce
            .binding
            .verify(&ctx.network, &ctx.set_hex, ctx.tip, ctx.ttl, &ctx.members)
            .ok()?;
        announce.possession_ok(&st).then_some(st.seq)
    }
}

/// The source of a connection, for the self-introduction limiter.
fn source_of(conn: &Connection) -> Source {
    let paths = conn.paths();
    let first = paths.iter().next().map(|p| p.remote_addr().clone());
    Source::of(first.as_ref(), conn.remote_id())
}

/// The members-only gate (an `EndpointHooks`): on [`ALPN`] only, an endpoint id that is not bound to a current member
/// is refused after the handshake, unless it may introduce itself (review N-A: a view exists, the source address has
/// a token, fewer than INTRO_PENDING_MAX wait) -- then the handler requires a valid self-introduction as its first
/// stream within INTRO_DEADLINE, or closes it with the same refusal. The agent never dials an unbound id. Other ALPNs
/// pass untouched.
#[derive(Debug)]
pub struct Gate {
    members: Members,
    intro: Arc<Intro>,
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
            let source = source_of(conn);
            if self.intro.admit(conn.remote_id(), &source, Instant::now()) {
                tracing::debug!(
                    "cancel direct: {} from {source} may introduce itself",
                    conn.remote_id().fmt_short()
                );
                return AfterHandshakeOutcome::Accept;
            }
            tracing::info!(
                "cancel direct: refused {} from {source} (not bound to a current member)",
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
    intro: Arc<Intro>,
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
        let guard = match self.members.seq_of(&remote) {
            Some(_) => None,
            None => self.intro.hold_pending(&remote),
        };
        if let Some(guard) = guard {
            // self-introduction (review N-A): the first stream, within the deadline, is this endpoint's own binding;
            // the connection counts as pending until this is decided (the guard), or until a newer one evicts it
            let first = tokio::select! {
                r = tokio::time::timeout(INTRO_DEADLINE, async {
                    let mut r = conn.accept_uni().await.ok()?;
                    r.read_to_end(STREAM_MAX).await.ok()
                }) => r.ok().flatten(),
                _ = guard.evict.notified() => None,
            };
            let admitted = first.as_deref().and_then(|d| {
                let (&kind, body) = d.split_first()?;
                if kind != KIND_INTRO {
                    return None;
                }
                let a = crate::binding::Announce::decode(body)?;
                let seq = self.intro.verify(&remote, &a)?;
                Some((seq, body.to_vec()))
            });
            match admitted {
                Some((seq, body)) => {
                    tracing::info!("cancel direct: {} introduced itself as seq {seq}", remote.fmt_short());
                    if let Ok(mut v) = self.intro.verified.lock() {
                        v.insert(remote, (seq, Instant::now()));
                    }
                    // the agent takes the binding into its table (as from this member's own connection, verifying it
                    // again there); until then the verified introduction stands in for it on this connection
                    let _ = self.announces.try_send((body, seq));
                }
                None => {
                    tracing::info!(
                        "cancel direct: {} gave no valid self-introduction; refused",
                        remote.fmt_short()
                    );
                    conn.close(VarInt::from_u32(REFUSED), b"not a bound member");
                    return Ok(());
                }
            }
            drop(guard);
        } else if self.members.seq_of(&remote).is_none() {
            // admitted by the gate, but evicted (or stale) before its handler ran
            conn.close(VarInt::from_u32(REFUSED), b"not a bound member");
            return Ok(());
        }
        loop {
            // the gate admitted it; a member removed meanwhile is dropped at its next stream
            let Some(seq) = self
                .members
                .seq_of(&remote)
                .or_else(|| self.intro.verified_seq(&remote, Instant::now()))
            else {
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
                KIND_ANNOUNCE | KIND_INTRO => {
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
    /// This member's own announce: sent as the first stream of every new connection (self-introduction).
    Intro(Vec<u8>),
}

pub struct DirectNode {
    pub endpoint: Endpoint,
    router: Router,
    pub members: Members,
    pub intro: Arc<Intro>,
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
        let intro = Arc::new(Intro::default());
        let endpoint = builder(relays)
            .secret_key(secret)
            .relay_mode(mode.clone())
            .hooks(Gate {
                members: members.clone(),
                intro: intro.clone(),
            })
            .bind()
            .await
            .context("iroh bind (cancel direct)")?;
        let (ftx, frx) = tokio::sync::mpsc::channel(1024);
        let (atx, arx) = tokio::sync::mpsc::channel(256);
        let handler = Handler {
            members: members.clone(),
            intro: intro.clone(),
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
                intro,
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
            let mut intro: Option<Vec<u8>> = None;
            while let Some(item) = rx.recv().await {
                let (kind, body) = match &item {
                    Out::Frame(b) => (KIND_FRAME, b.clone()),
                    Out::Announce(b) => (KIND_ANNOUNCE, b.clone()),
                    Out::Intro(b) => {
                        let mut m = vec![KIND_INTRO];
                        m.extend_from_slice(b);
                        intro = Some(m);
                        continue;
                    }
                };
                let mut msg = Vec::with_capacity(body.len() + 1);
                msg.push(kind);
                msg.extend_from_slice(&body);
                let me = endpoint.id();
                let targets: Vec<(EndpointId, Peer)> =
                    members.snapshot().into_iter().filter(|(id, _)| *id != me).collect();
                let sends = targets.into_iter().map(|(id, peer)| {
                    let (endpoint, conns, msg, intro) = (endpoint.clone(), conns.clone(), msg.clone(), intro.clone());
                    async move {
                        if let Err(e) = send_one(&endpoint, &conns, id, &peer, &msg, intro.as_deref()).await {
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
    intro: Option<&[u8]>,
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
            // a new connection opens with this member's own announce, which admits it at a member that does not
            // know its binding yet (self-introduction) and is an ordinary announce at one that does
            if let Some(i) = intro {
                let mut s = c.open_uni().await.context("open_uni (intro)")?;
                s.write_all(i).await.context("write (intro)")?;
                s.finish().context("finish (intro)")?;
            }
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

    /// This process's CPU time (user + system) in seconds: from /proc/self/stat in clock ticks on Linux, where
    /// `ps` reports whole seconds only; from `ps` (hundredths) on macOS.
    fn cpu_seconds() -> Option<f64> {
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
            // "pid (comm) state ppid ..."; utime and stime are fields 14 and 15, i.e. 11 and 12 after the comm
            let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
            let ticks = fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?;
            let out = std::process::Command::new("getconf").arg("CLK_TCK").output().ok()?;
            let hz = String::from_utf8_lossy(&out.stdout).trim().parse::<f64>().ok()?;
            return Some(ticks / hz);
        }
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
        // CPU seconds per handshake of the 10x run: the 100x run is held to it (the cost must stay linear)
        let mut per_handshake_10x = None;
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
            // The CPU bound is per handshake, absolute and relative, so that it holds on a slow runner and still
            // catches a regression. (A gate that let an outsider in -- a stream accepted, a frame read or verified --
            // fails the strict refusal assertions in outsider_flood whatever it costs.) Absolute: a debug build doing
            // both sides of every handshake in the one child process costs ~5 ms each on the dev Mac and 29-36 ms on
            // a GitHub ubuntu-22.04 runner (2026-10-13); 100 ms each (+ 5 s of fixed setup) is about 3x the slow
            // runner, a ceiling only an expensive regression reaches. Relative: the 100x run may cost at most 3x the
            // 10x run's CPU per handshake (+ 10 ms) on the same machine, so a cost that grows with the flood (a
            // per-connection scan, a table that is never pruned) fails anywhere, however fast or slow the runner.
            let per = cpu / handshakes as f64;
            assert!(
                cpu < 5.0 + 0.1 * handshakes as f64,
                "{factor}x: {cpu:.2} s of CPU for {handshakes} handshakes ({:.1} ms each, bound 100 ms)",
                per * 1e3
            );
            if let Some(base) = per_handshake_10x {
                assert!(
                    per < 3.0 * base + 0.010,
                    "{factor}x: {:.1} ms of CPU per handshake against {:.1} ms at 10x: the cost grows with the flood",
                    per * 1e3,
                    base * 1e3
                );
            } else {
                per_handshake_10x = Some(per);
            }
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

    // ---- self-introduction (review N-A)

    use crate::binding::testkit as bk;
    use crate::cosig::testkit as ck;

    fn intro_ctx() -> IntroCtx {
        IntroCtx {
            network: "regtest".into(),
            set_hex: bk::set_hex(),
            tip: 100,
            ttl: 200,
            members: [1u16, 2, 3]
                .iter()
                .map(|s| (*s, ck::pubkey(&ck::key(10 + *s as u8))))
                .collect(),
            held: BTreeMap::new(),
        }
    }

    /// Seq 2's announce for the endpoint `key` (its own key proves possession), member-signed by `member_key`.
    fn intro_for(key: &iroh::SecretKey, endpoint: [u8; 32], member_key: u8) -> Vec<u8> {
        bk::announce_with(2, member_key, endpoint, key, 100, 250, vec!["127.0.0.1:1".into()]).encode()
    }

    /// Dial `a` from a plain endpoint, send `first` as the first stream and then a frame; true when `a` closed the
    /// connection with the refusal within 6 s.
    async fn intro_and_frame(a: &DirectNode, from: &Endpoint, first: Option<Vec<u8>>) -> bool {
        let c = tokio::time::timeout(
            CONNECT_TIMEOUT,
            from.connect(endpoint_addr(a.id(), &local(a), None), ALPN),
        )
        .await
        .unwrap()
        .unwrap();
        for msg in first.into_iter().chain([[vec![KIND_FRAME], vec![0x42; 115]].concat()]) {
            if let Ok(mut s) = c.open_uni().await {
                let _ = s.write_all(&msg).await;
                let _ = s.finish();
            }
        }
        match tokio::time::timeout(Duration::from_secs(6), c.closed()).await {
            Ok(e) => format!("{e:?}").contains(&REFUSED.to_string()) || format!("{e:?}").contains("not a bound member"),
            Err(_) => false,
        }
    }

    /// A member whose binding the receiver has not seen yet is admitted on its first connection by a valid
    /// self-introduction: the receiver learns the binding and takes its frames, attributed to its seat.
    #[tokio::test]
    async fn a_valid_self_introduction_is_admitted() {
        let (a, mut a_frames, mut a_ann) = DirectNode::open(None, &["none".to_string()], &[]).await.unwrap();
        let (b, _) = node().await;
        a.intro.set_ctx(intro_ctx()); // a knows nobody's endpoint, but the members' keys
        let mut bm = HashMap::new();
        bm.insert(
            a.id(),
            Peer {
                seq: 1,
                addrs: local(&a),
                relay: None,
            },
        );
        b.members.set(bm);
        let blob = intro_for(b.endpoint.secret_key(), *b.id().as_bytes(), 12);
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        b.spawn_sender(rx);
        tx.send(Out::Intro(blob.clone())).await.unwrap();
        tx.send(Out::Frame(vec![0x42; 115])).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), a_frames.recv())
            .await
            .expect("the introduced member's frame within 20 s")
            .unwrap();
        assert_eq!(got, (vec![0x42; 115], 2));
        assert_eq!(
            a_ann.try_recv().unwrap(),
            (blob, 2),
            "the binding reaches the agent's table"
        );
        assert_eq!(a.intro.verified_seq(&b.id(), Instant::now()), Some(2));
        a.shutdown().await;
        b.shutdown().await;
    }

    /// Refused: a forged member signature, a valid binding of another endpoint, a frame instead of an introduction,
    /// and no stream at all (the deadline).
    #[tokio::test]
    async fn invalid_or_missing_self_introductions_are_refused() {
        let (a, mut a_frames, mut a_ann) = DirectNode::open(None, &["none".to_string()], &[]).await.unwrap();
        a.intro.set_ctx(intro_ctx());
        // forged: seq 2's statement signed by a key that is not seq 2's
        let e = plain().await;
        assert!(
            intro_and_frame(
                &a,
                &e,
                Some([vec![KIND_INTRO], intro_for(e.secret_key(), *e.id().as_bytes(), 13)].concat())
            )
            .await
        );
        e.close().await;
        // a genuine binding of another endpoint (replayed from the topic): not this connection's id
        let e = plain().await;
        let other = bk::endpoint_key(9);
        assert!(
            intro_and_frame(
                &a,
                &e,
                Some([vec![KIND_INTRO], intro_for(&other, bk::endpoint_id(9), 12)].concat())
            )
            .await
        );
        e.close().await;
        // a valid introduction sent as an ordinary announce, or a frame first: not an introduction
        let e = plain().await;
        assert!(
            intro_and_frame(
                &a,
                &e,
                Some([vec![KIND_ANNOUNCE], intro_for(e.secret_key(), *e.id().as_bytes(), 12)].concat())
            )
            .await
        );
        e.close().await;
        let e = plain().await;
        assert!(intro_and_frame(&a, &e, None).await);
        e.close().await;
        // nothing at all: closed at the deadline
        assert!(probe(endpoint_addr(a.id(), &local(&a), None), &["none".to_string()])
            .await
            .unwrap());
        assert!(a_frames.try_recv().is_err(), "no refused connection delivered a frame");
        assert!(a_ann.try_recv().is_err(), "no refused connection delivered a binding");
        a.shutdown().await;
    }

    fn ip(a: &str) -> Source {
        Source::Ip(ip_key(a.parse().unwrap()))
    }

    fn id(i: u16) -> EndpointId {
        let mut b = [0u8; 32];
        b[..2].copy_from_slice(&i.to_le_bytes());
        b[2] = 1;
        iroh::SecretKey::from_bytes(&b).public()
    }

    /// The limiter: no view, no admission; a burst per source address, then one per INTRO_SOURCE_SECONDS; other
    /// sources unaffected.
    #[test]
    fn self_introductions_are_rate_limited_per_source() {
        let intro = Intro::default();
        let t0 = Instant::now();
        assert!(!intro.admit(id(1), &ip("10.0.0.1"), t0), "no view yet");
        intro.set_ctx(intro_ctx());
        for i in 0..INTRO_SOURCE_BURST as u16 {
            assert!(intro.admit(id(10 + i), &ip("10.0.0.1"), t0));
        }
        assert!(!intro.admit(id(20), &ip("10.0.0.1"), t0), "over the source's burst");
        assert!(intro.admit(id(21), &ip("10.0.0.2"), t0), "another source is unaffected");
        let later = t0 + Duration::from_secs_f64(INTRO_SOURCE_SECONDS);
        assert!(intro.admit(id(22), &ip("10.0.0.1"), later), "one more after the refill");
    }

    /// Review 5, note 2: IPv4 sources by address, IPv6 ones by their /64 (one host's /64 is one source), IPv4-mapped
    /// IPv6 as its IPv4 address.
    #[test]
    fn ip_sources_are_keyed_per_ipv4_and_ipv6_slash_64() {
        let k = |a: &str| ip_key(a.parse().unwrap());
        assert_ne!(k("10.0.0.1"), k("10.0.0.2"));
        assert_eq!(k("2001:db8:1:2::1"), k("2001:db8:1:2:ffff:ffff:ffff:fffe"));
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
        assert_eq!(k("::ffff:10.0.0.1"), k("10.0.0.1"));
        // a whole /64 spends one bucket
        let intro = Intro::default();
        intro.set_ctx(intro_ctx());
        let t0 = Instant::now();
        for i in 0..INTRO_SOURCE_BURST as u16 {
            assert!(intro.admit(id(i), &ip(&format!("2001:db8:1:2::{:x}", i + 1)), t0));
        }
        assert!(
            !intro.admit(id(99), &ip("2001:db8:1:2::abcd"), t0),
            "the /64's burst is spent"
        );
        assert!(intro.admit(id(98), &ip("2001:db8:1:3::1"), t0), "the next /64 is not");
    }

    /// Review 5, note 1: relay arrivals are keyed by endpoint id, so one outsider's flood through a relay spends its
    /// own bucket, not the newcomers' -- until the relay ceiling (endpoint ids are free to mint), which leaves direct
    /// IP arrivals untouched.
    #[test]
    fn relay_introductions_are_keyed_by_endpoint_id_under_a_ceiling() {
        let intro = Intro::default();
        intro.set_ctx(intro_ctx());
        let t0 = Instant::now();
        let flooder = id(1);
        for _ in 0..INTRO_SOURCE_BURST as u16 {
            assert!(intro.admit(flooder, &Source::Relay(flooder), t0));
        }
        assert!(
            !intro.admit(flooder, &Source::Relay(flooder), t0),
            "the flooder's own bucket is spent"
        );
        assert!(
            intro.admit(id(2), &Source::Relay(id(2)), t0),
            "a newcomer by the same relay is admitted"
        );
        // the ceiling: INTRO_RELAY_BURST relay admissions in all, then none, whatever the id
        let mut admitted = INTRO_SOURCE_BURST as usize + 1;
        for i in 3..1_000u16 {
            if intro.admit(id(i), &Source::Relay(id(i)), t0) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, INTRO_RELAY_BURST as usize);
        assert!(
            intro.admit(id(1_001), &ip("10.9.0.1"), t0),
            "direct IP arrivals are outside the relay ceiling"
        );
        // it refills at INTRO_RELAY_PER_SECOND
        assert!(intro.admit(id(1_002), &Source::Relay(id(1_002)), t0 + Duration::from_secs(1)));
    }

    /// Review 5, note 2: the global ceiling covers every source.
    #[test]
    fn every_self_introduction_is_under_a_global_ceiling() {
        let intro = Intro::default();
        intro.set_ctx(intro_ctx());
        let t0 = Instant::now();
        let mut admitted = 0;
        for i in 0..1_000u16 {
            if intro.admit(id(i), &ip(&format!("10.{}.{}.1", i / 250, i % 250)), t0) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, INTRO_GLOBAL_BURST as usize);
    }

    /// Review 5, note 2: a connection counts as pending until it verifies or closes (the guard), and past
    /// INTRO_PENDING_MAX a new admission evicts the oldest, whose handler is told to close it.
    #[tokio::test]
    async fn held_connections_count_until_decided_and_the_oldest_is_evicted() {
        let intro = Intro::default();
        intro.set_ctx(intro_ctx());
        let t0 = Instant::now();
        let at = |i: u16| t0 + Duration::from_millis(i as u64);
        for i in 0..INTRO_PENDING_MAX as u16 {
            assert!(intro.admit(id(i), &ip(&format!("10.0.{}.{}", i / 250, i % 250)), at(i)));
        }
        assert_eq!(intro.pending_len(), INTRO_PENDING_MAX);
        let oldest = intro.hold_pending(&id(0)).unwrap();
        let held = intro.hold_pending(&id(1)).unwrap();
        // one more: the oldest is evicted and told so
        let n = INTRO_PENDING_MAX as u16;
        assert!(intro.admit(id(n), &ip("10.1.0.1"), at(n)));
        assert_eq!(intro.pending_len(), INTRO_PENDING_MAX);
        tokio::time::timeout(Duration::from_secs(1), oldest.evict.notified())
            .await
            .expect("the oldest pending connection is told to close");
        drop(oldest); // its entry is already gone: nothing else is released
        assert_eq!(intro.pending_len(), INTRO_PENDING_MAX);
        assert!(intro.hold_pending(&id(0)).is_none());
        // a decided connection releases its place
        drop(held);
        assert_eq!(intro.pending_len(), INTRO_PENDING_MAX - 1);
    }

    /// Review 5, note 2, end to end: a silent connection is held in the pending table for the deadline, then refused
    /// and released.
    #[tokio::test]
    async fn a_silent_connection_counts_as_pending_until_it_is_refused() {
        let (a, _f, _ann) = DirectNode::open(None, &["none".to_string()], &[]).await.unwrap();
        a.intro.set_ctx(intro_ctx());
        let e = plain().await;
        let c = tokio::time::timeout(
            CONNECT_TIMEOUT,
            e.connect(endpoint_addr(a.id(), &local(&a), None), ALPN),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::sleep(INTRO_DEADLINE / 3).await;
        assert_eq!(a.intro.pending_len(), 1, "held while it has not introduced itself");
        let closed = tokio::time::timeout(INTRO_DEADLINE * 2, c.closed()).await;
        assert!(closed.is_ok_and(|e| format!("{e:?}").contains(&REFUSED.to_string())));
        assert_eq!(a.intro.pending_len(), 0, "released once refused");
        e.close().await;
        a.shutdown().await;
    }

    /// Review 5, note 3: an introduction whose binding is older than the one held for its seat is refused (an
    /// endpoint key retired by a rotation); the same or a newer one is taken.
    #[test]
    fn an_introduction_older_than_the_held_binding_is_refused() {
        let key = bk::endpoint_key(9);
        let a = crate::binding::Announce::decode(&intro_for(&key, bk::endpoint_id(9), 12)).unwrap(); // issued 100
        let intro = Intro::default();
        for (held, want) in [
            (None, Some(2)),
            (Some(90), Some(2)),
            (Some(100), Some(2)),
            (Some(101), None),
        ] {
            let mut ctx = intro_ctx();
            if let Some(h) = held {
                ctx.held.insert(2, h);
            }
            intro.set_ctx(ctx);
            assert_eq!(intro.verify(&key.public(), &a), want, "held {held:?}");
        }
        // another seat's held binding does not matter
        let mut ctx = intro_ctx();
        ctx.held.insert(3, 1_000);
        intro.set_ctx(ctx);
        assert_eq!(intro.verify(&key.public(), &a), Some(2));
    }
}
