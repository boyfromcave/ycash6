// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The cancel-limit design's safety brake, automated (CAN-2 + C4b; owner 2026-10-13: automated before release).
//! Three parts, run inside `attest` once per poll:
//!
//! 1. **Watcher.** Every confirmed YED claim (`yed_listvaults CLAIMING`: the index holds confirmed state only) is
//!    judged at the claim's refHeight with this agent's own price: the price this seq signed for that height, else
//!    the aggregate it computed nearest that height, else its aggregate now while the refHeight is recent. A claim is
//!    **wrong-price** when the vault was not claimable at that price with `margin_bps` to spare
//!    ([`cosig::is_wrong_price`]). A wrong-price claim raises an alert and, with `auto_cosign`, is co-signed
//!    (`yed_signcancelcosign`: the node's equivocation guard locks the statement to the price this key signed for
//!    that height) and the co-signature is published on the cancel topic.
//! 2. **Gossip.** Frames on the cancel topic ([`cosig::Frame`], 115 bytes, nothing else) pass a digest dedup and a
//!    global token bucket, wait (bounded) until this node knows the claim, are verified locally -- the key the entry
//!    recovers to over the message rebuilt from this node's view must be `seq`'s current member key, the refHeight
//!    the claim's, the stated price one at which the vault was not claimable -- and then pass a per-seq bucket.
//! 3. **Collector.** For a wrong-price claim one member drives: the rota is the current members in seq order,
//!    rotated by the intent's hash; the member of rank r takes over r x `takeover_blocks` blocks after the claim
//!    confirmed. The driver waits for `cancelsRequired` (`yed_getvault`) valid co-signatures plus `spares` (at most
//!    `spare_wait_blocks` for the spares), calls `yed_buildcancel` (an entry the node refuses is dropped and the call
//!    retried), `set_signcancel`, `vault_send`, pushes the carrier and the cancel to `broadcast_rpc`, re-pushes a
//!    cancel that lingers, and rebuilds one that left the mempool (`vault_refee`, then `yed_buildcancel` re-attaches
//!    the carrier with the co-signatures valid now). Everything is persisted (`state_file`), so a restart resumes.
//!
//! The decisions are pure functions ([`honest_price`], [`judge`], [`rank`], [`decide`], [`GossipFilter`]) for the
//! unit tests; [`CancelAgent`] performs the RPCs.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::CancelConfig;
use crate::cosig::{self, Entry, Frame};
use crate::rpc::{Node, RpcError};

pub const STATE_VERSION: u32 = 1;
/// Frames waiting for a claim this node does not know yet (gossip can outrun a block by a few seconds).
pub const PENDING_MAX: usize = 256;
pub const PENDING_TTL: Duration = Duration::from_secs(600);
pub const DEDUP_CAPACITY: usize = 4096;
/// Price history kept (blocks): far more than CLAIM_DELAY.
pub const PRICE_HISTORY: u32 = 4096;
/// A closed claim is forgotten this many blocks after its release height.
pub const CLOSED_KEEP: u32 = 1152;
/// `yed_buildcancel` retries in one tick when the node refuses an entry.
pub const BUILD_ATTEMPTS: usize = 8;

// ---------------------------------------------------------------------------------------------------------- state

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not judged yet (the claim is not confirmed deep enough, or its refHeight is unknown).
    Pending,
    /// Not claimable at this agent's honest price: cancel it.
    Wrong,
    /// Claimable at this agent's honest price: leave it.
    Honest,
    /// No price of this agent's near the refHeight: no co-signature; driven only on others' co-signatures.
    Unjudged,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    Watching,
    /// This agent sent a cancel (`txid`; `hex` the signed transaction; `carrier` its co-signature carrier).
    Sent {
        txid: String,
        hex: String,
        carrier: String,
        height: u32,
        cosigners: Vec<u16>,
        last_push: u32,
    },
    /// The claim is gone from CLAIMING: "cancelled" or "released", or "expired" (past its release height).
    Closed {
        outcome: String,
        height: u32,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claim {
    /// The CLAIMING vault's outpoint ("txid:n"), the record `yed_getvault` reads.
    pub vault: String,
    pub confirm_height: u32,
    pub release_height: u32,
    pub ref_height: Option<u32>,
    /// blockHash(refHeight), display hex.
    pub block_hash: Option<String>,
    pub collateral_zat: i64,
    pub minted_cents: i64,
    /// `cancelsRequired` as last read (a cancel confirming in the next block).
    pub required: u32,
    pub verdict: Verdict,
    pub judged_price: Option<i64>,
    pub own_cosig: Option<String>,
    pub last_publish: Option<u32>,
    /// Verified co-signatures by seq (69-byte hex), this agent's own included.
    pub cosigs: BTreeMap<u16, String>,
    /// Seqs whose entry the node refused (yed_buildcancel), or that stopped being current.
    pub rejected: BTreeSet<u16>,
    /// The first height at which `required` valid co-signatures were in hand (spares wait from here).
    pub enough_since: Option<u32>,
    pub phase: Phase,
    pub sends: u32,
    /// Alert kinds already raised for this claim.
    pub alerted: BTreeSet<String>,
}

impl Claim {
    pub fn new(vault: String, confirm_height: u32, release_height: u32) -> Self {
        Claim {
            vault,
            confirm_height,
            release_height,
            ref_height: None,
            block_hash: None,
            collateral_zat: 0,
            minted_cents: 0,
            required: 1,
            verdict: Verdict::Pending,
            judged_price: None,
            own_cosig: None,
            last_publish: None,
            cosigs: BTreeMap::new(),
            rejected: BTreeSet::new(),
            enough_since: None,
            phase: Phase::Watching,
            sends: 0,
            alerted: BTreeSet::new(),
        }
    }

    /// The co-signatures a cancel would carry: valid (not refused) ones, this agent's first, then by seq; at most
    /// `CANCEL_COSIGN_MAX`.
    pub fn usable(&self, me: u16) -> Vec<(u16, String)> {
        let mut out: Vec<(u16, String)> = Vec::new();
        if let Some(own) = self.cosigs.get(&me).filter(|_| !self.rejected.contains(&me)) {
            out.push((me, own.clone()));
        }
        for (s, h) in &self.cosigs {
            if *s != me && !self.rejected.contains(s) {
                out.push((*s, h.clone()));
            }
        }
        out.truncate(cosig::CANCEL_COSIGN_MAX);
        out
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.phase, Phase::Closed { .. })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct State {
    pub version: u32,
    /// By claimant intent ("txid:n").
    pub claims: BTreeMap<String, Claim>,
    /// Tip height -> the aggregate (µUSD) this agent computed while the node was at that height.
    pub prices: BTreeMap<u32, i64>,
    /// citedHeight -> the price this seq signed (its published attestations).
    pub signed: BTreeMap<u32, i64>,
}

impl State {
    pub fn load(path: &Path) -> State {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<State>(&bytes) {
                Ok(s) if s.version == STATE_VERSION => s,
                Ok(s) => {
                    tracing::error!(
                        "cancel state {} has version {}, not {STATE_VERSION}; starting afresh (kept as .old)",
                        path.display(),
                        s.version
                    );
                    let _ = std::fs::rename(path, path.with_extension("old"));
                    State::fresh()
                }
                Err(e) => {
                    // Starting afresh is safe: co-signing again is idempotent (the node's guard), and so is building
                    // the cancel again (yed_buildcancel's sign-once build memo).
                    tracing::error!(
                        "cancel state {} is unreadable ({e}); starting afresh (kept as .corrupt)",
                        path.display()
                    );
                    let _ = std::fs::rename(path, path.with_extension("corrupt"));
                    State::fresh()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::fresh(),
            Err(e) => {
                tracing::error!("cancel state {}: {e}; starting afresh", path.display());
                State::fresh()
            }
        }
    }

    pub fn fresh() -> State {
        State {
            version: STATE_VERSION,
            ..Default::default()
        }
    }

    /// Written through a temporary file and one rename (mode 0600), so a crash leaves the old or the new file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            std::io::Write::write_all(&mut f, &serde_json::to_vec_pretty(self)?)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn record_price(&mut self, height: u32, micro_usd: i64) {
        self.prices.insert(height, micro_usd);
        let floor = height.saturating_sub(PRICE_HISTORY);
        self.prices = self.prices.split_off(&floor);
    }

    pub fn record_signed(&mut self, cited: u32, micro_usd: i64) {
        self.signed.insert(cited, micro_usd);
        let floor = cited.saturating_sub(PRICE_HISTORY);
        self.signed = self.signed.split_off(&floor);
    }

    /// Forget closed claims long past their release height.
    pub fn prune(&mut self, height: u32) {
        self.claims
            .retain(|_, c| !c.is_closed() || height < c.release_height.saturating_add(CLOSED_KEEP));
    }
}

// ---------------------------------------------------------------------------------------------- pure decisions

/// This agent's honest price at `ref_height`: what it signed for that height (the node's guard holds the same), else
/// the aggregate it computed at the nearest height within `tolerance` (the lower one on a tie), else `current` when
/// the refHeight is within `tolerance` of the tip. None: this agent cannot judge the claim.
pub fn honest_price(state: &State, ref_height: u32, tip: u32, tolerance: u32, current: Option<i64>) -> Option<i64> {
    if let Some(p) = state.signed.get(&ref_height) {
        return Some(*p);
    }
    let lo = ref_height.saturating_sub(tolerance);
    let hi = ref_height.saturating_add(tolerance);
    let best = state
        .prices
        .range(lo..=hi)
        .min_by_key(|(h, _)| (h.abs_diff(ref_height), **h))
        .map(|(_, p)| *p);
    if best.is_some() {
        return best;
    }
    if tip.abs_diff(ref_height) <= tolerance {
        return current;
    }
    None
}

/// The watcher's verdict on a claim at `price` (None: unjudged).
pub fn judge(collateral_zat: i64, minted_cents: i64, theta_bps: u32, margin_bps: u32, price: Option<i64>) -> Verdict {
    match price {
        None => Verdict::Unjudged,
        Some(p) if cosig::is_wrong_price(collateral_zat, p, minted_cents, theta_bps, margin_bps) => Verdict::Wrong,
        Some(_) => Verdict::Honest,
    }
}

/// This member's rank in the claim's rota: the current members in seq order, rotated by SHA-256(txid ‖ n) so the
/// first driver differs from claim to claim. None when `me` is not a current member.
pub fn rank(members: &[u16], me: u16, txid: &[u8; 32], n: u32) -> Option<u32> {
    let mut m: Vec<u16> = members.to_vec();
    m.sort_unstable();
    m.dedup();
    let idx = m.iter().position(|s| *s == me)?;
    let mut h = Sha256::new();
    h.update(txid);
    h.update(n.to_le_bytes());
    let d = h.finalize();
    let offset = (u64::from_le_bytes(d[..8].try_into().expect("8")) % m.len() as u64) as usize;
    Some(((idx + m.len() - offset) % m.len()) as u32)
}

/// What the collector should do with one claim this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Idle(&'static str),
    /// Build, sign and send with these co-signatures (seq order as in [`Claim::usable`]).
    Build(Vec<u16>),
    /// Our cancel lingers in the mempool: push it (and its carrier) to the broadcast peers again.
    Rebroadcast,
    /// Our cancel left the mempool unconfirmed: re-fund it and rebuild it with the co-signatures valid now.
    Rebuild,
}

pub struct DecideCtx {
    pub height: u32,
    pub me: u16,
    pub rank: Option<u32>,
    pub drive: bool,
    pub takeover_blocks: u32,
    pub spares: u32,
    pub spare_wait_blocks: u32,
    pub refee_after_blocks: u32,
    /// The claimant intent is spent in the mempool (a cancel or a release is pending).
    pub intent_spent_in_mempool: bool,
    /// Our sent cancel is in the node's mempool.
    pub our_tx_in_mempool: bool,
}

pub fn decide(c: &Claim, x: &DecideCtx) -> Decision {
    if c.is_closed() {
        return Decision::Idle("closed");
    }
    if x.height >= c.release_height {
        return Decision::Idle("past the release height");
    }
    match c.verdict {
        Verdict::Pending => return Decision::Idle("not judged yet"),
        Verdict::Honest => return Decision::Idle("honest claim"),
        Verdict::Wrong | Verdict::Unjudged => {}
    }
    if !x.drive {
        return Decision::Idle("drive = false");
    }
    let Some(rank) = x.rank else {
        return Decision::Idle("not a current member");
    };
    let usable = c.usable(x.me).len() as u32;
    if c.verdict == Verdict::Unjudged && usable < c.required {
        return Decision::Idle("unjudged and short of co-signatures");
    }
    match &c.phase {
        Phase::Closed { .. } => Decision::Idle("closed"),
        Phase::Sent { last_push, .. } => {
            if x.our_tx_in_mempool {
                if x.height >= last_push.saturating_add(x.refee_after_blocks) {
                    Decision::Rebroadcast
                } else {
                    Decision::Idle("sent")
                }
            } else if x.intent_spent_in_mempool {
                Decision::Idle("another cancel is in the mempool")
            } else if usable >= c.required {
                Decision::Rebuild
            } else {
                Decision::Idle("sent cancel gone; short of co-signatures to rebuild")
            }
        }
        Phase::Watching => {
            let turn = c.confirm_height.saturating_add(rank.saturating_mul(x.takeover_blocks));
            if x.height < turn {
                return Decision::Idle("not this member's turn yet");
            }
            if x.intent_spent_in_mempool {
                return Decision::Idle("another cancel is in the mempool");
            }
            if usable < c.required {
                return Decision::Idle("short of co-signatures");
            }
            let full = usable >= c.required.saturating_add(x.spares) || usable as usize >= cosig::CANCEL_COSIGN_MAX;
            let waited = c
                .enough_since
                .is_some_and(|h| x.height >= h.saturating_add(x.spare_wait_blocks));
            if full || waited {
                Decision::Build(c.usable(x.me).into_iter().map(|(s, _)| s).collect())
            } else {
                Decision::Idle("waiting for spare co-signatures")
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------------ gossip

/// Why a frame was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drop {
    Malformed(String),
    Duplicate,
    GlobalRate,
    /// The claim is unknown to this node (yet): the frame waits in the pending queue.
    UnknownClaim,
    NotMember(u16),
    WrongRefHeight(u16),
    BadSignature(u16),
    Claimable(u16),
    SeqRate(u16),
    /// A valid entry of this seq is already held for the claim.
    AlreadyHeld(u16),
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

fn take(b: &mut Bucket, burst: f64, refill: f64, now: Instant) -> bool {
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

/// The chain facts a frame is verified against.
#[derive(Clone, Debug, Default)]
pub struct MemberView {
    pub set_id: [u8; 32],
    pub theta_bps: u32,
    /// Current members: seq -> compressed key (the newest record of each key).
    pub members: BTreeMap<u16, [u8; 33]>,
}

/// The cancel topic's receive filter: dedup, a global bucket before any work, local verification, then a per-seq
/// bucket that only authenticated frames can drain (a forged `seq` never starves the real member).
pub struct GossipFilter {
    burst: f64,
    refill: f64,
    global: Bucket,
    seqs: HashMap<u16, Bucket>,
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl GossipFilter {
    pub fn new(burst: u32, refill_seconds: u64, now: Instant) -> Self {
        let burst = burst.max(1) as f64;
        GossipFilter {
            burst,
            refill: refill_seconds.max(1) as f64,
            // the global bucket admits 16 seqs' worth of burst, refilled 16 times as fast
            global: Bucket {
                tokens: burst * 16.0,
                last: now,
            },
            seqs: HashMap::new(),
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    fn remember(&mut self, d: [u8; 32]) {
        if self.seen.insert(d) {
            self.order.push_back(d);
            while self.order.len() > DEDUP_CAPACITY {
                if let Some(old) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }

    /// Stateless checks and the global bucket: size, magic, dedup.
    pub fn screen(&mut self, bytes: &[u8], now: Instant) -> Result<Frame, Drop> {
        let frame = Frame::decode(bytes).map_err(|e| Drop::Malformed(e.to_string()))?;
        let d: [u8; 32] = Sha256::digest(bytes).into();
        if self.seen.contains(&d) {
            return Err(Drop::Duplicate);
        }
        let (burst, refill) = (self.burst * 16.0, self.refill / 16.0);
        if !take(&mut self.global, burst, refill, now) {
            return Err(Drop::GlobalRate);
        }
        Ok(frame)
    }

    /// Verify `frame` against `claim` and the member view; on success the frame is remembered and the per-seq
    /// bucket charged.
    pub fn verify(&mut self, frame: &Frame, claim: &Claim, view: &MemberView, now: Instant) -> Result<(), Drop> {
        let seq = frame.seq;
        let Some(key) = view.members.get(&seq) else {
            return Err(Drop::NotMember(seq));
        };
        let (Some(r), Some(bh)) = (claim.ref_height, claim.block_hash.as_deref()) else {
            return Err(Drop::UnknownClaim);
        };
        if frame.ref_height != r {
            return Err(Drop::WrongRefHeight(seq));
        }
        let bh = cosig::internal_from_display(bh).ok_or(Drop::UnknownClaim)?;
        if (frame.entry.price as i64) < 100
            || cosig::is_underwater(
                claim.collateral_zat,
                frame.entry.price as i64,
                claim.minted_cents,
                view.theta_bps,
            )
        {
            return Err(Drop::Claimable(seq));
        }
        let msg = cosig::message(&view.set_id, &frame.txid, frame.n, r, frame.entry.price, &bh);
        if cosig::recover(&msg, &frame.entry.sig).as_ref() != Some(key) {
            return Err(Drop::BadSignature(seq));
        }
        if claim.cosigs.get(&seq) == Some(&frame.entry.to_hex()) {
            self.remember(Sha256::digest(frame.encode()).into());
            return Err(Drop::AlreadyHeld(seq));
        }
        let b = self.seqs.entry(seq).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        if !take(b, self.burst, self.refill, now) {
            return Err(Drop::SeqRate(seq));
        }
        self.remember(Sha256::digest(frame.encode()).into());
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------------- agent

/// The `yed_listattestors` rows → the current members (status ELIGIBLE or DORMANT, bond unspent and unfrozen; the
/// newest record of each key).
pub fn current_members(rows: &Value) -> BTreeMap<u16, [u8; 33]> {
    let mut newest: HashMap<[u8; 33], u16> = HashMap::new();
    let mut current: BTreeMap<u16, [u8; 33]> = BTreeMap::new();
    for r in rows.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let Some(seq) = r.get("seq").and_then(Value::as_u64).and_then(|s| u16::try_from(s).ok()) else {
            continue;
        };
        let Some(key) = r
            .get("attestorPubKey")
            .and_then(Value::as_str)
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 33]>::try_from(b.as_slice()).ok())
        else {
            continue;
        };
        let e = newest.entry(key).or_insert(seq);
        *e = (*e).max(seq);
        let status = r.get("status").and_then(Value::as_str).unwrap_or("");
        let spent = r.get("bondSpentHeight").is_some_and(|v| !v.is_null());
        let frozen = r.get("bondFrozen").and_then(Value::as_bool).unwrap_or(false);
        if (status == "ELIGIBLE" || status == "DORMANT") && !spent && !frozen {
            current.insert(seq, key);
        }
    }
    current.retain(|seq, key| newest.get(key) == Some(seq));
    current
}

/// `cosigs[i]` in a `yed_buildcancel` refusal.
pub fn refused_index(message: &str) -> Option<usize> {
    let start = message.find("cosigs[")? + 7;
    let end = start + message[start..].find(']')?;
    message[start..end].parse().ok()
}

pub struct CancelAgent {
    pub cfg: CancelConfig,
    pub node: Node,
    pub seq: u16,
    pub state: State,
    pub path: PathBuf,
    pub filter: GossipFilter,
    pending: VecDeque<(Frame, Instant)>,
    pub view: MemberView,
    peers: Vec<Node>,
    outbox: Vec<Vec<u8>>,
    pub dirty: bool,
}

impl CancelAgent {
    pub fn new(
        cfg: CancelConfig,
        node_cfg: &crate::config::NodeConfig,
        seq: u16,
        path: PathBuf,
    ) -> anyhow::Result<Self> {
        let node = Node::new(node_cfg)?;
        let mut peers = Vec::new();
        for u in &cfg.broadcast_rpc {
            let mut c = node_cfg.clone();
            c.rpc_url = u.clone();
            c.cookie = None;
            c.user = None;
            c.password = None;
            peers.push(Node::new(&c)?);
        }
        let state = State::load(&path);
        tracing::info!(
            "cancel automation: seq {seq}, auto_cosign {}, margin {} bps, drive {}, spares {}, state {} ({} claim(s) remembered)",
            cfg.auto_cosign,
            cfg.margin_bps,
            cfg.drive,
            cfg.spares,
            path.display(),
            state.claims.len()
        );
        Ok(CancelAgent {
            filter: GossipFilter::new(cfg.gossip_burst, cfg.gossip_refill_seconds, Instant::now()),
            cfg,
            node,
            seq,
            state,
            path,
            pending: VecDeque::new(),
            view: MemberView::default(),
            peers,
            outbox: Vec::new(),
            dirty: false,
        })
    }

    /// The default state file: `~/.ycash/yellowback-cancel-<network>-<seq>.json`.
    pub fn default_path(network: &str, seq: u16) -> PathBuf {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        home.join(".ycash")
            .join(format!("yellowback-cancel-{network}-{seq}.json"))
    }

    /// Frames to publish on the cancel topic (drained by the caller).
    pub fn take_outbox(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox)
    }

    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }
        match self.state.save(&self.path) {
            Ok(()) => self.dirty = false,
            Err(e) => tracing::error!("cancel state {} not saved: {e}", self.path.display()),
        }
    }

    fn alert(&mut self, intent: &str, kind: &str, message: String) {
        let Some(c) = self.state.claims.get_mut(intent) else {
            return;
        };
        if !c.alerted.insert(kind.to_string()) {
            return;
        }
        self.dirty = true;
        tracing::error!("ALERT {kind} {intent}: {message}");
        if let Some(cmd) = self.cfg.alert_command.clone() {
            let (k, i) = (kind.to_string(), intent.to_string());
            std::thread::spawn(move || {
                if let Err(e) = std::process::Command::new(&cmd).arg(&k).arg(&i).arg(&message).status() {
                    tracing::error!("alert_command {cmd}: {e}");
                }
            });
        }
    }

    /// Refresh the set id, theta and the current members. False when the node cannot say.
    pub async fn refresh_view(&mut self) -> bool {
        if self.view.theta_bps == 0 {
            match self.node.call("yed_getinfo", vec![]).await {
                Ok(v) => {
                    let set = v
                        .get("upgrade")
                        .and_then(|u| u.get("attestorSetId"))
                        .and_then(Value::as_str)
                        .and_then(cosig::internal_from_display);
                    let theta = v
                        .get("params")
                        .and_then(|p| p.get("claimThresholdBps"))
                        .and_then(Value::as_u64)
                        .and_then(|t| u32::try_from(t).ok());
                    match (set, theta) {
                        (Some(s), Some(t)) if t > 0 => {
                            self.view.set_id = s;
                            self.view.theta_bps = t;
                        }
                        _ => {
                            tracing::warn!("cancel: yed_getinfo carries no attestorSetId / claimThresholdBps yet");
                            return false;
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("cancel: yed_getinfo failed: {e}");
                    return false;
                }
            }
        }
        match self.node.call("yed_listattestors", vec![]).await {
            Ok(rows) => {
                self.view.members = current_members(&rows);
                true
            }
            Err(e) => {
                tracing::error!("cancel: yed_listattestors failed: {e}");
                false
            }
        }
    }

    /// `yed_listvaults CLAIMING`, every page: the claimant intents with their vault rows.
    async fn claiming(&self) -> Result<Vec<(String, Value)>, RpcError> {
        let mut out = Vec::new();
        let mut skip = 0u64;
        loop {
            let page = self
                .node
                .call("yed_listvaults", vec![json!("CLAIMING"), json!(100), json!(skip)])
                .await?;
            let rows = page.as_array().cloned().unwrap_or_default();
            for row in &rows {
                for it in row
                    .get("intents")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                {
                    if it.get("role").and_then(Value::as_str) != Some("claimant") {
                        continue;
                    }
                    let (Some(t), Some(n)) = (
                        it.get("txid").and_then(Value::as_str),
                        it.get("vout").and_then(Value::as_u64),
                    ) else {
                        continue;
                    };
                    out.push((format!("{t}:{n}"), row.clone()));
                }
            }
            if rows.len() < 100 {
                return Ok(out);
            }
            skip += 100;
        }
    }

    /// The claim's refHeight (its REDEEM payload) and blockHash(refHeight).
    async fn claim_ref(&self, intent: &str) -> Result<(u32, String), String> {
        let txid = intent.split(':').next().unwrap_or("");
        let raw = self
            .node
            .call("getrawtransaction", vec![json!(txid), json!(0)])
            .await
            .map_err(|e| format!("getrawtransaction {txid}: {e}"))?;
        let hex_str = raw.as_str().ok_or("getrawtransaction returned no hex")?;
        let dec = self
            .node
            .call("yed_decodepayload", vec![json!(hex_str)])
            .await
            .map_err(|e| format!("yed_decodepayload: {e}"))?;
        let r = dec
            .get("refHeight")
            .and_then(Value::as_u64)
            .and_then(|r| u32::try_from(r).ok())
            .ok_or("the claim carries no refHeight")?;
        let bh = self
            .node
            .call("getblockhash", vec![json!(r)])
            .await
            .map_err(|e| format!("getblockhash {r}: {e}"))?;
        Ok((r, bh.as_str().unwrap_or("").to_string()))
    }

    /// One poll at tip `height`. `current` is the aggregate this poll computed (already recorded by the caller);
    /// `inbox` the frames received since the last poll.
    pub async fn tick(&mut self, height: u32, current: Option<i64>, inbox: Vec<Vec<u8>>) {
        if !self.refresh_view().await {
            return;
        }
        let now = Instant::now();
        // 1. the claims the index holds
        match self.claiming().await {
            Ok(rows) => self.follow(height, rows).await,
            Err(e) => {
                tracing::error!("cancel: yed_listvaults CLAIMING failed: {e}");
                return;
            }
        }
        // 2. judge, co-sign, publish
        let intents: Vec<String> = self.state.claims.keys().cloned().collect();
        for intent in &intents {
            self.watch(intent, height, current).await;
        }
        // 3. the gossip: pending first (their claim may be known now), then the new frames
        let mut frames: Vec<(Frame, Instant)> = self.pending.drain(..).collect();
        for bytes in inbox {
            match self.filter.screen(&bytes, now) {
                Ok(f) => frames.push((f, now)),
                Err(d) => tracing::debug!("cancel topic: dropped {d:?}"),
            }
        }
        for (f, at) in frames {
            self.admit(f, at, now);
        }
        // 4. drive
        for intent in &intents {
            self.collect(intent, height).await;
        }
        self.state.prune(height);
        self.dirty = true;
        self.save();
    }

    /// Track new CLAIMING rows, refresh the open ones, close the ones that left CLAIMING.
    async fn follow(&mut self, height: u32, rows: Vec<(String, Value)>) {
        let mut live: HashSet<String> = HashSet::new();
        for (intent, row) in rows {
            live.insert(intent.clone());
            let vault = format!(
                "{}:{}",
                row.get("txid").and_then(Value::as_str).unwrap_or(""),
                row.get("vout").and_then(Value::as_u64).unwrap_or(0)
            );
            let it = row
                .get("intents")
                .and_then(Value::as_array)
                .and_then(|a| {
                    a.iter().find(|i| {
                        format!(
                            "{}:{}",
                            i.get("txid").and_then(Value::as_str).unwrap_or(""),
                            i.get("vout").and_then(Value::as_u64).unwrap_or(0)
                        ) == intent
                    })
                })
                .cloned()
                .unwrap_or(Value::Null);
            let confirm = it.get("height").and_then(Value::as_u64).unwrap_or(height as u64) as u32;
            let release = it.get("releaseHeight").and_then(Value::as_u64).unwrap_or(0) as u32;
            let c = self.state.claims.entry(intent.clone()).or_insert_with(|| {
                tracing::info!("cancel: following claim {intent} of vault {vault} (confirmed at {confirm}, releasable at {release})");
                Claim::new(vault.clone(), confirm, release)
            });
            if c.is_closed() {
                // the same intent CLAIMING again cannot happen (a cancel re-creates the vault at a new outpoint)
                continue;
            }
            let required = row.get("cancelsRequired").and_then(Value::as_u64).unwrap_or(1) as u32;
            let first_read = c.collateral_zat == 0;
            if required != c.required {
                if required > c.required && !first_read {
                    tracing::warn!(
                        "cancel: {intent} now needs {required} co-signature(s) (was {})",
                        c.required
                    );
                }
                c.required = required;
                c.enough_since = None;
            }
            c.collateral_zat = row.get("collateralZat").and_then(Value::as_i64).unwrap_or(0);
            c.minted_cents = row.get("mintedCents").and_then(Value::as_i64).unwrap_or(0);
        }
        // the ones that left CLAIMING
        let gone: Vec<String> = self
            .state
            .claims
            .iter()
            .filter(|(k, c)| !c.is_closed() && !live.contains(*k))
            .map(|(k, _)| k.clone())
            .collect();
        for intent in gone {
            let (vault, verdict) = {
                let c = &self.state.claims[&intent];
                (c.vault.clone(), c.verdict)
            };
            let vtxid = vault.split(':').next().unwrap_or("").to_string();
            let outcome = match self.node.call("yed_getvault", vec![json!(vtxid)]).await {
                Ok(v) if v.get("status").and_then(Value::as_str) == Some("CLAIMED") => "released",
                Ok(v) if v.get("status").and_then(Value::as_str) == Some("CLAIMING") => continue, // index racing; next poll
                Ok(_) => "cancelled",
                Err(RpcError::Node { message, .. }) if message.contains("vault-not-found") => "cancelled",
                Err(e) => {
                    tracing::warn!("cancel: yed_getvault {vtxid}: {e}; retried next poll");
                    continue;
                }
            };
            if let Some(c) = self.state.claims.get_mut(&intent) {
                c.phase = Phase::Closed {
                    outcome: outcome.to_string(),
                    height,
                };
            }
            self.dirty = true;
            if outcome == "released" && verdict == Verdict::Wrong {
                self.alert(
                    &intent,
                    "wrong-price-released",
                    format!(
                        "the wrong-price claim on vault {vault} was RELEASED: no cancel confirmed within CLAIM_DELAY"
                    ),
                );
            } else {
                tracing::info!("cancel: claim {intent} closed: {outcome} (verdict {verdict:?})");
            }
        }
    }

    /// Judge one claim and co-sign it when it is wrong-price.
    async fn watch(&mut self, intent: &str, height: u32, current: Option<i64>) {
        let Some(c) = self.state.claims.get(intent) else {
            return;
        };
        if c.is_closed() {
            return;
        }
        if height >= c.release_height && c.release_height > 0 {
            if c.verdict == Verdict::Wrong && c.phase == Phase::Watching {
                let v = c.vault.clone();
                self.alert(
                    intent,
                    "wrong-price-past-delay",
                    format!("the wrong-price claim on vault {v} reached its release height uncancelled"),
                );
            }
            return;
        }
        if height + 1 < c.confirm_height.saturating_add(self.cfg.min_confirmations) {
            return;
        }
        if c.ref_height.is_none() {
            match self.claim_ref(intent).await {
                Ok((r, bh)) => {
                    let c = self.state.claims.get_mut(intent).expect("present");
                    c.ref_height = Some(r);
                    c.block_hash = Some(bh);
                    self.dirty = true;
                }
                Err(e) => {
                    tracing::warn!("cancel: {intent}: {e}; retried next poll");
                    return;
                }
            }
        }
        let c = &self.state.claims[intent];
        let r = c.ref_height.expect("set above");
        if matches!(c.verdict, Verdict::Pending | Verdict::Unjudged) {
            let price = honest_price(&self.state, r, height, self.cfg.price_tolerance_blocks, current);
            let verdict = judge(
                c.collateral_zat,
                c.minted_cents,
                self.view.theta_bps,
                self.cfg.margin_bps,
                price,
            );
            let (vault, coll, debt) = (c.vault.clone(), c.collateral_zat, c.minted_cents);
            {
                let c = self.state.claims.get_mut(intent).expect("present");
                if c.verdict != verdict {
                    self.dirty = true;
                }
                c.verdict = verdict;
                c.judged_price = price;
            }
            match verdict {
                Verdict::Wrong => self.alert(
                    intent,
                    "wrong-price",
                    format!(
                        "claim on vault {vault} at refHeight {r} is NOT claimable at this agent's price {} µUSD \
                         (collateral {coll} zat, debt {debt} cents, theta {} bps, margin {} bps)",
                        price.unwrap_or(0),
                        self.view.theta_bps,
                        self.cfg.margin_bps
                    ),
                ),
                Verdict::Unjudged => self.alert(
                    intent,
                    "unjudged",
                    format!(
                        "no price of this agent's within {} blocks of refHeight {r}: not co-signed",
                        self.cfg.price_tolerance_blocks
                    ),
                ),
                Verdict::Honest => {
                    let first = self
                        .state
                        .claims
                        .get_mut(intent)
                        .is_some_and(|c| c.alerted.insert("honest".into()));
                    if first {
                        tracing::info!(
                            "cancel: claim {intent} on vault {vault} is claimable at this agent's price {} µUSD: honest, left alone",
                            price.unwrap_or(0)
                        );
                    }
                }
                Verdict::Pending => {}
            }
        }
        let c = &self.state.claims[intent];
        if c.verdict != Verdict::Wrong || !self.cfg.auto_cosign || !self.view.members.contains_key(&self.seq) {
            return;
        }
        if c.own_cosig.is_none() && !c.alerted.contains("cosign-refused") {
            self.cosign(intent).await;
        }
        let c = &self.state.claims[intent];
        if let Some(own) = c.own_cosig.clone() {
            let due = c
                .last_publish
                .is_none_or(|h| height >= h.saturating_add(self.cfg.republish_blocks));
            if due {
                if let Some(entry) = Entry::decode_hex(&own) {
                    if let Some((txid, n)) = cosig::parse_intent(intent) {
                        let f = Frame {
                            txid,
                            n,
                            seq: self.seq,
                            ref_height: r,
                            entry,
                        };
                        self.outbox.push(f.encode().to_vec());
                        let c = self.state.claims.get_mut(intent).expect("present");
                        c.last_publish = Some(height);
                        self.dirty = true;
                    }
                }
            }
        }
    }

    /// `yed_signcancelcosign`: the node's guard first (the price this key signed for refHeight), then the judged
    /// price when the key signed none there. A reply whose price is inside the margin is kept but not published.
    async fn cosign(&mut self, intent: &str) {
        let c = &self.state.claims[intent];
        let judged = c.judged_price;
        let (coll, debt) = (c.collateral_zat, c.minted_cents);
        let first = self
            .node
            .call(
                "yed_signcancelcosign",
                vec![json!(intent), Value::Null, json!(self.seq)],
            )
            .await;
        let reply = match first {
            Ok(v) => v,
            Err(RpcError::Node { message, .. }) if message.starts_with("price-required") => {
                let Some(p) = judged else {
                    return;
                };
                match self
                    .node
                    .call("yed_signcancelcosign", vec![json!(intent), json!(p), json!(self.seq)])
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        self.alert(
                            intent,
                            "cosign-refused",
                            format!("yed_signcancelcosign at {p} µUSD: {e}"),
                        );
                        return;
                    }
                }
            }
            Err(RpcError::Node { message, .. }) if message.starts_with("cancel-statement-claimable") => {
                // this key already signed, for the claim's refHeight, a price at which the vault was claimable
                self.alert(
                    intent,
                    "cosign-refused",
                    format!(
                        "the price this seq signed at the claim's refHeight says the vault was claimable: {message}"
                    ),
                );
                return;
            }
            Err(e) => {
                tracing::error!("cancel: yed_signcancelcosign {intent}: {e}; retried next poll");
                return;
            }
        };
        let Some(hex_str) = reply.get("cosig").and_then(Value::as_str) else {
            tracing::error!("cancel: yed_signcancelcosign returned no cosig");
            return;
        };
        let price = reply.get("priceMicroUsd").and_then(Value::as_i64).unwrap_or(0);
        if !cosig::is_wrong_price(coll, price, debt, self.view.theta_bps, self.cfg.margin_bps) {
            self.alert(
                intent,
                "cosign-within-margin",
                format!("the node's guard states {price} µUSD at the claim's refHeight, inside the {} bps margin: not published", self.cfg.margin_bps),
            );
            return;
        }
        tracing::info!("cancel: co-signed {intent} as seq {} at {price} µUSD", self.seq);
        let c = self.state.claims.get_mut(intent).expect("present");
        c.own_cosig = Some(hex_str.to_string());
        c.cosigs.insert(self.seq, hex_str.to_string());
        c.rejected.remove(&self.seq);
        self.dirty = true;
    }

    /// Take a screened frame: verify it against the claim it names, or park it until this node knows that claim.
    fn admit(&mut self, f: Frame, at: Instant, now: Instant) {
        let intent = f.intent();
        let known = self
            .state
            .claims
            .get(&intent)
            .filter(|c| !c.is_closed() && c.ref_height.is_some());
        let Some(claim) = known else {
            if self.state.claims.get(&intent).is_some_and(Claim::is_closed) {
                return;
            }
            if now.saturating_duration_since(at) < PENDING_TTL && self.pending.len() < PENDING_MAX {
                self.pending.push_back((f, at));
            }
            return;
        };
        match self.filter.verify(&f, claim, &self.view, now) {
            Ok(()) => {
                let c = self.state.claims.get_mut(&intent).expect("present");
                if let Some(old) = c.cosigs.get(&f.seq) {
                    if *old != f.entry.to_hex() && !c.rejected.contains(&f.seq) {
                        tracing::warn!(
                            "cancel: seq {} sent a second, different co-signature for {intent}; keeping the first",
                            f.seq
                        );
                        return;
                    }
                }
                tracing::info!(
                    "cancel: co-signature of seq {} for {intent} at {} µUSD verified",
                    f.seq,
                    f.entry.price
                );
                c.cosigs.insert(f.seq, f.entry.to_hex());
                c.rejected.remove(&f.seq);
                self.dirty = true;
            }
            Err(Drop::AlreadyHeld(_)) => {}
            Err(d) => tracing::info!("cancel topic: frame {f:?} dropped: {d:?}"),
        }
    }

    async fn mempool_has(&self, txid: &str) -> bool {
        match self.node.call("getrawmempool", vec![]).await {
            Ok(Value::Array(a)) => a.iter().any(|t| t.as_str() == Some(txid)),
            _ => false,
        }
    }

    async fn intent_spent_in_mempool(&self, intent: &str) -> bool {
        let Some((t, n)) = intent.split_once(':') else {
            return false;
        };
        let n: u64 = n.parse().unwrap_or(0);
        // the index says the intent is unspent in the chain (CLAIMING); gettxout with the mempool says null once a
        // mempool transaction spends it
        matches!(
            self.node.call("gettxout", vec![json!(t), json!(n), json!(true)]).await,
            Ok(Value::Null)
        )
    }

    /// Drop the co-signatures of seqs that stopped being current (the rule ignores them; spares replace them).
    fn prune_members(&mut self, intent: &str) {
        let members = self.view.members.clone();
        if let Some(c) = self.state.claims.get_mut(intent) {
            for s in c.cosigs.keys() {
                if !members.contains_key(s) && c.rejected.insert(*s) {
                    tracing::warn!(
                        "cancel: seq {s} is no longer a current member; its co-signature for {intent} is set aside"
                    );
                    self.dirty = true;
                }
            }
            let usable = c.usable(self.seq).len() as u32;
            if usable < c.required {
                c.enough_since = None;
            }
        }
    }

    async fn collect(&mut self, intent: &str, height: u32) {
        self.prune_members(intent);
        let Some(c) = self.state.claims.get(intent) else {
            return;
        };
        if c.is_closed() || matches!(c.verdict, Verdict::Pending | Verdict::Honest) {
            return;
        }
        if c.enough_since.is_none() && c.usable(self.seq).len() as u32 >= c.required {
            let c = self.state.claims.get_mut(intent).expect("present");
            c.enough_since = Some(height);
            self.dirty = true;
        }
        let c = &self.state.claims[intent];
        let members: Vec<u16> = self.view.members.keys().copied().collect();
        let r = cosig::parse_intent(intent).and_then(|(t, n)| rank(&members, self.seq, &t, n));
        let our_tx = match &c.phase {
            Phase::Sent { txid, .. } => Some(txid.clone()),
            _ => None,
        };
        let our_tx_in_mempool = match &our_tx {
            Some(t) => self.mempool_has(t).await,
            None => false,
        };
        let spent = if our_tx_in_mempool {
            true
        } else {
            self.intent_spent_in_mempool(intent).await
        };
        let c = &self.state.claims[intent];
        let x = DecideCtx {
            height,
            me: self.seq,
            rank: r,
            drive: self.cfg.drive,
            takeover_blocks: self.cfg.takeover_blocks,
            spares: self.cfg.spares,
            spare_wait_blocks: self.cfg.spare_wait_blocks,
            refee_after_blocks: self.cfg.refee_after_blocks,
            intent_spent_in_mempool: spent,
            our_tx_in_mempool,
        };
        match decide(c, &x) {
            Decision::Idle(why) => tracing::debug!("cancel: {intent}: {why}"),
            Decision::Build(_) => {
                tracing::info!(
                    "cancel: driving the cancel of {intent} (rank {}, {} co-signature(s), {} required)",
                    r.unwrap_or(0),
                    c.usable(self.seq).len(),
                    c.required
                );
                self.build_and_send(intent, height, None).await;
            }
            Decision::Rebroadcast => {
                if let Phase::Sent { txid, hex, carrier, .. } = c.phase.clone() {
                    tracing::warn!(
                        "cancel: {txid} for {intent} lingers in the mempool; pushing it to the broadcast peers again"
                    );
                    self.push_to_peers(&carrier, &hex).await;
                    if let Some(c) = self.state.claims.get_mut(intent) {
                        if let Phase::Sent { last_push, .. } = &mut c.phase {
                            *last_push = height;
                        }
                    }
                    self.dirty = true;
                }
            }
            Decision::Rebuild => {
                if let Phase::Sent { txid, hex, .. } = c.phase.clone() {
                    tracing::warn!(
                        "cancel: {txid} for {intent} left the mempool unconfirmed; re-funding and rebuilding"
                    );
                    // vault_refee replaces the fee inputs (and drops the carrier); yed_buildcancel then re-attaches a
                    // carrier with the co-signatures valid now (the build memo follows the re-funded transaction)
                    if let Err(e) = self.node.call("vault_refee", vec![json!(hex)]).await {
                        tracing::warn!("cancel: vault_refee: {e}; rebuilding without it");
                    }
                    self.build_and_send(intent, height, Some(txid)).await;
                }
            }
        }
    }

    /// `yed_buildcancel` (dropping refused entries and retrying), `set_signcancel`, `vault_send`, then the peers.
    async fn build_and_send(&mut self, intent: &str, height: u32, previous: Option<String>) {
        for _ in 0..BUILD_ATTEMPTS {
            let c = &self.state.claims[intent];
            let usable = c.usable(self.seq);
            if (usable.len() as u32) < c.required {
                tracing::warn!(
                    "cancel: {intent}: {} usable co-signature(s), {} required; waiting",
                    usable.len(),
                    c.required
                );
                return;
            }
            let hexes: Vec<String> = usable.iter().map(|(_, h)| h.clone()).collect();
            let built = match self
                .node
                .call("yed_buildcancel", vec![json!(intent), json!(hexes)])
                .await
            {
                Ok(v) => v,
                Err(RpcError::Node { message, .. })
                    if message.starts_with("cancel-cosign-not-member")
                        || message.starts_with("cancel-cosign-malformed")
                        || message.starts_with("cancel-statement-claimable") =>
                {
                    let Some(seq) = refused_index(&message).and_then(|i| usable.get(i)).map(|(s, _)| *s) else {
                        tracing::error!("cancel: yed_buildcancel {intent}: {message}");
                        return;
                    };
                    tracing::warn!("cancel: the node refused seq {seq}'s co-signature for {intent} ({message}); retrying without it");
                    let c = self.state.claims.get_mut(intent).expect("present");
                    c.rejected.insert(seq);
                    c.enough_since = None;
                    self.dirty = true;
                    continue;
                }
                Err(RpcError::Node { message, .. }) if message.starts_with("cancel-cosign-needed") => {
                    tracing::warn!("cancel: {intent}: {message}");
                    let c = self.state.claims.get_mut(intent).expect("present");
                    c.enough_since = None;
                    return;
                }
                Err(e) => {
                    tracing::error!("cancel: yed_buildcancel {intent}: {e}; retried next poll");
                    return;
                }
            };
            let hex_str = built.get("hex").and_then(Value::as_str).unwrap_or("").to_string();
            let carrier = built
                .get("carrierTxid")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let cosigners: Vec<u16> = built
                .get("cosigners")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_u64).map(|s| s as u16).collect())
                .unwrap_or_default();
            let signed = match self.node.call("set_signcancel", vec![json!(hex_str)]).await {
                Ok(v) => v,
                Err(e) => {
                    self.alert(
                        intent,
                        "sign-refused",
                        format!("set_signcancel: {e} (a restored wallet needs set_acknowledgerestore)"),
                    );
                    return;
                }
            };
            if signed.get("complete").and_then(Value::as_bool) != Some(true) {
                tracing::error!("cancel: set_signcancel for {intent} is not complete: {signed}");
                return;
            }
            let shex = signed.get("hex").and_then(Value::as_str).unwrap_or("").to_string();
            let txid = match self.node.call("vault_send", vec![json!(shex)]).await {
                Ok(v) => v.as_str().unwrap_or("").to_string(),
                Err(e) => {
                    tracing::error!("cancel: vault_send for {intent}: {e}; re-checked next poll");
                    // a co-signer that stopped being current shows up in the next refresh and is set aside then
                    return;
                }
            };
            tracing::info!(
                "cancel: SENT {txid} cancelling {intent} with co-signers {cosigners:?}{}",
                previous
                    .as_ref()
                    .map(|p| format!(" (replaces {p})"))
                    .unwrap_or_default()
            );
            let c = self.state.claims.get_mut(intent).expect("present");
            c.phase = Phase::Sent {
                txid,
                hex: shex.clone(),
                carrier: carrier.clone(),
                height,
                cosigners,
                last_push: height,
            };
            c.sends += 1;
            self.dirty = true;
            self.save();
            self.push_to_peers(&carrier, &shex).await;
            return;
        }
    }

    /// The carrier, then the cancel, to every `broadcast_rpc` node (review S1: send directly to well-connected peers).
    async fn push_to_peers(&self, carrier: &str, cancel_hex: &str) {
        if self.peers.is_empty() {
            return;
        }
        let carrier_hex = if carrier.is_empty() {
            None
        } else {
            match self
                .node
                .call("getrawtransaction", vec![json!(carrier), json!(0)])
                .await
            {
                Ok(v) => v.as_str().map(String::from),
                Err(e) => {
                    tracing::warn!("cancel: carrier {carrier}: {e}");
                    None
                }
            }
        };
        for p in &self.peers {
            for h in carrier_hex
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(cancel_hex))
            {
                match p.call("sendrawtransaction", vec![json!(h)]).await {
                    Ok(_) => {}
                    Err(RpcError::Node { message, .. })
                        if message.contains("already") || message.contains("txn-mempool-conflict") => {}
                    Err(e) => tracing::warn!("cancel: broadcast peer: {e}"),
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosig::testkit;
    use crate::rpc::mock::MockNode;
    use std::sync::{Arc, Mutex};

    const THETA: u32 = 12_500;
    const COLL: i64 = 75 * 100_000_000; // 75 YEC against $100: claimable below $1.6667
    const DEBT: i64 = 10_000;

    fn claim(required: u32) -> Claim {
        let mut c = Claim::new("aa:0".into(), 100, 110);
        c.ref_height = Some(99);
        c.block_hash = Some(hex::encode([0x33u8; 32]));
        c.collateral_zat = COLL;
        c.minted_cents = DEBT;
        c.required = required;
        c.verdict = Verdict::Wrong;
        c
    }

    fn ctx(height: u32, rank: u32) -> DecideCtx {
        DecideCtx {
            height,
            me: 1,
            rank: Some(rank),
            drive: true,
            takeover_blocks: 2,
            spares: 1,
            spare_wait_blocks: 1,
            refee_after_blocks: 3,
            intent_spent_in_mempool: false,
            our_tx_in_mempool: false,
        }
    }

    // ---- watcher

    #[test]
    fn honest_price_prefers_the_signed_then_the_nearest_then_now() {
        let mut s = State::fresh();
        assert_eq!(honest_price(&s, 100, 101, 5, Some(7)), Some(7)); // recent: the aggregate now
        assert_eq!(honest_price(&s, 100, 120, 5, Some(7)), None); // too old to judge with today's price
        s.record_price(97, 3);
        s.record_price(104, 4);
        assert_eq!(honest_price(&s, 100, 120, 5, Some(7)), Some(3)); // 97 is nearer than 104
        s.record_price(103, 5);
        assert_eq!(honest_price(&s, 100, 120, 5, Some(7)), Some(3)); // a tie (97, 103) takes the lower height
        s.record_price(100, 6);
        assert_eq!(honest_price(&s, 100, 120, 5, Some(7)), Some(6));
        s.record_signed(100, 9);
        assert_eq!(honest_price(&s, 100, 120, 5, Some(7)), Some(9)); // what this seq signed for R wins
        assert_eq!(honest_price(&s, 300, 301, 0, None), None);
    }

    #[test]
    fn the_verdict_with_and_without_margin() {
        assert_eq!(judge(COLL, DEBT, THETA, 500, Some(4_000_000)), Verdict::Wrong); // 300 %
        assert_eq!(judge(COLL, DEBT, THETA, 500, Some(1_600_000)), Verdict::Honest); // 120 %: claimable
        assert_eq!(judge(COLL, DEBT, THETA, 500, Some(1_700_000)), Verdict::Honest); // 127.5 %: inside the margin
        assert_eq!(judge(COLL, DEBT, THETA, 0, Some(1_700_000)), Verdict::Wrong);
        assert_eq!(judge(COLL, DEBT, THETA, 500, None), Verdict::Unjudged);
    }

    #[test]
    fn state_prices_are_bounded() {
        let mut s = State::fresh();
        s.record_price(10, 1);
        s.record_price(10 + PRICE_HISTORY + 1, 2);
        assert_eq!(s.prices.len(), 1);
    }

    // ---- the rota

    #[test]
    fn rank_is_a_rotation_by_the_intent() {
        let members = [5u16, 1, 3, 9];
        let ranks: Vec<u32> = members
            .iter()
            .map(|m| rank(&members, *m, &[7; 32], 0).unwrap())
            .collect();
        let mut sorted = ranks.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3]); // a permutation: exactly one leader
        assert_eq!(rank(&members, 4, &[7; 32], 0), None);
        // deterministic, independent of the list order, and it differs between claims
        assert_eq!(rank(&[9, 5, 3, 1], 3, &[7; 32], 0), rank(&members, 3, &[7; 32], 0));
        let leaders: HashSet<u16> = (0u8..32)
            .map(|i| {
                *members
                    .iter()
                    .find(|m| rank(&members, **m, &[i; 32], 0) == Some(0))
                    .unwrap()
            })
            .collect();
        assert!(leaders.len() > 1, "the first driver should vary across claims");
    }

    // ---- the collector state machine

    #[test]
    fn decide_waits_for_its_turn_then_for_spares() {
        let mut c = claim(1);
        assert_eq!(decide(&c, &ctx(100, 0)), Decision::Idle("short of co-signatures"));
        c.cosigs.insert(1, "11".into());
        // rank 1 waits takeover_blocks (2) after the confirmation
        assert_eq!(decide(&c, &ctx(101, 1)), Decision::Idle("not this member's turn yet"));
        // rank 0, one valid (= required), the spare not yet in: waits a block from enough_since
        c.enough_since = Some(100);
        assert_eq!(
            decide(&c, &ctx(100, 0)),
            Decision::Idle("waiting for spare co-signatures")
        );
        assert_eq!(decide(&c, &ctx(101, 0)), Decision::Build(vec![1]));
        // a spare in hand: at once, own first
        c.cosigs.insert(0, "00".into());
        assert_eq!(decide(&c, &ctx(100, 0)), Decision::Build(vec![1, 0]));
        // the takeover member drives at its turn
        assert_eq!(decide(&c, &ctx(102, 1)), Decision::Build(vec![1, 0]));
        // somebody's cancel already in the mempool: wait
        let mut x = ctx(102, 1);
        x.intent_spent_in_mempool = true;
        assert_eq!(decide(&c, &x), Decision::Idle("another cancel is in the mempool"));
    }

    #[test]
    fn decide_escalates_and_drops_refused_entries() {
        let mut c = claim(2);
        c.cosigs.insert(1, "11".into());
        c.cosigs.insert(4, "44".into());
        c.enough_since = Some(100);
        assert_eq!(decide(&c, &ctx(101, 0)), Decision::Build(vec![1, 4]));
        c.rejected.insert(4); // the node refused seq 4's entry (it left the set): one short again
        assert_eq!(decide(&c, &ctx(101, 0)), Decision::Idle("short of co-signatures"));
        c.cosigs.insert(6, "66".into()); // a spare arrives
        assert_eq!(decide(&c, &ctx(101, 0)), Decision::Build(vec![1, 6]));
        // more than CANCEL_COSIGN_MAX: the carrier holds seven
        for s in 10..20 {
            c.cosigs.insert(s, "ff".into());
        }
        match decide(&c, &ctx(101, 0)) {
            Decision::Build(v) => assert_eq!(v.len(), cosig::CANCEL_COSIGN_MAX),
            d => panic!("{d:?}"),
        }
    }

    #[test]
    fn decide_after_sending() {
        let mut c = claim(1);
        c.cosigs.insert(1, "11".into());
        c.phase = Phase::Sent {
            txid: "t".into(),
            hex: "h".into(),
            carrier: "c".into(),
            height: 101,
            cosigners: vec![1],
            last_push: 101,
        };
        let mut x = ctx(102, 0);
        x.our_tx_in_mempool = true;
        assert_eq!(decide(&c, &x), Decision::Idle("sent"));
        x.height = 104;
        assert_eq!(decide(&c, &x), Decision::Rebroadcast); // lingering: push again
        x.our_tx_in_mempool = false;
        assert_eq!(decide(&c, &x), Decision::Rebuild); // gone and nothing else spends the intent: rebuild
        c.rejected.insert(1);
        assert_eq!(
            decide(&c, &x),
            Decision::Idle("sent cancel gone; short of co-signatures to rebuild")
        );
    }

    #[test]
    fn decide_never_touches_honest_closed_late_or_passive() {
        let mut c = claim(1);
        c.cosigs.insert(1, "11".into());
        c.cosigs.insert(2, "22".into());
        c.verdict = Verdict::Honest;
        assert_eq!(decide(&c, &ctx(101, 0)), Decision::Idle("honest claim"));
        c.verdict = Verdict::Wrong;
        assert_eq!(decide(&c, &ctx(110, 0)), Decision::Idle("past the release height"));
        let mut x = ctx(101, 0);
        x.drive = false;
        assert_eq!(decide(&c, &x), Decision::Idle("drive = false"));
        x.drive = true;
        x.rank = None;
        assert_eq!(decide(&c, &x), Decision::Idle("not a current member"));
        // unjudged here, but others' co-signatures are enough: it still drives
        c.verdict = Verdict::Unjudged;
        assert_eq!(decide(&c, &ctx(101, 0)), Decision::Build(vec![1, 2]));
        c.phase = Phase::Closed {
            outcome: "cancelled".into(),
            height: 105,
        };
        assert_eq!(decide(&c, &ctx(106, 0)), Decision::Idle("closed"));
    }

    // ---- gossip validation

    fn view(keys: &[(u16, u8)]) -> MemberView {
        MemberView {
            set_id: [0x75; 32],
            theta_bps: THETA,
            members: keys
                .iter()
                .map(|(s, k)| (*s, testkit::pubkey(&testkit::key(*k))))
                .collect(),
        }
    }

    fn frame_for(c: &Claim, seq: u16, key: u8, price: u32, set: [u8; 32]) -> Frame {
        let txid = [0xaa; 32];
        let bh = cosig::internal_from_display(c.block_hash.as_deref().unwrap()).unwrap();
        let msg = cosig::message(&set, &txid, 0, c.ref_height.unwrap(), price, &bh);
        Frame {
            txid,
            n: 0,
            seq,
            ref_height: c.ref_height.unwrap(),
            entry: Entry {
                price,
                sig: testkit::sign(&testkit::key(key), &msg),
            },
        }
    }

    #[test]
    fn gossip_admits_only_verified_current_members() {
        let now = Instant::now();
        let c = claim(1);
        let v = view(&[(1, 1), (2, 2), (3, 3)]);
        let mut g = GossipFilter::new(4, 60, now);
        let good = frame_for(&c, 2, 2, 4_000_000, v.set_id);
        let f = g.screen(&good.encode(), now).unwrap();
        assert_eq!(g.verify(&f, &c, &v, now), Ok(()));
        // the same bytes again: a duplicate, before any work
        assert_eq!(g.screen(&good.encode(), now), Err(Drop::Duplicate));
        // size cap and magic
        assert!(matches!(g.screen(&[0u8; 116], now), Err(Drop::Malformed(_))));
        assert!(matches!(g.screen(b"YCG1", now), Err(Drop::Malformed(_))));
        // a non-member key, claiming a member's seq: the signature does not recover to seq 3's key
        let forged = frame_for(&c, 3, 9, 4_000_000, v.set_id);
        assert_eq!(g.verify(&forged, &c, &v, now), Err(Drop::BadSignature(3)));
        // an unknown seq
        let stranger = frame_for(&c, 7, 7, 4_000_000, v.set_id);
        assert_eq!(g.verify(&stranger, &c, &v, now), Err(Drop::NotMember(7)));
        // a member's signature over another set (another network) does not verify here
        let other_set = frame_for(&c, 1, 1, 4_000_000, [0x01; 32]);
        assert_eq!(g.verify(&other_set, &c, &v, now), Err(Drop::BadSignature(1)));
        // a statement saying the vault WAS claimable is worthless to the rule: dropped
        let claimable = frame_for(&c, 1, 1, 1_600_000, v.set_id);
        assert_eq!(g.verify(&claimable, &c, &v, now), Err(Drop::Claimable(1)));
        // the wrong refHeight
        let mut wrong_r = frame_for(&c, 1, 1, 4_000_000, v.set_id);
        wrong_r.ref_height += 1;
        assert_eq!(g.verify(&wrong_r, &c, &v, now), Err(Drop::WrongRefHeight(1)));
        // an entry already held is not counted again
        let mut held = c.clone();
        held.cosigs.insert(2, good.entry.to_hex());
        let again = frame_for(&c, 2, 2, 4_000_000, v.set_id);
        assert_eq!(g.verify(&again, &held, &v, now), Err(Drop::AlreadyHeld(2)));
    }

    #[test]
    fn gossip_rate_limits_per_authenticated_seq_and_globally() {
        let now = Instant::now();
        let c = claim(1);
        let v = view(&[(1, 1)]);
        let mut g = GossipFilter::new(2, 60, now);
        // distinct valid statements of seq 1 (different prices): two pass, the third is over its bucket
        let mut outcomes = Vec::new();
        for p in [4_000_000u32, 4_000_001, 4_000_002] {
            let f = frame_for(&c, 1, 1, p, v.set_id);
            outcomes.push(g.verify(&f, &c, &v, now));
        }
        assert_eq!(outcomes, vec![Ok(()), Ok(()), Err(Drop::SeqRate(1))]);
        // forged frames naming seq 1 do not drain its bucket (they fail before it), but the global bucket bounds
        // the work: 2 x 16 = 32 frames, then GlobalRate
        let mut g = GossipFilter::new(2, 60, now);
        let mut global = 0;
        for i in 0..40u32 {
            let mut junk = frame_for(&c, 1, 9, 4_000_000 + i, v.set_id).encode();
            junk[100] ^= 1;
            if g.screen(&junk, now) == Err(Drop::GlobalRate) {
                global += 1;
            }
        }
        assert_eq!(global, 8);
        let later = now + Duration::from_secs(120);
        let f = frame_for(&c, 1, 1, 4_000_100, v.set_id);
        assert_eq!(g.verify(&f, &c, &v, later), Ok(()));
    }

    #[test]
    fn members_are_current_and_newest() {
        let k = |i: u8| hex::encode(testkit::pubkey(&testkit::key(i)));
        let rows = json!([
            {"seq": 0, "attestorPubKey": k(1), "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 1, "attestorPubKey": k(2), "status": "DORMANT", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 2, "attestorPubKey": k(3), "status": "EJECTED", "bondSpentHeight": null, "bondFrozen": true},
            {"seq": 3, "attestorPubKey": k(4), "status": "PENDING", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 4, "attestorPubKey": k(5), "status": "WITHDRAWN", "bondSpentHeight": 50, "bondFrozen": false},
            {"seq": 5, "attestorPubKey": k(5), "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 6, "attestorPubKey": k(1), "status": "PENDING", "bondSpentHeight": null, "bondFrozen": false}
        ]);
        let m = current_members(&rows);
        // seq 0's key re-joined as seq 6 (pending): the newest record is not current, so neither is seq 0
        assert_eq!(m.keys().copied().collect::<Vec<_>>(), vec![1, 5]);
    }

    #[test]
    fn refused_index_parses_the_node_message() {
        assert_eq!(
            refused_index("cancel-cosign-not-member: cosigs[2] is not from a current member"),
            Some(2)
        );
        assert_eq!(refused_index("cancel-cosign-needed: this cancel needs 2"), None);
    }

    #[test]
    fn state_round_trips_and_survives_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s/cancel.json");
        let mut s = State::fresh();
        s.claims.insert("aa:0".into(), claim(2));
        s.record_price(10, 4_000_000);
        s.save(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let back = State::load(&p);
        assert_eq!(back.claims["aa:0"].required, 2);
        assert_eq!(back.prices[&10], 4_000_000);
        std::fs::write(&p, "{not json").unwrap();
        let fresh = State::load(&p);
        assert!(fresh.claims.is_empty());
        assert!(p.with_extension("corrupt").exists());
    }

    // ---- the agent end to end against a mock node: watch, co-sign, gossip in, collect, send, close, restart

    struct Chain {
        height: u32,
        claiming: bool,
        cancelled: bool,
        cancels_required: u32,
        sent: Vec<Vec<String>>,
        mempool: Vec<String>,
    }

    fn mock(chain: Arc<Mutex<Chain>>) -> MockNode {
        let set = [0x75u8; 32];
        let bh = [0x33u8; 32];
        let intent_txid = "aa".repeat(32);
        MockNode::start(None, move |method, params| {
            let mut ch = chain.lock().unwrap();
            let k = |i: u8| hex::encode(testkit::pubkey(&testkit::key(i)));
            match method {
                "yed_getinfo" => Ok(json!({"network": "regtest", "height": ch.height,
                    "upgrade": {"attestorSetId": cosig::display_of_internal(&set)}, "params": {"claimThresholdBps": THETA}})),
                "yed_listattestors" => Ok(json!([
                    {"seq": 0, "attestorPubKey": k(10), "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false},
                    {"seq": 1, "attestorPubKey": k(11), "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false},
                    {"seq": 2, "attestorPubKey": k(12), "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false}
                ])),
                "yed_listvaults" => Ok(if ch.claiming {
                    json!([{"txid": "bb".repeat(32), "vout": 0, "status": "CLAIMING", "collateralZat": COLL, "mintedCents": DEBT,
                        "cancelsRequired": ch.cancels_required,
                        "intents": [{"txid": intent_txid, "vout": 0, "role": "claimant", "height": 100, "releaseHeight": 110}]}])
                } else {
                    json!([])
                }),
                "getrawtransaction" => Ok(json!("00")),
                "yed_decodepayload" => Ok(json!({"valid": true, "type": "redeem", "refHeight": 99})),
                "getblockhash" => Ok(json!(cosig::display_of_internal(&bh))),
                "yed_signcancelcosign" => {
                    let seq = params[2].as_u64().unwrap() as u16;
                    if params[1].is_null() {
                        return Err((
                            -8,
                            format!("price-required: seq {seq} signed no price for the claim's refHeight 99"),
                        ));
                    }
                    let price = params[1].as_u64().unwrap() as u32;
                    let msg = cosig::message(
                        &set,
                        &cosig::internal_from_display(&intent_txid).unwrap(),
                        0,
                        99,
                        price,
                        &bh,
                    );
                    let e = Entry {
                        price,
                        sig: testkit::sign(&testkit::key(10 + seq as u8), &msg),
                    };
                    Ok(
                        json!({"cosig": e.to_hex(), "seq": seq, "priceMicroUsd": price, "citedHeight": 99, "reused": false}),
                    )
                }
                "yed_buildcancel" => {
                    let cos: Vec<String> = params[1]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect();
                    if (cos.len() as u32) < ch.cancels_required {
                        return Err((
                            -8,
                            format!(
                                "cancel-cosign-needed: this cancel needs {} co-signature(s)",
                                ch.cancels_required
                            ),
                        ));
                    }
                    ch.sent.push(cos.clone());
                    Ok(
                        json!({"hex": "c0ffee", "carrierTxid": "cc".repeat(32), "cosigners": (0..cos.len()).collect::<Vec<_>>(), "cancelsRequired": ch.cancels_required}),
                    )
                }
                "set_signcancel" => Ok(json!({"hex": "c0ffee01", "complete": true})),
                "vault_send" => {
                    ch.mempool.push("dd".repeat(32));
                    Ok(json!("dd".repeat(32)))
                }
                "getrawmempool" => Ok(json!(ch.mempool)),
                "gettxout" => Ok(if ch.mempool.is_empty() {
                    json!({"value": 1})
                } else {
                    Value::Null
                }),
                "yed_getvault" => {
                    if ch.cancelled {
                        Err((-8, "vault-not-found".into()))
                    } else {
                        Ok(json!({"status": "CLAIMED"}))
                    }
                }
                _ => Err((-32601, format!("Method not found: {method}"))),
            }
        })
    }

    fn agent_cfg() -> CancelConfig {
        crate::config::parse("[node]\nrpc_url = \"http://127.0.0.1:1\"\n[cancel]\nspares = 1\nspare_wait_blocks = 1\ntakeover_blocks = 50\n")
            .unwrap()
            .cancel
    }

    #[tokio::test]
    async fn agent_cosigns_collects_sends_closes_and_resumes() {
        let chain = Arc::new(Mutex::new(Chain {
            height: 100,
            claiming: true,
            cancelled: false,
            cancels_required: 2,
            sent: vec![],
            mempool: vec![],
        }));
        let m = mock(chain.clone());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let node_cfg = m.config(None, None, None);
        // find the rota's leader for this intent among seqs 0..2 and run as that member
        let txid = cosig::internal_from_display(&"aa".repeat(32)).unwrap();
        let leader = (0u16..3).find(|s| rank(&[0, 1, 2], *s, &txid, 0) == Some(0)).unwrap();
        let other = (0u16..3).find(|s| *s != leader).unwrap();
        let mut a = CancelAgent::new(agent_cfg(), &node_cfg, leader, path.clone()).unwrap();
        a.state.record_price(99, 4_000_000); // this agent's honest price at R = 99: $4.00 (the vault at 300 %)

        // tick 1: follows the claim, judges it wrong-price, co-signs (price-required -> its own price), publishes
        a.tick(100, Some(4_000_000), vec![]).await;
        let c = &a.state.claims[&format!("{}:0", "aa".repeat(32))];
        assert_eq!(c.verdict, Verdict::Wrong);
        assert!(c.alerted.contains("wrong-price"));
        assert!(c.own_cosig.is_some());
        let out = a.take_outbox();
        assert_eq!(out.len(), 1);
        let f = Frame::decode(&out[0]).unwrap();
        assert_eq!((f.seq, f.ref_height, f.entry.price), (leader, 99, 4_000_000));
        assert!(chain.lock().unwrap().sent.is_empty()); // required 2: one in hand, nothing built

        // a second member's co-signature arrives on the topic (and a forged one, dropped): the leader now holds 2 =
        // required, waits a block for the spare, then builds
        let set = [0x75u8; 32];
        let bh = [0x33u8; 32];
        let sign = |seq: u16, key: u8| {
            let msg = cosig::message(&set, &txid, 0, 99, 4_000_000, &bh);
            Frame {
                txid,
                n: 0,
                seq,
                ref_height: 99,
                entry: Entry {
                    price: 4_000_000,
                    sig: testkit::sign(&testkit::key(key), &msg),
                },
            }
            .encode()
            .to_vec()
        };
        a.tick(
            100,
            Some(4_000_000),
            vec![sign(other, 10 + other as u8), sign(other, 99)],
        )
        .await;
        assert_eq!(a.state.claims.values().next().unwrap().cosigs.len(), 2);
        assert!(chain.lock().unwrap().sent.is_empty());
        a.tick(101, Some(4_000_000), vec![]).await;
        {
            let ch = chain.lock().unwrap();
            assert_eq!(ch.sent.len(), 1);
            assert_eq!(ch.sent[0].len(), 2);
        }
        assert!(matches!(
            a.state.claims.values().next().unwrap().phase,
            Phase::Sent { .. }
        ));

        // restart: a new agent on the same state file neither re-co-signs nor rebuilds (the cancel is in the mempool)
        drop(a);
        let signs = |m: &MockNode| {
            m.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, _)| c == "yed_signcancelcosign")
                .count()
        };
        let before = signs(&m);
        let mut b = CancelAgent::new(agent_cfg(), &node_cfg, leader, path.clone()).unwrap();
        b.tick(102, Some(4_000_000), vec![]).await;
        assert_eq!(chain.lock().unwrap().sent.len(), 1);
        assert_eq!(signs(&m), before);
        assert_eq!(b.state.claims.values().next().unwrap().cosigs.len(), 2);

        // the cancel confirms: the claim leaves CLAIMING, the vault record is gone: closed as cancelled
        {
            let mut ch = chain.lock().unwrap();
            ch.claiming = false;
            ch.cancelled = true;
            ch.mempool.clear();
        }
        b.tick(103, Some(4_000_000), vec![]).await;
        assert_eq!(
            b.state.claims.values().next().unwrap().phase,
            Phase::Closed {
                outcome: "cancelled".into(),
                height: 103
            }
        );
    }

    #[tokio::test]
    async fn agent_leaves_an_honest_claim_alone() {
        let chain = Arc::new(Mutex::new(Chain {
            height: 100,
            claiming: true,
            cancelled: false,
            cancels_required: 1,
            sent: vec![],
            mempool: vec![],
        }));
        let m = mock(chain.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut a = CancelAgent::new(agent_cfg(), &m.config(None, None, None), 0, dir.path().join("s.json")).unwrap();
        a.state.record_price(99, 1_600_000); // the vault really is at 120 % at this agent's price
        for h in 100..111 {
            a.tick(h, Some(1_600_000), vec![]).await;
        }
        let c = a.state.claims.values().next().unwrap();
        assert_eq!(c.verdict, Verdict::Honest);
        assert!(c.own_cosig.is_none());
        assert!(a.take_outbox().is_empty());
        assert!(chain.lock().unwrap().sent.is_empty());
        assert!(!m.calls.lock().unwrap().iter().any(|(c, _)| c == "yed_signcancelcosign"));
        // released after the delay: closed as released, no alert (it was honest)
        chain.lock().unwrap().claiming = false;
        a.tick(111, Some(1_600_000), vec![]).await;
        let c = a.state.claims.values().next().unwrap();
        assert!(matches!(&c.phase, Phase::Closed { outcome, .. } if outcome == "released"));
        assert!(!c.alerted.contains("wrong-price-released"));
    }

    #[tokio::test]
    async fn agent_with_auto_cosign_off_only_alerts() {
        let chain = Arc::new(Mutex::new(Chain {
            height: 100,
            claiming: true,
            cancelled: false,
            cancels_required: 1,
            sent: vec![],
            mempool: vec![],
        }));
        let m = mock(chain.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = agent_cfg();
        cfg.auto_cosign = false;
        let mut a = CancelAgent::new(cfg, &m.config(None, None, None), 0, dir.path().join("s.json")).unwrap();
        a.tick(100, Some(4_000_000), vec![]).await;
        let c = a.state.claims.values().next().unwrap();
        assert_eq!(c.verdict, Verdict::Wrong);
        assert!(c.alerted.contains("wrong-price"));
        assert!(c.own_cosig.is_none());
        assert!(a.take_outbox().is_empty());
        // the claim is released: the alert that matters
        chain.lock().unwrap().claiming = false;
        a.tick(111, None, vec![]).await;
        assert!(a
            .state
            .claims
            .values()
            .next()
            .unwrap()
            .alerted
            .contains("wrong-price-released"));
    }
}
