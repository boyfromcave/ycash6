// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The cancel-limit design's safety brake, automated (CAN-2 + C4b; owner 2026-10-13: automated before release).
//! Three parts, run inside `attest`:
//!
//! 1. **Watcher** (once per poll). Every confirmed YED claim (`yed_listvaults CLAIMING`: the index holds confirmed
//!    state only) is judged at the claim's refHeight with this agent's own price there: a price this key is on
//!    record for at that height (the state's signed prices, the claim's own bundle, the node's pool, the node's
//!    equivocation guard), else the last aggregate it computed at or before that height. A claim is **wrong-price**
//!    when the vault was not claimable at that price with `margin_bps` to spare ([`cosig::is_wrong_price`]). A
//!    wrong-price claim raises an alert and, with `auto_cosign`, is co-signed (`yed_signcancelcosign`) and the
//!    co-signature published on the cancel topic. A price is stated anew for a height only when this agent's record
//!    covers that height (review M-2); with no price at all the claim is Unjudged and alerted, never guessed from a
//!    later aggregate (review L-6). Reorgs: a claim whose block leaves the chain is held (never closed), a claim back
//!    in CLAIMING is reopened, and a reorg across the refHeight resets the claim and re-signs (review H-1, H-2).
//! 2. **Gossip** (continuously, between polls). A frame ([`cosig::Frame`], 115 bytes) passes a digest dedup, then
//!    the cheap checks (current member seq, a claim this node knows, its refHeight, a price at which the vault was
//!    not claimable), then a token bucket of the peer that delivered it, then signature recovery against that seq's
//!    member key, then a per-seq bucket. A flood from one peer spends only that peer's bucket (review H-3).
//! 3. **Collector** (once per poll). One member drives each claim: the rota is the current members in seq order,
//!    rotated by the intent's hash; rank r takes over r x `takeover_blocks` after the claim confirmed (shrunk to fit
//!    CLAIM_DELAY). The driver waits for `cancelsRequired` valid co-signatures plus `spares`, calls
//!    `yed_buildcancel`, `set_signcancel`, `vault_send`, pushes the carrier and the cancel to `broadcast_rpc`,
//!    re-pushes a lingering cancel, and rebuilds one that left the mempool with exponential backoff, at most
//!    `max_sends` times (review M-3). Everything is persisted (`state_file`), so a restart resumes.
//!
//! The decisions are pure functions ([`honest_price`], [`judge`], [`rank`], [`decide`]; the gossip's in `gossip.rs`) for the
//! unit tests; [`CancelAgent`] performs the RPCs.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::CancelConfig;
use crate::cosig::{self, Entry, Frame};
use crate::rpc::{Node, RpcError};

pub const STATE_VERSION: u32 = 1;
/// Price history kept (blocks): far more than CLAIM_DELAY.
pub const PRICE_HISTORY: u32 = 4096;
/// A closed claim is forgotten this many blocks after its release height; a claim whose block left the chain and
/// never came back is closed as "orphaned" this long after its release height.
pub const CLOSED_KEEP: u32 = 1152;
/// `yed_buildcancel` retries in one tick when the node refuses an entry.
pub const BUILD_ATTEMPTS: usize = 8;
/// Public-topic binding announces kept between polls per claimed seq: a uniform sample of that seq's arrivals.
pub const BINDING_PER_SEQ: usize = 4;
/// Binding signature checks a poll, all sources together (a secp256k1 recovery and an ed25519 verification each).
pub const BINDING_RECOVERIES: usize = 64;
/// A newly signed binding is announced every poll for this many blocks (review N-A).
pub const FRESH_ANNOUNCE_BLOCKS: u32 = 20;
/// Announces one member's own connection may queue a poll (it can only be checked for its own seat).
pub const BINDING_PER_MEMBER: usize = 4;
/// `alert_command` children at once, and how long one may run before it is killed.
pub const ALERTS_INFLIGHT_MAX: usize = 4;
pub const ALERT_TIMEOUT: Duration = Duration::from_secs(30);

static ALERTS_INFLIGHT: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------------------------------------- state

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not judged yet (the claim is not confirmed deep enough, or its refHeight is unknown).
    Pending,
    /// Not claimable at this agent's honest price: cancel it.
    Wrong,
    /// Claimable at this agent's honest price: leave it.
    Honest,
    /// No price of this agent's at the refHeight: no co-signature; driven only on others' co-signatures.
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
    /// The claim's intent was spent in a confirmed block: "cancelled" or "released"; or "orphaned" (its block left
    /// the chain and it never came back).
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
    /// The hash of the block the claim confirmed in (display hex): a reorg is seen when it changes.
    #[serde(default)]
    pub confirm_hash: Option<String>,
    pub release_height: u32,
    pub ref_height: Option<u32>,
    /// blockHash(refHeight), display hex.
    pub block_hash: Option<String>,
    /// The price this seq attested at the refHeight inside the claim's own bundle, if it did (review M-2).
    #[serde(default)]
    pub bundle_price: Option<i64>,
    pub collateral_zat: i64,
    pub minted_cents: i64,
    /// `cancelsRequired` as last read (a cancel confirming in the next block).
    pub required: u32,
    pub verdict: Verdict,
    pub judged_price: Option<i64>,
    pub own_cosig: Option<String>,
    /// Why this agent will not co-sign this claim (a sticky refusal: the statement is claimable, an equivocation
    /// guard, a price out of range, inside the margin, no record at the height). None: it may still co-sign.
    #[serde(default)]
    pub cosign_blocked: Option<String>,
    pub last_publish: Option<u32>,
    /// Verified co-signatures by seq (69-byte hex), this agent's own included.
    pub cosigs: BTreeMap<u16, String>,
    /// Seqs whose entry the node refused or dropped for a reason that does not change (malformed, claimable,
    /// out of range). Membership is not recorded here: it is checked against the current view every time.
    pub rejected: BTreeSet<u16>,
    /// The first height at which `required` valid co-signatures were in hand (spares wait from here).
    pub enough_since: Option<u32>,
    pub phase: Phase,
    pub sends: u32,
    /// No rebuild before this height (exponential backoff, review M-3).
    #[serde(default)]
    pub next_rebuild: u32,
    /// The claim's block left the chain: it is held open but not driven until it is back in CLAIMING.
    #[serde(default)]
    pub orphaned: bool,
    /// Since when a transaction that is not this agent's spends the intent in the mempool.
    #[serde(default)]
    pub foreign_spend_since: Option<u32>,
    /// The on-chain fallback transaction this agent sent for the claim (owner decision 2).
    #[serde(default)]
    pub onchain_posted: Option<String>,
    /// The last block scanned for on-chain co-signature records.
    #[serde(default)]
    pub scanned_to: Option<u32>,
    /// Alert kinds already raised for this claim.
    pub alerted: BTreeSet<String>,
}

/// What a reset keeps aside: co-signatures stay valid when the claim comes back with the same refHeight and
/// blockHash(refHeight) (the message they sign is unchanged), and are restored then.
#[derive(Clone, Debug)]
pub struct Prior {
    pub ref_height: Option<u32>,
    pub block_hash: Option<String>,
    pub cosigs: BTreeMap<u16, String>,
    pub own_cosig: Option<String>,
}

impl Claim {
    pub fn new(vault: String, confirm_height: u32, release_height: u32) -> Self {
        Claim {
            vault,
            confirm_height,
            confirm_hash: None,
            release_height,
            ref_height: None,
            block_hash: None,
            bundle_price: None,
            collateral_zat: 0,
            minted_cents: 0,
            required: 1,
            verdict: Verdict::Pending,
            judged_price: None,
            own_cosig: None,
            cosign_blocked: None,
            last_publish: None,
            cosigs: BTreeMap::new(),
            rejected: BTreeSet::new(),
            enough_since: None,
            phase: Phase::Watching,
            sends: 0,
            next_rebuild: 0,
            orphaned: false,
            foreign_spend_since: None,
            onchain_posted: None,
            scanned_to: None,
            alerted: BTreeSet::new(),
        }
    }

    /// A reorg (review H-1, H-2): forget everything derived from the chain -- the confirmation, the refHeight and
    /// its hash, the verdict, the co-signatures, the sent cancel -- and judge the claim again. Returns what was set
    /// aside (see [`Prior`]).
    pub fn reset(&mut self, confirm_height: u32, release_height: u32) -> Prior {
        let prior = Prior {
            ref_height: self.ref_height,
            block_hash: self.block_hash.clone(),
            cosigs: std::mem::take(&mut self.cosigs),
            own_cosig: self.own_cosig.take(),
        };
        self.confirm_height = confirm_height;
        self.confirm_hash = None;
        self.release_height = release_height;
        self.ref_height = None;
        self.block_hash = None;
        self.bundle_price = None;
        self.verdict = Verdict::Pending;
        self.judged_price = None;
        self.cosign_blocked = None;
        self.last_publish = None;
        self.rejected.clear();
        self.enough_since = None;
        self.phase = Phase::Watching;
        // sends and next_rebuild survive a reorg (re-review N-7): the cap and the backoff count every attempt made
        // for this claimant intent, which a reorg does not re-create
        self.orphaned = false;
        self.foreign_spend_since = None;
        self.onchain_posted = None;
        self.scanned_to = None;
        for k in [
            "honest",
            "wrong-price",
            "unjudged",
            "cosign-refused",
            "cosign-within-margin",
            "no-record",
        ] {
            self.alerted.remove(k);
        }
        prior
    }

    /// The co-signatures a cancel would carry: those of current `members` the node did not refuse, this agent's
    /// first (only with `own`: never with `auto_cosign = false`, re-review N-5), then by seq; at most
    /// `CANCEL_COSIGN_MAX`.
    pub fn usable(&self, me: u16, own: bool, members: &BTreeMap<u16, [u8; 33]>) -> Vec<(u16, String)> {
        let ok = |s: &u16| members.contains_key(s) && !self.rejected.contains(s) && (own || *s != me);
        let mut out: Vec<(u16, String)> = Vec::new();
        if let Some(own) = self.cosigs.get(&me).filter(|_| ok(&me)) {
            out.push((me, own.clone()));
        }
        for (s, h) in &self.cosigs {
            if *s != me && ok(s) {
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
    /// The tip when this state file began recording `signed`: for a height above it, a missing `signed` entry means
    /// this agent did not attest there (review M-2); at or below it the state cannot say.
    #[serde(default)]
    pub recording_since: Option<u32>,
    /// The members' endpoint bindings (owner decision 1): the latest valid one per seq.
    #[serde(default)]
    pub bindings: crate::binding::Store,
    /// This member's own announced binding.
    #[serde(default)]
    pub own_binding: Option<crate::binding::Announce>,
    /// Alerts that are not about one claim, already raised ("kind|key").
    #[serde(default)]
    pub alerted_global: BTreeSet<String>,
    /// Heights of the on-chain fallback transactions this agent sent (the daily cap).
    #[serde(default)]
    pub fallback_posts: Vec<u32>,
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
                    // Starting afresh is safe: co-signing again goes through the node's guard (the price this key
                    // signed there), a price is stated only for heights the new record covers, and building again
                    // returns the same cancel (the sign-once build memo).
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

    /// Written through a new temporary file (O_EXCL, mode 0600) and one rename, so a crash leaves the old or the
    /// new file and the temporary name is never one somebody else created.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        let open = || {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&tmp)
        };
        let mut f = match open() {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // a leftover of this process (a failed write): remove it and create it afresh
                std::fs::remove_file(&tmp)?;
                open()?
            }
            Err(e) => return Err(e.into()),
        };
        std::io::Write::write_all(&mut f, &serde_json::to_vec_pretty(self)?)?;
        f.sync_all()?;
        drop(f);
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

/// This agent's aggregate at `ref_height`: what it signed for that height, else the last aggregate it recorded
/// while the tip was at or below that height (within `tolerance`) -- what it knew there, never a later move. None:
/// it has no price of its own there (it was not running, or its feed was down), and the claim is not judged on a
/// guess (review L-6).
pub fn honest_price(state: &State, ref_height: u32, tolerance: u32) -> Option<i64> {
    if let Some(p) = state.signed.get(&ref_height) {
        return Some(*p);
    }
    let lo = ref_height.saturating_sub(tolerance);
    state.prices.range(lo..=ref_height).next_back().map(|(_, p)| *p)
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

/// `takeover_blocks` shrunk so the last of `members` ranks still drives inside CLAIM_DELAY with the spare wait and
/// a block of slack: `(claimDelay − spare_wait − 2) / (members − 1)`, at least 1 (review L-4).
pub fn effective_takeover(configured: u32, claim_delay: Option<u32>, spare_wait: u32, members: usize) -> u32 {
    let Some(delay) = claim_delay else {
        return configured.max(1);
    };
    let ranks = (members.max(2) - 1) as u32;
    let room = delay.saturating_sub(spare_wait).saturating_sub(2) / ranks;
    configured.min(room).max(1)
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
    /// Our cancel left the mempool and `max_sends` are spent: alert, do nothing more.
    SendCap,
}

pub struct DecideCtx<'a> {
    pub height: u32,
    pub me: u16,
    pub rank: Option<u32>,
    pub drive: bool,
    pub takeover_blocks: u32,
    pub spares: u32,
    pub spare_wait_blocks: u32,
    pub refee_after_blocks: u32,
    pub max_sends: u32,
    /// This member's own co-signature may be carried (`auto_cosign`).
    pub own: bool,
    pub members: &'a BTreeMap<u16, [u8; 33]>,
    /// The claimant intent is spent in the mempool (a cancel or a release is pending).
    pub intent_spent_in_mempool: bool,
    /// Our sent cancel is in the node's mempool.
    pub our_tx_in_mempool: bool,
}

pub fn decide(c: &Claim, x: &DecideCtx) -> Decision {
    if c.is_closed() {
        return Decision::Idle("closed");
    }
    if c.orphaned {
        return Decision::Idle("the claim's block left the chain");
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
    let usable = c.usable(x.me, x.own, x.members);
    let n = usable.len() as u32;
    if c.verdict == Verdict::Unjudged && n < c.required {
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
            } else if c.sends >= x.max_sends {
                Decision::SendCap
            } else if x.height < c.next_rebuild {
                Decision::Idle("rebuild backoff")
            } else if n >= c.required {
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
            // a first send that failed counts as well (re-review N-1)
            if c.sends >= x.max_sends {
                return Decision::SendCap;
            }
            if x.height < c.next_rebuild {
                return Decision::Idle("rebuild backoff");
            }
            if n < c.required {
                return Decision::Idle("short of co-signatures");
            }
            let full = n >= c.required.saturating_add(x.spares) || n as usize >= cosig::CANCEL_COSIGN_MAX;
            let waited = c
                .enough_since
                .is_some_and(|h| x.height >= h.saturating_add(x.spare_wait_blocks));
            if full || waited {
                Decision::Build(usable.into_iter().map(|(s, _)| s).collect())
            } else {
                Decision::Idle("waiting for spare co-signatures")
            }
        }
    }
}

/// How a `yed_signcancelcosign` refusal is treated (review M-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignErr {
    /// The key signed no price for the height: one must be stated.
    PriceRequired,
    /// The key's price for the height says the vault was claimable: the claim is honest by this key's own record.
    Claimable(String),
    /// Will not change by retrying: a second price for one height (equivocation guard), a price out of range.
    Sticky(String),
    /// Anything else (a timeout, a locked wallet, the index behind the chain, a height not indexed, a claim not yet
    /// confirmed, a member not yet mature): retried at the next poll.
    Transient(String),
}

pub fn classify_sign_error(e: &RpcError) -> SignErr {
    match e {
        RpcError::Node { message, .. } if message.starts_with("price-required") => SignErr::PriceRequired,
        RpcError::Node { message, .. } if message.starts_with("cancel-statement-claimable") => {
            SignErr::Claimable(message.clone())
        }
        RpcError::Node { message, .. }
            if message.starts_with("equivocation-guard") || message.starts_with("attest-range") =>
        {
            SignErr::Sticky(message.clone())
        }
        other => SignErr::Transient(other.to_string()),
    }
}

// ------------------------------------------------------------------------------------------------------ view

/// The chain facts a frame is verified against (`gossip::Ctx` carries a copy).
#[derive(Clone, Debug, Default)]
pub struct MemberView {
    pub set_id: [u8; 32],
    pub theta_bps: u32,
    /// Current members: seq -> compressed key (the newest record of each key, current in the primitive's sense).
    pub members: BTreeMap<u16, [u8; 33]>,
}

// ------------------------------------------------------------------------------------------------------- agent

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A bound member's endpoint: (endpoint id, seq, address hints, relay).
pub type BoundPeer = ([u8; 32], u16, Vec<String>, Option<String>);

/// The `yed_listattestors` rows → the current members (status ELIGIBLE or DORMANT, bond unspent and unfrozen; the
/// newest record of each key). `current_keys`, when the node gave it (`set_getinfo`'s memberlist), is the primitive's
/// own IsCurrent (maturity included, review L-1); a key not in it is not current.
pub fn current_members(rows: &Value, current_keys: Option<&BTreeSet<[u8; 33]>>) -> BTreeMap<u16, [u8; 33]> {
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
        let mature = current_keys.is_none_or(|k| k.contains(&key));
        if (status == "ELIGIBLE" || status == "DORMANT") && !spent && !frozen && mature {
            current.insert(seq, key);
        }
    }
    current.retain(|seq, key| newest.get(key) == Some(seq));
    current
}

/// `set_getinfo`'s memberlist → the keys the primitive calls current at the next block.
pub fn current_keys(set: &Value) -> Option<BTreeSet<[u8; 33]>> {
    let list = set.get("memberlist")?.as_array()?;
    Some(
        list.iter()
            .filter(|m| m.get("current").and_then(Value::as_bool) == Some(true))
            .filter_map(|m| m.get("key").and_then(Value::as_str))
            .filter_map(|h| hex::decode(h).ok())
            .filter_map(|b| <[u8; 33]>::try_from(b.as_slice()).ok())
            .collect(),
    )
}

/// `cosigs[i]` in a `yed_buildcancel` refusal.
pub fn refused_index(message: &str) -> Option<usize> {
    let start = message.find("cosigs[")? + 7;
    let end = start + message[start..].find(']')?;
    message[start..end].parse().ok()
}

/// Every `cosigs[i] dropped: <identifier>` a `yed_buildcancel` names (its `warnings`, or the reasons appended to
/// `cancel-cosign-needed`), with the identifier.
pub fn dropped_entries(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("cosigs[") {
        let tail = &rest[i..];
        if let Some(idx) = refused_index(tail) {
            let after = tail[tail.find(']').map_or(0, |e| e + 1)..].trim_start();
            if let Some(reason) = after.strip_prefix("dropped") {
                let reason = reason.trim_start_matches([':', ' ']);
                let id: String = reason
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                    .collect();
                if !out.iter().any(|(j, _)| *j == idx) {
                    out.push((idx, id));
                }
            }
        }
        rest = &rest[i + 7..];
    }
    out
}

/// A dropped or refused entry that will never count for this claim (as opposed to one whose signer is not current
/// now and may be later: membership is checked against the live view instead).
pub fn permanent_refusal(identifier: &str) -> bool {
    !identifier.starts_with("cancel-cosign-not-member")
}

pub struct CancelAgent {
    pub cfg: CancelConfig,
    pub node: Node,
    pub seq: u16,
    pub state: State,
    pub path: PathBuf,
    pub view: MemberView,
    /// This seq's own member key (from yed_listattestors, whatever its status): the claim's bundle is verified with it.
    pub my_key: Option<[u8; 33]>,
    /// This seq's P2PKH address of the member key (`bondKeyAddress`): what `signmessage` signs the binding with.
    pub my_address: Option<String>,
    /// The network the node reports (yed_getinfo).
    pub network: String,
    /// The direct endpoint (id, address hints), set by attest; None while direct delivery is off.
    pub direct: Option<([u8; 32], Vec<String>, Option<String>)>,
    /// Binding announces received (the binding topic, the direct table exchange), checked at the next poll.
    /// Public-topic announces, by the seq they claim: a uniform reservoir of at most BINDING_PER_SEQ each (review
    /// B-2: an honest announce competes only with forgeries of its own seat).
    bindings_in: BTreeMap<u16, crate::gossip::Reservoir<Vec<u8>>>,
    /// Announces delivered over a member's own authenticated direct connection (only its own seat's binding is taken
    /// from it, review B-2), with that member's seq: checked first.
    bindings_member: Vec<(Vec<u8>, u16)>,
    /// The direct endpoint's key: it proves possession of the endpoint in this member's binding (review B-1).
    pub direct_key: Option<iroh::SecretKey>,
    /// Until this height the own binding is announced every poll (review N-A: a fresh binding spreads fast).
    own_fresh_until: Option<u32>,
    /// Announces to publish (the binding topic and every bound member).
    announces_out: Vec<Vec<u8>>,
    last_announce: Option<u32>,
    /// Binding candidates that reached signature recovery in the last poll (at most BINDING_RECOVERIES).
    pub recoveries_last_poll: usize,
    rng: crate::gossip::Rng,
    /// The node's CLAIM_DELAY (yed_getinfo), for the takeover bound.
    pub claim_delay: Option<u32>,
    peers: Vec<Node>,
    outbox: Vec<Vec<u8>>,
    /// Co-signatures set aside by a reorg reset, restored when the refHeight and its hash come back unchanged.
    priors: HashMap<String, Prior>,
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
            cfg,
            node,
            seq,
            state,
            path,
            view: MemberView::default(),
            my_key: None,
            my_address: None,
            network: String::new(),
            direct: None,
            bindings_in: BTreeMap::new(),
            bindings_member: Vec::new(),
            direct_key: None,
            own_fresh_until: None,
            announces_out: Vec::new(),
            last_announce: None,
            recoveries_last_poll: 0,
            rng: crate::gossip::Rng::from_clock(),
            claim_delay: None,
            peers,
            outbox: Vec::new(),
            priors: HashMap::new(),
            dirty: false,
        })
    }

    /// The default state file: beside the node's cookie when `rpc_cookie` is set (the node's own per-network data
    /// directory: one file per node and seq), else `~/.ycash/yellowback-cancel-<network>-<seq>.json`.
    pub fn default_path(node: &crate::config::NodeConfig, network: &str, seq: u16) -> PathBuf {
        if let Some(dir) = node
            .cookie
            .as_deref()
            .and_then(Path::parent)
            .filter(|d| !d.as_os_str().is_empty())
        {
            return dir.join(format!("yellowback-cancel-{seq}.json"));
        }
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
            run_alert_command(cmd, kind.to_string(), intent.to_string(), message);
        }
    }

    fn member(&self) -> bool {
        self.view.members.contains_key(&self.seq)
    }

    /// Refresh the set id, theta, CLAIM_DELAY and the current members. False when the node cannot say.
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
                    self.claim_delay = v
                        .get("params")
                        .and_then(|p| p.get("claimDelay"))
                        .or_else(|| v.get("upgrade").and_then(|u| u.get("claimDelay")))
                        .and_then(Value::as_u64)
                        .and_then(|t| u32::try_from(t).ok());
                    match (set, theta) {
                        (Some(s), Some(t)) if t > 0 => {
                            self.view.set_id = s;
                            self.view.theta_bps = t;
                            self.network = v.get("network").and_then(Value::as_str).unwrap_or("").to_string();
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
        let rows = match self.node.call("yed_listattestors", vec![]).await {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("cancel: yed_listattestors failed: {e}");
                return false;
            }
        };
        // the primitive's IsCurrent (maturity included) from the set's memberlist; without it, the records alone
        let set_hex = cosig::display_of_internal(&self.view.set_id);
        let keys = match self.node.call("set_getinfo", vec![json!(set_hex)]).await {
            Ok(v) => current_keys(&v),
            Err(e) => {
                tracing::debug!("cancel: set_getinfo: {e}; membership from yed_listattestors alone");
                None
            }
        };
        self.view.members = current_members(&rows, keys.as_ref());
        self.my_key = rows
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|r| r.get("seq").and_then(Value::as_u64) == Some(self.seq as u64))
            })
            .and_then(|r| r.get("attestorPubKey").and_then(Value::as_str))
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 33]>::try_from(b.as_slice()).ok());
        self.my_address = rows
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|r| r.get("seq").and_then(Value::as_u64) == Some(self.seq as u64))
            })
            .and_then(|r| r.get("bondKeyAddress").and_then(Value::as_str))
            .map(String::from);
        true
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

    async fn block_hash_at(&self, height: u32) -> Result<String, RpcError> {
        Ok(self
            .node
            .call("getblockhash", vec![json!(height)])
            .await?
            .as_str()
            .unwrap_or("")
            .to_string())
    }

    /// The claim's refHeight (its REDEEM payload), blockHash(refHeight), and this seq's attestation at the
    /// refHeight inside the claim's own bundle, if any. The claim is read from the block it confirmed in
    /// (`getrawtransaction txid 0 blockhash`), which needs no -txindex on either node line.
    async fn claim_ref(&self, intent: &str, confirm_height: u32) -> Result<(u32, String, Option<i64>), String> {
        let txid = intent.split(':').next().unwrap_or("");
        let in_block = self
            .block_hash_at(confirm_height)
            .await
            .map_err(|e| format!("getblockhash {confirm_height}: {e}"))?;
        let raw = self
            .node
            .call("getrawtransaction", vec![json!(txid), json!(0), json!(in_block)])
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
            .block_hash_at(r)
            .await
            .map_err(|e| format!("getblockhash {r}: {e}"))?;
        // this seq's attestation at R in the claim's bundle -- decoded only by the node, never verified (a bundle
        // carried before arming is not checked by consensus either), so it counts only if its signature verifies
        // under this seq's own key over AttestMessage(seq, price, R, blockHash(R)) (re-review N-2)
        let own = dec
            .get("bundle")
            .and_then(|b| b.get("attestations"))
            .and_then(Value::as_array)
            .map(|a| a.as_slice())
            .unwrap_or(&[])
            .iter()
            .filter(|x| {
                x.get("seq").and_then(Value::as_u64) == Some(self.seq as u64)
                    && x.get("citedHeight").and_then(Value::as_u64) == Some(r as u64)
            })
            .filter_map(|x| x.get("hex").and_then(Value::as_str))
            .filter_map(|h| crate::framing::Attestation::decode_hex(h).ok())
            .find(|att| match (self.my_key.as_ref(), cosig::internal_from_display(&bh)) {
                (Some(key), Some(bh_internal)) => {
                    let ok = att.seq == self.seq
                        && att.cited_height == r
                        && cosig::verify_attestation(key, att.seq, att.price_micro_usd, r, &bh_internal, &att.sig);
                    if !ok {
                        tracing::warn!(
                            "cancel: {intent}: the claim's bundle carries an attestation of seq {} at {r} that this key                              did not sign; ignored",
                            self.seq
                        );
                    }
                    ok
                }
                _ => false,
            })
            .map(|att| att.price_micro_usd as i64);
        Ok((r, bh, own))
    }

    /// This seq's attestation citing `r` in the node's pool (`yed_getattestations`), if it holds one.
    async fn pool_price(&self, r: u32) -> Option<i64> {
        let rows = self.node.call("yed_getattestations", vec![]).await.ok()?;
        rows.as_array()?
            .iter()
            .find(|x| {
                x.get("seq").and_then(Value::as_u64) == Some(self.seq as u64)
                    && x.get("citedHeight").and_then(Value::as_u64) == Some(r as u64)
            })
            .and_then(|x| x.get("priceMicroUsd").and_then(Value::as_i64))
    }

    /// `yed_signcancelcosign intent [price] seq` → (the stated price, the 69-byte co-signature hex).
    async fn sign(&self, intent: &str, price: Option<i64>) -> Result<(i64, String), SignErr> {
        let p = price.map(|p| json!(p)).unwrap_or(Value::Null);
        match self
            .node
            .call("yed_signcancelcosign", vec![json!(intent), p, json!(self.seq)])
            .await
        {
            Ok(v) => {
                let cosig = v.get("cosig").and_then(Value::as_str).unwrap_or("").to_string();
                let stated = v.get("priceMicroUsd").and_then(Value::as_i64).unwrap_or(0);
                if Entry::decode_hex(&cosig).is_none() {
                    return Err(SignErr::Transient(
                        "yed_signcancelcosign returned no 69-byte cosig".into(),
                    ));
                }
                Ok((stated, cosig))
            }
            Err(e) => Err(classify_sign_error(&e)),
        }
    }

    /// `getblockchaininfo`: out of initial block download and within two blocks of the best header.
    async fn node_synced(&self) -> bool {
        match self.node.call("getblockchaininfo", vec![]).await {
            Ok(v) => {
                let done = v.get("initial_block_download_complete").and_then(Value::as_bool) == Some(true);
                let blocks = v.get("blocks").and_then(Value::as_i64).unwrap_or(-1);
                let headers = v.get("headers").and_then(Value::as_i64).unwrap_or(i64::MAX);
                done && blocks >= 0 && headers - blocks <= 2
            }
            Err(e) => {
                tracing::warn!("cancel: getblockchaininfo: {e}");
                false
            }
        }
    }

    /// One poll at tip `height` (the caller has recorded this poll's aggregate and any attestation it signed;
    /// verified co-signatures arrive through [`CancelAgent::accept_verified`]).
    pub async fn tick(&mut self, height: u32) {
        // the record starts only on a node at the network's tip (re-review N-6): before that the agent has not seen
        // the heights it would vouch for, and states no new price at all
        if self.state.recording_since.is_none() && self.node_synced().await {
            self.state.recording_since = Some(height);
            self.dirty = true;
        }
        if !self.refresh_view().await {
            return;
        }
        // 0. the endpoint bindings (owner decision 1)
        self.bindings_step(height).await;
        // 1. the claims the index holds (reorgs included)
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
            self.watch(intent, height).await;
        }
        // 3. the on-chain fallback (owner decision 2): post when short, read what others posted
        if self.cfg.onchain_fallback {
            for intent in &intents {
                self.fallback(intent, height).await;
            }
        }
        // 4. drive
        for intent in &intents {
            self.collect(intent, height).await;
        }
        self.state.prune(height);
        self.dirty = true;
        self.save();
    }

    /// Reset a claim after a reorg and keep its co-signatures aside for [`CancelAgent::watch`] to restore when the
    /// refHeight and its hash come back unchanged.
    fn reorg_reset(&mut self, intent: &str, confirm: u32, release: u32, why: &str) {
        let Some(c) = self.state.claims.get_mut(intent) else {
            return;
        };
        let prior = c.reset(confirm, release);
        tracing::warn!("cancel: claim {intent}: {why}; judged again from the chain");
        self.priors.insert(intent.to_string(), prior);
        self.dirty = true;
    }

    /// Track new CLAIMING rows, refresh the open ones (a different confirmation is a reorg), reopen a closed one that
    /// is back (review H-1), and decide on the ones that left CLAIMING only from a confirmed spend of the intent.
    async fn follow(&mut self, height: u32, rows: Vec<(String, Value)>) {
        let mut live: BTreeSet<String> = BTreeSet::new();
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
            let Ok(hash) = self.block_hash_at(confirm).await else {
                continue; // the index is ahead of the chain RPC for a moment: next poll
            };
            match self.state.claims.get(&intent) {
                None => {
                    tracing::info!(
                        "cancel: following claim {intent} of vault {vault} (confirmed at {confirm}, releasable at {release})"
                    );
                    self.state
                        .claims
                        .insert(intent.clone(), Claim::new(vault.clone(), confirm, release));
                }
                Some(c) if c.is_closed() => {
                    self.reorg_reset(
                        &intent,
                        confirm,
                        release,
                        "back in CLAIMING after it was closed (a reorg)",
                    );
                    self.alert(
                        &intent,
                        "claim-reorged",
                        format!("the claim on vault {vault} is CLAIMING again at height {confirm}: reopened"),
                    );
                }
                Some(c) if c.confirm_height != confirm || c.confirm_hash.as_deref().is_some_and(|h| h != hash) => {
                    self.reorg_reset(&intent, confirm, release, "its confirming block changed (a reorg)");
                }
                Some(c) if c.orphaned => {
                    let c = self.state.claims.get_mut(&intent).expect("present");
                    c.orphaned = false;
                    tracing::warn!("cancel: claim {intent} is back in its block");
                }
                Some(_) => {}
            }
            let c = self.state.claims.get_mut(&intent).expect("present");
            if c.confirm_hash.is_none() {
                c.confirm_hash = Some(hash);
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
            let (vault, verdict, confirm, confirm_hash, release) = {
                let c = &self.state.claims[&intent];
                (
                    c.vault.clone(),
                    c.verdict,
                    c.confirm_height,
                    c.confirm_hash.clone(),
                    c.release_height,
                )
            };
            // is the claim still in the chain? a reorg that took its block away is not a cancel
            let in_chain = match (self.block_hash_at(confirm).await, &confirm_hash) {
                (Ok(h), Some(want)) => h == *want,
                (Err(RpcError::Node { .. }), Some(_)) => false, // the chain is now shorter than the claim's height
                _ => continue,
            };
            if !in_chain {
                let first = !self.state.claims[&intent].orphaned;
                if first {
                    let c = self.state.claims.get_mut(&intent).expect("present");
                    c.orphaned = true;
                    c.phase = Phase::Watching;
                    self.dirty = true;
                    self.alert(
                        &intent,
                        "claim-reorged",
                        format!(
                            "the block that confirmed the claim on vault {vault} (height {confirm}) left the chain: held, \
                             not closed; it is followed again if it is re-mined"
                        ),
                    );
                }
                if height >= release.saturating_add(CLOSED_KEEP) {
                    let c = self.state.claims.get_mut(&intent).expect("present");
                    c.phase = Phase::Closed {
                        outcome: "orphaned".into(),
                        height,
                    };
                }
                continue;
            }
            // in the chain and not CLAIMING: decide only from a spend of the intent in a confirmed block
            let Some((t, n)) = intent.split_once(':') else {
                continue;
            };
            let n: u64 = n.parse().unwrap_or(0);
            match self.node.call("gettxout", vec![json!(t), json!(n), json!(false)]).await {
                Ok(Value::Null) => {}
                Ok(_) => continue, // unspent in the chain: the index lags; next poll
                Err(e) => {
                    tracing::warn!("cancel: gettxout {intent}: {e}; retried next poll");
                    continue;
                }
            }
            let vtxid = vault.split(':').next().unwrap_or("").to_string();
            let outcome = match self.node.call("yed_getvault", vec![json!(vtxid)]).await {
                Ok(v) if v.get("status").and_then(Value::as_str) == Some("CLAIMED") => "released",
                Ok(v) if v.get("status").and_then(Value::as_str) == Some("CLAIMING") => continue,
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
    async fn watch(&mut self, intent: &str, height: u32) {
        let Some(c) = self.state.claims.get(intent) else {
            return;
        };
        if c.is_closed() || c.orphaned {
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
        // review H-2: a reorg across the refHeight changes blockHash(R), which every co-signature signs
        if let (Some(r), Some(bh)) = (c.ref_height, c.block_hash.clone()) {
            match self.block_hash_at(r).await {
                Ok(h) if h == bh => {}
                Ok(_) => {
                    let (confirm, release) = (c.confirm_height, c.release_height);
                    self.reorg_reset(
                        intent,
                        confirm,
                        release,
                        "blockHash(refHeight) changed (a reorg across it)",
                    );
                    self.priors.remove(intent); // the old co-signatures sign the old hash: never restored
                }
                Err(e) => {
                    tracing::warn!("cancel: getblockhash {r}: {e}; retried next poll");
                    return;
                }
            }
        }
        let c = &self.state.claims[intent];
        if c.ref_height.is_none() {
            match self.claim_ref(intent, c.confirm_height).await {
                Ok((r, bh, own)) => {
                    let prior = self.priors.remove(intent);
                    let c = self.state.claims.get_mut(intent).expect("present");
                    c.ref_height = Some(r);
                    c.block_hash = Some(bh.clone());
                    c.bundle_price = own;
                    // the same refHeight and hash: the co-signatures sign the same message and are still valid
                    if let Some(p) = prior.filter(|p| p.ref_height == Some(r) && p.block_hash.as_deref() == Some(&bh)) {
                        c.cosigs = p.cosigs;
                        c.own_cosig = p.own_cosig;
                    }
                    self.dirty = true;
                }
                Err(e) => {
                    tracing::warn!("cancel: {intent}: {e}; retried next poll");
                    return;
                }
            }
        }
        if matches!(self.state.claims[intent].verdict, Verdict::Pending | Verdict::Unjudged)
            && !self.judge_claim(intent).await
        {
            return;
        }
        let c = &self.state.claims[intent];
        if c.verdict != Verdict::Wrong || !self.cfg.auto_cosign || !self.member() {
            return;
        }
        if c.own_cosig.is_none() && c.cosign_blocked.is_none() {
            self.cosign(intent).await;
        }
        let c = &self.state.claims[intent];
        let r = c.ref_height.expect("set above");
        if let Some(own) = c.own_cosig.clone() {
            // every block while the claim is short of cancelsRequired (re-review N-3c: under a flood each copy is
            // drawn for verification with probability budget/offered), else every republish_blocks
            let members = self.view.members.clone();
            let short = (c.usable(self.seq, true, &members).len() as u32) < c.required;
            let every = if short { 1 } else { self.cfg.republish_blocks };
            let due = c.last_publish.is_none_or(|h| height >= h.saturating_add(every));
            if due {
                if let (Some(entry), Some((txid, n))) = (Entry::decode_hex(&own), cosig::parse_intent(intent)) {
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

    /// The price this key is on record for at `r`: what the state says it signed, the claim's own bundle, the
    /// node's pool. A record is what a statement must repeat (EQV-1 slashes two prices at one height).
    async fn recorded_price(&self, intent: &str, r: u32) -> Option<i64> {
        if let Some(p) = self.state.signed.get(&r) {
            return Some(*p);
        }
        if let Some(p) = self.state.claims.get(intent).and_then(|c| c.bundle_price) {
            return Some(p);
        }
        self.pool_price(r).await
    }

    /// The verdict. Returns false when it cannot be reached this poll (a transient node error).
    async fn judge_claim(&mut self, intent: &str) -> bool {
        let c = &self.state.claims[intent];
        let r = c.ref_height.expect("set");
        let (vault, coll, debt) = (c.vault.clone(), c.collateral_zat, c.minted_cents);
        let mut price = match self.recorded_price(intent, r).await {
            Some(p) => Some(p),
            None => honest_price(&self.state, r, self.cfg.price_tolerance_blocks),
        };
        let mut honest_by_record = false;
        // review L-2: with no price of its own, ask the node's guard (the price this key signed there) first
        // (never with auto_cosign = false: a null-price signing is a co-signature too, re-review N-5)
        if price.is_none() && self.member() && self.cfg.auto_cosign {
            match self.sign(intent, None).await {
                Ok((p, cosig)) => {
                    price = Some(p);
                    if cosig::is_wrong_price(coll, p, debt, self.view.theta_bps, self.cfg.margin_bps) {
                        let c = self.state.claims.get_mut(intent).expect("present");
                        c.own_cosig = Some(cosig.clone());
                        c.cosigs.insert(self.seq, cosig);
                    }
                }
                Err(SignErr::Claimable(_)) => honest_by_record = true,
                Err(SignErr::PriceRequired) => {}
                Err(SignErr::Sticky(m)) => {
                    self.state.claims.get_mut(intent).expect("present").cosign_blocked = Some(m);
                }
                Err(SignErr::Transient(m)) => {
                    tracing::warn!("cancel: {intent}: yed_signcancelcosign: {m}; judged next poll");
                    return false;
                }
            }
        }
        let verdict = if honest_by_record {
            Verdict::Honest
        } else {
            judge(coll, debt, self.view.theta_bps, self.cfg.margin_bps, price)
        };
        {
            let c = self.state.claims.get_mut(intent).expect("present");
            c.verdict = verdict;
            c.judged_price = price;
        }
        self.dirty = true;
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
                    "no price of this agent's at refHeight {r} (none signed, none in the bundle, pool or guard, no \
                     aggregate within {} blocks before it): not co-signed",
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
                        "cancel: claim {intent} on vault {vault} is claimable at this agent's price {}: honest, left alone",
                        price.map_or("(its own signed statement)".to_string(), |p| format!("{p} µUSD"))
                    );
                }
            }
            Verdict::Pending => {}
        }
        true
    }

    fn block_cosign(&mut self, intent: &str, kind: &str, why: String) {
        if let Some(c) = self.state.claims.get_mut(intent) {
            c.cosign_blocked = Some(why.clone());
        }
        self.dirty = true;
        self.alert(intent, kind, why);
    }

    /// `yed_signcancelcosign`: the node's guard first (the price this key signed for refHeight). When it signed none
    /// there, the price on record (state, bundle, pool), else the aggregate -- but a new price is stated only for a
    /// refHeight above `recording_since`, where the state proves this agent did not attest (review M-2). Sticky
    /// refusals block the claim; transient ones are retried (review M-1).
    async fn cosign(&mut self, intent: &str) {
        let c = &self.state.claims[intent];
        let r = c.ref_height.expect("set");
        let (coll, debt, judged) = (c.collateral_zat, c.minted_cents, c.judged_price);
        let first = match self.sign(intent, None).await {
            Ok(v) => Ok(v),
            Err(SignErr::PriceRequired) => {
                let recorded = self.recorded_price(intent, r).await;
                let covered = self.state.recording_since.is_some_and(|s| r > s);
                let statement = match recorded {
                    Some(p) => Some(p),
                    None if covered => judged,
                    None => None,
                };
                let Some(p) = statement else {
                    self.block_cosign(
                        intent,
                        "no-record",
                        format!(
                            "the node's guard holds no price of this key at refHeight {r}, and this agent's record starts \
                             at {:?}: stating one could contradict an attestation it cannot see (EQV-1); not co-signed",
                            self.state.recording_since
                        ),
                    );
                    return;
                };
                self.sign(intent, Some(p)).await
            }
            Err(e) => Err(e),
        };
        match first {
            Ok((price, cosig)) => {
                if !cosig::is_wrong_price(coll, price, debt, self.view.theta_bps, self.cfg.margin_bps) {
                    self.block_cosign(
                        intent,
                        "cosign-within-margin",
                        format!(
                            "this key's statement at the claim's refHeight is {price} µUSD, inside the {} bps margin: not published",
                            self.cfg.margin_bps
                        ),
                    );
                    return;
                }
                tracing::info!("cancel: co-signed {intent} as seq {} at {price} µUSD", self.seq);
                let c = self.state.claims.get_mut(intent).expect("present");
                c.own_cosig = Some(cosig.clone());
                c.cosigs.insert(self.seq, cosig);
                c.last_publish = None;
                self.dirty = true;
            }
            Err(SignErr::Claimable(m)) => {
                // this key's own record at the height says the vault was claimable: honest by its own statement
                if let Some(c) = self.state.claims.get_mut(intent) {
                    c.verdict = Verdict::Honest;
                }
                self.block_cosign(
                    intent,
                    "cosign-refused",
                    format!("this key's price at the claim's refHeight says the vault was claimable: {m}"),
                );
            }
            Err(SignErr::Sticky(m)) => self.block_cosign(intent, "cosign-refused", m),
            Err(SignErr::PriceRequired) => {
                tracing::warn!("cancel: {intent}: the node still asks for a price; retried next poll")
            }
            Err(SignErr::Transient(m)) => {
                tracing::warn!("cancel: yed_signcancelcosign {intent}: {m}; retried next poll")
            }
        }
    }

    /// A binding announce from the public binding topic, checked at a later poll. It goes to the reservoir of the
    /// seq it claims (a current member's seq only; parsing costs no signature), so a flood of forgeries for one seat
    /// dilutes only that seat's candidates, and a flood spread over every seat leaves each its own BINDING_PER_SEQ
    /// uniform sample (review B-2; never the head of a queue, M5-1).
    pub fn take_binding(&mut self, blob: Vec<u8>) {
        let Some(seq) = crate::binding::Announce::decode(&blob)
            .and_then(|a| crate::binding::Statement::parse(&a.binding.message))
            .map(|st| st.seq)
        else {
            return;
        };
        if !self.view.members.is_empty() && !self.view.members.contains_key(&seq) {
            return;
        }
        if !self.bindings_in.contains_key(&seq) && self.bindings_in.len() >= 64 {
            return; // before the view is known: at most 64 seats queue
        }
        self.bindings_in
            .entry(seq)
            .or_insert_with(|| crate::gossip::Reservoir::new(BINDING_PER_SEQ))
            .offer(blob, &mut self.rng);
    }

    /// A binding announce delivered by member `from` over its own authenticated direct connection. Only an announce
    /// of `from`'s own seat is taken (a member cannot relay -- or forge -- other seats' bindings this way, review
    /// B-2); it is checked first, and its hints are authenticated (review B-3).
    pub fn take_member_binding(&mut self, blob: Vec<u8>, from: u16) {
        let own_seat = crate::binding::Announce::decode(&blob)
            .and_then(|a| crate::binding::Statement::parse(&a.binding.message))
            .is_some_and(|st| st.seq == from);
        if !own_seat {
            tracing::debug!("cancel direct: member {from} sent a binding announce for another seat; dropped");
            return;
        }
        let mine = self.bindings_member.iter().filter(|(_, f)| *f == from).count();
        if mine < BINDING_PER_MEMBER {
            self.bindings_member.push((blob, from));
        } else {
            let j = self.rng.below(BINDING_PER_MEMBER as u64) as usize;
            if let Some(k) = self
                .bindings_member
                .iter()
                .enumerate()
                .filter(|(_, (_, f))| *f == from)
                .nth(j)
                .map(|(k, _)| k)
            {
                self.bindings_member[k] = (blob, from);
            }
        }
    }

    /// An alert that is not about one claim (kind and key deduplicated).
    fn alert_global(&mut self, kind: &str, key: &str, message: String) {
        if !self.state.alerted_global.insert(format!("{kind}|{key}")) {
            return;
        }
        self.dirty = true;
        tracing::error!("ALERT {kind} {key}: {message}");
        if let Some(cmd) = self.cfg.alert_command.clone() {
            run_alert_command(cmd, kind.to_string(), key.to_string(), message);
        }
    }

    /// Announces to publish (on the binding topic and to every bound member).
    pub fn take_announces(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.announces_out)
    }

    /// What a self-introduction at height `tip` is verified against (review N-A): this agent's network, set, TTL and
    /// current members.
    pub fn intro_ctx(&self, tip: u32) -> crate::direct::IntroCtx {
        crate::direct::IntroCtx {
            network: self.network.clone(),
            set_hex: cosig::display_of_internal(&self.view.set_id),
            tip,
            ttl: self.cfg.binding_ttl_blocks,
            members: self.view.members.clone(),
        }
    }

    /// This member's own announce, if it holds one: sent first on every new direct connection (self-introduction).
    pub fn own_announce(&self) -> Option<Vec<u8>> {
        self.member()
            .then(|| self.state.own_binding.as_ref().map(|a| a.encode()))
            .flatten()
    }

    /// The bound members' endpoints: (endpoint id, seq, address hints, relay).
    pub fn bound_peers(&self) -> Vec<BoundPeer> {
        self.state
            .bindings
            .endpoints()
            .into_iter()
            .map(|(ep, (seq, a))| (ep, seq, a.addrs, a.relay))
            .collect()
    }

    /// Sign this member's binding when it has none for its current direct endpoint or it is past half its life,
    /// announce it every 10 blocks (or when its hints change), check queued announces (member connections first, then
    /// the public topic's per-seat samples, at most BINDING_RECOVERIES signature checks a poll), resolve endpoint
    /// conflicts (review B-1), and drop the bindings of seqs that left.
    async fn bindings_step(&mut self, height: u32) {
        let set_hex = cosig::display_of_internal(&self.view.set_id);
        let ttl = self.cfg.binding_ttl_blocks;
        if let (Some((ep, addrs, relay)), Some(key), true) =
            (self.direct.clone(), self.direct_key.clone(), self.member())
        {
            let current = self.state.own_binding.as_ref().and_then(|a| {
                crate::binding::Statement::parse(&a.binding.message)
                    .filter(|st| st.endpoint == ep && st.seq == self.seq && st.set_id_hex == set_hex)
                    .filter(|st| height < st.issued.saturating_add(ttl / 2))
            });
            if current.is_none() {
                self.sign_binding(height, ep, &key, addrs.clone(), relay.clone(), &set_hex)
                    .await;
            }
            if let Some(own) = self.state.own_binding.clone() {
                // new addresses: re-sign the proof locally (review N-B; no node call), a higher hint_seq
                if own.addrs != addrs || own.relay != relay {
                    let next = own.hint_seq.saturating_add(1).max(unix_seconds());
                    self.state.own_binding = Some(own.with_hints(&key, addrs, relay, next));
                    self.last_announce = None;
                    self.dirty = true;
                }
                // every poll while the binding is fresh (review N-A), then every 10 blocks
                let fresh = self.own_fresh_until.is_some_and(|h| height < h);
                let due = fresh || self.last_announce.is_none_or(|h| height >= h.saturating_add(10));
                if due {
                    let blob = self.state.own_binding.as_ref().expect("set").encode();
                    self.announces_out.push(blob.clone());
                    self.last_announce = Some(height);
                    self.bindings_member.push((blob, self.seq)); // our own entry, verified like any other
                }
            }
        }
        let members = self.view.members.clone();
        // candidates: member connections first (their own seat only), then per seat a uniform sample of the
        // topic's announces, the seats in urgency order (no binding, or one expiring within a quarter of the TTL),
        // round robin across seats; deduplicated by the announce's digest (review N-C) before any signature check
        let mut cands: Vec<crate::binding::Announce> = Vec::new();
        for (blob, _) in std::mem::take(&mut self.bindings_member) {
            if let Some(a) = crate::binding::Announce::decode(&blob) {
                cands.push(a);
            }
        }
        let soon = height.saturating_add(ttl / 4);
        let mut seats: Vec<(u16, Vec<Vec<u8>>)> = std::mem::take(&mut self.bindings_in)
            .into_iter()
            .map(|(seq, mut r)| (seq, r.take().0))
            .collect();
        let urgency = |seq: &u16| match self.state.bindings.by_seq.get(seq) {
            None => 0,
            Some(h) if h.statement.expiry <= soon => 0,
            Some(_) => 1,
        };
        seats.sort_by_key(|(seq, _)| urgency(seq));
        let rounds = seats.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
        for k in 0..rounds {
            for (_, blobs) in &seats {
                if let Some(a) = blobs.get(k).and_then(|b| crate::binding::Announce::decode(b)) {
                    cands.push(a);
                }
            }
        }
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut staged: Vec<(crate::binding::Statement, crate::binding::Announce)> = Vec::new();
        let mut checked = 0;
        for a in cands {
            let Ok(st) = a.binding.precheck(&self.network, &set_hex, height, ttl, &members) else {
                continue;
            };
            if !self.state.bindings.newer_or_same(&st) {
                continue;
            }
            let same = self.state.bindings.holds(&a, st.seq);
            if same && !self.state.bindings.newer_hints(st.seq, &a) {
                continue; // the very binding and hints held
            }
            if !seen.insert(a.digest()) {
                continue;
            }
            if checked >= BINDING_RECOVERIES {
                continue;
            }
            checked += 1;
            if same {
                // the binding held, newer hints: only the endpoint's proof needs checking
                if a.possession_ok(&st) && self.state.bindings.refresh_hints(st.seq, &a) {
                    self.dirty = true;
                }
                continue;
            }
            match a.binding.verify(&self.network, &set_hex, height, ttl, &members) {
                Ok(st) if a.possession_ok(&st) => staged.push((st, a)),
                Ok(_) => tracing::debug!(
                    "cancel direct: binding of seq {} refused: {:?}",
                    st.seq,
                    crate::binding::Refusal::BadPossession
                ),
                Err(r) => tracing::debug!("cancel direct: binding refused: {r:?}"),
            }
        }
        self.recoveries_last_poll = checked;
        // per seat keep the latest (then the newest hints); an endpoint id claimed by two seats in this poll is
        // dropped for both (review B-1)
        let mut best: BTreeMap<u16, (crate::binding::Statement, crate::binding::Announce)> = BTreeMap::new();
        for (st, a) in staged {
            let replace = best
                .get(&st.seq)
                .is_none_or(|(b, ba)| st.issued > b.issued || (st.issued == b.issued && a.hint_seq > ba.hint_seq));
            if replace {
                best.insert(st.seq, (st, a));
            }
        }
        let mut by_endpoint: BTreeMap<[u8; 32], Vec<u16>> = BTreeMap::new();
        for (seq, (st, _)) in &best {
            by_endpoint.entry(st.endpoint).or_default().push(*seq);
        }
        for (ep, seqs) in by_endpoint.iter().filter(|(_, v)| v.len() > 1) {
            for s in seqs {
                best.remove(s);
            }
            self.alert_global(
                "binding-conflict",
                &hex::encode(ep),
                format!(
                    "seats {seqs:?} bound the same endpoint id {} in one poll: both refused",
                    hex::encode(ep)
                ),
            );
        }
        for (_, (st, a)) in best {
            let (seq, ep) = (st.seq, st.endpoint);
            let was = self.state.bindings.by_seq.get(&seq).map(|h| h.statement.endpoint);
            match self.state.bindings.commit(st, a) {
                Ok(true) => {
                    self.dirty = true;
                    // a member at a new endpoint: announce ours at the next poll, which also dials it directly
                    // with our self-introduction -- it learns our binding at once, whatever the topic carries
                    if seq != self.seq && was != Some(ep) {
                        self.last_announce = None;
                    }
                }
                Ok(false) => {}
                Err(crate::binding::Refusal::EndpointConflict(other)) => self.alert_global(
                    "binding-conflict",
                    &format!("{seq}-{}", hex::encode(ep)),
                    format!(
                        "seat {seq} bound endpoint id {}, already bound to seat {other}: refused, seat {other}'s kept",
                        hex::encode(ep)
                    ),
                ),
                Err(r) => tracing::debug!("cancel direct: binding of seq {seq} refused: {r:?}"),
            }
        }
        self.state.bindings.prune(height, &members);
    }

    /// `signmessage` with this seq's member key (its P2PKH address, checked to be the member key's own with
    /// `validateaddress`), then the endpoint key's proof of possession.
    async fn sign_binding(
        &mut self,
        height: u32,
        ep: [u8; 32],
        key: &iroh::SecretKey,
        addrs: Vec<String>,
        relay: Option<String>,
        set_hex: &str,
    ) {
        let (Some(addr), Some(member_key)) = (self.my_address.clone(), self.my_key) else {
            return;
        };
        match self.node.call("validateaddress", vec![json!(addr)]).await {
            Ok(v) if v.get("pubkey").and_then(Value::as_str) == Some(hex::encode(member_key).as_str()) => {}
            Ok(_) => {
                tracing::error!(
                    "cancel direct: {addr} is not the member key's own address in this wallet; no binding signed"
                );
                return;
            }
            Err(e) => {
                tracing::warn!("cancel direct: validateaddress: {e}; retried next poll");
                return;
            }
        }
        let st = crate::binding::Statement {
            network: self.network.clone(),
            set_id_hex: set_hex.to_string(),
            seq: self.seq,
            endpoint: ep,
            issued: height,
            expiry: height.saturating_add(self.cfg.binding_ttl_blocks),
        };
        let msg = st.message();
        match self.node.call("signmessage", vec![json!(addr), json!(msg)]).await {
            Ok(v) => match v
                .as_str()
                .and_then(|b| crate::binding::Binding::from_signmessage(msg, b))
            {
                Some(b) => {
                    tracing::info!(
                        "cancel direct: signed the binding of endpoint {} to seq {}",
                        hex::encode(ep),
                        self.seq
                    );
                    self.state.own_binding = Some(crate::binding::Announce::new(b, key, addrs, relay, unix_seconds()));
                    self.own_fresh_until = Some(height.saturating_add(FRESH_ANNOUNCE_BLOCKS));
                    self.last_announce = None;
                    self.dirty = true;
                }
                None => tracing::error!("cancel direct: signmessage returned no 65-byte signature"),
            },
            Err(e) => tracing::warn!("cancel direct: signmessage for the binding: {e}; retried next poll"),
        }
    }

    /// The on-chain fallback for one claim: post this member's co-signature when the claim is still short
    /// `fallback_after_blocks` after it confirmed, and read the records others posted.
    async fn fallback(&mut self, intent: &str, height: u32) {
        let Some(c) = self.state.claims.get(intent) else {
            return;
        };
        if c.is_closed() || c.orphaned || height >= c.release_height {
            return;
        }
        let (Some(r), Some(bh)) = (
            c.ref_height,
            c.block_hash.as_deref().and_then(cosig::internal_from_display),
        ) else {
            return;
        };
        let members = self.view.members.clone();
        let short = (c.usable(self.seq, self.cfg.auto_cosign, &members).len() as u32) < c.required;
        if !short || height < c.confirm_height.saturating_add(self.cfg.fallback_after_blocks) {
            return;
        }
        let Some((txid, n)) = cosig::parse_intent(intent) else {
            return;
        };
        // read: the blocks since the claim confirmed (at most 20 a poll)
        let from = c.scanned_to.map_or(c.confirm_height, |s| s + 1);
        let id = crate::onchain::short_id(&txid, n);
        let mut scanned = c.scanned_to;
        for h in from..=height.min(from.saturating_add(19)) {
            let Ok(hash) = self.block_hash_at(h).await else {
                break;
            };
            let Ok(block) = self.node.call("getblock", vec![json!(hash), json!(2)]).await else {
                break;
            };
            for e in crate::onchain::records_in_block(&block, &id) {
                let Some(key) = crate::onchain::signer(&self.view.set_id, &txid, n, r, &bh, &e) else {
                    continue;
                };
                let Some(seq) = members.iter().find(|(_, k)| **k == key).map(|(s, _)| *s) else {
                    continue;
                };
                if seq == self.seq && !self.cfg.auto_cosign {
                    continue;
                }
                if (e.price as i64) < 100 {
                    continue;
                }
                let c = self.state.claims.get_mut(intent).expect("present");
                if cosig::is_underwater(c.collateral_zat, e.price as i64, c.minted_cents, self.view.theta_bps) {
                    continue;
                }
                if let std::collections::btree_map::Entry::Vacant(v) = c.cosigs.entry(seq) {
                    tracing::info!("cancel: co-signature of seq {seq} for {intent} read from the chain (block {h})");
                    v.insert(e.to_hex());
                    self.dirty = true;
                }
            }
            scanned = Some(h);
        }
        if let Some(c) = self.state.claims.get_mut(intent) {
            c.scanned_to = scanned;
        }
        // post: this member's own co-signature, once per claim, within the daily cap
        let c = &self.state.claims[intent];
        if !self.cfg.auto_cosign || c.verdict != Verdict::Wrong || c.onchain_posted.is_some() {
            return;
        }
        let Some(own) = c.own_cosig.as_deref().and_then(Entry::decode_hex) else {
            return;
        };
        self.state.fallback_posts.retain(|p| height < p.saturating_add(1_152));
        if self.state.fallback_posts.len() as u32 >= self.cfg.fallback_max_txs {
            self.alert(
                intent,
                "onchain-fallback-cap",
                format!(
                    "{} fallback transactions in the last day: no more (fallback_max_txs)",
                    self.cfg.fallback_max_txs
                ),
            );
            return;
        }
        let v = c.vault.clone();
        let (have, need) = (c.usable(self.seq, self.cfg.auto_cosign, &members).len(), c.required);
        match self.post_onchain(&txid, n, &own).await {
            Ok(tx) => {
                self.alert(
                    intent,
                    "onchain-fallback",
                    format!(
                        "the claim on vault {v} had {have} of {need} co-signatures {} blocks after it confirmed: this                          member's co-signature was published on chain in {tx} (fee {} zat)",
                        self.cfg.fallback_after_blocks, self.cfg.fallback_fee_zat
                    ),
                );
                let c = self.state.claims.get_mut(intent).expect("present");
                c.onchain_posted = Some(tx);
                self.state.fallback_posts.push(height);
                self.dirty = true;
            }
            Err(e) => tracing::warn!("cancel: on-chain fallback for {intent}: {e:#}; retried next poll"),
        }
    }

    /// One standard transaction carrying the record: a random fundable coin, change back to its address, the data
    /// output inserted, signed, sent. The fee is exactly `fallback_fee_zat`.
    async fn post_onchain(&mut self, txid: &[u8; 32], n: u32, e: &Entry) -> anyhow::Result<String> {
        let fee = self.cfg.fallback_fee_zat;
        // the YED index's token outpoints of this wallet are never spent here (review L-1); without the list, no post
        let toks = self.node.call("yed_listunspent", vec![]).await?;
        let tokens: std::collections::HashSet<(String, u64)> = toks
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(|t| Some((t.get("txid")?.as_str()?.to_string(), t.get("vout")?.as_u64()?)))
            .collect();
        let rows = self.node.call("listunspent", vec![json!(1)]).await?;
        let coins: Vec<_> = rows
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(|r| crate::onchain::fundable_coin(r, fee + 2_000, &tokens))
            .collect();
        anyhow::ensure!(
            !coins.is_empty(),
            "no confirmed P2PKH coin above {} zat in the wallet",
            fee + 2_000
        );
        let (ctxid, vout, addr, zat) = coins[self.rng.below(coins.len() as u64) as usize].clone();
        let change = zat - fee;
        let raw = self
            .node
            .call(
                "createrawtransaction",
                vec![
                    json!([{"txid": ctxid, "vout": vout}]),
                    json!({ addr: change as f64 / 1e8 }),
                ],
            )
            .await?;
        let bytes =
            hex::decode(raw.as_str().unwrap_or("")).map_err(|e| anyhow::anyhow!("createrawtransaction hex: {e}"))?;
        let with = crate::onchain::insert_output(&bytes, 0, &crate::onchain::script(txid, n, e))
            .ok_or_else(|| anyhow::anyhow!("createrawtransaction returned a shape the fallback cannot extend"))?;
        let signed = self
            .node
            .call("signrawtransaction", vec![json!(hex::encode(with))])
            .await?;
        anyhow::ensure!(
            signed.get("complete").and_then(Value::as_bool) == Some(true),
            "signrawtransaction did not complete: {signed}"
        );
        let sent = self
            .node
            .call(
                "sendrawtransaction",
                vec![json!(signed.get("hex").and_then(Value::as_str).unwrap_or(""))],
            )
            .await?;
        Ok(sent.as_str().unwrap_or("").to_string())
    }

    /// The verifier's view (`gossip::Ctx`): the members, and every open claim with its refHeight, hash, numbers and
    /// the seqs whose entry is already held. Published after every poll.
    pub fn gossip_ctx(&self) -> crate::gossip::Ctx {
        let claims = self
            .state
            .claims
            .iter()
            .filter(|(_, c)| !c.is_closed() && !c.orphaned)
            .filter_map(|(k, c)| {
                let r = c.ref_height?;
                let bh = cosig::internal_from_display(c.block_hash.as_deref()?)?;
                Some((
                    k.clone(),
                    crate::gossip::ClaimCtx {
                        ref_height: r,
                        block_hash: bh,
                        collateral_zat: c.collateral_zat,
                        minted_cents: c.minted_cents,
                        held: c.cosigs.keys().filter(|s| !c.rejected.contains(s)).copied().collect(),
                    },
                ))
            })
            .collect();
        crate::gossip::Ctx {
            view: self.view.clone(),
            claims,
        }
    }

    /// A co-signature the verifier task checked: kept when the claim still has the refHeight and hash it was
    /// verified against (a reorg in between makes it worthless) and holds no other entry of that seq.
    pub fn accept_verified(&mut self, v: crate::gossip::Verified) {
        let own = self.cfg.auto_cosign;
        let Some(c) = self.state.claims.get_mut(&v.intent) else {
            return;
        };
        let same = c.ref_height == Some(v.ref_height)
            && c.block_hash.as_deref().and_then(cosig::internal_from_display) == Some(v.block_hash);
        if !same || c.is_closed() || (v.seq == self.seq && !own) {
            return;
        }
        if let Some(old) = c.cosigs.get(&v.seq) {
            if *old != v.entry_hex && !c.rejected.contains(&v.seq) {
                tracing::warn!(
                    "cancel: seq {} sent a second, different co-signature for {}; keeping the first",
                    v.seq,
                    v.intent
                );
            }
            return;
        }
        tracing::info!("cancel: co-signature of seq {} for {} verified", v.seq, v.intent);
        c.cosigs.insert(v.seq, v.entry_hex);
        self.dirty = true;
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

    async fn collect(&mut self, intent: &str, height: u32) {
        let Some(c) = self.state.claims.get(intent) else {
            return;
        };
        if c.is_closed() || c.orphaned || matches!(c.verdict, Verdict::Pending | Verdict::Honest) {
            return;
        }
        let members = self.view.members.clone();
        let n = c.usable(self.seq, self.cfg.auto_cosign, &members).len() as u32;
        if n < c.required {
            if c.enough_since.is_some() {
                self.state.claims.get_mut(intent).expect("present").enough_since = None;
            }
        } else if c.enough_since.is_none() {
            self.state.claims.get_mut(intent).expect("present").enough_since = Some(height);
            self.dirty = true;
        }
        let c = &self.state.claims[intent];
        let seqs: Vec<u16> = members.keys().copied().collect();
        let r = cosig::parse_intent(intent).and_then(|(t, n)| rank(&seqs, self.seq, &t, n));
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
        // review L-3: a spend that is not ours and does not confirm is pinning the intent
        let foreign = spent && !our_tx_in_mempool;
        {
            let c = self.state.claims.get_mut(intent).expect("present");
            c.foreign_spend_since = if foreign {
                Some(c.foreign_spend_since.unwrap_or(height))
            } else {
                None
            };
        }
        let c = &self.state.claims[intent];
        if let Some(since) = c.foreign_spend_since {
            if height >= since.saturating_add(self.cfg.refee_after_blocks) {
                let v = c.vault.clone();
                self.alert(
                    intent,
                    "foreign-spend",
                    format!(
                        "a transaction that is not this agent's has spent the claim on vault {v} in the mempool since \
                         height {since} without confirming (a pinned cancel variant, or a release): send a cancel \
                         directly to miners"
                    ),
                );
            }
        }
        let c = &self.state.claims[intent];
        let takeover = effective_takeover(
            self.cfg.takeover_blocks,
            self.claim_delay,
            self.cfg.spare_wait_blocks,
            members.len(),
        );
        let x = DecideCtx {
            height,
            me: self.seq,
            rank: r,
            drive: self.cfg.drive,
            takeover_blocks: takeover,
            spares: self.cfg.spares,
            spare_wait_blocks: self.cfg.spare_wait_blocks,
            refee_after_blocks: self.cfg.refee_after_blocks,
            max_sends: self.cfg.max_sends,
            own: self.cfg.auto_cosign,
            members: &members,
            intent_spent_in_mempool: spent,
            our_tx_in_mempool,
        };
        match decide(c, &x) {
            Decision::Idle(why) => tracing::debug!("cancel: {intent}: {why}"),
            Decision::Build(seqs) => {
                tracing::info!(
                    "cancel: driving the cancel of {intent} (rank {}, {} co-signature(s), {} required)",
                    r.unwrap_or(0),
                    seqs.len(),
                    c.required
                );
                self.count_attempt(intent, height);
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
                        "cancel: {txid} for {intent} left the mempool unconfirmed; re-funding and rebuilding (send {} of {})",
                        c.sends + 1,
                        self.cfg.max_sends
                    );
                    // vault_refee replaces the fee inputs of the cancel this agent sent last (and drops its carrier);
                    // yed_buildcancel then re-attaches a carrier with the co-signatures valid now (the build memo
                    // follows the re-funded transaction)
                    // the attempt counts before anything is tried: a failure counts towards the cap and the backoff too
                    // (re-review N-1)
                    self.count_attempt(intent, height);
                    if let Err(e) = self.node.call("vault_refee", vec![json!(hex)]).await {
                        tracing::warn!("cancel: vault_refee: {e}; rebuilding without it");
                    }
                    self.build_and_send(intent, height, Some(txid)).await;
                }
            }
            Decision::SendCap => {
                let v = c.vault.clone();
                let sends = c.sends;
                self.alert(
                    intent,
                    "cancel-send-cap",
                    format!(
                        "the cancel of the claim on vault {v} left the mempool unconfirmed {sends} time(s); no more \
                         rebuilds (max_sends): act by hand"
                    ),
                );
            }
        }
    }

    /// One send attempt (a first build or a rebuild), counted before it is tried: `sends` + 1, and the next attempt
    /// no sooner than `refee_after_blocks × 2^(sends − 1)` blocks later (review M-3, re-review N-1).
    fn count_attempt(&mut self, intent: &str, height: u32) {
        let refee = self.cfg.refee_after_blocks;
        if let Some(c) = self.state.claims.get_mut(intent) {
            c.sends = c.sends.saturating_add(1);
            let backoff = refee.saturating_mul(1u32 << (c.sends - 1).min(10));
            c.next_rebuild = height.saturating_add(backoff);
            self.dirty = true;
        }
    }

    /// `yed_buildcancel` (entries the node drops or refuses are set aside), `set_signcancel`, `vault_send`, then
    /// the peers.
    async fn build_and_send(&mut self, intent: &str, height: u32, previous: Option<String>) {
        let members = self.view.members.clone();
        for _ in 0..BUILD_ATTEMPTS {
            let c = &self.state.claims[intent];
            let usable = c.usable(self.seq, self.cfg.auto_cosign, &members);
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
                        || message.starts_with("cancel-statement-claimable")
                        || message.starts_with("attest-range") =>
                {
                    let Some(seq) = refused_index(&message).and_then(|i| usable.get(i)).map(|(s, _)| *s) else {
                        tracing::error!("cancel: yed_buildcancel {intent}: {message}");
                        return;
                    };
                    tracing::warn!("cancel: the node refused seq {seq}'s co-signature for {intent} ({message}); retrying without it");
                    let c = self.state.claims.get_mut(intent).expect("present");
                    if permanent_refusal(&message) {
                        c.rejected.insert(seq);
                    } else {
                        // the node does not count it as a member now: leave it out of this build only
                        c.cosigs.remove(&seq);
                    }
                    c.enough_since = None;
                    self.dirty = true;
                    continue;
                }
                Err(RpcError::Node { message, .. }) if message.starts_with("cancel-cosign-needed") => {
                    tracing::warn!("cancel: {intent}: {message}");
                    self.set_aside(intent, &usable, &message);
                    if let Some(c) = self.state.claims.get_mut(intent) {
                        c.enough_since = None;
                    }
                    return;
                }
                Err(e) => {
                    tracing::error!("cancel: yed_buildcancel {intent}: {e}; retried next poll");
                    return;
                }
            };
            // the node drops (and names) entries it would not count and builds from the rest: set those aside too
            let warnings: Vec<String> = built
                .get("warnings")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default();
            if !warnings.is_empty() {
                tracing::warn!("cancel: yed_buildcancel for {intent}: {}", warnings.join("; "));
                self.set_aside(intent, &usable, &warnings.join("\n"));
            }
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
            self.dirty = true;
            self.save();
            self.push_to_peers(&carrier, &shex).await;
            return;
        }
    }

    /// The entries a `yed_buildcancel` named as dropped: a permanent reason sets the seq aside for this claim; a
    /// membership reason drops the entry from this build only (the seq may be current again later).
    fn set_aside(&mut self, intent: &str, usable: &[(u16, String)], text: &str) {
        let Some(c) = self.state.claims.get_mut(intent) else {
            return;
        };
        for (i, id) in dropped_entries(text) {
            if let Some((s, _)) = usable.get(i) {
                if permanent_refusal(&id) {
                    c.rejected.insert(*s);
                } else {
                    c.cosigs.remove(s);
                }
            }
        }
        self.dirty = true;
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

/// `alert_command <kind> <intent> <message>`: at most ALERTS_INFLIGHT_MAX at once (more are logged and skipped),
/// each killed after ALERT_TIMEOUT.
fn run_alert_command(cmd: String, kind: String, intent: String, message: String) {
    if ALERTS_INFLIGHT.fetch_add(1, Ordering::SeqCst) >= ALERTS_INFLIGHT_MAX {
        ALERTS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        tracing::warn!("alert_command: {ALERTS_INFLIGHT_MAX} already running; this alert is in the log only");
        return;
    }
    std::thread::spawn(move || {
        match std::process::Command::new(&cmd)
            .arg(&kind)
            .arg(&intent)
            .arg(&message)
            .stdin(std::process::Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                let deadline = Instant::now() + ALERT_TIMEOUT;
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                        Ok(None) => {
                            tracing::error!("alert_command {cmd}: still running after {ALERT_TIMEOUT:?}; killed");
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        Err(e) => {
                            tracing::error!("alert_command {cmd}: {e}");
                            break;
                        }
                    }
                }
            }
            Err(e) => tracing::error!("alert_command {cmd}: {e}"),
        }
        ALERTS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
    });
}

// ------------------------------------------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosig::testkit;
    use crate::rpc::mock::MockNode;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    const THETA: u32 = 12_500;
    const COLL: i64 = 75 * 100_000_000; // 75 YEC against $100: claimable below $1.6667
    const DEBT: i64 = 10_000;

    fn members(seqs: &[u16]) -> BTreeMap<u16, [u8; 33]> {
        seqs.iter().map(|s| (*s, [*s as u8; 33])).collect()
    }

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

    fn ctx(height: u32, rank: u32, m: &BTreeMap<u16, [u8; 33]>) -> DecideCtx<'_> {
        DecideCtx {
            height,
            me: 1,
            rank: Some(rank),
            drive: true,
            takeover_blocks: 2,
            spares: 1,
            spare_wait_blocks: 1,
            refee_after_blocks: 3,
            max_sends: 3,
            own: true,
            members: m,
            intent_spent_in_mempool: false,
            our_tx_in_mempool: false,
        }
    }

    // ---- watcher

    #[test]
    fn honest_price_is_what_it_knew_at_r_and_never_later() {
        let mut s = State::fresh();
        assert_eq!(honest_price(&s, 100, 5), None);
        s.record_price(104, 4);
        assert_eq!(honest_price(&s, 100, 5), None); // only a later aggregate: unjudged, not guessed (L-6)
        s.record_price(94, 2);
        assert_eq!(honest_price(&s, 100, 5), None); // older than the tolerance
        s.record_price(96, 3);
        assert_eq!(honest_price(&s, 100, 5), Some(3));
        s.record_price(99, 5);
        s.record_price(101, 8);
        assert_eq!(honest_price(&s, 100, 5), Some(5)); // the last one at or before R
        s.record_price(100, 6);
        assert_eq!(honest_price(&s, 100, 5), Some(6));
        s.record_signed(100, 9);
        assert_eq!(honest_price(&s, 100, 5), Some(9)); // what this seq signed for R wins
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
    fn sign_errors_are_sticky_only_when_they_cannot_change() {
        let e = |m: &str| RpcError::Node {
            code: -8,
            message: m.into(),
        };
        assert_eq!(classify_sign_error(&e("price-required: x")), SignErr::PriceRequired);
        assert!(matches!(
            classify_sign_error(&e("cancel-statement-claimable: x")),
            SignErr::Claimable(_)
        ));
        assert!(matches!(
            classify_sign_error(&e("equivocation-guard: x")),
            SignErr::Sticky(_)
        ));
        assert!(matches!(classify_sign_error(&e("attest-range: x")), SignErr::Sticky(_)));
        for transient in [
            "the Yellowback index and the active chain disagree at the claim's refHeight; retry",
            "the claim's refHeight 99 is not indexed",
            "Error: Please enter the wallet passphrase with walletpassphrase first.",
            "claim-unconfirmed: co-sign the cancel once the claim has confirmed",
            "attest-not-eligible: seq 3 is not a current member",
        ] {
            assert!(
                matches!(classify_sign_error(&e(transient)), SignErr::Transient(_)),
                "{transient}"
            );
        }
        assert!(matches!(
            classify_sign_error(&RpcError::Transport("timed out".into())),
            SignErr::Transient(_)
        ));
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
        let m = [5u16, 1, 3, 9];
        let ranks: Vec<u32> = m.iter().map(|s| rank(&m, *s, &[7; 32], 0).unwrap()).collect();
        let mut sorted = ranks.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3]); // a permutation: exactly one leader
        assert_eq!(rank(&m, 4, &[7; 32], 0), None);
        assert_eq!(rank(&[9, 5, 3, 1], 3, &[7; 32], 0), rank(&m, 3, &[7; 32], 0));
        let leaders: HashSet<u16> = (0u8..32)
            .map(|i| *m.iter().find(|s| rank(&m, **s, &[i; 32], 0) == Some(0)).unwrap())
            .collect();
        assert!(leaders.len() > 1, "the first driver should vary across claims");
    }

    #[test]
    fn takeover_fits_claim_delay() {
        // mainnet: 576 blocks, 15 seats: (576 - 1 - 2) / 14 = 40, so 6 stands and 36 stands
        assert_eq!(effective_takeover(6, Some(576), 1, 15), 6);
        assert_eq!(effective_takeover(36, Some(576), 1, 15), 36);
        // regtest: 10 blocks, 4 members: (10 - 1 - 2) / 3 = 2
        assert_eq!(effective_takeover(6, Some(10), 1, 4), 2);
        assert_eq!(effective_takeover(6, Some(3), 1, 15), 1);
        assert_eq!(effective_takeover(6, None, 1, 4), 6);
        for members in 2..16usize {
            let t = effective_takeover(36, Some(576), 1, members);
            assert!((members as u32 - 1) * t + 1 + 2 <= 576, "{members} {t}");
        }
    }

    // ---- the collector state machine

    #[test]
    fn decide_waits_for_its_turn_then_for_spares() {
        let m = members(&[0, 1, 2]);
        let mut c = claim(1);
        assert_eq!(decide(&c, &ctx(100, 0, &m)), Decision::Idle("short of co-signatures"));
        c.cosigs.insert(1, "11".into());
        assert_eq!(
            decide(&c, &ctx(101, 1, &m)),
            Decision::Idle("not this member's turn yet")
        );
        c.enough_since = Some(100);
        assert_eq!(
            decide(&c, &ctx(100, 0, &m)),
            Decision::Idle("waiting for spare co-signatures")
        );
        assert_eq!(decide(&c, &ctx(101, 0, &m)), Decision::Build(vec![1]));
        c.cosigs.insert(0, "00".into());
        assert_eq!(decide(&c, &ctx(100, 0, &m)), Decision::Build(vec![1, 0]));
        assert_eq!(decide(&c, &ctx(102, 1, &m)), Decision::Build(vec![1, 0]));
        let mut x = ctx(102, 1, &m);
        x.intent_spent_in_mempool = true;
        assert_eq!(decide(&c, &x), Decision::Idle("another cancel is in the mempool"));
        // an orphaned claim (its block left the chain) is never driven
        c.orphaned = true;
        assert_eq!(
            decide(&c, &ctx(102, 0, &m)),
            Decision::Idle("the claim's block left the chain")
        );
    }

    #[test]
    fn decide_counts_only_current_members_and_unrefused_entries() {
        let mut m = members(&[1, 4, 6]);
        let mut c = claim(2);
        c.cosigs.insert(1, "11".into());
        c.cosigs.insert(4, "44".into());
        c.enough_since = Some(100);
        assert_eq!(decide(&c, &ctx(101, 0, &m)), Decision::Build(vec![1, 4]));
        c.rejected.insert(4); // the node refused seq 4's entry for good: one short again
        assert_eq!(decide(&c, &ctx(101, 0, &m)), Decision::Idle("short of co-signatures"));
        c.rejected.clear();
        m.remove(&4); // seq 4 is not current now (left, or not yet mature): not counted ...
        assert_eq!(decide(&c, &ctx(101, 0, &m)), Decision::Idle("short of co-signatures"));
        m.insert(4, [4; 33]); // ... and counted again once it is (review L-1: reinstated)
        assert_eq!(decide(&c, &ctx(101, 0, &m)), Decision::Build(vec![1, 4]));
        let mut big = m.clone();
        for s in 10..20 {
            c.cosigs.insert(s, "ff".into());
            big.insert(s, [s as u8; 33]);
        }
        match decide(&c, &ctx(101, 0, &big)) {
            Decision::Build(v) => assert_eq!(v.len(), cosig::CANCEL_COSIGN_MAX),
            d => panic!("{d:?}"),
        }
    }

    #[test]
    fn decide_after_sending_backs_off_and_caps() {
        let m = members(&[0, 1]);
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
        c.sends = 1;
        c.next_rebuild = 104;
        let mut x = ctx(102, 0, &m);
        x.our_tx_in_mempool = true;
        assert_eq!(decide(&c, &x), Decision::Idle("sent"));
        x.height = 104;
        assert_eq!(decide(&c, &x), Decision::Rebroadcast);
        x.our_tx_in_mempool = false;
        x.height = 103;
        assert_eq!(decide(&c, &x), Decision::Idle("rebuild backoff")); // review M-3
        x.height = 104;
        assert_eq!(decide(&c, &x), Decision::Rebuild);
        c.sends = 3; // max_sends
        assert_eq!(decide(&c, &x), Decision::SendCap);
        c.sends = 1;
        c.rejected.insert(1);
        assert_eq!(
            decide(&c, &x),
            Decision::Idle("sent cancel gone; short of co-signatures to rebuild")
        );
    }

    #[test]
    fn decide_never_touches_honest_closed_late_or_passive() {
        let m = members(&[0, 1, 2]);
        let mut c = claim(1);
        c.cosigs.insert(1, "11".into());
        c.cosigs.insert(2, "22".into());
        c.verdict = Verdict::Honest;
        assert_eq!(decide(&c, &ctx(101, 0, &m)), Decision::Idle("honest claim"));
        c.verdict = Verdict::Wrong;
        assert_eq!(decide(&c, &ctx(110, 0, &m)), Decision::Idle("past the release height"));
        let mut x = ctx(101, 0, &m);
        x.drive = false;
        assert_eq!(decide(&c, &x), Decision::Idle("drive = false"));
        x.drive = true;
        x.rank = None;
        assert_eq!(decide(&c, &x), Decision::Idle("not a current member"));
        c.verdict = Verdict::Unjudged;
        assert_eq!(decide(&c, &ctx(101, 0, &m)), Decision::Build(vec![1, 2]));
        c.phase = Phase::Closed {
            outcome: "cancelled".into(),
            height: 105,
        };
        assert_eq!(decide(&c, &ctx(106, 0, &m)), Decision::Idle("closed"));
    }

    #[test]
    fn a_reset_forgets_the_chain_and_sets_the_cosignatures_aside() {
        let mut c = claim(2);
        c.cosigs.insert(1, "11".into());
        c.own_cosig = Some("11".into());
        c.rejected.insert(3);
        c.sends = 2;
        c.alerted.insert("wrong-price".into());
        c.phase = Phase::Sent {
            txid: "t".into(),
            hex: "h".into(),
            carrier: "c".into(),
            height: 101,
            cosigners: vec![1],
            last_push: 101,
        };
        let prior = c.reset(105, 115);
        assert_eq!((c.confirm_height, c.release_height), (105, 115));
        assert!(c.ref_height.is_none() && c.block_hash.is_none() && c.own_cosig.is_none());
        assert!(c.cosigs.is_empty() && c.rejected.is_empty());
        assert_eq!(
            (c.verdict, c.phase.clone(), c.sends),
            (Verdict::Pending, Phase::Watching, 2)
        );
        assert!(!c.alerted.contains("wrong-price")); // a new verdict is alerted afresh
        assert_eq!(prior.ref_height, Some(99));
        assert_eq!(prior.cosigs.len(), 1);
    }

    #[test]
    fn members_are_current_mature_and_newest() {
        let k = |i: u8| hex::encode(testkit::pubkey(&testkit::key(i)));
        let rows = json!([
            {"seq": 0, "attestorPubKey": k(1), "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 1, "attestorPubKey": k(2), "status": "DORMANT", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 2, "attestorPubKey": k(3), "status": "EJECTED", "bondSpentHeight": null, "bondFrozen": true},
            {"seq": 3, "attestorPubKey": k(4), "status": "PENDING", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 4, "attestorPubKey": k(5), "status": "WITHDRAWN", "bondSpentHeight": 50, "bondFrozen": false},
            {"seq": 5, "attestorPubKey": k(5), "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 6, "attestorPubKey": k(1), "status": "PENDING", "bondSpentHeight": null, "bondFrozen": false},
            {"seq": 7, "attestorPubKey": k(8), "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false}
        ]);
        let m = current_members(&rows, None);
        assert_eq!(m.keys().copied().collect::<Vec<_>>(), vec![1, 5, 7]);
        // the primitive says seq 7's key is not current yet (its join has not matured): left out (review L-1)
        let set = json!({"memberlist": [
            {"key": k(2), "current": true}, {"key": k(5), "current": true}, {"key": k(8), "current": false}
        ]});
        let keys = current_keys(&set).unwrap();
        let m = current_members(&rows, Some(&keys));
        assert_eq!(m.keys().copied().collect::<Vec<_>>(), vec![1, 5]);
    }

    #[test]
    fn default_state_path_follows_the_cookie() {
        let mut n = crate::config::parse(
            "[node]\nrpc_url = \"http://127.0.0.1:1\"\nrpc_cookie = \"/data/ycash/regtest/.cookie\"\n",
        )
        .unwrap()
        .node;
        assert_eq!(
            CancelAgent::default_path(&n, "regtest", 3),
            PathBuf::from("/data/ycash/regtest/yellowback-cancel-3.json")
        );
        n.cookie = None;
        assert!(CancelAgent::default_path(&n, "main", 3).ends_with(".ycash/yellowback-cancel-main-3.json"));
    }

    #[test]
    fn refused_and_dropped_entries_parse_the_node_message() {
        assert_eq!(
            refused_index("cancel-cosign-not-member: cosigs[2] is not from a current member"),
            Some(2)
        );
        assert_eq!(refused_index("cancel-cosign-needed: this cancel needs 2"), None);
        assert_eq!(
            dropped_entries(
                "cosigs[1] dropped: cancel-cosign-not-member: key 02ab; cosigs[3] dropped: attest-range: x"
            ),
            vec![
                (1, "cancel-cosign-not-member".to_string()),
                (3, "attest-range".to_string())
            ]
        );
        assert_eq!(
            dropped_entries("cancel-cosign-needed: needs 2, 1 given; cosigs[0] dropped: cancel-statement-claimable"),
            vec![(0, "cancel-statement-claimable".to_string())]
        );
        assert!(dropped_entries("cosigs[2] is not from a current member").is_empty());
        assert!(!permanent_refusal("cancel-cosign-not-member"));
        assert!(permanent_refusal("cancel-statement-claimable"));
        assert!(permanent_refusal("cancel-cosign-malformed"));
    }

    #[test]
    fn state_round_trips_survives_corruption_and_reads_older_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s/cancel.json");
        let mut s = State::fresh();
        s.claims.insert("aa:0".into(), claim(2));
        s.record_price(10, 4_000_000);
        s.recording_since = Some(5);
        s.save(&p).unwrap();
        s.save(&p).unwrap(); // the O_EXCL temporary name is free again after a save
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // a leftover temporary file of this process is replaced, not written through
        std::fs::write(p.with_extension(format!("tmp.{}", std::process::id())), "junk").unwrap();
        s.save(&p).unwrap();
        let back = State::load(&p);
        assert_eq!(back.claims["aa:0"].required, 2);
        assert_eq!((back.prices[&10], back.recording_since), (4_000_000, Some(5)));
        // a file written before the review's fields still loads (serde defaults)
        let mut v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("recording_since");
        for k in [
            "confirm_hash",
            "bundle_price",
            "cosign_blocked",
            "next_rebuild",
            "orphaned",
            "foreign_spend_since",
        ] {
            v["claims"]["aa:0"].as_object_mut().unwrap().remove(k);
        }
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        let old = State::load(&p);
        assert_eq!(old.claims["aa:0"].required, 2);
        assert!(old.recording_since.is_none());
        std::fs::write(&p, "{not json").unwrap();
        let fresh = State::load(&p);
        assert!(fresh.claims.is_empty());
        assert!(p.with_extension("corrupt").exists());
    }

    // ---- the agent end to end against a mock node

    struct Chain {
        height: u32,
        claiming: bool,
        cancelled: bool,
        cancels_required: u32,
        /// blockHash(height) overrides (display hex); everything else is 0x33..
        hashes: HashMap<u32, String>,
        /// the claim's intent is spent in a confirmed block
        spent_in_chain: bool,
        /// the guard's price per (seq) for the refHeight; None: price-required
        guard: HashMap<u16, u32>,
        /// a transient failure for the next N yed_signcancelcosign calls
        sign_failures: u32,
        /// the equivocation guard refuses an explicit price
        guard_refuses: bool,
        /// vault_send refuses every cancel (re-review N-1)
        send_refused: bool,
        /// the claim's bundle as yed_decodepayload decodes it (re-review N-2)
        bundle: Value,
        /// the node is still in initial block download (re-review N-6)
        ibd: bool,
        sent: Vec<Vec<String>>,
        mempool: Vec<String>,
        sign_calls: u32,
    }

    fn chain(required: u32) -> Arc<Mutex<Chain>> {
        Arc::new(Mutex::new(Chain {
            height: 100,
            claiming: true,
            cancelled: false,
            cancels_required: required,
            hashes: HashMap::new(),
            spent_in_chain: false,
            guard: HashMap::new(),
            sign_failures: 0,
            guard_refuses: false,
            send_refused: false,
            bundle: Value::Null,
            ibd: false,
            sent: vec![],
            mempool: vec![],
            sign_calls: 0,
        }))
    }

    fn default_hash() -> String {
        cosig::display_of_internal(&[0x33u8; 32])
    }

    fn mock(chain: Arc<Mutex<Chain>>) -> MockNode {
        let set = [0x75u8; 32];
        let intent_txid = "aa".repeat(32);
        MockNode::start(None, move |method, params| {
            let mut ch = chain.lock().unwrap();
            let k = |i: u8| hex::encode(testkit::pubkey(&testkit::key(i)));
            let hash_at = |ch: &Chain, h: u32| ch.hashes.get(&h).cloned().unwrap_or_else(default_hash);
            match method {
                "yed_getinfo" => Ok(json!({"network": "regtest", "height": ch.height,
                    "upgrade": {"attestorSetId": cosig::display_of_internal(&set), "claimDelay": 10},
                    "params": {"claimThresholdBps": THETA, "claimDelay": 10}})),
                "yed_listattestors" => Ok(json!([
                    {"seq": 0, "attestorPubKey": k(10), "bondKeyAddress": "addr0", "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false},
                    {"seq": 1, "attestorPubKey": k(11), "bondKeyAddress": "addr1", "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false},
                    {"seq": 2, "attestorPubKey": k(12), "bondKeyAddress": "addr2", "status": "ELIGIBLE", "bondSpentHeight": null, "bondFrozen": false}
                ])),
                "yed_listvaults" => Ok(if ch.claiming {
                    json!([{"txid": "bb".repeat(32), "vout": 0, "status": "CLAIMING", "collateralZat": COLL, "mintedCents": DEBT,
                        "cancelsRequired": ch.cancels_required,
                        "intents": [{"txid": intent_txid, "vout": 0, "role": "claimant", "height": 100, "releaseHeight": 110}]}])
                } else {
                    json!([])
                }),
                "validateaddress" => {
                    let a = params[0].as_str().unwrap_or("");
                    let n: u8 = a.trim_start_matches("addr").parse().unwrap_or(99);
                    Ok(json!({"isvalid": true, "pubkey": k(10 + n)}))
                }
                "signmessage" => {
                    let a = params[0].as_str().unwrap_or("");
                    let n: u8 = a.trim_start_matches("addr").parse().unwrap_or(99);
                    let msg = params[1].as_str().unwrap_or("");
                    let sig = testkit::sign(&testkit::key(10 + n), &crate::binding::message_hash(msg));
                    Ok(json!(base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        sig
                    )))
                }
                "getrawtransaction" => Ok(json!("00")),
                "yed_decodepayload" => {
                    Ok(json!({"valid": true, "type": "redeem", "refHeight": 99, "bundle": ch.bundle}))
                }
                "getblockchaininfo" => {
                    Ok(json!({"blocks": 100, "headers": 100, "initial_block_download_complete": !ch.ibd}))
                }
                "yed_getattestations" => Ok(json!([])),
                "getblockhash" => Ok(json!(hash_at(&ch, params[0].as_u64().unwrap() as u32))),
                "yed_signcancelcosign" => {
                    ch.sign_calls += 1;
                    if ch.sign_failures > 0 {
                        ch.sign_failures -= 1;
                        return Err((
                            -4,
                            "Error: Please enter the wallet passphrase with walletpassphrase first.".into(),
                        ));
                    }
                    let seq = params[2].as_u64().unwrap() as u16;
                    let price = match (ch.guard.get(&seq), &params[1]) {
                        (Some(g), Value::Null) => *g,
                        (None, Value::Null) => {
                            return Err((
                                -8,
                                "price-required: this key signed no price for the claim's refHeight 99".into(),
                            ))
                        }
                        (_, p) if ch.guard_refuses => {
                            return Err((
                                -8,
                                format!("equivocation-guard: seq {seq} already signed 1 for height 99 ({p})"),
                            ))
                        }
                        (_, p) => p.as_u64().unwrap() as u32,
                    };
                    if cosig::is_underwater(COLL, price as i64, DEBT, THETA) {
                        return Err((
                            -8,
                            "cancel-statement-claimable: at that price the vault was claimable".into(),
                        ));
                    }
                    ch.guard.insert(seq, price);
                    let bh = cosig::internal_from_display(&hash_at(&ch, 99)).unwrap();
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
                    if ch.send_refused {
                        return Err((-26, "16: bad-txns-inputs-spent".into()));
                    }
                    ch.mempool.push("dd".repeat(32));
                    Ok(json!("dd".repeat(32)))
                }
                "getrawmempool" => Ok(json!(ch.mempool)),
                "gettxout" => {
                    let mempool = params[2].as_bool().unwrap_or(true);
                    let spent = ch.spent_in_chain || (mempool && !ch.mempool.is_empty());
                    Ok(if spent { Value::Null } else { json!({"value": 1}) })
                }
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
        crate::config::parse(
            "[node]\nrpc_url = \"http://127.0.0.1:1\"\n[cancel]\nspares = 1\nspare_wait_blocks = 1\ntakeover_blocks = 36\n",
        )
        .unwrap()
        .cancel
    }

    fn intent() -> String {
        format!("{}:0", "aa".repeat(32))
    }

    fn leader_and_other() -> (u16, u16) {
        let txid = cosig::internal_from_display(&"aa".repeat(32)).unwrap();
        let leader = (0u16..3).find(|s| rank(&[0, 1, 2], *s, &txid, 0) == Some(0)).unwrap();
        (leader, (0u16..3).find(|s| *s != leader).unwrap())
    }

    fn signed_frame(seq: u16, key: u8, price: u32, block_hash: &str) -> Vec<u8> {
        let txid = cosig::internal_from_display(&"aa".repeat(32)).unwrap();
        let bh = cosig::internal_from_display(block_hash).unwrap();
        let msg = cosig::message(&[0x75; 32], &txid, 0, 99, price, &bh);
        Frame {
            txid,
            n: 0,
            seq,
            ref_height: 99,
            entry: Entry {
                price,
                sig: testkit::sign(&testkit::key(key), &msg),
            },
        }
        .encode()
        .to_vec()
    }

    /// Frames through the verifier task's logic (gossip::Verifier) against the agent's view, as attest does.
    fn deliver(a: &mut CancelAgent, bytes: &[u8]) {
        let now = Instant::now();
        let mut v = crate::gossip::Verifier::new(16, 1, 10_000, crate::gossip::Rng::new(9));
        v.set_ctx(std::sync::Arc::new(a.gossip_ctx()), now);
        let _ = v.intake(bytes, now);
        for x in v.run_slice(now) {
            a.accept_verified(x);
        }
    }

    fn new_agent(m: &MockNode, seq: u16, path: &Path) -> CancelAgent {
        let mut a = CancelAgent::new(agent_cfg(), &m.config(None, None, None), seq, path.to_path_buf()).unwrap();
        a.state.recording_since.get_or_insert(50); // this agent's record covers the claim's refHeight (99)
        a
    }

    #[tokio::test]
    async fn agent_cosigns_collects_sends_closes_and_resumes() {
        let ch = chain(2);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let (leader, other) = leader_and_other();
        let mut a = new_agent(&m, leader, &path);
        a.state.record_price(99, 4_000_000); // its honest price at R = 99: $4.00 (the vault at 300 %)

        a.tick(100).await;
        let c = &a.state.claims[&intent()];
        assert_eq!(c.verdict, Verdict::Wrong);
        assert!(c.alerted.contains("wrong-price"));
        assert!(c.own_cosig.is_some());
        let out = a.take_outbox();
        assert_eq!(out.len(), 1);
        let f = Frame::decode(&out[0]).unwrap();
        assert_eq!((f.seq, f.ref_height, f.entry.price), (leader, 99, 4_000_000));
        assert!(ch.lock().unwrap().sent.is_empty()); // required 2: one in hand

        // another member's co-signature arrives (and a forged one, dropped), between polls
        deliver(
            &mut a,
            &signed_frame(other, 10 + other as u8, 4_000_000, &default_hash()),
        );
        deliver(&mut a, &signed_frame(other, 99, 4_000_001, &default_hash()));
        assert_eq!(a.state.claims[&intent()].cosigs.len(), 2);
        a.tick(100).await;
        assert!(ch.lock().unwrap().sent.is_empty()); // waits a block for the spare
        a.tick(101).await;
        assert_eq!(ch.lock().unwrap().sent.len(), 1);
        assert_eq!(ch.lock().unwrap().sent[0].len(), 2);
        assert!(matches!(a.state.claims[&intent()].phase, Phase::Sent { .. }));

        // restart: neither re-co-signs nor rebuilds (the cancel is in the mempool)
        drop(a);
        let before = ch.lock().unwrap().sign_calls;
        let mut b = new_agent(&m, leader, &path);
        b.tick(102).await;
        assert_eq!(ch.lock().unwrap().sent.len(), 1);
        assert_eq!(ch.lock().unwrap().sign_calls, before);

        // the cancel confirms: the intent is spent in the chain, the vault record gone: closed as cancelled
        {
            let mut c = ch.lock().unwrap();
            c.claiming = false;
            c.cancelled = true;
            c.spent_in_chain = true;
            c.mempool.clear();
        }
        b.tick(103).await;
        assert_eq!(
            b.state.claims[&intent()].phase,
            Phase::Closed {
                outcome: "cancelled".into(),
                height: 103
            }
        );
    }

    /// Review H-1: the claim's block is reorganised away. The claim is held (never closed as cancelled), its
    /// re-mining at another height reopens it with its co-signatures restored, and it is still cancelled; a claim
    /// that was closed and comes back is reopened too.
    #[tokio::test]
    async fn a_reorg_of_the_claim_block_never_closes_the_claim() {
        let ch = chain(1);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let (leader, _) = leader_and_other();
        let mut a = new_agent(&m, leader, &dir.path().join("s.json"));
        a.state.record_price(99, 4_000_000);
        a.tick(100).await;
        assert!(a.state.claims[&intent()].own_cosig.is_some());
        // the claim's block (100) is replaced: the claim is not CLAIMING, its intent is "spent" (gone) in the chain
        {
            let mut c = ch.lock().unwrap();
            c.claiming = false;
            c.spent_in_chain = true;
            c.cancelled = true; // yed_getvault would say vault-not-found: the old code closed it as cancelled
            c.hashes.insert(100, cosig::display_of_internal(&[0x44; 32]));
        }
        a.tick(100).await;
        let c = &a.state.claims[&intent()];
        assert!(!c.is_closed(), "a reorg is not a cancel");
        assert!(c.orphaned && c.alerted.contains("claim-reorged"));
        assert!(ch.lock().unwrap().sent.is_empty()); // an orphaned claim is not driven
                                                     // re-mined in a new block at the same height: followed again, co-signatures restored (same R and hash)
        {
            let mut c = ch.lock().unwrap();
            c.claiming = true;
            c.spent_in_chain = false;
            c.cancelled = false;
        }
        a.tick(101).await;
        let c = &a.state.claims[&intent()];
        assert!(!c.orphaned && !c.is_closed());
        assert!(c.own_cosig.is_some() && c.cosigs.contains_key(&leader));
        a.tick(102).await;
        assert_eq!(
            ch.lock().unwrap().sent.len(),
            1,
            "the re-mined claim is still cancelled"
        );

        // a claim closed earlier that is CLAIMING again is reopened
        a.state.claims.get_mut(&intent()).unwrap().phase = Phase::Closed {
            outcome: "cancelled".into(),
            height: 102,
        };
        ch.lock().unwrap().mempool.clear();
        a.tick(103).await;
        let c = &a.state.claims[&intent()];
        assert!(!c.is_closed());
        assert_eq!(c.phase, Phase::Watching);
    }

    /// Review H-2: a reorg across the refHeight changes blockHash(R): the claim is reset and re-signed over the new
    /// hash; frames over the old hash no longer verify.
    #[tokio::test]
    async fn a_reorg_across_the_ref_height_re_signs() {
        let ch = chain(2);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let (leader, other) = leader_and_other();
        let mut a = new_agent(&m, leader, &dir.path().join("s.json"));
        a.state.record_signed(99, 4_000_000);
        a.tick(100).await;
        deliver(
            &mut a,
            &signed_frame(other, 10 + other as u8, 4_000_000, &default_hash()),
        );
        let old = a.state.claims[&intent()].own_cosig.clone().unwrap();
        assert_eq!(a.state.claims[&intent()].cosigs.len(), 2);
        let new_hash = cosig::display_of_internal(&[0x55; 32]);
        ch.lock().unwrap().hashes.insert(99, new_hash.clone());
        a.take_outbox();
        a.tick(101).await;
        let c = &a.state.claims[&intent()];
        assert_eq!(c.block_hash.as_deref(), Some(new_hash.as_str()));
        let new = c.own_cosig.clone().unwrap();
        assert_ne!(new, old, "re-signed over the new blockHash(R)");
        assert_eq!(c.cosigs.len(), 1, "the other member's old co-signature is gone");
        assert_eq!(a.take_outbox().len(), 1, "the new co-signature is published at once");
        // the other member's old frame does not verify any more; its re-signed one does
        deliver(
            &mut a,
            &signed_frame(other, 10 + other as u8, 4_000_000, &default_hash()),
        );
        assert_eq!(a.state.claims[&intent()].cosigs.len(), 1);
        deliver(&mut a, &signed_frame(other, 10 + other as u8, 4_000_000, &new_hash));
        assert_eq!(a.state.claims[&intent()].cosigs.len(), 2);
    }

    /// Review M-1: a transient refusal (a locked wallet) is retried; a sticky one blocks.
    #[tokio::test]
    async fn transient_signing_errors_are_retried_sticky_ones_block() {
        let ch = chain(1);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let (leader, _) = leader_and_other();
        let mut a = new_agent(&m, leader, &dir.path().join("s.json"));
        a.state.record_price(99, 4_000_000);
        ch.lock().unwrap().sign_failures = 2;
        a.tick(100).await;
        assert!(a.state.claims[&intent()].own_cosig.is_none());
        assert!(a.state.claims[&intent()].cosign_blocked.is_none());
        a.tick(100).await;
        a.tick(100).await;
        assert!(
            a.state.claims[&intent()].own_cosig.is_some(),
            "co-signed once the wallet answered"
        );

        let ch2 = chain(1);
        ch2.lock().unwrap().guard_refuses = true;
        let m2 = mock(ch2.clone());
        let mut b = new_agent(&m2, leader, &dir.path().join("s2.json"));
        b.state.record_price(99, 4_000_000);
        b.tick(100).await;
        let calls = ch2.lock().unwrap().sign_calls;
        assert!(b.state.claims[&intent()].cosign_blocked.is_some());
        assert!(b.state.claims[&intent()].alerted.contains("cosign-refused"));
        b.tick(101).await;
        assert_eq!(ch2.lock().unwrap().sign_calls, calls, "a sticky refusal is not retried");
    }

    /// Review M-2 / L-2: with no record of its own at the refHeight and the height before its record began, the agent
    /// asks the guard and, finding none, states nothing.
    #[tokio::test]
    async fn no_price_is_stated_for_a_height_the_record_does_not_cover() {
        let ch = chain(1);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let (leader, _) = leader_and_other();
        let mut a = new_agent(&m, leader, &dir.path().join("s.json"));
        a.state.recording_since = Some(99); // the state began at R = 99 (it was lost and recreated)
        a.state.record_price(99, 4_000_000); // even with an aggregate there ...
        a.tick(106).await;
        let c = &a.state.claims[&intent()];
        assert_eq!(c.verdict, Verdict::Wrong);
        assert!(
            c.own_cosig.is_none(),
            "... no new statement at a height it may have attested"
        );
        assert!(c.alerted.contains("no-record"));
        // with the guard holding this key's price there, it co-signs at that price
        let ch2 = chain(1);
        ch2.lock().unwrap().guard.insert(leader, 4_100_000);
        let m2 = mock(ch2.clone());
        let mut b = new_agent(&m2, leader, &dir.path().join("s2.json"));
        b.state.recording_since = Some(105); // no history at all: the guard decides (L-2)
        b.tick(106).await;
        let c = &b.state.claims[&intent()];
        assert_eq!((c.verdict, c.judged_price), (Verdict::Wrong, Some(4_100_000)));
        assert!(c.own_cosig.is_some());
    }

    #[tokio::test]
    async fn agent_leaves_an_honest_claim_alone() {
        let ch = chain(1);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut a = new_agent(&m, 0, &dir.path().join("s.json"));
        a.state.record_price(99, 1_600_000); // the vault really is at 120 % at this agent's price
        for h in 100..111 {
            a.tick(h).await;
        }
        let c = &a.state.claims[&intent()];
        assert_eq!(c.verdict, Verdict::Honest);
        assert!(c.own_cosig.is_none());
        assert!(a.take_outbox().is_empty());
        assert!(ch.lock().unwrap().sent.is_empty());
        assert_eq!(ch.lock().unwrap().sign_calls, 0);
        {
            let mut c = ch.lock().unwrap();
            c.claiming = false;
            c.spent_in_chain = true;
        }
        a.tick(111).await;
        let c = &a.state.claims[&intent()];
        assert!(matches!(&c.phase, Phase::Closed { outcome, .. } if outcome == "released"));
        assert!(!c.alerted.contains("wrong-price-released"));
    }

    #[tokio::test]
    async fn agent_with_auto_cosign_off_only_alerts() {
        let ch = chain(1);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = agent_cfg();
        cfg.auto_cosign = false;
        let mut a = CancelAgent::new(cfg, &m.config(None, None, None), 0, dir.path().join("s.json")).unwrap();
        a.state.recording_since = Some(50);
        a.state.record_price(99, 4_000_000);
        a.tick(100).await;
        let c = &a.state.claims[&intent()];
        assert_eq!(c.verdict, Verdict::Wrong);
        assert!(c.alerted.contains("wrong-price"));
        assert!(c.own_cosig.is_none());
        assert!(a.take_outbox().is_empty());
        {
            let mut c = ch.lock().unwrap();
            c.claiming = false;
            c.spent_in_chain = true;
        }
        a.tick(111).await;
        assert!(a.state.claims[&intent()].alerted.contains("wrong-price-released"));
    }

    /// Review M-3: a cancel that keeps leaving the mempool is rebuilt with backoff, at most max_sends times.
    #[tokio::test]
    async fn rebuilds_back_off_and_stop_at_the_cap() {
        let ch = chain(1);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let (leader, _) = leader_and_other();
        let mut cfg = agent_cfg();
        cfg.refee_after_blocks = 1;
        cfg.max_sends = 3;
        cfg.spares = 0;
        let mut a = CancelAgent::new(cfg, &m.config(None, None, None), leader, dir.path().join("s.json")).unwrap();
        a.state.recording_since = Some(50);
        a.state.record_price(99, 4_000_000);
        let mut h = 100;
        for _ in 0..40 {
            a.tick(h).await;
            ch.lock().unwrap().mempool.clear(); // every cancel is evicted
            h += 1;
            if h >= 109 {
                break;
            }
        }
        let sends = ch.lock().unwrap().sent.len();
        assert_eq!(sends, 3, "max_sends");
        assert!(a.state.claims[&intent()].alerted.contains("cancel-send-cap"));
        let c = &a.state.claims[&intent()];
        assert!(c.next_rebuild > 0);
    }

    /// Re-review N-1: a cancel the node keeps refusing (vault_send) counts every attempt: the cap is reached after
    /// max_sends attempts, spaced by the backoff, and vault_refee is called fewer times than that.
    #[tokio::test]
    async fn persistent_send_failures_hit_the_cap() {
        let ch = chain(1);
        ch.lock().unwrap().send_refused = true;
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let (leader, _) = leader_and_other();
        let mut cfg = agent_cfg();
        cfg.refee_after_blocks = 1;
        cfg.max_sends = 3;
        cfg.spares = 0;
        let mut a = CancelAgent::new(cfg, &m.config(None, None, None), leader, dir.path().join("s.json")).unwrap();
        a.state.recording_since = Some(50);
        a.state.record_price(99, 4_000_000);
        for h in 100..110 {
            a.tick(h).await;
        }
        let builds = ch.lock().unwrap().sent.len();
        let refees = m
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(c, _)| c == "vault_refee")
            .count();
        let c = &a.state.claims[&intent()];
        assert_eq!(c.sends, 3);
        assert_eq!(builds, 3, "one build per counted attempt, none beyond the cap");
        assert!(refees <= 3);
        assert!(c.alerted.contains("cancel-send-cap"));
    }

    /// Re-review N-2: an attestation of this seq at R in the claim's bundle is used only when its signature
    /// verifies under this seq's key; a forged one (a thief's, claiming the vault was claimable) is ignored and the
    /// claim is judged on the real record.
    #[tokio::test]
    async fn a_forged_bundle_entry_is_ignored() {
        let ch = chain(1);
        let (leader, _) = leader_and_other();
        let bh = cosig::internal_from_display(&default_hash()).unwrap();
        let att = |key: u8, price: u32| {
            let msg = cosig::attest_message(leader, price, 99, &bh);
            let sig65 = testkit::sign(&testkit::key(key), &msg);
            let a = crate::framing::Attestation {
                seq: leader,
                price_micro_usd: price,
                cited_height: 99,
                sig: sig65[1..].try_into().unwrap(),
            };
            json!({"seq": leader, "priceMicroUsd": price, "citedHeight": 99, "hex": a.to_hex()})
        };
        // forged: signed by another key at a claimable price
        ch.lock().unwrap().bundle = json!({"attestations": [att(99, 1_600_000)]});
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut a = new_agent(&m, leader, &dir.path().join("s.json"));
        a.state.record_price(99, 4_000_000);
        a.tick(100).await;
        let c = &a.state.claims[&intent()];
        assert_eq!(c.bundle_price, None);
        assert_eq!((c.verdict, c.judged_price), (Verdict::Wrong, Some(4_000_000)));
        // with no history either, the forged entry still does not decide: unjudged (alerted)
        let ch2 = chain(1);
        ch2.lock().unwrap().bundle = json!({"attestations": [att(99, 1_600_000)]});
        let m2 = mock(ch2.clone());
        let mut cfg = agent_cfg();
        cfg.auto_cosign = false; // no guard either
        let mut b = CancelAgent::new(cfg, &m2.config(None, None, None), leader, dir.path().join("s2.json")).unwrap();
        b.state.recording_since = Some(50);
        b.tick(100).await;
        assert_eq!(b.state.claims[&intent()].verdict, Verdict::Unjudged);
        assert!(b.state.claims[&intent()].alerted.contains("unjudged"));
        // a genuine entry of this key is the record: here it says claimable, so the claim is honest by its own word
        let ch3 = chain(1);
        ch3.lock().unwrap().bundle = json!({"attestations": [att(10 + leader as u8, 1_600_000)]});
        let m3 = mock(ch3.clone());
        let mut c3 = new_agent(&m3, leader, &dir.path().join("s3.json"));
        c3.state.record_price(99, 4_000_000);
        c3.tick(100).await;
        let c = &c3.state.claims[&intent()];
        assert_eq!((c.bundle_price, c.verdict), (Some(1_600_000), Verdict::Honest));
        assert!(c.own_cosig.is_none());
    }

    /// Re-review N-5: with auto_cosign = false the member's own co-signature is never made, stored or carried, even
    /// when the guard holds a price or a frame of its own seq arrives.
    #[tokio::test]
    async fn auto_cosign_off_never_carries_its_own_cosignature() {
        let ch = chain(1);
        let (leader, other) = leader_and_other();
        ch.lock().unwrap().guard.insert(leader, 4_000_000);
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = agent_cfg();
        cfg.auto_cosign = false;
        cfg.spares = 0;
        let mut a = CancelAgent::new(cfg, &m.config(None, None, None), leader, dir.path().join("s.json")).unwrap();
        a.state.recording_since = Some(50);
        a.tick(100).await; // no history: unjudged, and the guard is not asked
        assert_eq!(ch.lock().unwrap().sign_calls, 0);
        deliver(
            &mut a,
            &signed_frame(leader, 10 + leader as u8, 4_000_000, &default_hash()),
        );
        assert!(!a.state.claims[&intent()].cosigs.contains_key(&leader));
        deliver(
            &mut a,
            &signed_frame(other, 10 + other as u8, 4_000_000, &default_hash()),
        );
        a.tick(101).await;
        let sent = ch.lock().unwrap().sent.clone();
        assert_eq!(sent.len(), 1, "it still drives on another member's co-signature");
        let own = Entry::decode_hex(&sent[0][0]).unwrap();
        assert_eq!(sent[0].len(), 1);
        let msg = cosig::message(
            &[0x75; 32],
            &cosig::internal_from_display(&"aa".repeat(32)).unwrap(),
            0,
            99,
            own.price,
            &cosig::internal_from_display(&default_hash()).unwrap(),
        );
        assert_eq!(
            cosig::recover(&msg, &own.sig),
            Some(testkit::pubkey(&testkit::key(10 + other as u8)))
        );
    }

    /// Re-review N-6: the record starts only once the node is out of IBD and at the tip.
    #[tokio::test]
    async fn the_record_starts_at_the_tip_only() {
        let ch = chain(1);
        ch.lock().unwrap().ibd = true;
        let m = mock(ch.clone());
        let dir = tempfile::tempdir().unwrap();
        let mut a = CancelAgent::new(agent_cfg(), &m.config(None, None, None), 0, dir.path().join("s.json")).unwrap();
        a.tick(100).await;
        assert_eq!(a.state.recording_since, None);
        ch.lock().unwrap().ibd = false;
        a.tick(101).await;
        assert_eq!(a.state.recording_since, Some(101));
    }

    /// Re-review N-1 for a first send: Watching respects the cap and the backoff too.
    #[test]
    fn decide_backs_off_a_failed_first_send() {
        let m = members(&[0, 1]);
        let mut c = claim(1);
        c.cosigs.insert(1, "11".into());
        c.enough_since = Some(100);
        c.sends = 1;
        c.next_rebuild = 104;
        assert_eq!(decide(&c, &ctx(102, 0, &m)), Decision::Idle("rebuild backoff"));
        assert_eq!(decide(&c, &ctx(104, 0, &m)), Decision::Build(vec![1]));
        c.sends = 3;
        assert_eq!(decide(&c, &ctx(104, 0, &m)), Decision::SendCap);
        // own entries are not carried when the member does not co-sign
        c.sends = 0;
        c.next_rebuild = 0;
        let mut x = ctx(104, 0, &m);
        x.own = false;
        assert_eq!(decide(&c, &x), Decision::Idle("short of co-signatures"));
    }

    // ---- M5 and review B-1/B-2/B-3: bindings under a flood (docs/plans/yellowback-attest-gossip-evaluation.md §7)

    use crate::binding::testkit as bk;

    /// A valid announce of seat `seq` (member key 10 + seq in the mock), on its own endpoint `ep`.
    fn valid(seq: u16, ep: u8, issued: u32) -> Vec<u8> {
        bk::announce(seq, 10 + seq as u8, ep, issued, issued + 1_000).encode()
    }

    /// Forgeries that pass every cheap check for seat `seq`: our network and set, a sane window, a current member's
    /// seq, an issued height newer than anything held; signed by a member key that is not the seat's (99), with a
    /// valid proof of possession of a fresh endpoint.
    fn forged(seq: u16, n: usize, base: u32) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| bk::announce(seq, 99, (i % 200) as u8 + 30, base + (i as u32 % 2), base + 900).encode())
            .collect()
    }

    async fn binding_agent(seed: u64) -> (CancelAgent, MockNode, tempfile::TempDir) {
        let ch = chain(1);
        ch.lock().unwrap().claiming = false;
        let m = mock(ch);
        let dir = tempfile::tempdir().unwrap();
        let mut a = new_agent(&m, 0, &dir.path().join("s.json"));
        a.rng = crate::gossip::Rng::new(seed);
        a.tick(100).await; // the view: members 0, 1, 2; the set; the network
        (a, m, dir)
    }

    /// M5: the per-poll check cap holds whatever arrives: 5,000 forgeries of one seat leave that seat 4 candidates
    /// (BINDING_PER_SEQ), a poll drains the queue, no forgery is taken; stale announces change nothing.
    #[tokio::test]
    async fn a_binding_flood_is_capped_per_poll() {
        let (mut a, _m, _d) = binding_agent(1).await;
        for f in forged(2, 5_000, 100) {
            a.take_binding(f);
        }
        let t0 = Instant::now();
        a.tick(101).await;
        assert!(a.recoveries_last_poll <= BINDING_PER_SEQ, "{}", a.recoveries_last_poll);
        assert!(a.bindings_in.is_empty(), "a poll drains the queue");
        assert!(a.state.bindings.by_seq.is_empty());
        assert!(t0.elapsed() < Duration::from_secs(2));
        // stale: expired, or valid far longer than the TTL allows -- refused before any signature check
        for i in 0..1_000u32 {
            a.take_binding(bk::announce(1, 11, 7, 10 + i % 50, 60).encode());
            a.take_binding(bk::announce(1, 11, 7, 101, 101 + 100_000).encode());
        }
        a.tick(102).await;
        assert_eq!(a.recoveries_last_poll, 0);
        assert!(a.state.bindings.by_seq.is_empty());
    }

    /// M5 at 10x normal (15 forgeries a poll), the honest announce last: taken.
    #[tokio::test]
    async fn a_valid_binding_propagates_through_a_10x_flood() {
        let (mut a, _m, _d) = binding_agent(2).await;
        for f in forged(2, 15, 100) {
            a.take_binding(f);
        }
        a.take_binding(valid(1, 7, 100));
        a.tick(101).await;
        assert!(a.state.bindings.by_seq.contains_key(&1));
    }

    /// M5-1, fixed (review B-2): at 100x (150 forgeries a poll) for another seat, the honest announce arriving last is
    /// taken in the first poll -- it competes only with forgeries of its own seat.
    #[tokio::test]
    async fn a_valid_binding_propagates_through_a_100x_flood() {
        let (mut a, _m, _d) = binding_agent(3).await;
        for f in forged(2, 150, 101) {
            a.take_binding(f);
        }
        a.take_binding(valid(1, 7, 101));
        a.tick(101).await;
        assert!(a.state.bindings.by_seq.contains_key(&1), "taken in the first poll");
        assert!(a.recoveries_last_poll <= BINDING_RECOVERIES);
    }

    /// Review B-2: the topic flooded at 100x across every seat, the fresh member's own seat included. Its honest
    /// announce (repeated every poll here, as in production for the first FRESH_ANNOUNCE_BLOCKS -- about 100 polls on
    /// mainnet -- then every 10 blocks) competes with 150 forgeries of its seat a poll, drawn 4 at a time uniformly:
    /// seeded, it lands within 200 polls (1 - (147/151)^200 > 0.99). The production timing is in
    /// `a_fresh_binding_is_announced_every_poll_then_every_ten_blocks`; self-introduction bypasses the topic.
    #[tokio::test]
    async fn a_fresh_binding_lands_through_a_100x_flood_across_seats() {
        let (mut a, _m, _d) = binding_agent(4).await;
        // 150 distinct forgeries a seat, signed once and replayed every poll (valid through height 1,001)
        let pools: Vec<Vec<Vec<u8>>> = [0u16, 1, 2].iter().map(|seq| forged(*seq, 150, 101)).collect();
        let honest = valid(1, 7, 101);
        let mut landed = None;
        for poll in 0..200u32 {
            let h = 101 + poll;
            for pool in &pools {
                for f in pool {
                    a.take_binding(f.clone());
                }
            }
            a.take_binding(honest.clone());
            a.tick(h).await;
            assert!(a.recoveries_last_poll <= 3 * BINDING_PER_SEQ);
            if a.state.bindings.by_seq.contains_key(&1) {
                landed = Some(poll);
                break;
            }
        }
        assert!(landed.is_some(), "the fresh member's binding never landed in 200 polls");
        assert!(!a.state.bindings.by_seq.contains_key(&0) && !a.state.bindings.by_seq.contains_key(&2));
    }

    /// Review B-2: over its own authenticated connection a member's own binding is taken first and at once, however
    /// the public topic is flooded -- and a member sending forged bindings for OTHER seats over its connection gets
    /// nothing in: only its own seat's announce is accepted from it.
    #[tokio::test]
    async fn member_connections_carry_their_own_binding_only() {
        let (mut a, _m, _d) = binding_agent(5).await;
        for seq in [0u16, 1, 2] {
            for f in forged(seq, 1_500, 101) {
                a.take_binding(f);
            }
        }
        // member 2 floods forged bindings of seat 1 over its own connection: all dropped at intake
        for f in forged(1, 1_000, 101) {
            a.take_member_binding(f, 2);
        }
        assert!(a.bindings_member.is_empty());
        // member 1's own binding over its own connection: taken in this poll
        a.take_member_binding(valid(1, 7, 101), 1);
        a.tick(101).await;
        assert!(a.state.bindings.by_seq.contains_key(&1));
        assert!(a.recoveries_last_poll <= BINDING_RECOVERIES);
    }

    /// Review B-1: one endpoint id claimed by two seats in the same poll is refused for both, with an alert; a seat
    /// claiming an endpoint another seat holds is refused, the holder kept, with an alert. (The proofs of possession
    /// are made with the endpoint's key here, as if it had been stolen: without it the binding is refused anyway,
    /// binding::tests.)
    #[tokio::test]
    async fn an_endpoint_bound_to_two_seats_is_refused_with_an_alert() {
        let (mut a, _m, _d) = binding_agent(6).await;
        let ep = bk::endpoint_id(7);
        let key = bk::endpoint_key(7);
        let both = |seq: u16, issued: u32| {
            bk::announce_with(seq, 10 + seq as u8, ep, &key, issued, issued + 900, vec![]).encode()
        };
        a.take_binding(both(1, 101));
        a.take_binding(both(2, 101));
        a.tick(101).await;
        assert!(a.state.bindings.by_seq.is_empty(), "both refused");
        assert!(a
            .state
            .alerted_global
            .iter()
            .any(|k| k.starts_with("binding-conflict|")));
        // seat 1 binds it alone; then seat 2 claims it: refused, seat 1 kept
        a.take_binding(both(1, 102));
        a.tick(102).await;
        assert!(a.state.bindings.by_seq.contains_key(&1));
        a.take_binding(both(2, 103));
        a.tick(103).await;
        assert!(!a.state.bindings.by_seq.contains_key(&2));
        assert_eq!(a.state.bindings.by_seq[&1].statement.endpoint, ep);
        assert!(a
            .state
            .alerted_global
            .iter()
            .any(|k| k.starts_with("binding-conflict|2-")));
    }

    /// Review N-B: a topic replay of a binding with fake hints is refused (the endpoint signed the real ones); newer
    /// signed hints from any copy replace older ones.
    #[tokio::test]
    async fn a_replay_with_fake_hints_is_refused() {
        let (mut a, _m, _d) = binding_agent(7).await;
        let own = bk::announce(1, 11, 7, 101, 1_001).with_hints(
            &bk::endpoint_key(7),
            vec!["192.168.1.5:4433".into()],
            None,
            10,
        );
        a.take_binding(own.encode());
        a.tick(101).await;
        assert_eq!(
            a.state.bindings.by_seq[&1].announce.addrs,
            vec!["192.168.1.5:4433".to_string()]
        );
        let mut evil = own.clone();
        evil.addrs = vec!["6.6.6.6:6".into()];
        evil.hint_seq = 11;
        a.take_binding(evil.encode());
        a.tick(102).await;
        assert_eq!(
            a.state.bindings.by_seq[&1].announce.addrs,
            vec!["192.168.1.5:4433".to_string()]
        );
        // the endpoint moved and re-signed: any copy carries it in
        let moved = own.with_hints(&bk::endpoint_key(7), vec!["192.168.1.9:4433".into()], None, 12);
        a.take_binding(moved.encode());
        a.tick(103).await;
        assert_eq!(
            a.state.bindings.by_seq[&1].announce.addrs,
            vec!["192.168.1.9:4433".to_string()]
        );
        // an old copy replayed does not roll it back
        a.take_binding(own.encode());
        a.tick(104).await;
        assert_eq!(a.state.bindings.by_seq[&1].announce.hint_seq, 12);
    }

    /// Review N-C: forged look-alikes of the genuine announce -- the same seat, endpoint and issued height, a bad
    /// member signature -- arriving first in the same poll do not displace it: dedup is by digest.
    #[tokio::test]
    async fn a_forged_look_alike_does_not_block_the_genuine_copy() {
        let (mut a, _m, _d) = binding_agent(8).await;
        let genuine = bk::announce(1, 11, 7, 101, 1_001);
        let look_alike = bk::announce(1, 99, 7, 101, 1_001); // same (seq, endpoint, issued), forged member signature
        assert_ne!(genuine.digest(), look_alike.digest());
        a.take_member_binding(look_alike.encode(), 1);
        a.take_member_binding(look_alike.encode(), 1);
        a.take_member_binding(genuine.encode(), 1);
        a.take_binding(look_alike.encode());
        a.tick(101).await;
        assert!(a.state.bindings.by_seq.contains_key(&1), "the genuine copy was taken");
        assert!(a.recoveries_last_poll >= 2);
    }

    /// Review N-A: a fresh binding is announced every poll for FRESH_ANNOUNCE_BLOCKS, then every 10 blocks, and at
    /// the next poll after a member is newly bound. Timing through the topic alone under a 100x per-seat flood: each
    /// announce lands with p = 4/151, so the 20 fresh blocks at 15-second polls (about 100 announces, 25 minutes on
    /// mainnet) carry it with ~93 %; after that one announce per 10 blocks (12.5 minutes) adds 4/151 each, ~98 % by 12
    /// hours. Self-introduction (direct::tests) admits a fresh member at every member it can dial on its first
    /// connection, and each of those announces back at once.
    #[tokio::test]
    async fn a_fresh_binding_is_announced_every_poll_then_every_ten_blocks() {
        let ch = chain(1);
        ch.lock().unwrap().claiming = false;
        let m = mock(ch);
        let dir = tempfile::tempdir().unwrap();
        let mut a = new_agent(&m, 1, &dir.path().join("s.json"));
        a.direct_key = Some(bk::endpoint_key(7));
        a.direct = Some((bk::endpoint_id(7), vec!["127.0.0.1:1".into()], None));
        let mut announced = Vec::new();
        for h in 100..140u32 {
            a.tick(h).await;
            if !a.take_announces().is_empty() {
                announced.push(h);
            }
        }
        assert!(
            a.state.own_binding.is_some(),
            "the binding was signed (signmessage, validateaddress)"
        );
        let first = announced[0];
        let fresh: Vec<u32> = announced
            .iter()
            .copied()
            .filter(|h| *h < first + FRESH_ANNOUNCE_BLOCKS)
            .collect();
        assert_eq!(
            fresh.len() as u32,
            FRESH_ANNOUNCE_BLOCKS,
            "every poll while fresh: {announced:?}"
        );
        let later: Vec<u32> = announced
            .iter()
            .copied()
            .filter(|h| *h >= first + FRESH_ANNOUNCE_BLOCKS)
            .collect();
        assert!(
            later.windows(2).all(|w| w[1] - w[0] == 10),
            "then every 10 blocks: {later:?}"
        );
        // a member newly bound at a new endpoint: ours goes out at the next poll (and over the direct path, with our
        // self-introduction), not at the next 10-block mark
        let h = later.last().copied().unwrap_or(first) + 1;
        a.take_binding(valid(2, 9, h));
        a.tick(h).await;
        assert!(a.state.bindings.by_seq.contains_key(&2));
        let _ = a.take_announces();
        a.tick(h + 1).await;
        assert!(!a.take_announces().is_empty(), "announced at once to the new member");
        a.tick(h + 2).await;
        assert!(a.take_announces().is_empty(), "then back to every 10 blocks");
        // the same member's binding again (renewed in place, same endpoint): no extra announce
        a.take_binding(valid(2, 9, h + 2));
        a.tick(h + 3).await;
        a.tick(h + 4).await;
        assert!(a.take_announces().is_empty());
    }
}
