// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The cancel topic's receive side (the cancel-limit design's co-signature gossip), on its own task so that nothing
//! the agent's poll does (RPCs, signing) ever delays draining the topic (re-review N-4).
//!
//! Every frame is taken off the topic as it arrives and passes, in order:
//! 1. size, magic and a digest dedup of frames already verified;
//! 2. the cheap checks against the agent's latest view ([`Ctx`]): a current member's seq, a claim the node knows,
//!    its refHeight, a price at which the vault was not claimable, and **no valid entry of that seq already held for
//!    the claim** (re-review N-3a: a held co-signature is never re-verified, whoever relays it again);
//! 3. a uniform random sample: the frames that pass are offered to a reservoir of `VERIFY_PER_SECOND × SLICE`
//!    places, and every `SLICE` the reservoir's frames -- a uniform sample of everything offered in that slice -- are
//!    verified (secp256k1 recovery to the seq's member key) and the rest dropped (N-3b). Under a flood an honest
//!    frame keeps a chance of `budget / offered` per copy, whoever relays it; the honest member republishes every
//!    block while the claim is short (N-3c), so it gets through within a few blocks with high probability. There is
//!    no per-peer state: a relaying neighbour is never blamed for its traffic (N-3, N-4);
//! 4. the authenticated per-seq bucket.
//!
//! Frames for a claim the agent does not know yet wait in a bounded pending set (random replacement when full) and
//! are offered again when the view changes. Verified entries go to the agent ([`Verified`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::cancel::MemberView;
use crate::cosig::{self, Frame};

/// The verification budget: signature recoveries per second (~100 µs each: a fifth of one core at most).
pub const VERIFY_PER_SECOND: usize = 2_000;
/// One sampling slice: the reservoir holds `VERIFY_PER_SECOND × SLICE` frames.
pub const SLICE: Duration = Duration::from_millis(250);
pub const PENDING_MAX: usize = 1_024;
pub const PENDING_TTL: Duration = Duration::from_secs(600);
pub const DEDUP_CAPACITY: usize = 8_192;

pub fn slice_budget() -> usize {
    (VERIFY_PER_SECOND as u128 * SLICE.as_millis() / 1000) as usize
}

/// Why a frame was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drop {
    Malformed(String),
    Duplicate,
    /// The claim is unknown to this node (yet): the frame waits in the pending set.
    UnknownClaim,
    NotMember(u16),
    WrongRefHeight(u16),
    Claimable(u16),
    /// A valid entry of this seq is already held for the claim.
    AlreadyHeld(u16),
    BadSignature(u16),
    SeqRate(u16),
}

/// What the verifier needs to know about one claim.
#[derive(Clone, Debug)]
pub struct ClaimCtx {
    pub ref_height: u32,
    /// blockHash(refHeight), internal byte order.
    pub block_hash: [u8; 32],
    pub collateral_zat: i64,
    pub minted_cents: i64,
    /// Seqs whose valid entry the agent already holds.
    pub held: BTreeSet<u16>,
}

/// The agent's view, replaced after every poll.
#[derive(Clone, Debug, Default)]
pub struct Ctx {
    pub view: MemberView,
    /// By claimant intent ("txid:n").
    pub claims: HashMap<String, ClaimCtx>,
}

/// A verified co-signature for the agent, with the refHeight and hash it was verified against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub intent: String,
    pub seq: u16,
    pub ref_height: u32,
    pub block_hash: [u8; 32],
    pub entry_hex: String,
}

/// xorshift64*: the sampler needs uniform choices, not secrecy; seeded from the clock in production, fixed in tests.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    pub fn from_clock() -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15);
        Rng::new(n ^ (std::process::id() as u64).rotate_left(32))
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        // the modulo bias over 64 bits is far below anything a sampler can notice
        self.next() % n
    }
}

/// A uniform sample of at most `cap` of the items offered since the last `take` (Algorithm R).
pub struct Reservoir<T> {
    cap: usize,
    seen: u64,
    items: Vec<T>,
}

impl<T> Reservoir<T> {
    pub fn new(cap: usize) -> Self {
        Reservoir {
            cap: cap.max(1),
            seen: 0,
            items: Vec::new(),
        }
    }

    pub fn offer(&mut self, item: T, rng: &mut Rng) {
        self.seen += 1;
        if self.items.len() < self.cap {
            self.items.push(item);
        } else {
            let j = rng.below(self.seen) as usize;
            if j < self.cap {
                self.items[j] = item;
            }
        }
    }

    /// The sample, and how many were offered in all.
    pub fn take(&mut self) -> (Vec<T>, u64) {
        let seen = std::mem::take(&mut self.seen);
        (std::mem::take(&mut self.items), seen)
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct Verifier {
    ctx: Arc<Ctx>,
    rng: Rng,
    reservoir: Reservoir<Frame>,
    pending: Vec<(Frame, Instant)>,
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    /// (intent, seq, refHeight, blockHash) verified since the context was taken (N-3a between updates).
    accepted: HashSet<(String, u16, u32, [u8; 32])>,
    seq_burst: f64,
    seq_per_second: f64,
    seqs: BTreeMap<u16, Bucket>,
    /// Counters for the log: offered to the sampler, sampled, verified.
    pub offered: u64,
    pub sampled: u64,
    pub verified: u64,
}

impl Verifier {
    pub fn new(seq_burst: u32, seq_refill_seconds: u64, budget: usize, rng: Rng) -> Self {
        Verifier {
            ctx: Arc::new(Ctx::default()),
            rng,
            reservoir: Reservoir::new(budget),
            pending: Vec::new(),
            seen: HashSet::new(),
            order: VecDeque::new(),
            accepted: HashSet::new(),
            seq_burst: seq_burst.max(1) as f64,
            seq_per_second: 1.0 / seq_refill_seconds.max(1) as f64,
            seqs: BTreeMap::new(),
            offered: 0,
            sampled: 0,
            verified: 0,
        }
    }

    /// A new view: the pending frames are offered again.
    pub fn set_ctx(&mut self, ctx: Arc<Ctx>, now: Instant) {
        self.ctx = ctx;
        self.accepted.clear();
        let pending = std::mem::take(&mut self.pending);
        for (f, at) in pending {
            if now.saturating_duration_since(at) < PENDING_TTL {
                let _ = self.classify(f, at);
            }
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

    /// The cheap checks; on success the frame is offered to the sampler.
    fn classify(&mut self, f: Frame, at: Instant) -> Result<(), Drop> {
        let intent = f.intent();
        let seq = f.seq;
        if !self.ctx.view.members.contains_key(&seq) {
            return Err(Drop::NotMember(seq));
        }
        let Some(c) = self.ctx.claims.get(&intent) else {
            // random replacement when full: a flood of frames for invented claims cannot hold the set
            if self.pending.len() < PENDING_MAX {
                self.pending.push((f, at));
            } else {
                let j = self.rng.below(PENDING_MAX as u64) as usize;
                self.pending[j] = (f, at);
            }
            return Err(Drop::UnknownClaim);
        };
        if f.ref_height != c.ref_height {
            return Err(Drop::WrongRefHeight(seq));
        }
        if (f.entry.price as i64) < 100
            || cosig::is_underwater(
                c.collateral_zat,
                f.entry.price as i64,
                c.minted_cents,
                self.ctx.view.theta_bps,
            )
        {
            return Err(Drop::Claimable(seq));
        }
        if c.held.contains(&seq) || self.accepted.contains(&(intent, seq, c.ref_height, c.block_hash)) {
            return Err(Drop::AlreadyHeld(seq));
        }
        self.offered += 1;
        self.reservoir.offer(f, &mut self.rng);
        Ok(())
    }

    /// A frame off the topic.
    pub fn intake(&mut self, bytes: &[u8], now: Instant) -> Result<(), Drop> {
        let f = Frame::decode(bytes).map_err(|e| Drop::Malformed(e.to_string()))?;
        let d: [u8; 32] = Sha256::digest(bytes).into();
        if self.seen.contains(&d) {
            return Err(Drop::Duplicate);
        }
        self.classify(f, now)
    }

    /// The end of a slice: verify the sample, drop the rest.
    pub fn run_slice(&mut self, now: Instant) -> Vec<Verified> {
        let (sample, _offered) = self.reservoir.take();
        self.sampled += sample.len() as u64;
        let mut out = Vec::new();
        for f in sample {
            match self.verify(&f, now) {
                Ok(v) => out.push(v),
                Err(d) => tracing::debug!("cancel topic: frame {f:?} dropped: {d:?}"),
            }
        }
        out
    }

    fn verify(&mut self, f: &Frame, now: Instant) -> Result<Verified, Drop> {
        let intent = f.intent();
        let seq = f.seq;
        let ctx = self.ctx.clone();
        let key = ctx.view.members.get(&seq).ok_or(Drop::NotMember(seq))?;
        let c = ctx.claims.get(&intent).ok_or(Drop::UnknownClaim)?;
        if self
            .accepted
            .contains(&(intent.clone(), seq, c.ref_height, c.block_hash))
        {
            return Err(Drop::AlreadyHeld(seq)); // two copies drawn in one slice
        }
        let msg = cosig::message(
            &ctx.view.set_id,
            &f.txid,
            f.n,
            c.ref_height,
            f.entry.price,
            &c.block_hash,
        );
        self.remember(Sha256::digest(f.encode()).into());
        if cosig::recover(&msg, &f.entry.sig).as_ref() != Some(key) {
            return Err(Drop::BadSignature(seq));
        }
        let b = self.seqs.entry(seq).or_insert(Bucket {
            tokens: self.seq_burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.seq_per_second).min(self.seq_burst);
        b.last = now;
        if b.tokens < 1.0 {
            return Err(Drop::SeqRate(seq));
        }
        b.tokens -= 1.0;
        self.verified += 1;
        self.accepted.insert((intent.clone(), seq, c.ref_height, c.block_hash));
        Ok(Verified {
            intent,
            seq,
            ref_height: c.ref_height,
            block_hash: c.block_hash,
            entry_hex: f.entry.to_hex(),
        })
    }
}

/// The verifier's task: frames from the pump, the agent's view after each poll, a slice timer; verified entries to
/// the agent. It ends -- and the agent sees its output close -- when the pump's channel closes.
pub fn spawn(
    mut frames: tokio::sync::mpsc::Receiver<crate::transport::Delivered>,
    mut ctx: tokio::sync::watch::Receiver<Arc<Ctx>>,
    out: tokio::sync::mpsc::Sender<Verified>,
    seq_burst: u32,
    seq_refill_seconds: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut v = Verifier::new(seq_burst, seq_refill_seconds, slice_budget(), Rng::from_clock());
        let mut tick = tokio::time::interval(SLICE);
        loop {
            tokio::select! {
                got = frames.recv() => match got {
                    Some((bytes, peer)) => {
                        if let Err(d) = v.intake(&bytes, Instant::now()) {
                            tracing::trace!("cancel topic: from {peer}: {d:?}");
                        }
                    }
                    None => {
                        tracing::error!("cancel topic: the transport task is gone; the verifier stops");
                        return;
                    }
                },
                changed = ctx.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let c = ctx.borrow_and_update().clone();
                    v.set_ctx(c, Instant::now());
                }
                _ = tick.tick() => {
                    for item in v.run_slice(Instant::now()) {
                        if out.send(item).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosig::{testkit, Entry};

    const THETA: u32 = 12_500;
    const COLL: i64 = 75 * 100_000_000;

    fn ctx(keys: &[(u16, u8)]) -> Arc<Ctx> {
        let mut claims = HashMap::new();
        claims.insert(
            format!("{}:0", cosig::display_of_internal(&[0xaa; 32])),
            ClaimCtx {
                ref_height: 99,
                block_hash: [0x33; 32],
                collateral_zat: COLL,
                minted_cents: 10_000,
                held: BTreeSet::new(),
            },
        );
        Arc::new(Ctx {
            view: MemberView {
                set_id: [0x75; 32],
                theta_bps: THETA,
                members: keys
                    .iter()
                    .map(|(s, k)| (*s, testkit::pubkey(&testkit::key(*k))))
                    .collect(),
            },
            claims,
        })
    }

    fn frame(seq: u16, key: u8, price: u32) -> Vec<u8> {
        let txid = [0xaa; 32];
        let msg = cosig::message(&[0x75; 32], &txid, 0, 99, price, &[0x33; 32]);
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

    /// A forged frame: a member's seq, the right claim, a non-claimable price, a signature by another key. It
    /// passes every cheap check and costs one recovery to reject.
    fn forged(seq: u16, i: u32) -> Vec<u8> {
        // one real signature by a non-member key, reused under every price: well-formed, unique bytes, never valid
        static SIG: std::sync::OnceLock<[u8; 65]> = std::sync::OnceLock::new();
        let sig = *SIG.get_or_init(|| {
            testkit::sign(
                &testkit::key(99),
                &cosig::message(&[0x75; 32], &[0xaa; 32], 0, 99, 1, &[0x33; 32]),
            )
        });
        Frame {
            txid: [0xaa; 32],
            n: 0,
            seq,
            ref_height: 99,
            entry: Entry {
                price: 4_000_000 + i,
                sig,
            },
        }
        .encode()
        .to_vec()
    }

    #[test]
    fn the_cheap_checks_then_the_signature() {
        let now = Instant::now();
        let mut v = Verifier::new(4, 60, 100, Rng::new(1));
        v.set_ctx(ctx(&[(1, 1), (2, 2)]), now);
        assert!(matches!(v.intake(&[0u8; 116], now), Err(Drop::Malformed(_))));
        assert_eq!(v.intake(&frame(7, 7, 4_000_000), now), Err(Drop::NotMember(7)));
        assert_eq!(v.intake(&frame(1, 1, 1_600_000), now), Err(Drop::Claimable(1)));
        assert_eq!(v.intake(&forged(2, 0), now), Ok(())); // the cheap checks cannot tell ...
        assert_eq!(v.intake(&frame(1, 1, 4_000_000), now), Ok(()));
        let out = v.run_slice(now); // ... the signature can
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].seq, out[0].ref_height), (1, 99));
        // verified frames are remembered: a second copy is a duplicate, before any check
        assert_eq!(v.intake(&frame(1, 1, 4_000_000), now), Err(Drop::Duplicate));
        // a second, different statement of a seq already accepted is not verified again (N-3a)
        assert_eq!(v.intake(&frame(1, 1, 4_000_001), now), Err(Drop::AlreadyHeld(1)));
        // nor one the agent already holds
        let mut c = (*ctx(&[(1, 1), (2, 2)])).clone();
        c.claims.values_mut().for_each(|x| {
            x.held.insert(2);
        });
        v.set_ctx(Arc::new(c), now);
        assert_eq!(v.intake(&frame(2, 2, 4_000_000), now), Err(Drop::AlreadyHeld(2)));
    }

    #[test]
    fn unknown_claims_wait_and_are_offered_again() {
        let now = Instant::now();
        let mut v = Verifier::new(4, 60, 100, Rng::new(2));
        let mut empty = (*ctx(&[(1, 1)])).clone();
        empty.claims.clear();
        v.set_ctx(Arc::new(empty), now);
        assert_eq!(v.intake(&frame(1, 1, 4_000_000), now), Err(Drop::UnknownClaim));
        assert!(v.run_slice(now).is_empty());
        v.set_ctx(ctx(&[(1, 1)]), now); // the agent learnt the claim
        assert_eq!(v.run_slice(now).len(), 1);
        // a flood of frames for invented claims keeps the pending set bounded
        let mut empty = (*ctx(&[(1, 1)])).clone();
        empty.claims.clear();
        v.set_ctx(Arc::new(empty), now);
        for i in 0..5_000u32 {
            let _ = v.intake(&forged(1, i), now);
        }
        assert!(v.pending.len() <= PENDING_MAX);
    }

    #[test]
    fn the_reservoir_is_a_uniform_sample() {
        let mut rng = Rng::new(7);
        let mut hits = [0u32; 10];
        for _ in 0..20_000 {
            let mut r = Reservoir::new(1);
            for i in 0..10usize {
                r.offer(i, &mut rng);
            }
            let (s, seen) = r.take();
            assert_eq!(seen, 10);
            hits[s[0]] += 1;
        }
        for h in hits {
            assert!((1_700..2_300).contains(&h), "{hits:?}"); // 2,000 expected each
        }
    }

    /// N-3: a 20,000 frames/s flood of forged frames that pass every cheap check, an honest member republishing
    /// once per block (75 s on mainnet; one second of flood per block here is the attacker's best case per copy).
    /// With the 2,000/s budget each copy is drawn with probability ~0.1, so the honest frame gets through within 60
    /// blocks with probability 1 - 0.9^60 > 0.998. Seeded, so deterministic; the bound is checked over 200 seeds.
    #[test]
    fn a_flood_cannot_starve_an_honest_frame() {
        let flood_per_slice = 20_000 * SLICE.as_millis() as usize / 1000; // 5,000 per slice
        let honest = frame(1, 1, 4_000_000);
        // the sampler alone (no signatures) over many seeds: blocks until the honest copy is drawn
        let mut worst = 0;
        let mut within = 0;
        for seed in 1..=200u64 {
            let mut rng = Rng::new(seed);
            let mut blocks = 0;
            loop {
                blocks += 1;
                let mut r = Reservoir::new(slice_budget());
                let at = rng.below(flood_per_slice as u64 + 1) as usize;
                for i in 0..=flood_per_slice {
                    r.offer(if i == at { usize::MAX } else { i }, &mut rng);
                }
                if r.take().0.contains(&usize::MAX) || blocks > 200 {
                    break;
                }
            }
            worst = worst.max(blocks);
            if blocks <= 60 {
                within += 1;
            }
        }
        assert!(
            within >= 199,
            "honest frame drawn within 60 blocks in only {within}/200 seeds (worst {worst})"
        );
        // end to end through the verifier, one seed: the flood with real (failing) recoveries
        let now = Instant::now();
        let mut v = Verifier::new(4, 60, slice_budget(), Rng::new(42));
        v.set_ctx(ctx(&[(1, 1), (2, 2)]), now);
        let mut got = None;
        for block in 1..=60 {
            // fresh forged frames every block (a remembered one would be a cheap duplicate)
            for i in 0..flood_per_slice as u32 {
                if i as usize == flood_per_slice / 2 {
                    let _ = v.intake(&honest, now);
                }
                let _ = v.intake(&forged(2, block * 1_000_000 + i), now);
            }
            if v.run_slice(now).iter().any(|x| x.seq == 1) {
                got = Some(block);
                break;
            }
        }
        assert!(got.is_some(), "the honest frame never got through in 60 blocks");
        assert!(v.sampled <= 60 * slice_budget() as u64, "the budget bounds the work");
    }
}
