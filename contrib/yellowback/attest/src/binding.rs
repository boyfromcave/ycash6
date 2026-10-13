// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The endpoint binding (docs/plans/yellowback-attest-gossip-evaluation.md §4.2, owner decision 1, 2026-10-13): one
//! statement a member signs with its member key through the node's stock `signmessage`, binding the agent's direct
//! iroh endpoint id to its seat:
//!
//! ```text
//! YED-IROH-1|<network>|<attestorSetId hex>|<seq>|<endpoint id hex>|<issuedHeight>|<expiryHeight>
//! ```
//!
//! `signmessage` signs `SHA256d(compact(magic) ‖ magic ‖ compact(msg) ‖ msg)` with magic "Zcash Signed Message:\n"
//! (ycash-dd `src/main.cpp:141`, ycash6 `src/main.cpp:156`: the same string on both lines) and returns the 65-byte
//! compact recoverable signature in base64. The prefix cannot collide with a sighash, an attestation or a cancel
//! co-signature, and the statement says nothing about a price, so it cannot be used for EQV-1.
//!
//! **Proof of possession.** The endpoint's own key (ed25519) also signs
//! `"YED-IROH-POP-2|" ‖ statement ‖ "|" ‖ hintSeq ‖ "|" ‖ addrs ‖ "|" ‖ relay` (reviews B-1, N-B): a member cannot bind
//! another member's endpoint id, because it does not hold that endpoint's key; and the dial hints are signed by the
//! endpoint itself, so any copy of an announce carries authenticated hints, a replay with altered hints fails, and
//! hints from a proof with a higher `hintSeq` replace older ones. The agent re-signs the proof locally whenever its
//! addresses change (no node call; the `signmessage` statement is unchanged). On top of that, a binding whose
//! endpoint id another current seq already holds is refused (`binding-conflict`).
//!
//! A binding is valid while its network and set are ours, it has not expired, its life is at most the configured TTL,
//! its member signature recovers to the current member key of its seq, its proof of possession verifies, and (per
//! seq) no binding with a later `issuedHeight` is held. On the wire ([`Announce`]) it travels with its endpoint-signed
//! hints.

use std::collections::BTreeMap;

use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREFIX: &str = "YED-IROH-1";
pub const POP_PREFIX: &str = "YED-IROH-POP-2|";
pub const MESSAGE_MAGIC: &str = "Zcash Signed Message:\n";
pub const ANNOUNCE_MAGIC: &[u8; 4] = b"YBD3";
/// An announce never exceeds this (the message, both signatures, at most 8 short address hints and a relay URL).
pub const ANNOUNCE_MAX: usize = 1024;
pub const ADDRS_MAX: usize = 8;

/// The parsed statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub network: String,
    pub set_id_hex: String,
    pub seq: u16,
    pub endpoint: [u8; 32],
    pub issued: u32,
    pub expiry: u32,
}

impl Statement {
    pub fn message(&self) -> String {
        format!(
            "{PREFIX}|{}|{}|{}|{}|{}|{}",
            self.network,
            self.set_id_hex,
            self.seq,
            hex::encode(self.endpoint),
            self.issued,
            self.expiry
        )
    }

    pub fn parse(msg: &str) -> Option<Statement> {
        let parts: Vec<&str> = msg.split('|').collect();
        if parts.len() != 7 || parts[0] != PREFIX {
            return None;
        }
        let endpoint: [u8; 32] = hex::decode(parts[4]).ok()?.try_into().ok()?;
        if parts[2].len() != 64 || hex::decode(parts[2]).is_err() {
            return None;
        }
        let s = Statement {
            network: parts[1].to_string(),
            set_id_hex: parts[2].to_string(),
            seq: parts[3].parse().ok()?,
            endpoint,
            issued: parts[5].parse().ok()?,
            expiry: parts[6].parse().ok()?,
        };
        // canonical text only: a re-rendering must give the same bytes that were signed
        (s.message() == msg).then_some(s)
    }
}

fn compact_size(n: usize, out: &mut Vec<u8>) {
    if n < 253 {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(253);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(254);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
}

/// The digest `signmessage` signs.
pub fn message_hash(msg: &str) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + msg.len());
    compact_size(MESSAGE_MAGIC.len(), &mut buf);
    buf.extend_from_slice(MESSAGE_MAGIC.as_bytes());
    compact_size(msg.len(), &mut buf);
    buf.extend_from_slice(msg.as_bytes());
    Sha256::digest(Sha256::digest(&buf)).into()
}

/// The bytes the endpoint key signs for the proof of possession: the statement and the dial hints.
pub fn pop_message(msg: &str, hint_seq: u64, addrs: &[String], relay: Option<&str>) -> Vec<u8> {
    let mut b = POP_PREFIX.as_bytes().to_vec();
    b.extend_from_slice(msg.as_bytes());
    b.extend_from_slice(format!("|{hint_seq}|{}|{}", addrs.join(","), relay.unwrap_or("")).as_bytes());
    b
}

/// The compressed key a `signmessage` signature recovers to (header 31..34: a compressed key; low S, as the node
/// produces). None otherwise.
pub fn recover_signer(msg: &str, sig: &[u8; 65]) -> Option<[u8; 33]> {
    if !(31..=34).contains(&sig[0]) {
        return None;
    }
    let s = Signature::from_slice(&sig[1..]).ok()?;
    if s.normalize_s().is_some() {
        return None;
    }
    let recid = RecoveryId::from_byte(sig[0] - 31)?;
    let key = VerifyingKey::recover_from_prehash(&message_hash(msg), &s, recid).ok()?;
    key.to_encoded_point(true).as_bytes().try_into().ok()
}

/// A signed binding: the statement's text and the member key's signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub message: String,
    #[serde(with = "hex_bytes")]
    pub sig: [u8; 65],
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        let h = String::deserialize(d)?;
        hex::decode(h)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("wrong length of hex"))
    }
}

/// Why a binding is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    WrongNetwork,
    WrongSet,
    Expired,
    /// Issued in the future (beyond a small slack).
    NotYet,
    /// Valid for longer than the configured TTL.
    TooLong,
    /// The seq is not a current member.
    NotMember,
    /// The signature does not recover to the seq's member key: forged, or signed for another seq.
    BadSignature,
    /// The endpoint key's proof of possession does not verify.
    BadPossession,
    /// Another current seq already holds a binding of this endpoint id.
    EndpointConflict(u16),
}

impl Binding {
    /// From `signmessage`'s base64.
    pub fn from_signmessage(message: String, b64: &str) -> Option<Binding> {
        let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
        Some(Binding {
            message,
            sig: raw.try_into().ok()?,
        })
    }

    /// The checks that cost nothing: the text, our network and set, the validity window, the TTL bound, a current
    /// member's seq.
    pub fn precheck(
        &self,
        network: &str,
        set_id_hex: &str,
        tip: u32,
        max_ttl: u32,
        members: &BTreeMap<u16, [u8; 33]>,
    ) -> Result<Statement, Refusal> {
        let st = Statement::parse(&self.message).ok_or(Refusal::Malformed)?;
        if st.network != network {
            return Err(Refusal::WrongNetwork);
        }
        if !st.set_id_hex.eq_ignore_ascii_case(set_id_hex) {
            return Err(Refusal::WrongSet);
        }
        if st.expiry <= tip {
            return Err(Refusal::Expired);
        }
        if st.issued > tip.saturating_add(2) {
            return Err(Refusal::NotYet);
        }
        if st.expiry > st.issued.saturating_add(max_ttl) {
            return Err(Refusal::TooLong);
        }
        if !members.contains_key(&st.seq) {
            return Err(Refusal::NotMember);
        }
        Ok(st)
    }

    /// The member key's signature (one secp256k1 recovery) after [`Binding::precheck`].
    pub fn verify(
        &self,
        network: &str,
        set_id_hex: &str,
        tip: u32,
        max_ttl: u32,
        members: &BTreeMap<u16, [u8; 33]>,
    ) -> Result<Statement, Refusal> {
        let st = self.precheck(network, set_id_hex, tip, max_ttl, members)?;
        let key = members.get(&st.seq).ok_or(Refusal::NotMember)?;
        if recover_signer(&self.message, &self.sig).as_ref() != Some(key) {
            return Err(Refusal::BadSignature);
        }
        Ok(st)
    }
}

/// A binding as announced: the signed binding, the dial hints, and the endpoint key's proof of possession over
/// both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announce {
    pub binding: Binding,
    /// Orders the endpoint's hint updates: a valid proof with a higher one replaces the hints held.
    pub hint_seq: u64,
    #[serde(with = "hex_bytes")]
    pub pop: [u8; 64],
    /// Direct socket addresses, "ip:port".
    pub addrs: Vec<String>,
    pub relay: Option<String>,
}

impl Announce {
    /// Make an announce: `endpoint_key` signs the proof of possession over the statement and the hints.
    pub fn new(
        binding: Binding,
        endpoint_key: &iroh::SecretKey,
        addrs: Vec<String>,
        relay: Option<String>,
        hint_seq: u64,
    ) -> Self {
        let addrs: Vec<String> = addrs.into_iter().filter(|a| a.len() < 64).take(ADDRS_MAX).collect();
        let relay = relay.filter(|r| r.len() < 200);
        let pop = endpoint_key
            .sign(&pop_message(&binding.message, hint_seq, &addrs, relay.as_deref()))
            .to_bytes();
        Announce {
            binding,
            hint_seq,
            pop,
            addrs,
            relay,
        }
    }

    /// Re-sign the proof for new hints (a higher `hint_seq`), the binding unchanged.
    pub fn with_hints(
        &self,
        endpoint_key: &iroh::SecretKey,
        addrs: Vec<String>,
        relay: Option<String>,
        hint_seq: u64,
    ) -> Self {
        Announce::new(self.binding.clone(), endpoint_key, addrs, relay, hint_seq)
    }

    /// The proof of possession -- over the statement and the hints -- verifies under the statement's endpoint id.
    pub fn possession_ok(&self, st: &Statement) -> bool {
        let Ok(pk) = iroh::PublicKey::from_bytes(&st.endpoint) else {
            return false;
        };
        let msg = pop_message(&self.binding.message, self.hint_seq, &self.addrs, self.relay.as_deref());
        pk.verify(&msg, &iroh::Signature::from_bytes(&self.pop)).is_ok()
    }

    /// SHA-256 of the encoding: the dedup key (review N-C: a look-alike never displaces the genuine copy).
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }

    /// `"YBD3" ‖ u16 len ‖ message ‖ sig65 ‖ hintSeq u64 ‖ pop64 ‖ u8 n ‖ n × (u8 len ‖ addr) ‖ u8 len ‖ relay`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(ANNOUNCE_MAGIC);
        let m = self.binding.message.as_bytes();
        out.extend_from_slice(&(m.len() as u16).to_le_bytes());
        out.extend_from_slice(m);
        out.extend_from_slice(&self.binding.sig);
        out.extend_from_slice(&self.hint_seq.to_le_bytes());
        out.extend_from_slice(&self.pop);
        let addrs: Vec<&String> = self.addrs.iter().filter(|a| a.len() < 64).take(ADDRS_MAX).collect();
        out.push(addrs.len() as u8);
        for a in addrs {
            out.push(a.len() as u8);
            out.extend_from_slice(a.as_bytes());
        }
        match self.relay.as_deref().filter(|r| r.len() < 200) {
            Some(r) => {
                out.push(r.len() as u8);
                out.extend_from_slice(r.as_bytes());
            }
            None => out.push(0),
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<Announce> {
        if b.len() > ANNOUNCE_MAX || b.len() < 6 || &b[0..4] != ANNOUNCE_MAGIC {
            return None;
        }
        let mut i = 4;
        let take = |i: &mut usize, n: usize| -> Option<&[u8]> {
            let s = b.get(*i..*i + n)?;
            *i += n;
            Some(s)
        };
        let mlen = u16::from_le_bytes(take(&mut i, 2)?.try_into().ok()?) as usize;
        let message = std::str::from_utf8(take(&mut i, mlen)?).ok()?.to_string();
        let sig: [u8; 65] = take(&mut i, 65)?.try_into().ok()?;
        let hint_seq = u64::from_le_bytes(take(&mut i, 8)?.try_into().ok()?);
        let pop: [u8; 64] = take(&mut i, 64)?.try_into().ok()?;
        let n = *take(&mut i, 1)?.first()? as usize;
        if n > ADDRS_MAX {
            return None;
        }
        let mut addrs = Vec::with_capacity(n);
        for _ in 0..n {
            let l = *take(&mut i, 1)?.first()? as usize;
            addrs.push(std::str::from_utf8(take(&mut i, l)?).ok()?.to_string());
        }
        let rl = *take(&mut i, 1)?.first()? as usize;
        let relay = if rl == 0 {
            None
        } else {
            Some(std::str::from_utf8(take(&mut i, rl)?).ok()?.to_string())
        };
        if i != b.len() {
            return None;
        }
        Some(Announce {
            binding: Binding { message, sig },
            hint_seq,
            pop,
            addrs,
            relay,
        })
    }
}

/// One seat's binding and its (endpoint-signed) hints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub statement: Statement,
    pub announce: Announce,
}

/// The bindings an agent holds, by seq.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Store {
    pub by_seq: BTreeMap<u16, Held>,
}

impl Store {
    /// Whether a prechecked statement may be worth a recovery: not older than the binding held for its seq.
    pub fn newer_or_same(&self, st: &Statement) -> bool {
        self.by_seq.get(&st.seq).is_none_or(|h| st.issued >= h.statement.issued)
    }

    /// Whether this announce carries the very binding held for its seq (only its hints may differ).
    pub fn holds(&self, a: &Announce, seq: u16) -> bool {
        self.by_seq.get(&seq).is_some_and(|h| h.announce.binding == a.binding)
    }

    /// Newer hints for a held binding (review N-B): the caller has verified this announce's proof of possession;
    /// they replace the held ones only when its `hint_seq` is higher. True when they changed.
    pub fn refresh_hints(&mut self, seq: u16, a: &Announce) -> bool {
        let Some(h) = self.by_seq.get_mut(&seq) else {
            return false;
        };
        if h.announce.binding != a.binding || a.hint_seq <= h.announce.hint_seq {
            return false;
        }
        h.announce = a.clone();
        true
    }

    /// Whether `a` (the binding held) carries newer hints than those held, before its proof is checked.
    pub fn newer_hints(&self, seq: u16, a: &Announce) -> bool {
        self.by_seq
            .get(&seq)
            .is_some_and(|h| h.announce.binding == a.binding && a.hint_seq > h.announce.hint_seq)
    }

    /// Take a verified binding (member signature and proof of possession checked by the caller). Refused when another
    /// current seq holds the same endpoint id (review B-1: the existing binding is kept).
    pub fn commit(&mut self, st: Statement, a: Announce) -> Result<bool, Refusal> {
        if let Some((other, _)) = self
            .by_seq
            .iter()
            .find(|(seq, h)| **seq != st.seq && h.statement.endpoint == st.endpoint)
        {
            return Err(Refusal::EndpointConflict(*other));
        }
        if let Some(h) = self.by_seq.get(&st.seq) {
            if h.statement.issued > st.issued || h.announce.binding == a.binding {
                return Ok(false);
            }
        }
        self.by_seq.insert(
            st.seq,
            Held {
                statement: st,
                announce: a,
            },
        );
        Ok(true)
    }

    /// Drop bindings that expired or whose seq is no longer a current member.
    pub fn prune(&mut self, tip: u32, members: &BTreeMap<u16, [u8; 33]>) {
        self.by_seq
            .retain(|seq, h| h.statement.expiry > tip && members.contains_key(seq));
    }

    /// The bound endpoints: endpoint id -> (seq, announce).
    pub fn endpoints(&self) -> BTreeMap<[u8; 32], (u16, Announce)> {
        self.by_seq
            .iter()
            .map(|(seq, h)| (h.statement.endpoint, (*seq, h.announce.clone())))
            .collect()
    }
}

#[cfg(test)]
pub mod testkit {
    use super::*;
    use crate::cosig::testkit as ck;

    pub const SET: [u8; 32] = [0x75; 32];

    pub fn set_hex() -> String {
        crate::cosig::display_of_internal(&SET)
    }

    /// An endpoint key from a small seed.
    pub fn endpoint_key(seed: u8) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&[seed.max(1); 32])
    }

    pub fn endpoint_id(seed: u8) -> [u8; 32] {
        *endpoint_key(seed).public().as_bytes()
    }

    /// An announce of `seq`, member-signed by `member_key`, possession proven by `pop_key`, for endpoint `endpoint`.
    #[allow(clippy::too_many_arguments)]
    pub fn announce_with(
        seq: u16,
        member_key: u8,
        endpoint: [u8; 32],
        pop_key: &iroh::SecretKey,
        issued: u32,
        expiry: u32,
        addrs: Vec<String>,
    ) -> Announce {
        let st = Statement {
            network: "regtest".into(),
            set_id_hex: set_hex(),
            seq,
            endpoint,
            issued,
            expiry,
        };
        let msg = st.message();
        let b = Binding {
            sig: ck::sign(&ck::key(member_key), &message_hash(&msg)),
            message: msg,
        };
        Announce::new(b, pop_key, addrs, None, 1)
    }

    /// A valid announce: seq's member key `member_key`, its own endpoint `ep_seed`.
    pub fn announce(seq: u16, member_key: u8, ep_seed: u8, issued: u32, expiry: u32) -> Announce {
        announce_with(
            seq,
            member_key,
            endpoint_id(ep_seed),
            &endpoint_key(ep_seed),
            issued,
            expiry,
            vec!["127.0.0.1:1".into()],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::cosig::testkit as ck;

    fn members() -> BTreeMap<u16, [u8; 33]> {
        [(1u16, ck::pubkey(&ck::key(1))), (2, ck::pubkey(&ck::key(2)))]
            .into_iter()
            .collect()
    }

    fn check(a: &Announce, tip: u32) -> Result<Statement, Refusal> {
        let st = a.binding.verify("regtest", &set_hex(), tip, 1_000, &members())?;
        if !a.possession_ok(&st) {
            return Err(Refusal::BadPossession);
        }
        Ok(st)
    }

    #[test]
    fn the_message_hash_is_signmessages() {
        let mut pre = vec![22u8];
        pre.extend_from_slice(b"Zcash Signed Message:\n");
        pre.push(5);
        pre.extend_from_slice(b"hello");
        let want: [u8; 32] = Sha256::digest(Sha256::digest(&pre)).into();
        assert_eq!(message_hash("hello"), want);
        let long = "x".repeat(300);
        let mut pre = vec![22u8];
        pre.extend_from_slice(b"Zcash Signed Message:\n");
        pre.extend_from_slice(&[253, 44, 1]);
        pre.extend_from_slice(long.as_bytes());
        assert_eq!(
            message_hash(&long),
            <[u8; 32]>::from(Sha256::digest(Sha256::digest(&pre)))
        );
    }

    #[test]
    fn a_valid_binding_verifies() {
        let a = announce(1, 1, 7, 100, 200);
        let st = check(&a, 150).unwrap();
        assert_eq!((st.seq, st.endpoint), (1, endpoint_id(7)));
        let b64 = base64::engine::general_purpose::STANDARD.encode(a.binding.sig);
        assert_eq!(
            Binding::from_signmessage(a.binding.message.clone(), &b64),
            Some(a.binding)
        );
    }

    #[test]
    fn forged_expired_and_wrong_seq_bindings_are_refused() {
        // forged: signed by a key that is no member's
        let forged = announce(1, 9, 7, 100, 200);
        assert_eq!(check(&forged, 150), Err(Refusal::BadSignature));
        // wrong seq: member 2 signs a statement claiming seat 1
        assert_eq!(check(&announce(1, 2, 7, 100, 200), 150), Err(Refusal::BadSignature));
        // a seq that is not a current member
        assert_eq!(check(&announce(9, 9, 7, 100, 200), 150), Err(Refusal::NotMember));
        // expired, issued in the future, valid for longer than the TTL
        let ok = announce(1, 1, 7, 100, 200);
        assert_eq!(check(&ok, 200), Err(Refusal::Expired));
        assert_eq!(check(&ok, 97), Err(Refusal::NotYet));
        assert_eq!(check(&announce(1, 1, 7, 100, 1_101), 150), Err(Refusal::TooLong));
        // another network or set
        assert_eq!(
            ok.binding.verify("main", &set_hex(), 150, 1_000, &members()),
            Err(Refusal::WrongNetwork)
        );
        assert_eq!(
            ok.binding.verify("regtest", &"00".repeat(32), 150, 1_000, &members()),
            Err(Refusal::WrongSet)
        );
        // a tampered message (the endpoint changed after signing)
        let st = Statement::parse(&ok.binding.message).unwrap();
        let mut t = st.clone();
        t.endpoint = endpoint_id(8);
        let mut tampered = ok.clone();
        tampered.binding.message = t.message();
        assert_eq!(check(&tampered, 150), Err(Refusal::BadSignature));
        // non-canonical text is malformed
        let mut odd = ok.clone();
        odd.binding.message = ok.binding.message.replace("|100|", "|0100|");
        assert_eq!(check(&odd, 150), Err(Refusal::Malformed));
    }

    /// Review B-1: a member cannot bind another member's endpoint id -- it lacks that endpoint's key.
    #[test]
    fn a_binding_without_possession_of_the_endpoint_is_refused() {
        // member 2 signs (validly, with its own member key) a binding of seat 2 to the endpoint of seed 7, which is
        // member 1's; the proof of possession is made with member 2's own endpoint key (it has no other)
        let stolen = announce_with(2, 2, endpoint_id(7), &endpoint_key(8), 100, 200, vec![]);
        assert_eq!(check(&stolen, 150), Err(Refusal::BadPossession));
    }

    /// Review B-1: even a well-formed binding of an endpoint id another seq holds is refused, the holder kept.
    #[test]
    fn an_endpoint_already_bound_to_another_seq_is_refused() {
        let mut s = Store::default();
        let a1 = announce(1, 1, 7, 100, 200);
        let st1 = check(&a1, 150).unwrap();
        assert_eq!(s.commit(st1, a1), Ok(true));
        // (bypassing the possession check, as if both held the key) seat 2 claims endpoint 7
        let a2 = announce_with(2, 2, endpoint_id(7), &endpoint_key(7), 101, 200, vec![]);
        let st2 = check(&a2, 150).unwrap();
        assert_eq!(s.commit(st2, a2), Err(Refusal::EndpointConflict(1)));
        assert_eq!(s.by_seq[&1].statement.seq, 1);
        assert!(!s.by_seq.contains_key(&2));
    }

    /// Review N-B: the hints are signed by the endpoint. A copy with altered hints fails the proof (whoever relays
    /// it); a newer proof (higher hint_seq) replaces the hints held, an older or equal one does not.
    #[test]
    fn hints_are_signed_by_the_endpoint() {
        let a = announce(1, 1, 7, 100, 200);
        let st = check(&a, 150).unwrap();
        let mut fake = a.clone();
        fake.addrs = vec!["6.6.6.6:6".into()];
        assert!(!fake.possession_ok(&st), "a replay with fake hints fails");
        let mut fake_relay = a.clone();
        fake_relay.relay = Some("https://evil.example".into());
        assert!(!fake_relay.possession_ok(&st));
        let mut s = Store::default();
        s.commit(st.clone(), a.clone()).unwrap();
        let moved = a.with_hints(&endpoint_key(7), vec!["192.168.1.9:4433".into()], None, 2);
        assert!(moved.possession_ok(&st));
        assert!(s.newer_hints(1, &moved));
        assert!(s.refresh_hints(1, &moved));
        assert_eq!(s.by_seq[&1].announce.addrs, vec!["192.168.1.9:4433".to_string()]);
        // a valid but older proof (an old copy replayed) does not roll the hints back
        assert!(!s.newer_hints(1, &a));
        assert!(!s.refresh_hints(1, &a));
        assert_eq!(s.by_seq[&1].announce.hint_seq, 2);
    }

    #[test]
    fn announces_round_trip_and_are_bounded() {
        let a = announce(1, 1, 7, 100, 200).with_hints(
            &endpoint_key(7),
            vec!["127.0.0.1:4433".into(), "[::1]:4433".into()],
            Some("https://relay.example".into()),
            5,
        );
        let b = a.encode();
        assert!(b.len() < ANNOUNCE_MAX);
        assert_eq!(Announce::decode(&b), Some(a.clone()));
        let mut long = b.clone();
        long.push(0);
        assert_eq!(Announce::decode(&long), None);
        assert_eq!(Announce::decode(&b[..b.len() - 1]), None);
        assert_eq!(Announce::decode(b"YBD2xxxxxx"), None);
        assert_ne!(a.digest(), announce(1, 1, 7, 100, 200).digest());
    }

    #[test]
    fn the_store_keeps_the_latest_binding_per_seq() {
        let mut s = Store::default();
        let add = |s: &mut Store, a: Announce| {
            let st = check(&a, 150)?;
            s.commit(st, a)
        };
        assert_eq!(add(&mut s, announce(1, 1, 7, 100, 200)), Ok(true));
        assert_eq!(add(&mut s, announce(1, 1, 7, 100, 200)), Ok(false));
        assert_eq!(add(&mut s, announce(1, 1, 8, 90, 200)), Ok(false)); // older
        assert_eq!(add(&mut s, announce(1, 2, 9, 120, 200)), Err(Refusal::BadSignature));
        assert_eq!(add(&mut s, announce(1, 1, 8, 120, 200)), Ok(true)); // a rotation
        assert_eq!(s.endpoints().keys().copied().collect::<Vec<_>>(), vec![endpoint_id(8)]);
        s.prune(250, &members());
        assert!(s.by_seq.is_empty());
    }
}
