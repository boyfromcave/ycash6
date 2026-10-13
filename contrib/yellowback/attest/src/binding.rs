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
//! A binding is valid while its network and set are ours, it has not expired, its signature recovers to the
//! current member key of its seq, and (per seq) no binding with a later `issuedHeight` is held. On the wire
//! ([`Announce`]) it travels with unsigned address hints (the endpoint's direct addresses and relay): the hints help
//! a dialer find the endpoint, the connection itself authenticates the id.

use std::collections::BTreeMap;

use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREFIX: &str = "YED-IROH-1";
pub const MESSAGE_MAGIC: &str = "Zcash Signed Message:\n";
pub const ANNOUNCE_MAGIC: &[u8; 4] = b"YBD1";
/// An announce never exceeds this (the message, the signature, at most 8 short address hints and a relay URL).
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

/// A signed binding: the statement's text and the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub message: String,
    #[serde(with = "hex_sig")]
    pub sig: [u8; 65],
}

mod hex_sig {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 65], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 65], D::Error> {
        let h = String::deserialize(d)?;
        hex::decode(h)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("binding signature: not 65 bytes of hex"))
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
    /// The seq is not a current member.
    NotMember,
    /// The signature does not recover to the seq's member key: forged, or signed for another seq.
    BadSignature,
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

    /// Verify against our network, set, the tip and the current members (seq -> member key).
    pub fn verify(
        &self,
        network: &str,
        set_id_hex: &str,
        tip: u32,
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
        let key = members.get(&st.seq).ok_or(Refusal::NotMember)?;
        if recover_signer(&self.message, &self.sig).as_ref() != Some(key) {
            return Err(Refusal::BadSignature);
        }
        Ok(st)
    }
}

/// A binding as announced: the signed binding plus unsigned address hints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announce {
    pub binding: Binding,
    /// Direct socket addresses, "ip:port".
    pub addrs: Vec<String>,
    pub relay: Option<String>,
}

impl Announce {
    /// `"YBD1" ‖ u16 len ‖ message ‖ sig65 ‖ u8 n ‖ n × (u8 len ‖ addr) ‖ u8 len ‖ relay`
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(ANNOUNCE_MAGIC);
        let m = self.binding.message.as_bytes();
        out.extend_from_slice(&(m.len() as u16).to_le_bytes());
        out.extend_from_slice(m);
        out.extend_from_slice(&self.binding.sig);
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
            addrs,
            relay,
        })
    }
}

/// The bindings an agent holds, by seq: the valid one with the latest `issuedHeight` wins.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Store {
    pub by_seq: BTreeMap<u16, (Statement, Announce)>,
}

impl Store {
    /// Take an announce; true when it changed the table.
    pub fn offer(
        &mut self,
        a: Announce,
        network: &str,
        set_id_hex: &str,
        tip: u32,
        members: &BTreeMap<u16, [u8; 33]>,
    ) -> Result<bool, Refusal> {
        // cheap first: an announce no newer than the one held costs no recovery
        if let Some(st) = Statement::parse(&a.binding.message) {
            if let Some((held, held_a)) = self.by_seq.get(&st.seq) {
                if held.issued > st.issued || (held.issued == st.issued && held_a.binding == a.binding) {
                    if held.issued == st.issued && held_a.binding == a.binding && held_a.addrs != a.addrs {
                        // the same binding with fresher address hints
                        let entry = self.by_seq.get_mut(&st.seq).expect("held");
                        entry.1.addrs = a.addrs;
                        entry.1.relay = a.relay;
                        return Ok(true);
                    }
                    return Ok(false);
                }
            }
        }
        let st = a.binding.verify(network, set_id_hex, tip, members)?;
        self.by_seq.insert(st.seq, (st, a));
        Ok(true)
    }

    /// Drop bindings that expired or whose seq is no longer a current member.
    pub fn prune(&mut self, tip: u32, members: &BTreeMap<u16, [u8; 33]>) {
        self.by_seq
            .retain(|seq, (st, _)| st.expiry > tip && members.contains_key(seq));
    }

    /// The bound endpoints: endpoint id -> (seq, announce).
    pub fn endpoints(&self) -> BTreeMap<[u8; 32], (u16, Announce)> {
        self.by_seq
            .iter()
            .map(|(seq, (st, a))| (st.endpoint, (*seq, a.clone())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosig::testkit;

    const SET: &str = "755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e755e";

    fn sign(key: u8, msg: &str) -> [u8; 65] {
        testkit::sign(&testkit::key(key), &message_hash(msg))
    }

    fn statement(seq: u16, endpoint: u8, issued: u32, expiry: u32) -> Statement {
        Statement {
            network: "regtest".into(),
            set_id_hex: SET.into(),
            seq,
            endpoint: [endpoint; 32],
            issued,
            expiry,
        }
    }

    fn members() -> BTreeMap<u16, [u8; 33]> {
        [
            (1u16, testkit::pubkey(&testkit::key(1))),
            (2, testkit::pubkey(&testkit::key(2))),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn the_message_hash_is_signmessages() {
        // compact(22) ‖ "Zcash Signed Message:\n" ‖ compact(len) ‖ msg, hashed twice
        let msg = "hello";
        let mut pre = vec![22u8];
        pre.extend_from_slice(b"Zcash Signed Message:\n");
        pre.push(5);
        pre.extend_from_slice(b"hello");
        let want: [u8; 32] = Sha256::digest(Sha256::digest(&pre)).into();
        assert_eq!(message_hash(msg), want);
        // a message longer than 252 bytes takes the 3-byte compact size
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
        let st = statement(1, 7, 100, 200);
        let b = Binding {
            message: st.message(),
            sig: sign(1, &st.message()),
        };
        assert_eq!(b.verify("regtest", SET, 150, &members()), Ok(st.clone()));
        let b64 = base64::engine::general_purpose::STANDARD.encode(b.sig);
        assert_eq!(Binding::from_signmessage(st.message(), &b64), Some(b));
    }

    #[test]
    fn forged_expired_and_wrong_seq_bindings_are_refused() {
        let m = members();
        // forged: signed by a key that is no member's
        let st = statement(1, 7, 100, 200);
        let forged = Binding {
            message: st.message(),
            sig: sign(9, &st.message()),
        };
        assert_eq!(forged.verify("regtest", SET, 150, &m), Err(Refusal::BadSignature));
        // wrong seq: member 2 signs a statement claiming seat 1
        let wrong = Binding {
            message: st.message(),
            sig: sign(2, &st.message()),
        };
        assert_eq!(wrong.verify("regtest", SET, 150, &m), Err(Refusal::BadSignature));
        // a seq that is not a current member
        let st9 = statement(9, 7, 100, 200);
        let b9 = Binding {
            message: st9.message(),
            sig: sign(9, &st9.message()),
        };
        assert_eq!(b9.verify("regtest", SET, 150, &m), Err(Refusal::NotMember));
        // expired, and issued in the future
        let ok = Binding {
            message: st.message(),
            sig: sign(1, &st.message()),
        };
        assert_eq!(ok.verify("regtest", SET, 200, &m), Err(Refusal::Expired));
        assert_eq!(ok.verify("regtest", SET, 97, &m), Err(Refusal::NotYet));
        // another network or set
        assert_eq!(ok.verify("main", SET, 150, &m), Err(Refusal::WrongNetwork));
        assert_eq!(ok.verify("regtest", &"00".repeat(32), 150, &m), Err(Refusal::WrongSet));
        // a tampered message (the endpoint changed after signing)
        let mut t = st.clone();
        t.endpoint = [8; 32];
        let tampered = Binding {
            message: t.message(),
            sig: ok.sig,
        };
        assert_eq!(tampered.verify("regtest", SET, 150, &m), Err(Refusal::BadSignature));
        // non-canonical text is malformed
        let odd = Binding {
            message: st.message().replace("|100|", "|0100|"),
            sig: ok.sig,
        };
        assert_eq!(odd.verify("regtest", SET, 150, &m), Err(Refusal::Malformed));
    }

    #[test]
    fn announces_round_trip_and_are_bounded() {
        let st = statement(1, 7, 100, 200);
        let a = Announce {
            binding: Binding {
                message: st.message(),
                sig: sign(1, &st.message()),
            },
            addrs: vec!["127.0.0.1:4433".into(), "[::1]:4433".into()],
            relay: Some("https://relay.example".into()),
        };
        let b = a.encode();
        assert!(b.len() < ANNOUNCE_MAX);
        assert_eq!(Announce::decode(&b), Some(a.clone()));
        let mut long = b.clone();
        long.push(0);
        assert_eq!(Announce::decode(&long), None);
        assert_eq!(Announce::decode(&b[..b.len() - 1]), None);
        assert_eq!(Announce::decode(b"YBD2xxxxxx"), None);
    }

    #[test]
    fn the_store_keeps_the_latest_valid_binding_per_seq() {
        let m = members();
        let mk = |seq: u16, key: u8, ep: u8, issued: u32| {
            let st = statement(seq, ep, issued, issued + 100);
            Announce {
                binding: Binding {
                    message: st.message(),
                    sig: sign(key, &st.message()),
                },
                addrs: vec![],
                relay: None,
            }
        };
        let mut s = Store::default();
        assert_eq!(s.offer(mk(1, 1, 7, 100), "regtest", SET, 150, &m), Ok(true));
        assert_eq!(s.offer(mk(1, 1, 7, 100), "regtest", SET, 150, &m), Ok(false)); // the same again
        assert_eq!(s.offer(mk(1, 1, 8, 90), "regtest", SET, 150, &m), Ok(false)); // older: ignored unverified
        assert_eq!(
            s.offer(mk(1, 2, 9, 120), "regtest", SET, 150, &m),
            Err(Refusal::BadSignature)
        ); // forged rebind
        assert_eq!(s.offer(mk(1, 1, 8, 120), "regtest", SET, 150, &m), Ok(true)); // a rotation
        assert_eq!(s.endpoints().keys().copied().collect::<Vec<_>>(), vec![[8u8; 32]]);
        s.prune(250, &m);
        assert!(s.by_seq.is_empty());
    }
}
