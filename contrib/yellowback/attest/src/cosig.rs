// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The cancel co-signature of the cancel-limit design (CAN-2 + C4b) as the agent sees it: the 69-byte entry the node
//! signs (`yed_signcancelcosign`) and `yed_buildcancel` takes, the message it signs, the public-key recovery that
//! verifies it locally, the claimability arithmetic of a price statement, and the gossip frame that carries one entry
//! between agents.
//!
//! The message is `attest.cpp` `CancelCosignMessage`: SHA256d("YedCancelCosign" ‖ attestorSetId ‖ intent txid ‖
//! n LE32 ‖ refHeight LE32 ‖ price LE32 ‖ blockHash(refHeight)), every hash in its internal (little-endian) byte
//! order, i.e. the reverse of the RPC's hex. The signature is the node's compact recoverable one (`vault::RecoverSig`):
//! header 31..34 (compressed key, recid = header - 31), r, s, low-S.

use std::fmt;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const PREFIX: &[u8; 15] = b"YedCancelCosign";
/// price LE32 ‖ sig65
pub const ENTRY_SIZE: usize = 69;
pub const SIG_SIZE: usize = 65;
/// `CANCEL_COSIGN_MAX` (bundle.h): the most entries one carrier holds.
pub const CANCEL_COSIGN_MAX: usize = 7;
pub const COIN: u128 = 100_000_000;

/// A 32-byte hash in internal byte order, from the RPC's display hex (reversed).
pub fn internal_from_display(hex_str: &str) -> Option<[u8; 32]> {
    let mut b: [u8; 32] = hex::decode(hex_str.trim()).ok()?.try_into().ok()?;
    b.reverse();
    Some(b)
}

pub fn display_of_internal(b: &[u8; 32]) -> String {
    let mut r = *b;
    r.reverse();
    hex::encode(r)
}

/// `CancelCosignMessage`: the 32-byte digest the member key signs.
pub fn message(
    set_id: &[u8; 32],
    txid: &[u8; 32],
    n: u32,
    ref_height: u32,
    price: u32,
    block_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(15 + 32 + 32 + 12 + 32);
    buf.extend_from_slice(PREFIX);
    buf.extend_from_slice(set_id);
    buf.extend_from_slice(txid);
    buf.extend_from_slice(&n.to_le_bytes());
    buf.extend_from_slice(&ref_height.to_le_bytes());
    buf.extend_from_slice(&price.to_le_bytes());
    buf.extend_from_slice(block_hash);
    let once = Sha256::digest(&buf);
    Sha256::digest(once).into()
}

/// The compressed public key a 65-byte compact signature recovers to over `msg`, under the node's rule
/// (`vault::RecoverSig`): header 31..34, low S, a valid compressed key. None otherwise.
pub fn recover(msg: &[u8; 32], sig: &[u8; SIG_SIZE]) -> Option<[u8; 33]> {
    if !(31..=34).contains(&sig[0]) {
        return None;
    }
    let s = Signature::from_slice(&sig[1..65]).ok()?;
    if s.normalize_s().is_some() {
        return None; // high S: the node refuses it rather than repairing it
    }
    let recid = RecoveryId::from_byte(sig[0] - 31)?;
    let key = VerifyingKey::recover_from_prehash(msg, &s, recid).ok()?;
    let point = key.to_encoded_point(true);
    point.as_bytes().try_into().ok()
}

/// One co-signature entry: the stated price and the member's signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub price: u32,
    pub sig: [u8; SIG_SIZE],
}

impl Entry {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ENTRY_SIZE {
            return None;
        }
        Some(Entry {
            price: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            sig: bytes[4..69].try_into().ok()?,
        })
    }

    pub fn decode_hex(h: &str) -> Option<Self> {
        Self::decode(&hex::decode(h.trim()).ok()?)
    }

    pub fn encode(&self) -> [u8; ENTRY_SIZE] {
        let mut out = [0u8; ENTRY_SIZE];
        out[0..4].copy_from_slice(&self.price.to_le_bytes());
        out[4..].copy_from_slice(&self.sig);
        out
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.encode())
    }
}

/// RED-4 clause (a)'s test, `IsUnderwater`: `collateralZat · price < mintedCents · thetaBps · COIN`.
pub fn is_underwater(collateral_zat: i64, price: i64, minted_cents: i64, theta_bps: u32) -> bool {
    if collateral_zat < 0 || price < 0 || minted_cents < 0 {
        return true;
    }
    (collateral_zat as u128) * (price as u128) < (minted_cents as u128) * (theta_bps as u128) * COIN
}

/// The watcher's verdict: the claim is **wrong-price** when, at `price` (this agent's honest price at the claim's
/// refHeight), the vault was not claimable even with `margin_bps` to spare:
/// `collateralZat · price · 10⁴ ≥ mintedCents · θ · COIN · (10⁴ + margin)`. Margin 0 is exactly the consensus
/// statement condition (`!IsUnderwater`), which a co-signature must meet anyway.
pub fn is_wrong_price(collateral_zat: i64, price: i64, minted_cents: i64, theta_bps: u32, margin_bps: u32) -> bool {
    if collateral_zat <= 0 || price <= 0 || minted_cents <= 0 {
        return false;
    }
    (collateral_zat as u128) * (price as u128) * 10_000
        >= (minted_cents as u128) * (theta_bps as u128) * COIN * (10_000 + margin_bps as u128)
}

/// The gossip frame on the cancel topic (`yellowback/cancel/<network>/1`): exactly [`FRAME_SIZE`] bytes,
/// `"YCG1" ‖ intent txid (internal) ‖ n LE32 ‖ seq LE16 ‖ refHeight LE32 ‖ entry 69`. Nothing in it is trusted:
/// the receiver recovers the key from the entry over the message it rebuilds from its own node's view (the set id,
/// the claim's refHeight and its block hash) and requires it to be `seq`'s current member key.
pub const FRAME_MAGIC: &[u8; 4] = b"YCG1";
pub const FRAME_SIZE: usize = 4 + 32 + 4 + 2 + 4 + ENTRY_SIZE;

#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    pub txid: [u8; 32],
    pub n: u32,
    pub seq: u16,
    pub ref_height: u32,
    pub entry: Entry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    Size(usize),
    Magic,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Size(n) => write!(f, "cancel frame is {n} bytes, not {FRAME_SIZE}"),
            FrameError::Magic => write!(f, "cancel frame magic is not YCG1"),
        }
    }
}

impl Frame {
    pub fn decode(b: &[u8]) -> Result<Self, FrameError> {
        if b.len() != FRAME_SIZE {
            return Err(FrameError::Size(b.len()));
        }
        if &b[0..4] != FRAME_MAGIC {
            return Err(FrameError::Magic);
        }
        let txid: [u8; 32] = b[4..36].try_into().expect("32");
        let n = u32::from_le_bytes(b[36..40].try_into().expect("4"));
        let seq = u16::from_le_bytes(b[40..42].try_into().expect("2"));
        let ref_height = u32::from_le_bytes(b[42..46].try_into().expect("4"));
        let entry = Entry::decode(&b[46..]).expect("69");
        Ok(Frame {
            txid,
            n,
            seq,
            ref_height,
            entry,
        })
    }

    pub fn encode(&self) -> [u8; FRAME_SIZE] {
        let mut out = [0u8; FRAME_SIZE];
        out[0..4].copy_from_slice(FRAME_MAGIC);
        out[4..36].copy_from_slice(&self.txid);
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out[40..42].copy_from_slice(&self.seq.to_le_bytes());
        out[42..46].copy_from_slice(&self.ref_height.to_le_bytes());
        out[46..].copy_from_slice(&self.entry.encode());
        out
    }

    /// `"txid:n"` in the RPC's display order.
    pub fn intent(&self) -> String {
        format!("{}:{}", display_of_internal(&self.txid), self.n)
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Frame{{{} seq {} R {} {} µUSD}}",
            self.intent(),
            self.seq,
            self.ref_height,
            self.entry.price
        )
    }
}

/// Split `"txid:n"` into the internal txid and n.
pub fn parse_intent(s: &str) -> Option<([u8; 32], u32)> {
    let (t, n) = s.split_once(':')?;
    Some((internal_from_display(t)?, n.parse().ok()?))
}

#[cfg(test)]
pub mod testkit {
    //! Signing in the tests, as the node's `vault::SignRecoverable` does (RFC 6979, low S, header 31 + recid).
    use super::*;
    use k256::ecdsa::SigningKey;

    pub fn key(i: u8) -> SigningKey {
        let mut b = [0u8; 32];
        b[31] = i;
        b[0] = 0x11;
        SigningKey::from_bytes(&b.into()).unwrap()
    }

    pub fn pubkey(k: &SigningKey) -> [u8; 33] {
        k.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap()
    }

    pub fn sign(k: &SigningKey, msg: &[u8; 32]) -> [u8; SIG_SIZE] {
        let (sig, recid) = k.sign_prehash_recoverable(msg).unwrap();
        let (sig, recid) = match sig.normalize_s() {
            Some(low) => (low, RecoveryId::from_byte(recid.to_byte() ^ 1).unwrap()),
            None => (sig, recid),
        };
        let mut out = [0u8; SIG_SIZE];
        out[0] = 31 + recid.to_byte();
        out[1..].copy_from_slice(&sig.to_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    #[test]
    fn message_layout_matches_the_node() {
        // The preimage is 15 + 32 + 32 + 4 + 4 + 4 + 32 = 123 bytes, hashed twice (attest.cpp CancelCosignMessage).
        let set = [0x75u8; 32];
        let txid = [0x11u8; 32];
        let bh = [0x22u8; 32];
        let mut pre = Vec::new();
        pre.extend_from_slice(b"YedCancelCosign");
        pre.extend_from_slice(&set);
        pre.extend_from_slice(&txid);
        pre.extend_from_slice(&2u32.to_le_bytes());
        pre.extend_from_slice(&950u32.to_le_bytes());
        pre.extend_from_slice(&50_000u32.to_le_bytes());
        pre.extend_from_slice(&bh);
        assert_eq!(pre.len(), 123);
        let want: [u8; 32] = Sha256::digest(Sha256::digest(&pre)).into();
        assert_eq!(message(&set, &txid, 2, 950, 50_000, &bh), want);
    }

    #[test]
    fn recover_round_trip_and_the_node_rules() {
        let k = key(7);
        let msg = message(&[1; 32], &[2; 32], 0, 100, 4_000_000, &[3; 32]);
        let sig = sign(&k, &msg);
        assert!((31..=34).contains(&sig[0]));
        assert_eq!(recover(&msg, &sig), Some(pubkey(&k)));
        // another message recovers to another key (never to k's)
        let other = message(&[1; 32], &[2; 32], 0, 101, 4_000_000, &[3; 32]);
        assert_ne!(recover(&other, &sig), Some(pubkey(&k)));
        // an uncompressed header (27..30) or garbage header is refused
        let mut bad = sig;
        bad[0] = 27;
        assert_eq!(recover(&msg, &bad), None);
        bad[0] = 35;
        assert_eq!(recover(&msg, &bad), None);
        // high S is refused (the node rejects it rather than normalising)
        let s = Signature::from_slice(&sig[1..]).unwrap();
        let (r, low_s) = s.split_scalars();
        let high = Signature::from_scalars(r, -*low_s).unwrap();
        let mut hs = sig;
        hs[1..].copy_from_slice(&high.to_bytes());
        hs[0] = if sig[0] == 31 { 32 } else { 31 };
        assert_eq!(recover(&msg, &hs), None);
    }

    #[test]
    fn hex_order_is_reversed() {
        let mut b = [0u8; 32];
        b[0] = 0xaa;
        b[31] = 0x01;
        let d = display_of_internal(&b);
        assert!(d.starts_with("01") && d.ends_with("aa"));
        assert_eq!(internal_from_display(&d), Some(b));
        assert_eq!(parse_intent(&format!("{d}:3")), Some((b, 3)));
        assert_eq!(parse_intent("zz:1"), None);
        assert_eq!(parse_intent(&d), None);
    }

    #[test]
    fn claimability_arithmetic() {
        // 75 YEC against $100 at theta 125 %: claimable below $1.6667
        let c = 75 * 100_000_000i64;
        assert!(is_underwater(c, 1_600_000, 10_000, 12_500));
        assert!(!is_underwater(c, 1_666_667, 10_000, 12_500));
        assert!(!is_underwater(c, 4_000_000, 10_000, 12_500));
        // the verdict with a margin: $4.00 is wrong-price with 5 % to spare, $1.70 is not (only 2 % above the line)
        assert!(is_wrong_price(c, 4_000_000, 10_000, 12_500, 500));
        assert!(is_wrong_price(c, 1_700_000, 10_000, 12_500, 0));
        assert!(!is_wrong_price(c, 1_700_000, 10_000, 12_500, 500));
        assert!(!is_wrong_price(c, 1_600_000, 10_000, 12_500, 0));
        assert!(!is_wrong_price(0, 4_000_000, 10_000, 12_500, 0));
        // no overflow at the extremes (u128)
        assert!(is_wrong_price(i64::MAX, u32::MAX as i64, 10_000_000, 12_500, 10_000));
    }

    #[test]
    fn frame_round_trip_and_size_cap() {
        let f = Frame {
            txid: [9; 32],
            n: 1,
            seq: 513,
            ref_height: 4242,
            entry: Entry {
                price: 4_000_000,
                sig: [0x5a; 65],
            },
        };
        let b = f.encode();
        assert_eq!(b.len(), FRAME_SIZE);
        assert_eq!(FRAME_SIZE, 115);
        assert_eq!(Frame::decode(&b).unwrap(), f);
        assert_eq!(Frame::decode(&b[..114]), Err(FrameError::Size(114)));
        let mut long = b.to_vec();
        long.push(0);
        assert_eq!(Frame::decode(&long), Err(FrameError::Size(116)));
        let mut m = b;
        m[0] = b'X';
        assert_eq!(Frame::decode(&m), Err(FrameError::Magic));
        assert_eq!(Entry::decode_hex(&f.entry.to_hex()), Some(f.entry.clone()));
        assert_eq!(f.entry.to_hex().len(), 138);
    }
}
