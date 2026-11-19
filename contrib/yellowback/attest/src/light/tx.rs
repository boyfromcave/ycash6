// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The little of a raw transaction the light backend reads itself: its txid (to check that what an endpoint
//! returned for a txid is that transaction) and its transparent outputs (the on-chain "YF" records,
//! `onchain.rs`, which compact blocks do not carry).

use sha2::{Digest, Sha256};

fn compact(b: &[u8], i: &mut usize) -> Option<u64> {
    let first = *b.get(*i)?;
    *i += 1;
    let (len, v) = match first {
        0xfd => (2, u16::from_le_bytes(b.get(*i..*i + 2)?.try_into().ok()?) as u64),
        0xfe => (4, u32::from_le_bytes(b.get(*i..*i + 4)?.try_into().ok()?) as u64),
        0xff => (8, u64::from_le_bytes(b.get(*i..*i + 8)?.try_into().ok()?)),
        n => (0, n as u64),
    };
    *i += len;
    Some(v)
}

fn skip(b: &[u8], i: &mut usize, n: usize) -> Option<()> {
    let end = i.checked_add(n)?;
    (end <= b.len()).then(|| *i = end)
}

/// The version of a raw transaction (the low 31 bits of its header).
pub fn version(raw: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(raw.get(0..4)?.try_into().ok()?) & 0x7fff_ffff)
}

/// The txid (display hex) of a transaction of version 1..4: SHA256d of its bytes, reversed. None for v5 (ZIP 244),
/// whose txid this backend does not compute.
pub fn txid_v4(raw: &[u8]) -> Option<String> {
    if version(raw)? >= 5 {
        return None;
    }
    let mut h: [u8; 32] = Sha256::digest(Sha256::digest(raw)).into();
    h.reverse();
    Some(hex::encode(h))
}

/// The transparent outputs: (value in zat, scriptPubKey).
pub fn outputs(raw: &[u8]) -> Option<Vec<(i64, Vec<u8>)>> {
    let header = u32::from_le_bytes(raw.get(0..4)?.try_into().ok()?);
    let overwintered = header >> 31 == 1;
    let v = header & 0x7fff_ffff;
    let mut i = 4;
    if overwintered {
        skip(raw, &mut i, 4)?; // nVersionGroupId
    }
    if overwintered && v >= 5 {
        skip(raw, &mut i, 12)?; // consensusBranchId, nLockTime, nExpiryHeight
    }
    let nin = compact(raw, &mut i)?;
    for _ in 0..nin {
        skip(raw, &mut i, 36)?;
        let l = compact(raw, &mut i)? as usize;
        skip(raw, &mut i, l)?;
        skip(raw, &mut i, 4)?;
    }
    let nout = compact(raw, &mut i)?;
    let mut out = Vec::new();
    for _ in 0..nout {
        let value = i64::from_le_bytes(raw.get(i..i + 8)?.try_into().ok()?);
        i += 8;
        let l = compact(raw, &mut i)? as usize;
        out.push((value, raw.get(i..i + l)?.to_vec()));
        i += l;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A v4 (Sapling) transaction: one input, two outputs (P2PKH, OP_RETURN), no shielded parts.
    pub fn sample() -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&(0x8000_0004u32).to_le_bytes());
        t.extend_from_slice(&0x892f_2085u32.to_le_bytes());
        t.push(1);
        t.extend_from_slice(&[7u8; 32]);
        t.extend_from_slice(&1u32.to_le_bytes());
        t.push(2);
        t.extend_from_slice(&[0xab, 0xcd]);
        t.extend_from_slice(&0xffff_fffeu32.to_le_bytes());
        t.push(2);
        t.extend_from_slice(&5_000i64.to_le_bytes());
        t.push(25);
        t.extend_from_slice(&[0x76, 0xa9, 0x14]);
        t.extend_from_slice(&[1u8; 20]);
        t.extend_from_slice(&[0x88, 0xac]);
        t.extend_from_slice(&0i64.to_le_bytes());
        t.push(3);
        t.extend_from_slice(&[0x6a, 0x01, 0x42]);
        t.extend_from_slice(&[0u8; 4 + 4 + 8 + 3]); // lock, expiry, valueBalance, no spends/outputs/joinsplits
        t
    }

    #[test]
    fn outputs_and_txid() {
        let t = sample();
        let o = outputs(&t).unwrap();
        assert_eq!(o.len(), 2);
        assert_eq!(o[0].0, 5_000);
        assert_eq!(o[1].1, vec![0x6a, 0x01, 0x42]);
        let id = txid_v4(&t).unwrap();
        assert_eq!(id.len(), 64);
        let mut want: [u8; 32] = Sha256::digest(Sha256::digest(&t)).into();
        want.reverse();
        assert_eq!(id, hex::encode(want));
        assert!(outputs(&t[..20]).is_none());
        let mut v5 = t.clone();
        v5[0] = 5;
        assert!(txid_v4(&v5).is_none());
    }
}
