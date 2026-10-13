// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The on-chain fallback for cancel co-signatures (docs/plans/yellowback-attest-gossip-evaluation.md F1; owner
//! decision 2, 2026-10-13). When a claim is still short of `cancelsRequired` co-signatures `fallback_after_blocks`
//! after it confirmed, every co-signing agent publishes its co-signature in one standard transaction:
//!
//! ```text
//! OP_RETURN OP_PUSHDATA1 79 ‖ "YF" ‖ intent short id (8) ‖ price LE32 ‖ sig65        (82-byte script ≤ 83)
//! ```
//!
//! The short id is the first 8 bytes of SHA-256(intent txid (internal order) ‖ n LE32); the seq comes from key
//! recovery and the refHeight from the claim, so the record needs neither. "YF" is not the Yellowback payload magic
//! ("YB"), so the module never reads it as a payload: it is a plain data output, relayed and mined like any other
//! (`MAX_OP_RETURN_RELAY` = 83 on both lines; no node change). Drivers scan the claim's blocks for the tag and take
//! every record that verifies, exactly as a co-signature from the direct path.
//!
//! The transaction is built without `fundrawtransaction` (whose coin choice could touch a YED token or a bond): one
//! confirmed P2PKH coin of this wallet larger than `fee + 2 × dust` is chosen from `listunspent`,
//! `createrawtransaction` pays the change back to the coin's own address, the OP_RETURN output is inserted into the
//! serialized transaction ([`insert_output`]), then `signrawtransaction` and `sendrawtransaction`. The fee is exactly
//! `fallback_fee_zat`.

use sha2::{Digest, Sha256};

use crate::cosig::{self, Entry};

pub const TAG: &[u8; 2] = b"YF";
pub const RECORD_SIZE: usize = 2 + 8 + 4 + 65;
/// `OP_RETURN OP_PUSHDATA1 79`
pub const SCRIPT_PREFIX: [u8; 3] = [0x6a, 0x4c, RECORD_SIZE as u8];

pub fn short_id(txid: &[u8; 32], n: u32) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(txid);
    h.update(n.to_le_bytes());
    h.finalize()[..8].try_into().expect("8")
}

pub fn encode(txid: &[u8; 32], n: u32, entry: &Entry) -> [u8; RECORD_SIZE] {
    let mut out = [0u8; RECORD_SIZE];
    out[0..2].copy_from_slice(TAG);
    out[2..10].copy_from_slice(&short_id(txid, n));
    out[10..14].copy_from_slice(&entry.price.to_le_bytes());
    out[14..].copy_from_slice(&entry.sig);
    out
}

/// The script of the data output.
pub fn script(txid: &[u8; 32], n: u32, entry: &Entry) -> Vec<u8> {
    let mut s = SCRIPT_PREFIX.to_vec();
    s.extend_from_slice(&encode(txid, n, entry));
    s
}

/// A record from a data output's script hex: (short id, entry). None for anything else.
pub fn decode_script_hex(script_hex: &str) -> Option<([u8; 8], Entry)> {
    let b = hex::decode(script_hex).ok()?;
    if b.len() != 3 + RECORD_SIZE || b[0..3] != SCRIPT_PREFIX || &b[3..5] != TAG {
        return None;
    }
    let r = &b[3..];
    Some((
        r[2..10].try_into().ok()?,
        Entry {
            price: u32::from_le_bytes(r[10..14].try_into().ok()?),
            sig: r[14..79].try_into().ok()?,
        },
    ))
}

/// The records in a `getblock <hash> 2` result that name the intent's short id.
pub fn records_in_block(block: &serde_json::Value, id: &[u8; 8]) -> Vec<Entry> {
    let mut out = Vec::new();
    for tx in block
        .get("tx")
        .and_then(|t| t.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        for vout in tx
            .get("vout")
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let hex_str = vout
                .get("scriptPubKey")
                .and_then(|s| s.get("hex"))
                .and_then(|h| h.as_str())
                .unwrap_or("");
            if let Some((sid, e)) = decode_script_hex(hex_str) {
                if &sid == id {
                    out.push(e);
                }
            }
        }
    }
    out
}

fn read_compact(b: &[u8], i: &mut usize) -> Option<u64> {
    let first = *b.get(*i)?;
    *i += 1;
    let n = match first {
        0xfd => {
            let v = u16::from_le_bytes(b.get(*i..*i + 2)?.try_into().ok()?) as u64;
            *i += 2;
            v
        }
        0xfe => {
            let v = u32::from_le_bytes(b.get(*i..*i + 4)?.try_into().ok()?) as u64;
            *i += 4;
            v
        }
        0xff => {
            let v = u64::from_le_bytes(b.get(*i..*i + 8)?.try_into().ok()?);
            *i += 8;
            v
        }
        n => n as u64,
    };
    Some(n)
}

fn write_compact(n: u64, out: &mut Vec<u8>) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
}

/// Insert one output (`value` zat, `script`) as the last transparent output of an unsigned v4 (Sapling) or v5
/// (NU5) transaction as `createrawtransaction` returns it. None for any other shape.
pub fn insert_output(tx: &[u8], value: i64, script: &[u8]) -> Option<Vec<u8>> {
    let header = u32::from_le_bytes(tx.get(0..4)?.try_into().ok()?);
    let version = header & 0x7fff_ffff;
    let overwintered = header & 0x8000_0000 != 0;
    let group = u32::from_le_bytes(tx.get(4..8)?.try_into().ok()?);
    let vin_at = match (overwintered, version, group) {
        (true, 4, 0x892f_2085) => 8,
        (true, 5, 0x26a7_270a) => 20, // header, group, branch id, lock time, expiry height
        _ => return None,
    };
    let mut i = vin_at;
    let nin = read_compact(tx, &mut i)?;
    for _ in 0..nin {
        i += 36;
        let l = read_compact(tx, &mut i)? as usize;
        i += l + 4;
        if i > tx.len() {
            return None;
        }
    }
    let vout_at = i;
    let nout = read_compact(tx, &mut i)?;
    for _ in 0..nout {
        i += 8;
        let l = read_compact(tx, &mut i)? as usize;
        i += l;
        if i > tx.len() {
            return None;
        }
    }
    let mut out = tx[..vout_at].to_vec();
    write_compact(nout + 1, &mut out);
    let mut j = vout_at;
    read_compact(tx, &mut j)?;
    out.extend_from_slice(&tx[j..i]);
    out.extend_from_slice(&value.to_le_bytes());
    write_compact(script.len() as u64, &mut out);
    out.extend_from_slice(script);
    out.extend_from_slice(&tx[i..]);
    Some(out)
}

/// `TOKEN_VALUE`: the zat every YED token output carries. A fallback coin is always worth more (review L-1).
pub const TOKEN_VALUE: i64 = 10_000;

/// Whether a `listunspent` row can fund the fallback: confirmed, spendable, P2PKH, not a coinbase output (review
/// L-2: ycash6 lists mature coinbase), worth more than both `min_zat` and TOKEN_VALUE, and not an outpoint in
/// `tokens` (the YED index's own token outpoints of this wallet, review L-1). Bonds are P2SH and never chosen.
pub fn fundable_coin(
    row: &serde_json::Value,
    min_zat: i64,
    tokens: &std::collections::HashSet<(String, u64)>,
) -> Option<(String, u64, String, i64)> {
    if row.get("generated").and_then(|v| v.as_bool()) == Some(true) {
        return None;
    }
    let c = fundable(row, min_zat.max(TOKEN_VALUE + 1))?;
    if tokens.contains(&(c.0.clone(), c.1)) {
        return None;
    }
    Some(c)
}

/// The shape checks of [`fundable_coin`] without the token and coinbase filters.
pub fn fundable(row: &serde_json::Value, min_zat: i64) -> Option<(String, u64, String, i64)> {
    let spk = row.get("scriptPubKey")?.as_str()?;
    if !(spk.len() == 50 && spk.starts_with("76a914") && spk.ends_with("88ac")) {
        return None;
    }
    if row.get("spendable").and_then(|v| v.as_bool()) == Some(false) {
        return None;
    }
    if row.get("confirmations").and_then(|v| v.as_i64()).unwrap_or(0) < 1 {
        return None;
    }
    let zat = row.get("amountZat").and_then(|v| v.as_i64()).or_else(|| {
        row.get("amount")
            .and_then(|v| v.as_f64())
            .map(|a| (a * 1e8).round() as i64)
    })?;
    if zat < min_zat {
        return None;
    }
    Some((
        row.get("txid")?.as_str()?.to_string(),
        row.get("vout")?.as_u64()?,
        row.get("address")?.as_str()?.to_string(),
        zat,
    ))
}

/// Recover the co-signer of an on-chain record for the claim (set, intent, refHeight, its hash).
pub fn signer(set_id: &[u8; 32], txid: &[u8; 32], n: u32, r: u32, bh: &[u8; 32], e: &Entry) -> Option<[u8; 33]> {
    cosig::recover(&cosig::message(set_id, txid, n, r, e.price, bh), &e.sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cosig::testkit;

    #[test]
    fn the_record_fits_a_standard_op_return() {
        let e = Entry {
            price: 4_000_000,
            sig: [0x5a; 65],
        };
        let s = script(&[1; 32], 0, &e);
        assert_eq!(RECORD_SIZE, 79);
        assert_eq!(s.len(), 82); // <= MAX_OP_RETURN_RELAY (83)
        assert_ne!(&s[3..5], b"YB"); // never the Yellowback payload magic
        let (id, back) = decode_script_hex(&hex::encode(&s)).unwrap();
        assert_eq!((id, back), (short_id(&[1; 32], 0), e));
        assert_ne!(short_id(&[1; 32], 0), short_id(&[1; 32], 1));
        assert!(decode_script_hex("6a").is_none());
        assert!(decode_script_hex(&hex::encode(&s[..81])).is_none());
    }

    #[test]
    fn records_are_found_in_a_block_and_their_signer_recovered() {
        let set = [0x75; 32];
        let txid = [0xaa; 32];
        let bh = [0x33; 32];
        let k = testkit::key(5);
        let e = Entry {
            price: 4_000_000,
            sig: testkit::sign(&k, &cosig::message(&set, &txid, 0, 99, 4_000_000, &bh)),
        };
        let other = Entry { price: 1, sig: [1; 65] };
        let block = serde_json::json!({"tx": [
            {"vout": [{"scriptPubKey": {"hex": "76a91400000000000000000000000000000000000000000088ac"}}]},
            {"vout": [{"scriptPubKey": {"hex": hex::encode(script(&txid, 0, &e))}}]},
            {"vout": [{"scriptPubKey": {"hex": hex::encode(script(&[9; 32], 0, &other))}}]}
        ]});
        let found = records_in_block(&block, &short_id(&txid, 0));
        assert_eq!(found, vec![e.clone()]);
        assert_eq!(signer(&set, &txid, 0, 99, &bh, &e), Some(testkit::pubkey(&k)));
        assert_ne!(signer(&set, &txid, 0, 100, &bh, &e), Some(testkit::pubkey(&k)));
    }

    #[test]
    fn an_output_is_inserted_into_v4_and_v5_transactions() {
        // v4: header, group, 1 input (empty script), 1 output, lock time, expiry, value balance, 3 empty vectors
        let mut v4 = Vec::new();
        v4.extend_from_slice(&(0x8000_0004u32).to_le_bytes());
        v4.extend_from_slice(&0x892f_2085u32.to_le_bytes());
        v4.push(1);
        v4.extend_from_slice(&[0x11; 32]);
        v4.extend_from_slice(&3u32.to_le_bytes());
        v4.push(0);
        v4.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        v4.push(1);
        v4.extend_from_slice(&5000i64.to_le_bytes());
        v4.push(2);
        v4.extend_from_slice(&[0x51, 0x52]);
        let tail = [0u8; 4 + 4 + 8 + 3];
        v4.extend_from_slice(&tail);
        let out = insert_output(&v4, 0, &[0x6a, 0x01, 0x02]).unwrap();
        // the output count went to 2 and the new output sits after the first, before the tail
        let at = 8 + 1 + 32 + 4 + 1 + 4;
        assert_eq!(out[at], 2);
        let new_at = at + 1 + 8 + 1 + 2;
        assert_eq!(&out[new_at..new_at + 8], &0i64.to_le_bytes());
        assert_eq!(&out[new_at + 8..new_at + 12], &[3, 0x6a, 0x01, 0x02]);
        assert_eq!(&out[out.len() - tail.len()..], &tail);
        assert_eq!(out.len(), v4.len() + 8 + 1 + 3);
        // v5 keeps its 20-byte prefix
        let mut v5 = Vec::new();
        v5.extend_from_slice(&(0x8000_0005u32).to_le_bytes());
        v5.extend_from_slice(&0x26a7_270au32.to_le_bytes());
        v5.extend_from_slice(&[0u8; 12]);
        v5.extend_from_slice(&v4[8..]);
        let out5 = insert_output(&v5, 0, &[0x6a]).unwrap();
        assert_eq!(out5[20 + 1 + 32 + 4 + 1 + 4], 2);
        // anything else is refused
        assert!(insert_output(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, &[0x6a]).is_none());
    }

    #[test]
    fn only_confirmed_p2pkh_coins_above_the_minimum_fund_it() {
        let row = |spk: &str, zat: i64, conf: i64| {
            serde_json::json!({"txid": "aa", "vout": 1, "address": "tm1", "scriptPubKey": spk, "amountZat": zat,
                "confirmations": conf, "spendable": true})
        };
        let p2pkh = format!("76a914{}88ac", "00".repeat(20));
        assert!(fundable(&row(&p2pkh, 100_000, 1), 30_000).is_some());
        assert!(fundable(&row(&p2pkh, 10_000, 1), 30_000).is_none()); // a YED token's 10,000 zat
        assert!(fundable(&row(&p2pkh, 100_000, 0), 30_000).is_none());
        assert!(fundable(&row(&format!("a914{}87", "00".repeat(20)), 100_000, 5), 30_000).is_none());
        // a bond (P2SH)
        // review L-1/L-2: never at or under TOKEN_VALUE whatever the fee, never a known token, never a coinbase
        let none = std::collections::HashSet::new();
        assert!(fundable_coin(&row(&p2pkh, 10_000, 1), 1_000, &none).is_none());
        assert!(fundable_coin(&row(&p2pkh, 10_001, 1), 1_000, &none).is_some());
        let tokens: std::collections::HashSet<(String, u64)> = [("aa".to_string(), 1u64)].into_iter().collect();
        assert!(fundable_coin(&row(&p2pkh, 100_000, 1), 1_000, &tokens).is_none());
        let mut cb = row(&p2pkh, 100_000, 200);
        cb["generated"] = serde_json::json!(true);
        assert!(fundable_coin(&cb, 1_000, &none).is_none());
    }
}
