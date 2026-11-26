// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! `yugen-sendbuild`: the helper ycashd's `z_sendmany` runs (as a child process, like
//! `yugen-leafverify`) to pay a Yugen address from transparent coins in one transaction.
//!
//!   yugen-sendbuild check <input.json>   validate the recipient, amount and memo; no proving
//!   yugen-sendbuild resolve <input.json> a short Yugen address: its static full address (hex) from
//!                                        the two mailbox hosts ("hosts"), or "pending: …" (decision Y-16)
//!   yugen-sendbuild build <input.json>   build the deposit transfer and prove it
//!
//! Input: {"prover": path of yewd-yugen, "branch_id", "network" (spec NET_*), "anchor_height",
//! "anchor_root" hex48, "anchor_block_hash" hex32 (internal order), "to": a Yugen address
//! (yqf/yqtf/yqrf, decisions Y-13, Y-14) or a static full address (§12.1, hex), "hosts": ycashd's
//! `-yugenhosts` (two host:port, for a short address), "amount": zat, "memo": hex or null,
//! "vout": hex of the transaction's transparent outputs (consensus serialisation)}.
//! Output (stdout, one JSON line): {"transfer", "proof_a", "proof_b" (hex), "fee", "expiry",
//! "value_balance"}; a refusal is {"error": text} with exit status 1. A short address whose record
//! the hosts do not serve yet is {"error": "pending: …"} (decision Y-16: ycashd retries at the next sync).
//!
//! The transfer is the deposit shape of spec 0.5.2 §7.1 (two dummy spends, value_balance =
//! -(amount + fee), FLAG_LEAFFEE), output 1 pays the recipient `amount`, output 2 is a zero note.
//! It is built by yewd-yugen's builder (Adapted from yugen-ref `Wallet::build`, see its build.rs)
//! under a one-time account from a fresh random seed (decision N-S2, doc/yugen-sendmany.md): the
//! spends are dummies, so no key of the user's Yugen wallet is needed; the transparent inputs
//! are signed by ycashd with the coins' own keys (ZIP-243 + hashYugen, N-TX).

use serde_json::{json, Value};
use yewd_yugen::account::Account;
use yewd_yugen::build::BuildExt;
use yewd_yugen::engine::prove_both;
use yewd_yugen::{hosts, yaddr};
use yugen_ref::address::FullAddress;
use yugen_ref::params::*;
use yugen_ref::registry::Registry;
use yugen_ref::request::PaymentRequest;
use yugen_ref::transfer::{self, FLAG_LEAFFEE};
use yugen_ref::vectors::{public_json, witness_json};
use yugen_ref::wallet::{BuildParams, Output};

fn arr<const L: usize>(v: &Value, what: &str) -> Result<[u8; L], String> {
    hex::decode(v.as_str().unwrap_or("")).ok().and_then(|b| b.try_into().ok()).ok_or(format!("{what}: {L} bytes hex"))
}

enum Dest {
    Request(PaymentRequest),
    Static(FullAddress, Vec<u8>),
    /// A short static part, resolved through the hosts only when building (`check` does not ask them).
    Short,
}

/// The recipient (decisions Y-13, Y-14; UX-1 P-1..P-3): a Yugen address `yqf…`/`yqtf…`/`yqrf…` (Falcon-512;
/// the `k` forms are reserved and refused until Falcon-1024 is enabled), decoded by the wallet's own
/// codec (`yewd_yugen::yaddr`); the withdrawn test strings `yug1…`/`yugreq1…` are refused. A full
/// static address as hex (spec §12.1, the debug form) is still taken. P-3: the request when present,
/// no memo and payable at the anchor; otherwise the static part with the memo. ycashd keeps no set of
/// paid requests, so it never treats a request as paid before (recorded, doc/yugen-sendmany.md).
/// A short static part is resolved through the two mailbox hosts (`hosts`, spec §12.3, §17.8 item 3).
fn dest(inp: &Value, network: u8, ha: u32, resolve: bool) -> Result<Dest, String> {
    let to = inp["to"].as_str().ok_or("to")?.trim();
    let memo = match inp["memo"].as_str() {
        None | Some("") => None,
        Some(h) => Some(hex::decode(h).map_err(|_| "memo: hex")?),
    };
    if yaddr::is_legacy(to) {
        return Err(yaddr::LEGACY_REFUSED.into());
    }
    let low = to.to_lowercase();
    if ["yqk1", "yqtk1", "yqrk1"].iter().any(|p| low.starts_with(p)) {
        return Err("refused: Falcon-1024 Yugen addresses (yqk…/yqtk…/yqrk…) are reserved until that scheme is enabled (decision Y-14)".into());
    }
    if yaddr::looks_like(to) {
        let a = yaddr::YugenAddress::decode(to, network).map_err(|e| format!("refused: {e}"))?;
        let anchored = inp.get("anchor_height").map_or(false, |v| !v.is_null());
        // without an anchor ("check") a request is judged payable; the build re-chooses at its anchor
        let payable_at = if anchored { ha } else { a.request.as_ref().map_or(ha, |r| r.day * DAY_BLOCKS) };
        let choice = match (&a.stat, yaddr::choose(&a, memo.is_some(), payable_at, |_| false)) {
            (_, Ok(c)) => c,
            (yaddr::Static::Short(..), Err(_)) if !resolve => return Ok(Dest::Short),
            (yaddr::Static::Short(f, sa), Err(_)) => yaddr::Choice::Static(resolve_short(inp, network, *f, sa)?),
            (_, Err(e)) => return Err(e),
        };
        return match choice {
            yaddr::Choice::Request(req) => Ok(Dest::Request(req)),
            yaddr::Choice::Static(full) => static_dest(full, memo, network),
        };
    }
    let b = hex::decode(to).map_err(|_| "not a Yugen payment request or static full address")?;
    let a = FullAddress::from_bytes(&b).ok_or("not a Yugen payment request or static full address")?;
    static_dest(a, memo, network)
}

/// Pending (decision Y-16): the record of a short address is not served yet; ycashd retries at the
/// next sync boundary (`next_sync`) and reports the operation as pending meanwhile.
const PENDING: &str = "pending: ";

/// One sync session's address queries to the hosts in `inp["hosts"]` (ycashd `-yugenhosts`).
fn resolve_short(inp: &Value, network: u8, flags: u8, sa: &[u8; 32]) -> Result<FullAddress, String> {
    let hosts = inp["hosts"].as_str().unwrap_or("");
    if hosts.is_empty() {
        return Err("refused: this Yugen address needs its mailbox hosts (start ycashd with -yugenhosts=host1:port,host2:port)".into());
    }
    let pair = hosts::Pair::new(hosts)?;
    match pair.resolve_session(network, &[(flags, *sa)])?.pop() {
        Some(hosts::Resolution::Resolved(a)) => Ok(a),
        Some(hosts::Resolution::Invalid) => Err("refused: the mailbox hosts serve an invalid record for this Yugen address (spec §12.3)".into()),
        _ => {
            let h = pair.roots().map(|r| r.h).unwrap_or(0);
            Err(format!("{PENDING}the record of this Yugen address is not served yet; resolved at the next sync (after height {})", h + ANCHOR_GRID as u32))
        }
    }
}

fn static_dest(a: FullAddress, memo: Option<Vec<u8>>, network: u8) -> Result<Dest, String> {
    if !a.valid() || a.network != network {
        return Err("static full address refused (spec §12.1: network, flags or encapsulation key)".into());
    }
    let mut m = memo.unwrap_or_default();
    if m.len() > MEMO_LEN {
        return Err(format!("memo longer than {MEMO_LEN} bytes"));
    }
    if !m.is_empty() {
        m.resize(MEMO_LEN, 0);
    }
    Ok(Dest::Static(a, m))
}

fn run(mode: &str, inp: &Value) -> Result<Value, String> {
    let network = inp["network"].as_u64().ok_or("network")? as u8;
    let ha = inp["anchor_height"].as_u64().unwrap_or(0) as u32;
    let amount = inp["amount"].as_u64().ok_or("amount: zat")?;
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    let d = dest(inp, network, ha, mode == "build")?;
    let fee = BASE_FEE + LEAF_PROOF_FEE;
    if mode == "resolve" {
        // a short static part through the hosts; anything else is already payable as given
        let to = inp["to"].as_str().unwrap_or("").trim();
        if !matches!(d, Dest::Short) {
            return Ok(json!({"to": to, "resolved": false}));
        }
        if let Ok(a) = yaddr::YugenAddress::decode(to, network) {
            if let yaddr::Static::Short(f, sa) = a.stat {
                let full = resolve_short(inp, network, f, &sa)?;
                return Ok(json!({"to": hex::encode(full.to_bytes()), "resolved": true}));
            }
        }
        return Ok(json!({"to": to, "resolved": false}));
    }
    if mode == "check" {
        return Ok(json!({"fee": fee, "kind": match d { Dest::Request(_) => "request", Dest::Static(..) => "static", Dest::Short => "short" }}));
    }
    let mut seed = vec![0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
    let mut acct = Account::from_seed(&seed, network).ok_or("seed refused (spec §4)")?;
    let first = match d {
        Dest::Request(req) => Output::Request { req, v: amount },
        Dest::Static(addr, memo) => Output::Static { addr, v: amount, memo },
        Dest::Short => unreachable!("resolved when building"),
    };
    let outputs = [first, Output::Change { n: 0, v: 0 }];
    let spends = [yugen_ref::wallet::Spend::Dummy { c: 0 }, yugen_ref::wallet::Spend::Dummy { c: 1 }];
    let bp = BuildParams {
        branch_id: inp["branch_id"].as_u64().ok_or("branch_id")? as u32,
        fee_class: 0,
        anchor_height: ha,
        anchor_root: arr(&inp["anchor_root"], "anchor_root")?,
        anchor_block_hash: arr(&inp["anchor_block_hash"], "anchor_block_hash")?,
        value_balance: -((amount + fee) as i64),
        vout: hex::decode(inp["vout"].as_str().unwrap_or("00")).map_err(|_| "vout: hex")?,
        otag_counter: [0, 1],
        auth_mode: 0,
        registry: Registry::default(),
    };
    let built = acct.wallet.build_flags(&mut acct.signer, &spends, &outputs, &bp, FLAG_LEAFFEE);
    yugen_ref::statement::check_statement(&built.public, &built.witness).map_err(|v| format!("statement refused: {v:?}"))?;
    let stmt = json!({"public": public_json(&built.public), "witness": witness_json(&built.witness)});
    let prover = std::path::PathBuf::from(inp["prover"].as_str().ok_or("prover: path of yewd-yugen")?);
    let (pa, pb) = prove_both(&prover, &stmt)?;
    Ok(json!({
        "transfer": hex::encode(built.transfer.encode()),
        "proof_a": hex::encode(pa),
        "proof_b": hex::encode(pb),
        "fee": built.transfer.fee(),
        "expiry": transfer::expiry_height(ha),
        "value_balance": built.transfer.value_balance,
        "nf1": hex::encode(built.transfer.nf[0]),
    }))
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let r = (|| {
        let mode = a.get(1).map(String::as_str).unwrap_or("");
        if mode != "check" && mode != "build" && mode != "resolve" {
            return Err("usage: yugen-sendbuild check|resolve|build <input.json>".to_string());
        }
        let s = std::fs::read_to_string(a.get(2).ok_or("input file")?).map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&s).map_err(|e| e.to_string())?;
        run(mode, &v)
    })();
    match r {
        Ok(v) => println!("{v}"),
        Err(e) => {
            println!("{}", json!({"error": e}));
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct() -> Account {
        Account::from_seed(&[7u8; 32], NET_REGTEST).unwrap()
    }
    fn chk(to: &str, memo: Option<&str>) -> Result<Dest, String> {
        let mut v = json!({"to": to, "amount": 1});
        if let Some(m) = memo {
            v["memo"] = json!(hex::encode(m));
        }
        dest(&v, NET_REGTEST, 0, false)
    }

    #[test]
    fn ruled_prefixes_and_refusals() {
        let a = acct();
        let full = a.static_address(0);
        let req = a.request(0, 1);
        let y = |stat, request| yaddr::YugenAddress { network: NET_REGTEST, stat, request }.encode();
        // full static + request: the request without a memo, the static part with one (P-3)
        let s = y(yaddr::Static::Full(full.clone()), Some(req.clone()));
        assert!(s.starts_with("yqrf1"));
        assert!(matches!(chk(&s, None), Ok(Dest::Request(_))));
        assert!(matches!(chk(&s, Some("hi")), Ok(Dest::Static(_, m)) if m.len() == MEMO_LEN));
        // full static only
        assert!(matches!(chk(&y(yaddr::Static::Full(full.clone()), None), None), Ok(Dest::Static(..))));
        // short only: accepted by check, resolved only when building
        let short = y(yaddr::Static::Short(full.flags, full.short()), None);
        assert!(matches!(chk(&short, None), Ok(Dest::Short)));
        let e = dest(&json!({"to": short, "amount": 1, "anchor_height": 16}), NET_REGTEST, 16, true).err().unwrap();
        assert!(e.contains("-yugenhosts"), "{e}");
        // the regtest string on mainnet: refused (not "unknown")
        let e = dest(&json!({"to": s, "amount": 1}), NET_MAIN, 0, false).err().unwrap();
        assert!(e.starts_with("refused"), "{e}");
        // reserved Falcon-1024 and withdrawn strings: refused
        for bad in ["yqrk1qqqqqqqq", "yqk1qqqqqqqq", "yugreq1qqqq", "yug1qqqq", "yugregtest1qqqq"] {
            let e = chk(bad, None).err().unwrap();
            assert!(e.starts_with("refused"), "{bad}: {e}");
            assert!(!e.contains("not a Yugen payment request"), "{bad}");
        }
        // anything else stays "not a Yugen address" (ycashd then says unknown address format)
        assert!(chk("zzz", None).err().unwrap().contains("not a Yugen payment request or static full address"));
    }
}
