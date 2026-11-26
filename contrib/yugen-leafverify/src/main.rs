// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! yugen-leafverify: ycashd's Yugen leaf-transfer verifier and note-tree helper, run by the node
//! as a separate process (decision N-D1, docs in ycash6 doc/yugen-node.md).
//!
//!   yugen-leafverify verify <request.json>   -> "ACCEPT" (exit 0) | "REJECT <reason>" (exit 10)
//!   yugen-leafverify root <commitments file> -> "<size> <root hex>": the note-tree root (§6, T1)
//!                                               with cm* at leaf 0 (§13.2), then each line's cm
//!   yugen-leafverify regroot                 -> the empty exit-registry root (§13.1.4)
//!   yugen-leafverify bundle <request.json>   -> "ACCEPT <json>" | "REJECT {"proofs_bound":b,"reason":r}"
//!                                               (exit 10): §15.6 B1, B3 to B5
//!                                               (and the B8 pay of the applied mask); B2's chain
//!                                               comparison, B6, B7 and the coinbase run in ycashd
//!   yugen-leafverify testbundle <request.json> -> "<bundle hex> <proof A hex> <proof B hex>": a
//!                                               bundle of fresh random transfers with TEST-ONLY stub
//!                                               proofs (regtest functional tests only); optional
//!                                               "transfers": [hex] are included first, and
//!                                               "records": [{"vb", "vout" hex, "vin": [{"txid",
//!                                               "index", "script_sig"}]}] (VB records, §15.1) after
//!                                               them; with records it prints a fourth field, the
//!                                               records' transfer hashes (hex, comma-separated)
//!
//! Exit codes: 0 accept / result, 10 reject (a verdict on the input), anything else a failure of the
//! helper, never a verdict: 1 is what a Rust `main` returning `Err` exits with and 101 a panic, so
//! neither can be read as a reject. A bundle reject says whether the helper had confirmed, before
//! it, that both proofs hash to the hashes the bundle commits to (`proofs_bound`): only then is it
//! a verdict on the block; otherwise the proofs (sidecar data, outside the txid) may have been
//! replaced in transit. Errors that start with "FAIL" are failures (exit 3).
//!
//! The request carries the transfer, both proofs and the context of spec 0.5.1 §7.2 in hex. The
//! node rules of §7.9 rules 1 (decode), 5 (transfer hash, m) and 6 (prechecks, both proofs) run
//! here; anchors, nullifiers and W4 run in ycashd. The two verifiers are configured exactly as
//! the wallet's provers (yewd/yugen wallet/src/prove.rs, W-PROOF): System A
//! `e2::verify_wallet04_with` under `CAT1_TREE_LEAF_SALTED` over `Params::wallet04_masked`;
//! System B `Public::precheck(0)` then `ZkLeaf::verify_words` of `WALLET_MODE0` ("wallet/mode0"),
//! rate 1/8, consensus build `cat1t,blake3` (yew Y-W3b), proof at most
//! `LEAF_PROOF_MAX_B`.

use serde_json::{json, Value};
use std::process::exit;
use yugen_ref::falcon::sig_digest as sig_digest_of;
use yugen_ref::transfer::{transfer_hash, Transfer, TxContext};

fn hx(b: &[u8]) -> String { hex::encode(b) }
fn field<const L: usize>(v: &Value, k: &str) -> Result<[u8; L], String> {
    let b = hex::decode(v[k].as_str().ok_or(format!("{k} missing"))?).map_err(|_| format!("{k}: hex"))?;
    b.try_into().map_err(|b: Vec<u8>| format!("{k}: {} bytes, {L} needed", b.len()))
}
fn bytes(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    hex::decode(v[k].as_str().ok_or(format!("{k} missing"))?).map_err(|_| format!("{k}: hex"))
}

/// A request field the node writes itself: its absence or a bad encoding is this node's fault.
fn fail<T>(r: Result<T, String>) -> Result<T, String> { r.map_err(|e| format!("FAIL request: {e}")) }

/// The exit code of a helper run whose result is `r` (see the module comment).
const EXIT_REJECT: i32 = 10;
const EXIT_FAIL: i32 = 3;

fn verify(req: &Value) -> Result<(), String> {
    let t = Transfer::decode(&fail(bytes(req, "transfer"))?).map_err(|e| format!("decode {e:?}"))?;
    let num = |k: &str| fail(req[k].as_u64().ok_or(k.to_string()));
    let ctx = TxContext {
        branch_id: num("branch_id")? as u32,
        network: num("network")? as u8,
        anchor_height: num("anchor_height")? as u32,
        anchor_root: fail(field(req, "anchor_root"))?,
        anchor_block_hash: fail(field(req, "anchor_block_hash"))?,
        vout: fail(bytes(req, "vout"))?,
    };
    let th = transfer_hash(&t, &ctx);
    let m = sig_digest_of(&th);
    let (vb_in, vb_out) = t.vb_split();
    let auth_mode = req["auth_mode"].as_u64().unwrap_or(0);
    let public = json!({
        "anchor_root": hx(&ctx.anchor_root), "nf_1": hx(&t.nf[0]), "nf_2": hx(&t.nf[1]),
        "cm_1": hx(&t.cm[0]), "cm_2": hx(&t.cm[1]), "fee": t.fee().to_string(),
        "vb_in": vb_in.to_string(), "vb_out": vb_out.to_string(),
        "sig_digest": hx(&m), "auth_mode": auth_mode, "reg_root": req["reg_root"],
    });
    let pa = fail(bytes(req, "proof_a"))?;
    let pb = fail(bytes(req, "proof_b"))?;
    if pb.len() > b::LEAF_PROOF_MAX_B {
        return Err(format!("proof B: {} bytes, above LEAF_PROOF_MAX_B {}", pb.len(), b::LEAF_PROOF_MAX_B));
    }
    a::verify(&a::setup(), &public, &pa).map_err(|e| if e.starts_with("FAIL") { e } else { format!("proof A: {e}") })?;
    b::verify(&b::setup(), &public, &pb).map_err(|e| format!("proof B: {e}"))?;
    Ok(())
}

mod a {
    use super::*;
    use yugen_proof_a::circuit::{build, Circuit, Params};
    use yugen_proof_a::e2;
    use yugen_proof_a::wallet::v04::Public;
    pub struct Setup { circuit: Circuit, key: e2::Key }
    pub fn setup() -> Setup {
        let circuit = build(&Params::wallet04_masked(), &[]);
        let key = e2::Key::new(&circuit);
        Setup { circuit, key }
    }
    fn public(p: &Value) -> Result<Public, String> {
        public_of(p).map_err(|e| format!("FAIL public inputs: {e}"))
    }
    fn public_of(p: &Value) -> Result<Public, String> {
        let n = |k: &str| p[k].as_str().and_then(|s| s.parse::<u64>().ok()).ok_or(format!("{k}"));
        Ok(Public {
            anchor_root: field(p, "anchor_root")?, nf: [field(p, "nf_1")?, field(p, "nf_2")?],
            cm: [field(p, "cm_1")?, field(p, "cm_2")?], fee: n("fee")?, vb_in: n("vb_in")?, vb_out: n("vb_out")?,
            m: field(p, "sig_digest")?, auth_mode: p["auth_mode"].as_u64().unwrap_or(0) as u8, reg_root: field(p, "reg_root")?,
        })
    }
    pub fn verify(s: &Setup, p: &Value, proof: &[u8]) -> Result<(), String> {
        let p = public(p)?;
        let proof = verifier_e2::Proof::from_bytes(proof).ok_or("proof A does not decode")?;
        e2::verify_wallet04_with(&verifier_e2::params::CAT1_TREE_LEAF_SALTED, &s.key, &s.circuit, &p, &proof)
    }
}

mod b {
    use super::*;
    use binius_core::word::Word;
    use yugen_proof_b2::prove::{ZkLeaf, WALLET_MODE0};
    use yugen_proof_b2::statement04;
    use yugen_proof_b2::witness04::Public;
    /// The most a leaf transfer's System B proof may be (spec §2 `LEAF_PROOF_MAX_B`, W4).
    /// Spec 0.5.2 (SPEC-214).
    /// ycashd's own W4 check uses `yugen::LEAF_PROOF_MAX_B` in src/primitives/yugen.h.
    pub const LEAF_PROOF_MAX_B: usize = 817_736;
    pub fn setup() -> ZkLeaf {
        let st = statement04::build(None);
        ZkLeaf::setup(WALLET_MODE0, st.circuit.constraint_system(), 3)
    }
    pub fn verify(leaf: &ZkLeaf, p: &Value, proof: &[u8]) -> Result<(), String> {
        let p = Public::from_json(p).map_err(|e| format!("FAIL public inputs: {e:?}"))?;
        p.precheck(0).map_err(|e| e.to_string())?;
        let words: Vec<Word> = p.words().into_iter().map(Word::from_u64).collect();
        leaf.verify_words(&words, proof).map_err(|e| format!("{e:?}"))
    }
}

// ------------------------------------------------------------------ bundles (spec 0.5.1 §15)
use yugen_ref::bundle::{proof_hash, Bundle, BundleError, LeafView, Node};

/// §8.2 with the network's activation height `act` (yugen-ref's `resolve_anchor` fixes its own
/// ACTIVATION_HEIGHT; a devnet activates elsewhere).
fn resolve(slot: u8, h: u32, act: u32) -> Option<u32> {
    let g = yugen_ref::params::ANCHOR_GRID;
    let mut ha = h.checked_sub(1)? / g * g;
    loop {
        if !(ha >= act && ha % g == 0 && ha < h && h - ha <= yugen_ref::params::ANCHOR_WINDOW) { return None; }
        if ((ha / g) & 0xff) as u8 == slot { return Some(ha); }
        ha = ha.checked_sub(g)?;
    }
}

/// yugen-ref `bundle_views` (rules B2 to B4) with `resolve` in place of its anchor resolution.
fn bundle_views(b: &Bundle, branch_id: u32, network: u8, h: u32, act: u32, mode: u8) -> Result<(Vec<LeafView>, [u8; 32]), BundleError> {
    use yugen_ref::bundle::{bundle_statement, leaf_pi_digest};
    use yugen_ref::statement::Public;
    let mut heights = Vec::new();
    for a in &b.anchors { heights.push(resolve(a.slot, h, act).ok_or(BundleError::AnchorExpired)?); }
    if heights.windows(2).any(|w| w[0] >= w[1]) { return Err(BundleError::AnchorOrder); }
    let mut views = Vec::new();
    for r in &b.records {
        let i = b.anchors.iter().position(|a| a.slot == r.transfer.anchor_slot).ok_or(BundleError::AnchorMissing)?;
        let ctx = TxContext { branch_id, network, anchor_height: heights[i], anchor_root: b.anchors[i].anchor_root,
            anchor_block_hash: b.anchors[i].block_hash, vout: r.vout.clone().unwrap_or_default() };
        let th = transfer_hash(&r.transfer, &ctx);
        let (vb_in, vb_out) = r.transfer.vb_split();
        let public = Public { anchor_root: b.anchors[i].anchor_root, nf: r.transfer.nf, cm: r.transfer.cm,
            fee: r.transfer.fee(), vb_in, vb_out, sig_digest: sig_digest_of(&th), auth_mode: mode, reg_root: b.anchors[i].reg_root };
        let lpi = leaf_pi_digest(&public);
        views.push(LeafView { anchor_height: heights[i], transfer_hash: th, public, lpi });
    }
    let lpis: Vec<[u8; 32]> = views.iter().map(|v| v.lpi).collect();
    let stmt = bundle_statement(&b.tree, &lpis, mode);
    Ok((views, stmt))
}

const STUB_A: &[u8] = b"YUGEN-TEST-STUB-A";
const STUB_B: &[u8] = b"YUGEN-TEST-STUB-B";

fn stub(tag: &[u8], stmt: &[u8; 32]) -> Vec<u8> { [tag, &stmt[..]].concat() }

/// `bound` is set once both proofs are confirmed to be the ones the bundle commits to (B5's
/// hashes), before anything else about them is judged: a reject after that is a verdict on the
/// block, one before it may be a relay's substitution (review H-1).
///
/// A bundle that fails to decode (B1) or whose anchors do not resolve (B2 to B4) is refused with
/// `bound` set whatever the proofs: the bundle bytes are committed by the txid and the height by
/// the block, so that refusal is a verdict on the block, never a relay's substitution (review P-1).
fn bundle(req: &Value, bound: &mut bool) -> Result<Value, String> {
    *bound = false;
    let num = |k: &str| fail(req[k].as_u64().ok_or(k.to_string()));
    let raw = fail(bytes(req, "bundle"))?;
    let h = num("height")? as u32;
    let (branch_id, network, act) = (num("branch_id")? as u32, num("network")? as u8, num("activation")? as u32);
    let mode = req["mode"].as_u64().unwrap_or(0) as u8;
    let pa = fail(bytes(req, "proof_a"))?;
    let pb = fail(bytes(req, "proof_b"))?;
    let b = Bundle::decode(&raw).map_err(|e| { *bound = true; format!("bundle {e:?}") })?;
    let check = req["check_proofs"].as_bool().unwrap_or(true);
    if check {
        // B5 first: the proofs are sidecar data. A bundle proof may be up to PROOF_BYTES_MAX (§15.1,
        // §16.2 W1); LEAF_PROOF_MAX_B is a leaf's limit (W4) and never applies here (review C-1).
        let max = yugen_ref::params::PROOF_BYTES_MAX as usize;
        if pa.is_empty() || pb.is_empty() { return Err("proof missing".into()); }
        if pa.len() > max || pb.len() > max { return Err("proof too long".into()); }
        if proof_hash(1, &pa) != b.proof_hash[0] || proof_hash(2, &pb) != b.proof_hash[1] {
            return Err("proof hash".into());
        }
        *bound = true;
    }
    let (views, stmt) = bundle_views(&b, branch_id, network, h, act, mode).map_err(|e| { *bound = true; format!("bundle {e:?}") })?;
    if check {
        if req["stub"].as_bool() == Some(true) {
            // TEST-ONLY (regtest, -yugenteststubproofs): the "proof" is a tag and the statement.
            // Zero padding after it is allowed, so tests can build blocks of full proof weight.
            let ok = |p: &[u8], t: &[u8]| { let s = stub(t, &stmt); p.len() >= s.len() && p[..s.len()] == s[..] && p[s.len()..].iter().all(|&x| x == 0) };
            if !ok(&pa, STUB_A) || !ok(&pb, STUB_B) { return Err("stub proof".into()); }
        } else {
            ba::verify(&stmt, &pa)?;
            bb::verify(req, &b.tree, &stmt, &pb)?;
        }
    }
    let applied: Vec<bool> = match req["applied"].as_array() {
        Some(a) => a.iter().map(|x| x.as_bool().unwrap_or(false)).collect(),
        None => vec![true; b.records.len()],
    };
    if applied.len() != b.records.len() { return Err("applied mask length".into()); }
    let mask: Vec<Option<(u64, u64)>> = b.records.iter().zip(&applied)
        .map(|(r, &a)| a.then(|| (r.transfer.fee(), yugen_ref::params::BASE_FEE << r.transfer.fee_class))).collect();
    let pay = yugen_ref::safety::bundle_pay(&b.tree, &mask);
    let anchors: Vec<Value> = b.anchors.iter().map(|a| {
        let ha = resolve(a.slot, h, req["activation"].as_u64().unwrap_or(0) as u32).unwrap_or(0);
        json!({"height": ha, "anchor_root": hx(&a.anchor_root), "reg_root": hx(&a.reg_root), "block_hash": hx(&a.block_hash)})
    }).collect();
    let transfers: Vec<Value> = b.records.iter().zip(&views).map(|(r, v)| json!({
        "nf": [hx(&r.transfer.nf[0]), hx(&r.transfer.nf[1])], "cm": [hx(&r.transfer.cm[0]), hx(&r.transfer.cm[1])],
        "fee": r.transfer.fee(), "vb": r.transfer.value_balance, "anchor_height": v.anchor_height,
        "transfer": hx(&r.transfer.encode()), "transfer_hash": hx(&v.transfer_hash),
    })).collect();
    let records: Vec<Value> = pay.records.iter().filter(|r| !r.script.is_empty())
        .map(|r| json!({"script": hx(&r.script), "pay": r.pay})).collect();
    Ok(json!({"stmt": hx(&stmt), "anchors": anchors, "transfers": transfers, "records": records,
              "fees": pay.fees, "pot": pay.pot}))
}

/// System A's bundle (root node) verifier, configured as bundler-verify's SystemA (yugen-bundler
/// decision C-29): masked leaf row 8, node row 9, mode 0.
mod ba {
    use yugen_proof_a::bundle2::{self as bundle, BundleProof, LeafProgram, Programs};
    use yugen_proof_a::circuit::{build, Params};
    use yugen_proof_a::e2;
    pub fn verify(stmt: &[u8; 32], bytes: &[u8]) -> Result<(), String> {
        let leaf = build(&Params::wallet04_masked(), &[]);
        let key = e2::Key::new(&leaf);
        let lp = || LeafProgram { circuit: &leaf, key: &key };
        let programs = Programs::build(&verifier_e2::params::CAT1_TREE_LEAF_SALTED, &verifier_e2::params::CAT1_TREE_NODE, lp())
            .map_err(|e| format!("FAIL proof A programs: {e}"))?;
        if !programs.is_consensus() { return Err("FAIL proof A: not the consensus programs".into()); }
        let proof = BundleProof::from_bytes(bytes).ok_or("proof A does not decode")?;
        let kind = proof.points.kind();
        bundle::verify(&programs, lp(), 0, stmt, kind, &proof).map_err(|e| format!("proof A: {e}"))
    }
}

/// System B's root verifier: yugen-proof-b2 verifier-lib 230d9fc `b2verify root`, run as its own
/// process (9.6 GB footprint, docs/b2verify.md). Wire form of proof B: `LE32(n) || n x LE64 public
/// word || proof bytes` (the prover's `.inout` words, then its proof).
mod bb {
    use super::*;
    pub fn verify(req: &Value, tree: &Node, stmt: &[u8; 32], blob: &[u8]) -> Result<(), String> {
        let bin = req["b2verify"].as_str().filter(|s| !s.is_empty()).ok_or("FAIL no -yugenb2verify")?;
        let plan = req["b_plan"].as_str().filter(|s| !s.is_empty()).ok_or("FAIL no -yugenbplan")?;
        if blob.len() < 4 { return Err("proof B: truncated".into()); }
        let n = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
        let end = 4usize.checked_add(n.checked_mul(8).ok_or("proof B: words")?).ok_or("proof B: words")?;
        if blob.len() <= end { return Err("proof B: truncated".into()); }
        let dir = std::env::temp_dir().join(format!("yugen-b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("FAIL {e}"))?;
        let (inout, proof) = (dir.join("root.inout"), dir.join("root.proof"));
        std::fs::write(&inout, &blob[4..end]).map_err(|e| format!("FAIL {e}"))?;
        std::fs::write(&proof, &blob[end..]).map_err(|e| format!("FAIL {e}"))?;
        let kind = if matches!(tree, Node::Sub { .. }) { "t0" } else { "t" };
        let out = std::process::Command::new(bin)
            .args(["root", plan, "2", "0", kind]).arg(&inout).arg(&proof).arg(hx(stmt)).output();
        let _ = std::fs::remove_dir_all(&dir);
        let out = out.map_err(|e| format!("FAIL b2verify: {e}"))?;
        outcome(out.status.code(), &String::from_utf8_lossy(&out.stdout), &String::from_utf8_lossy(&out.stderr))
    }

    /// b2verify's result (yugen-proof-b2 docs/b2verify.md: exit 0 all accepted, 1 any rejected, 2
    /// usage, plan or build error). Exit 1 is a verdict only with the `REJECT <label>: <reason>` line
    /// it prints for a rejected proof and no `ACCEPT` line: a Rust `main` that returns `Err` also
    /// exits 1, and a panic exits 101 (review H-2).
    pub fn outcome(code: Option<i32>, stdout: &str, stderr: &str) -> Result<(), String> {
        let rejected = stdout.lines().any(|l| l.starts_with("REJECT "));
        let accepted = stdout.lines().any(|l| l.starts_with("ACCEPT "));
        match code {
            Some(0) if accepted && !rejected => Ok(()),
            Some(1) if rejected && !accepted => Err(format!("proof B: {}", stdout.trim())),
            _ => Err(format!("FAIL b2verify (exit {code:?}): {} {}", stdout.trim(), stderr.trim())),
        }
    }
}

/// TEST-ONLY: a bundle over the given anchor entries, one sub-bundle per group of up to 4 fresh
/// random transfers under one merge when more than 4, records unclaimed except the root's slot A
/// (paid to `payee` when given), with stub proofs.
fn testbundle(req: &Value) -> Result<String, String> {
    use yugen_ref::bundle::AnchorEntry;
    let a = &req["anchor"];
    let anchor = AnchorEntry { slot: a["slot"].as_u64().ok_or("slot")? as u8, anchor_root: field(a, "anchor_root")?,
        reg_root: field(a, "reg_root")?, block_hash: field(a, "block_hash")? };
    let n = req["n"].as_u64().unwrap_or(2) as usize;
    let payee = hex::decode(req["payee"].as_str().unwrap_or("")).map_err(|_| "payee hex")?;
    let seed = req["seed"].as_u64().unwrap_or(1);
    let mut records = Vec::new();
    // Optional given transfers (hex, e.g. a pool leaf's), placed first.
    for h in req["transfers"].as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
        let e = hex::decode(h.as_str().ok_or("transfers: hex")?).map_err(|_| "transfers: hex")?;
        let t = Transfer::decode(&e).map_err(|e| format!("{e:?}"))?;
        records.push(yugen_ref::bundle::Record { transfer: t, vout: None, vin: vec![] });
    }
    for i in 0..n {
        let mut e = vec![0u8; 232];
        e[1] = anchor.slot;
        for (j, x) in e[4..196].iter_mut().enumerate() {
            *x = yugen_ref::hash::hvar(yugen_ref::hash::Dom::Proof, &[seed.to_le_bytes(), (i as u64).to_le_bytes(), (j as u64).to_le_bytes()].concat())[0];
        }
        let t = Transfer::decode(&e).map_err(|e| format!("{e:?}"))?;
        records.push(yugen_ref::bundle::Record { transfer: t, vout: None, vin: vec![] });
    }
    // Optional VB records (§15.1), after the others: a fresh random transfer with flag VB and `vb`, its serialized
    // `vout`, and for a deposit its inputs (`txid` in serialization order).
    let given = records.len();
    for (i, r) in req["records"].as_array().map(|v| v.as_slice()).unwrap_or(&[]).iter().enumerate() {
        let vb = r["vb"].as_i64().ok_or("records: vb")?;
        let mut e = vec![0u8; 240];
        e[1] = anchor.slot;
        e[2] = 0x10;   // flag VB
        for (j, x) in e[4..196].iter_mut().enumerate() {
            *x = yugen_ref::hash::hvar(yugen_ref::hash::Dom::Proof, &[seed.to_le_bytes(), (1000 + i as u64).to_le_bytes(), (j as u64).to_le_bytes()].concat())[0];
        }
        e[232..].copy_from_slice(&vb.to_le_bytes());
        let t = Transfer::decode(&e).map_err(|e| format!("records: {e:?}"))?;
        let vout = hex::decode(r["vout"].as_str().ok_or("records: vout")?).map_err(|_| "records: vout hex")?;
        let mut vin = Vec::new();
        for x in r["vin"].as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
            let prevout = yugen_ref::bundle::Outpoint { txid: field(x, "txid")?, index: x["index"].as_u64().ok_or("records: index")? as u32 };
            vin.push(yugen_ref::bundle::DepositInput { prevout, script_sig: hex::decode(x["script_sig"].as_str().unwrap_or("")).map_err(|_| "records: script_sig hex")? });
        }
        records.push(yugen_ref::bundle::Record { transfer: t, vout: Some(vout), vin });
    }
    let slots = |k: usize| yugen_ref::bundle::record_slots(k);
    let mut subs: Vec<Node> = records.chunks(4).map(|c| Node::Sub { count: c.len() as u8, recs: vec![vec![]; slots(c.len())] }).collect();
    let mut tree = if subs.len() == 1 { subs.pop().unwrap() } else {
        let k = subs.len();
        Node::Merge { kids: subs, recs: vec![vec![]; slots(k)] }
    };
    match &mut tree { Node::Sub { recs, .. } | Node::Merge { recs, .. } => recs[0] = payee };
    let mut b = Bundle { anchors: vec![anchor], tree, records, proof_hash: [[0; 32]; 2] };
    let (views, stmt) = bundle_views(&b, req["branch_id"].as_u64().ok_or("branch_id")? as u32,
        req["network"].as_u64().ok_or("network")? as u8, req["height"].as_u64().ok_or("height")? as u32,
        req["activation"].as_u64().ok_or("activation")? as u32, 0)
        .map_err(|e| format!("{e:?}"))?;
    let (mut pa, mut pb) = (stub(STUB_A, &stmt), stub(STUB_B, &stmt));
    // Zero bytes appended to the stub proofs ("pad_a", "pad_b").
    pa.resize(pa.len() + req["pad_a"].as_u64().unwrap_or(0) as usize, 0);
    pb.resize(pb.len() + req["pad_b"].as_u64().unwrap_or(0) as usize, 0);
    b.proof_hash = [proof_hash(1, &pa), proof_hash(2, &pb)];
    let mut out = format!("{} {} {}", hx(&b.encode()), hx(&pa), hx(&pb));
    if b.records.len() > given {
        let hashes: Vec<String> = views[given..].iter().map(|v| hx(&v.transfer_hash)).collect();
        out += &format!(" {}", hashes.join(","));
    }
    Ok(out)
}

fn read_req(p: &str) -> Value {
    match std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
        Some(v) => v,
        None => { println!("FAIL request unreadable"); exit(2) }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("verify") if args.len() == 3 => {
            match verify(&read_req(&args[2])) {
                Ok(()) => println!("ACCEPT"),
                Err(e) if e.starts_with("FAIL") => { println!("{}", e.replace('\n', " ")); exit(EXIT_FAIL) }
                Err(e) => { println!("REJECT {}", e.replace('\n', " ")); exit(EXIT_REJECT) }
            }
        }
        Some("root") if args.len() == 3 => {
            let text = std::fs::read_to_string(&args[2]).unwrap_or_else(|_| exit(2));
            let mut tree = yugen_ref::tree::Tree::new();
            tree.append(&yugen_ref::tree::canary_nullifier().1);
            for l in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let cm: [u8; 48] = hex::decode(l).ok().and_then(|b| b.try_into().ok()).unwrap_or_else(|| exit(2));
                tree.append(&cm);
            }
            println!("{} {}", tree.len(), hx(&tree.root()));
        }
        Some("bundle") if args.len() == 3 => {
            let mut bound = false;
            match bundle(&read_req(&args[2]), &mut bound) {
                Ok(v) => println!("ACCEPT {v}"),
                Err(e) if e.starts_with("FAIL") => { println!("{}", e.replace('\n', " ")); exit(EXIT_FAIL) }
                Err(e) => { println!("REJECT {}", json!({"proofs_bound": bound, "reason": e})); exit(EXIT_REJECT) }
            }
        }
        Some("testbundle") if args.len() == 3 => match testbundle(&read_req(&args[2])) {
            Ok(v) => println!("{v}"),
            Err(e) => { println!("FAIL {e}"); exit(3) }
        },
        Some("regroot") => println!("{}", hx(&yugen_ref::registry::Registry::default().root())),
        _ => { eprintln!("usage: yugen-leafverify verify <request.json> | root <file> | regroot"); exit(2) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review P-1: a bundle the reference refuses at decode is a verdict on the block (proofs_bound),
    /// whatever the proofs, so the node does not refetch it as a possibly corrupt body.
    #[test]
    fn structurally_invalid_bundle_is_bound() {
        for enc in [vec![0x80u8], vec![0x80, 0x01, 0x00], vec![0x00; 8]] {
            let req = json!({"bundle": hex::encode(&enc), "height": 100, "branch_id": 1, "network": 2, "activation": 16,
                             "proof_a": "00", "proof_b": "00"});
            let mut bound = false;
            let e = bundle(&req, &mut bound).unwrap_err();
            assert!(e.starts_with("bundle "), "{e}");
            assert!(bound, "{e}");
        }
        // A request field missing is not a verdict on anything.
        let mut bound = false;
        assert!(bundle(&json!({"bundle": "80"}), &mut bound).is_err());
        assert!(!bound);
    }

    #[test]
    fn b2verify_exit_one_without_a_reject_line_is_a_failure() {
        assert!(bb::outcome(Some(0), "ACCEPT root\n", "").is_ok());
        let v = bb::outcome(Some(1), "REJECT root: bad sumcheck\n", "").unwrap_err();
        assert!(v.starts_with("proof B: "), "{v}");
        for (code, out) in [(Some(1), ""), (Some(1), "Error: plan unreadable"), (Some(101), ""), (Some(2), ""), (None, ""),
                            (Some(0), ""), (Some(1), "ACCEPT root\nREJECT root: x\n")] {
            let e = bb::outcome(code, out, "").unwrap_err();
            assert!(e.starts_with("FAIL"), "{code:?} {out:?}: {e}");
        }
    }
}
