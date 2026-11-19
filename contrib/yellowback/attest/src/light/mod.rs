// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The light backend (`[backend] kind = "lightwalletd"`, beta4 item 3d, plan `docs/plans/beta4/price-feed.md`
//! §2.2–§2.3, D-6/D-7): a seat with no node. The agent's loops (`attest.rs`, `cancel.rs`, `subscribe.rs`) are
//! unchanged and still speak node RPC method names; [`Light::call`] answers each of them, with the node's JSON
//! shape, from lightwalletd-dd endpoints and a local signer:
//!
//! | Method | Answered by |
//! |---|---|
//! | `yed_getinfo`, `yed_listattestors`, `set_getinfo`, `yed_getattestations`, `yed_listvaults`, `yed_getvault`, `yed_decodepayload`, `gettxout`, `getrawtransaction` | the first endpoint that answers (failover, B-6) |
//! | `getblockhash` | every endpoint; two that answer must agree, else nothing is signed on it (B-7) |
//! | `getrawmempool` | the union of every endpoint's |
//! | `getblockchaininfo` | `GetChainInfo` + `GetLightdInfo` |
//! | `getblock <hash> 2` | the block's compact transactions plus every member address's transactions in it (`GetTaddressTxids`): the on-chain "YF" records |
//! | `sendrawtransaction`, `yed_addattestation` | every endpoint (`SendTransaction`, `SubmitAttestation`); success if one accepts |
//! | `yed_signattestation`, `yed_signcancelcosign` | the seat key ([`crate::signer`]) behind the guard file ([`crate::guard`]), ported from ycashd |
//! | `validateaddress`, `signmessage` | the seat key, for the endpoint binding |
//! | `set_heartbeat`, `yed_buildcancel` (+ `set_signcancel`, `vault_send`) | the `yew-attestor` CLI ([`yew`]) |
//!
//! Trust (plan §2.2): a lying endpoint can make the seat cite a wrong hash. That statement is invalid and cannot be
//! equivocation (EQV-1 verifies under the real block hash), and the guard is keyed on the hash, so a lying endpoint
//! costs liveness, never the bond. A claim is co-signed only when `cosign_endpoints` endpoints show it and none that
//! answers denies it (B-10).

// generated (proto/regen.sh): never formatted or linted by hand
#[rustfmt::skip]
#[allow(clippy::all, dead_code, missing_docs)]
pub mod proto;

pub mod grpc;
pub mod tx;
pub mod yew;

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::LightConfig;
use crate::guard::{Guard, Signed};
use crate::rpc::RpcError;
use crate::signer::SeatKey;

/// `params.h` PRICE_MIN / PRICE_MAX (µUSD per YEC).
pub const PRICE_MIN: i64 = 100;
pub const PRICE_MAX: i64 = u32::MAX as i64;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One request to one endpoint (each is one lightwalletd-dd call).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Req {
    Info,
    Attestors,
    Set(String),
    Block(u64),
    ChainInfo,
    LightdInfo,
    Tx(String),
    DecodePayload(String),
    Attestations,
    Vaults { status: String, count: u32, skip: u32 },
    Vault(String),
    TxOut { txid: String, vout: u32, mempool: bool },
    Mempool,
    Send(String),
    Submit(String),
    AddressTxids { address: String, start: u64, end: u64 },
}

/// One endpoint. [`grpc::GrpcUpstream`] in production; a closure in the tests.
pub trait Upstream: Send + Sync {
    fn name(&self) -> &str;
    fn call(&self, req: Req) -> BoxFut<'_, Result<Value, RpcError>>;
}

#[derive(Default)]
struct Cache {
    network: Option<String>,
    attestors: Vec<Value>,
    /// display hash → height, from `getblockhash` (lightwalletd's GetBlock takes a height only)
    heights: HashMap<String, u32>,
    /// the signed cancel hex yew-attestor built and sent → its txid
    sent: HashMap<String, String>,
}

pub struct Light {
    ups: Vec<Box<dyn Upstream>>,
    preferred: AtomicUsize,
    key: SeatKey,
    key_file: PathBuf,
    guard: tokio::sync::Mutex<Guard>,
    yew: Option<yew::YewCli>,
    cosign_endpoints: usize,
    cache: std::sync::Mutex<Cache>,
}

fn node_err(message: impl Into<String>) -> RpcError {
    RpcError::Node {
        code: -8,
        message: message.into(),
    }
}

fn param_u64(params: &[Value], i: usize) -> Option<u64> {
    params
        .get(i)
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
}

fn param_str(params: &[Value], i: usize) -> Option<&str> {
    params.get(i).and_then(Value::as_str)
}

impl Light {
    /// The production backend: one gRPC channel per endpoint, the seat key, its guard.
    pub fn open(cfg: &LightConfig) -> Result<Self, String> {
        let timeout = Duration::from_secs(cfg.timeout_seconds);
        let mut ups: Vec<Box<dyn Upstream>> = Vec::new();
        for u in &cfg.endpoints {
            ups.push(Box::new(grpc::GrpcUpstream::new(u, timeout)?));
        }
        let yew = cfg.yew_attestor.clone().map(|program| yew::YewCli {
            program,
            key_file: cfg.key_file.clone(),
            endpoints: cfg.endpoints.clone(),
            insecure: cfg.endpoints.iter().any(|e| e.starts_with("http://")),
            timeout: yew::TIMEOUT,
        });
        Self::with_upstreams(ups, &cfg.key_file, &cfg.guard_file, yew, cfg.cosign_endpoints)
    }

    pub fn with_upstreams(
        ups: Vec<Box<dyn Upstream>>,
        key_file: &std::path::Path,
        guard_file: &std::path::Path,
        yew: Option<yew::YewCli>,
        cosign_endpoints: usize,
    ) -> Result<Self, String> {
        if ups.is_empty() {
            return Err("[backend] lightwalletd: at least one endpoint".into());
        }
        let key = SeatKey::load(key_file)?;
        let guard = Guard::load(guard_file)?;
        tracing::info!(
            "light backend: seat key {}, guard {} ({} line(s)), {} endpoint(s): {}{}",
            key.pubkey_hex(),
            guard.path().display(),
            guard.len(),
            ups.len(),
            ups.iter().map(|u| u.name().to_string()).collect::<Vec<_>>().join(", "),
            if yew.is_none() {
                "; no yew_attestor: no heartbeat, cancel driving or on-chain fallback"
            } else {
                ""
            }
        );
        Ok(Light {
            cosign_endpoints: cosign_endpoints.clamp(1, ups.len()),
            ups,
            preferred: AtomicUsize::new(0),
            key,
            key_file: key_file.to_path_buf(),
            guard: tokio::sync::Mutex::new(guard),
            yew,
            cache: Default::default(),
        })
    }

    pub fn key_file(&self) -> &std::path::Path {
        &self.key_file
    }

    // ------------------------------------------------------------------------------------------- endpoints

    /// The first endpoint that answers, starting from the last one that did (B-6). A node refusal relayed by an
    /// endpoint is an answer; only the endpoint's own trouble (unreachable, a deadline, a rate limit) or an answer
    /// `check` rejects moves on to the next.
    async fn first_checked(&self, req: Req, check: impl Fn(&Value) -> Result<(), String>) -> Result<Value, RpcError> {
        let n = self.ups.len();
        let start = self.preferred.load(Ordering::Relaxed) % n;
        let mut last = RpcError::Transport("no endpoint".into());
        for k in 0..n {
            let i = (start + k) % n;
            match self.ups[i].call(req.clone()).await {
                Ok(v) => match check(&v) {
                    Ok(()) => {
                        if i != start {
                            tracing::warn!("light backend: answered by {} (failover)", self.ups[i].name());
                            self.preferred.store(i, Ordering::Relaxed);
                        }
                        return Ok(v);
                    }
                    Err(e) => {
                        tracing::warn!("light backend: {}: {e}", self.ups[i].name());
                        last = RpcError::Transport(format!("{}: {e}", self.ups[i].name()));
                    }
                },
                Err(e @ RpcError::Node { .. }) => return Err(e),
                Err(e) => {
                    tracing::debug!("light backend: {}: {e}", self.ups[i].name());
                    last = e;
                }
            }
        }
        Err(last)
    }

    async fn first(&self, req: Req) -> Result<Value, RpcError> {
        self.first_checked(req, |_| Ok(())).await
    }

    /// Every endpoint at once, in configuration order.
    async fn all(&self, req: Req) -> Vec<Result<Value, RpcError>> {
        n0_future::join_all(self.ups.iter().map(|u| u.call(req.clone()))).await
    }

    /// blockHash(height), display hex: every endpoint is asked; two that answer must agree (B-7). An endpoint
    /// whose chain is shorter does not answer for that height and is not counted.
    pub async fn hash_at(&self, height: u32) -> Result<String, RpcError> {
        let got = self.all(Req::Block(height as u64)).await;
        let mut seen: Vec<(usize, String)> = Vec::new();
        let mut first_err = None;
        for (i, r) in got.into_iter().enumerate() {
            match r {
                Ok(v) => match v.get("hash").and_then(Value::as_str).filter(|h| h.len() == 64) {
                    Some(h) => seen.push((i, h.to_string())),
                    None => {
                        first_err.get_or_insert(RpcError::Transport(format!(
                            "{}: GetBlock without a hash",
                            self.ups[i].name()
                        )));
                    }
                },
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        let Some((_, h)) = seen.first().cloned() else {
            return Err(first_err.unwrap_or_else(|| RpcError::Transport("no endpoint".into())));
        };
        if let Some((j, other)) = seen.iter().find(|(_, x)| *x != h) {
            let msg = format!(
                "endpoint-disagreement: at height {height} {} serves {h} and {} serves {other}; nothing is signed on \
                 either until they agree",
                self.ups[seen[0].0].name(),
                self.ups[*j].name()
            );
            tracing::error!("light backend: {msg}");
            return Err(RpcError::Node {
                code: -32,
                message: msg,
            });
        }
        self.cache.lock().expect("cache").heights.insert(h.clone(), height);
        Ok(h)
    }

    async fn info(&self) -> Result<Value, RpcError> {
        let v = self.first(Req::Info).await?;
        if let Some(n) = v.get("network").and_then(Value::as_str).filter(|n| !n.is_empty()) {
            self.cache.lock().expect("cache").network = Some(n.to_string());
        }
        Ok(v)
    }

    /// The seat key's WIF network must be the endpoints' (a mainnet key on a test network, or the reverse, is a
    /// misconfiguration: nothing is signed).
    async fn check_network(&self) -> Result<(), RpcError> {
        let n = self.network().await?;
        if (n == "main") != self.key.mainnet() {
            return Err(node_err(format!(
                "attest-key-not-held: the seat key is a {} key and the endpoints serve {n}",
                if self.key.mainnet() { "mainnet" } else { "test-network" }
            )));
        }
        Ok(())
    }

    async fn network(&self) -> Result<String, RpcError> {
        if let Some(n) = self.cache.lock().expect("cache").network.clone() {
            return Ok(n);
        }
        let v = self.info().await?;
        Ok(v.get("network").and_then(Value::as_str).unwrap_or("").to_string())
    }

    async fn attestors(&self) -> Result<Vec<Value>, RpcError> {
        let v = self.first(Req::Attestors).await?;
        let rows = v.as_array().cloned().unwrap_or_default();
        self.cache.lock().expect("cache").attestors = rows.clone();
        Ok(rows)
    }

    async fn cached_attestors(&self) -> Result<Vec<Value>, RpcError> {
        let rows = self.cache.lock().expect("cache").attestors.clone();
        if rows.is_empty() {
            self.attestors().await
        } else {
            Ok(rows)
        }
    }

    // ----------------------------------------------------------------------------------------- dispatch

    /// Answer one node RPC (see the table at the top of this module).
    pub async fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, RpcError> {
        match method {
            "yed_getinfo" => self.info().await,
            "yed_listattestors" => self.attestors().await.map(Value::Array),
            "set_getinfo" => {
                let id = param_str(&params, 0).ok_or_else(|| node_err("set_getinfo setid"))?;
                self.first(Req::Set(id.to_string())).await
            }
            "yed_getattestations" => self.first(Req::Attestations).await,
            "yed_listvaults" => {
                let status = param_str(&params, 0).unwrap_or("").to_string();
                let count = param_u64(&params, 1).unwrap_or(100) as u32;
                let skip = param_u64(&params, 2).unwrap_or(0) as u32;
                self.first(Req::Vaults { status, count, skip }).await
            }
            "yed_getvault" => {
                let t = param_str(&params, 0).ok_or_else(|| node_err("yed_getvault txid"))?;
                self.first(Req::Vault(t.to_string())).await
            }
            "yed_decodepayload" => {
                let h = param_str(&params, 0).ok_or_else(|| node_err("yed_decodepayload hex"))?;
                self.first(Req::DecodePayload(h.to_string())).await
            }
            "gettxout" => {
                let txid = param_str(&params, 0)
                    .ok_or_else(|| node_err("gettxout txid"))?
                    .to_string();
                let vout = param_u64(&params, 1).unwrap_or(0) as u32;
                let mempool = params.get(2).and_then(Value::as_bool).unwrap_or(true);
                self.first(Req::TxOut { txid, vout, mempool }).await
            }
            "getrawtransaction" => {
                let txid = param_str(&params, 0).ok_or_else(|| node_err("getrawtransaction txid"))?;
                self.raw_tx(txid).await.map(Value::String)
            }
            "getblockhash" => {
                let h = param_u64(&params, 0).ok_or_else(|| node_err("getblockhash height"))?;
                self.hash_at(h as u32).await.map(Value::String)
            }
            "getblock" => {
                let hash = param_str(&params, 0).ok_or_else(|| node_err("getblock hash"))?;
                self.block(hash).await
            }
            "getrawmempool" => {
                let mut ids = BTreeSet::new();
                let mut err = None;
                for r in self.all(Req::Mempool).await {
                    match r {
                        Ok(v) => ids.extend(
                            v.as_array()
                                .map(Vec::as_slice)
                                .unwrap_or(&[])
                                .iter()
                                .filter_map(Value::as_str)
                                .map(String::from),
                        ),
                        Err(e) => err = Some(e),
                    }
                }
                match (ids.is_empty(), err) {
                    (true, Some(e)) if self.ups.len() == 1 => Err(e),
                    _ => Ok(json!(ids.into_iter().collect::<Vec<_>>())),
                }
            }
            "getblockchaininfo" => {
                let c = self.first(Req::ChainInfo).await?;
                let blocks = c.get("blockHeight").and_then(Value::as_i64).unwrap_or(-1);
                let est = match self.first(Req::LightdInfo).await {
                    Ok(l) => l.get("estimatedHeight").and_then(Value::as_i64).unwrap_or(0),
                    Err(_) => 0,
                };
                let headers = blocks.max(est);
                Ok(json!({
                    "chain": c.get("chainName").cloned().unwrap_or(Value::Null),
                    "blocks": blocks,
                    "headers": headers,
                    "bestblockhash": c.get("bestBlockHash").cloned().unwrap_or(Value::Null),
                    "initial_block_download_complete": blocks >= 0 && headers - blocks <= 2,
                }))
            }
            "sendrawtransaction" => {
                let h = param_str(&params, 0).ok_or_else(|| node_err("sendrawtransaction hex"))?;
                self.send(h).await.map(Value::String)
            }
            "yed_addattestation" => {
                let h = param_str(&params, 0).ok_or_else(|| node_err("yed_addattestation hex"))?;
                self.submit(h).await
            }
            "validateaddress" => {
                let a = param_str(&params, 0).unwrap_or("");
                let mine = self.own_address(a).await?;
                Ok(if mine {
                    json!({"isvalid": true, "address": a, "ismine": true, "iscompressed": true, "pubkey": self.key.pubkey_hex()})
                } else {
                    json!({"isvalid": true, "address": a, "ismine": false})
                })
            }
            "signmessage" => {
                let a = param_str(&params, 0).unwrap_or("");
                let msg = param_str(&params, 1).ok_or_else(|| node_err("signmessage message"))?;
                if !self.own_address(a).await? {
                    return Err(RpcError::Node {
                        code: -4,
                        message: format!("Private key not available: {a} is not this seat's member key address"),
                    });
                }
                Ok(Value::String(self.key.sign_message(msg)))
            }
            "yed_signattestation" => self.sign_attestation(&params).await,
            "yed_signcancelcosign" => self.sign_cancel_cosign(&params).await,
            "set_heartbeat" => {
                let set = param_str(&params, 0).ok_or_else(|| node_err("set_heartbeat setid"))?;
                let member = param_str(&params, 1).unwrap_or("");
                if !member.is_empty() && member != self.key.pubkey_hex() {
                    return Err(node_err(format!(
                        "attest-key-not-held: member {member} is not this seat's key"
                    )));
                }
                self.yew("heartbeat", vec!["--set".into(), set.to_string()], None).await
            }
            "yed_buildcancel" => self.build_cancel(&params).await,
            "set_signcancel" => {
                let h = param_str(&params, 0).unwrap_or("");
                if self.cache.lock().expect("cache").sent.contains_key(h) {
                    Ok(json!({"hex": h, "complete": true}))
                } else {
                    Err(node_err(
                        "set_signcancel: a light seat's cancel is built, signed and sent by yew-attestor (yed_buildcancel)",
                    ))
                }
            }
            "vault_send" => {
                let h = param_str(&params, 0).ok_or_else(|| node_err("vault_send hex"))?;
                let known = self.cache.lock().expect("cache").sent.get(h).cloned();
                match known {
                    Some(txid) => {
                        // already sent by yew-attestor; pushed again, an "already" refusal is expected
                        let _ = self.send(h).await;
                        Ok(Value::String(txid))
                    }
                    None => self.send(h).await.map(Value::String),
                }
            }
            "vault_refee" => Err(RpcError::Node {
                code: -32601,
                message:
                    "vault_refee is not available on a light seat: the cancel is rebuilt by yew-attestor from the \
                          seat's own coins"
                        .into(),
            }),
            other => Err(RpcError::Node {
                code: -32601,
                message: format!("Method not found: {other} is not served by the lightwalletd backend"),
            }),
        }
    }

    // ---------------------------------------------------------------------------------------------- reads

    /// The raw transaction, checked to be `txid` (versions 1..4; a v5 one is taken as served).
    async fn raw_tx(&self, txid: &str) -> Result<String, RpcError> {
        let want = txid.to_ascii_lowercase();
        let v = self
            .first_checked(Req::Tx(txid.to_string()), |v| {
                let raw = hex::decode(v.get("hex").and_then(Value::as_str).unwrap_or("")).map_err(|e| e.to_string())?;
                match tx::txid_v4(&raw) {
                    Some(id) if id != want => Err(format!("served a transaction that is not {want} (it is {id})")),
                    _ if raw.is_empty() => Err("served an empty transaction".into()),
                    _ => Ok(()),
                }
            })
            .await?;
        Ok(v.get("hex").and_then(Value::as_str).unwrap_or("").to_string())
    }

    /// `getblock <hash> 2` as far as the agent reads it (`onchain::records_in_block`): the transactions of the block
    /// that can carry a "YF" record — those with shielded parts (the compact block) and every member address's (the
    /// fallback is funded from the seat's own address). A record funded from another address is not seen here.
    async fn block(&self, hash: &str) -> Result<Value, RpcError> {
        let height = self.cache.lock().expect("cache").heights.get(hash).copied();
        let Some(height) = height else {
            return Err(node_err(format!(
                "getblock {hash}: unknown to the light backend (getblockhash first)"
            )));
        };
        let b = self.first(Req::Block(height as u64)).await?;
        let mut ids: BTreeSet<String> = b
            .get("vtx")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect();
        let mut raws: HashMap<String, String> = HashMap::new();
        let addrs: BTreeSet<String> = self
            .cached_attestors()
            .await?
            .iter()
            .filter_map(|r| r.get("bondKeyAddress").and_then(Value::as_str))
            .filter(|a| !a.is_empty())
            .map(String::from)
            .collect();
        for a in addrs {
            let rows = self
                .first(Req::AddressTxids {
                    address: a,
                    start: height as u64,
                    end: height as u64,
                })
                .await?;
            for r in rows.as_array().map(Vec::as_slice).unwrap_or(&[]) {
                let Some(h) = r.get("hex").and_then(Value::as_str) else {
                    continue;
                };
                if r.get("height")
                    .and_then(Value::as_u64)
                    .is_some_and(|x| x != height as u64)
                {
                    continue;
                }
                if let Some(id) = hex::decode(h).ok().and_then(|b| tx::txid_v4(&b)) {
                    ids.insert(id.clone());
                    raws.insert(id, h.to_string());
                }
            }
        }
        let mut txs = Vec::new();
        for id in ids {
            let h = match raws.remove(&id) {
                Some(h) => h,
                None => self.raw_tx(&id).await?,
            };
            let raw = hex::decode(&h).unwrap_or_default();
            let vout: Vec<Value> = tx::outputs(&raw)
                .unwrap_or_default()
                .into_iter()
                .enumerate()
                .map(|(n, (zat, script))| {
                    json!({"n": n, "valueZat": zat, "value": zat as f64 / 1e8, "scriptPubKey": {"hex": hex::encode(script)}})
                })
                .collect();
            txs.push(json!({"txid": id, "vout": vout}));
        }
        Ok(json!({"hash": hash, "height": height, "tx": txs}))
    }

    /// Whether `addr` is a member key address (`bondKeyAddress`) of this seat's key in the attestor registry.
    async fn own_address(&self, addr: &str) -> Result<bool, RpcError> {
        let mine = self.key.pubkey_hex();
        let check = |rows: &[Value]| {
            rows.iter().any(|r| {
                r.get("bondKeyAddress").and_then(Value::as_str) == Some(addr)
                    && r.get("attestorPubKey").and_then(Value::as_str) == Some(mine.as_str())
            })
        };
        if check(&self.cached_attestors().await?) {
            return Ok(true);
        }
        Ok(check(&self.attestors().await?))
    }

    // ------------------------------------------------------------------------------------------------ writes

    /// `SendTransaction` to every endpoint; the txid once one accepts it.
    async fn send(&self, hex_str: &str) -> Result<String, RpcError> {
        let raw = hex::decode(hex_str).map_err(|_| node_err("TX decode failed"))?;
        let txid = tx::txid_v4(&raw);
        let mut errors = Vec::new();
        let mut ok = false;
        for (i, r) in self.all(Req::Send(hex_str.to_string())).await.into_iter().enumerate() {
            match r {
                Ok(v) if v.get("errorCode").and_then(Value::as_i64).unwrap_or(0) == 0 => ok = true,
                Ok(v) => {
                    let m = v.get("errorMessage").and_then(Value::as_str).unwrap_or("").to_string();
                    if m.contains("already") {
                        ok = true;
                    } else {
                        errors.push(format!("{}: {m}", self.ups[i].name()));
                    }
                }
                Err(e) => errors.push(format!("{}: {e}", self.ups[i].name())),
            }
        }
        if ok {
            if !errors.is_empty() {
                tracing::warn!("light backend: SendTransaction refused by {}", errors.join("; "));
            }
            Ok(txid.unwrap_or_default())
        } else {
            Err(RpcError::Node {
                code: -26,
                message: errors.join("; "),
            })
        }
    }

    /// `SubmitAttestation` to every endpoint (B-2): the first acceptance's result.
    async fn submit(&self, hex_str: &str) -> Result<Value, RpcError> {
        let mut first_ok = None;
        let mut errors = Vec::new();
        let mut node_refusal = None;
        for (i, r) in self.all(Req::Submit(hex_str.to_string())).await.into_iter().enumerate() {
            match r {
                Ok(v) => {
                    first_ok.get_or_insert(v);
                }
                Err(e) => {
                    if let RpcError::Node { .. } = &e {
                        node_refusal.get_or_insert(RpcError::Node {
                            code: -8,
                            message: e.to_string(),
                        });
                    }
                    errors.push(format!("{}: {e}", self.ups[i].name()));
                }
            }
        }
        if !errors.is_empty() {
            tracing::warn!("light backend: SubmitAttestation: {}", errors.join("; "));
        }
        match first_ok {
            Some(v) => Ok(v),
            None => Err(node_refusal.unwrap_or_else(|| RpcError::Transport(errors.join("; ")))),
        }
    }

    async fn yew(&self, command: &str, mut args: Vec<String>, stdin: Option<String>) -> Result<Value, RpcError> {
        let Some(cli) = &self.yew else {
            return Err(RpcError::Node {
                code: -32601,
                message: format!(
                    "{command}: [backend] yew_attestor is not configured; a light seat sends transactions through it"
                ),
            });
        };
        let network = self.network().await?;
        args.insert(0, command.to_string());
        cli.run(&network, &args, stdin).await
    }

    /// The on-chain fallback (`onchain.rs`): one transaction with one OP_RETURN output carrying `data` (the 79-byte
    /// "YF" record), funded from the seat's own coins, fee exactly `fee_zat`.
    pub async fn op_return(&self, data: &[u8], fee_zat: i64) -> Result<String, RpcError> {
        let v = self
            .yew(
                "op-return",
                vec![
                    "--data".into(),
                    hex::encode(data),
                    "--fee-zat".into(),
                    fee_zat.to_string(),
                ],
                None,
            )
            .await?;
        Ok(v.get("txid").and_then(Value::as_str).unwrap_or("").to_string())
    }

    /// `yed_buildcancel intent [cosig hex…]` on a light seat: yew-attestor builds the carrier and the cancel, signs
    /// and sends both; `set_signcancel` and `vault_send` then only hand back what it did.
    async fn build_cancel(&self, params: &[Value]) -> Result<Value, RpcError> {
        let intent = param_str(params, 0).ok_or_else(|| node_err("yed_buildcancel intent"))?;
        let hexes: Vec<String> = params
            .get(1)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default();
        let v = self
            .yew(
                "cancel",
                vec!["--intent".into(), intent.to_string(), "--cosigs".into(), "-".into()],
                Some(json!(hexes).to_string()),
            )
            .await?;
        let hex_str = v.get("hex").and_then(Value::as_str).unwrap_or("").to_string();
        let txid = v.get("txid").and_then(Value::as_str).unwrap_or("").to_string();
        if hex_str.is_empty() {
            return Err(RpcError::Transport(format!("yew-attestor cancel returned no hex: {v}")));
        }
        self.cache.lock().expect("cache").sent.insert(hex_str.clone(), txid);
        let cosigners = self.cosigners(intent, &hexes).await.unwrap_or_default();
        Ok(json!({
            "hex": hex_str,
            "txid": v.get("txid").cloned().unwrap_or(Value::Null),
            "carrierTxid": v.get("carrierTxid").cloned().unwrap_or(Value::Null),
            "cosigners": cosigners,
            "warnings": [],
        }))
    }

    /// The seqs whose co-signatures `hexes` are (recovered over the claim's message), for the log.
    async fn cosigners(&self, intent: &str, hexes: &[String]) -> Result<Vec<u16>, RpcError> {
        let t = self.claim_target(intent, false).await?;
        let rows = self.cached_attestors().await?;
        let (txid, n) = crate::cosig::parse_intent(intent).ok_or_else(|| node_err("intent"))?;
        let mut out = Vec::new();
        for h in hexes {
            let Some(e) = crate::cosig::Entry::decode_hex(h) else {
                continue;
            };
            let msg = crate::cosig::message(&t.set_id, &txid, n, t.ref_height, e.price, &t.block_hash);
            let Some(k) = crate::cosig::recover(&msg, &e.sig) else {
                continue;
            };
            let k = hex::encode(k);
            if let Some(s) = rows
                .iter()
                .filter(|r| r.get("attestorPubKey").and_then(Value::as_str) == Some(k.as_str()))
                .filter_map(|r| r.get("seq").and_then(Value::as_u64))
                .max()
            {
                out.push(s as u16);
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------------------------------------- signing

    /// `SignAttestationGuarded` (`txbuilder.cpp`): the guard decides before anything is signed; the guard is also
    /// looked up across every seq this key holds (EQV-1 binds a statement to the key). Returns (sig, reused).
    async fn sign_guarded(
        &self,
        rows: &[Value],
        seq: u16,
        price: i64,
        cited: u32,
        block_hash: &str,
    ) -> Result<([u8; 64], bool), RpcError> {
        let mine = self.key.pubkey_hex();
        let row = rows
            .iter()
            .find(|r| r.get("seq").and_then(Value::as_u64) == Some(seq as u64))
            .ok_or_else(|| node_err(format!("attest-unknown-seq: no attestor with seq {seq}")))?;
        if row.get("attestorPubKey").and_then(Value::as_str) != Some(mine.as_str()) {
            return Err(node_err(format!(
                "attest-key-not-held: the hot key of seq {seq} is not this seat's key file"
            )));
        }
        if !(PRICE_MIN..=PRICE_MAX).contains(&price) {
            return Err(node_err(format!(
                "attest-range: priceMicroUsd must be in [{PRICE_MIN}, {PRICE_MAX}]"
            )));
        }
        let bh = crate::cosig::internal_from_display(block_hash).ok_or_else(|| node_err("block hash"))?;
        let price = price as u32;
        let key_seqs: Vec<u16> = rows
            .iter()
            .filter(|r| r.get("attestorPubKey").and_then(Value::as_str) == Some(mine.as_str()))
            .filter_map(|r| r.get("seq").and_then(Value::as_u64))
            .filter_map(|s| u16::try_from(s).ok())
            .collect();
        let mut guard = self.guard.lock().await;
        guard.reload().map_err(|e| node_err(format!("guard-unreadable: {e}")))?;
        for s in key_seqs.iter().copied().filter(|s| *s != seq) {
            if let Some(o) = guard.lookup(s, cited, &bh) {
                if o.price != price {
                    return Err(node_err(format!(
                        "equivocation-guard: this key already signed {} for height {cited} under seq {s}",
                        o.price
                    )));
                }
            }
        }
        if let Some(p) = guard.lookup(seq, cited, &bh) {
            if p.price != price {
                return Err(node_err(format!(
                    "equivocation-guard: seq {seq} already signed {} for height {cited}",
                    p.price
                )));
            }
            return Ok((p.sig, true));
        }
        let msg = crate::cosig::attest_message(seq, price, cited, &bh);
        let sig = self.key.sign_compact(&msg);
        if !crate::cosig::verify_attestation(&self.key.pubkey(), seq, price, cited, &bh, &sig) {
            return Err(node_err("attestation signature does not verify"));
        }
        guard
            .record(Signed {
                seq,
                cited_height: cited,
                price,
                sig,
                block_hash: bh,
            })
            .map_err(|e| {
                tracing::error!("light backend: {e}");
                node_err("guard-write-failed: the equivocation guard could not be written; nothing was returned")
            })?;
        Ok((sig, false))
    }

    /// `yed_signattestation seq priceMicroUsd [citedHeight]`.
    async fn sign_attestation(&self, params: &[Value]) -> Result<Value, RpcError> {
        let seq = param_u64(params, 0)
            .and_then(|s| u16::try_from(s).ok())
            .ok_or_else(|| node_err("seq must be a u16"))?;
        let price = params
            .get(1)
            .and_then(Value::as_i64)
            .ok_or_else(|| node_err("priceMicroUsd"))?;
        let info = self.info().await?;
        let tip = info.get("height").and_then(Value::as_i64).unwrap_or(-1);
        let cited = match param_u64(params, 2) {
            Some(c) => c as i64,
            None => tip - 2,
        };
        if cited < 0 || cited > tip {
            return Err(node_err(format!(
                "attest-stale: citedHeight {cited} must be in [0, {tip}]"
            )));
        }
        let cited = cited as u32;
        self.check_network().await?;
        let rows = self.attestors().await?;
        let bh = self.hash_at(cited).await?;
        let (sig, reused) = self.sign_guarded(&rows, seq, price, cited, &bh).await?;
        let att = crate::framing::Attestation {
            seq,
            price_micro_usd: price as u32,
            cited_height: cited,
            sig,
        };
        Ok(json!({
            "hex": att.to_hex(),
            "seq": seq,
            "priceMicroUsd": price,
            "citedHeight": cited,
            "reused": reused,
        }))
    }

    /// The claim behind a claimant intent, as `CancelTargetOf` reads it: the vault (from `yed_listvaults
    /// CLAIMING`), the claim's refHeight (its REDEEM payload) and blockHash(refHeight), the attestor set and θ.
    /// With `strict` (co-signing, B-10) every endpoint is asked: `cosign_endpoints` of them must show the claim and
    /// none that answers may deny it.
    async fn claim_target(&self, intent: &str, strict: bool) -> Result<Target, RpcError> {
        let (txid_disp, n) = intent
            .split_once(':')
            .and_then(|(t, n)| Some((t.to_ascii_lowercase(), n.parse::<u32>().ok()?)))
            .ok_or_else(|| node_err("intentoutpoint must be \"txid:n\""))?;
        let idxs: Vec<usize> = if strict {
            (0..self.ups.len()).collect()
        } else {
            vec![self.preferred.load(Ordering::Relaxed) % self.ups.len()]
        };
        let found = n0_future::join_all(idxs.iter().map(|&i| self.find_claim(i, &txid_disp, n))).await;
        let mut shown = Vec::new();
        let mut denied = Vec::new();
        let mut first_err = None;
        for (k, r) in found.into_iter().enumerate() {
            match r {
                Ok(Some(x)) => shown.push(x),
                Ok(None) => denied.push(self.ups[idxs[k]].name().to_string()),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if !denied.is_empty() {
            return Err(node_err(format!(
                "claim-not-shown: {} does not show {intent} as a confirmed claim; not co-signed (B-10)",
                denied.join(", ")
            )));
        }
        let need = if strict { self.cosign_endpoints } else { 1 };
        if shown.len() < need {
            return Err(first_err.unwrap_or_else(|| {
                node_err(format!(
                    "claim-unconfirmed: {intent} is shown by {} endpoint(s), {need} required before co-signing (B-10)",
                    shown.len()
                ))
            }));
        }
        let (row, confirm_height) = shown.swap_remove(0);
        // the claim's refHeight from its own payload (the transaction is checked to be the intent's txid)
        let raw = self.raw_tx(&txid_disp).await?;
        let dec = self.first(Req::DecodePayload(raw)).await?;
        let ref_height = dec
            .get("refHeight")
            .and_then(Value::as_u64)
            .and_then(|r| u32::try_from(r).ok())
            .filter(|r| *r > 0)
            .ok_or_else(|| node_err("the claim carries no refHeight"))?;
        let bh_disp = self.hash_at(ref_height).await?;
        let info = self.info().await?;
        let set_disp = info
            .get("upgrade")
            .and_then(|u| u.get("attestorSetId"))
            .and_then(Value::as_str)
            .or_else(|| {
                info.get("params")
                    .and_then(|p| p.get("attestorSetId"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("")
            .to_string();
        let set_id = crate::cosig::internal_from_display(&set_disp)
            .ok_or_else(|| node_err("no attestorSetId in yed_getinfo"))?;
        let theta = info
            .get("params")
            .and_then(|p| p.get("claimThresholdBps"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        Ok(Target {
            set_id,
            set_disp,
            theta,
            ref_height,
            block_hash: crate::cosig::internal_from_display(&bh_disp).ok_or_else(|| node_err("block hash"))?,
            block_hash_disp: bh_disp,
            collateral_zat: row.get("collateralZat").and_then(Value::as_i64).unwrap_or(0),
            minted_cents: row.get("mintedCents").and_then(Value::as_i64).unwrap_or(0),
            confirm_height,
        })
    }

    /// The CLAIMING vault row holding `txid:n` as its claimant intent on endpoint `i`, with the intent's height.
    async fn find_claim(&self, i: usize, txid: &str, n: u32) -> Result<Option<(Value, u32)>, RpcError> {
        let mut skip = 0u32;
        loop {
            let page = self.ups[i]
                .call(Req::Vaults {
                    status: "CLAIMING".into(),
                    count: 100,
                    skip,
                })
                .await?;
            let rows = page.as_array().cloned().unwrap_or_default();
            for row in &rows {
                for it in row
                    .get("intents")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[])
                {
                    if it.get("role").and_then(Value::as_str) == Some("claimant")
                        && it
                            .get("txid")
                            .and_then(Value::as_str)
                            .map(str::to_ascii_lowercase)
                            .as_deref()
                            == Some(txid)
                        && it.get("vout").and_then(Value::as_u64) == Some(n as u64)
                    {
                        let h = it.get("height").and_then(Value::as_u64).unwrap_or(0) as u32;
                        return Ok(Some((row.clone(), h)));
                    }
                }
            }
            if rows.len() < 100 {
                return Ok(None);
            }
            skip += 100;
        }
    }

    /// `yed_signcancelcosign intent [priceMicroUsd] [seq]` (`yellowbackwallet.cpp`), the price locked through the
    /// guard exactly as the node locks it: the default is the price this key already signed for the claim's
    /// refHeight; a different one is refused; with none on record the price must be given and is recorded.
    async fn sign_cancel_cosign(&self, params: &[Value]) -> Result<Value, RpcError> {
        let intent = param_str(params, 0).ok_or_else(|| node_err("intentoutpoint must be \"txid:n\""))?;
        let (txid, n) =
            crate::cosig::parse_intent(intent).ok_or_else(|| node_err("intentoutpoint must be \"txid:n\""))?;
        self.check_network().await?;
        let t = self.claim_target(intent, true).await?;
        let rows = self.attestors().await?;
        let mine = self.key.pubkey_hex();
        let my_seqs: Vec<u16> = rows
            .iter()
            .filter(|r| r.get("attestorPubKey").and_then(Value::as_str) == Some(mine.as_str()))
            .filter_map(|r| r.get("seq").and_then(Value::as_u64))
            .filter_map(|s| u16::try_from(s).ok())
            .collect();
        let seq = match param_u64(params, 2) {
            Some(s) => u16::try_from(s).map_err(|_| node_err("seq must be a u16"))?,
            None => *my_seqs.iter().max().ok_or_else(|| {
                node_err("attest-key-not-held: this seat's key is no current member key of the attestor set")
            })?,
        };
        if !rows
            .iter()
            .any(|r| r.get("seq").and_then(Value::as_u64) == Some(seq as u64))
        {
            return Err(node_err(format!("attest-unknown-seq: no attestor with seq {seq}")));
        }
        // CurrentMember: the key is current in the set's memberlist and seq is the key's newest record
        let set = self.first(Req::Set(t.set_disp.clone())).await?;
        let current = crate::cancel::current_keys(&set).is_some_and(|k| k.contains(&self.key.pubkey()));
        if !current || my_seqs.iter().max() != Some(&seq) {
            return Err(node_err(format!(
                "attest-not-eligible: seq {seq} is not a current member of the attestor set"
            )));
        }
        let bh = t.block_hash;
        let r = t.ref_height;
        let prior = {
            let mut guard = self.guard.lock().await;
            guard.reload().map_err(|e| node_err(format!("guard-unreadable: {e}")))?;
            let mut prior: Option<(u16, u32)> = None;
            for s in &my_seqs {
                if let Some(o) = guard.lookup(*s, r, &bh) {
                    if prior.is_some_and(|(_, p)| p != o.price) {
                        return Err(node_err(format!(
                            "equivocation-guard: this key already signed two prices for height {r}"
                        )));
                    }
                    prior = Some((*s, o.price));
                }
            }
            prior
        };
        let price = match params.get(1).filter(|v| !v.is_null()).and_then(Value::as_i64) {
            Some(p) => {
                if let Some((s, pp)) = prior.filter(|(_, pp)| *pp as i64 != p) {
                    return Err(node_err(format!(
                        "equivocation-guard: seq {s} already signed {pp} for height {r}"
                    )));
                }
                p
            }
            None => match prior {
                Some((_, p)) => p as i64,
                None => {
                    return Err(node_err(format!(
                        "price-required: this key signed no price for the claim's refHeight {r}; pass priceMicroUsd"
                    )))
                }
            },
        };
        if !(PRICE_MIN..=PRICE_MAX).contains(&price) {
            return Err(node_err(format!(
                "attest-range: priceMicroUsd must be in [{PRICE_MIN}, {PRICE_MAX}]"
            )));
        }
        if crate::cosig::is_underwater(t.collateral_zat, price, t.minted_cents, t.theta) {
            return Err(node_err(format!(
                "cancel-statement-claimable: at {price} micro-USD the vault was claimable at refHeight {r}; a cancel \
                 co-signature states it was not"
            )));
        }
        // S16: lock this key's price for R (an attestation at R is signed and recorded, as the node does)
        let (_, reused) = self.sign_guarded(&rows, seq, price, r, &t.block_hash_disp).await?;
        let msg = crate::cosig::message(&t.set_id, &txid, n, r, price as u32, &bh);
        let entry = crate::cosig::Entry {
            price: price as u32,
            sig: self.key.sign_recoverable(&msg),
        };
        tracing::info!(
            "light backend: co-signed the cancel of {intent} (claim confirmed at {}) at {price} µUSD, refHeight {r}",
            t.confirm_height
        );
        Ok(json!({
            "cosig": entry.to_hex(),
            "seq": seq,
            "priceMicroUsd": price,
            "citedHeight": r,
            "reused": reused,
        }))
    }
}

struct Target {
    set_id: [u8; 32],
    set_disp: String,
    theta: u32,
    ref_height: u32,
    block_hash: [u8; 32],
    block_hash_disp: String,
    collateral_zat: i64,
    minted_cents: i64,
    confirm_height: u32,
}

#[cfg(test)]
pub mod fake {
    //! An in-process endpoint for the tests: each request is answered by a closure; every request is logged.
    use super::*;
    use std::sync::{Arc, Mutex};

    pub type Handler = Arc<dyn Fn(&Req) -> Result<Value, RpcError> + Send + Sync>;

    pub struct FakeUpstream {
        pub name: String,
        pub handler: Arc<Mutex<Handler>>,
        pub log: Arc<Mutex<Vec<Req>>>,
    }

    impl FakeUpstream {
        pub fn new(name: &str, h: impl Fn(&Req) -> Result<Value, RpcError> + Send + Sync + 'static) -> Self {
            FakeUpstream {
                name: name.into(),
                handler: Arc::new(Mutex::new(Arc::new(h))),
                log: Default::default(),
            }
        }
    }

    impl Upstream for FakeUpstream {
        fn name(&self) -> &str {
            &self.name
        }
        fn call(&self, req: Req) -> BoxFut<'_, Result<Value, RpcError>> {
            self.log.lock().unwrap().push(req.clone());
            let h = self.handler.lock().unwrap().clone();
            Box::pin(async move { h(&req) })
        }
    }

    /// A small consistent chain for the tests: blocks `0..=tip` with hash `h(height)`, seq 1 held by `key`.
    pub struct Chain {
        pub tip: u32,
        pub key_hex: String,
        pub set_id: String,
        /// a vault in CLAIMING with this claimant intent (txid, n), confirmed at `claim_height`
        pub claim: Option<(String, u32)>,
        pub claim_height: u32,
        pub claim_tx: Vec<u8>,
        pub ref_height: u32,
        pub collateral_zat: i64,
        pub minted_cents: i64,
        /// bump every hash by this (a lying endpoint)
        pub hash_fork: u8,
        pub down: bool,
    }

    /// The fake chain's block hash at `height`: SHA-256 of the height and the chain's `fork` byte, so two fakes
    /// with different bytes disagree at every height.
    pub fn h(height: u32, fork: u8) -> String {
        use sha2::{Digest, Sha256};
        let mut d = Sha256::new();
        d.update(height.to_le_bytes());
        d.update([fork]);
        hex::encode(d.finalize())
    }

    impl Chain {
        pub fn answer(&self, req: &Req) -> Result<Value, RpcError> {
            if self.down {
                return Err(RpcError::Transport("connection refused".into()));
            }
            match req {
                Req::Info => Ok(json!({
                    "network": "regtest", "height": self.tip,
                    "params": {"claimThresholdBps": 12500, "claimDelay": 20},
                    "upgrade": {"attestorSetId": self.set_id, "claimDelay": 20},
                })),
                Req::Attestors => Ok(json!([
                    {"seq": 1, "attestorPubKey": self.key_hex, "bondKeyAddress": "tmSeat", "status": "ELIGIBLE", "bondSpentHeight": null},
                    {"seq": 2, "attestorPubKey": "03".to_string() + &"22".repeat(32), "bondKeyAddress": "tmOther", "status": "ELIGIBLE", "bondSpentHeight": null},
                ])),
                Req::Set(_) => Ok(json!({"memberlist": [{"key": self.key_hex, "current": true}]})),
                Req::Block(height) if *height as u32 <= self.tip => {
                    Ok(json!({"height": height, "hash": h(*height as u32, self.hash_fork), "vtx": []}))
                }
                Req::Block(_) => Err(RpcError::Node {
                    code: 11,
                    message: "block requested is newer than latest block".into(),
                }),
                Req::Vaults { .. } => Ok(match &self.claim {
                    Some((t, n)) => json!([{
                        "txid": "aa".repeat(32), "vout": 0, "status": "CLAIMING",
                        "collateralZat": self.collateral_zat, "mintedCents": self.minted_cents,
                        "intents": [{"txid": t, "vout": n, "role": "claimant", "height": self.claim_height, "releaseHeight": self.claim_height + 20}],
                    }]),
                    None => json!([]),
                }),
                Req::Tx(_) => Ok(json!({"hex": hex::encode(&self.claim_tx), "height": self.claim_height})),
                Req::DecodePayload(_) => Ok(json!({"type": "REDEEM", "refHeight": self.ref_height})),
                Req::Send(_) => Ok(json!({"errorCode": 0, "errorMessage": ""})),
                Req::Submit(_) => Ok(json!({"accepted": true, "seq": 1})),
                Req::Mempool => Ok(json!([])),
                other => Err(RpcError::Node {
                    code: -32601,
                    message: format!("fake: {other:?}"),
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{h, Chain, FakeUpstream};
    use super::*;
    use crate::signer::testkit;
    use std::sync::{Arc, Mutex};

    struct Rig {
        dir: tempfile::TempDir,
        chains: Vec<Arc<Mutex<Chain>>>,
        logs: Vec<Arc<Mutex<Vec<Req>>>>,
    }

    fn claim_tx() -> Vec<u8> {
        // any v4 transaction: its txid is the intent's
        let mut t = vec![0x04, 0, 0, 0x80, 0x85, 0x20, 0x2f, 0x89, 0, 0];
        t.extend_from_slice(&[0u8; 4 + 4 + 8 + 3]);
        t
    }

    fn chain(key: &SeatKey) -> Chain {
        let ct = claim_tx();
        Chain {
            tip: 100,
            key_hex: key.pubkey_hex(),
            set_id: "5e".repeat(32),
            claim: Some((tx::txid_v4(&ct).unwrap(), 1)),
            claim_height: 95,
            claim_tx: ct,
            ref_height: 90,
            collateral_zat: 10 * 100_000_000,
            minted_cents: 100 * 100,
            hash_fork: 0,
            down: false,
        }
    }

    impl Rig {
        fn new(endpoints: usize) -> (Rig, Light) {
            let dir = tempfile::tempdir().unwrap();
            let rig = Rig {
                dir,
                chains: Vec::new(),
                logs: Vec::new(),
            };
            rig.light(endpoints, None, 2)
        }

        fn light(mut self, endpoints: usize, yew: Option<yew::YewCli>, cosign: usize) -> (Rig, Light) {
            let kf = self.dir.path().join("seat.key");
            std::fs::write(&kf, testkit::wif(1)).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let key = SeatKey::load(&kf).unwrap();
            if self.chains.is_empty() {
                for _ in 0..endpoints {
                    self.chains.push(Arc::new(Mutex::new(chain(&key))));
                }
            }
            let mut ups: Vec<Box<dyn Upstream>> = Vec::new();
            self.logs.clear();
            for (i, c) in self.chains.iter().enumerate() {
                let c = c.clone();
                let f = FakeUpstream::new(&format!("lwd{i}"), move |r| c.lock().unwrap().answer(r));
                self.logs.push(f.log.clone());
                ups.push(Box::new(f));
            }
            let light = Light::with_upstreams(ups, &kf, &self.dir.path().join("seat.guard"), yew, cosign).unwrap();
            (self, light)
        }

        fn restart(self) -> (Rig, Light) {
            let n = self.chains.len();
            self.light(n, None, 2)
        }

        fn set(&self, i: usize, f: impl FnOnce(&mut Chain)) {
            f(&mut self.chains[i].lock().unwrap());
        }
    }

    fn err(r: Result<Value, RpcError>) -> String {
        match r {
            Err(e) => e.to_string(),
            Ok(v) => panic!("expected an error, got {v}"),
        }
    }

    #[tokio::test]
    async fn signs_an_attestation_the_node_would_accept_and_guards_it() {
        let (rig, l) = Rig::new(2);
        let v = l
            .call("yed_signattestation", vec![json!(1), json!(50_000), json!(98)])
            .await
            .unwrap();
        assert_eq!(v["reused"], false);
        let att = crate::framing::Attestation::decode_hex(v["hex"].as_str().unwrap()).unwrap();
        assert_eq!((att.seq, att.price_micro_usd, att.cited_height), (1, 50_000, 98));
        let bh = crate::cosig::internal_from_display(&h(98, 0)).unwrap();
        assert!(crate::cosig::verify_attestation(
            &testkit::key(1).pubkey(),
            1,
            50_000,
            98,
            &bh,
            &att.sig
        ));
        // the same price again: the recorded signature, reused
        let again = l
            .call("yed_signattestation", vec![json!(1), json!(50_000), json!(98)])
            .await
            .unwrap();
        assert_eq!(
            (again["hex"].clone(), again["reused"].clone()),
            (v["hex"].clone(), json!(true))
        );
        // a different price for the same (seq, citedHeight, hash): refused
        let e = err(l
            .call("yed_signattestation", vec![json!(1), json!(51_000), json!(98)])
            .await);
        assert!(e.starts_with("equivocation-guard"), "{e}");
        // the guard persists across a restart
        drop(l);
        let (rig, l) = rig.restart();
        let e = err(l
            .call("yed_signattestation", vec![json!(1), json!(51_000), json!(98)])
            .await);
        assert!(e.starts_with("equivocation-guard"), "{e}");
        // after a reorg across citedHeight (another hash) a new price is not equivocation
        rig.set(0, |c| c.hash_fork = 7);
        rig.set(1, |c| c.hash_fork = 7);
        let v2 = l
            .call("yed_signattestation", vec![json!(1), json!(51_000), json!(98)])
            .await
            .unwrap();
        assert_eq!(v2["reused"], false);
        // refusals the node makes
        let e = err(l
            .call("yed_signattestation", vec![json!(2), json!(50_000), json!(98)])
            .await);
        assert!(e.starts_with("attest-key-not-held"), "{e}");
        let e = err(l
            .call("yed_signattestation", vec![json!(9), json!(50_000), json!(98)])
            .await);
        assert!(e.starts_with("attest-unknown-seq"), "{e}");
        let e = err(l.call("yed_signattestation", vec![json!(1), json!(5), json!(98)]).await);
        assert!(e.starts_with("attest-range"), "{e}");
        let e = err(l
            .call("yed_signattestation", vec![json!(1), json!(50_000), json!(101)])
            .await);
        assert!(e.starts_with("attest-stale"), "{e}");
    }

    #[tokio::test]
    async fn endpoints_fail_over_and_must_agree_on_the_cited_hash() {
        let (rig, l) = Rig::new(2);
        // B-6: one endpoint down, the other answers every read and the seat keeps signing
        rig.set(0, |c| c.down = true);
        assert_eq!(l.call("yed_getinfo", vec![]).await.unwrap()["height"], 100);
        assert_eq!(l.preferred.load(Ordering::Relaxed), 1);
        l.call("yed_signattestation", vec![json!(1), json!(50_000), json!(98)])
            .await
            .unwrap();
        // B-7: both answer with different hashes: nothing is signed, and nothing is recorded
        rig.set(0, |c| {
            c.down = false;
            c.hash_fork = 9
        });
        let e = err(l
            .call("yed_signattestation", vec![json!(1), json!(52_000), json!(97)])
            .await);
        assert!(e.starts_with("endpoint-disagreement"), "{e}");
        assert!(err(l.call("getblockhash", vec![json!(97)]).await).starts_with("endpoint-disagreement"));
        assert_eq!(l.guard.lock().await.len(), 1);
        // an endpoint behind the cited height is not counted
        rig.set(0, |c| {
            c.hash_fork = 0;
            c.tip = 90
        });
        l.call("yed_signattestation", vec![json!(1), json!(52_000), json!(97)])
            .await
            .unwrap();
        // both down: a transport error, no signature
        rig.set(0, |c| c.down = true);
        rig.set(1, |c| c.down = true);
        assert!(matches!(
            l.call("yed_signattestation", vec![json!(1), json!(53_000), json!(96)])
                .await,
            Err(RpcError::Transport(_))
        ));
        // a node refusal relayed by an endpoint is an answer, not a failover
        rig.set(0, |c| c.down = false);
        rig.set(1, |c| c.down = false);
        let before = rig.logs[1].lock().unwrap().len();
        let pref = l.preferred.load(Ordering::Relaxed);
        let _ = l.call("yed_getvault", vec![json!("ab")]).await.unwrap_err();
        let asked: usize = rig.logs.iter().map(|x| x.lock().unwrap().len()).sum::<usize>();
        assert!(asked > before);
        assert_eq!(l.preferred.load(Ordering::Relaxed), pref);
    }

    #[tokio::test]
    async fn cosigns_only_a_claim_both_endpoints_show_and_locks_its_price() {
        let (rig, l) = Rig::new(2);
        let intent = format!("{}:1", tx::txid_v4(&claim_tx()).unwrap());
        // no price on record and none given
        let e = err(l
            .call("yed_signcancelcosign", vec![json!(intent), Value::Null, json!(1)])
            .await);
        assert!(e.starts_with("price-required"), "{e}");
        // the attestation the seat signed at the refHeight fixes the price
        l.call("yed_signattestation", vec![json!(1), json!(20_000_000), json!(90)])
            .await
            .unwrap();
        let v = l
            .call("yed_signcancelcosign", vec![json!(intent), Value::Null, json!(1)])
            .await
            .unwrap();
        assert_eq!(
            (v["priceMicroUsd"].clone(), v["reused"].clone()),
            (json!(20_000_000), json!(true))
        );
        let entry = crate::cosig::Entry::decode_hex(v["cosig"].as_str().unwrap()).unwrap();
        let (txid, n) = crate::cosig::parse_intent(&intent).unwrap();
        let msg = crate::cosig::message(
            &crate::cosig::internal_from_display(&"5e".repeat(32)).unwrap(),
            &txid,
            n,
            90,
            20_000_000,
            &crate::cosig::internal_from_display(&h(90, 0)).unwrap(),
        );
        assert_eq!(crate::cosig::recover(&msg, &entry.sig), Some(testkit::key(1).pubkey()));
        // another price than the recorded one: the co-signature would be equivocation
        let e = err(l
            .call("yed_signcancelcosign", vec![json!(intent), json!(30_000_000), json!(1)])
            .await);
        assert!(e.starts_with("equivocation-guard"), "{e}");
        // B-10: a claim one endpoint does not show is not co-signed
        rig.set(1, |c| c.claim = None);
        let e = err(l
            .call("yed_signcancelcosign", vec![json!(intent), Value::Null, json!(1)])
            .await);
        assert!(e.starts_with("claim-not-shown"), "{e}");
        // ... nor while one endpoint is down (2 of 2 required)
        rig.set(1, |c| {
            c.claim = rig.chains[0].lock().unwrap().claim.clone();
            c.down = true
        });
        let e = err(l
            .call("yed_signcancelcosign", vec![json!(intent), Value::Null, json!(1)])
            .await);
        assert!(
            e.contains("connection refused") || e.starts_with("claim-unconfirmed"),
            "{e}"
        );
    }

    #[tokio::test]
    async fn a_cosignature_records_its_price_and_refuses_a_claimable_statement() {
        let (_rig, l) = Rig::new(1);
        let intent = format!("{}:1", tx::txid_v4(&claim_tx()).unwrap());
        // 10 YEC against $100 at θ 125 %: claimable below $12.50 a YEC (12_500_000 µUSD)
        let e = err(l
            .call("yed_signcancelcosign", vec![json!(intent), json!(1_000_000), json!(1)])
            .await);
        assert!(e.starts_with("cancel-statement-claimable"), "{e}");
        let v = l
            .call("yed_signcancelcosign", vec![json!(intent), json!(20_000_000), json!(1)])
            .await
            .unwrap();
        assert_eq!(v["reused"], false);
        // the co-signature locked the price at R: an attestation at R at another price is refused (C4b)
        let e = err(l
            .call("yed_signattestation", vec![json!(1), json!(19_000_000), json!(90)])
            .await);
        assert!(e.starts_with("equivocation-guard"), "{e}");
        l.call("yed_signattestation", vec![json!(1), json!(20_000_000), json!(90)])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn binding_signatures_heartbeat_and_cancel_go_through_the_seat_key_and_yew() {
        let f = yew::fake::FakeYew::new();
        let dir = tempfile::tempdir().unwrap();
        let rig = Rig {
            dir,
            chains: Vec::new(),
            logs: Vec::new(),
        };
        let cli = yew::YewCli {
            program: f.program.clone(),
            key_file: rig.dir.path().join("seat.key"),
            endpoints: vec!["http://127.0.0.1:39390".into()],
            insecure: true,
            timeout: Duration::from_secs(10),
        };
        let (rig, l) = rig.light(2, Some(cli), 2);
        // validateaddress / signmessage: the seat's own member key address only
        let v = l.call("validateaddress", vec![json!("tmSeat")]).await.unwrap();
        assert_eq!(v["pubkey"], testkit::key(1).pubkey_hex());
        assert_eq!(
            l.call("validateaddress", vec![json!("tmOther")]).await.unwrap()["ismine"],
            false
        );
        let sig = l
            .call("signmessage", vec![json!("tmSeat"), json!("hello")])
            .await
            .unwrap();
        let b = crate::binding::Binding::from_signmessage("hello".into(), sig.as_str().unwrap()).unwrap();
        assert_eq!(
            crate::binding::recover_signer("hello", &b.sig),
            Some(testkit::key(1).pubkey())
        );
        assert!(l.call("signmessage", vec![json!("tmOther"), json!("x")]).await.is_err());
        // set_heartbeat -> yew-attestor heartbeat
        f.answer("heartbeat", r#"{"txid":"beef"}"#, 0);
        let v = l
            .call(
                "set_heartbeat",
                vec![json!("5e".repeat(32)), json!(testkit::key(1).pubkey_hex())],
            )
            .await
            .unwrap();
        assert_eq!(v["txid"], "beef");
        assert!(f.args()[0].ends_with(&format!("heartbeat --set {}", "5e".repeat(32))));
        assert!(f.args()[0].starts_with("--network regtest --key-file "));
        // yed_buildcancel -> yew-attestor cancel; set_signcancel and vault_send hand back what it sent
        f.answer(
            "cancel",
            r#"{"carrierTxid":"cc","txid":"dd","carrierHex":"00","hex":"0400008085202f89"}"#,
            0,
        );
        let intent = format!("{}:1", tx::txid_v4(&claim_tx()).unwrap());
        let built = l
            .call("yed_buildcancel", vec![json!(intent), json!(["ab", "cd"])])
            .await
            .unwrap();
        assert_eq!(built["carrierTxid"], "cc");
        assert_eq!(f.stdin(), r#"["ab","cd"]"#);
        assert!(f.args()[1].ends_with(&format!("cancel --intent {intent} --cosigs -")));
        let s = l.call("set_signcancel", vec![built["hex"].clone()]).await.unwrap();
        assert_eq!(s["complete"], true);
        assert_eq!(l.call("vault_send", vec![s["hex"].clone()]).await.unwrap(), "dd");
        assert!(l.call("set_signcancel", vec![json!("ff")]).await.is_err());
        // a refusal keeps the node's identifier first, so cancel.rs sets the entry aside as before
        f.answer(
            "cancel",
            r#"{"error":"cosigs[1] is not a current member","code":"cancel-cosign-not-member"}"#,
            1,
        );
        let e = err(l
            .call("yed_buildcancel", vec![json!(intent), json!(["ab", "cd"])])
            .await);
        assert_eq!(crate::cancel::refused_index(&e), Some(1));
        assert!(e.starts_with("cancel-cosign-not-member"));
        // the on-chain fallback
        f.answer("op-return", r#"{"txid":"ee"}"#, 0);
        assert_eq!(l.op_return(&[0x59, 0x46], 10_000).await.unwrap(), "ee");
        assert!(f
            .args()
            .last()
            .unwrap()
            .ends_with("op-return --data 5946 --fee-zat 10000"));
        drop(rig);
    }

    #[tokio::test]
    async fn writes_go_to_every_endpoint() {
        let (rig, l) = Rig::new(2);
        let t = super::tx::txid_v4(&claim_tx()).unwrap();
        assert_eq!(
            l.call("sendrawtransaction", vec![json!(hex::encode(claim_tx()))])
                .await
                .unwrap(),
            t
        );
        assert!(
            l.call("yed_addattestation", vec![json!("00")]).await.unwrap()["accepted"]
                .as_bool()
                .unwrap()
        );
        for log in &rig.logs {
            let log = log.lock().unwrap();
            assert!(log.iter().any(|r| matches!(r, Req::Send(_))));
            assert!(log.iter().any(|r| matches!(r, Req::Submit(_))));
        }
        // one endpoint down: still sent
        rig.set(0, |c| c.down = true);
        l.call("yed_addattestation", vec![json!("00")]).await.unwrap();
        assert!(l.call("nosuchmethod", vec![]).await.is_err());
        assert!(l.call("vault_refee", vec![json!("00")]).await.is_err());
    }
}
