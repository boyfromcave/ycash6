// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! One lightwalletd-dd endpoint over gRPC (light attestor contract §1): each [`Req`] is one CompactTxStreamer or
//! YellowbackStreamer call, its answer turned into the JSON the node's RPC of the same meaning returns. The
//! YellowbackStreamer messages carry the node's JSON field names (lightwalletd-dd unmarshals the node's result into
//! them), so they serialize back to that shape; the few differences (proto3 zeros for the node's nulls, bytes for
//! hashes) are fixed up here.

use std::time::Duration;

use serde_json::{json, Value};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::Code;

use super::proto::compact_tx_streamer_client::CompactTxStreamerClient;
use super::proto::yellowback_streamer_client::YellowbackStreamerClient;
use super::proto::{
    BlockId, BlockRange, Empty, HeightFilter, RawTransaction, TransparentAddressBlockFilter, TxFilter, VaultSetQuery,
    YedAttestationFrame, YedHex, YedTxOutQuery, YedTxid, YedVaultFilter,
};
use super::{BoxFut, Req, Upstream};
use crate::rpc::RpcError;

/// The largest message accepted from an endpoint (a vault listing page, a block's transactions).
const MAX_MESSAGE: usize = 16 << 20;

pub struct GrpcUpstream {
    url: String,
    chan: Channel,
}

impl GrpcUpstream {
    /// A lazily connected channel to `url` (`https://` with the Mozilla roots, or plain `http://` h2c).
    pub fn new(url: &str, timeout: Duration) -> Result<Self, String> {
        let mut ep = Endpoint::from_shared(url.to_string())
            .map_err(|e| format!("lightwalletd endpoint {url:?}: {e}"))?
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .tcp_keepalive(Some(Duration::from_secs(60)));
        if url.starts_with("https://") {
            ep = ep
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .map_err(|e| format!("lightwalletd endpoint {url:?}: TLS: {e}"))?;
        }
        Ok(GrpcUpstream {
            url: url.to_string(),
            chan: ep.connect_lazy(),
        })
    }

    fn cs(&self) -> CompactTxStreamerClient<Channel> {
        CompactTxStreamerClient::new(self.chan.clone()).max_decoding_message_size(MAX_MESSAGE)
    }

    fn ys(&self) -> YellowbackStreamerClient<Channel> {
        YellowbackStreamerClient::new(self.chan.clone()).max_decoding_message_size(MAX_MESSAGE)
    }

    async fn run(&self, req: Req) -> Result<Value, tonic::Status> {
        Ok(match req {
            Req::Info => to_json(self.ys().get_yellowback_info(Empty {}).await?.into_inner()),
            Req::Attestors => {
                let mut s = self.ys().list_attestors(HeightFilter { height: 0 }).await?.into_inner();
                let mut rows = Vec::new();
                while let Some(m) = s.message().await? {
                    rows.push(attestor_json(to_json(m)));
                }
                Value::Array(rows)
            }
            Req::Set(setid) => to_json(
                self.ys()
                    .get_set(VaultSetQuery { setid, height: 0 })
                    .await?
                    .into_inner(),
            ),
            Req::Block(height) => {
                let b = self
                    .cs()
                    .get_block(BlockId { height, hash: vec![] })
                    .await?
                    .into_inner();
                json!({
                    "height": b.height,
                    "hash": display(&b.hash),
                    "vtx": b.vtx.iter().map(|t| display(&t.hash)).collect::<Vec<_>>(),
                })
            }
            Req::ChainInfo => to_json(self.ys().get_chain_info(Empty {}).await?.into_inner()),
            Req::LightdInfo => to_json(self.cs().get_lightd_info(Empty {}).await?.into_inner()),
            Req::Tx(txid) => {
                let hash = internal(&txid).ok_or_else(|| tonic::Status::invalid_argument("txid is not 32-byte hex"))?;
                let t = self
                    .cs()
                    .get_transaction(TxFilter {
                        block: None,
                        index: 0,
                        hash: hash.to_vec(),
                    })
                    .await?
                    .into_inner();
                json!({"hex": hex::encode(&t.data), "height": t.height})
            }
            Req::DecodePayload(hex) => to_json(self.ys().decode_payload(YedHex { hex }).await?.into_inner()),
            Req::Attestations => {
                let mut s = self.ys().get_attestations(Empty {}).await?.into_inner();
                let mut rows = Vec::new();
                while let Some(m) = s.message().await? {
                    rows.push(to_json(m));
                }
                Value::Array(rows)
            }
            Req::Vaults { status, count, skip } => {
                let mut s = self
                    .ys()
                    .list_vaults(YedVaultFilter { status, count, skip })
                    .await?
                    .into_inner();
                let mut rows = Vec::new();
                while let Some(m) = s.message().await? {
                    rows.push(to_json(m));
                }
                Value::Array(rows)
            }
            Req::Vault(txid) => to_json(self.ys().get_vault(YedTxid { txid }).await?.into_inner()),
            Req::TxOut { txid, vout, mempool } => {
                let o = self
                    .ys()
                    .get_tx_out(YedTxOutQuery {
                        txid,
                        vout,
                        include_mempool: mempool,
                    })
                    .await?
                    .into_inner();
                if !o.found {
                    Value::Null
                } else {
                    json!({
                        "bestblock": o.bestblock,
                        "confirmations": o.confirmations,
                        "value": o.value_zat as f64 / 1e8,
                        "valueZat": o.value_zat,
                        "scriptPubKey": {"hex": o.script_pub_key_hex},
                        "coinbase": o.coinbase,
                    })
                }
            }
            Req::Mempool => json!(self.ys().get_mempool_txids(Empty {}).await?.into_inner().txids),
            Req::Send(hex_str) => {
                let data = hex::decode(&hex_str).map_err(|_| tonic::Status::invalid_argument("not hex"))?;
                let r = self
                    .cs()
                    .send_transaction(RawTransaction { data, height: 0 })
                    .await?
                    .into_inner();
                json!({"errorCode": r.error_code, "errorMessage": r.error_message})
            }
            Req::Submit(hex_str) => {
                let frame = hex::decode(&hex_str).map_err(|_| tonic::Status::invalid_argument("not hex"))?;
                to_json(
                    self.ys()
                        .submit_attestation(YedAttestationFrame { frame })
                        .await?
                        .into_inner(),
                )
            }
            Req::AddressTxids { address, start, end } => {
                let mut s = self
                    .cs()
                    .get_taddress_txids(TransparentAddressBlockFilter {
                        address,
                        range: Some(BlockRange {
                            start: Some(BlockId {
                                height: start,
                                hash: vec![],
                            }),
                            end: Some(BlockId {
                                height: end,
                                hash: vec![],
                            }),
                        }),
                    })
                    .await?
                    .into_inner();
                let mut rows = Vec::new();
                while let Some(t) = s.message().await? {
                    rows.push(json!({"hex": hex::encode(&t.data), "height": t.height}));
                }
                Value::Array(rows)
            }
        })
    }
}

impl Upstream for GrpcUpstream {
    fn name(&self) -> &str {
        &self.url
    }

    fn call(&self, req: Req) -> BoxFut<'_, Result<Value, RpcError>> {
        Box::pin(async move { self.run(req).await.map_err(status_error) })
    }
}

fn to_json<T: serde::Serialize>(m: T) -> Value {
    serde_json::to_value(m).unwrap_or(Value::Null)
}

/// A hash in the protos' byte order (internal) as the RPC's display hex.
fn display(b: &[u8]) -> String {
    let mut r = b.to_vec();
    r.reverse();
    hex::encode(r)
}

fn internal(display_hex: &str) -> Option<[u8; 32]> {
    crate::cosig::internal_from_display(display_hex)
}

/// `yed_listattestors` row: proto3 writes the node's null `bondSpentHeight` (an unspent bond) as 0.
pub fn attestor_json(mut v: Value) -> Value {
    if v.get("bondSpentHeight").and_then(Value::as_i64) == Some(0) {
        v["bondSpentHeight"] = Value::Null;
    }
    v
}

/// The node's refusals reach the client as FailedPrecondition / InvalidArgument / NotFound … with the node's message:
/// those are answers. Unavailable, a deadline, a rate limit or an internal error are the endpoint's trouble: the
/// next endpoint is tried.
pub fn status_error(s: tonic::Status) -> RpcError {
    match s.code() {
        Code::FailedPrecondition
        | Code::InvalidArgument
        | Code::NotFound
        | Code::PermissionDenied
        | Code::OutOfRange
        | Code::AlreadyExists => RpcError::Node {
            code: s.code() as i64,
            message: s.message().to_string(),
        },
        c => RpcError::Transport(format!("{c:?}: {}", s.message())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestor_rows_and_errors_and_hashes() {
        let v = attestor_json(json!({"seq": 1, "bondSpentHeight": 0}));
        assert!(v["bondSpentHeight"].is_null());
        assert_eq!(attestor_json(json!({"bondSpentHeight": 7}))["bondSpentHeight"], 7);
        assert!(matches!(
            status_error(tonic::Status::failed_precondition("vault-not-found")),
            RpcError::Node { message, .. } if message == "vault-not-found"
        ));
        assert!(matches!(
            status_error(tonic::Status::unavailable("down")),
            RpcError::Transport(_)
        ));
        assert_eq!(display(&[1, 2]), "0201");
        // a YellowbackStreamer message serializes with the node's JSON names
        let a = super::super::proto::YedAttestor {
            attestor_pub_key: "02aa".into(),
            bond_key_address: "tm".into(),
            seq: 3,
            status: "ELIGIBLE".into(),
            ..Default::default()
        };
        let j = attestor_json(to_json(a));
        assert_eq!(j["attestorPubKey"], "02aa");
        assert_eq!(j["bondKeyAddress"], "tm");
        assert_eq!(j["seq"], 3);
        assert!(j["bondSpentHeight"].is_null());
        let info = super::super::proto::YellowbackInfo {
            network: "regtest".into(),
            height: 9,
            upgrade: Some(super::super::proto::YellowbackActivation {
                attestor_set_id: "ff".into(),
                claim_delay: 20,
                ..Default::default()
            }),
            ..Default::default()
        };
        let j = to_json(info);
        assert_eq!(j["upgrade"]["attestorSetId"], "ff");
        assert_eq!(j["upgrade"]["claimDelay"], 20);
        assert_eq!(j["network"], "regtest");
    }
}
