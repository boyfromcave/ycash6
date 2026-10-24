// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! Transports (plan §5): the gossip layer carries no trust, so a transport is only "publish
//! bytes" and "receive bytes". `dir` is a shared directory (tests, devnet); `iroh` is
//! `iroh-gossip` (production).

pub mod dir;
pub mod iroh;

use std::future::Future;
use std::pin::Pin;

use anyhow::Context;

use crate::config::TransportConfig;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Topic name of plan §5: `"yellowback/attest/" ‖ network ‖ "/" ‖ PAYLOAD_VERSION`.
pub const PAYLOAD_VERSION: u32 = 3;

pub fn topic_name(network: &str) -> String {
    format!("yellowback/attest/{network}/{PAYLOAD_VERSION}")
}

/// The cancel-limit design's co-signature topic (CAN-2 + C4b): `"yellowback/cancel/" ‖ network ‖ "/" ‖
/// CANCEL_FRAME_VERSION`, on the same iroh endpoint and peers as the attestation topic (`<topic_override>/cancel`
/// when the attestation topic is overridden). Its frames are `cosig::Frame` (115 bytes).
pub const CANCEL_FRAME_VERSION: u32 = 1;

pub fn cancel_topic_name(network: &str) -> String {
    format!("yellowback/cancel/{network}/{CANCEL_FRAME_VERSION}")
}

pub trait Transport: Send {
    fn name(&self) -> &'static str;
    /// Publish one message (a 74-byte attestation).
    fn publish<'a>(&'a mut self, message: &'a [u8]) -> BoxFuture<'a, anyhow::Result<()>>;
    /// The next message from the topic, whatever its size; `Err` means the transport is gone.
    fn recv(&mut self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>>;
    /// The next message and the peer that delivered it (iroh: the neighbour's endpoint id, which is not the author;
    /// a transport that cannot tell names every message "local"). The cancel topic rate-limits by it.
    fn recv_from(&mut self) -> BoxFuture<'_, anyhow::Result<(Vec<u8>, String)>> {
        Box::pin(async move { Ok((self.recv().await?, "local".to_string())) })
    }
}

/// Open the configured transport on `topic` (`network` names the chain the node reports).
pub async fn open(cfg: &TransportConfig, network: &str) -> anyhow::Result<Box<dyn Transport>> {
    Ok(match cfg {
        TransportConfig::Dir { path } => Box::new(dir::DirTransport::open(path)?),
        TransportConfig::Iroh {
            relays,
            peers,
            secret_key_file,
            topic_override,
            fallback_relays,
        } => {
            let topic = topic_override.clone().unwrap_or_else(|| topic_name(network));
            let mut v =
                iroh::IrohTransport::open_topics(relays, fallback_relays, peers, secret_key_file.as_deref(), &[&topic])
                    .await?;
            Box::new(v.remove(0))
        }
    })
}

/// The endpoint-binding topic (owner decision 1): members announce the signed binding of their direct endpoint here
/// (`binding::Announce`, self-verifying; anyone may read them), so agents learn which endpoint ids to admit and dial.
pub const BINDING_VERSION: u32 = 1;

pub fn binding_topic_name(network: &str) -> String {
    format!("yellowback/bindings/{network}/{BINDING_VERSION}")
}

/// The topics `attest` opens: the attestation topic, the cancel gossip topic (only while it is in use: delivery
/// "gossip" or "trial") and the binding topic, sharing one iroh endpoint (or the dir bus's `cancel/` and `bindings/`).
pub struct Topics {
    pub attest: Box<dyn Transport>,
    pub cancel: Option<Box<dyn Transport>>,
    pub bindings: Box<dyn Transport>,
}

pub async fn open_with_cancel(cfg: &TransportConfig, network: &str, cancel_topic: bool) -> anyhow::Result<Topics> {
    Ok(match cfg {
        TransportConfig::Dir { path } => Topics {
            attest: Box::new(dir::DirTransport::open(path)?),
            cancel: if cancel_topic {
                Some(Box::new(dir::DirTransport::open_cancel(path)?))
            } else {
                None
            },
            bindings: Box::new(dir::DirTransport::open_digest(path, "bindings")?),
        },
        TransportConfig::Iroh {
            relays,
            peers,
            secret_key_file,
            topic_override,
            fallback_relays,
        } => {
            let topic = topic_override.clone().unwrap_or_else(|| topic_name(network));
            let (cancel, bindings) = match topic_override {
                Some(t) => (format!("{t}/cancel"), format!("{t}/bindings")),
                None => (cancel_topic_name(network), binding_topic_name(network)),
            };
            let mut names: Vec<&str> = vec![&topic, &bindings];
            if cancel_topic {
                names.push(&cancel);
            }
            let mut v =
                iroh::IrohTransport::open_topics(relays, fallback_relays, peers, secret_key_file.as_deref(), &names)
                    .await?;
            // open_topics returns one transport per name or an error; a short vector is still an error, not a panic.
            let c: Option<Box<dyn Transport>> = if cancel_topic {
                Some(Box::new(v.pop().context("iroh: cancel topic missing")?))
            } else {
                None
            };
            let b = v.pop().context("iroh: binding topic missing")?;
            let a = v.pop().context("iroh: attestation topic missing")?;
            Topics {
                attest: Box::new(a),
                cancel: c,
                bindings: Box::new(b),
            }
        }
    })
}

/// A frame from the cancel topic and the peer that delivered it.
pub type Delivered = (Vec<u8>, String);

/// Run `transport` on its own task: what arrives goes to the returned receiver with its delivering peer, what is
/// sent on the returned sender is published. The task ends when the sender is dropped or the transport fails
/// (logged); the caller sees the receiver close and must not carry on without its topic.
pub fn spawn_pump(
    mut transport: Box<dyn Transport>,
) -> (
    tokio::sync::mpsc::Sender<Vec<u8>>,
    tokio::sync::mpsc::Receiver<Delivered>,
) {
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Delivered>(PUMP_INBOX);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = out_rx.recv() => match msg {
                    Some(m) => {
                        if let Err(e) = transport.publish(&m).await {
                            tracing::error!("cancel topic: publish on {} failed: {e}", transport.name());
                        }
                    }
                    None => return,
                },
                got = transport.recv_from() => match got {
                    Ok(m) => {
                        // the receiver drains continuously (attest's poll loop); a full inbox means it is far
                        // behind, and the frame is dropped rather than queued without bound
                        if in_tx.try_send(m).is_err() {
                            tracing::debug!("cancel topic: inbox full, frame dropped");
                        }
                    }
                    Err(e) => {
                        tracing::error!("cancel topic: {} closed: {e}", transport.name());
                        return;
                    }
                },
            }
        }
    });
    (out_tx, in_rx)
}

pub const PUMP_INBOX: usize = 4096;

#[cfg(test)]
mod tests {
    #[test]
    fn topic_names_the_network_and_payload_version() {
        assert_eq!(super::topic_name("main"), "yellowback/attest/main/3");
        assert_eq!(super::topic_name("regtest"), "yellowback/attest/regtest/3");
        assert_eq!(super::cancel_topic_name("main"), "yellowback/cancel/main/1");
        assert_eq!(super::binding_topic_name("main"), "yellowback/bindings/main/1");
    }
}
