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
        } => {
            let topic = topic_override.clone().unwrap_or_else(|| topic_name(network));
            Box::new(iroh::IrohTransport::open(relays, peers, secret_key_file.as_deref(), &topic).await?)
        }
    })
}

/// The attestation topic and the cancel topic, sharing one iroh endpoint (or the `dir` bus and its `cancel/`).
pub async fn open_with_cancel(
    cfg: &TransportConfig,
    network: &str,
) -> anyhow::Result<(Box<dyn Transport>, Box<dyn Transport>)> {
    Ok(match cfg {
        TransportConfig::Dir { path } => (
            Box::new(dir::DirTransport::open(path)?),
            Box::new(dir::DirTransport::open_cancel(path)?),
        ),
        TransportConfig::Iroh {
            relays,
            peers,
            secret_key_file,
            topic_override,
        } => {
            let topic = topic_override.clone().unwrap_or_else(|| topic_name(network));
            let cancel = match topic_override {
                Some(t) => format!("{t}/cancel"),
                None => cancel_topic_name(network),
            };
            let mut v =
                iroh::IrohTransport::open_topics(relays, peers, secret_key_file.as_deref(), &[&topic, &cancel]).await?;
            let c = v.pop().expect("two topics");
            let a = v.pop().expect("two topics");
            (Box::new(a), Box::new(c))
        }
    })
}

/// Run `transport` on its own task: what arrives goes to the returned receiver, what is sent on the returned sender
/// is published. The loop ends when the sender is dropped or the transport fails (logged).
pub fn spawn_pump(
    mut transport: Box<dyn Transport>,
) -> (tokio::sync::mpsc::Sender<Vec<u8>>, tokio::sync::mpsc::Receiver<Vec<u8>>) {
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
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
                got = transport.recv() => match got {
                    Ok(m) => {
                        // a full inbox drops (the receiver's rate limit would drop it anyway)
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

#[cfg(test)]
mod tests {
    #[test]
    fn topic_names_the_network_and_payload_version() {
        assert_eq!(super::topic_name("main"), "yellowback/attest/main/3");
        assert_eq!(super::topic_name("regtest"), "yellowback/attest/regtest/3");
        assert_eq!(super::cancel_topic_name("main"), "yellowback/cancel/main/1");
    }
}
