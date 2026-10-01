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

#[cfg(test)]
mod tests {
    #[test]
    fn topic_names_the_network_and_payload_version() {
        assert_eq!(super::topic_name("main"), "yellowback/attest/main/3");
        assert_eq!(super::topic_name("regtest"), "yellowback/attest/regtest/3");
    }
}
