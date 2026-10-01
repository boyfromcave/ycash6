//! `iroh` transport: one `iroh-gossip` topic per network. The topic id is SHA-256 of the topic
//! name of plan §5. Relays come from `[transport] relays` (empty: iroh's default relay set;
//! `["none"]`: no relay, direct only). `iroh-gossip` has no topic discovery of its own, so the
//! swarm is bootstrapped from `[transport] peers` — endpoint ids other operators publish — and
//! this agent prints its own endpoint id at startup for the same purpose. `secret_key_file`
//! keeps that id stable across restarts (created on first use, mode 0600).

use std::path::Path;

use anyhow::Context;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_gossip::proto::TopicId;
use n0_future::StreamExt;
use sha2::{Digest, Sha256};

use super::{BoxFuture, Transport};

pub struct IrohTransport {
    endpoint: Endpoint,
    lookup: MemoryLookup,
    router: Router,
    _gossip: Gossip,
    sender: GossipSender,
    receiver: GossipReceiver,
}

pub fn topic_id(topic: &str) -> TopicId {
    TopicId::from_bytes(Sha256::digest(topic.as_bytes()).into())
}

fn load_or_create_secret(path: Option<&Path>) -> anyhow::Result<SecretKey> {
    let Some(path) = path else {
        return Ok(SecretKey::generate());
    };
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let bytes = hex::decode(text.trim()).with_context(|| format!("secret_key_file {}", path.display()))?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("secret_key_file {}: not 32 bytes", path.display()))?;
            Ok(SecretKey::from_bytes(&arr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, hex::encode(key.to_bytes()))
                .with_context(|| format!("secret_key_file {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            tracing::info!("iroh: new secret key written to {}", path.display());
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("secret_key_file {}", path.display())),
    }
}

fn relay_mode(relays: &[String]) -> anyhow::Result<RelayMode> {
    if relays.is_empty() {
        return Ok(RelayMode::Default);
    }
    if relays.len() == 1 && relays[0].eq_ignore_ascii_case("none") {
        return Ok(RelayMode::Disabled);
    }
    let urls = relays
        .iter()
        .map(|r| r.parse::<RelayUrl>().with_context(|| format!("relay url {r:?}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(RelayMode::Custom(urls.into_iter().collect::<RelayMap>()))
}

impl IrohTransport {
    pub async fn open(
        relays: &[String],
        peers: &[String],
        secret_key_file: Option<&Path>,
        topic: &str,
    ) -> anyhow::Result<Self> {
        let secret = load_or_create_secret(secret_key_file)?;
        let bootstrap = peers
            .iter()
            .map(|p| {
                p.parse::<EndpointId>()
                    .with_context(|| format!("peer endpoint id {p:?}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mode = relay_mode(relays)?;
        let lookup = MemoryLookup::new();
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .address_lookup(lookup.clone())
            .relay_mode(mode.clone())
            .bind()
            .await
            .context("iroh bind")?;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let router = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();
        if !matches!(mode, RelayMode::Disabled) {
            endpoint.online().await;
        }
        tracing::info!(
            "iroh: endpoint id {} (give this to peers as [transport] peers); topic {topic}",
            endpoint.id()
        );
        if bootstrap.is_empty() {
            tracing::warn!("iroh: no [transport] peers configured; waiting for peers to dial us");
        }
        // `subscribe` (not `subscribe_and_join`): the topic is usable before a neighbour appears,
        // and publications queue until one does.
        let sub = gossip
            .subscribe(topic_id(topic), bootstrap)
            .await
            .context("iroh-gossip subscribe")?;
        let (sender, receiver) = sub.split();
        Ok(IrohTransport {
            endpoint,
            lookup,
            router,
            _gossip: gossip,
            sender,
            receiver,
        })
    }

    /// Used by the tests and kept public for a future `peers`-less bootstrap path.
    #[allow(dead_code)]
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    #[allow(dead_code)]
    pub fn endpoint_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Make a peer dialable by its full address (the tests, and a relay-less deployment).
    #[allow(dead_code)]
    pub fn add_peer_addr(&self, addr: EndpointAddr) {
        self.lookup.add_endpoint_info(addr);
    }

    #[allow(dead_code)]
    pub async fn shutdown(self) {
        let _ = self.router.shutdown().await;
    }
}

impl Transport for IrohTransport {
    fn name(&self) -> &'static str {
        "iroh"
    }

    fn publish<'a>(&'a mut self, message: &'a [u8]) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let n: usize = self.receiver.neighbors().count();
            if n == 0 {
                tracing::warn!("iroh: no neighbours on the topic yet; the message is queued");
            }
            self.sender
                .broadcast(bytes::Bytes::copy_from_slice(message))
                .await
                .context("iroh-gossip broadcast")
        })
    }

    fn recv(&mut self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        Box::pin(async move {
            loop {
                match self.receiver.next().await {
                    Some(Ok(Event::Received(msg))) => return Ok(msg.content.to_vec()),
                    Some(Ok(Event::NeighborUp(id))) => tracing::info!("iroh: neighbour up {}", id.fmt_short()),
                    Some(Ok(Event::NeighborDown(id))) => tracing::info!("iroh: neighbour down {}", id.fmt_short()),
                    Some(Ok(Event::Lagged)) => tracing::warn!("iroh: receiver lagged; some messages were dropped"),
                    Some(Err(e)) => anyhow::bail!("iroh-gossip: {e}"),
                    None => anyhow::bail!("iroh-gossip: topic closed"),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_id_is_sha256_of_the_name() {
        let id = topic_id("yellowback/attest/main/3");
        assert_eq!(id.as_bytes(), &Sha256::digest(b"yellowback/attest/main/3")[..]);
        assert_ne!(topic_id("yellowback/attest/test/3"), id);
    }

    #[test]
    fn relay_modes() {
        assert!(matches!(relay_mode(&[]).unwrap(), RelayMode::Default));
        assert!(matches!(relay_mode(&["none".into()]).unwrap(), RelayMode::Disabled));
        assert!(matches!(
            relay_mode(&["https://relay.example".into()]).unwrap(),
            RelayMode::Custom(_)
        ));
        assert!(relay_mode(&["not a url".into()]).is_err());
    }

    #[test]
    fn secret_key_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("keys/iroh.key");
        let a = load_or_create_secret(Some(&p)).unwrap();
        let b = load_or_create_secret(Some(&p)).unwrap();
        assert_eq!(a.public(), b.public());
        std::fs::write(&p, "zz").unwrap();
        assert!(load_or_create_secret(Some(&p)).is_err());
    }

    /// Two endpoints on one machine, no relay: publish on one, receive on the other.
    #[tokio::test]
    async fn local_gossip_round_trip() {
        let none = vec!["none".to_string()];
        let a = IrohTransport::open(&none, &[], None, "yellowback/attest/regtest/3")
            .await
            .unwrap();
        let a_id = a.endpoint_id().to_string();
        // b needs a's address, not only its id, without a relay or discovery: hand it over directly.
        let mut b = IrohTransport::open(&none, &[a_id], None, "yellowback/attest/regtest/3")
            .await
            .unwrap();
        let mut a = a;
        b.add_peer_addr(a.endpoint_addr());
        let mut a_rx = a.receiver;
        let mut b_rx_joined = false;
        // give the topic a moment to join; then broadcast from b and read on a
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        while !b_rx_joined && tokio::time::Instant::now() < deadline {
            tokio::select! {
                r = b.receiver.joined() => { r.unwrap(); b_rx_joined = true; }
                _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
            }
        }
        assert!(b_rx_joined, "b never joined a");
        b.sender.broadcast(bytes::Bytes::from_static(&[7u8; 74])).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(Ok(Event::Received(m))) = a_rx.next().await {
                    return m.content.to_vec();
                }
            }
        })
        .await
        .expect("no message within 10 s");
        assert_eq!(got, vec![7u8; 74]);
        a.receiver = a_rx;
        a.shutdown().await;
        b.shutdown().await;
    }
}
