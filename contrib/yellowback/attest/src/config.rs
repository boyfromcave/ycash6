// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! `attest.toml` (plan §4.7). Bad configuration is the one thing that exits non-zero (code 2).

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::price::{self, FeedSettings, FeedSettingsToml, Source, SourceToml};

#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl From<String> for ConfigError {
    fn from(s: String) -> Self {
        ConfigError(s)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeToml {
    pub rpc_url: Option<String>,
    pub rpc_cookie: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub rpc_timeout: Option<u64>,
    /// Basic auth over plain http:// to a host that is not loopback (audit D-7). Off by default.
    pub allow_insecure_rpc: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestToml {
    pub seq: Option<u16>,
    pub every_blocks: Option<u32>,
    pub fail_polls: Option<u32>,
    pub ref_lag: Option<u32>,
    pub poll_seconds: Option<u64>,
    pub heartbeat_blocks: Option<u32>,
    #[serde(flatten)]
    pub feed: FeedSettingsToml,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportToml {
    pub kind: Option<String>,
    pub path: Option<String>,
    pub relays: Option<Vec<String>>,
    pub peers: Option<Vec<String>>,
    pub secret_key_file: Option<String>,
    pub topic_override: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribeToml {
    pub listattestors_seconds: Option<u64>,
    pub endpoints: Option<Vec<String>>,
    pub endpoints_seconds: Option<u64>,
    /// http:// endpoints on hosts other than loopback (audit D-6). Off by default.
    pub allow_insecure_endpoints: Option<bool>,
    /// Per-seq token bucket (audit D-5): burst size and seconds per token.
    pub seq_burst: Option<u32>,
    pub seq_refill_seconds: Option<u64>,
}

/// `[cancel]`: the cancel-limit design's automation (CAN-2 + C4b, owner 2026-10-13): the watcher, the co-signature
/// gossip and the collector, all inside `attest`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelToml {
    pub enabled: Option<bool>,
    pub auto_cosign: Option<bool>,
    pub margin_bps: Option<u32>,
    pub drive: Option<bool>,
    pub spares: Option<u32>,
    pub spare_wait_blocks: Option<u32>,
    pub takeover_blocks: Option<u32>,
    pub min_confirmations: Option<u32>,
    pub refee_after_blocks: Option<u32>,
    pub republish_blocks: Option<u32>,
    pub price_tolerance_blocks: Option<u32>,
    pub state_file: Option<String>,
    pub broadcast_rpc: Option<Vec<String>>,
    pub allow_insecure_broadcast: Option<bool>,
    pub alert_command: Option<String>,
    pub gossip_burst: Option<u32>,
    pub gossip_refill_seconds: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    node: Option<NodeToml>,
    attest: Option<AttestToml>,
    sources: Option<Vec<SourceToml>>,
    btc_usd_sources: Option<Vec<SourceToml>>,
    transport: Option<TransportToml>,
    subscribe: Option<SubscribeToml>,
    cancel: Option<CancelToml>,
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub rpc_url: String,
    pub cookie: Option<PathBuf>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct AttestConfig {
    pub seq: Option<u16>,
    pub every_blocks: u32,
    pub fail_polls: u32,
    pub ref_lag: u32,
    pub poll_seconds: u64,
    /// P4-b: send a SET_HEARTBEAT of this attestor's member key every this many blocks (the attestor set's
    /// member dormancy: no act in its livenessWindow makes the record DORMANT); 0 = never.
    pub heartbeat_blocks: u32,
    pub feed: FeedSettings,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportConfig {
    Dir {
        path: PathBuf,
    },
    Iroh {
        relays: Vec<String>,
        peers: Vec<String>,
        secret_key_file: Option<PathBuf>,
        topic_override: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct SubscribeConfig {
    pub listattestors_seconds: u64,
    pub endpoints: Vec<String>,
    pub endpoints_seconds: u64,
    pub seq_burst: u32,
    pub seq_refill_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct CancelConfig {
    /// Run the watcher, the gossip and the collector inside `attest`.
    pub enabled: bool,
    /// Co-sign (yed_signcancelcosign) and publish every confirmed claim judged wrong-price, with no operator.
    pub auto_cosign: bool,
    /// Co-sign only when the vault is above theta at this agent's price with this many basis points to spare.
    pub margin_bps: u32,
    /// Take part in the leader rota: build, sign and send the cancel when this member's turn comes.
    pub drive: bool,
    /// Co-signatures beyond `cancelsRequired` to wait for (the rule counts valid entries; spares absorb a co-signer
    /// that leaves or a reorg that raises the count, design A-6).
    pub spares: u32,
    /// Once `cancelsRequired` are in hand, how many blocks to wait for the spares before sending without them.
    pub spare_wait_blocks: u32,
    /// The member of rank r in the rota drives after r × this many blocks since the claim confirmed.
    pub takeover_blocks: u32,
    pub min_confirmations: u32,
    /// A cancel unconfirmed this long after it was sent is re-pushed, and re-funded (vault_refee) if it left the mempool.
    pub refee_after_blocks: u32,
    /// Republish this agent's own co-signature every this many blocks while the claim stands (late joiners, restarts).
    pub republish_blocks: u32,
    /// How far the height of the aggregate the watcher judges with may lie from the claim's refHeight.
    pub price_tolerance_blocks: u32,
    /// Persisted state (JSON); None: `~/.ycash/yellowback-cancel-<network>-<seq>.json`.
    pub state_file: Option<PathBuf>,
    /// Other nodes' JSON-RPC URLs (`http://user:pass@host:port`) the cancel and its carrier are pushed to with
    /// `sendrawtransaction` as soon as they are sent (pinning, review S1: broadcast early to well-connected peers).
    pub broadcast_rpc: Vec<String>,
    /// A program run on every alert: `<program> <kind> <intent> <message>`.
    pub alert_command: Option<String>,
    /// Per-seq token bucket on the cancel topic.
    pub gossip_burst: u32,
    pub gossip_refill_seconds: u64,
}

pub const DEFAULT_CANCEL_MARGIN_BPS: u32 = 500;
pub const DEFAULT_CANCEL_SPARES: u32 = 2;
pub const DEFAULT_SPARE_WAIT_BLOCKS: u32 = 1;
pub const DEFAULT_TAKEOVER_BLOCKS: u32 = 6;
pub const DEFAULT_REFEE_AFTER_BLOCKS: u32 = 6;
pub const DEFAULT_REPUBLISH_BLOCKS: u32 = 4;
pub const DEFAULT_PRICE_TOLERANCE_BLOCKS: u32 = 24;
pub const DEFAULT_GOSSIP_BURST: u32 = 16;
pub const DEFAULT_GOSSIP_REFILL_SECONDS: u64 = 10;

#[derive(Debug, Clone)]
pub struct Config {
    pub node: NodeConfig,
    pub attest: AttestConfig,
    pub sources: Vec<Source>,
    pub btc_usd_sources: Vec<Source>,
    pub transport: TransportConfig,
    pub subscribe: SubscribeConfig,
    pub cancel: CancelConfig,
}

pub const DEFAULT_EVERY_BLOCKS: u32 = 10;
/// P4-b: one SET_HEARTBEAT a day at 75-second blocks; the attestor set's livenessWindow must exceed it.
pub const DEFAULT_HEARTBEAT_BLOCKS: u32 = 1152;
pub const DEFAULT_FAIL_POLLS: u32 = 2;
pub const DEFAULT_REF_LAG: u32 = 2;
pub const DEFAULT_POLL_SECONDS: u64 = 15;
pub const DEFAULT_LISTATTESTORS_SECONDS: u64 = 60;
pub const DEFAULT_ENDPOINTS_SECONDS: u64 = 30;
/// A legitimate attestor emits one frame per `every_blocks` blocks and republishes it on a
/// failed tick; endpoints re-serve it every `endpoints_seconds` (deduplicated before this).
pub const DEFAULT_SEQ_BURST: u32 = 8;
pub const DEFAULT_SEQ_REFILL_SECONDS: u64 = 15;

fn expand_user(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    PathBuf::from(p)
}

/// The host of an http(s) URL is loopback (`localhost`, `127.0.0.0/8`, `::1`).
pub fn is_loopback_url(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host = if let Some(h) = hostport.strip_prefix('[') {
        h.split_once(']').map(|(h, _)| h).unwrap_or(h)
    } else {
        hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport)
    };
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a.is_loopback())
        || host.parse::<std::net::Ipv6Addr>().is_ok_and(|a| a.is_loopback())
}

/// Read and validate `path`. A file holding `rpc_password` must not be group- or world-readable
/// (audit D-7) unless `insecure_permissions` (the `--insecure-config-permissions` flag) says so.
pub fn load(path: &Path, insecure_permissions: bool) -> Result<Config, ConfigError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
    let cfg = parse(&text).map_err(|e| ConfigError(format!("{}: {e}", path.display())))?;
    if cfg.node.password.is_some() && !insecure_permissions {
        if let Some(mode) = file_mode(path) {
            if mode & 0o077 != 0 {
                return Err(ConfigError(format!(
                    "{} holds rpc_password but is readable by group or others (mode {:04o}): chmod 600 it, \
                     or pass --insecure-config-permissions to run anyway",
                    path.display(),
                    mode & 0o7777
                )));
            }
        }
    }
    Ok(cfg)
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.mode())
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError(e.to_string()))?;

    let n = raw.node.unwrap_or_default();
    if n.rpc_cookie.is_some() && (n.rpc_user.is_some() || n.rpc_password.is_some()) {
        return Err("[node]: give rpc_cookie or rpc_user/rpc_password, not both"
            .to_string()
            .into());
    }
    if n.rpc_password.is_some() && n.rpc_user.is_none() {
        return Err("[node]: rpc_password needs rpc_user".to_string().into());
    }
    let rpc_url = n
        .rpc_url
        .filter(|u| !u.is_empty())
        .ok_or_else(|| "[node] rpc_url is required".to_string())?;
    if !(rpc_url.starts_with("http://") || rpc_url.starts_with("https://")) {
        return Err(format!("[node] rpc_url must start with http:// or https:// (got {rpc_url:?})").into());
    }
    let has_credentials = n.rpc_user.is_some() || n.rpc_cookie.is_some() || rpc_url.contains('@');
    if rpc_url.starts_with("http://")
        && has_credentials
        && !is_loopback_url(&rpc_url)
        && !n.allow_insecure_rpc.unwrap_or(false)
    {
        return Err(format!(
            "[node] rpc_url {rpc_url:?} would send the node's credentials as cleartext Basic auth to a host that is not \
             loopback: use https://, an SSH tunnel to 127.0.0.1, or set allow_insecure_rpc = true"
        )
        .into());
    }
    let node = NodeConfig {
        rpc_url,
        cookie: n.rpc_cookie.as_deref().map(expand_user),
        user: n.rpc_user,
        password: n.rpc_password,
        timeout_seconds: n.rpc_timeout.unwrap_or(30),
    };

    let a = raw.attest.unwrap_or_default();
    let attest = AttestConfig {
        seq: a.seq,
        every_blocks: a.every_blocks.unwrap_or(DEFAULT_EVERY_BLOCKS),
        fail_polls: a.fail_polls.unwrap_or(DEFAULT_FAIL_POLLS),
        ref_lag: a.ref_lag.unwrap_or(DEFAULT_REF_LAG),
        poll_seconds: a.poll_seconds.unwrap_or(DEFAULT_POLL_SECONDS),
        heartbeat_blocks: a.heartbeat_blocks.unwrap_or(DEFAULT_HEARTBEAT_BLOCKS),
        feed: a.feed.resolve().map_err(|e| format!("[attest]: {e}"))?,
    };
    if attest.every_blocks < 1 || attest.fail_polls < 1 || attest.poll_seconds < 1 {
        return Err("[attest]: every_blocks, fail_polls and poll_seconds must be >= 1"
            .to_string()
            .into());
    }

    let sources = price::normalize_sources(&raw.sources.unwrap_or_default(), "sources")?;
    let btc_usd_sources = price::normalize_btc_sources(&raw.btc_usd_sources.unwrap_or_default())?;

    let t = raw.transport.unwrap_or_default();
    let transport = match t.kind.as_deref().unwrap_or("iroh") {
        "dir" => {
            if t.relays.is_some() || t.peers.is_some() || t.secret_key_file.is_some() || t.topic_override.is_some() {
                return Err("[transport]: kind = \"dir\" takes only path".to_string().into());
            }
            let path = t
                .path
                .filter(|p| !p.is_empty())
                .ok_or_else(|| "[transport]: kind = \"dir\" needs path".to_string())?;
            TransportConfig::Dir {
                path: expand_user(&path),
            }
        }
        "iroh" => {
            if t.path.is_some() {
                return Err("[transport]: path belongs to kind = \"dir\"".to_string().into());
            }
            TransportConfig::Iroh {
                relays: t.relays.unwrap_or_default(),
                peers: t.peers.unwrap_or_default(),
                secret_key_file: t.secret_key_file.as_deref().map(expand_user),
                topic_override: t.topic_override.filter(|s| !s.is_empty()),
            }
        }
        other => return Err(format!("[transport]: unknown kind {other:?} (iroh or dir)").into()),
    };

    let s = raw.subscribe.unwrap_or_default();
    let subscribe = SubscribeConfig {
        listattestors_seconds: s.listattestors_seconds.unwrap_or(DEFAULT_LISTATTESTORS_SECONDS).max(1),
        endpoints: s.endpoints.unwrap_or_default(),
        endpoints_seconds: s.endpoints_seconds.unwrap_or(DEFAULT_ENDPOINTS_SECONDS).max(1),
        seq_burst: s.seq_burst.unwrap_or(DEFAULT_SEQ_BURST).max(1),
        seq_refill_seconds: s.seq_refill_seconds.unwrap_or(DEFAULT_SEQ_REFILL_SECONDS).max(1),
    };
    let allow_insecure_endpoints = s.allow_insecure_endpoints.unwrap_or(false);
    for e in &subscribe.endpoints {
        if e.starts_with("https://") {
            continue;
        }
        if e.starts_with("http://") {
            if is_loopback_url(e) || allow_insecure_endpoints {
                continue;
            }
            return Err(format!(
                "[subscribe] endpoints: {e:?} is plain http:// to a host that is not loopback; endpoints are HTTPS \
                 (set allow_insecure_endpoints = true to override)"
            )
            .into());
        }
        return Err(format!("[subscribe] endpoints: {e:?} is not an http(s) URL").into());
    }

    let c = raw.cancel.unwrap_or_default();
    let cancel = CancelConfig {
        enabled: c.enabled.unwrap_or(true),
        auto_cosign: c.auto_cosign.unwrap_or(true),
        margin_bps: c.margin_bps.unwrap_or(DEFAULT_CANCEL_MARGIN_BPS),
        drive: c.drive.unwrap_or(true),
        spares: c.spares.unwrap_or(DEFAULT_CANCEL_SPARES),
        spare_wait_blocks: c.spare_wait_blocks.unwrap_or(DEFAULT_SPARE_WAIT_BLOCKS),
        takeover_blocks: c.takeover_blocks.unwrap_or(DEFAULT_TAKEOVER_BLOCKS).max(1),
        min_confirmations: c.min_confirmations.unwrap_or(1).max(1),
        refee_after_blocks: c.refee_after_blocks.unwrap_or(DEFAULT_REFEE_AFTER_BLOCKS).max(1),
        republish_blocks: c.republish_blocks.unwrap_or(DEFAULT_REPUBLISH_BLOCKS).max(1),
        price_tolerance_blocks: c.price_tolerance_blocks.unwrap_or(DEFAULT_PRICE_TOLERANCE_BLOCKS),
        state_file: c.state_file.as_deref().filter(|p| !p.is_empty()).map(expand_user),
        broadcast_rpc: c.broadcast_rpc.unwrap_or_default(),
        alert_command: c.alert_command.filter(|s| !s.is_empty()),
        gossip_burst: c.gossip_burst.unwrap_or(DEFAULT_GOSSIP_BURST).max(1),
        gossip_refill_seconds: c.gossip_refill_seconds.unwrap_or(DEFAULT_GOSSIP_REFILL_SECONDS).max(1),
    };
    if cancel.margin_bps > 100_000 {
        return Err("[cancel]: margin_bps must be at most 100000".to_string().into());
    }
    let allow_insecure_broadcast = c.allow_insecure_broadcast.unwrap_or(false);
    for u in &cancel.broadcast_rpc {
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return Err(format!("[cancel] broadcast_rpc: {u:?} is not an http(s) URL").into());
        }
        if u.starts_with("http://") && u.contains('@') && !is_loopback_url(u) && !allow_insecure_broadcast {
            return Err(format!(
                "[cancel] broadcast_rpc: {u:?} would send credentials as cleartext to a host that is not loopback \
                 (use https://, a tunnel, or allow_insecure_broadcast = true)"
            )
            .into());
        }
    }

    Ok(Config {
        node,
        attest,
        sources,
        btc_usd_sources,
        transport,
        subscribe,
        cancel,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[node]
rpc_url = "http://127.0.0.1:18232"
rpc_cookie = "~/.ycash/regtest/.cookie"

[attest]
seq = 3
every_blocks = 4
min_sources = 2

[[sources]]
name = "coingecko"
kind = "coingecko_simple"
max_age = 900

[[sources]]
name = "nonkyc"
kind = "nonkyc_market"
max_spread_bps = 500

[transport]
kind = "dir"
path = "/tmp/yb-attest"

[subscribe]
listattestors_seconds = 5
endpoints = ["https://attestor.example/att"]
"#;

    #[test]
    fn sample_parses_with_defaults() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.node.rpc_url, "http://127.0.0.1:18232");
        assert!(c.node.cookie.as_ref().unwrap().ends_with(".ycash/regtest/.cookie"));
        assert_eq!(
            (
                c.attest.seq,
                c.attest.every_blocks,
                c.attest.fail_polls,
                c.attest.ref_lag,
                c.attest.poll_seconds
            ),
            (Some(3), 4, 2, 2, 15)
        );
        assert_eq!((c.attest.feed.min_sources, c.attest.feed.min_venues), (2, 2));
        assert_eq!(c.sources.len(), 2);
        assert_eq!(c.sources[1].max_spread_bps, Some(500.0));
        assert_eq!(
            c.transport,
            TransportConfig::Dir {
                path: PathBuf::from("/tmp/yb-attest")
            }
        );
        assert_eq!(c.subscribe.listattestors_seconds, 5);
        assert_eq!(c.subscribe.endpoints, vec!["https://attestor.example/att"]);
    }

    #[test]
    fn iroh_is_the_default_transport() {
        let c =
            parse("[node]\nrpc_url = \"http://h:1\"\n[transport]\nrelays = [\"https://relay.example\"]\npeers = []\n")
                .unwrap();
        assert!(
            matches!(c.transport, TransportConfig::Iroh { ref relays, .. } if relays == &["https://relay.example"])
        );
        assert_eq!(c.attest.every_blocks, DEFAULT_EVERY_BLOCKS);
    }

    #[test]
    fn loopback_hosts() {
        for url in [
            "http://127.0.0.1:8832",
            "http://127.5.6.7:1",
            "http://localhost:8832/",
            "http://LOCALHOST",
            "http://[::1]:8832",
            "http://u:p@127.0.0.1:8832",
        ] {
            assert!(is_loopback_url(url), "{url}");
        }
        for url in [
            "http://10.0.0.5:8832",
            "http://node.example",
            "http://u:p@h:1",
            "http://[::2]:1",
            "h:1",
        ] {
            assert!(!is_loopback_url(url), "{url}");
        }
    }

    /// Audit D-6 / D-7: plain http is fine on loopback or when the operator says so explicitly.
    #[test]
    fn insecure_transports_need_an_explicit_opt_in() {
        let c = parse("[node]\nrpc_url = \"http://127.0.0.1:8832\"\nrpc_user = \"u\"\nrpc_password = \"p\"\n[subscribe]\nendpoints = [\"http://127.0.0.1:9/att\", \"http://[::1]:9/att\"]\n").unwrap();
        assert_eq!(c.subscribe.endpoints.len(), 2);
        assert!(parse("[node]\nrpc_url = \"http://10.0.0.5:8832\"\n").is_ok()); // no credentials: nothing to leak
        assert!(parse("[node]\nrpc_url = \"https://10.0.0.5:8832\"\nrpc_user = \"u\"\nrpc_password = \"p\"\n").is_ok());
        assert!(parse("[node]\nrpc_url = \"http://10.0.0.5:8832\"\nrpc_user = \"u\"\nrpc_password = \"p\"\nallow_insecure_rpc = true\n").is_ok());
        assert!(parse("[node]\nrpc_url = \"http://h:1\"\n[subscribe]\nendpoints = [\"http://attestor.example/att\"]\nallow_insecure_endpoints = true\n").is_ok());
        assert_eq!(
            (c.subscribe.seq_burst, c.subscribe.seq_refill_seconds),
            (DEFAULT_SEQ_BURST, DEFAULT_SEQ_REFILL_SECONDS)
        );
    }

    /// Audit D-7: a TOML holding rpc_password must be 0600 unless the flag says otherwise.
    #[cfg(unix)]
    #[test]
    fn config_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("attest.toml");
        std::fs::write(
            &p,
            "[node]\nrpc_url = \"http://127.0.0.1:1\"\nrpc_user = \"u\"\nrpc_password = \"p\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load(&p, false).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");
        assert!(load(&p, true).is_ok());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&p, false).is_ok());
        // without a password the mode does not matter (the cookie file carries its own)
        std::fs::write(&p, "[node]\nrpc_url = \"http://127.0.0.1:1\"\nrpc_cookie = \"/x\"\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&p, false).is_ok());
    }

    #[test]
    fn cancel_defaults_and_overrides() {
        let c = parse("[node]\nrpc_url = \"http://h:1\"\n").unwrap();
        assert!(c.cancel.enabled && c.cancel.auto_cosign && c.cancel.drive);
        assert_eq!(
            (
                c.cancel.margin_bps,
                c.cancel.spares,
                c.cancel.takeover_blocks,
                c.cancel.min_confirmations
            ),
            (
                DEFAULT_CANCEL_MARGIN_BPS,
                DEFAULT_CANCEL_SPARES,
                DEFAULT_TAKEOVER_BLOCKS,
                1
            )
        );
        assert!(c.cancel.state_file.is_none() && c.cancel.broadcast_rpc.is_empty());
        let c = parse(
            "[node]\nrpc_url = \"http://h:1\"\n[cancel]\nauto_cosign = false\nmargin_bps = 0\ntakeover_blocks = 0\n\
             state_file = \"/tmp/s.json\"\nbroadcast_rpc = [\"http://u:p@127.0.0.1:9\", \"https://u:p@miner.example\"]\n",
        )
        .unwrap();
        assert!(!c.cancel.auto_cosign);
        assert_eq!((c.cancel.margin_bps, c.cancel.takeover_blocks), (0, 1));
        assert_eq!(c.cancel.state_file, Some(PathBuf::from("/tmp/s.json")));
        assert_eq!(c.cancel.broadcast_rpc.len(), 2);
        assert!(
            parse("[node]\nrpc_url = \"http://h:1\"\n[cancel]\nbroadcast_rpc = [\"http://u:p@peer.example:9\"]\n")
                .is_err()
        );
        assert!(parse("[node]\nrpc_url = \"http://h:1\"\n[cancel]\nbroadcast_rpc = [\"http://u:p@peer.example:9\"]\nallow_insecure_broadcast = true\n").is_ok());
        assert!(parse("[node]\nrpc_url = \"http://h:1\"\n[cancel]\nbroadcast_rpc = [\"ftp://x\"]\n").is_err());
        assert!(parse("[node]\nrpc_url = \"http://h:1\"\n[cancel]\nbogus = 1\n").is_err());
    }

    #[test]
    fn rejects() {
        let bad = [
            "",                                                                        // no rpc_url
            "[node]\nrpc_url = \"h:1\"\n",                                             // scheme
            "[node]\nrpc_url = \"http://h:1\"\nrpc_cookie = \"c\"\nrpc_user = \"u\"\n", // both auths
            "[node]\nrpc_url = \"http://h:1\"\nrpc_password = \"p\"\n",                 // password without user
            "[node]\nrpc_url = \"http://h:1\"\n[attest]\nevery_blocks = 0\n",
            "[node]\nrpc_url = \"http://h:1\"\n[attest]\nbogus = 1\n",
            "[node]\nrpc_url = \"http://h:1\"\n[transport]\nkind = \"dir\"\n",         // no path
            "[node]\nrpc_url = \"http://h:1\"\n[transport]\nkind = \"pigeon\"\n",
            "[node]\nrpc_url = \"http://h:1\"\n[transport]\nkind = \"iroh\"\npath = \"/x\"\n",
            "[node]\nrpc_url = \"http://h:1\"\n[[sources]]\nname = \"a\"\nkind = \"nope\"\n",
            "[node]\nrpc_url = \"http://h:1\"\n[[sources]]\nname = \"a\"\nkind = \"coingecko_simple\"\n[[sources]]\nname = \"a\"\nkind = \"nonkyc_market\"\n",
            "[node]\nrpc_url = \"http://h:1\"\n[subscribe]\nendpoints = [\"ftp://x\"]\n",
            "[node]\nrpc_url = \"http://h:1\"\n[subscribe]\nendpoints = [\"http://attestor.example/att\"]\n", // D-6
            "[node]\nrpc_url = \"http://10.0.0.5:8832\"\nrpc_user = \"u\"\nrpc_password = \"p\"\n",      // D-7
            "[node]\nrpc_url = \"http://10.0.0.5:8832\"\nrpc_cookie = \"~/.ycash/.cookie\"\n",          // D-7
            "[node]\nrpc_url = \"http://u:p@node.example:8832\"\n",                                     // D-7
            "[quote]\npoll_seconds = 1\n",                                              // the quote agent's table
        ];
        for text in bad {
            assert!(parse(text).is_err(), "accepted: {text:?}");
        }
    }
}
