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
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestToml {
    pub seq: Option<u16>,
    pub every_blocks: Option<u32>,
    pub fail_polls: Option<u32>,
    pub ref_lag: Option<u32>,
    pub poll_seconds: Option<u64>,
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
}

#[derive(Debug, Clone)]
pub struct Config {
    pub node: NodeConfig,
    pub attest: AttestConfig,
    pub sources: Vec<Source>,
    pub btc_usd_sources: Vec<Source>,
    pub transport: TransportConfig,
    pub subscribe: SubscribeConfig,
}

pub const DEFAULT_EVERY_BLOCKS: u32 = 10;
pub const DEFAULT_FAIL_POLLS: u32 = 2;
pub const DEFAULT_REF_LAG: u32 = 2;
pub const DEFAULT_POLL_SECONDS: u64 = 15;
pub const DEFAULT_LISTATTESTORS_SECONDS: u64 = 60;
pub const DEFAULT_ENDPOINTS_SECONDS: u64 = 30;

fn expand_user(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    PathBuf::from(p)
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| ConfigError(format!("cannot read {}: {e}", path.display())))?;
    parse(&text).map_err(|e| ConfigError(format!("{}: {e}", path.display())))
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
    };
    for e in &subscribe.endpoints {
        if !(e.starts_with("https://") || e.starts_with("http://")) {
            return Err(format!("[subscribe] endpoints: {e:?} is not an http(s) URL").into());
        }
    }

    Ok(Config {
        node,
        attest,
        sources,
        btc_usd_sources,
        transport,
        subscribe,
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
            "[quote]\npoll_seconds = 1\n",                                              // the quote agent's table
        ];
        for text in bad {
            assert!(parse(text).is_err(), "accepted: {text:?}");
        }
    }
}
