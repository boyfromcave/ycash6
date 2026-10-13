// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! `yellowback-attest`: the Ycash Yellowback attestor agent (plan §5, W13).
//!
//! Two modes, one binary: `attest` (beside an attestor's node) and `subscribe` (beside any
//! minting node). The agent never holds a key: signing is the node's `yed_signattestation`.
//! Exit codes: 2 for a bad configuration; otherwise the loops run until a signal.

mod attest;
mod binding;
mod cancel;
mod config;
mod cosig;
mod direct;
mod fixtures;
mod framing;
mod gossip;
mod http;
mod onchain;
mod price;
mod rpc;
mod subscribe;
mod tls;
mod transport;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub const EXIT_BAD_CONFIG: i32 = 2;

#[derive(Parser)]
#[command(name = "yellowback-attest", version, about = "Ycash Yellowback attestor agent")]
struct Cli {
    /// TOML configuration file (see attest.toml.sample)
    #[arg(long, global = true, value_name = "FILE")]
    conf: Option<PathBuf>,
    /// Log filter (RUST_LOG syntax), e.g. info, debug, yellowback_attest=debug
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
    /// Run although the configuration file holds rpc_password and is group/world-readable
    #[arg(long, global = true)]
    insecure_config_permissions: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Poll sources, have the node sign every `every_blocks`, publish on the topic (forever)
    Attest {
        /// TEST/DEVNET: read one USD price from FILE every poll instead of the sources
        #[arg(long, value_name = "FILE")]
        mock_price: Option<PathBuf>,
        /// Allow --mock-price although the node is not on regtest (you will attest that number)
        #[arg(long, requires = "mock_price")]
        i_know_this_is_not_regtest: bool,
    },
    /// Join the topic and push every plausible attestation into the node's pool (forever)
    Subscribe,
    /// Fetch every configured source once and show what resolved (exit 1 if nothing would be attested)
    Sources,
    /// Parse the configuration and exit 0 if the agent could run with it
    CheckConfig,
    /// Dial a member's direct endpoint on the members-only co-signature ALPN with this (unbound) endpoint; exit 3 when
    /// the member's gate refuses it (what any non-member sees), 0 when it is admitted, 1 on no answer
    DirectProbe {
        /// The target endpoint id (hex)
        endpoint: String,
        /// The target's direct addresses ("ip:port"), as its binding announces them
        #[arg(long)]
        addr: Vec<String>,
    },
    /// Co-sign the cancel of a YED claimant intent (the cancel-limit design): print the co-signature for yed_buildcancel
    Cosign {
        /// The claimant intent, "txid:n"
        intent: String,
        /// The price statement in µUSD; default the price this seq signed for the claim's refHeight, else the aggregate now
        #[arg(long)]
        price: Option<i64>,
        /// TEST/DEVNET: read the USD price from FILE instead of the sources
        #[arg(long, value_name = "FILE")]
        mock_price: Option<PathBuf>,
        /// Allow --mock-price although the node is not on regtest
        #[arg(long, requires = "mock_price")]
        i_know_this_is_not_regtest: bool,
    },
}

fn init_logging(filter: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_logging(&cli.log_level);
    tls::install();
    let Some(conf) = cli.conf else {
        tracing::error!("bad configuration: --conf FILE is required");
        std::process::exit(EXIT_BAD_CONFIG);
    };
    let cfg = match config::load(&conf, cli.insecure_config_permissions) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("bad configuration: {e}");
            std::process::exit(EXIT_BAD_CONFIG);
        }
    };
    let result: anyhow::Result<i32> = match cli.command {
        Command::Attest {
            mock_price,
            i_know_this_is_not_regtest,
        } => match attest::Attestor::new(cfg, mock_price, i_know_this_is_not_regtest) {
            Ok(a) => a.run().await,
            Err(e) => {
                tracing::error!("bad configuration: {e}");
                std::process::exit(EXIT_BAD_CONFIG);
            }
        },
        Command::Subscribe => match subscribe::Subscriber::new(cfg) {
            Ok(s) => s.run().await.map(|_| 0),
            Err(e) => {
                tracing::error!("bad configuration: {e}");
                std::process::exit(EXIT_BAD_CONFIG);
            }
        },
        Command::Sources => attest::sources_command(&cfg).await,
        Command::Cosign {
            intent,
            price,
            mock_price,
            i_know_this_is_not_regtest,
        } => match attest::Attestor::new(cfg, mock_price, i_know_this_is_not_regtest) {
            Ok(a) => a.cosign_command(&intent, price).await,
            Err(e) => {
                tracing::error!("bad configuration: {e}");
                std::process::exit(EXIT_BAD_CONFIG);
            }
        },
        Command::DirectProbe { endpoint, addr } => {
            let r = async {
                let id: iroh::EndpointId = endpoint.parse().map_err(|e| anyhow::anyhow!("endpoint id: {e}"))?;
                let addrs: Vec<std::net::SocketAddr> = addr.iter().filter_map(|a| a.parse().ok()).collect();
                let refused = direct::probe(direct::endpoint_addr(id, &addrs, None), &cfg.cancel.direct_relays).await?;
                println!("{}", if refused { "refused" } else { "admitted" });
                Ok::<i32, anyhow::Error>(if refused { 3 } else { 0 })
            };
            r.await
        }
        Command::CheckConfig => {
            println!(
                "ok: {} source(s), {} BTC/USD reference(s), transport {}",
                cfg.sources.len(),
                cfg.btc_usd_sources.len(),
                match &cfg.transport {
                    config::TransportConfig::Dir { path } => format!("dir {}", path.display()),
                    config::TransportConfig::Iroh { relays, peers, .. } =>
                        format!("iroh ({} relay(s), {} peer(s))", relays.len(), peers.len()),
                }
            );
            Ok(0)
        }
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            tracing::error!("{e:#}");
            std::process::exit(1);
        }
    }
}
