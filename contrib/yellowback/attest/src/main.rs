//! `yellowback-attest`: the Ycash Yellowback attestor agent (plan §5, W13).
//!
//! Two modes, one binary: `attest` (beside an attestor's node) and `subscribe` (beside any
//! minting node). The agent never holds a key: signing is the node's `yed_signattestation`.
//! Exit codes: 2 for a bad configuration; otherwise the loops run until a signal.

mod attest;
mod config;
mod fixtures;
mod framing;
mod price;
mod rpc;
mod subscribe;
mod tls;
mod transport;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

const EXIT_BAD_CONFIG: i32 = 2;

#[derive(Parser)]
#[command(name = "yellowback-attest", version, about = "Ycash Yellowback attestor agent")]
struct Cli {
    /// TOML configuration file (see attest.toml.sample)
    #[arg(long, global = true, value_name = "FILE")]
    conf: Option<PathBuf>,
    /// Log filter (RUST_LOG syntax), e.g. info, debug, yellowback_attest=debug
    #[arg(long, global = true, default_value = "info")]
    log_level: String,
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
    },
    /// Join the topic and push every plausible attestation into the node's pool (forever)
    Subscribe,
    /// Fetch every configured source once and show what resolved (exit 1 if nothing would be attested)
    Sources,
    /// Parse the configuration and exit 0 if the agent could run with it
    CheckConfig,
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
    let cfg = match config::load(&conf) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("bad configuration: {e}");
            std::process::exit(EXIT_BAD_CONFIG);
        }
    };
    let result: anyhow::Result<i32> = match cli.command {
        Command::Attest { mock_price } => match attest::Attestor::new(cfg, mock_price) {
            Ok(a) => a.run().await.map(|_| 0),
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
