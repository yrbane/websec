//! WebSec - Proxy de sécurité HTTP intelligent
//!
//! Point d'entrée principal pour le binaire WebSec.
//! Lance le serveur proxy avec détection de menaces et système de réputation.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use websec::cli;

/// WebSec - Proxy de sécurité HTTP avec détection de menaces
#[derive(Parser, Debug)]
#[command(name = "websec")]
#[command(author = "WebSec Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Proxy de sécurité HTTP intelligent avec système de réputation", long_about = None)]
struct Args {
    /// Chemin vers le fichier de configuration TOML
    #[arg(short, long, value_name = "FILE", default_value = "config/websec.toml", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the WebSec proxy server
    Run {
        /// Validate configuration without starting the server (dry-run mode)
        #[arg(long)]
        dry_run: bool,
    },

    /// Show configuration details
    Config,

    /// Check storage backend health
    CheckStorage,

    /// Display live statistics (requires running WebSec instance)
    Stats {
        /// Metrics endpoint URL
        #[arg(short, long, default_value = "http://localhost:8080/metrics")]
        url: String,

        /// Refresh interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
    },
}

#[tokio::main]
async fn main() -> websec::Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Commands::Run { dry_run }) => {
            cli::run_server(&args.config, dry_run).await?;
        }
        Some(Commands::Config) => {
            cli::show_config(&args.config)?;
        }
        Some(Commands::CheckStorage) => {
            cli::check_storage(&args.config).await?;
        }
        Some(Commands::Stats { url, interval }) => {
            cli::show_stats(&url, interval).await?;
        }
        None => {
            // Default: run server
            cli::run_server(&args.config, false).await?;
        }
    }

    Ok(())
}
