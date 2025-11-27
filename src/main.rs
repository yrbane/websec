//! WebSec - Proxy de sécurité HTTP intelligent
//!
//! Point d'entrée principal pour le binaire WebSec.
//! Lance le serveur proxy avec détection de menaces et système de réputation.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use websec::cli::{self, docker, e2e, lists};

/// WebSec - Proxy de sécurité HTTP avec détection de menaces
#[derive(Parser, Debug)]
#[command(name = "websec")]
#[command(author = "WebSec Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Proxy de sécurité HTTP intelligent avec système de réputation", long_about = None)]
struct Args {
    /// Chemin vers le fichier de configuration TOML.
    /// Peut aussi être défini via la variable d'environnement WEBSEC_CONFIG.
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value = "config/websec.toml",
        env = "WEBSEC_CONFIG",
        global = true
    )]
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

    /// Interactive setup assistant (Apache integration)
    Setup,

    /// Docker utilities (build/test)
    Docker {
        #[command(subcommand)]
        command: DockerCommands,
    },

    /// End-to-end integration tests
    E2e {
        /// Backend port for the test backend
        #[arg(long, default_value_t = 3000)]
        backend_port: u16,
        /// Proxy port where WebSec will listen during the test
        #[arg(long, default_value_t = 8080)]
        proxy_port: u16,
    },

    /// Run the built-in test backend only
    DevBackend {
        /// Port to listen on
        #[arg(long, default_value_t = 3000)]
        port: u16,
    },

    /// Manage blacklist/whitelist files
    Lists {
        /// Custom directory for list files
        #[arg(long)]
        dir: Option<PathBuf>,
        #[command(subcommand)]
        command: ListCommands,
    },

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
        Some(Commands::Setup) => {
            cli::run_setup(&args.config)?;
        }
        Some(Commands::Docker { command }) => match command {
            DockerCommands::Build => {
                docker::docker_build()?;
            }
            DockerCommands::Test { keep_up } => {
                docker::docker_test(keep_up).await?;
            }
        },
        Some(Commands::E2e {
            backend_port,
            proxy_port,
        }) => {
            e2e::run_e2e(&args.config, backend_port, proxy_port).await?;
        }
        Some(Commands::DevBackend { port }) => {
            e2e::run_dev_backend(port).await?;
        }
        Some(Commands::Lists { dir, command }) => {
            handle_lists(dir.as_deref(), &command)?;
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

fn handle_lists(dir: Option<&Path>, command: &ListCommands) -> websec::Result<()> {
    let manager = lists::ListManager::new(dir)?;
    match command {
        ListCommands::Blacklist(action) => match action {
            ListAction::Add { entry } => manager.add_blacklist(entry)?,
            ListAction::Remove { entry } => manager.remove_blacklist(entry)?,
            ListAction::List => {
                for entry in manager.list_blacklist()? {
                    println!("{entry}");
                }
            }
            ListAction::Clear => manager.clear_blacklist()?,
        },
        ListCommands::Whitelist(action) => match action {
            ListAction::Add { entry } => manager.add_whitelist(entry)?,
            ListAction::Remove { entry } => manager.remove_whitelist(entry)?,
            ListAction::List => {
                for entry in manager.list_whitelist()? {
                    println!("{entry}");
                }
            }
            ListAction::Clear => manager.clear_whitelist()?,
        },
        ListCommands::Check { ip } => {
            let (black, white) = manager.check_ip(ip)?;
            println!("Blacklist: {}", if black { "YES" } else { "NO" });
            println!("Whitelist: {}", if white { "YES" } else { "NO" });
        }
        ListCommands::Stats => {
            let (black, white) = manager.stats()?;
            println!("Blacklist entries: {black}");
            println!("Whitelist entries: {white}");
            println!("Directory: {}", manager.dir().display());
        }
        ListCommands::Export { format } => {
            let export = manager.export(match format {
                ExportFormatArg::Json => lists::ExportFormat::Json,
                ExportFormatArg::Csv => lists::ExportFormat::Csv,
            })?;
            println!("{export}");
        }
        ListCommands::Import { file } => {
            manager.import(file)?;
        }
    }
    Ok(())
}

#[derive(Subcommand, Debug)]
enum DockerCommands {
    /// Build the WebSec Docker image
    Build,
    /// Run the docker-compose stack & functional tests
    Test {
        /// Keep the stack running after tests
        #[arg(long)]
        keep_up: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ListCommands {
    #[command(subcommand)]
    Blacklist(ListAction),
    #[command(subcommand)]
    Whitelist(ListAction),
    Check {
        ip: String,
    },
    Stats,
    Export {
        #[arg(value_enum)]
        format: ExportFormatArg,
    },
    Import {
        file: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum ListAction {
    Add { entry: String },
    Remove { entry: String },
    List,
    Clear,
}

#[derive(Clone, Debug, ValueEnum)]
enum ExportFormatArg {
    Json,
    Csv,
}
