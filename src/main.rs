//! WebSec - Proxy de sécurité HTTP intelligent
//!
//! Point d'entrée principal pour le binaire WebSec.
//! Lance le serveur proxy avec détection de menaces et système de réputation.

use clap::Parser;
use std::path::PathBuf;
use websec::config::load_from_file;
use websec::proxy::server::ProxyServer;

/// WebSec - Proxy de sécurité HTTP avec détection de menaces
#[derive(Parser, Debug)]
#[command(name = "websec")]
#[command(author = "WebSec Team")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Proxy de sécurité HTTP intelligent avec système de réputation", long_about = None)]
struct Args {
    /// Chemin vers le fichier de configuration TOML
    #[arg(short, long, value_name = "FILE", default_value = "config/websec.toml")]
    config: PathBuf,

    /// Active le mode verbose (logs détaillés)
    #[arg(short, long)]
    verbose: bool,

    /// Affiche la configuration chargée et quitte
    #[arg(long)]
    show_config: bool,
}

#[tokio::main]
async fn main() -> websec::Result<()> {
    // Parser les arguments CLI
    let args = Args::parse();

    // Charger la configuration depuis le fichier TOML
    let settings = load_from_file(args.config.to_str().unwrap())?;

    // Si --show-config, afficher la config et quitter
    if args.show_config {
        println!("Configuration chargée depuis: {:?}", args.config);
        println!("\nServeur:");
        println!("  Listen: {}", settings.server.listen);
        println!("  Backend: {}", settings.server.backend);
        println!("  Workers: {}", settings.server.workers);
        println!("\nRéputation:");
        println!("  Base score: {}", settings.reputation.base_score);
        println!("  Threshold allow: {}", settings.reputation.threshold_allow);
        println!("  Threshold rate limit: {}", settings.reputation.threshold_ratelimit);
        println!("  Threshold challenge: {}", settings.reputation.threshold_challenge);
        println!("  Threshold block: {}", settings.reputation.threshold_block);
        println!("  Decay half-life: {}h", settings.reputation.decay_half_life_hours);
        println!("\nStorage:");
        println!("  Type: {}", settings.storage.storage_type);
        println!("  Cache size: {}", settings.storage.cache_size);
        println!("\nLogging:");
        println!("  Level: {}", settings.logging.level);
        println!("  Format: {}", settings.logging.format);
        println!("\nGéolocalisation:");
        println!("  Enabled: {}", settings.geolocation.enabled);
        if let Some(db) = &settings.geolocation.database {
            println!("  Database: {}", db);
        }
        println!("\nRate Limiting:");
        println!("  Normal: {} req/min (burst: {})", settings.ratelimit.normal_rpm, settings.ratelimit.normal_burst);
        println!("  Suspicious: {} req/min (burst: {})", settings.ratelimit.suspicious_rpm, settings.ratelimit.suspicious_burst);
        println!("  Aggressive: {} req/min (burst: {})", settings.ratelimit.aggressive_rpm, settings.ratelimit.aggressive_burst);
        return Ok(());
    }

    // Créer le serveur proxy
    println!("🔧 Initialisation de WebSec...");
    let server = ProxyServer::new(&settings)?;

    println!("✅ WebSec initialisé avec succès");
    println!("📍 Écoute sur: {}", server.listen_addr());
    println!("🎯 Backend cible: {}", settings.server.backend);
    println!("📊 Métriques disponibles via MetricsRegistry::export_prometheus()");
    println!();
    println!("Press Ctrl+C to stop");
    println!();

    // Configurer le gestionnaire de signal pour shutdown gracieux
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Impossible d'installer le gestionnaire Ctrl+C");
        println!("\n🛑 Signal d'arrêt reçu, arrêt gracieux...");
    };

    // Lancer le serveur avec shutdown gracieux
    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                eprintln!("❌ Erreur serveur: {}", e);
                std::process::exit(1);
            }
        }
        _ = shutdown_signal => {
            println!("✅ Serveur arrêté proprement");
        }
    }

    Ok(())
}
