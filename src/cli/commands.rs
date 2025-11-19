//! CLI commands implementation

use crate::config::load_from_file;
use crate::storage::{InMemoryRepository, RedisRepository, ReputationRepository};
use crate::{Error, Result};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;

/// Run server with configuration file
///
/// # Arguments
///
/// * `config_path` - Path to configuration TOML file
/// * `dry_run` - If true, validate config without starting server
pub async fn run_server(config_path: &PathBuf, dry_run: bool) -> Result<()> {
    // Load configuration
    let settings = load_from_file(config_path.to_str().unwrap())?;

    if dry_run {
        println!("🔍 DRY RUN MODE - Validation only");
        println!("✅ Configuration is valid");
        println!("\nConfiguration loaded from: {}", config_path.display());
        println!("\nServer:");
        println!("  Listen: {}", settings.server.listen);
        println!("  Backend: {}", settings.server.backend);
        println!("\nStorage:");
        println!("  Type: {}", settings.storage.storage_type);
        if let Some(redis_url) = &settings.storage.redis_url {
            println!("  Redis URL: {}", redis_url);
        }
        println!("\n✅ Dry run completed successfully");
        return Ok(());
    }

    // Normal run
    println!("🔧 Initializing WebSec...");
    let server = crate::proxy::server::ProxyServer::new(&settings)?;

    println!("✅ WebSec initialized successfully");
    println!("📍 Listening on: {}", server.listen_addr());
    println!("🎯 Backend target: {}", settings.server.backend);
    println!();
    println!("Press Ctrl+C to stop");
    println!();

    // Graceful shutdown
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        println!("\n🛑 Shutdown signal received...");
    };

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                eprintln!("❌ Server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = shutdown_signal => {
            println!("✅ Server stopped gracefully");
        }
    }

    Ok(())
}

/// Show configuration details
pub fn show_config(config_path: &PathBuf) -> Result<()> {
    let settings = load_from_file(config_path.to_str().unwrap())?;

    println!("Configuration loaded from: {}", config_path.display());
    println!("\n📡 Server:");
    println!("  Listen: {}", settings.server.listen);
    println!("  Backend: {}", settings.server.backend);
    println!("  Workers: {}", settings.server.workers);

    println!("\n🎯 Reputation:");
    println!("  Base score: {}", settings.reputation.base_score);
    println!("  Threshold allow: {}", settings.reputation.threshold_allow);
    println!(
        "  Threshold rate limit: {}",
        settings.reputation.threshold_ratelimit
    );
    println!(
        "  Threshold challenge: {}",
        settings.reputation.threshold_challenge
    );
    println!("  Threshold block: {}", settings.reputation.threshold_block);
    println!(
        "  Decay half-life: {}h",
        settings.reputation.decay_half_life_hours
    );

    println!("\n💾 Storage:");
    println!("  Type: {}", settings.storage.storage_type);
    if let Some(redis_url) = &settings.storage.redis_url {
        println!("  Redis URL: {}", redis_url);
    }
    println!("  Cache size: {}", settings.storage.cache_size);

    println!("\n📝 Logging:");
    println!("  Level: {}", settings.logging.level);
    println!("  Format: {}", settings.logging.format);

    println!("\n🌍 Geolocation:");
    println!("  Enabled: {}", settings.geolocation.enabled);
    if let Some(db) = &settings.geolocation.database {
        println!("  Database: {}", db);
    }

    println!("\n⏱️  Rate Limiting:");
    println!(
        "  Normal: {} req/min (burst: {})",
        settings.ratelimit.normal_rpm, settings.ratelimit.normal_burst
    );
    println!(
        "  Suspicious: {} req/min (burst: {})",
        settings.ratelimit.suspicious_rpm, settings.ratelimit.suspicious_burst
    );
    println!(
        "  Aggressive: {} req/min (burst: {})",
        settings.ratelimit.aggressive_rpm, settings.ratelimit.aggressive_burst
    );

    Ok(())
}

/// Check storage backend health
pub async fn check_storage(config_path: &PathBuf) -> Result<()> {
    let settings = load_from_file(config_path.to_str().unwrap())?;

    println!("🔍 Checking storage backend...");
    println!("Storage type: {}", settings.storage.storage_type);

    match settings.storage.storage_type.as_str() {
        "redis" => {
            let redis_url = settings
                .storage
                .redis_url
                .ok_or_else(|| Error::Config("Redis URL not configured".to_string()))?;

            println!("Redis URL: {}", redis_url);
            println!("Connecting to Redis...");

            match RedisRepository::new(&redis_url).await {
                Ok(repo) => {
                    println!("✅ Connected to Redis successfully");

                    match repo.health_check().await {
                        Ok(true) => {
                            println!("✅ Redis health check: PASS");

                            // Get count
                            match repo.count().await {
                                Ok(count) => {
                                    println!("📊 Tracked IPs: {}", count);
                                }
                                Err(e) => {
                                    println!("⚠️  Failed to get count: {}", e);
                                }
                            }
                        }
                        Ok(false) => {
                            println!("❌ Redis health check: FAIL");
                            return Err(Error::Storage("Redis unhealthy".to_string()));
                        }
                        Err(e) => {
                            println!("❌ Redis health check error: {}", e);
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Failed to connect to Redis: {}", e);
                    return Err(e);
                }
            }
        }
        "memory" => {
            println!("✅ In-memory storage (no external dependencies)");
            let repo = InMemoryRepository::new();
            match repo.health_check().await {
                Ok(true) => println!("✅ In-memory storage health check: PASS"),
                _ => println!("❌ In-memory storage health check: FAIL"),
            }
        }
        _ => {
            return Err(Error::Config(format!(
                "Unknown storage type: {}",
                settings.storage.storage_type
            )));
        }
    }

    Ok(())
}

/// Display live statistics (requires running WebSec instance)
///
/// # Arguments
///
/// * `metrics_url` - URL of /metrics endpoint (e.g., "http://localhost:8080/metrics")
/// * `interval_secs` - Refresh interval in seconds
pub async fn show_stats(metrics_url: &str, interval_secs: u64) -> Result<()> {
    println!("📊 Live Statistics");
    println!("Endpoint: {}", metrics_url);
    println!("Refresh interval: {}s", interval_secs);
    println!("Press Ctrl+C to stop\n");

    let client = reqwest::Client::new();

    loop {
        match client.get(metrics_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    if let Ok(text) = response.text().await {
                        // Parse and display metrics
                        display_metrics(&text);
                    } else {
                        eprintln!("⚠️  Failed to read response body");
                    }
                } else {
                    eprintln!(
                        "⚠️  HTTP error: {} - Is WebSec running?",
                        response.status()
                    );
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to fetch metrics: {} - Is WebSec running?", e);
            }
        }

        sleep(Duration::from_secs(interval_secs)).await;
    }
}

/// Parse and display Prometheus metrics in human-readable format
fn display_metrics(metrics_text: &str) {
    // Clear terminal
    print!("\x1B[2J\x1B[1;1H");

    println!("╔════════════════════════════════════════════╗");
    println!("║         WebSec Live Statistics             ║");
    println!("╚════════════════════════════════════════════╝");
    println!();

    let mut allowed = 0;
    let mut blocked = 0;
    let mut rate_limited = 0;
    let mut tracked_ips = 0;
    let mut signals: Vec<(String, u64)> = Vec::new();

    for line in metrics_text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        if line.contains("requests_total{decision=\"allow\"}") {
            allowed = parse_metric_value(line);
        } else if line.contains("requests_total{decision=\"block\"}") {
            blocked = parse_metric_value(line);
        } else if line.contains("requests_total{decision=\"rate_limit\"}") {
            rate_limited = parse_metric_value(line);
        } else if line.contains("tracked_ips_total") {
            tracked_ips = parse_metric_value(line);
        } else if line.contains("signals_total{signal_type=") {
            if let Some(signal_name) = extract_signal_type(line) {
                let count = parse_metric_value(line);
                signals.push((signal_name, count));
            }
        }
    }

    let total_requests = allowed + blocked + rate_limited;

    // Display requests
    println!("📊 Requests:");
    println!("  Total:        {}", total_requests);
    println!("  ✅ Allowed:    {} ({:.1}%)", allowed, percentage(allowed, total_requests));
    println!("  ❌ Blocked:    {} ({:.1}%)", blocked, percentage(blocked, total_requests));
    println!("  ⏱️  Rate Limited: {} ({:.1}%)", rate_limited, percentage(rate_limited, total_requests));

    println!();
    println!("🌐 Tracked IPs: {}", tracked_ips);

    if !signals.is_empty() {
        println!();
        println!("🚨 Top Signals:");
        // Sort by count descending
        signals.sort_by(|a, b| b.1.cmp(&a.1));
        for (i, (signal, count)) in signals.iter().take(5).enumerate() {
            println!("  {}. {} ({})", i + 1, signal, count);
        }
    }

    println!();
    println!("Last updated: {}", chrono::Local::now().format("%H:%M:%S"));
}

fn parse_metric_value(line: &str) -> u64 {
    line.split_whitespace()
        .last()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn extract_signal_type(line: &str) -> Option<String> {
    if let Some(start) = line.find("signal_type=\"") {
        let after_start = &line[start + 13..];
        if let Some(end) = after_start.find('"') {
            return Some(after_start[..end].to_string());
        }
    }
    None
}

fn percentage(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (value as f64 / total as f64) * 100.0
    }
}
