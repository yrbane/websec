//! Configuration structures for `WebSec`
//!
//! Loads settings from TOML files with serde deserialization.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete `WebSec` configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Settings {
    /// Server configuration
    pub server: ServerConfig,
    /// Reputation scoring configuration
    pub reputation: ReputationConfig,
    /// Storage backend configuration
    pub storage: StorageConfig,
    /// Geolocation configuration
    pub geolocation: GeolocationConfig,
    /// Rate limiting configuration
    pub ratelimit: RateLimitConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Metrics configuration
    pub metrics: MetricsConfig,
}

/// HTTP server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Listen address (e.g., "0.0.0.0:8080")
    pub listen: String,
    /// Backend web server URL (e.g., `http://127.0.0.1:3000`)
    pub backend: String,
    /// Number of worker threads (defaults to CPU cores)
    #[serde(default = "default_workers")]
    pub workers: usize,
    /// Optional list of explicit listeners (HTTP/HTTPS)
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    /// Trusted proxies/load balancers allowed to set X-Forwarded-For/X-Real-IP
    /// If empty, these headers are ignored (direct client connection assumed)
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Maximum request body size in bytes (0 = unlimited, not recommended)
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
}

/// Individual listener configuration (port/backend/TLS)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenerConfig {
    /// Address to bind (e.g., 0.0.0.0:80)
    pub listen: String,
    /// Backend URL for this listener
    pub backend: String,
    /// TLS configuration (if HTTPS)
    #[serde(default)]
    pub tls: Option<ListenerTlsConfig>,
}

/// TLS certificate/key configuration for HTTPS listeners
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenerTlsConfig {
    /// Path to PEM-encoded certificate chain (default/fallback cert)
    pub cert_file: String,
    /// Path to private key (PEM) (default/fallback key)
    pub key_file: String,
    /// SNI: Additional certificates for multiple domains on same listener
    /// Map of domain -> certificate configuration
    #[serde(default)]
    pub sni_certificates: Vec<SniCertConfig>,
}

/// SNI certificate configuration for a specific domain
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SniCertConfig {
    /// Server name (e.g., "example.com", "*.example.com")
    pub server_name: String,
    /// Path to PEM-encoded certificate chain for this domain
    pub cert_file: String,
    /// Path to private key (PEM) for this domain
    pub key_file: String,
}

/// Reputation scoring parameters
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReputationConfig {
    /// Base score for new IPs (0-100)
    #[serde(default = "default_base_score")]
    pub base_score: u8,
    /// ALLOW threshold (>= this score)
    #[serde(default = "default_threshold_allow")]
    pub threshold_allow: u8,
    /// `RATE_LIMIT` threshold (>= this score, < allow)
    #[serde(default = "default_threshold_ratelimit")]
    pub threshold_ratelimit: u8,
    /// CHALLENGE threshold (>= this score, < ratelimit)
    #[serde(default = "default_threshold_challenge")]
    pub threshold_challenge: u8,
    /// BLOCK threshold (< this score)
    #[serde(default = "default_threshold_block")]
    pub threshold_block: u8,
    /// Exponential decay half-life in hours
    #[serde(default = "default_decay_half_life")]
    pub decay_half_life_hours: f64,
    /// Correlation penalty bonus for multiple signal families
    #[serde(default = "default_correlation_bonus")]
    pub correlation_penalty_bonus: u8,
}

/// Storage backend configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    /// Storage type: "redis", "sled", or "memory"
    #[serde(rename = "type")]
    pub storage_type: String,
    /// Redis connection URL
    pub redis_url: Option<String>,
    /// File path for file-based storage (sled)
    pub path: Option<String>,
    /// L1 cache size (number of IPs)
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
}

/// Geolocation configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeolocationConfig {
    /// Enable geolocation lookups
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path to `GeoIP2` database
    pub database: Option<String>,
    /// Country code penalties (ISO 3166-1 alpha-2 -> penalty points)
    #[serde(default)]
    pub penalties: HashMap<String, u8>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Normal tier: requests per minute
    #[serde(default = "default_normal_rpm")]
    pub normal_rpm: u32,
    /// Normal tier: burst size
    #[serde(default = "default_normal_burst")]
    pub normal_burst: u32,
    /// Suspicious tier: requests per minute
    #[serde(default = "default_suspicious_rpm")]
    pub suspicious_rpm: u32,
    /// Suspicious tier: burst size
    #[serde(default = "default_suspicious_burst")]
    pub suspicious_burst: u32,
    /// Aggressive tier: requests per minute
    #[serde(default = "default_aggressive_rpm")]
    pub aggressive_rpm: u32,
    /// Aggressive tier: burst size
    #[serde(default = "default_aggressive_burst")]
    pub aggressive_burst: u32,
    /// Sliding window duration in seconds
    #[serde(default = "default_window_duration")]
    pub window_duration_secs: u64,
}

/// Logging configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log format: "json" or "pretty"
    #[serde(default = "default_log_format")]
    pub format: String,
}

/// Metrics configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Metrics HTTP port
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

// Default value functions
fn default_workers() -> usize {
    num_cpus::get()
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10 MB par défaut
}

fn default_base_score() -> u8 {
    100
}

fn default_threshold_allow() -> u8 {
    70
}

fn default_threshold_ratelimit() -> u8 {
    40
}

fn default_threshold_challenge() -> u8 {
    20
}

fn default_threshold_block() -> u8 {
    0
}

fn default_decay_half_life() -> f64 {
    24.0
}

fn default_correlation_bonus() -> u8 {
    10
}

fn default_cache_size() -> usize {
    10_000
}

fn default_true() -> bool {
    true
}

fn default_normal_rpm() -> u32 {
    1000
}

fn default_normal_burst() -> u32 {
    100
}

fn default_suspicious_rpm() -> u32 {
    200
}

fn default_suspicious_burst() -> u32 {
    20
}

fn default_aggressive_rpm() -> u32 {
    50
}

fn default_aggressive_burst() -> u32 {
    5
}

fn default_window_duration() -> u64 {
    60
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_metrics_port() -> u16 {
    9090
}
