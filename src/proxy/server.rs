//! HTTP proxy server using hyper
//!
//! Basic HTTP reverse proxy server with request interception.

use crate::config::Settings;
use crate::{Error, Result};
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::TcpListener;

/// HTTP proxy server
pub struct ProxyServer {
    /// Listen address
    listen_addr: SocketAddr,
    /// Backend server URL
    backend_url: String,
}

impl ProxyServer {
    /// Create a new proxy server from configuration
    ///
    /// # Arguments
    ///
    /// * `settings` - Configuration settings
    ///
    /// # Errors
    ///
    /// Returns error if listen address is invalid
    pub fn new(settings: &Settings) -> Result<Self> {
        let listen_addr = SocketAddr::from_str(&settings.server.listen)
            .map_err(|e| Error::Config(format!("Invalid listen address: {}", e)))?;

        Ok(Self {
            listen_addr,
            backend_url: settings.server.backend.clone(),
        })
    }

    /// Start the proxy server
    ///
    /// Runs until interrupted. Listens for HTTP connections and
    /// forwards them to the backend server.
    ///
    /// # Errors
    ///
    /// Returns error if server fails to bind or encounters I/O errors
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        tracing::info!("Proxy server listening on {}", self.listen_addr);
        tracing::info!("Forwarding to backend: {}", self.backend_url);

        // Placeholder: Phase 3+ will implement actual request handling
        // For now, just accept connections and log
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    tracing::debug!("Accepted connection from {}", addr);
                    drop(stream); // Placeholder: close immediately
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Get the listen address
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Get the backend URL
    #[must_use]
    pub fn backend_url(&self) -> &str {
        &self.backend_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{
        GeolocationConfig, LoggingConfig, MetricsConfig, RateLimitConfig, ReputationConfig,
        ServerConfig, Settings, StorageConfig,
    };

    fn create_test_settings() -> Settings {
        Settings {
            server: ServerConfig {
                listen: "127.0.0.1:8080".to_string(),
                backend: "http://127.0.0.1:3000".to_string(),
                workers: 4,
            },
            reputation: ReputationConfig {
                base_score: 100,
                threshold_allow: 70,
                threshold_ratelimit: 40,
                threshold_challenge: 20,
                threshold_block: 0,
                decay_half_life_hours: 24.0,
                correlation_penalty_bonus: 10,
            },
            storage: StorageConfig {
                storage_type: "memory".to_string(),
                redis_url: None,
                cache_size: 10000,
            },
            geolocation: GeolocationConfig {
                enabled: false,
                database: None,
                penalties: std::collections::HashMap::new(),
            },
            ratelimit: RateLimitConfig {
                normal_rpm: 1000,
                normal_burst: 100,
                suspicious_rpm: 200,
                suspicious_burst: 20,
                aggressive_rpm: 50,
                aggressive_burst: 5,
                window_duration_secs: 60,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
            metrics: MetricsConfig {
                enabled: true,
                port: 9090,
            },
        }
    }

    #[test]
    fn test_server_creation() {
        let settings = create_test_settings();
        let server = ProxyServer::new(&settings).unwrap();

        assert_eq!(server.listen_addr().to_string(), "127.0.0.1:8080");
        assert_eq!(server.backend_url(), "http://127.0.0.1:3000");
    }

    #[test]
    fn test_invalid_listen_address() {
        let mut settings = create_test_settings();
        settings.server.listen = "invalid_address".to_string();

        let result = ProxyServer::new(&settings);
        assert!(result.is_err());
    }
}
