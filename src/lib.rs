//! WebSec - High-performance security reverse proxy
//!
//! WebSec is a transparent HTTP(S) reverse proxy that provides real-time threat detection
//! and mitigation through IP reputation scoring, behavioral analysis, and adaptive rate limiting.
//!
//! # Architecture
//!
//! - **Detectors**: Threat detection using Strategy pattern (12 detector families)
//! - **Reputation**: Dynamic IP scoring with exponential decay (0-100 scale)
//! - **Rate Limiting**: Token Bucket + Sliding Window adaptive throttling
//! - **Storage**: Multi-tier caching (L1: LRU, L2: Redis, L3: File fallback)
//! - **Proxy**: Transparent HTTP forwarding with <5ms p95 latency overhead
//!
//! # Performance Targets
//!
//! - Throughput: 10,000+ req/s per instance
//! - Latency: <5ms p95 overhead
//! - Memory: <500MB per 100k tracked IPs
//!
//! # Example
//!
//! ```no_run
//! // Server initialization (placeholder for future implementation)
//! // let config = websec::config::Settings::load()?;
//! // websec::proxy::Server::new(config).run().await?;
//! ```

#![deny(warnings)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(missing_docs)]

pub mod cli;
pub mod config;
pub mod detectors;
pub mod geolocation;
pub mod models;
pub mod observability;
pub mod proxy;
pub mod ratelimit;
pub mod reputation;
pub mod storage;
pub mod utils;

/// Common error type for WebSec operations
pub type Result<T> = std::result::Result<T, Error>;

/// WebSec error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Storage backend error
    #[error("Storage error: {0}")]
    Storage(String),

    /// HTTP proxy error
    #[error("HTTP error: {0}")]
    Http(String),

    /// Geolocation lookup error
    #[error("Geolocation error: {0}")]
    Geolocation(String),

    /// Generic I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
