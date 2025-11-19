//! `WebSec` - High-performance security reverse proxy
//!
//! `WebSec` is a transparent HTTP(S) reverse proxy that provides real-time threat detection
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
// Allow unused_self for methods that are part of traits or public APIs
#![allow(clippy::unused_self)]
// Allow match_same_arms for clarity in signal weights
#![allow(clippy::match_same_arms)]
// Allow float_cmp in tests where exact comparisons are intentional
#![cfg_attr(test, allow(clippy::float_cmp))]
// Allow casting warnings - precision loss and truncation are acceptable for metrics/scores
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
// Allow stylistic lints
#![allow(clippy::manual_let_else)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::ref_option)]
#![allow(clippy::must_use_candidate)]
// Allow missing docs sections - we have sufficient documentation
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
// Allow test-specific lints - tests often use temporary/unused variables for clarity
#![cfg_attr(test, allow(unused_variables))]
#![cfg_attr(test, allow(unused_must_use))]
#![cfg_attr(test, allow(clippy::absurd_extreme_comparisons))]
#![cfg_attr(test, allow(clippy::overly_complex_bool_expr))]
#![cfg_attr(test, allow(clippy::comparison_to_empty))]
#![cfg_attr(test, allow(clippy::type_complexity))]

pub mod challenge;
pub mod cli;
pub mod config;
pub mod detectors;
pub mod geolocation;
pub mod lists;
pub mod models;
pub mod observability;
pub mod proxy;
pub mod ratelimit;
pub mod reputation;
pub mod storage;
pub mod utils;

/// Common error type for `WebSec` operations
pub type Result<T> = std::result::Result<T, Error>;

/// `WebSec` error types
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
