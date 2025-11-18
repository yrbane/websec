//! Observability: logging, tracing, and metrics
//!
//! - Structured logging with `tracing` (JSON format for production)
//! - Prometheus metrics exposition (request counts, latency histograms, reputation distributions)
//! - Distributed tracing with request IDs

pub mod logging;
pub mod metrics;

pub use logging::init_logging;
pub use metrics::{record_request_decision, record_signal, update_score_bucket};
