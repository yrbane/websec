//! Observabilité : logging, tracing et métriques
//!
//! - Logging structuré avec `tracing` (format JSON pour production)
//! - Exposition de métriques Prometheus (compteurs de requêtes, histogrammes de latence, distributions de réputation)
//! - Tracing distribué avec request IDs

pub mod logging;
pub mod metrics;

pub use logging::{init_logging, LogFormat};
pub use metrics::{init_metrics, MetricsRegistry};
