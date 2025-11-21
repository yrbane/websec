//! HTTP reverse proxy server
//!
//! Transparent request forwarding with:
//! - HTTP/1.1 and HTTP/2 support via hyper 1.0
//! - Connection pooling to backend servers
//! - Header preservation (X-Forwarded-For, X-Real-IP)
//! - Request/response streaming for large payloads
//! - Retry logic with exponential backoff
//! - Circuit breaker pattern for backend protection

pub mod backend;
pub mod circuit_breaker;
pub mod middleware;
pub mod retry;
pub mod server;
#[cfg(feature = "tls")]
pub mod sni;

pub use backend::BackendClient;
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
pub use middleware::{metrics_handler, proxy_handler, ProxyState};
pub use retry::RetryPolicy;
pub use server::ProxyServer;
#[cfg(feature = "tls")]
pub use sni::SniResolver;
