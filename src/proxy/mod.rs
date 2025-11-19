//! HTTP reverse proxy server
//!
//! Transparent request forwarding with:
//! - HTTP/1.1 and HTTP/2 support via hyper 1.0
//! - Connection pooling to backend servers
//! - Header preservation (X-Forwarded-For, X-Real-IP)
//! - Request/response streaming for large payloads

pub mod backend;
pub mod middleware;
pub mod server;

pub use backend::BackendClient;
pub use middleware::{metrics_handler, proxy_handler, ProxyState};
pub use server::ProxyServer;
