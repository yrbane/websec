//! Host-based backend routing.
//!
//! Chooses the upstream [`BackendClient`] for a request from its `Host` header.
//! When no route matches (or none are configured) it falls back to the
//! listener's default backend, so a listener without `routes` behaves exactly
//! like the historical single-backend proxy — the feature is purely additive.
//!
//! Matching order (most specific first):
//! 1. exact host (`app.example.com`)
//! 2. wildcard suffix (`*.example.com`), longest suffix wins
//! 3. listener default backend
//!
//! Each distinct backend keeps its own [`BackendClient`], hence its own
//! connection pool and circuit breaker — a failing node app cannot trip the
//! breaker of the Apache backend, and vice-versa.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::settings::RouteConfig;
use crate::proxy::backend::BackendClient;

/// Resolves a `Host` header to a backend client.
pub struct HostRouter {
    default: Arc<BackendClient>,
    exact: HashMap<String, Arc<BackendClient>>,
    /// `(suffix, backend)` where `suffix` is the part after `*.`, lowercased
    /// (e.g. `example.com`). Sorted longest-first so the most specific matches.
    wildcard: Vec<(String, Arc<BackendClient>)>,
}

impl HostRouter {
    /// Builds a router from a listener's default backend and its host routes.
    #[must_use]
    pub fn new(default: Arc<BackendClient>, routes: &[RouteConfig]) -> Self {
        let mut exact = HashMap::new();
        let mut wildcard = Vec::new();

        for route in routes {
            let backend = Arc::new(BackendClient::new(&route.backend));
            let name = route.server_name.trim().to_ascii_lowercase();
            if let Some(suffix) = name.strip_prefix("*.") {
                wildcard.push((suffix.to_string(), backend));
            } else if !name.is_empty() {
                exact.insert(name, backend);
            }
        }
        wildcard.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self { default, exact, wildcard }
    }

    /// Number of configured host routes (default backend excluded).
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// Selects the backend for a `Host` header value.
    ///
    /// The value may carry a port (`example.com:443`) — it is stripped before
    /// matching. Matching is case-insensitive.
    #[must_use]
    pub fn select(&self, host: &str) -> &Arc<BackendClient> {
        let host = host
            .rsplit('@')
            .next()
            .unwrap_or(host)
            .trim();
        // Strip a trailing :port (IPv6 literals in Host use brackets, and we
        // only ever match on names, so a plain split on the last ':' is safe
        // for the hostnames we route).
        let host = host.split(':').next().unwrap_or(host).trim().to_ascii_lowercase();

        if let Some(backend) = self.exact.get(&host) {
            return backend;
        }
        for (suffix, backend) in &self.wildcard {
            if host == *suffix || host.ends_with(&format!(".{suffix}")) {
                return backend;
            }
        }
        &self.default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes() -> Vec<RouteConfig> {
        vec![
            RouteConfig {
                server_name: "app.example.com".to_string(),
                backend: "http://127.0.0.1:3000".to_string(),
            },
            RouteConfig {
                server_name: "*.example.com".to_string(),
                backend: "http://127.0.0.1:4000".to_string(),
            },
        ]
    }

    fn router() -> HostRouter {
        let default = Arc::new(BackendClient::new("http://127.0.0.1:8443"));
        HostRouter::new(default, &routes())
    }

    #[test]
    fn exact_beats_wildcard() {
        let r = router();
        assert_eq!(r.select("app.example.com").backend_url(), "http://127.0.0.1:3000");
    }

    #[test]
    fn wildcard_matches_subdomain() {
        let r = router();
        assert_eq!(r.select("other.example.com").backend_url(), "http://127.0.0.1:4000");
    }

    #[test]
    fn unmatched_host_uses_default() {
        let r = router();
        assert_eq!(r.select("nethttp.net").backend_url(), "http://127.0.0.1:8443");
    }

    #[test]
    fn strips_port_and_is_case_insensitive() {
        let r = router();
        assert_eq!(r.select("APP.Example.com:443").backend_url(), "http://127.0.0.1:3000");
    }

    #[test]
    fn no_routes_is_always_default() {
        let default = Arc::new(BackendClient::new("http://127.0.0.1:8443"));
        let r = HostRouter::new(default, &[]);
        assert_eq!(r.route_count(), 0);
        assert_eq!(r.select("anything").backend_url(), "http://127.0.0.1:8443");
    }
}
