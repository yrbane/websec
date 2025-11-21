//! Client HTTP backend pour forwarder les requêtes
//!
//! Forward les requêtes autorisées vers le serveur web backend avec :
//! - Retry logic avec exponential backoff
//! - Circuit breaker pour protection backend
//! - Connection pooling
//!
//! # Utilisation
//!
//! ```no_run
//! use websec::proxy::backend::BackendClient;
//! use http::{Request, Response};
//! use http_body_util::Full;
//! use bytes::Bytes;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = BackendClient::new("http://localhost:3000");
//!
//! let request = Request::builder()
//!     .uri("/api/users")
//!     .body(Full::new(Bytes::new()))?;
//!
//! let response = client.forward(request).await?;
//! # Ok(())
//! # }
//! ```

use crate::proxy::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use crate::proxy::retry::RetryPolicy;
use crate::{Error, Result};
use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::str::FromStr;
use std::sync::Arc;

/// Client pour forwarder les requêtes au backend
///
/// Utilise hyper pour envoyer les requêtes HTTP au serveur backend
/// et retourner les réponses de manière transparente.
///
/// Includes:
/// - Retry logic with exponential backoff
/// - Circuit breaker for backend protection
/// - Connection pooling via hyper
pub struct BackendClient {
    /// URL de base du backend
    backend_url: String,
    /// Client HTTP hyper
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    /// Retry policy
    retry_policy: RetryPolicy,
    /// Circuit breaker
    circuit_breaker: Arc<CircuitBreaker>,
}

impl BackendClient {
    /// Crée un nouveau client backend avec politique de retry et circuit breaker par défaut
    ///
    /// # Arguments
    ///
    /// * `backend_url` - URL du serveur backend (ex: "<http://localhost:3000>")
    ///
    /// # Examples
    ///
    /// ```
    /// use websec::proxy::backend::BackendClient;
    ///
    /// let client = BackendClient::new("http://localhost:3000");
    /// ```
    #[must_use]
    pub fn new(backend_url: impl Into<String>) -> Self {
        let url = backend_url.into();
        Self::with_policies(
            url.clone(),
            RetryPolicy::default(),
            CircuitBreakerConfig::default(),
        )
    }

    /// Crée un client backend avec retry et circuit breaker personnalisés
    ///
    /// # Arguments
    ///
    /// * `backend_url` - URL du serveur backend
    /// * `retry_policy` - Politique de retry
    /// * `cb_config` - Configuration du circuit breaker
    #[must_use]
    pub fn with_policies(
        backend_url: impl Into<String>,
        retry_policy: RetryPolicy,
        cb_config: CircuitBreakerConfig,
    ) -> Self {
        // Force HTTP/1 only - most backends (like Apache) don't support HTTP/2
        let client = Client::builder(TokioExecutor::new())
            .http2_only(false)
            .build_http();
        let url = backend_url.into();
        let circuit_breaker = Arc::new(CircuitBreaker::new(url.clone(), cb_config));

        Self {
            backend_url: url,
            client,
            retry_policy,
            circuit_breaker,
        }
    }

    /// Crée un client sans retry ni circuit breaker (pour tests)
    #[must_use]
    pub fn without_resilience(backend_url: impl Into<String>) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        let url = backend_url.into();
        let circuit_breaker = Arc::new(CircuitBreaker::new(
            url.clone(),
            CircuitBreakerConfig {
                failure_threshold: u64::MAX, // Never open
                ..Default::default()
            },
        ));

        Self {
            backend_url: url,
            client,
            retry_policy: RetryPolicy::no_retry(),
            circuit_breaker,
        }
    }

    /// Forward une requête au backend avec retry et circuit breaker
    ///
    /// Prend une requête HTTP, la forward au backend, et retourne la réponse.
    /// L'URI de la requête est préservée et ajoutée à l'URL du backend.
    ///
    /// Resilience features:
    /// - Retry avec exponential backoff sur erreurs transitoires
    /// - Circuit breaker pour protéger le backend de surcharge
    ///
    /// # Arguments
    ///
    /// * `request` - Requête HTTP à forwarder
    ///
    /// # Returns
    ///
    /// La réponse HTTP du backend
    ///
    /// # Errors
    ///
    /// Retourne une erreur si :
    /// - L'URI est invalide
    /// - Le circuit breaker est ouvert
    /// - La connexion au backend échoue après tous les retries
    /// - Le backend retourne une erreur
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use websec::proxy::backend::BackendClient;
    /// # use http::Request;
    /// # use http_body_util::Full;
    /// # use bytes::Bytes;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = BackendClient::new("http://localhost:3000");
    ///
    /// let request = Request::builder()
    ///     .uri("/api/users")
    ///     .body(Full::new(Bytes::new()))?;
    ///
    /// let response = client.forward(request).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn forward(&self, request: Request<Full<Bytes>>) -> Result<Response<Incoming>> {
        // Construire l'URI complète en combinant backend_url + path original
        let path_and_query = request
            .uri()
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);

        let target_uri = format!("{}{}", self.backend_url, path_and_query);

        // Clone request parts for retry
        let (parts, body) = request.into_parts();

        // Extract bytes from Full body
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                return Err(Error::Http(format!("Failed to read request body: {e}")));
            }
        };

        // Execute with circuit breaker and retry
        let circuit_breaker = Arc::clone(&self.circuit_breaker);
        let client = self.client.clone();
        let uri_str = target_uri.clone();

        let response = self
            .retry_policy
            .retry("backend_forward", || {
                let parts_clone = parts.clone();
                let body_clone = body_bytes.clone();
                let uri_str_clone = uri_str.clone();
                let client_clone = client.clone();
                let cb = Arc::clone(&circuit_breaker);

                async move {
                    // Check circuit breaker
                    cb.call_allowed()
                        .await
                        .map_err(|()| Error::Http("Circuit breaker is open".to_string()))?;

                    // Build request
                    let uri = Uri::from_str(&uri_str_clone)
                        .map_err(|e| Error::Http(format!("Invalid URI: {e}")))?;

                    let mut req = Request::from_parts(parts_clone, Full::new(body_clone));
                    *req.uri_mut() = uri;

                    // Send request
                    match client_clone.request(req).await {
                        Ok(response) => {
                            // Check if response indicates backend error (5xx)
                            if response.status().is_server_error() {
                                cb.record_failure().await;
                                Err(Error::Http(format!("Backend error: {}", response.status())))
                            } else {
                                cb.record_success().await;
                                Ok(response)
                            }
                        }
                        Err(e) => {
                            cb.record_failure().await;
                            Err(Error::Http(format!("Backend request failed: {e}")))
                        }
                    }
                }
            })
            .await?;

        Ok(response)
    }

    /// Forward une requête sans body au backend
    ///
    /// Version simplifiée pour les requêtes GET/HEAD sans body.
    ///
    /// # Arguments
    ///
    /// * `request` - Requête HTTP sans body
    ///
    /// # Returns
    ///
    /// La réponse HTTP du backend
    ///
    /// # Errors
    ///
    /// Retourne une erreur si la connexion ou le traitement échoue
    pub async fn forward_empty(
        &self,
        request: Request<Empty<Bytes>>,
    ) -> Result<Response<Incoming>> {
        // Convertir Empty en Full pour réutiliser forward()
        let (parts, _body) = request.into_parts();
        let request_with_full = Request::from_parts(parts, Full::new(Bytes::new()));

        self.forward(request_with_full).await
    }

    /// Récupère l'URL du backend
    #[must_use]
    pub fn backend_url(&self) -> &str {
        &self.backend_url
    }
}

impl Clone for BackendClient {
    fn clone(&self) -> Self {
        Self {
            backend_url: self.backend_url.clone(),
            client: Client::builder(TokioExecutor::new()).build_http(),
            retry_policy: self.retry_policy.clone(),
            circuit_breaker: Arc::clone(&self.circuit_breaker),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_client_creation() {
        let client = BackendClient::new("http://localhost:3000");
        assert_eq!(client.backend_url(), "http://localhost:3000");
    }

    #[test]
    fn test_backend_client_clone() {
        let client = BackendClient::new("http://localhost:3000");
        let cloned = client.clone();
        assert_eq!(cloned.backend_url(), "http://localhost:3000");
    }

    // Note: Les tests d'intégration réels nécessitent un serveur backend
    // Ces tests seront ajoutés dans tests/proxy_integration_test.rs
}
