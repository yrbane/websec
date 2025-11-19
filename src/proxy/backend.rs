//! Client HTTP backend pour forwarder les requêtes
//!
//! Forward les requêtes autorisées vers le serveur web backend.
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

use crate::{Error, Result};
use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::{Empty, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::str::FromStr;

/// Client pour forwarder les requêtes au backend
///
/// Utilise hyper pour envoyer les requêtes HTTP au serveur backend
/// et retourner les réponses de manière transparente.
pub struct BackendClient {
    /// URL de base du backend
    backend_url: String,
    /// Client HTTP hyper
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
}

impl BackendClient {
    /// Crée un nouveau client backend
    ///
    /// # Arguments
    ///
    /// * `backend_url` - URL du serveur backend (ex: "http://localhost:3000")
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
        let client = Client::builder(TokioExecutor::new()).build_http();

        Self {
            backend_url: backend_url.into(),
            client,
        }
    }

    /// Forward une requête au backend
    ///
    /// Prend une requête HTTP, la forward au backend, et retourne la réponse.
    /// L'URI de la requête est préservée et ajoutée à l'URL du backend.
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
    /// - La connexion au backend échoue
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
    pub async fn forward(
        &self,
        mut request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>> {
        // Construire l'URI complète en combinant backend_url + path original
        let path_and_query = request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let target_uri = format!("{}{}", self.backend_url, path_and_query);
        let uri = Uri::from_str(&target_uri)
            .map_err(|e| Error::Http(format!("Invalid URI: {}", e)))?;

        // Mettre à jour l'URI de la requête
        *request.uri_mut() = uri;

        // Forward la requête au backend
        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| Error::Http(format!("Backend request failed: {}", e)))?;

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
        Self::new(self.backend_url.clone())
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
