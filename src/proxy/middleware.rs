//! Middleware proxy pour l'interception et l'analyse des requêtes
//!
//! Couche middleware qui intercepte les requêtes pour l'analyse de menaces,
//! coordonne les détecteurs, calcule le score de réputation, et prend une décision.
//!
//! # Architecture
//!
//! ```text
//! Client → Middleware → DetectorRegistry → DecisionEngine → [ALLOW/BLOCK/CHALLENGE/RATE_LIMIT]
//!                                                                  ↓
//!                                                            BackendClient
//! ```

use crate::challenge::ChallengeManager;
use crate::detectors::HttpRequestContext;
use crate::observability::metrics::MetricsRegistry;
use crate::proxy::backend::BackendClient;
use crate::reputation::decision::DecisionEngine;
use crate::reputation::score::ProxyDecision;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

/// État partagé du middleware
#[derive(Clone)]
pub struct ProxyState {
    /// Moteur de décision de réputation
    pub decision_engine: Arc<DecisionEngine>,
    /// Client pour forwarder au backend
    pub backend_client: Arc<BackendClient>,
    /// Gestionnaire de challenges CAPTCHA
    pub challenge_manager: Arc<ChallengeManager>,
    /// Registry de métriques
    pub metrics: Arc<MetricsRegistry>,
}

impl ProxyState {
    /// Crée un nouvel état de proxy
    #[must_use]
    pub fn new(
        decision_engine: Arc<DecisionEngine>,
        backend_client: Arc<BackendClient>,
        challenge_manager: Arc<ChallengeManager>,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            decision_engine,
            backend_client,
            challenge_manager,
            metrics,
        }
    }
}

/// Handler principal du middleware proxy
///
/// Analyse chaque requête avec les détecteurs, calcule le score de réputation,
/// prend une décision (`ALLOW/BLOCK/CHALLENGE/RATE_LIMIT`), et agit en conséquence.
///
/// # Flux de traitement
///
/// 1. Extraire l'IP du client (X-Forwarded-For ou socket)
/// 2. Construire le contexte de requête HTTP
/// 3. Passer par le `DecisionEngine` (détecteurs + scoring)
/// 4. Selon la décision :
///    - ALLOW: Forward au backend
///    - BLOCK: Retourner 403
///    - CHALLENGE: Afficher page CAPTCHA
///    - `RATE_LIMIT`: Retourner 429
/// 5. Enregistrer métriques et logs
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
) -> Response<Body> {
    let start = Instant::now();

    // 1. Extraire l'IP du client
    let client_ip = extract_client_ip(&req);

    // Incrémenter le compteur de requêtes
    state.metrics.increment_counter("requests_total");

    // 2. Lire le body de la requête (nécessaire pour analyse)
    let (parts, body) = req.into_parts();

    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to read request body");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Bad Request"))
                .unwrap();
        }
    };

    // 3. Construire le contexte HTTP pour les détecteurs
    let context = build_http_context(client_ip, &parts, &body_bytes);

    // 4. Passer par le DecisionEngine
    let decision_result = match state.decision_engine.process_request(&context).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, ip = %client_ip, "Decision engine error");
            // En cas d'erreur, on AUTORISE par défaut (fail-open pour disponibilité)
            // Une alternative plus stricte serait BLOQUER (fail-closed)
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap();
        }
    };

    // Enregistrer les métriques de décision
    let decision_str = match decision_result.decision {
        ProxyDecision::Allow => "allow",
        ProxyDecision::RateLimit => "rate_limit",
        ProxyDecision::Challenge => "challenge",
        ProxyDecision::Block => "block",
    };
    state.metrics.increment_decision(decision_str);

    state
        .metrics
        .set_reputation_score(&client_ip.to_string(), decision_result.score.into());

    // 5. Agir selon la décision
    let response = match decision_result.decision {
        ProxyDecision::Allow => {
            // Forward la requête au backend
            forward_to_backend(state.clone(), parts, body_bytes).await
        }
        ProxyDecision::Block => {
            tracing::warn!(
                ip = %client_ip,
                score = decision_result.score,
                signals = decision_result.detection.signals.len(),
                "Request blocked"
            );

            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("X-WebSec-Decision", "BLOCK")
                .header("X-WebSec-Score", decision_result.score.to_string())
                .body(Body::from(format!(
                    "Access Denied - Reputation Score: {}",
                    decision_result.score
                )))
                .unwrap()
        }
        ProxyDecision::Challenge => {
            tracing::info!(
                ip = %client_ip,
                score = decision_result.score,
                "Challenge required"
            );

            // Générer un challenge CAPTCHA
            if let Some(challenge) = state
                .challenge_manager
                .create_challenge(client_ip, crate::challenge::ChallengeType::SimpleMath)
            {
                let html = challenge.to_html();
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "text/html; charset=utf-8")
                    .header("X-WebSec-Decision", "CHALLENGE")
                    .header("X-WebSec-Score", decision_result.score.to_string())
                    .body(Body::from(html))
                    .unwrap()
            } else {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Failed to generate challenge"))
                    .unwrap()
            }
        }
        ProxyDecision::RateLimit => {
            tracing::warn!(
                ip = %client_ip,
                score = decision_result.score,
                "Rate limit applied"
            );

            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("X-WebSec-Decision", "RATE_LIMIT")
                .header("X-WebSec-Score", decision_result.score.to_string())
                .header("Retry-After", "60")
                .body(Body::from("Too Many Requests - Please slow down"))
                .unwrap()
        }
    };

    // Enregistrer la latence
    let duration = start.elapsed();
    state.metrics.observe_latency(duration.as_secs_f64());

    response
}

/// Handler pour l'endpoint `/metrics` Prometheus
///
/// Expose les métriques au format Prometheus pour scraping.
pub async fn metrics_handler(
    State(state): State<Arc<ProxyState>>,
) -> impl axum::response::IntoResponse {
    let metrics_text = state.metrics.export_prometheus();

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(axum::body::Body::from(metrics_text))
        .unwrap()
}

/// Extrait l'IP du client depuis les headers ou la socket
///
/// Priorité :
/// 1. X-Forwarded-For (premier IP)
/// 2. X-Real-IP
/// 3. `SocketAddr` de la connexion
fn extract_client_ip(req: &Request<Body>) -> IpAddr {
    // Essayer X-Forwarded-For
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(value) = forwarded.to_str() {
            // Prendre le premier IP de la liste
            if let Some(first_ip) = value.split(',').next() {
                if let Ok(ip) = IpAddr::from_str(first_ip.trim()) {
                    return ip;
                }
            }
        }
    }

    // Essayer X-Real-IP
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = IpAddr::from_str(value.trim()) {
                return ip;
            }
        }
    }

    // Fallback : extraire de la SocketAddr des extensions
    if let Some(addr) = req.extensions().get::<SocketAddr>() {
        return addr.ip();
    }

    // Dernier fallback : localhost (pour tests)
    IpAddr::from_str("127.0.0.1").unwrap()
}

/// Construit le contexte HTTP pour les détecteurs
fn build_http_context(
    ip: IpAddr,
    parts: &http::request::Parts,
    body: &Bytes,
) -> HttpRequestContext {
    // Extraire les headers sous forme de vecteurs de tuples
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    // Extraire User-Agent
    let user_agent = parts
        .headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Extraire Referer
    let referer = parts
        .headers
        .get("Referer")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Extraire Content-Type
    let content_type = parts
        .headers
        .get("Content-Type")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Convertir le body en Option<Vec<u8>>
    let body_vec = if body.is_empty() {
        None
    } else {
        Some(body.to_vec())
    };

    HttpRequestContext {
        ip,
        method: parts.method.to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().map(String::from),
        headers,
        body: body_vec,
        user_agent,
        referer,
        content_type,
    }
}

/// Forward la requête au backend
async fn forward_to_backend(
    state: Arc<ProxyState>,
    parts: http::request::Parts,
    body: Bytes,
) -> Response<Body> {
    // Reconstruire la requête avec le body
    let request = Request::from_parts(parts, Full::new(body));

    // Forward au backend
    match state.backend_client.forward(request).await {
        Ok(backend_response) => {
            // Convertir la réponse backend en Response<Body>
            let (parts, body) = backend_response.into_parts();

            // Lire le body du backend
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to read backend response");
                    return Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from("Bad Gateway"))
                        .unwrap();
                }
            };

            // Reconstruire la réponse
            let mut response = Response::from_parts(parts, Body::from(body_bytes));

            // Ajouter headers informationnels WebSec
            response
                .headers_mut()
                .insert("X-WebSec-Decision", "ALLOW".parse().unwrap());

            response
        }
        Err(e) => {
            tracing::error!(error = %e, "Backend forwarding failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Backend Error: {e}")))
                .unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_client_ip_from_x_forwarded_for() {
        let req = Request::builder()
            .header("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req);
        assert_eq!(ip.to_string(), "203.0.113.195");
    }

    #[test]
    fn test_extract_client_ip_from_x_real_ip() {
        let req = Request::builder()
            .header("X-Real-IP", "198.51.100.42")
            .body(Body::empty())
            .unwrap();

        let ip = extract_client_ip(&req);
        assert_eq!(ip.to_string(), "198.51.100.42");
    }

    #[test]
    fn test_build_http_context() {
        let req = Request::builder()
            .method("POST")
            .uri("/api/users?page=1")
            .header("User-Agent", "Mozilla/5.0")
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let (parts, _body) = req.into_parts();
        let body = Bytes::from("{}");
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        let context = build_http_context(ip, &parts, &body);

        assert_eq!(context.ip.to_string(), "192.168.1.1");
        assert_eq!(context.method, "POST");
        assert_eq!(context.path, "/api/users");
        assert_eq!(context.query, Some("page=1".to_string()));
        assert_eq!(context.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(context.content_type, Some("application/json".to_string()));
    }
}
