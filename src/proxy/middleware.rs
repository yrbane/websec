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
    /// Liste des proxies/LB de confiance (X-Forwarded-For autorisé uniquement depuis ces IPs)
    pub trusted_proxies: Arc<Vec<IpAddr>>,
    /// Taille maximale du corps de requête en bytes
    pub max_body_size: usize,
}

impl ProxyState {
    /// Crée un nouvel état de proxy
    #[must_use]
    pub fn new(
        decision_engine: Arc<DecisionEngine>,
        backend_client: Arc<BackendClient>,
        challenge_manager: Arc<ChallengeManager>,
        metrics: Arc<MetricsRegistry>,
        trusted_proxies: Arc<Vec<IpAddr>>,
        max_body_size: usize,
    ) -> Self {
        Self {
            decision_engine,
            backend_client,
            challenge_manager,
            metrics,
            trusted_proxies,
            max_body_size,
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

    // 1. Extraire l'IP du client (avec validation des proxies de confiance)
    let client_ip = extract_client_ip(&req, &state.trusted_proxies);

    // Incrémenter le compteur de requêtes
    state.metrics.increment_counter("requests_total");

    // 2. Lire le body de la requête (nécessaire pour analyse)
    let (parts, body) = req.into_parts();

    // Limiter la taille du body pour éviter le DoS mémoire
    let body_bytes = if state.max_body_size > 0 {
        match http_body_util::Limited::new(body, state.max_body_size)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                // Vérifier si c'est une erreur de limite dépassée
                if e.to_string().contains("body length limit exceeded") {
                    tracing::warn!(
                        ip = %client_ip,
                        max_size = state.max_body_size,
                        "Request body too large, rejecting"
                    );
                    return Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Body::from(format!(
                            "Request body too large (max {} bytes)",
                            state.max_body_size
                        )))
                        .unwrap();
                }
                tracing::error!(error = %e, "Failed to read request body");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Bad Request"))
                    .unwrap();
            }
        }
    } else {
        // Pas de limite configurée (déconseillé en production)
        match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::error!(error = %e, "Failed to read request body");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Bad Request"))
                    .unwrap();
            }
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
            // Forward la requête au backend (avec sanitization des headers)
            forward_to_backend(state.clone(), parts, body_bytes, client_ip).await
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
/// Priorité (seulement si la connexion vient d'un proxy de confiance) :
/// 1. X-Forwarded-For (premier IP)
/// 2. X-Real-IP
/// 3. `SocketAddr` de la connexion (par défaut)
///
/// # Sécurité
///
/// Les headers X-Forwarded-For/X-Real-IP ne sont acceptés QUE si la connexion
/// provient d'une IP listée dans `trusted_proxies`. Sinon, on utilise toujours
/// le `SocketAddr` réel pour empêcher l'usurpation d'IP.
fn extract_client_ip(req: &Request<Body>, trusted_proxies: &[IpAddr]) -> IpAddr {
    // Extraire l'IP de la socket (connexion réelle)
    let socket_ip = if let Some(addr) = req.extensions().get::<SocketAddr>() {
        addr.ip()
    } else {
        // Fallback si pas de SocketAddr (ne devrait jamais arriver)
        return IpAddr::from_str("127.0.0.1").unwrap();
    };

    // Si trusted_proxies est vide, TOUJOURS utiliser l'IP socket (connexion directe)
    if trusted_proxies.is_empty() {
        tracing::debug!(
            "No trusted proxies configured, using socket IP: {}",
            socket_ip
        );
        return socket_ip;
    }

    // Vérifier si la connexion vient d'un proxy de confiance
    if !trusted_proxies.contains(&socket_ip) {
        tracing::debug!(
            "Connection from untrusted IP {}, ignoring X-Forwarded-For/X-Real-IP headers",
            socket_ip
        );
        return socket_ip;
    }

    // La connexion vient d'un proxy de confiance, on peut lire les headers
    tracing::debug!(
        "Connection from trusted proxy {}, checking forwarding headers",
        socket_ip
    );

    // Essayer X-Forwarded-For
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(value) = forwarded.to_str() {
            // Prendre le premier IP de la liste (client originel)
            if let Some(first_ip) = value.split(',').next() {
                if let Ok(ip) = IpAddr::from_str(first_ip.trim()) {
                    tracing::debug!("Using X-Forwarded-For IP: {}", ip);
                    return ip;
                }
            }
        }
    }

    // Essayer X-Real-IP
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = IpAddr::from_str(value.trim()) {
                tracing::debug!("Using X-Real-IP: {}", ip);
                return ip;
            }
        }
    }

    // Fallback : utiliser l'IP du proxy de confiance
    tracing::debug!(
        "No valid forwarding headers, using trusted proxy IP: {}",
        socket_ip
    );
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

/// Sanitize les headers HTTP avant de forwarder au backend
///
/// Supprime les headers hop-by-hop et potentiellement dangereux,
/// normalise Host, et ajoute X-Forwarded-* appropriés.
///
/// # Sécurité
///
/// - Supprime headers hop-by-hop (Connection, Transfer-Encoding, etc.)
/// - Empêche Host header poisoning en fixant Host au backend
/// - Normalise Content-Length/Transfer-Encoding
/// - Ajoute X-Forwarded-For/X-Real-IP avec l'IP réelle du client
fn sanitize_request_headers(
    mut parts: http::request::Parts,
    state: &ProxyState,
    client_ip: IpAddr,
) -> http::request::Parts {
    // Liste des headers hop-by-hop à supprimer (RFC 7230)
    const HOP_BY_HOP_HEADERS: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];

    // Supprimer tous les headers hop-by-hop
    for header in HOP_BY_HOP_HEADERS {
        parts.headers.remove(*header);
    }

    // Supprimer headers potentiellement dangereux multiples
    // (empêche HTTP request smuggling via headers dupliqués)
    let host_count = parts.headers.get_all("host").iter().count();
    if host_count > 1 {
        tracing::warn!("Multiple Host headers detected, removing all");
        parts.headers.remove("host");
    }

    // Fixer le Host header vers le backend (empêche Host header poisoning)
    if let Some(backend_host) = extract_host_from_url(&state.backend_client.backend_url()) {
        parts.headers.insert(
            "host",
            backend_host.parse().unwrap_or_else(|_| {
                tracing::warn!("Failed to parse backend host, using default");
                "localhost".parse().unwrap()
            }),
        );
    }

    // Ajouter/remplacer X-Forwarded-For avec l'IP réelle du client
    // (pas celle potentiellement spoofée)
    let forwarded_for = match parts.headers.get("x-forwarded-for") {
        Some(existing) => {
            // Ajouter l'IP client à la fin de la liste
            format!(
                "{}, {}",
                existing.to_str().unwrap_or(""),
                client_ip
            )
        }
        None => client_ip.to_string(),
    };

    parts.headers.insert(
        "x-forwarded-for",
        forwarded_for
            .parse()
            .unwrap_or_else(|_| client_ip.to_string().parse().unwrap()),
    );

    // Définir X-Real-IP avec l'IP du client
    parts.headers.insert(
        "x-real-ip",
        client_ip
            .to_string()
            .parse()
            .unwrap_or_else(|_| "127.0.0.1".parse().unwrap()),
    );

    // Normaliser Content-Length et Transfer-Encoding
    // Si les deux sont présents, supprimer Transfer-Encoding (prévention smuggling)
    if parts.headers.contains_key("content-length")
        && parts.headers.contains_key("transfer-encoding")
    {
        tracing::warn!(
            "Both Content-Length and Transfer-Encoding present, removing Transfer-Encoding"
        );
        parts.headers.remove("transfer-encoding");
    }

    parts
}

/// Extrait le hostname d'une URL backend (simple parsing)
fn extract_host_from_url(url: &str) -> Option<String> {
    // Simple parsing: http://host:port/path -> host:port
    url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .and_then(|rest| rest.split('/').next())
        .map(|host| host.to_string())
}

/// Forward la requête au backend avec sanitization des headers
async fn forward_to_backend(
    state: Arc<ProxyState>,
    parts: http::request::Parts,
    body: Bytes,
    client_ip: IpAddr,
) -> Response<Body> {
    // Sanitize headers avant de forwarder (sécurité)
    let sanitized_parts = sanitize_request_headers(parts, &state, client_ip);

    // Reconstruire la requête avec le body et headers sanitizés
    let request = Request::from_parts(sanitized_parts, Full::new(body));

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
    fn test_extract_client_ip_ignores_headers_without_trusted_proxy() {
        // Sans trusted proxies, les headers doivent être ignorés (sécurité)
        let mut req = Request::builder()
            .header("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
            .header("X-Real-IP", "198.51.100.42")
            .body(Body::empty())
            .unwrap();

        // Ajouter un SocketAddr dans les extensions
        req.extensions_mut()
            .insert(SocketAddr::from_str("127.0.0.1:1234").unwrap());

        let ip = extract_client_ip(&req, &[]);
        // Doit utiliser le SocketAddr, pas les headers
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn test_extract_client_ip_from_x_forwarded_for_with_trusted_proxy() {
        // Avec un proxy de confiance, on peut lire X-Forwarded-For
        let trusted_proxy = IpAddr::from_str("127.0.0.1").unwrap();
        let mut req = Request::builder()
            .header("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
            .body(Body::empty())
            .unwrap();

        req.extensions_mut()
            .insert(SocketAddr::from_str("127.0.0.1:1234").unwrap());

        let ip = extract_client_ip(&req, &[trusted_proxy]);
        assert_eq!(ip.to_string(), "203.0.113.195");
    }

    #[test]
    fn test_extract_client_ip_from_x_real_ip_with_trusted_proxy() {
        let trusted_proxy = IpAddr::from_str("127.0.0.1").unwrap();
        let mut req = Request::builder()
            .header("X-Real-IP", "198.51.100.42")
            .body(Body::empty())
            .unwrap();

        req.extensions_mut()
            .insert(SocketAddr::from_str("127.0.0.1:1234").unwrap());

        let ip = extract_client_ip(&req, &[trusted_proxy]);
        assert_eq!(ip.to_string(), "198.51.100.42");
    }

    #[test]
    fn test_extract_client_ip_untrusted_proxy_ignores_headers() {
        // Si la connexion vient d'une IP NON listée dans trusted_proxies
        let trusted_proxy = IpAddr::from_str("10.0.0.1").unwrap();
        let mut req = Request::builder()
            .header("X-Forwarded-For", "203.0.113.195")
            .body(Body::empty())
            .unwrap();

        // Connexion depuis 127.0.0.1 qui n'est PAS dans trusted_proxies
        req.extensions_mut()
            .insert(SocketAddr::from_str("127.0.0.1:1234").unwrap());

        let ip = extract_client_ip(&req, &[trusted_proxy]);
        // Doit ignorer X-Forwarded-For et utiliser l'IP socket
        assert_eq!(ip.to_string(), "127.0.0.1");
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
