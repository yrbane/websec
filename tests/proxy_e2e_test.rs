//! Tests end-to-end du serveur proxy HTTP
//!
//! Tests d'intégration complets du proxy server avec backend simulé.

use axum::{body::Body, http::StatusCode, routing::get, Router};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;
use websec::config::settings::{
    GeolocationConfig, LoggingConfig, MetricsConfig, RateLimitConfig, ReputationConfig,
    ServerConfig, Settings, StorageConfig,
};
use websec::proxy::server::ProxyServer;

// Handlers pour le backend de test
async fn root_handler() -> &'static str {
    "Backend OK"
}

async fn users_handler() -> &'static str {
    "Users list"
}

async fn echo_handler() -> Response<Body> {
    Response::builder()
        .status(200)
        .body(Body::from("Echo"))
        .unwrap()
}

/// Crée un serveur backend de test simple
async fn start_test_backend(port: u16) -> tokio::task::JoinHandle<()> {
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/api/users", get(users_handler))
        .route("/echo", get(echo_handler));

    let addr = SocketAddr::from_str(&format!("127.0.0.1:{port}")).unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    })
}

/// Crée des settings de test pour le proxy
fn create_test_settings(proxy_port: u16, backend_port: u16) -> Settings {
    Settings {
        server: ServerConfig {
            listen: format!("127.0.0.1:{proxy_port}"),
            backend: format!("http://127.0.0.1:{backend_port}"),
            workers: 2,
        },
        reputation: ReputationConfig {
            base_score: 100,
            threshold_allow: 70,
            threshold_ratelimit: 40,
            threshold_challenge: 20,
            threshold_block: 0,
            decay_half_life_hours: 24.0,
            correlation_penalty_bonus: 10,
        },
        storage: StorageConfig {
            storage_type: "memory".to_string(),
            redis_url: None,
            cache_size: 10000,
        },
        geolocation: GeolocationConfig {
            enabled: false,
            database: None,
            penalties: std::collections::HashMap::new(),
        },
        ratelimit: RateLimitConfig {
            normal_rpm: 1000,
            normal_burst: 100,
            suspicious_rpm: 200,
            suspicious_burst: 20,
            aggressive_rpm: 50,
            aggressive_burst: 5,
            window_duration_secs: 60,
        },
        logging: LoggingConfig {
            level: "error".to_string(), // Réduire le bruit dans les tests
            format: "json".to_string(),
        },
        metrics: MetricsConfig {
            enabled: true,
            port: 9090,
        },
    }
}

/// Helper pour faire une requête HTTP vers le proxy
async fn make_request(
    proxy_port: u16,
    path: &str,
) -> Result<Response<hyper::body::Incoming>, Box<dyn std::error::Error>> {
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();

    let uri = format!("http://127.0.0.1:{proxy_port}{path}");
    let request = Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))?;

    let response = client.request(request).await?;
    Ok(response)
}

#[tokio::test]
async fn test_proxy_forwards_to_backend() {
    // 1. Démarrer le backend sur port 13001
    let backend_handle = start_test_backend(13001).await;

    // Attendre que le backend démarre
    sleep(Duration::from_millis(100)).await;

    // 2. Démarrer le proxy sur port 18001
    let settings = create_test_settings(18001, 13001);
    let proxy = ProxyServer::new(&settings).unwrap();

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.unwrap();
    });

    // Attendre que le proxy démarre
    sleep(Duration::from_millis(200)).await;

    // 3. Faire une requête via le proxy
    let response = make_request(18001, "/").await.unwrap();

    // 4. Vérifier que la réponse vient bien du backend
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert_eq!(body_str, "Backend OK");

    // Cleanup
    proxy_handle.abort();
    backend_handle.abort();
}

#[tokio::test]
async fn test_proxy_server_creation() {
    // Test de création du serveur sans le démarrer
    let settings = create_test_settings(18002, 13002);
    let proxy = ProxyServer::new(&settings);

    assert!(proxy.is_ok());
    assert_eq!(
        proxy.unwrap().listen_addr().to_string(),
        "127.0.0.1:18002"
    );
}

#[tokio::test]
async fn test_proxy_adds_websec_headers() {
    // 1. Démarrer le backend sur port 13003
    let backend_handle = start_test_backend(13003).await;
    sleep(Duration::from_millis(100)).await;

    // 2. Démarrer le proxy sur port 18003
    let settings = create_test_settings(18003, 13003);
    let proxy = ProxyServer::new(&settings).unwrap();

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.unwrap();
    });

    sleep(Duration::from_millis(200)).await;

    // 3. Faire une requête
    let response = make_request(18003, "/echo").await.unwrap();

    // 4. Vérifier les headers WebSec
    assert_eq!(response.status(), StatusCode::OK);

    let decision_header = response
        .headers()
        .get("X-WebSec-Decision")
        .and_then(|v| v.to_str().ok());

    assert_eq!(decision_header, Some("ALLOW"));

    // Cleanup
    proxy_handle.abort();
    backend_handle.abort();
}

#[tokio::test]
async fn test_proxy_extracts_client_ip() {
    // 1. Démarrer le backend sur port 13004
    let backend_handle = start_test_backend(13004).await;
    sleep(Duration::from_millis(100)).await;

    // 2. Démarrer le proxy sur port 18004
    let settings = create_test_settings(18004, 13004);
    let proxy = ProxyServer::new(&settings).unwrap();

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.unwrap();
    });

    sleep(Duration::from_millis(200)).await;

    // 3. Faire une requête avec X-Forwarded-For
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();

    let uri = "http://127.0.0.1:18004/";
    let request = Request::builder()
        .uri(uri)
        .header("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = client.request(request).await.unwrap();

    // 4. Vérifier que la requête passe (IP normale)
    assert_eq!(response.status(), StatusCode::OK);

    // Cleanup
    proxy_handle.abort();
    backend_handle.abort();
}

#[tokio::test]
async fn test_metrics_endpoint() {
    // 1. Démarrer le backend sur port 13005
    let backend_handle = start_test_backend(13005).await;
    sleep(Duration::from_millis(100)).await;

    // 2. Démarrer le proxy sur port 18005
    let settings = create_test_settings(18005, 13005);
    let proxy = ProxyServer::new(&settings).unwrap();

    let proxy_handle = tokio::spawn(async move {
        proxy.run().await.unwrap();
    });

    sleep(Duration::from_millis(200)).await;

    // 3. Faire une requête normale pour générer des métriques
    let _ = make_request(18005, "/").await;

    sleep(Duration::from_millis(100)).await;

    // 4. Requêter l'endpoint /metrics
    let response = make_request(18005, "/metrics").await.unwrap();

    // 5. Vérifier le status et le content-type
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("Content-Type")
        .and_then(|v| v.to_str().ok());
    assert_eq!(content_type, Some("text/plain; version=0.0.4; charset=utf-8"));

    // 6. Vérifier le contenu des métriques
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    // Vérifier que les métriques Prometheus sont présentes
    assert!(body_str.contains("requests_total"));
    assert!(body_str.contains("TYPE requests_total counter"));

    // Cleanup
    proxy_handle.abort();
    backend_handle.abort();
}
