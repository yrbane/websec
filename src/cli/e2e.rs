use crate::config::load_from_file;
use crate::proxy::server::ProxyServer;
use crate::{Error, Result};
use axum::{routing::get, Router};
use http::StatusCode;
use reqwest::Client;
use serde_json::json;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::{signal, time};

/// Run the in-process E2E suite (backend + `WebSec`) against the provided config.
pub async fn run_e2e(config_path: &Path, backend_port: u16, proxy_port: u16) -> Result<()> {
    println!("🚀 Lancement des tests E2E WebSec\n");

    build_release()?;

    let backend = start_test_backend(backend_port).await?;

    let mut settings = load_from_file(config_path).map_err(|e| {
        Error::Config(format!(
            "Impossible de charger {}: {e}",
            config_path.display()
        ))
    })?;
    settings.server.listen = format!("127.0.0.1:{proxy_port}");
    if settings.server.listeners.is_empty() {
        settings.server.backend = format!("http://127.0.0.1:{backend_port}");
    }
    let proxy = ProxyServer::new(&settings).await?;
    let proxy_infos = proxy.listener_infos().to_vec();
    for info in &proxy_infos {
        println!(
            "  - Listener {} -> {}{}",
            info.addr,
            info.backend,
            if info.tls { " (TLS)" } else { "" }
        );
    }

    let proxy_task = tokio::spawn(async move { proxy.run().await });

    time::sleep(Duration::from_secs(2)).await;

    run_functional_tests(proxy_port).await?;
    display_metrics(proxy_port).await?;

    backend.shutdown.send(()).ok();
    backend.handle.abort();
    proxy_task.abort();

    println!("\n✅ Tests E2E terminés");
    Ok(())
}

/// Run the lightweight test backend only (useful for docker-compose or manual testing).
pub async fn run_dev_backend(port: u16) -> Result<()> {
    println!("🔧 Backend de test WebSec sur port {port}");
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(Error::Io)?;
    axum::serve(listener, backend_router())
        .with_graceful_shutdown(async {
            let _ = signal::ctrl_c().await;
        })
        .await
        .map_err(|e| Error::Http(format!("backend error: {e}")))
}

fn build_release() -> Result<()> {
    println!("📦 Compilation de WebSec (release)...");
    let status = Command::new("cargo")
        .args(["build", "--release"])
        .status()
        .map_err(Error::Io)?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Config("cargo build --release a échoué".to_string()))
    }
}

struct BackendHandle {
    handle: JoinHandle<()>,
    shutdown: oneshot::Sender<()>,
}

async fn start_test_backend(port: u16) -> Result<BackendHandle> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(Error::Io)?;
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, backend_router()).with_graceful_shutdown(async move {
            let _ = rx.await;
        });
        let _ = server.await;
    });

    Ok(BackendHandle {
        handle,
        shutdown: tx,
    })
}

fn backend_router() -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/api/health", get(health_handler))
        .route("/api/users", get(users_handler))
        .route("/slow", get(slow_handler))
        .route("/api/login", axum::routing::post(login_handler))
        .route("/api/echo", axum::routing::post(echo_handler))
}

async fn root_handler() -> &'static str {
    "<h1>Test Backend</h1><p>WebSec E2E Test Server</p>"
}

async fn health_handler() -> axum::Json<serde_json::Value> {
    axum::Json(json!({ "status": "healthy" }))
}

async fn users_handler() -> axum::Json<serde_json::Value> {
    axum::Json(json!([
        {"id": 1, "name": "Alice"},
        {"id": 2, "name": "Bob"},
        {"id": 3, "name": "Charlie"}
    ]))
}

async fn slow_handler() -> &'static str {
    time::sleep(Duration::from_secs(2)).await;
    "Slow response"
}

async fn login_handler() -> axum::Json<serde_json::Value> {
    axum::Json(json!({
        "success": true,
        "token": "fake-jwt-token-12345",
        "user": {"id": 1, "username": "testuser"}
    }))
}

async fn echo_handler(body: axum::body::Bytes) -> (StatusCode, axum::body::Bytes) {
    (StatusCode::OK, body)
}

async fn run_functional_tests(proxy_port: u16) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| Error::Http(format!("reqwest erreur: {e}")))?;

    println!("\n🧪 Tests fonctionnels\n");
    let base = format!("http://127.0.0.1:{proxy_port}");
    get_expect(&client, &base, "/", StatusCode::OK).await?;
    get_metrics(&client, &base).await?;
    get_expect(&client, &base, "/api/users", StatusCode::OK).await?;
    post_echo(&client, &base).await?;
    check_headers(&client, &base).await?;
    Ok(())
}

async fn get_expect(client: &Client, base: &str, path: &str, status: StatusCode) -> Result<()> {
    print!("  GET {path} ... ");
    let resp = client
        .get(format!("{base}{path}"))
        .send()
        .await
        .map_err(|e| Error::Http(format!("requête {path} échouée: {e}")))?;
    if resp.status() == status {
        println!("✓");
        Ok(())
    } else {
        Err(Error::Http(format!(
            "statut inattendu pour {path}: {}",
            resp.status()
        )))
    }
}

async fn get_metrics(client: &Client, base: &str) -> Result<()> {
    print!("  GET /metrics ... ");
    let body = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .map_err(|e| Error::Http(format!("metrics request failed: {e}")))?
        .text()
        .await
        .map_err(|e| Error::Http(format!("metrics body failed: {e}")))?;
    if body.contains("requests_total") {
        println!("✓");
        Ok(())
    } else {
        Err(Error::Http("'requests_total' absent des métriques".into()))
    }
}

async fn post_echo(client: &Client, base: &str) -> Result<()> {
    print!("  POST /api/echo ... ");
    let body = client
        .post(format!("{base}/api/echo"))
        .json(&json!({"test": "data"}))
        .send()
        .await
        .map_err(|e| Error::Http(format!("echo request failed: {e}")))?
        .text()
        .await
        .map_err(|e| Error::Http(format!("echo body failed: {e}")))?;
    if body.contains("data") {
        println!("✓");
        Ok(())
    } else {
        Err(Error::Http("Réponse echo inattendue".into()))
    }
}

async fn check_headers(client: &Client, base: &str) -> Result<()> {
    print!("  Headers WebSec ... ");
    let resp = client
        .get(format!("{base}/"))
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
        .map_err(|e| Error::Http(format!("headers request failed: {e}")))?;
    if resp.headers().contains_key("x-websec-decision") {
        println!("✓");
        Ok(())
    } else {
        Err(Error::Http("Header X-WebSec-Decision manquant".into()))
    }
}

async fn display_metrics(proxy_port: u16) -> Result<()> {
    println!("\n📊 Métriques finales\n");
    let client = Client::new();
    let body = client
        .get(format!("http://127.0.0.1:{proxy_port}/metrics"))
        .send()
        .await
        .map_err(|e| Error::Http(format!("metrics request failed: {e}")))?
        .text()
        .await
        .map_err(|e| Error::Http(format!("metrics body failed: {e}")))?;
    if let Some(line) = body.lines().find(|l| l.starts_with("requests_total")) {
        println!("  {line}");
    }
    if let Some(line) = body
        .lines()
        .find(|l| l.contains("decisions_by_type{decision=\"allow\"}"))
    {
        println!("  {line}");
    }
    Ok(())
}
