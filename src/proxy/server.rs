//! Serveur proxy HTTP utilisant axum
//!
//! Serveur reverse proxy HTTP avec interception des requêtes pour analyse de sécurité.
//!
//! # Architecture
//!
//! ```text
//! Client HTTP → ProxyServer (axum) → Middleware → DecisionEngine
//!                                        ↓
//!                        [ALLOW] → BackendClient → Backend Server
//!                        [BLOCK/CHALLENGE/RATE_LIMIT] → Error Response
//! ```
//!
//! # Utilisation
//!
//! ```no_run
//! use websec::proxy::server::ProxyServer;
//! use websec::config::load_from_file;
//!
//! # async fn example() -> websec::Result<()> {
//! let settings = load_from_file("config/websec.toml")?;
//! let server = ProxyServer::new(&settings)?;
//!
//! // Démarre le serveur (bloque jusqu'à interruption)
//! server.run().await?;
//! # Ok(())
//! # }
//! ```

use crate::challenge::ChallengeManager;
use crate::config::settings::{ListenerTlsConfig, ServerConfig};
use crate::config::Settings;
use crate::detectors::DetectorRegistry;
use crate::observability::logging::{init_logging, LogFormat};
use crate::observability::metrics::MetricsRegistry;
use crate::proxy::backend::BackendClient;
use crate::proxy::middleware::{metrics_standalone_handler, proxy_handler, ProxyState};
use crate::reputation::decision::{DecisionEngine, DecisionEngineConfig};
use crate::storage::InMemoryRepository;
use crate::{Error, Result};
use axum::{routing::get, Router};
#[cfg(feature = "tls")]
use axum_server::tls_rustls::RustlsConfig;
use futures::future::try_join_all;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Serveur proxy HTTP
///
/// Encapsule le serveur axum avec tous les composants nécessaires :
/// - `DecisionEngine` (détecteurs + scoring)
/// - `BackendClient` (forwarding)
/// - `ChallengeManager` (CAPTCHA)
/// - `MetricsRegistry` (Prometheus)
pub struct ProxyServer {
    listeners: Vec<ListenerRuntime>,
    info: Vec<ListenerInfo>,
}

/// Informations publiques sur un listener (utilisé pour l'affichage CLI)
#[derive(Clone, Debug)]
pub struct ListenerInfo {
    /// Adresse d'écoute (IP:port)
    pub addr: SocketAddr,
    /// Indique si ce listener est configuré avec TLS (HTTPS)
    pub tls: bool,
    /// URL du backend vers lequel les requêtes sont relayées
    pub backend: String,
}

impl ProxyServer {
    /// Informations sur les listeners configurés
    #[must_use]
    pub fn listener_infos(&self) -> &[ListenerInfo] {
        &self.info
    }

    /// Crée un nouveau serveur proxy depuis la configuration
    ///
    /// Initialise tous les composants :
    /// - Logging structuré
    /// - Storage (`InMemoryRepository`)
    /// - Détecteurs (registry avec tous les détecteurs)
    /// - `DecisionEngine`
    /// - `BackendClient`
    /// - `ChallengeManager`
    /// - Métriques Prometheus
    ///
    /// # Arguments
    ///
    /// * `settings` - Configuration complète du serveur
    ///
    /// # Errors
    ///
    /// Retourne une erreur si :
    /// - L'adresse d'écoute est invalide
    /// - L'initialisation du logging échoue
    /// - Un composant ne peut être créé
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use websec::proxy::server::ProxyServer;
    /// use websec::config::load_from_file;
    ///
    /// # fn example() -> websec::Result<()> {
    /// let settings = load_from_file("config/websec.toml")?;
    /// let server = ProxyServer::new(&settings)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(settings: &Settings) -> Result<Self> {
        // 1. Initialiser le logging
        let log_format = match settings.logging.format.as_str() {
            "json" => LogFormat::Json,
            "pretty" => LogFormat::Pretty,
            _ => LogFormat::Pretty,
        };

        if let Err(e) = init_logging(log_format, &settings.logging.level) {
            eprintln!("Warning: Logging already initialized: {e}");
        }

        tracing::info!("Initializing WebSec proxy server");

        // 2. Créer le storage (InMemoryRepository pour MVP)
        let repository = Arc::new(InMemoryRepository::new());
        tracing::info!("Repository initialized: InMemoryRepository");

        // 3. Créer le registry de détecteurs avec tous les détecteurs
        let mut detector_registry = DetectorRegistry::new();

        // Ajouter tous les détecteurs disponibles
        detector_registry.register(Arc::new(crate::detectors::BotDetector::new()));
        detector_registry.register(Arc::new(crate::detectors::BruteForceDetector::new()));
        detector_registry.register(Arc::new(crate::detectors::FloodDetector::new()));
        detector_registry.register(Arc::new(crate::detectors::InjectionDetector::new()));
        detector_registry.register(Arc::new(crate::detectors::ScanDetector::new()));
        detector_registry.register(Arc::new(crate::detectors::HeaderDetector::new()));
        detector_registry.register(Arc::new(crate::detectors::GeoDetector::new()));
        detector_registry.register(Arc::new(crate::detectors::ProtocolDetector::new()));
        detector_registry.register(Arc::new(crate::detectors::SessionDetector::new()));

        let detectors = Arc::new(detector_registry);
        tracing::info!("Detectors registered: {}", detectors.count());

        // 4. Créer la configuration du DecisionEngine
        let decision_config = DecisionEngineConfig {
            base_score: settings.reputation.base_score,
            decay_half_life_hours: settings.reputation.decay_half_life_hours,
            correlation_penalty_bonus: settings.reputation.correlation_penalty_bonus,
            thresholds: crate::reputation::score::ScoringThresholds {
                allow: settings.reputation.threshold_allow,
                ratelimit: settings.reputation.threshold_ratelimit,
                challenge: settings.reputation.threshold_challenge,
                block: settings.reputation.threshold_block,
            },
            blacklist: None,
            whitelist: None,
        };

        // 5. Créer le DecisionEngine
        let decision_engine = Arc::new(DecisionEngine::new(
            decision_config,
            repository.clone(),
            detectors.clone(),
        ));

        tracing::info!("DecisionEngine initialized");

        // 6. Challenge manager et métriques
        let challenge_manager = Arc::new(ChallengeManager::new(Duration::from_secs(300)));
        tracing::info!("ChallengeManager initialized");

        let metrics = Arc::new(MetricsRegistry::new());
        tracing::info!("MetricsRegistry initialized");

        // Parser les trusted proxies
        let trusted_proxies: Vec<IpAddr> = settings
            .server
            .trusted_proxies
            .iter()
            .filter_map(|s| {
                s.parse::<IpAddr>().ok().or_else(|| {
                    tracing::warn!("Invalid IP in trusted_proxies: {}", s);
                    None
                })
            })
            .collect();

        if !trusted_proxies.is_empty() {
            tracing::info!(
                "Trusted proxies configured: {} IPs",
                trusted_proxies.len()
            );
        } else {
            tracing::info!("No trusted proxies configured (direct client connections)");
        }

        let trusted_proxies = Arc::new(trusted_proxies);
        let max_body_size = settings.server.max_body_size;

        if max_body_size > 0 {
            tracing::info!(
                "Request body size limit: {} bytes ({} MB)",
                max_body_size,
                max_body_size / (1024 * 1024)
            );
        } else {
            tracing::warn!("No request body size limit configured (not recommended in production)");
        }

        let effective_listeners = resolve_listeners(&settings.server)?;
        if effective_listeners.is_empty() {
            return Err(Error::Config(
                "Aucun listener configuré (définissez server.listen ou server.listeners)"
                    .to_string(),
            ));
        }

        let mut runtimes = Vec::new();
        let mut info = Vec::new();

        for listener in effective_listeners {
            tracing::info!(
                "Listener configured on {} -> {}{}",
                listener.addr,
                listener.backend,
                if listener.tls.is_some() { " (TLS)" } else { "" }
            );

            let backend_client = Arc::new(BackendClient::new(&listener.backend));
            let proxy_state = Arc::new(ProxyState::new(
                decision_engine.clone(),
                backend_client,
                challenge_manager.clone(),
                metrics.clone(),
                trusted_proxies.clone(),
                max_body_size,
            ));
            let app = build_router(proxy_state);

            info.push(ListenerInfo {
                addr: listener.addr,
                tls: listener.tls.is_some(),
                backend: listener.backend.clone(),
            });

            runtimes.push(ListenerRuntime {
                addr: listener.addr,
                app,
                tls: listener.tls.clone(),
            });
        }

        // Add dedicated metrics listener (separate port for security)
        if settings.metrics.enabled {
            let metrics_addr = SocketAddr::from(([0, 0, 0, 0], settings.metrics.port));
            let metrics_app = build_metrics_router(metrics.clone());

            tracing::info!(
                "Metrics server configured on {}{}",
                metrics_addr,
                " (separate port for security)"
            );

            runtimes.push(ListenerRuntime {
                addr: metrics_addr,
                app: metrics_app,
                tls: None, // Metrics always served over HTTP (internal only)
            });
        } else {
            tracing::warn!("Metrics disabled - Prometheus endpoint not available");
        }

        Ok(Self {
            listeners: runtimes,
            info,
        })
    }

    /// Démarre le serveur proxy
    ///
    /// Cette méthode bloque jusqu'à ce que le serveur soit arrêté (Ctrl+C).
    /// Le serveur écoute sur l'adresse configurée et traite toutes les requêtes
    /// HTTP entrantes via le middleware de détection.
    ///
    /// # Errors
    ///
    /// Retourne une erreur si :
    /// - Le bind sur l'adresse échoue (port déjà utilisé, permissions)
    /// - Une erreur I/O se produit pendant le fonctionnement
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use websec::proxy::server::ProxyServer;
    /// use websec::config::load_from_file;
    ///
    /// # async fn example() -> websec::Result<()> {
    /// let settings = load_from_file("config/websec.toml")?;
    /// let server = ProxyServer::new(&settings)?;
    ///
    /// // Démarre le serveur (bloque jusqu'à Ctrl+C)
    /// server.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run(self) -> Result<()> {
        try_join_all(self.listeners.into_iter().map(|listener| listener.run())).await?;
        Ok(())
    }
}

struct ListenerRuntime {
    addr: SocketAddr,
    app: Router,
    tls: Option<ListenerTlsConfig>,
}

impl ListenerRuntime {
    async fn run(self) -> Result<()> {
        if let Some(tls_conf) = self.tls {
            run_tls_listener(self.addr, self.app, tls_conf).await
        } else {
            run_http_listener(self.addr, self.app).await
        }
    }
}

struct EffectiveListener {
    addr: SocketAddr,
    backend: String,
    tls: Option<ListenerTlsConfig>,
}

fn build_router(state: Arc<ProxyState>) -> Router {
    Router::new()
        // REMOVED: /metrics route for security (served on separate port)
        .fallback(proxy_handler)
        .with_state(state)
}

/// Build a dedicated metrics router (separate port for security)
fn build_metrics_router(metrics: Arc<MetricsRegistry>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_standalone_handler))
        .with_state(metrics)
}

fn resolve_listeners(server_cfg: &ServerConfig) -> Result<Vec<EffectiveListener>> {
    if server_cfg.listeners.is_empty() {
        let addr = SocketAddr::from_str(&server_cfg.listen)
            .map_err(|e| Error::Config(format!("Invalid listen address: {e}")))?;
        return Ok(vec![EffectiveListener {
            addr,
            backend: server_cfg.backend.clone(),
            tls: None,
        }]);
    }

    server_cfg
        .listeners
        .iter()
        .map(|listener| {
            let addr = SocketAddr::from_str(&listener.listen)
                .map_err(|e| Error::Config(format!("Invalid listen address: {e}")))?;
            Ok(EffectiveListener {
                addr,
                backend: listener.backend.clone(),
                tls: listener.tls.clone(),
            })
        })
        .collect()
}

async fn run_http_listener(addr: SocketAddr, app: Router) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| map_bind_error(e, addr))?;
    tracing::info!("🚀 HTTP listener ready on {}", addr);
    tracing::info!(
        "📊 Prometheus metrics available at http://{addr}/metrics",
        addr = addr
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| Error::Http(format!("Server error on {addr}: {e}")))
}

#[cfg(feature = "tls")]
async fn run_tls_listener(addr: SocketAddr, app: Router, tls: ListenerTlsConfig) -> Result<()> {
    let config = RustlsConfig::from_pem_file(tls.cert_file, tls.key_file)
        .await
        .map_err(|e| Error::Config(format!("Failed to load TLS config: {e}")))?;

    tracing::info!("🔒 HTTPS listener ready on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| Error::Http(format!("TLS server error on {addr}: {e}")))
}

#[cfg(not(feature = "tls"))]
async fn run_tls_listener(_addr: SocketAddr, _app: Router, _tls: ListenerTlsConfig) -> Result<()> {
    Err(Error::Config(
        "Listener TLS configuré mais la fonctionnalité 'tls' n'est pas activée".to_string(),
    ))
}

fn map_bind_error(error: io::Error, addr: SocketAddr) -> Error {
    if error.kind() == io::ErrorKind::AddrInUse {
        let detailed_msg =
            crate::utils::port_checker::format_port_conflict_error(addr.port(), &addr.to_string());
        Error::Io(io::Error::new(io::ErrorKind::AddrInUse, detailed_msg))
    } else {
        Error::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{
        GeolocationConfig, ListenerConfig, LoggingConfig, MetricsConfig, RateLimitConfig,
        ReputationConfig, ServerConfig, Settings, StorageConfig,
    };

    fn create_test_settings() -> Settings {
        Settings {
            server: ServerConfig {
                listen: "127.0.0.1:18080".to_string(), // Port de test différent
                backend: "http://127.0.0.1:13000".to_string(),
                workers: 4,
                listeners: Vec::new(),
                trusted_proxies: Vec::new(),
                max_body_size: 10 * 1024 * 1024,
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
                level: "info".to_string(),
                format: "json".to_string(),
            },
            metrics: MetricsConfig {
                enabled: true,
                port: 9090,
            },
        }
    }

    #[test]
    fn test_server_creation() {
        let settings = create_test_settings();
        let server = ProxyServer::new(&settings).unwrap();

        let infos = server.listener_infos();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].addr.to_string(), "127.0.0.1:18080");
        assert!(!infos[0].tls);
    }

    #[test]
    fn test_invalid_listen_address() {
        let mut settings = create_test_settings();
        settings.server.listen = "invalid_address".to_string();

        let result = ProxyServer::new(&settings);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_listeners_configuration() {
        let mut settings = create_test_settings();
        settings.server.listeners = vec![
            ListenerConfig {
                listen: "127.0.0.1:18080".to_string(),
                backend: "http://127.0.0.1:13000".to_string(),
                tls: None,
            },
            ListenerConfig {
                listen: "127.0.0.1:18443".to_string(),
                backend: "http://127.0.0.1:13001".to_string(),
                tls: None,
            },
        ];

        let server = ProxyServer::new(&settings).unwrap();
        assert_eq!(server.listener_infos().len(), 2);
    }

    // Note: Les tests end-to-end avec vraies requêtes HTTP seront dans
    // tests/proxy_e2e_test.rs pour tester le serveur complet en action
}
