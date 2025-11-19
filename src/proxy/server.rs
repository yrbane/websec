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
use crate::config::Settings;
use crate::detectors::DetectorRegistry;
use crate::observability::logging::{init_logging, LogFormat};
use crate::observability::metrics::MetricsRegistry;
use crate::proxy::backend::BackendClient;
use crate::proxy::middleware::{proxy_handler, ProxyState};
use crate::reputation::decision::{DecisionEngine, DecisionEngineConfig};
use crate::storage::InMemoryRepository;
use crate::{Error, Result};
use axum::Router;
use std::net::SocketAddr;
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
    /// Adresse d'écoute
    listen_addr: SocketAddr,
    /// Application axum configurée
    app: Router,
}

impl ProxyServer {
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

        // 6. Créer le BackendClient
        let backend_client = Arc::new(BackendClient::new(&settings.server.backend));
        tracing::info!("BackendClient initialized: {}", settings.server.backend);

        // 7. Créer le ChallengeManager (timeout 5 minutes)
        let challenge_manager = Arc::new(ChallengeManager::new(Duration::from_secs(300)));
        tracing::info!("ChallengeManager initialized");

        // 8. Créer le registry de métriques
        let metrics = Arc::new(MetricsRegistry::new());
        tracing::info!("MetricsRegistry initialized");

        // 9. Créer l'état partagé du proxy
        let proxy_state = Arc::new(ProxyState::new(
            decision_engine,
            backend_client,
            challenge_manager,
            metrics,
        ));

        // 10. Construire l'application axum avec le middleware
        let app = Router::new()
            .fallback(proxy_handler)
            .with_state(proxy_state);

        // 11. Parser l'adresse d'écoute
        let listen_addr = SocketAddr::from_str(&settings.server.listen)
            .map_err(|e| Error::Config(format!("Invalid listen address: {e}")))?;

        tracing::info!("Proxy server configured on {}", listen_addr);

        Ok(Self { listen_addr, app })
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
        let listener = TcpListener::bind(self.listen_addr).await?;

        tracing::info!("🚀 WebSec proxy server listening on {}", self.listen_addr);
        tracing::info!("📊 Prometheus metrics available (call MetricsRegistry::export_prometheus())");
        tracing::info!("✅ Server ready to accept connections");

        // Démarrer le serveur axum
        axum::serve(
            listener,
            self.app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| Error::Http(format!("Server error: {e}")))?;

        Ok(())
    }

    /// Récupère l'adresse d'écoute
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{
        GeolocationConfig, LoggingConfig, MetricsConfig, RateLimitConfig, ReputationConfig,
        ServerConfig, Settings, StorageConfig,
    };

    fn create_test_settings() -> Settings {
        Settings {
            server: ServerConfig {
                listen: "127.0.0.1:18080".to_string(), // Port de test différent
                backend: "http://127.0.0.1:13000".to_string(),
                workers: 4,
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

        assert_eq!(server.listen_addr().to_string(), "127.0.0.1:18080");
    }

    #[test]
    fn test_invalid_listen_address() {
        let mut settings = create_test_settings();
        settings.server.listen = "invalid_address".to_string();

        let result = ProxyServer::new(&settings);
        assert!(result.is_err());
    }

    // Note: Les tests end-to-end avec vraies requêtes HTTP seront dans
    // tests/proxy_e2e_test.rs pour tester le serveur complet en action
}
