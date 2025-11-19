//! Tests pour le système de logging structuré
//!
//! TDD PHASE ROUGE : Tests écrits AVANT implémentation
//!
//! Tests :
//! - Initialisation du logging structuré (tracing)
//! - Logs de détection avec contexte (IP, méthode, chemin)
//! - Niveaux de log appropriés (info, warn, error)
//! - Format JSON pour parsing automatique
//! - Corrélation des événements par request_id

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::{BotDetector, DetectorRegistry, HttpRequestContext};
use websec::observability::logging::{init_logging, LogFormat};
use websec::reputation::{DecisionEngine, DecisionEngineConfig};
use websec::storage::InMemoryRepository;

#[test]
fn test_logging_initialization_json() {
    // Initialiser le logging en format JSON
    let result = init_logging(LogFormat::Json, "info");
    assert!(result.is_ok(), "L'initialisation du logging JSON doit réussir");
}

#[test]
fn test_logging_initialization_pretty() {
    // Initialiser le logging en format lisible
    let result = init_logging(LogFormat::Pretty, "debug");
    assert!(result.is_ok(), "L'initialisation du logging Pretty doit réussir");
}

#[tokio::test]
async fn test_detection_logging() {
    // Initialiser logging
    let _ = init_logging(LogFormat::Pretty, "info");

    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());
    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(BotDetector::new()));
    let detectors = Arc::new(registry);

    let engine = DecisionEngine::new(config, repository, detectors);

    // Requête suspecte qui devrait être loggée
    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.100").unwrap(),
        method: "GET".to_string(),
        path: "/admin".to_string(),
        query: None,
        headers: vec![],
        body: None,
        user_agent: Some("Nikto/2.1.5".to_string()), // Scanner détecté
        referer: None,
        content_type: None,
    };

    let result = engine.process_request(&context).await;
    assert!(result.is_ok(), "Le traitement doit réussir");

    // Vérifier que la détection a été loggée
    // Note: Dans un vrai test, on capturerait les logs pour vérification
}

#[test]
fn test_log_levels() {
    use tracing::{debug, error, info, warn};

    let _ = init_logging(LogFormat::Pretty, "debug");

    // Ces logs doivent être capturables
    debug!("Message de debug pour tests");
    info!("Message d'info pour détection");
    warn!("Message d'avertissement pour comportement suspect");
    error!("Message d'erreur pour problème critique");
}

#[tokio::test]
async fn test_structured_logging_with_context() {
    use tracing::info;

    let _ = init_logging(LogFormat::Json, "info");

    let ip = "192.168.1.50";
    let method = "POST";
    let path = "/api/login";

    // Log structuré avec contexte
    info!(
        ip = %ip,
        method = %method,
        path = %path,
        "Requête traitée"
    );

    // Ce test vérifie que les logs structurés compilent correctement
}

#[test]
fn test_request_id_correlation() {
    use uuid::Uuid;

    let _ = init_logging(LogFormat::Json, "info");

    let request_id = Uuid::new_v4();

    // Les logs doivent inclure request_id pour corrélation
    tracing::info!(
        request_id = %request_id,
        "Début du traitement de la requête"
    );

    tracing::info!(
        request_id = %request_id,
        detector = "BotDetector",
        "Détection effectuée"
    );

    tracing::info!(
        request_id = %request_id,
        score = 85,
        "Score de réputation calculé"
    );
}
