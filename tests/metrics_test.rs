//! Tests pour les métriques Prometheus
//!
//! TDD PHASE ROUGE : Tests écrits AVANT implémentation
//!
//! Tests :
//! - Enregistrement des métriques de détection
//! - Compteurs par type de détecteur
//! - Histogrammes de latence
//! - Jauges pour score de réputation
//! - Export au format Prometheus

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::{BotDetector, DetectorRegistry, HttpRequestContext};
use websec::observability::metrics::{init_metrics, MetricsRegistry};
use websec::reputation::{DecisionEngine, DecisionEngineConfig};
use websec::storage::InMemoryRepository;

#[test]
fn test_metrics_initialization() {
    let registry = init_metrics();
    assert!(registry.is_ok(), "L'initialisation des métriques doit réussir");
}

#[test]
fn test_metrics_registry_creation() {
    let registry = MetricsRegistry::new();

    // Vérifier que les métriques de base sont créées
    assert!(registry.get_counter("requests_total").is_some());
    assert!(registry.get_counter("detections_total").is_some());
    assert!(registry.get_histogram("request_duration_seconds").is_some());
    assert!(registry.get_gauge("reputation_score").is_some());
}

#[tokio::test]
async fn test_detection_metrics() {
    let metrics = MetricsRegistry::new();

    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());
    let mut detector_registry = DetectorRegistry::new();
    detector_registry.register(Arc::new(BotDetector::new()));
    let detectors = Arc::new(detector_registry);

    let engine = DecisionEngine::new(config, repository, detectors);

    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.100").unwrap(),
        method: "GET".to_string(),
        path: "/".to_string(),
        query: None,
        headers: vec![],
        body: None,
        user_agent: Some("Nikto/2.1.5".to_string()),
        referer: None,
        content_type: None,
    };

    // Traiter la requête
    let _result = engine.process_request(&context).await.unwrap();

    // Vérifier que les métriques ont été incrémentées
    let requests_total = metrics.get_counter_value("requests_total");
    assert!(requests_total > 0.0, "Le compteur de requêtes doit être incrémenté");

    let detections_total = metrics.get_counter_value("detections_total");
    assert!(
        detections_total > 0.0,
        "Le compteur de détections doit être incrémenté"
    );
}

#[test]
fn test_metrics_by_detector_type() {
    let metrics = MetricsRegistry::new();

    // Incrémenter les métriques par type de détecteur
    metrics.increment_detection("BotDetector");
    metrics.increment_detection("BotDetector");
    metrics.increment_detection("InjectionDetector");

    // Vérifier les compteurs
    let bot_count = metrics.get_detector_count("BotDetector");
    assert_eq!(bot_count, 2, "BotDetector doit avoir 2 détections");

    let injection_count = metrics.get_detector_count("InjectionDetector");
    assert_eq!(injection_count, 1, "InjectionDetector doit avoir 1 détection");
}

#[test]
fn test_latency_histogram() {
    let metrics = MetricsRegistry::new();

    // Enregistrer des latences
    metrics.observe_latency(0.050); // 50ms
    metrics.observe_latency(0.100); // 100ms
    metrics.observe_latency(0.025); // 25ms

    // Vérifier que l'histogramme a enregistré les observations
    let histogram = metrics.get_histogram("request_duration_seconds").unwrap();
    assert!(
        histogram.sample_count() >= 3,
        "L'histogramme doit contenir au moins 3 observations"
    );
}

#[test]
fn test_reputation_score_gauge() {
    let metrics = MetricsRegistry::new();

    // Enregistrer différents scores
    metrics.set_reputation_score("192.168.1.1", 100.0);
    metrics.set_reputation_score("192.168.1.2", 75.0);
    metrics.set_reputation_score("192.168.1.3", 50.0);

    // Vérifier que les jauges sont mises à jour
    let score1 = metrics.get_reputation_score("192.168.1.1");
    assert_eq!(score1, 100.0, "Le score pour IP1 doit être 100");

    let score2 = metrics.get_reputation_score("192.168.1.2");
    assert_eq!(score2, 75.0, "Le score pour IP2 doit être 75");
}

#[test]
fn test_prometheus_export() {
    let metrics = MetricsRegistry::new();

    // Ajouter quelques métriques
    metrics.increment_counter("requests_total");
    metrics.increment_detection("BotDetector");
    metrics.observe_latency(0.042);

    // Exporter au format Prometheus
    let export = metrics.export_prometheus();

    // Vérifier le format
    assert!(
        export.contains("requests_total"),
        "L'export doit contenir requests_total"
    );
    assert!(
        export.contains("detections_total"),
        "L'export doit contenir detections_total"
    );
    assert!(
        export.contains("request_duration_seconds"),
        "L'export doit contenir request_duration_seconds"
    );
}

#[test]
fn test_metrics_by_decision_type() {
    let metrics = MetricsRegistry::new();

    // Compter les décisions par type
    metrics.increment_decision("allow");
    metrics.increment_decision("allow");
    metrics.increment_decision("rate_limit");
    metrics.increment_decision("block");

    let allow_count = metrics.get_decision_count("allow");
    assert_eq!(allow_count, 2, "Doit avoir 2 décisions 'allow'");

    let block_count = metrics.get_decision_count("block");
    assert_eq!(block_count, 1, "Doit avoir 1 décision 'block'");
}

#[tokio::test]
async fn test_concurrent_metrics() {
    let metrics = Arc::new(MetricsRegistry::new());

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let metrics_clone = Arc::clone(&metrics);
            tokio::spawn(async move {
                metrics_clone.increment_counter("requests_total");
                metrics_clone.increment_detection("BotDetector");
                metrics_clone.observe_latency(0.001 * f64::from(i));
            })
        })
        .collect();

    for handle in handles {
        handle.await.unwrap();
    }

    // Vérifier que toutes les incrémentations ont été enregistrées
    let total = metrics.get_counter_value("requests_total");
    assert!(total >= 10.0, "Doit avoir au moins 10 requêtes enregistrées");
}
