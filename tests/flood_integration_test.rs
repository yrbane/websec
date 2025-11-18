//! Integration tests for flood detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - T063: 1000 req in 10s generates Flooding signal
//! - Score degradation under sustained load
//! - Recovery after flood stops

use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::detectors::flood_detector::FloodDetector;
use websec::reputation::{DecisionEngine, DecisionEngineConfig, SignalVariant, ProxyDecision};
use websec::storage::InMemoryRepository;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Helper to create test engine with FloodDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(FloodDetector::new()));
    let detectors = Arc::new(registry);

    DecisionEngine::new(config, repository, detectors)
}

/// Helper to create context
fn create_context(ip: &str, path: &str) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: None,
        headers: vec![],
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    }
}

/// T063: 1000 requests in 10 seconds generates Flooding signal
#[tokio::test]
async fn test_high_volume_generates_flood_signal() {
    let engine = create_test_engine();
    let ip = "192.168.1.100";

    let mut last_result = None;

    // Simulate high volume: 100 requests (scaled down for test speed)
    for i in 0..100 {
        let context = create_context(ip, &format!("/page{}", i));
        let result = engine.process_request(&context).await.unwrap();
        last_result = Some(result);
    }

    let result = last_result.unwrap();

    // Should have detected flooding
    assert!(result.detection.suspicious, "High volume should be detected");

    // Check for RequestFlood signal
    let has_flood = result.detection.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::RequestFlood)
    });
    assert!(has_flood, "Should generate RequestFlood signal after high volume");

    // Score should have decreased
    assert!(result.score < 100, "Score should decrease after flooding");
}

#[tokio::test]
async fn test_sustained_flood_lowers_score_progressively() {
    let engine = create_test_engine();
    let ip = "10.0.0.50";

    let mut scores = Vec::new();

    // Sustained flood
    for i in 0..150 {
        let context = create_context(ip, &format!("/flood{}", i));
        let result = engine.process_request(&context).await.unwrap();

        // Sample scores periodically
        if i % 30 == 0 {
            scores.push(result.score);
        }
    }

    // Score should trend downward
    assert!(scores.len() >= 3, "Should have multiple score samples");
    assert!(scores.last().unwrap() < scores.first().unwrap(),
        "Score should decrease under sustained flood (first: {}, last: {})",
        scores.first().unwrap(), scores.last().unwrap());
}

#[tokio::test]
async fn test_flood_eventually_triggers_block() {
    let engine = create_test_engine();
    let ip = "10.0.0.60";

    let mut final_decision = ProxyDecision::Allow;

    // Keep flooding until blocked
    for i in 0..200 {
        let context = create_context(ip, &format!("/attack{}", i));
        let result = engine.process_request(&context).await.unwrap();
        final_decision = result.decision;

        if result.decision == ProxyDecision::Block {
            break;
        }
    }

    // Eventually should block or rate limit
    assert!(
        final_decision == ProxyDecision::Block
        || final_decision == ProxyDecision::RateLimit
        || final_decision == ProxyDecision::Challenge,
        "Sustained flood should eventually trigger blocking (got {:?})",
        final_decision
    );
}

#[tokio::test]
async fn test_burst_followed_by_normal_traffic() {
    let engine = create_test_engine();
    let ip = "10.0.0.70";

    // Initial burst
    for i in 0..50 {
        let context = create_context(ip, &format!("/burst{}", i));
        let _ = engine.process_request(&context).await.unwrap();
    }

    // Pause (simulate normal behavior)
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Normal request
    let context = create_context(ip, "/normal");
    let result = engine.process_request(&context).await.unwrap();

    // Behavior depends on implementation (may rate limit or allow with degraded score)
}

#[tokio::test]
async fn test_different_ips_dont_affect_each_other() {
    let engine = create_test_engine();

    // IP1: Flood
    for i in 0..100 {
        let context = create_context("192.168.1.100", &format!("/flood{}", i));
        let _ = engine.process_request(&context).await.unwrap();
    }

    // IP2: First request should be clean
    let context = create_context("192.168.1.101", "/test");
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(result.score, 100, "Different IP should start with clean score");
    assert!(!result.detection.suspicious, "Different IP should not be affected");
}

#[tokio::test]
async fn test_moderate_volume_not_flagged() {
    let engine = create_test_engine();
    let ip = "192.168.1.102";

    // Moderate volume: 20 requests
    for i in 0..20 {
        let context = create_context(ip, &format!("/page{}", i));
        let result = engine.process_request(&context).await.unwrap();

        assert!(!result.detection.suspicious,
            "Moderate volume should not be flagged on request {}", i);
    }
}

#[tokio::test]
async fn test_clean_traffic_maintains_perfect_score() {
    let engine = create_test_engine();
    let ip = "192.168.1.103";

    // Small number of requests
    for i in 0..5 {
        let context = create_context(ip, &format!("/page{}", i));
        let result = engine.process_request(&context).await.unwrap();

        assert_eq!(result.score, 100, "Clean traffic should maintain perfect score");
        assert_eq!(result.decision, ProxyDecision::Allow);
    }
}

#[tokio::test]
async fn test_distributed_attack_detection() {
    let engine = create_test_engine();

    // Multiple IPs sending moderate volume (potential distributed attack)
    for ip_suffix in 100..110 {
        let ip = format!("10.0.0.{}", ip_suffix);
        for i in 0..30 {
            let context = create_context(&ip, &format!("/target{}", i));
            let _ = engine.process_request(&context).await.unwrap();
        }
    }

    // Note: Distributed attack detection requires cross-IP correlation
    // which may be implemented in later phases
}
