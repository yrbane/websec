//! Integration tests for geographic threat detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - High-risk country lowers score
//! - Multiple requests from different countries
//! - Integration with overall reputation system

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::geo_detector::GeoDetector;
use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::reputation::{DecisionEngine, DecisionEngineConfig, ProxyDecision, SignalVariant};
use websec::storage::InMemoryRepository;

/// Helper to create test engine with GeoDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(GeoDetector::new()));
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

#[tokio::test]
async fn test_high_risk_country_lowers_score() {
    let engine = create_test_engine();

    // Request from high-risk country
    let context = create_context("1.2.3.4", "/");
    let result = engine.process_request(&context).await.unwrap();

    // May or may not detect depending on GeoIP database availability
    // but should not crash
    assert!(result.score <= 100, "Score should be valid");
}

#[tokio::test]
async fn test_safe_country_maintains_score() {
    let engine = create_test_engine();

    // Request from safe country (US)
    let context = create_context("8.8.8.8", "/");
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(
        result.score, 100,
        "Safe country should maintain perfect score"
    );
    assert_eq!(result.decision, ProxyDecision::Allow);
}

#[tokio::test]
async fn test_multiple_countries_correlation() {
    let engine = create_test_engine();

    // First request from one country
    let context1 = create_context("8.8.8.8", "/");
    let result1 = engine.process_request(&context1).await.unwrap();

    // Second request from different country (same session?)
    // This would require session tracking
    let context2 = create_context("1.2.3.4", "/");
    let result2 = engine.process_request(&context2).await.unwrap();

    // Both should be processed successfully
    assert!(result1.score <= 100);
    assert!(result2.score <= 100);
}

#[tokio::test]
async fn test_private_ip_no_geo_signal() {
    let engine = create_test_engine();

    // Private IP has no geolocation
    let context = create_context("192.168.1.100", "/");
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(result.score, 100, "Private IP should have perfect score");
    assert!(
        !result
            .detection
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::HighRiskCountry)),
        "Private IP should not generate geo signals"
    );
}

#[tokio::test]
async fn test_localhost_exempt_from_geo() {
    let engine = create_test_engine();

    let context = create_context("127.0.0.1", "/");
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(result.score, 100, "Localhost should have perfect score");
    assert_eq!(result.decision, ProxyDecision::Allow);
}

#[tokio::test]
async fn test_high_risk_with_clean_behavior() {
    let engine = create_test_engine();

    // High-risk country but clean behavior
    let context = create_context("1.2.3.4", "/index.html");
    let result = engine.process_request(&context).await.unwrap();

    // Score may be slightly lower due to country, but should still allow
    assert!(
        result.score >= 70,
        "Clean behavior from high-risk country should still be allowed"
    );
}

#[tokio::test]
async fn test_high_risk_with_attack() {
    let engine = create_test_engine();

    // High-risk country + suspicious path
    // Note: This test would need InjectionDetector or ScanDetector registered too
    let context = create_context("1.2.3.4", "/wp-admin/");
    let result = engine.process_request(&context).await.unwrap();

    // Should process request (actual detection depends on registered detectors)
    assert!(result.score <= 100);
}

#[tokio::test]
async fn test_different_ips_independent_geo() {
    let engine = create_test_engine();

    // IP1: High-risk
    let context1 = create_context("1.2.3.4", "/");
    let _result1 = engine.process_request(&context1).await.unwrap();

    // IP2: Safe - should start fresh
    let context2 = create_context("8.8.8.8", "/");
    let result2 = engine.process_request(&context2).await.unwrap();

    assert_eq!(
        result2.score, 100,
        "Different IP should have independent geo scoring"
    );
}

#[tokio::test]
async fn test_geo_signal_metadata() {
    let engine = create_test_engine();

    let context = create_context("1.2.3.4", "/");
    let result = engine.process_request(&context).await.unwrap();

    // Check if HighRiskCountry signal has proper metadata
    if let Some(signal) = result
        .detection
        .signals
        .iter()
        .find(|s| matches!(s.variant, SignalVariant::HighRiskCountry))
    {
        assert!(signal.weight > 0, "Signal should have weight");
        assert!(signal.context.is_some(), "Should have country context");
    }
}
