//! Integration tests for header manipulation detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - Header injection lowers reputation score
//! - Multiple header attacks trigger blocking
//! - Clean headers maintain perfect score

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::header_detector::HeaderDetector;
use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::reputation::{DecisionEngine, DecisionEngineConfig, ProxyDecision, SignalVariant};
use websec::storage::InMemoryRepository;

/// Helper to create test engine with HeaderDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(HeaderDetector::new()));
    let detectors = Arc::new(registry);

    DecisionEngine::new(config, repository, detectors)
}

/// Helper to create context
fn create_context(
    ip: &str,
    path: &str,
    headers: Vec<(String, String)>,
) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: None,
        headers,
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    }
}

#[tokio::test]
async fn test_header_injection_lowers_score() {
    let engine = create_test_engine();

    let headers = vec![("Host".to_string(), "evil.com\r\nX-Injected: true".to_string())];
    let context = create_context("192.168.1.100", "/", headers);
    let result = engine.process_request(&context).await.unwrap();

    assert!(
        result.detection.suspicious,
        "Header injection should be detected"
    );
    assert!(
        result.score < 100,
        "Score should decrease after header injection"
    );

    let has_header_injection = result
        .detection
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::HeaderInjection));
    assert!(has_header_injection, "Should generate HeaderInjection signal");
}

#[tokio::test]
async fn test_multiple_host_headers_attack() {
    let engine = create_test_engine();

    let headers = vec![
        ("Host".to_string(), "legitimate.com".to_string()),
        ("Host".to_string(), "evil.com".to_string()),
    ];
    let context = create_context("10.0.0.50", "/", headers);
    let result = engine.process_request(&context).await.unwrap();

    assert!(
        result.detection.suspicious,
        "Multiple Host headers should be detected"
    );
    assert!(result.score < 100, "Score should decrease");
}

#[tokio::test]
async fn test_clean_headers_maintain_score() {
    let engine = create_test_engine();

    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("Accept".to_string(), "text/html".to_string()),
    ];
    let context = create_context("192.168.1.100", "/", headers);
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(
        result.score, 100,
        "Clean headers should maintain perfect score"
    );
    assert_eq!(result.decision, ProxyDecision::Allow);
}

#[tokio::test]
async fn test_repeated_header_attacks() {
    let engine = create_test_engine();
    let ip = "10.0.0.60";

    let mut final_score = 100;

    // Multiple header injection attempts
    for i in 0..5 {
        let headers = vec![(
            "Host".to_string(),
            format!("evil{}.com\r\nX-Injected: true", i),
        )];
        let context = create_context(ip, "/", headers);
        let result = engine.process_request(&context).await.unwrap();
        final_score = result.score;
    }

    assert!(
        final_score < 50,
        "Repeated attacks should severely lower score"
    );
}

#[tokio::test]
async fn test_header_injection_eventually_blocks() {
    let engine = create_test_engine();
    let ip = "10.0.0.70";

    let mut final_decision = ProxyDecision::Allow;

    // Keep attacking until blocked
    for i in 0..10 {
        let headers = vec![(
            "X-Custom".to_string(),
            format!("value\r\nX-Attack: {}", i),
        )];
        let context = create_context(ip, "/", headers);
        let result = engine.process_request(&context).await.unwrap();
        final_decision = result.decision;

        if result.decision == ProxyDecision::Block {
            break;
        }
    }

    assert!(
        final_decision == ProxyDecision::Block || final_decision == ProxyDecision::Challenge,
        "Repeated header attacks should eventually block"
    );
}

#[tokio::test]
async fn test_different_ips_independent() {
    let engine = create_test_engine();

    // IP1: Header injection
    let headers1 = vec![("Host".to_string(), "evil.com\r\nX-Inject: true".to_string())];
    let context1 = create_context("192.168.1.100", "/", headers1);
    let _result1 = engine.process_request(&context1).await.unwrap();

    // IP2: Clean - should start fresh
    let headers2 = vec![("Host".to_string(), "example.com".to_string())];
    let context2 = create_context("192.168.1.101", "/", headers2);
    let result2 = engine.process_request(&context2).await.unwrap();

    assert_eq!(
        result2.score, 100,
        "Different IP should have independent score"
    );
}

#[tokio::test]
async fn test_crlf_injection_signal() {
    let engine = create_test_engine();

    let headers = vec![
        (
            "User-Agent".to_string(),
            "Mozilla\r\nX-Injected: malicious".to_string(),
        ),
        ("Host".to_string(), "example.com".to_string()),
    ];
    let context = create_context("192.168.1.102", "/", headers);
    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious, "CRLF should be detected");
    assert!(
        result
            .detection
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::HeaderInjection)),
        "Should generate HeaderInjection signal"
    );
}

#[tokio::test]
async fn test_signal_metadata() {
    let engine = create_test_engine();

    let headers = vec![("Host".to_string(), "evil\r\nX-Inject: true".to_string())];
    let context = create_context("192.168.1.103", "/", headers);
    let result = engine.process_request(&context).await.unwrap();

    if let Some(signal) = result
        .detection
        .signals
        .iter()
        .find(|s| matches!(s.variant, SignalVariant::HeaderInjection))
    {
        assert!(signal.weight > 0, "Signal should have weight");
        assert!(
            signal.context.is_some(),
            "Should have context about the attack"
        );
    }
}
