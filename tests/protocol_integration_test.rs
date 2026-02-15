//! Integration tests for protocol violation detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - Protocol violations lower reputation score
//! - Repeated violations trigger blocking
//! - Valid requests maintain perfect score

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::protocol_detector::ProtocolDetector;
use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::reputation::{DecisionEngine, DecisionEngineConfig, ProxyDecision, SignalVariant};
use websec::storage::InMemoryRepository;

/// Helper to create test engine with ProtocolDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(ProtocolDetector::new()));
    let detectors = Arc::new(registry);

    DecisionEngine::new(config, repository, detectors)
}

/// Helper to create context
fn create_context(
    ip: &str,
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: method.to_string(),
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
async fn test_invalid_method_lowers_score() {
    let engine = create_test_engine();

    let context = create_context("192.168.1.1", "HACK", "/", vec![]);
    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious, "Should detect invalid method");
    assert!(result.score < 100, "Score should decrease");
}

#[tokio::test]
async fn test_valid_request_maintains_score() {
    let engine = create_test_engine();

    let headers = vec![("Host".to_string(), "example.com".to_string())];
    let context = create_context("192.168.1.1", "GET", "/index.html", headers);
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(result.score, 100, "Valid request should maintain score");
    assert_eq!(result.decision, ProxyDecision::Allow);
}

#[tokio::test]
async fn test_repeated_violations() {
    let engine = create_test_engine();
    let ip = "10.0.0.10";

    let mut final_score = 100;

    // Multiple protocol violations
    for i in 0..5 {
        let method = format!("HACK{}", i);
        let context = create_context(ip, &method, "/", vec![]);
        let result = engine.process_request(&context).await.unwrap();
        final_score = result.score;
    }

    assert!(
        final_score < 50,
        "Repeated violations should severely lower score"
    );
}

#[tokio::test]
async fn test_malformed_path_detection() {
    let engine = create_test_engine();

    let context = create_context("192.168.1.2", "GET", "/path\0malicious", vec![]);
    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious);
    assert!(result.score < 100);
}

#[tokio::test]
async fn test_missing_host_header() {
    let engine = create_test_engine();

    let context = create_context("192.168.1.3", "GET", "/", vec![]);
    let result = engine.process_request(&context).await.unwrap();

    // Host header check is now skipped to avoid HTTP/2 false positives
    // (hyper enforces Host for HTTP/1.1 before reaching detectors)
    assert!(!result.detection.suspicious);
}

#[tokio::test]
async fn test_different_ips_independent() {
    let engine = create_test_engine();

    // IP1: Protocol violation
    let context1 = create_context("192.168.1.10", "INVALID", "/", vec![]);
    let _result1 = engine.process_request(&context1).await.unwrap();

    // IP2: Valid request - should start fresh
    let headers = vec![("Host".to_string(), "example.com".to_string())];
    let context2 = create_context("192.168.1.11", "GET", "/", headers);
    let result2 = engine.process_request(&context2).await.unwrap();

    assert_eq!(result2.score, 100, "Different IP should be independent");
}

#[tokio::test]
async fn test_signal_metadata() {
    let engine = create_test_engine();

    let context = create_context("192.168.1.20", "HACK", "/", vec![]);
    let result = engine.process_request(&context).await.unwrap();

    if let Some(signal) = result
        .detection
        .signals
        .iter()
        .find(|s| matches!(s.variant, SignalVariant::InvalidHttpMethod))
    {
        assert!(signal.weight > 0);
        assert!(signal.context.is_some());
    }
}

#[tokio::test]
async fn test_multiple_valid_methods() {
    let engine = create_test_engine();

    let methods = ["GET", "POST", "PUT", "DELETE"];
    let headers = vec![("Host".to_string(), "api.example.com".to_string())];

    for method in &methods {
        let context = create_context("192.168.1.30", method, "/api/resource", headers.clone());
        let result = engine.process_request(&context).await.unwrap();

        assert_eq!(
            result.score, 100,
            "Valid method {} should maintain score",
            method
        );
    }
}
