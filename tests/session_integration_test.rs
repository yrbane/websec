//! Integration tests for session hijacking detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - Session anomalies lower reputation score
//! - Repeated session violations trigger blocking
//! - Normal session usage maintains score
//! - Multi-user independence

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::session_detector::SessionDetector;
use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::reputation::{DecisionEngine, DecisionEngineConfig, ProxyDecision};
use websec::storage::InMemoryRepository;

/// Helper to create test engine with SessionDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(SessionDetector::new()));
    let detectors = Arc::new(registry);

    DecisionEngine::new(config, repository, detectors)
}

/// Helper to create context
fn create_context(
    ip: &str,
    path: &str,
    headers: Vec<(String, String)>,
    user_agent: Option<String>,
) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: None,
        headers,
        body: None,
        user_agent,
        referer: None,
        content_type: None,
    }
}

#[tokio::test]
async fn test_session_anomaly_lowers_score() {
    let engine = create_test_engine();

    let session = vec![("Cookie".to_string(), "session=test123".to_string())];
    let ua = Some("Mozilla/5.0".to_string());

    // Establish session from IP1
    let context1 = create_context("192.168.1.1", "/home", session.clone(), ua.clone());
    let result1 = engine.process_request(&context1).await.unwrap();
    let initial_score = result1.score;

    // Same session from different IP (anomaly)
    let context2 = create_context("192.168.1.99", "/home", session, ua);
    let result2 = engine.process_request(&context2).await.unwrap();

    assert!(
        result2.detection.suspicious,
        "Should detect session anomaly"
    );
    assert!(result2.score < initial_score, "Score should decrease");
}

#[tokio::test]
async fn test_normal_session_maintains_score() {
    let engine = create_test_engine();

    let session = vec![("Cookie".to_string(), "session=valid_token".to_string())];
    let ua = Some("Mozilla/5.0".to_string());
    let ip = "192.168.1.5";

    // Multiple requests from same IP with same session
    for _ in 0..3 {
        let context = create_context(ip, "/dashboard", session.clone(), ua.clone());
        let result = engine.process_request(&context).await.unwrap();

        assert_eq!(result.score, 100, "Normal session should maintain score");
        assert_eq!(result.decision, ProxyDecision::Allow);
    }
}

#[tokio::test]
async fn test_repeated_session_violations() {
    let engine = create_test_engine();

    let session = vec![("Cookie".to_string(), "session=attacker_token".to_string())];
    let ua = Some("Mozilla/5.0".to_string());

    // Establish session from first IP
    let context1 = create_context("10.0.0.10", "/data", session.clone(), ua.clone());
    let result1 = engine.process_request(&context1).await.unwrap();
    let initial_score = result1.score;

    // Same session from multiple different IPs (hijacking)
    for i in 11..15 {
        let ip = format!("10.0.0.{}", i);
        let context = create_context(&ip, "/data", session.clone(), ua.clone());
        let _result = engine.process_request(&context).await.unwrap();
    }

    // Check the original IP's score after violations
    let context_final = create_context("10.0.0.10", "/data", session.clone(), ua.clone());
    let result_final = engine.process_request(&context_final).await.unwrap();

    assert!(
        result_final.score < initial_score,
        "IP that experienced session hijacking should have degraded score"
    );
}

#[tokio::test]
async fn test_user_agent_switch_detection() {
    let engine = create_test_engine();

    let session = vec![("Cookie".to_string(), "session=switch_token".to_string())];
    let ip = "192.168.1.20";

    // First request with Chrome
    let context1 = create_context(ip, "/home", session.clone(), Some("Chrome/90.0".to_string()));
    let _result1 = engine.process_request(&context1).await.unwrap();

    // Same session, same IP, but different UA
    let context2 = create_context(ip, "/api", session, Some("Firefox/88.0".to_string()));
    let result2 = engine.process_request(&context2).await.unwrap();

    assert!(result2.detection.suspicious, "UA switch should be detected");
    assert!(result2.score < 100, "Score should decrease on UA change");
}

#[tokio::test]
async fn test_different_users_independent() {
    let engine = create_test_engine();

    let ua = Some("Mozilla/5.0".to_string());

    // User 1: Normal session
    let session1 = vec![("Cookie".to_string(), "session=user1_token".to_string())];
    let context1 = create_context("192.168.1.10", "/app", session1, ua.clone());
    let result1 = engine.process_request(&context1).await.unwrap();

    // User 2: Normal session (independent)
    let session2 = vec![("Cookie".to_string(), "session=user2_token".to_string())];
    let context2 = create_context("192.168.1.11", "/app", session2, ua);
    let result2 = engine.process_request(&context2).await.unwrap();

    assert_eq!(result1.score, 100, "User 1 should have clean score");
    assert_eq!(result2.score, 100, "User 2 should have clean score");
}

#[tokio::test]
async fn test_missing_session_protected_path() {
    let engine = create_test_engine();

    let context = create_context(
        "192.168.1.30",
        "/admin/settings",
        vec![],
        Some("Mozilla/5.0".to_string()),
    );
    let result = engine.process_request(&context).await.unwrap();

    assert!(
        result.detection.suspicious,
        "Missing session on protected path should be flagged"
    );
}

#[tokio::test]
async fn test_rapid_session_switching() {
    let engine = create_test_engine();

    let ip = "192.168.1.40";
    let ua = Some("Mozilla/5.0".to_string());

    let mut final_score = 100;

    // Rapidly switch between different sessions
    for i in 0..10 {
        let session = vec![("Cookie".to_string(), format!("session=rapid_token{}", i))];
        let context = create_context(ip, "/data", session, ua.clone());
        let result = engine.process_request(&context).await.unwrap();
        final_score = result.score;
    }

    assert!(
        final_score < 80,
        "Rapid session switching should lower score"
    );
}
