//! Integration tests for injection detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - T075: SQL injection payload generates SqlInjectionAttempt signal
//! - XSS payload generates XssAttempt signal
//! - Path traversal generates PathTraversalAttempt signal

use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::detectors::injection_detector::InjectionDetector;
use websec::reputation::{DecisionEngine, DecisionEngineConfig, SignalVariant, ProxyDecision};
use websec::storage::InMemoryRepository;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Helper to create test engine with InjectionDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(InjectionDetector::new()));
    let detectors = Arc::new(registry);

    DecisionEngine::new(config, repository, detectors)
}

/// Helper to create context
fn create_context(ip: &str, path: &str, query: Option<&str>) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: query.map(String::from),
        headers: vec![],
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    }
}

/// T075: SQL injection generates SqlInjectionAttempt signal
#[tokio::test]
async fn test_sql_injection_generates_signal() {
    let engine = create_test_engine();

    let context = create_context(
        "192.168.1.100",
        "/api/users",
        Some("id=1' UNION SELECT password FROM users--")
    );

    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious, "SQL injection should be detected");

    let has_sqli = result.detection.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::SqlInjectionAttempt)
    });
    assert!(has_sqli, "Should generate SqlInjectionAttempt signal");

    // Score should decrease (SQLi has weight 30 - high severity)
    assert!(result.score < 100, "Score should decrease after SQLi detection");
    assert!(result.score <= 70, "SQLi should lower score significantly (weight 30)");
}

#[tokio::test]
async fn test_xss_injection_generates_signal() {
    let engine = create_test_engine();

    let context = create_context(
        "10.0.0.50",
        "/search",
        Some("q=<script>alert('XSS')</script>")
    );

    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious, "XSS should be detected");

    let has_xss = result.detection.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::XssAttempt)
    });
    assert!(has_xss, "Should generate XssAttempt signal");

    // XSS also has weight 30
    assert!(result.score <= 70, "XSS should lower score significantly");
}

#[tokio::test]
async fn test_path_traversal_generates_signal() {
    let engine = create_test_engine();

    let context = create_context(
        "10.0.0.60",
        "/api/file",
        Some("path=../../etc/passwd")
    );

    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious, "Path traversal should be detected");

    let has_traversal = result.detection.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::PathTraversalAttempt)
    });
    assert!(has_traversal, "Should generate PathTraversalAttempt signal");

    // PathTraversal also has weight 30
    assert!(result.score <= 70);
}

#[tokio::test]
async fn test_multiple_injection_attempts_lower_score() {
    let engine = create_test_engine();
    let ip = "192.168.1.200";

    // Multiple SQLi attempts
    let payloads = vec![
        "id=1' OR '1'='1",
        "id=1 UNION SELECT null",
        "id=1; DROP TABLE users--",
    ];

    let mut scores = Vec::new();

    for payload in payloads {
        let context = create_context(ip, "/api/query", Some(payload));
        let result = engine.process_request(&context).await.unwrap();
        scores.push(result.score);
    }

    // Score should progressively decrease
    assert!(scores[0] < 100, "First attack should lower score");
    assert!(scores[2] < scores[0], "Score should continue decreasing");

    // After 3 high-severity attacks (weight 30 each), should be in BLOCK range
    assert!(scores[2] < 40, "After multiple SQLi, should be in BLOCK/CHALLENGE range");
}

#[tokio::test]
async fn test_mixed_injection_types_correlation() {
    let engine = create_test_engine();
    let ip = "10.0.0.100";

    // SQLi attempt
    let context1 = create_context(ip, "/api/users", Some("id=1' OR 1=1--"));
    let result1 = engine.process_request(&context1).await.unwrap();

    // XSS attempt
    let context2 = create_context(ip, "/search", Some("q=<script>alert(1)</script>"));
    let _result2 = engine.process_request(&context2).await.unwrap();

    // Path traversal attempt
    let context3 = create_context(ip, "/file", Some("path=../../../etc/passwd"));
    let result3 = engine.process_request(&context3).await.unwrap();

    // Multiple attack families should trigger correlation bonus
    assert!(result3.score < result1.score, "Multiple attack types should accumulate");

    // With 3 different attack families + correlation bonus, should be very low
    assert!(result3.score < 50, "Multiple injection types should severely lower score");
}

#[tokio::test]
async fn test_clean_traffic_not_affected() {
    let engine = create_test_engine();

    let context = create_context(
        "192.168.1.250",
        "/search",
        Some("q=hello+world&category=books")
    );

    let result = engine.process_request(&context).await.unwrap();

    assert!(!result.detection.suspicious, "Clean query should not be flagged");
    assert!(result.detection.signals.is_empty());
    assert_eq!(result.score, 100, "Clean traffic should maintain perfect score");
    assert_eq!(result.decision, ProxyDecision::Allow);
}

#[tokio::test]
async fn test_encoded_injection_detected() {
    let engine = create_test_engine();

    // URL-encoded SQL injection
    let context = create_context(
        "10.0.0.70",
        "/api/search",
        Some("q=%27+UNION+SELECT+password+FROM+users--")
    );

    let result = engine.process_request(&context).await.unwrap();

    // URL decoding should happen before detection
    assert!(result.detection.suspicious, "URL-encoded SQLi should be detected after decoding");
}

#[tokio::test]
async fn test_repeated_injection_eventually_blocks() {
    let engine = create_test_engine();
    let ip = "10.0.0.80";

    let mut final_decision = ProxyDecision::Allow;

    // Keep attacking until blocked
    for i in 0..10 {
        let context = create_context(
            ip,
            "/api/query",
            Some(&format!("id={} UNION SELECT password", i))
        );

        let result = engine.process_request(&context).await.unwrap();
        final_decision = result.decision;

        if result.decision == ProxyDecision::Block {
            break;
        }
    }

    // Eventually should block
    assert!(
        final_decision == ProxyDecision::Block || final_decision == ProxyDecision::Challenge,
        "Repeated SQLi should eventually block (got {:?})",
        final_decision
    );
}
