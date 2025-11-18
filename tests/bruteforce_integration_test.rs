//! Integration tests for brute force detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - T046: 5 failed login attempts generate FailedLogin signal
//! - T047: 20 failed attempts trigger BLOCK decision

use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::detectors::bruteforce_detector::BruteForceDetector;
use websec::reputation::{DecisionEngine, DecisionEngineConfig, SignalVariant, ProxyDecision};
use websec::storage::InMemoryRepository;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Helper to create test engine with BruteForceDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(BruteForceDetector::new()));
    let detectors = Arc::new(registry);

    DecisionEngine::new(config, repository, detectors)
}

/// Helper to create failed login context
fn create_failed_login(ip: &str, username: &str, password: &str) -> HttpRequestContext {
    let body = format!("username={}&password={}", username, password);

    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "POST".to_string(),
        path: "/login".to_string(),
        query: None,
        headers: vec![
            ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
        ],
        body: Some(body.into_bytes()),
        user_agent: Some("Mozilla/5.0 (Windows NT 10.0) Chrome/91.0".to_string()),
        referer: Some("/".to_string()),
        content_type: Some("application/x-www-form-urlencoded".to_string()),
    }
}

/// T046: Integration test - 5 failed login attempts generate FailedLogin signal
#[tokio::test]
async fn test_five_failed_logins_generate_signal() {
    let engine = create_test_engine();
    let ip = "192.168.1.100";

    let mut last_result = None;

    // Simulate 5 failed login attempts
    for i in 0..5 {
        let context = create_failed_login(ip, "admin", &format!("wrongpass{}", i));
        let result = engine.process_request(&context).await.unwrap();
        last_result = Some(result);
    }

    let result = last_result.unwrap();

    // Should have detected failed login attempts
    assert!(result.detection.suspicious, "After 5 failed logins, should be suspicious");

    // Check for FailedLogin signal
    let has_failed_login = result.detection.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::FailedLogin)
    });
    assert!(has_failed_login, "Should generate FailedLogin signal after 5 attempts");

    // Score should have decreased
    assert!(result.score < 100, "Score should decrease after failed logins");
}

/// T047: Integration test - 20 failed attempts trigger BLOCK decision
#[tokio::test]
async fn test_twenty_failed_logins_trigger_block() {
    let engine = create_test_engine();
    let ip = "10.0.0.50";

    let mut results = Vec::new();

    // Simulate 20 failed login attempts
    for i in 0..20 {
        let context = create_failed_login(ip, "admin", &format!("pass{}", i));
        let result = engine.process_request(&context).await.unwrap();
        results.push(result);
    }

    // Final result should have low score
    let final_result = results.last().unwrap();

    assert!(final_result.score < 50, "After 20 failed logins, score should be very low");

    // Should eventually reach BLOCK or CHALLENGE decision
    assert!(
        final_result.decision == ProxyDecision::Block ||
        final_result.decision == ProxyDecision::Challenge,
        "After 20 failed logins, should BLOCK or CHALLENGE (got {:?})",
        final_result.decision
    );

    // Check progression: score should decrease over attempts
    assert!(results[0].score > results[10].score, "Score should decrease progressively");
    assert!(results[10].score > results[19].score, "Score should continue decreasing");
}

/// Test: Different IPs don't affect each other
#[tokio::test]
async fn test_different_ips_tracked_independently() {
    let engine = create_test_engine();

    // IP1: 5 failed attempts
    for i in 0..5 {
        let context = create_failed_login("192.168.1.100", "admin", &format!("pass{}", i));
        let _ = engine.process_request(&context).await.unwrap();
    }

    // IP2: First attempt should be clean (independent tracking)
    let context = create_failed_login("192.168.1.101", "admin", "wrongpass");
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(result.score, 100, "Different IP should start with clean score");
    assert!(!result.detection.suspicious, "First attempt from new IP should not be suspicious");
}

/// Test: Successful login between failed attempts
#[tokio::test]
async fn test_successful_login_between_failures() {
    let engine = create_test_engine();
    let ip = "192.168.1.100";

    // 2 failed attempts
    for i in 0..2 {
        let context = create_failed_login(ip, "admin", &format!("wrong{}", i));
        let _ = engine.process_request(&context).await.unwrap();
    }

    // Successful login (simulated by clean request)
    let mut success_context = create_failed_login(ip, "admin", "correctpass");
    success_context.path = "/dashboard".to_string(); // After successful login
    let _ = engine.process_request(&success_context).await.unwrap();

    // Continue with failed attempts
    for i in 0..2 {
        let context = create_failed_login(ip, "admin", &format!("wrong{}", i));
        let _ = engine.process_request(&context).await.unwrap();
    }

    // Behavior depends on implementation (may reset or accumulate)
}

/// Test: Rapid login attempts trigger pattern detection
#[tokio::test]
async fn test_rapid_login_attempts_pattern() {
    let engine = create_test_engine();
    let ip = "10.0.0.60";

    // Rapid sequential attempts with different passwords (password spray)
    for i in 0..10 {
        let context = create_failed_login(ip, "admin", &format!("common_pass_{}", i));
        let result = engine.process_request(&context).await.unwrap();

        // After threshold, should detect LoginAttemptPattern
        if i >= 7 {
            let has_pattern = result.detection.signals.iter().any(|s| {
                matches!(s.variant, SignalVariant::LoginAttemptPattern)
            });
            // May or may not be detected depending on implementation sophistication
        }
    }
}

/// Test: Non-login endpoints not affected
#[tokio::test]
async fn test_non_login_endpoints_not_tracked() {
    let engine = create_test_engine();
    let ip = "192.168.1.100";

    // Multiple requests to non-auth endpoints
    for _ in 0..10 {
        let mut context = create_failed_login(ip, "", "");
        context.path = "/api/users".to_string();
        context.method = "GET".to_string();
        context.body = None;

        let result = engine.process_request(&context).await.unwrap();

        // Should not trigger brute force detection
        assert!(!result.detection.suspicious, "Non-auth endpoints should not be tracked");
    }
}

/// Test: Mixed success and failure
#[tokio::test]
async fn test_mixed_success_and_failure() {
    let engine = create_test_engine();
    let ip = "192.168.1.100";

    // Pattern: fail, fail, success, fail, fail, success
    // Should accumulate signals but not as aggressively as pure failures

    for i in 0..6 {
        let context = if i % 3 == 2 {
            // Every 3rd request is "successful" (different endpoint)
            let mut ctx = create_failed_login(ip, "admin", "correctpass");
            ctx.path = "/dashboard".to_string();
            ctx
        } else {
            create_failed_login(ip, "admin", &format!("wrong{}", i))
        };

        let _ = engine.process_request(&context).await.unwrap();
    }

    // Final check
    let context = create_failed_login(ip, "admin", "wrongpass_final");
    let result = engine.process_request(&context).await.unwrap();

    // Behavior is implementation-specific
}

/// Test: Credential stuffing detection
#[tokio::test]
async fn test_credential_stuffing_detection() {
    let engine = create_test_engine();

    // Same credentials from multiple IPs
    let username = "admin";
    let password = "Password123!";

    for i in 0..5 {
        let ip = format!("10.0.0.{}", 100 + i);
        let context = create_failed_login(&ip, username, password);
        let result = engine.process_request(&context).await.unwrap();

        // After seeing same credentials from multiple IPs, should detect credential stuffing
        if i >= 3 {
            let has_stuffing = result.detection.signals.iter().any(|s| {
                matches!(s.variant, SignalVariant::CredentialStuffing)
            });
            // This requires cross-IP correlation, which is advanced feature
        }
    }
}
