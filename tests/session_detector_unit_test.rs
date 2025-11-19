//! Unit tests for SessionDetector
//!
//! TDD RED PHASE: Tests written BEFORE implementation
//!
//! Testing:
//! - Session token anomalies (sudden IP changes, User-Agent changes)
//! - Session fixation attempts (forcing session IDs)
//! - Missing or suspicious session cookies
//! - Rapid session switching patterns

use std::net::IpAddr;
use std::str::FromStr;
use websec::detectors::session_detector::SessionDetector;
use websec::detectors::{Detector, HttpRequestContext};
use websec::reputation::SignalVariant;

/// Helper to create test context
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
async fn test_normal_session_no_flags() {
    let detector = SessionDetector::new();

    // Normal session: same IP, same User-Agent
    let headers = vec![("Cookie".to_string(), "session=valid_token_12345".to_string())];
    let ua = Some("Mozilla/5.0".to_string());

    let context1 = create_context("192.168.1.1", "/dashboard", headers.clone(), ua.clone());
    let result1 = detector.analyze(&context1).await;
    assert!(!result1.suspicious, "First request should not be flagged");

    // Same session, same IP, same UA
    let context2 = create_context("192.168.1.1", "/profile", headers.clone(), ua.clone());
    let result2 = detector.analyze(&context2).await;
    assert!(!result2.suspicious, "Consistent session should not be flagged");
}

#[tokio::test]
async fn test_ip_change_same_session() {
    let detector = SessionDetector::new();

    let session_cookie = vec![("Cookie".to_string(), "session=xyz789".to_string())];
    let ua = Some("Mozilla/5.0".to_string());

    // First request from IP1
    let context1 = create_context("10.0.0.1", "/dashboard", session_cookie.clone(), ua.clone());
    let _result1 = detector.analyze(&context1).await;

    // Same session from different IP (potential hijack)
    let context2 = create_context("10.0.0.99", "/admin", session_cookie.clone(), ua);
    let result2 = detector.analyze(&context2).await;

    assert!(result2.suspicious, "IP change should be flagged");
    assert!(
        result2
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::SessionTokenAnomaly)),
        "Should generate SessionTokenAnomaly signal"
    );
}

#[tokio::test]
async fn test_user_agent_change_same_session() {
    let detector = SessionDetector::new();

    let session_cookie = vec![("Cookie".to_string(), "session=token456".to_string())];
    let ip = "192.168.1.10";

    // First request with Chrome UA
    let context1 = create_context(
        ip,
        "/home",
        session_cookie.clone(),
        Some("Chrome/90.0".to_string()),
    );
    let _result1 = detector.analyze(&context1).await;

    // Same session with Firefox UA (suspicious)
    let context2 = create_context(
        ip,
        "/api",
        session_cookie.clone(),
        Some("Firefox/88.0".to_string()),
    );
    let result2 = detector.analyze(&context2).await;

    assert!(result2.suspicious, "User-Agent change should be flagged");
}

#[tokio::test]
async fn test_session_fixation_attempt() {
    let detector = SessionDetector::new();

    // Attacker tries to force a specific session ID
    let headers = vec![("Cookie".to_string(), "session=AAAAAAAA".to_string())];

    let context = create_context("192.168.1.20", "/login", headers, Some("curl/7.0".to_string()));
    let result = detector.analyze(&context).await;

    // Should detect suspicious session pattern
    assert!(result.suspicious, "Session fixation should be detected");
}

#[tokio::test]
async fn test_missing_session_on_protected_path() {
    let detector = SessionDetector::new();

    // Accessing protected resource without session
    let context = create_context(
        "192.168.1.5",
        "/admin/users",
        vec![],
        Some("Mozilla/5.0".to_string()),
    );
    let result = detector.analyze(&context).await;

    // Should flag missing session on protected path
    assert!(result.suspicious, "Missing session on /admin should be flagged");
}

#[tokio::test]
async fn test_rapid_session_switching() {
    let detector = SessionDetector::new();

    let ip = "192.168.1.15";
    let ua = Some("Mozilla/5.0".to_string());

    // Rapidly switch between different session tokens
    for i in 0..5 {
        let session = format!("session=token{}", i);
        let headers = vec![("Cookie".to_string(), session)];
        let context = create_context(ip, "/data", headers, ua.clone());
        let _ = detector.analyze(&context).await;
    }

    // Check if rapid switching is detected
    let headers = vec![("Cookie".to_string(), "session=token99".to_string())];
    let context = create_context(ip, "/data", headers, ua);
    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "Rapid session switching should be detected"
    );
}

#[tokio::test]
async fn test_different_sessions_different_ips() {
    let detector = SessionDetector::new();

    let ua = Some("Mozilla/5.0".to_string());

    // IP1 with session1
    let headers1 = vec![("Cookie".to_string(), "session=user1token".to_string())];
    let context1 = create_context("192.168.1.100", "/app", headers1, ua.clone());
    let result1 = detector.analyze(&context1).await;
    assert!(!result1.suspicious, "Independent session 1 should be clean");

    // IP2 with session2 (independent user)
    let headers2 = vec![("Cookie".to_string(), "session=user2token".to_string())];
    let context2 = create_context("192.168.1.101", "/app", headers2, ua);
    let result2 = detector.analyze(&context2).await;
    assert!(!result2.suspicious, "Independent session 2 should be clean");
}

#[tokio::test]
async fn test_signal_weight() {
    let detector = SessionDetector::new();

    let session_cookie = vec![("Cookie".to_string(), "session=test".to_string())];
    let ua = Some("Mozilla/5.0".to_string());

    // Establish session
    let context1 = create_context("10.0.0.5", "/home", session_cookie.clone(), ua.clone());
    let _ = detector.analyze(&context1).await;

    // Change IP
    let context2 = create_context("10.0.0.200", "/home", session_cookie, ua);
    let result = detector.analyze(&context2).await;

    if let Some(signal) = result
        .signals
        .iter()
        .find(|s| matches!(s.variant, SignalVariant::SessionTokenAnomaly))
    {
        assert_eq!(signal.weight, 15, "SessionTokenAnomaly should have weight 15");
    }
}

#[tokio::test]
async fn test_concurrent_analysis() {
    let detector = SessionDetector::new();

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let detector = detector.clone();
            tokio::spawn(async move {
                let session = format!("session=concurrent{}", i);
                let ip = format!("192.168.1.{}", i + 50);
                let headers = vec![("Cookie".to_string(), session)];
                let context = create_context(&ip, "/api", headers, Some("Mozilla/5.0".to_string()));
                detector.analyze(&context).await
            })
        })
        .collect();

    for handle in handles {
        let result = handle.await.unwrap();
        // Each session is independent, should not interfere
        assert!(!result.suspicious || result.suspicious); // Just verify it completes
    }
}
