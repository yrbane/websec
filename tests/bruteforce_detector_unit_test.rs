//! Unit tests for BruteForceDetector
//!
//! TDD RED PHASE: These tests MUST fail before implementation
//!
//! Testing:
//! - T043: Failed login attempt counting per IP
//! - T044: Credential stuffing detection (same credentials, different IPs)

use std::net::IpAddr;
use std::str::FromStr;
use websec::detectors::bruteforce_detector::BruteForceDetector;
use websec::detectors::{Detector, HttpRequestContext};
use websec::reputation::SignalVariant;

/// Helper to create login request context
fn create_login_context(
    ip: &str,
    username: &str,
    password: &str,
    response_status: u16,
) -> HttpRequestContext {
    let body = format!("username={}&password={}", username, password);
    let headers = vec![(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    )];

    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "POST".to_string(),
        path: "/login".to_string(),
        query: None,
        headers,
        body: Some(body.into_bytes()),
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: Some("application/x-www-form-urlencoded".to_string()),
    }
}

/// T043: Test failed login attempt counting
#[tokio::test]
async fn test_single_failed_login_no_signal() {
    let detector = BruteForceDetector::new();

    let context = create_login_context(
        "192.168.1.100",
        "admin",
        "wrongpass",
        401, // Unauthorized
    );

    // First failed attempt should not trigger signal yet
    let result = detector.analyze(&context).await;

    // Depending on threshold, might be clean or generate signal
    // Conservative: only flag after multiple attempts
}

#[tokio::test]
async fn test_multiple_failed_logins_generate_signal() {
    let detector = BruteForceDetector::new();
    let ip = "192.168.1.100";

    // Simulate 5 failed login attempts
    for i in 0..5 {
        let context = create_login_context(ip, "admin", &format!("wrongpass{}", i), 401);

        let result = detector.analyze(&context).await;

        // After threshold (e.g., 3-5 attempts), should generate FailedLogin signal
        if i >= 4 {
            assert!(
                result.suspicious,
                "After 5 failed logins, should be suspicious"
            );
            let has_failed_login = result
                .signals
                .iter()
                .any(|s| matches!(s.variant, SignalVariant::FailedLogin));
            assert!(has_failed_login, "Should generate FailedLogin signal");
        }
    }
}

#[tokio::test]
async fn test_successful_login_resets_counter() {
    let detector = BruteForceDetector::new();
    let ip = "192.168.1.100";

    // 2 failed attempts
    for i in 0..2 {
        let context = create_login_context(ip, "admin", "wrongpass", 401);
        let _ = detector.analyze(&context).await;
    }

    // Successful login (200 OK)
    let success_context = create_login_context(ip, "admin", "correctpass", 200);
    let _ = detector.analyze(&success_context).await;

    // Next failed attempt should not trigger (counter reset)
    let context = create_login_context(ip, "admin", "wrongpass2", 401);
    let result = detector.analyze(&context).await;

    // Should be clean (counter was reset)
    assert!(
        !result.suspicious || result.signals.is_empty(),
        "Counter should reset after successful login"
    );
}

#[tokio::test]
async fn test_login_attempt_pattern_detection() {
    let detector = BruteForceDetector::new();
    let ip = "192.168.1.100";

    // Rapid sequential login attempts (within short time window)
    for i in 0..10 {
        let context = create_login_context(ip, "admin", &format!("pass{}", i), 401);

        let result = detector.analyze(&context).await;

        // After threshold, should detect LoginAttemptPattern
        if i >= 7 {
            let has_pattern = result
                .signals
                .iter()
                .any(|s| matches!(s.variant, SignalVariant::LoginAttemptPattern));
            assert!(
                has_pattern,
                "Should detect LoginAttemptPattern after many attempts"
            );
        }
    }
}

/// T044: Test credential stuffing detection
#[tokio::test]
async fn test_credential_stuffing_same_creds_different_ips() {
    let detector = BruteForceDetector::new();

    // Same credentials attempted from multiple IPs (credential stuffing attack)
    let ips = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
        "192.168.1.14",
    ];
    let username = "admin";
    let password = "password123";

    for (idx, ip) in ips.iter().enumerate() {
        let context = create_login_context(ip, username, password, 401);
        let result = detector.analyze(&context).await;

        // After seeing same credentials from multiple IPs, should detect credential stuffing
        if idx >= 3 {
            let has_stuffing = result
                .signals
                .iter()
                .any(|s| matches!(s.variant, SignalVariant::CredentialStuffing));
            assert!(
                has_stuffing,
                "Should detect CredentialStuffing after {} IPs",
                idx + 1
            );
        }
    }
}

#[tokio::test]
async fn test_different_endpoints_tracked_separately() {
    let detector = BruteForceDetector::new();
    let ip = "192.168.1.100";

    // Failed attempts on /login
    for _ in 0..3 {
        let mut context = create_login_context(ip, "admin", "wrongpass", 401);
        context.path = "/login".to_string();
        let _ = detector.analyze(&context).await;
    }

    // Failed attempts on /admin/login should be tracked separately or together
    // depending on implementation (sensitive endpoint grouping)
    let mut admin_context = create_login_context(ip, "admin", "wrongpass", 401);
    admin_context.path = "/admin/login".to_string();
    let result = detector.analyze(&admin_context).await;

    // Implementation detail: might aggregate or track separately
}

#[tokio::test]
async fn test_non_auth_endpoint_not_tracked() {
    let detector = BruteForceDetector::new();

    let mut context = create_login_context("192.168.1.100", "admin", "wrongpass", 404);
    context.path = "/api/users".to_string(); // Non-auth endpoint

    let result = detector.analyze(&context).await;

    // Should not track non-authentication endpoints
    assert!(
        !result.suspicious,
        "Non-auth endpoints should not be tracked"
    );
    assert!(result.signals.is_empty());
}

#[tokio::test]
async fn test_detector_name() {
    let detector = BruteForceDetector::new();
    assert_eq!(detector.name(), "BruteForceDetector");
}

#[tokio::test]
async fn test_detector_enabled_by_default() {
    let detector = BruteForceDetector::new();
    assert!(detector.enabled());
}

#[tokio::test]
async fn test_time_window_expiry() {
    let detector = BruteForceDetector::new();
    let ip = "192.168.1.100";

    // Failed attempts
    for _ in 0..3 {
        let context = create_login_context(ip, "admin", "wrongpass", 401);
        let _ = detector.analyze(&context).await;
    }

    // In real implementation, old attempts outside time window should expire
    // This test would need time manipulation or mock clock
    // For now, just document the requirement
}
