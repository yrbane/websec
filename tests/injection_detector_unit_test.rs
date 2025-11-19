//! Unit tests for InjectionDetector
//!
//! TDD RED PHASE: These tests MUST fail before implementation
//!
//! Testing:
//! - T072: SQL injection pattern detection
//! - T073: XSS pattern detection
//! - T074: Command injection/RCE pattern detection

use std::net::IpAddr;
use std::str::FromStr;
use websec::detectors::injection_detector::InjectionDetector;
use websec::detectors::{Detector, HttpRequestContext};
use websec::reputation::SignalVariant;

/// Helper to create request context with query params
fn create_context_with_query(ip: &str, path: &str, query: &str) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: Some(query.to_string()),
        headers: vec![],
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    }
}

/// Helper to create POST request with body
fn create_context_with_body(ip: &str, path: &str, body: &str) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "POST".to_string(),
        path: path.to_string(),
        query: None,
        headers: vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: Some(body.as_bytes().to_vec()),
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: Some("application/x-www-form-urlencoded".to_string()),
    }
}

// ============================================================================
// T072: SQL Injection Detection Tests
// ============================================================================

#[tokio::test]
async fn test_detect_sql_union_injection() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query(
        "192.168.1.100",
        "/api/users",
        "id=1 UNION SELECT password FROM users",
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "UNION SELECT should be detected as SQLi");
    let has_sqli = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::SqlInjectionAttempt));
    assert!(has_sqli, "Should generate SqlInjectionAttempt signal");
}

#[tokio::test]
async fn test_detect_sql_or_injection() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query("192.168.1.100", "/login", "username=admin' OR '1'='1");

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "OR '1'='1 should be detected");
    let has_sqli = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::SqlInjectionAttempt));
    assert!(has_sqli);
}

#[tokio::test]
async fn test_detect_sql_drop_table() {
    let detector = InjectionDetector::new();
    let context =
        create_context_with_query("192.168.1.100", "/api/delete", "id=1; DROP TABLE users--");

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "DROP TABLE should be detected");
    let has_sqli = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::SqlInjectionAttempt));
    assert!(has_sqli);
}

#[tokio::test]
async fn test_detect_sql_comment_injection() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query("192.168.1.100", "/search", "q=test'--");

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "SQL comment -- should be detected");
}

#[tokio::test]
async fn test_detect_sql_sleep_time_based() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query("192.168.1.100", "/api/check", "id=1 AND SLEEP(5)");

    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "SLEEP() time-based attack should be detected"
    );
}

#[tokio::test]
async fn test_sql_in_post_body() {
    let detector = InjectionDetector::new();
    let context = create_context_with_body(
        "192.168.1.100",
        "/api/update",
        "name=John&email=test@example.com' OR 1=1--",
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "SQLi in POST body should be detected");
}

// ============================================================================
// T073: XSS Detection Tests
// ============================================================================

#[tokio::test]
async fn test_detect_xss_script_tag() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query(
        "192.168.1.100",
        "/search",
        "q=<script>alert('XSS')</script>",
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "<script> tag should be detected as XSS");
    let has_xss = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::XssAttempt));
    assert!(has_xss, "Should generate XssAttempt signal");
}

#[tokio::test]
async fn test_detect_xss_onerror() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query(
        "192.168.1.100",
        "/profile",
        "name=<img src=x onerror=alert(1)>",
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "onerror event should be detected");
    let has_xss = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::XssAttempt));
    assert!(has_xss);
}

#[tokio::test]
async fn test_detect_xss_javascript_protocol() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query(
        "192.168.1.100",
        "/redirect",
        "url=javascript:alert(document.cookie)",
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "javascript: protocol should be detected");
}

#[tokio::test]
async fn test_detect_xss_iframe() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query(
        "192.168.1.100",
        "/comment",
        "text=<iframe src='http://evil.com'></iframe>",
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "iframe injection should be detected");
}

#[tokio::test]
async fn test_detect_xss_onload() {
    let detector = InjectionDetector::new();
    let context =
        create_context_with_query("192.168.1.100", "/form", "data=<body onload=alert(1)>");

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "onload event should be detected");
}

// ============================================================================
// T074: Command Injection / RCE Detection Tests
// ============================================================================

#[tokio::test]
async fn test_detect_command_injection_pipe() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query(
        "192.168.1.100",
        "/api/ping",
        "host=127.0.0.1; cat /etc/passwd",
    );

    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "Command injection with ; should be detected"
    );
}

#[tokio::test]
async fn test_detect_command_injection_backticks() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query("192.168.1.100", "/api/exec", "cmd=`whoami`");

    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "Backtick command substitution should be detected"
    );
}

#[tokio::test]
async fn test_detect_path_traversal() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query("192.168.1.100", "/api/file", "path=../../etc/passwd");

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Path traversal should be detected");
    let has_traversal = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::PathTraversalAttempt));
    assert!(has_traversal, "Should generate PathTraversalAttempt signal");
}

#[tokio::test]
async fn test_detect_path_traversal_encoded() {
    let detector = InjectionDetector::new();
    let context = create_context_with_query(
        "192.168.1.100",
        "/download",
        "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    );

    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "URL-encoded path traversal should be detected"
    );
}

// ============================================================================
// Clean Traffic Tests
// ============================================================================

#[tokio::test]
async fn test_clean_query_not_flagged() {
    let detector = InjectionDetector::new();
    let context =
        create_context_with_query("192.168.1.100", "/search", "q=hello world&category=books");

    let result = detector.analyze(&context).await;

    assert!(!result.suspicious, "Clean query should not be flagged");
    assert!(result.signals.is_empty());
}

#[tokio::test]
async fn test_clean_post_body_not_flagged() {
    let detector = InjectionDetector::new();
    let context = create_context_with_body(
        "192.168.1.100",
        "/api/user",
        "name=John Doe&email=john@example.com&age=30",
    );

    let result = detector.analyze(&context).await;

    assert!(!result.suspicious);
    assert!(result.signals.is_empty());
}

#[tokio::test]
async fn test_detector_name() {
    let detector = InjectionDetector::new();
    assert_eq!(detector.name(), "InjectionDetector");
}

#[tokio::test]
async fn test_detector_enabled_by_default() {
    let detector = InjectionDetector::new();
    assert!(detector.enabled());
}
