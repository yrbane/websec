//! Unit tests for ProtocolDetector
//!
//! TDD RED PHASE: Tests written BEFORE implementation
//!
//! Testing:
//! - Invalid HTTP methods
//! - Malformed request paths
//! - Missing required HTTP/1.1 headers
//! - Invalid HTTP versions
//! - Oversized request lines

use std::net::IpAddr;
use std::str::FromStr;
use websec::detectors::protocol_detector::ProtocolDetector;
use websec::detectors::{Detector, HttpRequestContext};
use websec::reputation::SignalVariant;

/// Helper to create test context
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
async fn test_invalid_http_method() {
    let detector = ProtocolDetector::new();

    // Invalid HTTP method
    let context = create_context("192.168.1.1", "HACK", "/", vec![]);
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Should detect invalid HTTP method");
    assert!(
        result
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::InvalidHttpMethod)),
        "Should generate InvalidHttpMethod signal"
    );
}

#[tokio::test]
async fn test_valid_http_methods() {
    let detector = ProtocolDetector::new();

    let valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
    let headers = vec![("Host".to_string(), "example.com".to_string())];

    for method in &valid_methods {
        let context = create_context("192.168.1.1", method, "/", headers.clone());
        let result = detector.analyze(&context).await;

        assert!(
            !result.suspicious,
            "Valid method {} should not be flagged",
            method
        );
    }
}

#[tokio::test]
async fn test_malformed_path() {
    let detector = ProtocolDetector::new();

    // Path with null bytes
    let context = create_context("192.168.1.1", "GET", "/path\0malicious", vec![]);
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Should detect null byte in path");
    assert!(
        result
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::MalformedRequest)),
        "Should generate MalformedRequest signal"
    );
}

#[tokio::test]
async fn test_path_with_control_characters() {
    let detector = ProtocolDetector::new();

    // Path with control characters
    let context = create_context("192.168.1.1", "GET", "/path\r\nmalicious", vec![]);
    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "Should detect control characters in path"
    );
}

#[tokio::test]
async fn test_oversized_path() {
    let detector = ProtocolDetector::new();

    // Path exceeding reasonable length (8KB)
    let long_path = format!("/{}", "a".repeat(10000));
    let context = create_context("192.168.1.1", "GET", &long_path, vec![]);
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Should detect oversized path");
}

#[tokio::test]
async fn test_missing_host_header_http11() {
    let detector = ProtocolDetector::new();

    // Host header check is now skipped to avoid HTTP/2 false positives.
    // hyper/axum already enforces Host for HTTP/1.1 before reaching detectors.
    let context = create_context("192.168.1.1", "GET", "/", vec![]);
    let result = detector.analyze(&context).await;

    assert!(
        !result.suspicious,
        "Missing Host should not be flagged (handled by hyper, HTTP/2 compatible)"
    );
}

#[tokio::test]
async fn test_valid_request_with_host() {
    let detector = ProtocolDetector::new();

    let headers = vec![("Host".to_string(), "example.com".to_string())];
    let context = create_context("192.168.1.1", "GET", "/", headers);
    let result = detector.analyze(&context).await;

    assert!(!result.suspicious, "Valid request should not be flagged");
    assert!(result.signals.is_empty());
}

#[tokio::test]
async fn test_protocol_violation_weight() {
    let detector = ProtocolDetector::new();

    let context = create_context("192.168.1.1", "INVALID", "/", vec![]);
    let result = detector.analyze(&context).await;

    if let Some(signal) = result
        .signals
        .iter()
        .find(|s| matches!(s.variant, SignalVariant::InvalidHttpMethod))
    {
        assert_eq!(signal.weight, 15, "InvalidHttpMethod should have weight 15");
    }
}

#[tokio::test]
async fn test_space_in_method() {
    let detector = ProtocolDetector::new();

    // Method with space (smuggling attempt)
    let context = create_context("192.168.1.1", "GET ", "/", vec![]);
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Should detect space in method");
}

#[tokio::test]
async fn test_lowercase_method() {
    let detector = ProtocolDetector::new();

    // Methods should be uppercase per RFC
    let context = create_context("192.168.1.1", "get", "/", vec![]);
    let result = detector.analyze(&context).await;

    // Some implementations may be lenient, but we flag it
    assert!(result.suspicious, "Should flag lowercase method");
}

#[tokio::test]
async fn test_path_without_leading_slash() {
    let detector = ProtocolDetector::new();

    // Path must start with /
    let context = create_context("192.168.1.1", "GET", "no-slash", vec![]);
    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "Path without leading / should be flagged"
    );
}

#[tokio::test]
async fn test_multiple_violations() {
    let detector = ProtocolDetector::new();

    // Multiple violations: invalid method + malformed path
    let context = create_context("192.168.1.1", "HACK", "/\0evil", vec![]);
    let result = detector.analyze(&context).await;

    assert!(result.suspicious);
    assert!(
        !result.signals.is_empty(),
        "Should generate multiple signals"
    );
}

#[tokio::test]
async fn test_concurrent_analysis() {
    let detector = ProtocolDetector::new();

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let detector = detector.clone();
            tokio::spawn(async move {
                let method = if i % 2 == 0 { "GET" } else { "POST" };
                let context = create_context(
                    "192.168.1.1",
                    method,
                    "/",
                    vec![("Host".to_string(), "example.com".to_string())],
                );
                detector.analyze(&context).await
            })
        })
        .collect();

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(!result.suspicious, "Valid requests should not be flagged");
    }
}
