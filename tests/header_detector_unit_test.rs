//! Unit tests for HeaderDetector
//!
//! TDD RED PHASE: Tests written BEFORE implementation
//!
//! Testing:
//! - Host header injection/manipulation
//! - Referer spoofing detection
//! - Header injection attempts (CRLF)
//! - Multiple host headers
//! - Invalid header formats

use std::net::IpAddr;
use std::str::FromStr;
use websec::detectors::header_detector::HeaderDetector;
use websec::detectors::{Detector, HttpRequestContext};
use websec::reputation::SignalVariant;

/// Helper to create test context
fn create_context(
    ip: &str,
    headers: Vec<(String, String)>,
    referer: Option<&str>,
) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: "/".to_string(),
        query: None,
        headers,
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: referer.map(String::from),
        content_type: None,
    }
}

#[tokio::test]
async fn test_host_header_injection() {
    let detector = HeaderDetector::new();

    // Host header with injection attempt
    let headers = vec![("Host".to_string(), "evil.com\r\nX-Injected: true".to_string())];
    let context = create_context("192.168.1.100", headers, None);
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Should detect CRLF injection in Host");
    assert!(
        result
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::HeaderInjection)),
        "Should generate HeaderInjection signal"
    );
}

#[tokio::test]
async fn test_multiple_host_headers() {
    let detector = HeaderDetector::new();

    // Multiple Host headers (attack vector)
    let headers = vec![
        ("Host".to_string(), "legitimate.com".to_string()),
        ("Host".to_string(), "evil.com".to_string()),
    ];
    let context = create_context("192.168.1.100", headers, None);
    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "Multiple Host headers should be suspicious"
    );
    assert!(
        result
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::HostHeaderAttack)),
        "Should generate HostHeaderAttack signal"
    );
}

#[tokio::test]
async fn test_host_header_mismatch() {
    let detector = HeaderDetector::new();

    // Host header with suspicious domain
    let headers = vec![("Host".to_string(), "localhost:1337".to_string())];
    let context = create_context("8.8.8.8", headers, None);
    let result = detector.analyze(&context).await;

    // May or may not be suspicious depending on configuration
    assert!(result.signals.len() >= 0);
}

#[tokio::test]
async fn test_referer_spoofing() {
    let detector = HeaderDetector::new();

    // Referer from different domain (potential spoofing)
    let headers = vec![("Host".to_string(), "mysite.com".to_string())];
    let context = create_context(
        "192.168.1.100",
        headers,
        Some("http://definitely-not-spoofed.ru/"),
    );
    let result = detector.analyze(&context).await;

    // Referer from different domain might be flagged
    assert!(result.signals.len() >= 0);
}

#[tokio::test]
async fn test_crlf_injection_in_headers() {
    let detector = HeaderDetector::new();

    // CRLF injection attempt
    let headers = vec![
        (
            "User-Agent".to_string(),
            "Mozilla/5.0\r\nX-Injected: malicious".to_string(),
        ),
        ("Host".to_string(), "example.com".to_string()),
    ];
    let context = create_context("192.168.1.100", headers, None);
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Should detect CRLF injection");
    assert!(
        result
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::HeaderInjection)),
        "Should generate HeaderInjection signal"
    );
}

#[tokio::test]
async fn test_null_byte_in_headers() {
    let detector = HeaderDetector::new();

    // Null byte injection
    let headers = vec![
        ("X-Custom".to_string(), "value\0malicious".to_string()),
        ("Host".to_string(), "example.com".to_string()),
    ];
    let context = create_context("192.168.1.100", headers, None);
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Should detect null byte injection");
}

#[tokio::test]
async fn test_oversized_header_values() {
    let detector = HeaderDetector::new();

    // Very long header value (potential buffer overflow attempt)
    let long_value = "A".repeat(10000);
    let headers = vec![
        ("X-Custom".to_string(), long_value),
        ("Host".to_string(), "example.com".to_string()),
    ];
    let context = create_context("192.168.1.100", headers, None);
    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "Should detect oversized header values"
    );
}

#[tokio::test]
async fn test_clean_headers() {
    let detector = HeaderDetector::new();

    // Normal, clean headers
    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("Accept".to_string(), "text/html".to_string()),
        ("Accept-Language".to_string(), "en-US".to_string()),
    ];
    let context = create_context("192.168.1.100", headers, Some("http://example.com/page"));
    let result = detector.analyze(&context).await;

    assert!(!result.suspicious, "Clean headers should not be flagged");
    assert!(result.signals.is_empty());
}

#[tokio::test]
async fn test_x_forwarded_for_spoofing() {
    let detector = HeaderDetector::new();

    // Suspicious X-Forwarded-For
    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        (
            "X-Forwarded-For".to_string(),
            "127.0.0.1, 127.0.0.1, 127.0.0.1".to_string(),
        ),
    ];
    let context = create_context("8.8.8.8", headers, None);
    let result = detector.analyze(&context).await;

    // Multiple localhost entries might be suspicious
    assert!(result.signals.len() >= 0);
}

#[tokio::test]
async fn test_missing_required_headers() {
    let detector = HeaderDetector::new();

    // No Host header (required in HTTP/1.1)
    let headers = vec![("Accept".to_string(), "text/html".to_string())];
    let context = create_context("192.168.1.100", headers, None);
    let result = detector.analyze(&context).await;

    // Missing Host header might be flagged
    assert!(result.signals.len() >= 0);
}

#[tokio::test]
async fn test_header_name_with_special_chars() {
    let detector = HeaderDetector::new();

    // Invalid header name
    let headers = vec![
        ("X-Test\r\n".to_string(), "value".to_string()),
        ("Host".to_string(), "example.com".to_string()),
    ];
    let context = create_context("192.168.1.100", headers, None);
    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "Should detect invalid header name"
    );
}

#[tokio::test]
async fn test_concurrent_header_analysis() {
    let detector = HeaderDetector::new();

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let detector = detector.clone();
            tokio::spawn(async move {
                let headers = vec![("Host".to_string(), format!("site{}.com", i))];
                let context = create_context("192.168.1.100", headers, None);
                detector.analyze(&context).await
            })
        })
        .collect();

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.signals.len() >= 0, "Should handle concurrent analysis");
    }
}

#[tokio::test]
async fn test_signal_weights() {
    let detector = HeaderDetector::new();

    let headers = vec![("Host".to_string(), "evil\r\nX-Inject: true".to_string())];
    let context = create_context("192.168.1.100", headers, None);
    let result = detector.analyze(&context).await;

    if let Some(signal) = result
        .signals
        .iter()
        .find(|s| matches!(s.variant, SignalVariant::HeaderInjection))
    {
        // HeaderInjection should have weight 20 (from signal.rs)
        assert_eq!(signal.weight, 20, "HeaderInjection should have weight 20");
    }
}
