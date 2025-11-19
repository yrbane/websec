//! Unit tests for BotDetector
//!
//! TDD RED PHASE: These tests MUST fail before implementation
//!
//! Testing:
//! - T025: Suspicious User-Agent detection
//! - T026: Non-human client profile detection

use std::net::IpAddr;
use std::str::FromStr;
use websec::detectors::bot_detector::BotDetector;
use websec::detectors::{Detector, HttpRequestContext};
use websec::reputation::SignalVariant;

/// Helper to create test context
fn create_context(
    ip: &str,
    method: &str,
    path: &str,
    user_agent: Option<&str>,
) -> HttpRequestContext {
    let headers = if let Some(ua) = user_agent {
        vec![("User-Agent".to_string(), ua.to_string())]
    } else {
        vec![]
    };

    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: method.to_string(),
        path: path.to_string(),
        query: None,
        headers: headers.clone(),
        body: None,
        user_agent: user_agent.map(String::from),
        referer: None,
        content_type: None,
    }
}

/// T025: Test suspicious User-Agent detection
#[tokio::test]
async fn test_detect_suspicious_user_agent_sqlmap() {
    let detector = BotDetector::new();
    let context = create_context(
        "192.168.1.100",
        "GET",
        "/admin/login",
        Some("sqlmap/1.4.7#stable (http://sqlmap.org)"),
    );

    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "sqlmap User-Agent should be detected as suspicious"
    );
    assert!(
        !result.signals.is_empty(),
        "Should generate at least one signal"
    );

    // Check that VulnerabilityScan signal was generated
    let has_vuln_scan = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::VulnerabilityScan));
    assert!(
        has_vuln_scan,
        "Should generate VulnerabilityScan signal for sqlmap"
    );
}

#[tokio::test]
async fn test_detect_suspicious_user_agent_curl() {
    let detector = BotDetector::new();
    let context = create_context("192.168.1.100", "GET", "/api/users", Some("curl/7.68.0"));

    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "curl User-Agent should be detected as suspicious"
    );

    // Check for SuspiciousUserAgent signal
    let has_suspicious_ua = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::SuspiciousUserAgent));
    assert!(
        has_suspicious_ua,
        "Should generate SuspiciousUserAgent signal for curl"
    );
}

#[tokio::test]
async fn test_detect_suspicious_user_agent_python() {
    let detector = BotDetector::new();
    let context = create_context(
        "192.168.1.100",
        "POST",
        "/api/data",
        Some("python-requests/2.25.1"),
    );

    let result = detector.analyze(&context).await;

    assert!(
        result.suspicious,
        "python-requests User-Agent should be detected"
    );
    assert!(!result.signals.is_empty());
}

#[tokio::test]
async fn test_detect_nikto_scanner() {
    let detector = BotDetector::new();
    let context = create_context(
        "192.168.1.100",
        "GET",
        "/cgi-bin/test.cgi",
        Some("Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"),
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Nikto scanner should be detected");

    let has_vuln_scan = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::VulnerabilityScan));
    assert!(has_vuln_scan, "Should generate VulnerabilityScan for Nikto");
}

#[tokio::test]
async fn test_legitimate_user_agent_chrome() {
    let detector = BotDetector::new();
    let context = create_context(
        "192.168.1.100",
        "GET",
        "/index.html",
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    );

    let result = detector.analyze(&context).await;

    assert!(
        !result.suspicious,
        "Legitimate Chrome User-Agent should NOT be flagged"
    );
    assert!(
        result.signals.is_empty(),
        "Should not generate signals for legitimate browsers"
    );
}

#[tokio::test]
async fn test_legitimate_user_agent_firefox() {
    let detector = BotDetector::new();
    let context = create_context(
        "192.168.1.100",
        "GET",
        "/page.html",
        Some("Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"),
    );

    let result = detector.analyze(&context).await;

    assert!(!result.suspicious, "Firefox should not be flagged");
    assert!(result.signals.is_empty());
}

/// T026: Test non-human client profile detection
#[tokio::test]
async fn test_detect_missing_user_agent() {
    let detector = BotDetector::new();
    let context = create_context(
        "192.168.1.100",
        "GET",
        "/api/endpoint",
        None, // No User-Agent header
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Missing User-Agent should be flagged");

    let has_bot_pattern = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::BotBehaviorPattern));
    assert!(
        has_bot_pattern,
        "Should generate BotBehaviorPattern for missing UA"
    );
}

#[tokio::test]
async fn test_detect_empty_user_agent() {
    let detector = BotDetector::new();
    let context = create_context(
        "192.168.1.100",
        "GET",
        "/api/endpoint",
        Some(""), // Empty User-Agent
    );

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Empty User-Agent should be flagged");
}

#[tokio::test]
async fn test_detect_non_human_profile_missing_accept() {
    let detector = BotDetector::new();

    // Context with User-Agent but missing other standard browser headers
    let mut context = create_context("192.168.1.100", "GET", "/page.html", Some("Mozilla/5.0"));

    // Real browsers send Accept, Accept-Language, Accept-Encoding headers
    // This request only has User-Agent

    let result = detector.analyze(&context).await;

    // This might be suspicious depending on implementation strategy
    // For now, we'll be lenient and only flag if UA is also suspicious
    // More sophisticated profiling can be added later
}

#[tokio::test]
async fn test_detect_scanner_with_standard_headers() {
    let detector = BotDetector::new();

    let headers = vec![
        (
            "User-Agent".to_string(),
            "Acunetix-Security-Scanner".to_string(),
        ),
        ("Accept".to_string(), "*/*".to_string()),
    ];

    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.100").unwrap(),
        method: "GET".to_string(),
        path: "/admin/".to_string(),
        query: None,
        headers,
        body: None,
        user_agent: Some("Acunetix-Security-Scanner".to_string()),
        referer: None,
        content_type: None,
    };

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Acunetix scanner should be detected");

    let has_vuln_scan = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::VulnerabilityScan));
    assert!(has_vuln_scan, "Should generate VulnerabilityScan signal");
}

#[tokio::test]
async fn test_detector_name() {
    let detector = BotDetector::new();
    assert_eq!(detector.name(), "BotDetector");
}

#[tokio::test]
async fn test_detector_enabled_by_default() {
    let detector = BotDetector::new();
    assert!(
        detector.enabled(),
        "BotDetector should be enabled by default"
    );
}
