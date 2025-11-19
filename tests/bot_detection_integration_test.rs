//! Integration tests for bot detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - T028: sqlmap User-Agent generates VulnerabilityScan signal
//! - T029: 100 requests without assets generates AbusiveClient signal

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::bot_detector::BotDetector;
use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::reputation::{DecisionEngine, DecisionEngineConfig, ProxyDecision, SignalVariant};
use websec::storage::InMemoryRepository;

/// Helper to create test engine with BotDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(BotDetector::new()));
    let detectors = Arc::new(registry);

    DecisionEngine::new(config, repository, detectors)
}

/// Helper to create HTTP context
fn create_context(ip: &str, path: &str, user_agent: Option<&str>) -> HttpRequestContext {
    let headers = if let Some(ua) = user_agent {
        vec![("User-Agent".to_string(), ua.to_string())]
    } else {
        vec![]
    };

    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: None,
        headers: headers.clone(),
        body: None,
        user_agent: user_agent.map(String::from),
        referer: None,
        content_type: None,
    }
}

/// T028: Integration test - sqlmap generates VulnerabilityScan signal
#[tokio::test]
async fn test_sqlmap_user_agent_generates_vulnerability_scan_signal() {
    let engine = create_test_engine();

    let context = create_context(
        "192.168.1.100",
        "/admin/login.php",
        Some("sqlmap/1.4.7#stable (http://sqlmap.org)"),
    );

    let result = engine.process_request(&context).await.unwrap();

    // Verify detection occurred
    assert!(
        result.detection.suspicious,
        "sqlmap should be detected as suspicious"
    );

    // Verify VulnerabilityScan signal was generated
    let has_vuln_scan = result
        .detection
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::VulnerabilityScan));
    assert!(
        has_vuln_scan,
        "Should generate VulnerabilityScan signal for sqlmap"
    );

    // Verify score was lowered
    assert!(
        result.score < 100,
        "Reputation score should decrease from base 100"
    );

    // Verify decision based on score
    // With weight 25 for VulnerabilityScan, score should be ~75 (ALLOW or RATE_LIMIT)
    assert!(
        result.decision == ProxyDecision::Allow || result.decision == ProxyDecision::RateLimit,
        "Decision should be ALLOW or RATE_LIMIT for first offense"
    );
}

/// T028 variant: Multiple scanner tools
#[tokio::test]
async fn test_nikto_generates_vulnerability_scan_signal() {
    let engine = create_test_engine();

    let context = create_context(
        "10.0.0.50",
        "/cgi-bin/test.cgi",
        Some("Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"),
    );

    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious);

    let has_vuln_scan = result
        .detection
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::VulnerabilityScan));
    assert!(has_vuln_scan, "Nikto should generate VulnerabilityScan");
}

#[tokio::test]
async fn test_nmap_generates_vulnerability_scan_signal() {
    let engine = create_test_engine();

    let context = create_context(
        "10.0.0.60",
        "/",
        Some("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"),
    );

    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious);

    let has_vuln_scan = result
        .detection
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::VulnerabilityScan));
    assert!(has_vuln_scan, "Nmap should generate VulnerabilityScan");
}

/// T028: curl should generate SuspiciousUserAgent (not VulnerabilityScan)
#[tokio::test]
async fn test_curl_generates_suspicious_user_agent_signal() {
    let engine = create_test_engine();

    let context = create_context("192.168.1.110", "/api/users", Some("curl/7.68.0"));

    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious);

    let has_suspicious_ua = result
        .detection
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::SuspiciousUserAgent));
    assert!(
        has_suspicious_ua,
        "curl should generate SuspiciousUserAgent signal"
    );

    // curl is less severe than scanners
    assert!(
        result.score >= 80,
        "curl should result in minor penalty (~10 points)"
    );
}

/// T029: Integration test - 100 requests without assets generates AbusiveClient
///
/// This test simulates a scraper making many requests to content pages
/// without requesting any assets (CSS, JS, images) like a real browser would.
///
/// NOTE: This requires advanced pattern analysis (T033) - implementing request history tracking
/// Ignored for now as it's a Phase 3+ enhancement
#[tokio::test]
#[ignore = "Requires advanced pattern analysis (T033) - request history tracking"]
async fn test_many_requests_without_assets_generates_abusive_client() {
    let engine = create_test_engine();
    let ip = "203.0.113.50";

    // Simulate 100 requests to HTML pages (no CSS/JS/images)
    for i in 0..100 {
        let context = create_context(
            ip,
            &format!("/page{}.html", i),
            Some("Mozilla/5.0"), // Generic UA
        );

        let _ = engine.process_request(&context).await.unwrap();
    }

    // After 100 requests, BotDetector should recognize the pattern
    // and generate AbusiveClient signal

    // Make one more request to check final state
    let context = create_context(ip, "/page101.html", Some("Mozilla/5.0"));

    let result = engine.process_request(&context).await.unwrap();

    // Check if AbusiveClient signal was generated at some point
    // This requires BotDetector to track request patterns in ReputationProfile
    let has_abusive_client = result
        .detection
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::AbusiveClient));

    // Note: This test might need adjustment based on implementation
    // BotDetector needs access to profile history to detect this pattern
    assert!(
        has_abusive_client || result.score < 70,
        "After 100 requests without assets, should flag AbusiveClient or lower score significantly"
    );
}

/// T029 variant: Normal browsing pattern should NOT trigger AbusiveClient
#[tokio::test]
async fn test_normal_browsing_with_assets_not_abusive() {
    let engine = create_test_engine();
    let ip = "203.0.113.60";

    // Simulate normal browsing: page + assets
    let pages = vec![
        "/index.html",
        "/style.css",
        "/script.js",
        "/logo.png",
        "/about.html",
        "/main.css",
        "/app.js",
    ];

    for path in pages {
        let context = create_context(
            ip,
            path,
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"),
        );

        let _ = engine.process_request(&context).await.unwrap();
    }

    // Check final state
    let context = create_context(
        ip,
        "/contact.html",
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"),
    );

    let result = engine.process_request(&context).await.unwrap();

    // Should NOT have AbusiveClient signal
    let has_abusive_client = result
        .detection
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::AbusiveClient));

    assert!(
        !has_abusive_client,
        "Normal browsing should not trigger AbusiveClient"
    );
    assert!(
        result.score >= 90,
        "Normal browsing should maintain high score"
    );
}

/// Integration test: Legitimate browser should pass through
#[tokio::test]
async fn test_legitimate_browser_chrome_allows() {
    let engine = create_test_engine();

    let context = create_context(
        "192.168.1.200",
        "/index.html",
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124"),
    );

    let result = engine.process_request(&context).await.unwrap();

    assert!(!result.detection.suspicious, "Chrome should not be flagged");
    assert!(
        result.detection.signals.is_empty(),
        "No signals for legitimate browser"
    );
    assert_eq!(result.score, 100, "Score should remain at 100");
    assert_eq!(
        result.decision,
        ProxyDecision::Allow,
        "Should ALLOW legitimate traffic"
    );
}

/// Integration test: Repeated attacks lower score progressively
#[tokio::test]
async fn test_repeated_bot_attacks_lower_score() {
    let engine = create_test_engine();
    let ip = "10.0.0.100";

    let mut scores = Vec::new();

    // Make 10 requests with sqlmap User-Agent
    for _ in 0..10 {
        let context = create_context(ip, "/admin", Some("sqlmap/1.0"));

        let result = engine.process_request(&context).await.unwrap();
        scores.push(result.score);
    }

    // Verify score decreases over time
    assert!(scores[0] < 100, "First attack should lower score");
    assert!(
        scores[9] < scores[0],
        "Score should continue decreasing with repeated attacks"
    );

    // Eventually should reach BLOCK threshold
    assert!(
        scores[9] < 70,
        "After 10 attacks, score should be in RATE_LIMIT or lower range"
    );
}
