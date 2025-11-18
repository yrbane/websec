//! Integration tests for vulnerability scan detection
//!
//! TDD RED PHASE: End-to-end tests with DecisionEngine
//!
//! Testing:
//! - T099: Rafale 404 génère signal VulnerabilityScan
//! - Score degradation with scan activity
//! - Multiple scan patterns correlation

use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::detectors::scan_detector::ScanDetector;
use websec::reputation::{DecisionEngine, DecisionEngineConfig, SignalVariant, ProxyDecision};
use websec::storage::InMemoryRepository;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Helper to create test engine with ScanDetector
fn create_test_engine() -> DecisionEngine {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(ScanDetector::new()));
    let detectors = Arc::new(registry);

    DecisionEngine::new(config, repository, detectors)
}

/// Helper to create context
fn create_context(ip: &str, path: &str) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: None,
        headers: vec![],
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    }
}

// ============================================================================
// T099: 404 Burst Generates VulnerabilityScan Signal
// ============================================================================

#[tokio::test]
async fn test_404_burst_generates_scan_signal() {
    let engine = create_test_engine();
    let ip = "192.168.1.100";

    let mut last_result = None;

    // Simulate 50 404s (path enumeration)
    for i in 0..50 {
        let context = create_context(ip, &format!("/nonexistent{}", i));
        let result = engine.process_request(&context).await.unwrap();
        last_result = Some(result);
    }

    let result = last_result.unwrap();

    // Should have detected scan activity
    assert!(result.detection.suspicious, "404 burst should be detected");

    // Check for VulnerabilityScan signal
    let has_scan = result.detection.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::VulnerabilityScan)
    });
    assert!(has_scan, "Should generate VulnerabilityScan signal after 404 burst");

    // Score should have decreased
    assert!(result.score < 100, "Score should decrease after scan detection");
}

#[tokio::test]
async fn test_suspicious_path_generates_scan_signal() {
    let engine = create_test_engine();
    let ip = "10.0.0.50";

    // Access suspicious admin path
    let context = create_context(ip, "/wp-admin/");
    let result = engine.process_request(&context).await.unwrap();

    assert!(result.detection.suspicious, "wp-admin access should be detected");

    let has_scan = result.detection.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::VulnerabilityScan)
    });
    assert!(has_scan, "Suspicious path should generate VulnerabilityScan signal");
}

#[tokio::test]
async fn test_multiple_scan_paths_lower_score() {
    let engine = create_test_engine();
    let ip = "10.0.0.60";

    let scan_paths = vec![
        "/wp-admin/",
        "/phpmyadmin/",
        "/admin/",
        "/.git/config",
        "/.env",
    ];

    let mut scores = Vec::new();

    for path in &scan_paths {
        let context = create_context(ip, path);
        let result = engine.process_request(&context).await.unwrap();
        scores.push(result.score);
    }

    // Score should decrease progressively
    assert!(scores.len() >= 3, "Should have multiple score samples");
    assert!(scores.last().unwrap() < scores.first().unwrap(),
        "Score should decrease with multiple scan attempts (first: {}, last: {})",
        scores.first().unwrap(), scores.last().unwrap());
}

#[tokio::test]
async fn test_scan_eventually_triggers_block() {
    let engine = create_test_engine();
    let ip = "10.0.0.70";

    let mut final_decision = ProxyDecision::Allow;

    // Aggressive scanning
    for i in 0..100 {
        let path = if i % 2 == 0 {
            format!("/wp-admin/page{}", i)
        } else {
            format!("/admin/test{}", i)
        };

        let context = create_context(ip, &path);
        let result = engine.process_request(&context).await.unwrap();
        final_decision = result.decision;

        if result.decision == ProxyDecision::Block {
            break;
        }
    }

    // Eventually should block or rate limit aggressive scanner
    assert!(
        final_decision == ProxyDecision::Block
        || final_decision == ProxyDecision::RateLimit
        || final_decision == ProxyDecision::Challenge,
        "Aggressive scanning should eventually trigger blocking (got {:?})",
        final_decision
    );
}

#[tokio::test]
async fn test_normal_paths_not_affected() {
    let engine = create_test_engine();
    let ip = "192.168.1.101";

    let normal_paths = vec![
        "/",
        "/index.html",
        "/api/users",
        "/products/123",
        "/about",
    ];

    for path in &normal_paths {
        let context = create_context(ip, path);
        let result = engine.process_request(&context).await.unwrap();

        assert!(!result.detection.suspicious,
            "Normal path {} should not be flagged", path);
        assert_eq!(result.score, 100, "Score should remain perfect for normal paths");
    }
}

#[tokio::test]
async fn test_different_ips_dont_affect_each_other() {
    let engine = create_test_engine();

    // IP1: Scanning
    for i in 0..30 {
        let context = create_context("192.168.1.100", &format!("/wp-admin/page{}", i));
        let _ = engine.process_request(&context).await.unwrap();
    }

    // IP2: First request should be clean
    let context = create_context("192.168.1.101", "/");
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(result.score, 100, "Different IP should start with clean score");
    assert!(!result.detection.suspicious, "Different IP should not be affected");
}

#[tokio::test]
async fn test_mixed_scan_and_normal_traffic() {
    let engine = create_test_engine();
    let ip = "10.0.0.80";

    // Mix of scan and normal requests
    let paths = vec![
        ("/", false),           // Normal
        ("/wp-admin/", true),   // Scan
        ("/index.html", false), // Normal
        ("/.git/config", true), // Scan
        ("/api/users", false),  // Normal
    ];

    for (path, is_scan) in paths {
        let context = create_context(ip, path);
        let result = engine.process_request(&context).await.unwrap();

        if is_scan {
            assert!(result.detection.suspicious,
                "Scan path {} should be detected", path);
        }
    }
}

#[tokio::test]
async fn test_scan_pattern_correlation() {
    let engine = create_test_engine();
    let ip = "10.0.0.90";

    // Access multiple types of suspicious paths (shows scanning behavior)
    let patterns = vec![
        "/wp-admin/",      // WordPress
        "/phpmyadmin/",    // Database
        "/.git/config",    // Source control
        "/.env",           // Config files
        "/admin/",         // Generic admin
    ];

    let mut final_result = None;

    for path in patterns {
        let context = create_context(ip, path);
        let result = engine.process_request(&context).await.unwrap();
        final_result = Some(result);
    }

    let result = final_result.unwrap();

    // Multiple different scan patterns indicate reconnaissance
    assert!(result.score < 100, "Multiple scan patterns should lower score");
}

#[tokio::test]
async fn test_legitimate_robots_txt_access() {
    let engine = create_test_engine();
    let ip = "192.168.1.102";

    // robots.txt is legitimate
    let context = create_context(ip, "/robots.txt");
    let result = engine.process_request(&context).await.unwrap();

    // Should not necessarily flag as suspicious (depends on implementation)
    // robots.txt is commonly accessed by legitimate crawlers
}
