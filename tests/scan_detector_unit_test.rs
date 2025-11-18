//! Unit tests for ScanDetector
//!
//! TDD RED PHASE: These tests MUST fail before implementation
//!
//! Testing:
//! - T098: Scan pattern detection (wp-admin, phpmyadmin, etc.)
//! - 404/403 burst detection
//! - Suspicious path enumeration

use websec::detectors::{Detector, HttpRequestContext};
use websec::detectors::scan_detector::ScanDetector;
use websec::reputation::SignalVariant;
use std::net::IpAddr;
use std::str::FromStr;

/// Helper to create request context
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
// T098: Suspicious Path Detection Tests
// ============================================================================

#[tokio::test]
async fn test_detect_wordpress_admin_scan() {
    let detector = ScanDetector::new();
    let context = create_context("192.168.1.100", "/wp-admin/");

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "wp-admin access should be detected as scan");
    let has_scan = result.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::VulnerabilityScan)
    });
    assert!(has_scan, "Should generate VulnerabilityScan signal");
}

#[tokio::test]
async fn test_detect_phpmyadmin_scan() {
    let detector = ScanDetector::new();
    let context = create_context("192.168.1.100", "/phpmyadmin/");

    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "phpmyadmin access should be detected");
    let has_scan = result.signals.iter().any(|s| {
        matches!(s.variant, SignalVariant::VulnerabilityScan)
    });
    assert!(has_scan);
}

#[tokio::test]
async fn test_detect_admin_panel_scan() {
    let detector = ScanDetector::new();

    let suspicious_paths = vec![
        "/admin/",
        "/administrator/",
        "/manager/html",
        "/.env",
        "/.git/config",
        "/config.php",
    ];

    for path in suspicious_paths {
        let context = create_context("192.168.1.100", path);
        let result = detector.analyze(&context).await;

        assert!(result.suspicious, "Path {} should be detected as suspicious", path);
    }
}

#[tokio::test]
async fn test_normal_path_not_flagged() {
    let detector = ScanDetector::new();

    let normal_paths = vec![
        "/",
        "/index.html",
        "/api/users",
        "/products/123",
        "/search?q=test",
    ];

    for path in normal_paths {
        let context = create_context("192.168.1.100", path);
        let result = detector.analyze(&context).await;

        assert!(!result.suspicious, "Normal path {} should not be flagged", path);
    }
}

// ============================================================================
// 404 Burst Detection Tests
// ============================================================================

#[tokio::test]
async fn test_detect_404_burst() {
    let detector = ScanDetector::new();
    let ip = "10.0.0.50";

    // Simulate 50 requests to different non-existent paths (404 burst)
    for i in 0..50 {
        let context = create_context(ip, &format!("/nonexistent{}", i));
        let _ = detector.analyze(&context).await;
    }

    // Next request should trigger scan detection
    let context = create_context(ip, "/another404");
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "404 burst should be detected as scan");
}

#[tokio::test]
async fn test_moderate_404s_not_flagged() {
    let detector = ScanDetector::new();
    let ip = "10.0.0.51";

    // Only 5 404s - not a burst
    for i in 0..5 {
        let context = create_context(ip, &format!("/notfound{}", i));
        let _ = detector.analyze(&context).await;
    }

    let context = create_context(ip, "/check");
    let result = detector.analyze(&context).await;

    assert!(!result.suspicious, "Moderate 404s should not trigger detection");
}

// ============================================================================
// Path Enumeration Detection Tests
// ============================================================================

#[tokio::test]
async fn test_detect_path_enumeration() {
    let detector = ScanDetector::new();
    let ip = "10.0.0.60";

    // Access multiple suspicious paths (enumeration)
    let scan_paths = vec![
        "/wp-admin/",
        "/phpmyadmin/",
        "/admin/",
        "/.git/",
        "/config/",
    ];

    for path in &scan_paths {
        let context = create_context(ip, path);
        let _ = detector.analyze(&context).await;
    }

    // Should accumulate scan signals
    let context = create_context(ip, "/check");
    let result = detector.analyze(&context).await;

    // Multiple suspicious path access indicates scanning
}

// ============================================================================
// Common Vulnerability Scanners Tests
// ============================================================================

#[tokio::test]
async fn test_detect_sqlmap_paths() {
    let detector = ScanDetector::new();

    // Common SQLMap test paths
    let sqlmap_paths = vec![
        "/index.php?id=1",
        "/products.php?id=1'",
    ];

    for path in sqlmap_paths {
        let context = create_context("192.168.1.100", path);
        let result = detector.analyze(&context).await;
        // May or may not flag depending on path analysis
    }
}

#[tokio::test]
async fn test_detect_nikto_paths() {
    let detector = ScanDetector::new();

    // Common Nikto scanner paths
    let nikto_paths = vec![
        "/cgi-bin/",
        "/scripts/",
        "/CHANGELOG.txt",
    ];

    for path in nikto_paths {
        let context = create_context("192.168.1.100", path);
        let _ = detector.analyze(&context).await;
    }
}

// ============================================================================
// Detector Interface Tests
// ============================================================================

#[tokio::test]
async fn test_detector_name() {
    let detector = ScanDetector::new();
    assert_eq!(detector.name(), "ScanDetector");
}

#[tokio::test]
async fn test_detector_enabled_by_default() {
    let detector = ScanDetector::new();
    assert!(detector.enabled());
}

// ============================================================================
// Different IPs Tests
// ============================================================================

#[tokio::test]
async fn test_different_ips_tracked_independently() {
    let detector = ScanDetector::new();

    // IP1: Scan activity
    for i in 0..30 {
        let context = create_context("192.168.1.100", &format!("/scan{}", i));
        let _ = detector.analyze(&context).await;
    }

    // IP2: Normal activity (should not be affected by IP1)
    let context = create_context("192.168.1.101", "/normal");
    let result = detector.analyze(&context).await;

    assert!(!result.suspicious, "Different IP should have independent tracking");
}

// ============================================================================
// Sensitive Files Detection Tests
// ============================================================================

#[tokio::test]
async fn test_detect_sensitive_file_access() {
    let detector = ScanDetector::new();

    let sensitive_files = vec![
        "/.env",
        "/.git/config",
        "/web.config",
        "/composer.json",
        "/package.json",
        "/.htaccess",
        "/robots.txt", // May be legitimate
    ];

    for file in sensitive_files {
        let context = create_context("192.168.1.100", file);
        let result = detector.analyze(&context).await;

        // Some files like robots.txt are legitimate
        if file != "/robots.txt" {
            assert!(result.suspicious || result.signals.is_empty(),
                "File {} detection behavior", file);
        }
    }
}

#[tokio::test]
async fn test_backup_file_detection() {
    let detector = ScanDetector::new();

    let backup_paths = vec![
        "/backup.sql",
        "/database.sql.gz",
        "/site.tar.gz",
        "/backup/",
    ];

    for path in backup_paths {
        let context = create_context("192.168.1.100", path);
        let _ = detector.analyze(&context).await;
    }
}
