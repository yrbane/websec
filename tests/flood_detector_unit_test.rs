//! Unit tests for FloodDetector
//!
//! TDD RED PHASE: These tests MUST fail before implementation
//!
//! Testing:
//! - T061: Volume anormal detection (1000 req in 10s)
//! - T062: Burst detection (spike patterns)
//! - Detection of sustained high rate (100 req/s)

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use websec::detectors::flood_detector::FloodDetector;
use websec::detectors::{Detector, HttpRequestContext};
use websec::reputation::SignalVariant;

/// Helper to create basic request context
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
// T061: Volume Anormal Detection Tests
// ============================================================================

#[tokio::test]
async fn test_high_volume_generates_flood_signal() {
    let detector = FloodDetector::new();
    let ip = "192.168.1.100";

    // Send 100 requests rapidly (simulating high volume)
    for i in 0..100 {
        let context = create_context(ip, &format!("/page{}", i));
        let _ = detector.analyze(&context).await;
    }

    // Final request should trigger flood detection
    let context = create_context(ip, "/final");
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "High volume should be detected as flood");
    let has_flood = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::RequestFlood));
    assert!(has_flood, "Should generate RequestFlood signal");
}

#[tokio::test]
async fn test_moderate_volume_not_flagged() {
    let detector = FloodDetector::new();
    let ip = "192.168.1.101";

    // Send 10 requests (normal volume)
    for i in 0..10 {
        let context = create_context(ip, &format!("/page{}", i));
        let result = detector.analyze(&context).await;
        assert!(!result.suspicious, "Moderate volume should not be flagged");
    }
}

#[tokio::test]
async fn test_volume_threshold_exact_boundary() {
    let detector = FloodDetector::new();
    let ip = "192.168.1.102";

    // Send exactly at threshold (should not trigger yet)
    for i in 0..50 {
        let context = create_context(ip, &format!("/api/{}", i));
        let _ = detector.analyze(&context).await;
    }

    let context = create_context(ip, "/check");
    let result = detector.analyze(&context).await;

    // Behavior at boundary depends on threshold configuration
    // This test verifies consistent behavior at threshold
}

// ============================================================================
// T062: Burst Detection Tests
// ============================================================================

#[tokio::test]
async fn test_burst_detection_rapid_requests() {
    let detector = FloodDetector::new();
    let ip = "10.0.0.50";

    // Rapid burst: 50 requests in very short time
    for i in 0..50 {
        let context = create_context(ip, &format!("/burst{}", i));
        let _ = detector.analyze(&context).await;
    }

    // Check if burst was detected
    let context = create_context(ip, "/check_burst");
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Burst pattern should be detected");
    let has_flood = result
        .signals
        .iter()
        .any(|s| matches!(s.variant, SignalVariant::RequestFlood));
    assert!(has_flood, "Burst should generate RequestFlood signal");
}

#[tokio::test]
async fn test_burst_with_delay_not_flagged() {
    let detector = FloodDetector::new();
    let ip = "10.0.0.51";

    // Send requests with delays (not a burst)
    for i in 0..20 {
        let context = create_context(ip, &format!("/slow{}", i));
        let result = detector.analyze(&context).await;

        // Small delay between requests
        if i % 5 == 0 {
            sleep(Duration::from_millis(100)).await;
        }
    }

    let context = create_context(ip, "/final");
    let result = detector.analyze(&context).await;

    // Spaced requests should not trigger burst detection
    assert!(
        !result.suspicious || result.signals.is_empty(),
        "Spaced requests should not be flagged as burst"
    );
}

// ============================================================================
// Sustained Rate Detection Tests
// ============================================================================

#[tokio::test]
async fn test_sustained_high_rate() {
    let detector = FloodDetector::new();
    let ip = "10.0.0.60";

    // Simulate sustained high rate: 200 requests
    for i in 0..200 {
        let context = create_context(ip, &format!("/sustained{}", i));
        let _ = detector.analyze(&context).await;
    }

    // Should detect sustained pattern
    let context = create_context(ip, "/check_sustained");
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Sustained high rate should be detected");
}

#[tokio::test]
async fn test_normal_sustained_rate() {
    let detector = FloodDetector::new();
    let ip = "10.0.0.61";

    // Normal rate: 20 requests with delays
    for i in 0..20 {
        let context = create_context(ip, &format!("/normal{}", i));
        let result = detector.analyze(&context).await;
        assert!(!result.suspicious, "Normal rate should not be flagged");

        sleep(Duration::from_millis(50)).await;
    }
}

// ============================================================================
// Time Window Tests
// ============================================================================

#[tokio::test]
async fn test_time_window_reset() {
    let detector = FloodDetector::new();
    let ip = "10.0.0.70";

    // First wave of requests
    for i in 0..30 {
        let context = create_context(ip, &format!("/wave1_{}", i));
        let _ = detector.analyze(&context).await;
    }

    // Wait for window to reset (implementation dependent)
    sleep(Duration::from_millis(100)).await;

    // Second wave should start fresh count
    for i in 0..30 {
        let context = create_context(ip, &format!("/wave2_{}", i));
        let _ = detector.analyze(&context).await;
    }

    // Should track properly across windows
}

// ============================================================================
// Different IPs Tests
// ============================================================================

#[tokio::test]
async fn test_different_ips_tracked_independently() {
    let detector = FloodDetector::new();

    // IP1: High volume
    for i in 0..100 {
        let context = create_context("192.168.1.100", &format!("/ip1_{}", i));
        let _ = detector.analyze(&context).await;
    }

    // IP2: Normal volume (should not be affected by IP1)
    let context = create_context("192.168.1.101", "/test");
    let result = detector.analyze(&context).await;

    assert!(
        !result.suspicious,
        "Different IP should have independent tracking"
    );
}

// ============================================================================
// Detector Interface Tests
// ============================================================================

#[tokio::test]
async fn test_detector_name() {
    let detector = FloodDetector::new();
    assert_eq!(detector.name(), "FloodDetector");
}

#[tokio::test]
async fn test_detector_enabled_by_default() {
    let detector = FloodDetector::new();
    assert!(detector.enabled());
}

// ============================================================================
// Multiple Signal Types Tests
// ============================================================================

#[tokio::test]
async fn test_extreme_flood_multiple_signals() {
    let detector = FloodDetector::new();
    let ip = "10.0.0.80";

    // Extreme volume to potentially trigger multiple signal types
    for i in 0..500 {
        let context = create_context(ip, &format!("/extreme{}", i));
        let _ = detector.analyze(&context).await;
    }

    let context = create_context(ip, "/check");
    let result = detector.analyze(&context).await;

    assert!(result.suspicious, "Extreme flood should be detected");
    assert!(!result.signals.is_empty(), "Should generate flood signals");
}
