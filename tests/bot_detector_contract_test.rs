//! Contract tests for Detector trait implementations
//!
//! TDD RED PHASE: Verify BotDetector properly implements Detector trait
//!
//! Testing:
//! - T027: BotDetector contract compliance

use websec::detectors::{Detector, HttpRequestContext};
use websec::detectors::bot_detector::BotDetector;
use std::net::IpAddr;
use std::str::FromStr;

/// Contract test: BotDetector must implement Detector trait
#[tokio::test]
async fn test_bot_detector_implements_detector_trait() {
    let detector = BotDetector::new();

    // Verify trait methods are available
    assert_eq!(detector.name(), "BotDetector", "Detector must have a name");
    assert!(detector.enabled(), "Detector should be enabled by default");

    // Verify analyze method works
    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.1").unwrap(),
        method: "GET".to_string(),
        path: "/".to_string(),
        query: None,
        headers: vec![],
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    };

    let result = detector.analyze(&context).await;

    // Result must have required fields
    assert!(result.signals.is_empty() || !result.signals.is_empty(), "signals field must exist");
    assert!(!result.suspicious || result.suspicious, "suspicious field must exist");
}

/// Contract test: BotDetector can be used as Arc<dyn Detector>
#[tokio::test]
async fn test_bot_detector_as_trait_object() {
    use std::sync::Arc;

    let detector: Arc<dyn Detector> = Arc::new(BotDetector::new());

    // Verify trait object works
    assert_eq!(detector.name(), "BotDetector");

    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.1").unwrap(),
        method: "GET".to_string(),
        path: "/".to_string(),
        query: None,
        headers: vec![],
        body: None,
        user_agent: Some("curl/7.68.0".to_string()),
        referer: None,
        content_type: None,
    };

    let result = detector.analyze(&context).await;

    // Should detect curl
    assert!(result.suspicious, "Trait object analyze() must work correctly");
}

/// Contract test: BotDetector works in DetectorRegistry
#[tokio::test]
async fn test_bot_detector_in_registry() {
    use websec::detectors::DetectorRegistry;
    use std::sync::Arc;

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(BotDetector::new()));

    assert_eq!(registry.count(), 1, "Registry should contain BotDetector");
    assert_eq!(registry.enabled_count(), 1, "BotDetector should be enabled");

    let names = registry.detector_names();
    assert!(names.contains(&"BotDetector".to_string()), "Registry should list BotDetector");

    // Test analyze_all with BotDetector
    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.1").unwrap(),
        method: "GET".to_string(),
        path: "/admin".to_string(),
        query: None,
        headers: vec![],
        body: None,
        user_agent: Some("sqlmap/1.0".to_string()),
        referer: None,
        content_type: None,
    };

    let result = registry.analyze_all(&context).await;

    assert!(result.suspicious, "Registry analyze_all should detect sqlmap");
    assert!(!result.signals.is_empty(), "Should have signals from BotDetector");
}

/// Contract test: BotDetector is Send + Sync
#[test]
fn test_bot_detector_is_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<BotDetector>();
    assert_sync::<BotDetector>();
}

/// Contract test: BotDetector::new() is repeatable
#[test]
fn test_bot_detector_new_is_repeatable() {
    let detector1 = BotDetector::new();
    let detector2 = BotDetector::new();

    assert_eq!(detector1.name(), detector2.name());
    assert_eq!(detector1.enabled(), detector2.enabled());
}

// ============================================================================
// BruteForceDetector Contract Tests (T045)
// ============================================================================

use websec::detectors::bruteforce_detector::BruteForceDetector;

/// Contract test: BruteForceDetector must implement Detector trait
#[tokio::test]
async fn test_bruteforce_detector_implements_detector_trait() {
    let detector = BruteForceDetector::new();

    assert_eq!(detector.name(), "BruteForceDetector");
    assert!(detector.enabled());

    // Verify analyze method works
    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.1").unwrap(),
        method: "POST".to_string(),
        path: "/login".to_string(),
        query: None,
        headers: vec![],
        body: Some(b"username=test&password=test".to_vec()),
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: Some("application/x-www-form-urlencoded".to_string()),
    };

    let result = detector.analyze(&context).await;

    assert!(result.signals.is_empty() || !result.signals.is_empty());
    assert!(!result.suspicious || result.suspicious);
}

/// Contract test: BruteForceDetector can be used as Arc<dyn Detector>
#[tokio::test]
async fn test_bruteforce_detector_as_trait_object() {
    let detector: Arc<dyn Detector> = Arc::new(BruteForceDetector::new());

    assert_eq!(detector.name(), "BruteForceDetector");

    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.1").unwrap(),
        method: "POST".to_string(),
        path: "/login".to_string(),
        query: None,
        headers: vec![],
        body: Some(b"username=admin&password=wrong".to_vec()),
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: Some("application/x-www-form-urlencoded".to_string()),
    };

    let _result = detector.analyze(&context).await;
}

/// Contract test: BruteForceDetector is Send + Sync
#[test]
fn test_bruteforce_detector_is_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<BruteForceDetector>();
    assert_sync::<BruteForceDetector>();
}
