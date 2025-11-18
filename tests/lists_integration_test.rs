//! Integration tests for Blacklist/Whitelist with DecisionEngine
//!
//! TDD RED PHASE: End-to-end tests
//!
//! Testing:
//! - T107: Blacklist override le scoring (block immédiatement)
//! - Whitelist bypass scoring (always allow)
//! - Priority: blacklist > whitelist > scoring

use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::reputation::{DecisionEngine, DecisionEngineConfig, ProxyDecision};
use websec::storage::InMemoryRepository;
use websec::lists::{Blacklist, Whitelist};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Helper to create test engine with lists
fn create_test_engine_with_lists(
    blacklist: Option<Blacklist>,
    whitelist: Option<Whitelist>,
) -> DecisionEngine {
    let mut config = DecisionEngineConfig::default();

    if let Some(bl) = blacklist {
        config.set_blacklist(bl);
    }
    if let Some(wl) = whitelist {
        config.set_whitelist(wl);
    }

    let repository = Arc::new(InMemoryRepository::new());
    let detectors = Arc::new(DetectorRegistry::new());

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
// T107: Blacklist Override Scoring Tests
// ============================================================================

#[tokio::test]
async fn test_blacklisted_ip_blocked_immediately() {
    let mut blacklist = Blacklist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();
    blacklist.add(ip);

    let engine = create_test_engine_with_lists(Some(blacklist), None);
    let context = create_context("192.168.1.100", "/test");

    let result = engine.process_request(&context).await.unwrap();

    // Should be blocked immediately
    assert_eq!(result.decision, ProxyDecision::Block,
        "Blacklisted IP should be blocked immediately");
    assert_eq!(result.score, 0, "Blacklisted IP should have score 0");
}

#[tokio::test]
async fn test_blacklist_overrides_perfect_score() {
    let mut blacklist = Blacklist::new();
    let ip = IpAddr::from_str("192.168.1.101").unwrap();
    blacklist.add(ip);

    let engine = create_test_engine_with_lists(Some(blacklist), None);

    // First request - should be blocked even though IP is clean
    let context = create_context("192.168.1.101", "/test");
    let result = engine.process_request(&context).await.unwrap();

    assert_eq!(result.decision, ProxyDecision::Block,
        "Blacklisted IP should be blocked even with clean history");
}

#[tokio::test]
async fn test_non_blacklisted_ip_uses_normal_scoring() {
    let blacklist = Blacklist::new(); // Empty
    let engine = create_test_engine_with_lists(Some(blacklist), None);

    let context = create_context("192.168.1.102", "/test");
    let result = engine.process_request(&context).await.unwrap();

    // Should use normal scoring (clean IP = allow)
    assert_eq!(result.decision, ProxyDecision::Allow);
    assert_eq!(result.score, 100);
}

// ============================================================================
// Whitelist Bypass Tests
// ============================================================================

#[tokio::test]
async fn test_whitelisted_ip_always_allowed() {
    let mut whitelist = Whitelist::new();
    let ip = IpAddr::from_str("10.0.0.50").unwrap();
    whitelist.add(ip);

    let engine = create_test_engine_with_lists(None, Some(whitelist));
    let context = create_context("10.0.0.50", "/test");

    let result = engine.process_request(&context).await.unwrap();

    // Should be allowed with perfect score
    assert_eq!(result.decision, ProxyDecision::Allow,
        "Whitelisted IP should always be allowed");
    assert_eq!(result.score, 100, "Whitelisted IP should have perfect score");
}

#[tokio::test]
async fn test_whitelist_bypasses_scoring() {
    let mut whitelist = Whitelist::new();
    let ip = IpAddr::from_str("10.0.0.51").unwrap();
    whitelist.add(ip);

    let engine = create_test_engine_with_lists(None, Some(whitelist));

    // Make multiple requests that would normally degrade score
    for i in 0..200 {
        let context = create_context("10.0.0.51", &format!("/flood{}", i));
        let result = engine.process_request(&context).await.unwrap();

        // Should still be allowed
        assert_eq!(result.decision, ProxyDecision::Allow,
            "Whitelisted IP should remain allowed on request {}", i);
        assert_eq!(result.score, 100,
            "Whitelisted IP should maintain perfect score on request {}", i);
    }
}

// ============================================================================
// Priority Tests: Blacklist > Whitelist
// ============================================================================

#[tokio::test]
async fn test_blacklist_has_priority_over_whitelist() {
    let mut blacklist = Blacklist::new();
    let mut whitelist = Whitelist::new();
    let ip = IpAddr::from_str("192.168.1.200").unwrap();

    // IP in both lists
    blacklist.add(ip);
    whitelist.add(ip);

    let engine = create_test_engine_with_lists(Some(blacklist), Some(whitelist));
    let context = create_context("192.168.1.200", "/test");

    let result = engine.process_request(&context).await.unwrap();

    // Blacklist should take priority
    assert_eq!(result.decision, ProxyDecision::Block,
        "Blacklist should have priority over whitelist");
    assert_eq!(result.score, 0);
}

// ============================================================================
// Multiple IPs Tests
// ============================================================================

#[tokio::test]
async fn test_multiple_blacklisted_ips() {
    let mut blacklist = Blacklist::new();
    blacklist.add(IpAddr::from_str("192.168.1.100").unwrap());
    blacklist.add(IpAddr::from_str("192.168.1.101").unwrap());
    blacklist.add(IpAddr::from_str("192.168.1.102").unwrap());

    let engine = create_test_engine_with_lists(Some(blacklist), None);

    for i in 100..=102 {
        let ip = format!("192.168.1.{}", i);
        let context = create_context(&ip, "/test");
        let result = engine.process_request(&context).await.unwrap();

        assert_eq!(result.decision, ProxyDecision::Block,
            "IP {} should be blocked", ip);
    }
}

#[tokio::test]
async fn test_multiple_whitelisted_ips() {
    let mut whitelist = Whitelist::new();
    whitelist.add(IpAddr::from_str("10.0.0.100").unwrap());
    whitelist.add(IpAddr::from_str("10.0.0.101").unwrap());
    whitelist.add(IpAddr::from_str("10.0.0.102").unwrap());

    let engine = create_test_engine_with_lists(None, Some(whitelist));

    for i in 100..=102 {
        let ip = format!("10.0.0.{}", i);
        let context = create_context(&ip, "/test");
        let result = engine.process_request(&context).await.unwrap();

        assert_eq!(result.decision, ProxyDecision::Allow,
            "IP {} should be allowed", ip);
        assert_eq!(result.score, 100);
    }
}

// ============================================================================
// Mixed Scenarios Tests
// ============================================================================

#[tokio::test]
async fn test_mixed_blacklist_whitelist_and_normal() {
    let mut blacklist = Blacklist::new();
    let mut whitelist = Whitelist::new();

    // Setup lists
    blacklist.add(IpAddr::from_str("192.168.1.100").unwrap());
    whitelist.add(IpAddr::from_str("10.0.0.50").unwrap());

    let engine = create_test_engine_with_lists(Some(blacklist), Some(whitelist));

    // Blacklisted IP
    let context1 = create_context("192.168.1.100", "/test");
    let result1 = engine.process_request(&context1).await.unwrap();
    assert_eq!(result1.decision, ProxyDecision::Block);

    // Whitelisted IP
    let context2 = create_context("10.0.0.50", "/test");
    let result2 = engine.process_request(&context2).await.unwrap();
    assert_eq!(result2.decision, ProxyDecision::Allow);
    assert_eq!(result2.score, 100);

    // Normal IP (not in either list)
    let context3 = create_context("172.16.0.1", "/test");
    let result3 = engine.process_request(&context3).await.unwrap();
    assert_eq!(result3.decision, ProxyDecision::Allow); // Clean IP
    assert_eq!(result3.score, 100);
}
