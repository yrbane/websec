//! Integration tests for geographic threat detection through DecisionEngine.
//!
//! Exercises the real CIDR-backed GeoDetector wired into the reputation engine:
//! per-domain hard blocks (force_block -> ProxyDecision::Block), allow-list
//! passthrough, and exemptions. No MaxMind, no network — a deterministic
//! in-memory country DB.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::config::settings::{GeoSiteRule, GeolocationConfig};
use websec::detectors::geo_detector::GeoDetector;
use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::geolocation::CountryDb;
use websec::reputation::{DecisionEngine, DecisionEngineConfig, ProxyDecision};
use websec::storage::InMemoryRepository;

fn country_db() -> Arc<CountryDb> {
    Arc::new(CountryDb::from_pairs(&[
        ("fr", "90.114.0.0/16"),
        ("cn", "1.0.0.0/8"),
        ("us", "8.8.8.0/24"),
    ]))
}

/// Engine whose GeoDetector enforces: boutique.fr = allow-only FR,
/// api.example.com = block CN, global default = no policy.
fn geo_engine() -> DecisionEngine {
    let cfg = GeolocationConfig {
        enabled: true,
        database: None,
        penalties: HashMap::new(),
        country_dir: None,
        allow: vec![],
        block: vec![],
        sites: vec![
            GeoSiteRule {
                server_name: "boutique.fr".into(),
                allow: vec!["FR".into()],
                block: vec![],
            },
            GeoSiteRule {
                server_name: "api.example.com".into(),
                allow: vec![],
                block: vec!["CN".into()],
            },
        ],
    };
    let detector = GeoDetector::from_config(&cfg, country_db());

    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(detector));

    DecisionEngine::new(
        DecisionEngineConfig::default(),
        Arc::new(InMemoryRepository::new()),
        Arc::new(registry),
    )
}

fn context(ip: &str, host: &str) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: "/".to_string(),
        query: None,
        headers: vec![("host".to_string(), host.to_string())],
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    }
}

#[tokio::test]
async fn allow_only_domain_blocks_foreign_ip() {
    let engine = geo_engine();
    // CN visitor on a FR-only shop -> hard Block.
    let result = engine
        .process_request(&context("1.2.3.4", "boutique.fr"))
        .await
        .unwrap();
    assert_eq!(result.decision, ProxyDecision::Block);
    assert!(result.detection.force_block);
}

#[tokio::test]
async fn allow_only_domain_admits_local_ip() {
    let engine = geo_engine();
    let result = engine
        .process_request(&context("90.114.131.138", "boutique.fr"))
        .await
        .unwrap();
    assert_eq!(result.decision, ProxyDecision::Allow);
    assert_eq!(result.score, 100);
}

#[tokio::test]
async fn blocklist_domain_blocks_listed_country() {
    let engine = geo_engine();
    let blocked = engine
        .process_request(&context("1.2.3.4", "api.example.com"))
        .await
        .unwrap();
    assert_eq!(blocked.decision, ProxyDecision::Block);

    let allowed = engine
        .process_request(&context("8.8.8.8", "api.example.com"))
        .await
        .unwrap();
    assert_eq!(allowed.decision, ProxyDecision::Allow);
}

#[tokio::test]
async fn unmatched_host_has_no_policy() {
    let engine = geo_engine();
    // No site rule, no global policy -> passes regardless of country.
    let result = engine
        .process_request(&context("1.2.3.4", "blog.example.com"))
        .await
        .unwrap();
    assert_eq!(result.decision, ProxyDecision::Allow);
    assert_eq!(result.score, 100);
}

#[tokio::test]
async fn loopback_is_exempt_even_on_allow_only_domain() {
    let engine = geo_engine();
    let result = engine
        .process_request(&context("127.0.0.1", "boutique.fr"))
        .await
        .unwrap();
    assert_eq!(result.decision, ProxyDecision::Allow);
    assert_eq!(result.score, 100);
}

#[tokio::test]
async fn private_ip_is_exempt() {
    let engine = geo_engine();
    let result = engine
        .process_request(&context("192.168.1.100", "boutique.fr"))
        .await
        .unwrap();
    assert_eq!(result.decision, ProxyDecision::Allow);
}
