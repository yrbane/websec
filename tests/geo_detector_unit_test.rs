//! Unit tests for GeoDetector — real CIDR-backed API (ipdeny country DB).
//!
//! Covers per-domain geo policy (allow-only / blocklist), global fallback,
//! exemptions (loopback/private), unknown-country handling, and soft scoring.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::config::settings::{GeoSiteRule, GeolocationConfig};
use websec::detectors::geo_detector::GeoDetector;
use websec::detectors::{Detector, HttpRequestContext};
use websec::geolocation::CountryDb;
use websec::reputation::SignalVariant;

/// Small deterministic country DB (no MaxMind, no network).
fn db() -> Arc<CountryDb> {
    Arc::new(CountryDb::from_pairs(&[
        ("fr", "90.114.0.0/16"),
        ("cn", "1.0.0.0/8"),
        ("us", "8.8.8.0/24"),
    ]))
}

fn ctx(ip: &str, host: &str) -> HttpRequestContext {
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

fn cfg(sites: Vec<GeoSiteRule>, allow: Vec<String>, block: Vec<String>) -> GeolocationConfig {
    GeolocationConfig {
        enabled: true,
        database: None,
        penalties: HashMap::new(),
        country_dir: None,
        allow,
        block,
        sites,
    }
}

#[tokio::test]
async fn allow_only_per_domain_blocks_everyone_else() {
    let det = GeoDetector::from_config(
        &cfg(
            vec![GeoSiteRule {
                server_name: "boutique.fr".into(),
                allow: vec!["FR".into()],
                block: vec![],
            }],
            vec![],
            vec![],
        ),
        db(),
    );
    // FR allowed
    assert!(!det.analyze(&ctx("90.114.131.138", "boutique.fr")).await.force_block);
    // CN refused
    assert!(det.analyze(&ctx("1.2.3.4", "boutique.fr")).await.force_block);
    // Unknown country refused under allow-only
    assert!(det.analyze(&ctx("203.0.113.7", "boutique.fr")).await.force_block);
}

#[tokio::test]
async fn blocklist_per_domain() {
    let det = GeoDetector::from_config(
        &cfg(
            vec![GeoSiteRule {
                server_name: "api.example.com".into(),
                allow: vec![],
                block: vec!["CN".into()],
            }],
            vec![],
            vec![],
        ),
        db(),
    );
    assert!(det.analyze(&ctx("1.2.3.4", "api.example.com")).await.force_block);
    assert!(!det.analyze(&ctx("8.8.8.8", "api.example.com")).await.force_block);
}

#[tokio::test]
async fn global_policy_and_wildcard_override() {
    let det = GeoDetector::from_config(
        &cfg(
            vec![GeoSiteRule {
                server_name: "*.corp.example".into(),
                allow: vec!["FR".into()],
                block: vec![],
            }],
            vec![],
            vec!["CN".into()],
        ),
        db(),
    );
    // wildcard host is allow-only FR
    assert!(det.analyze(&ctx("1.2.3.4", "a.corp.example")).await.force_block);
    assert!(!det.analyze(&ctx("90.114.131.138", "a.corp.example")).await.force_block);
    // unmatched host falls back to global block CN
    assert!(det.analyze(&ctx("1.2.3.4", "blog.example.com")).await.force_block);
    assert!(!det.analyze(&ctx("8.8.8.8", "blog.example.com")).await.force_block);
}

#[tokio::test]
async fn loopback_and_private_are_exempt() {
    let det = GeoDetector::from_config(&cfg(vec![], vec!["FR".into()], vec![]), db());
    // allow-only FR, but loopback/private never geo-blocked
    assert!(!det.analyze(&ctx("127.0.0.1", "boutique.fr")).await.force_block);
    assert!(!det.analyze(&ctx("192.168.1.10", "boutique.fr")).await.force_block);
}

#[tokio::test]
async fn disabled_detector_never_blocks() {
    let mut c = cfg(vec![], vec!["FR".into()], vec![]);
    c.enabled = false;
    let det = GeoDetector::from_config(&c, db());
    assert!(!det.analyze(&ctx("1.2.3.4", "boutique.fr")).await.force_block);
}

#[tokio::test]
async fn soft_penalty_scores_high_risk_country() {
    let mut penalties = HashMap::new();
    penalties.insert("CN".to_string(), 15u8);
    let c = GeolocationConfig {
        enabled: true,
        database: None,
        penalties,
        country_dir: None,
        allow: vec![],
        block: vec![],
        sites: vec![],
    };
    let det = GeoDetector::from_config(&c, db());
    let result = det.analyze(&ctx("1.2.3.4", "blog.example.com")).await;
    // Not a hard block: just a scoring signal
    assert!(!result.force_block);
    let sig = result
        .signals
        .iter()
        .find(|s| matches!(s.variant, SignalVariant::HighRiskCountry))
        .expect("should emit HighRiskCountry signal");
    assert_eq!(sig.weight, 15);
}

#[tokio::test]
async fn unknown_country_without_allow_is_clean() {
    let det = GeoDetector::from_config(&cfg(vec![], vec![], vec!["CN".into()]), db());
    // Unknown IP, only a global blocklist -> passes through
    let result = det.analyze(&ctx("203.0.113.7", "blog.example.com")).await;
    assert!(!result.force_block);
    assert!(!result.suspicious);
}
