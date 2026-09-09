//! Exemptions de chemin : ce qu'une exemption peut contourner, et ce qu'elle
//! ne peut pas.
//!
//! Une exemption dispense un chemin public des décisions **comportementales**
//! (challenge `PoW`, rate limit, score bas) pour que les robots sans JavaScript
//! — OpenSea, indexeurs, sondes — lisent des métadonnées publiques. Elle ne
//! doit jamais ouvrir un chemin à un client bloqué de façon **déterministe**
//! (blacklist d'IP, politique géo) : c'est l'invariant testé ici via
//! `DecisionEngineResult::hard_block`, sur lequel le middleware s'appuie.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::config::settings::{GeoSiteRule, GeolocationConfig, PathExemption};
use websec::detectors::geo_detector::GeoDetector;
use websec::detectors::{BotDetector, DetectorRegistry, HttpRequestContext};
use websec::lists::Blacklist;
use websec::proxy::ExemptionSet;
use websec::reputation::{DecisionEngine, DecisionEngineConfig, ProxyDecision};
use websec::storage::InMemoryRepository;

/// Exemptions telles qu'on les configure pour une collection NFT.
fn nft_exemptions() -> ExemptionSet {
    ExemptionSet::new(&[PathExemption {
        server_name: "minoupix.com".into(),
        paths: vec!["/api/nft".into(), "/media".into()],
        methods: vec!["GET".into(), "HEAD".into()],
    }])
}

fn context(ip: &str, host: &str, path: &str, ua: &str) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: path.to_string(),
        query: None,
        headers: vec![("host".to_string(), host.to_string())],
        body: None,
        user_agent: Some(ua.to_string()),
        referer: None,
        content_type: None,
    }
}

/// Moteur avec le détecteur de bots : un client outil (curl-like) se dégrade
/// jusqu'au challenge puis au blocage, comme en production.
fn bot_engine() -> DecisionEngine {
    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(BotDetector::new()));
    DecisionEngine::new(
        DecisionEngineConfig::default(),
        Arc::new(InMemoryRepository::new()),
        Arc::new(registry),
    )
}

/// Moteur dont la politique géo n'autorise que la France sur `minoupix.com`.
fn geo_engine() -> DecisionEngine {
    let db = Arc::new(websec::geolocation::CountryDb::from_pairs(&[
        ("fr", "90.114.0.0/16"),
        ("us", "8.8.8.0/24"),
    ]));
    let cfg = GeolocationConfig {
        enabled: true,
        database: None,
        penalties: HashMap::new(),
        country_dir: None,
        allow: vec![],
        block: vec![],
        sites: vec![GeoSiteRule {
            server_name: "minoupix.com".into(),
            allow: vec!["FR".into()],
            block: vec![],
        }],
    };
    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(GeoDetector::from_config(&cfg, db)));
    DecisionEngine::new(
        DecisionEngineConfig::default(),
        Arc::new(InMemoryRepository::new()),
        Arc::new(registry),
    )
}

#[test]
fn nft_metadata_paths_are_exempt() {
    let set = nft_exemptions();
    assert!(set.matches("minoupix.com", "GET", "/api/nft/collection"));
    assert!(set.matches("minoupix.com", "GET", "/api/nft/1"));
    assert!(set.matches("minoupix.com", "GET", "/media/1.png"));
}

#[test]
fn the_rest_of_the_site_stays_protected() {
    let set = nft_exemptions();
    assert!(!set.matches("minoupix.com", "GET", "/"));
    assert!(!set.matches("minoupix.com", "GET", "/admin"));
    assert!(!set.matches("minoupix.com", "POST", "/api/nft/1"));
}

#[tokio::test]
async fn a_degraded_bot_is_only_soft_blocked_so_the_exemption_applies() {
    let engine = bot_engine();
    let ctx = context("203.0.113.10", "minoupix.com", "/api/nft/1", "curl/8.5.0");

    // Marteler jusqu'à ce que le score tombe sous le seuil d'ALLOW.
    let mut last = engine.process_request(&ctx).await.unwrap();
    for _ in 0..30 {
        if last.decision != ProxyDecision::Allow {
            break;
        }
        last = engine.process_request(&ctx).await.unwrap();
    }

    assert_ne!(
        last.decision,
        ProxyDecision::Allow,
        "un client outil doit finir par être filtré sans exemption"
    );
    assert!(
        !last.hard_block,
        "une dégradation de score n'est pas un blocage déterministe : \
         l'exemption de chemin doit pouvoir la contourner"
    );
    assert!(nft_exemptions().matches("minoupix.com", "GET", "/api/nft/1"));
}

#[tokio::test]
async fn a_blacklisted_ip_is_hard_blocked_even_on_an_exempt_path() {
    let ip = IpAddr::from_str("198.51.100.7").unwrap();
    let mut blacklist = Blacklist::new();
    blacklist.add(ip);
    let mut config = DecisionEngineConfig::default();
    config.set_blacklist(blacklist);
    let engine = DecisionEngine::new(
        config,
        Arc::new(InMemoryRepository::new()),
        Arc::new(DetectorRegistry::new()),
    );

    let ctx = context("198.51.100.7", "minoupix.com", "/api/nft/1", "Mozilla/5.0");
    let result = engine.process_request(&ctx).await.unwrap();

    assert_eq!(result.decision, ProxyDecision::Block);
    assert!(
        result.hard_block,
        "la blacklist doit rester prioritaire sur toute exemption de chemin"
    );
}

#[tokio::test]
async fn a_geo_blocked_visitor_is_hard_blocked_even_on_an_exempt_path() {
    let engine = geo_engine();
    // 8.8.8.8 = US sur un domaine allow-only FR.
    let ctx = context("8.8.8.8", "minoupix.com", "/media/1.png", "Mozilla/5.0");
    let result = engine.process_request(&ctx).await.unwrap();

    assert_eq!(result.decision, ProxyDecision::Block);
    assert!(
        result.hard_block,
        "la politique géo doit rester prioritaire sur toute exemption de chemin"
    );
}

#[tokio::test]
async fn a_clean_visitor_is_allowed_without_any_exemption() {
    let engine = geo_engine();
    let ctx = context("90.114.0.1", "minoupix.com", "/media/1.png", "Mozilla/5.0");
    let result = engine.process_request(&ctx).await.unwrap();

    assert_eq!(result.decision, ProxyDecision::Allow);
    assert!(!result.hard_block);
}
