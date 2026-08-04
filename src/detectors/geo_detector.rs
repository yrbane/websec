//! Geolocation detector.
//!
//! Two responsibilities:
//! 1. **Hard per-domain policy** — allow/block visitors by country, overriding
//!    a global default, resolved from the request's `Host`. "Allow only FR" is
//!    a deterministic block (via `DetectionResult::block`), not a score nudge.
//! 2. **Soft scoring** — optional per-country penalties and impossible-travel
//!    heuristics that feed the reputation score.
//!
//! Country resolution uses [`CountryDb`] (per-country CIDR lists, no MaxMind
//! licence). Loopback/private/link-local IPs and whitelisted IPs never reach a
//! geo block (the whitelist short-circuits before detectors run).

use crate::config::settings::{GeoSiteRule, GeolocationConfig};
use crate::detectors::{DetectionResult, Detector, HttpRequestContext};
use crate::geolocation::CountryDb;
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Weight of the impossible-travel scoring signal.
const IMPOSSIBLE_TRAVEL_WEIGHT: u8 = 20;

/// A remembered location for impossible-travel detection.
#[derive(Debug, Clone)]
struct GeoLocation {
    country_code: String,
    timestamp: u64,
}

/// Compiled per-domain geo policy.
struct SiteRule {
    /// Lowercased host, exact or `*.domain` wildcard.
    server_name: String,
    allow: HashSet<String>,
    block: HashSet<String>,
}

/// Geolocation detector: hard per-domain country policy + soft scoring.
pub struct GeoDetector {
    db: Arc<CountryDb>,
    global_allow: HashSet<String>,
    global_block: HashSet<String>,
    sites: Vec<SiteRule>,
    /// Country -> soft penalty weight (scoring, not a hard block).
    penalties: HashMap<String, u8>,
    ip_history: Arc<DashMap<IpAddr, Vec<GeoLocation>>>,
    enabled: bool,
}

fn upper_set(v: &[String]) -> HashSet<String> {
    v.iter().map(|s| s.trim().to_ascii_uppercase()).collect()
}

fn compile_site(rule: &GeoSiteRule) -> SiteRule {
    SiteRule {
        server_name: rule.server_name.trim().to_ascii_lowercase(),
        allow: upper_set(&rule.allow),
        block: upper_set(&rule.block),
    }
}

/// Does `pattern` (exact or `*.domain`) match `host` (lowercased)?
fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        pattern == host
    }
}

/// Extract the target host from the request headers (lowercased, port stripped).
/// We read it from `headers` rather than a dedicated context field to avoid
/// touching every `HttpRequestContext` construction in the codebase.
fn host_of(context: &HttpRequestContext) -> String {
    context
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.split(':').next().unwrap_or(v).trim().to_ascii_lowercase())
        .unwrap_or_default()
}

impl GeoDetector {
    /// Inert detector: no country data, no rules. Resolves nothing and never
    /// blocks — the safe default used when geolocation is disabled or unset.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: Arc::new(CountryDb::empty()),
            global_allow: HashSet::new(),
            global_block: HashSet::new(),
            sites: Vec::new(),
            penalties: HashMap::new(),
            ip_history: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Build from configuration and a shared country database.
    #[must_use]
    pub fn from_config(cfg: &GeolocationConfig, db: Arc<CountryDb>) -> Self {
        Self {
            db,
            global_allow: upper_set(&cfg.allow),
            global_block: upper_set(&cfg.block),
            sites: cfg.sites.iter().map(compile_site).collect(),
            penalties: cfg
                .penalties
                .iter()
                .map(|(k, v)| (k.trim().to_ascii_uppercase(), *v))
                .collect(),
            ip_history: Arc::new(DashMap::new()),
            enabled: cfg.enabled,
        }
    }

    /// Resolve the effective allow/block sets for a target host. A matching
    /// per-domain rule fully overrides the global policy; otherwise the global
    /// allow/block applies.
    fn effective_policy(&self, host: &str) -> (&HashSet<String>, &HashSet<String>) {
        if !host.is_empty() {
            if let Some(rule) = self.sites.iter().find(|r| host_matches(&r.server_name, host)) {
                return (&rule.allow, &rule.block);
            }
        }
        (&self.global_allow, &self.global_block)
    }

    /// Loopback / private / link-local IPs are never geo-evaluated.
    fn is_exempt_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    fn detect_impossible_travel(&self, ip: &IpAddr, current: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(mut history) = self.ip_history.get_mut(ip) {
            let flagged = history
                .last()
                .is_some_and(|last| now.saturating_sub(last.timestamp) < 3600 && last.country_code != current);
            history.push(GeoLocation { country_code: current.to_string(), timestamp: now });
            if history.len() > 10 {
                history.remove(0);
            }
            flagged
        } else {
            self.ip_history
                .insert(*ip, vec![GeoLocation { country_code: current.to_string(), timestamp: now }]);
            false
        }
    }
}

impl Default for GeoDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for GeoDetector {
    fn name(&self) -> &'static str {
        "GeoDetector"
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        if !self.enabled {
            return DetectionResult::clean();
        }
        let ip = context.ip;
        if Self::is_exempt_ip(&ip) {
            return DetectionResult::clean();
        }

        let country = self.db.lookup(ip).map(str::to_string); // already upper-case
        let host = host_of(context);
        let (allow, block) = self.effective_policy(&host);

        // --- Hard policy (deterministic block) ---
        if !allow.is_empty() {
            // Allow-only: an IP whose country is unknown or not listed is refused.
            let permitted = country.as_deref().is_some_and(|c| allow.contains(c));
            if !permitted {
                return DetectionResult::block(format!(
                    "Accès non autorisé depuis votre zone géographique ({}).",
                    country.as_deref().unwrap_or("pays inconnu")
                ));
            }
        } else if let Some(cc) = country.as_deref() {
            if block.contains(cc) {
                return DetectionResult::block(format!(
                    "Accès bloqué depuis votre pays ({cc})."
                ));
            }
        }

        // --- Soft scoring (only for a resolved country) ---
        let Some(cc) = country else {
            return DetectionResult::clean();
        };
        let mut signals = Vec::new();
        if let Some(weight) = self.penalties.get(&cc) {
            if *weight > 0 {
                signals.push(Signal::with_context(
                    SignalVariant::HighRiskCountry,
                    *weight,
                    format!("Requête depuis un pays à risque : {cc}"),
                ));
            }
        }
        if self.detect_impossible_travel(&ip, &cc) {
            signals.push(Signal::with_context(
                SignalVariant::ImpossibleTravel,
                IMPOSSIBLE_TRAVEL_WEIGHT,
                format!("Voyage impossible détecté vers {cc} (IP {ip})"),
            ));
        }

        if signals.is_empty() {
            DetectionResult::clean()
        } else {
            DetectionResult::with_signals(signals)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::GeolocationConfig;

    fn ctx(ip: &str, host: &str) -> HttpRequestContext {
        HttpRequestContext {
            ip: ip.parse().unwrap(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            headers: vec![("host".to_string(), host.to_string())],
            body: None,
            user_agent: None,
            referer: None,
            content_type: None,
        }
    }

    fn db() -> Arc<CountryDb> {
        Arc::new(CountryDb::from_pairs(&[
            ("fr", "90.114.0.0/16"),
            ("cn", "1.0.0.0/8"),
            ("us", "8.8.8.0/24"),
        ]))
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
    async fn allow_only_blocks_other_countries_per_domain() {
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
        // FR visitor allowed
        assert!(!det.analyze(&ctx("90.114.131.138", "boutique.fr")).await.force_block);
        // CN visitor blocked
        assert!(det.analyze(&ctx("1.2.3.4", "boutique.fr")).await.force_block);
        // Unknown country blocked under allow-only
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
    async fn other_host_inherits_global_and_wildcard() {
        let det = GeoDetector::from_config(
            &cfg(
                vec![GeoSiteRule {
                    server_name: "*.corp.example".into(),
                    allow: vec!["FR".into()],
                    block: vec![],
                }],
                vec![],
                vec!["CN".into()], // global block CN
            ),
            db(),
        );
        // wildcard host: allow-only FR -> CN blocked, FR ok
        assert!(det.analyze(&ctx("1.2.3.4", "a.corp.example")).await.force_block);
        assert!(!det.analyze(&ctx("90.114.131.138", "a.corp.example")).await.force_block);
        // unmatched host: global block CN
        assert!(det.analyze(&ctx("1.2.3.4", "blog.example.com")).await.force_block);
        assert!(!det.analyze(&ctx("8.8.8.8", "blog.example.com")).await.force_block);
    }

    #[tokio::test]
    async fn loopback_and_disabled_never_block() {
        let det = GeoDetector::from_config(
            &cfg(vec![], vec!["FR".into()], vec![]),
            db(),
        );
        // loopback exempt even under allow-only
        assert!(!det.analyze(&ctx("127.0.0.1", "boutique.fr")).await.force_block);

        let mut c = cfg(vec![], vec!["FR".into()], vec![]);
        c.enabled = false;
        let det_off = GeoDetector::from_config(&c, db());
        assert!(!det_off.analyze(&ctx("1.2.3.4", "boutique.fr")).await.force_block);
    }
}
