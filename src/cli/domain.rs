//! `websec domain` — configuration simple par domaine, sans reverse-proxy
//! externe : routage (hôte → backend/port) et politique GeoIP par domaine
//! (allow / block / allow-only), en exceptions aux règles globales.
//!
//! Exemples :
//! ```text
//! # Router un hôte vers un port local
//! websec domain app.example.com --port 8082
//!
//! # N'autoriser que la France sur une boutique
//! websec domain boutique.fr --geo-allow FR
//!
//! # Bloquer deux pays sur une API (le reste passe)
//! websec domain api.example.com --geo-block CN,RU
//!
//! # Retirer la politique géo d'un domaine (retour aux règles globales)
//! websec domain api.example.com --geo-clear
//!
//! # Tout supprimer pour un hôte (route + géo)
//! websec domain vieux.example.com --remove
//!
//! # Lister la configuration par domaine
//! websec domain --list
//! ```
//! Le fichier est sauvegardé avant modification ; relancer WebSec pour appliquer.

use crate::config::load_from_file;
use crate::config::settings::{GeoSiteRule, RouteConfig, Settings};
use crate::detectors::{Detector, GeoDetector, HttpRequestContext};
use crate::geolocation::CountryDb;
use crate::{Error, Result};
use chrono::Utc;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

/// Intention parsée pour un domaine (issue des drapeaux CLI).
#[derive(Debug, Default, Clone)]
pub struct DomainChange {
    /// Hôte cible (exact ou `*.domaine`).
    pub host: String,
    /// Backend à router pour cet hôte (`http://127.0.0.1:PORT`).
    pub backend: Option<String>,
    /// Liste allow-only (ISO alpha-2). `Some` remplace, `None` laisse inchangé.
    pub geo_allow: Option<Vec<String>>,
    /// Liste block (ISO alpha-2). `Some` remplace, `None` laisse inchangé.
    pub geo_block: Option<Vec<String>>,
    /// Retirer la règle géo de cet hôte (retour aux règles globales).
    pub geo_clear: bool,
    /// Retirer route + géo pour cet hôte.
    pub remove: bool,
}

fn norm_host(h: &str) -> String {
    h.trim().to_ascii_lowercase()
}

fn norm_codes(list: &[String]) -> Vec<String> {
    list.iter()
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Applique le changement à la configuration en mémoire. Fonction pure :
/// aucune I/O, entièrement testable.
///
/// Retourne un journal des actions effectuées (pour l'affichage).
pub fn apply_domain_change(settings: &mut Settings, change: &DomainChange) -> Vec<String> {
    let host = norm_host(&change.host);
    let mut log = Vec::new();

    if change.remove {
        let mut removed_routes = 0;
        for listener in &mut settings.server.listeners {
            let before = listener.routes.len();
            listener.routes.retain(|r| norm_host(&r.server_name) != host);
            removed_routes += before - listener.routes.len();
        }
        let before = settings.geolocation.sites.len();
        settings
            .geolocation
            .sites
            .retain(|s| norm_host(&s.server_name) != host);
        let removed_geo = before - settings.geolocation.sites.len();
        log.push(format!(
            "supprimé : {removed_routes} route(s) et {removed_geo} règle(s) géo pour {host}"
        ));
        return log;
    }

    // --- Routage ---
    if let Some(backend) = &change.backend {
        if settings.server.listeners.is_empty() {
            log.push(
                "⚠️  aucun listener configuré : lancez d'abord `websec setup`.".to_string(),
            );
        }
        for listener in &mut settings.server.listeners {
            // upsert par server_name
            if let Some(route) = listener
                .routes
                .iter_mut()
                .find(|r| norm_host(&r.server_name) == host)
            {
                route.backend = backend.clone();
            } else {
                listener.routes.push(RouteConfig {
                    server_name: host.clone(),
                    backend: backend.clone(),
                });
            }
        }
        log.push(format!("route : {host} → {backend}"));
    }

    // --- Politique géo ---
    if change.geo_clear {
        let before = settings.geolocation.sites.len();
        settings
            .geolocation
            .sites
            .retain(|s| norm_host(&s.server_name) != host);
        if settings.geolocation.sites.len() < before {
            log.push(format!("règle géo retirée pour {host} (règles globales appliquées)"));
        } else {
            log.push(format!("aucune règle géo à retirer pour {host}"));
        }
    } else if change.geo_allow.is_some() || change.geo_block.is_some() {
        let allow = change.geo_allow.as_deref().map(norm_codes);
        let block = change.geo_block.as_deref().map(norm_codes);

        let rule = settings
            .geolocation
            .sites
            .iter_mut()
            .find(|s| norm_host(&s.server_name) == host);

        if let Some(rule) = rule {
            if let Some(a) = allow {
                rule.allow = a;
            }
            if let Some(b) = block {
                rule.block = b;
            }
        } else {
            settings.geolocation.sites.push(GeoSiteRule {
                server_name: host.clone(),
                allow: allow.unwrap_or_default(),
                block: block.unwrap_or_default(),
            });
        }

        if let Some(rule) = settings
            .geolocation
            .sites
            .iter()
            .find(|s| norm_host(&s.server_name) == host)
        {
            if !rule.allow.is_empty() {
                log.push(format!(
                    "géo {host} : allow-only [{}] (tout autre pays bloqué)",
                    rule.allow.join(", ")
                ));
            }
            if !rule.block.is_empty() {
                log.push(format!("géo {host} : block [{}]", rule.block.join(", ")));
            }
            if rule.allow.is_empty() && rule.block.is_empty() {
                log.push(format!("géo {host} : règle vide (aucun effet)"));
            }
        }

        if !settings.geolocation.enabled {
            log.push(
                "⚠️  [geolocation].enabled = false : les règles géo par domaine \
                 sont ignorées tant que la géolocalisation n'est pas activée."
                    .to_string(),
            );
        }
    }

    log
}

/// Rendu lisible de la configuration par domaine (routes + géo).
pub fn render_listing(settings: &Settings) -> String {
    let mut out = String::new();
    out.push_str("Routage par hôte :\n");
    let mut any_route = false;
    for listener in &settings.server.listeners {
        for r in &listener.routes {
            out.push_str(&format!(
                "  [{}] {} → {}\n",
                listener.listen, r.server_name, r.backend
            ));
            any_route = true;
        }
    }
    if !any_route {
        out.push_str("  (aucune route ; tout va au backend par défaut du listener)\n");
    }

    out.push_str("\nPolitique GeoIP :\n");
    out.push_str(&format!(
        "  activée : {}\n",
        if settings.geolocation.enabled { "oui" } else { "non" }
    ));
    if !settings.geolocation.allow.is_empty() {
        out.push_str(&format!(
            "  globale allow-only : [{}]\n",
            settings.geolocation.allow.join(", ")
        ));
    }
    if !settings.geolocation.block.is_empty() {
        out.push_str(&format!(
            "  globale block : [{}]\n",
            settings.geolocation.block.join(", ")
        ));
    }
    if settings.geolocation.allow.is_empty() && settings.geolocation.block.is_empty() {
        out.push_str("  globale : aucune (par défaut : tout passe)\n");
    }
    if settings.geolocation.sites.is_empty() {
        out.push_str("  par domaine : aucune\n");
    } else {
        out.push_str("  par domaine :\n");
        for s in &settings.geolocation.sites {
            let mut parts = Vec::new();
            if !s.allow.is_empty() {
                parts.push(format!("allow-only [{}]", s.allow.join(", ")));
            }
            if !s.block.is_empty() {
                parts.push(format!("block [{}]", s.block.join(", ")));
            }
            if parts.is_empty() {
                parts.push("(vide)".to_string());
            }
            out.push_str(&format!("    {} : {}\n", s.server_name, parts.join(" ; ")));
        }
    }
    out
}

/// Sauvegarde `config_path` en `.websec.bak.<timestamp>` puis renvoie le chemin.
fn backup(config_path: &Path) -> Result<std::path::PathBuf> {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let name = config_path
        .file_name()
        .map_or_else(|| "websec.toml".to_string(), |s| s.to_string_lossy().into_owned());
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    let backup_path = parent.join(format!("{name}.websec.bak.{timestamp}"));
    fs::copy(config_path, &backup_path).map_err(Error::Io)?;
    Ok(backup_path)
}

/// Charge la base pays depuis `country_dir` (défaut `/etc/websec/geoip`).
fn load_country_db(settings: &Settings) -> CountryDb {
    let dir = settings
        .geolocation
        .country_dir
        .clone()
        .unwrap_or_else(|| "/etc/websec/geoip".to_string());
    CountryDb::load_dir(&dir).unwrap_or_else(|_| CountryDb::empty())
}

/// Vérifie les codes pays demandés contre la base. Un code `allow` inconnu est
/// une erreur (allow-only bloquerait tout le monde) ; un code `block` inconnu
/// n'est qu'un avertissement (règle inerte pour ce pays).
fn validate_codes(db: &CountryDb, change: &DomainChange) -> Result<()> {
    if db.is_empty() {
        eprintln!(
            "⚠️  Base géo absente ou vide (/etc/websec/geoip) : validation des \
             codes pays ignorée. Lancez `websec-geoip-sync.sh`."
        );
        return Ok(());
    }
    if let Some(codes) = &change.geo_allow {
        let unknown: Vec<String> = codes
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| !s.is_empty() && !db.knows_country(s))
            .collect();
        if !unknown.is_empty() {
            return Err(Error::Config(format!(
                "Codes pays inconnus dans --geo-allow : [{}]. En allow-only, un \
                 pays non identifiable bloquerait TOUS les visiteurs. Corrigez \
                 les codes (ISO alpha-2) ou vérifiez les données géo.",
                unknown.join(", ")
            )));
        }
    }
    if let Some(codes) = &change.geo_block {
        let unknown: Vec<String> = codes
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| !s.is_empty() && !db.knows_country(s))
            .collect();
        if !unknown.is_empty() {
            eprintln!(
                "⚠️  Codes pays inconnus dans --geo-block : [{}]. La règle sera \
                 inerte pour ces pays (aucune plage chargée).",
                unknown.join(", ")
            );
        }
    }
    Ok(())
}

/// Simule la décision géo pour une IP sur un hôte, sans rien modifier.
async fn simulate(settings: &Settings, host: &str, ip: IpAddr) -> Result<()> {
    let db = Arc::new(load_country_db(settings));
    let country = db.lookup(ip).map(str::to_string);
    let detector = GeoDetector::from_config(&settings.geolocation, db);

    let ctx = HttpRequestContext {
        ip,
        method: "GET".into(),
        path: "/".into(),
        query: None,
        headers: vec![("host".into(), host.to_string())],
        body: None,
        user_agent: None,
        referer: None,
        content_type: None,
    };
    let result = detector.analyze(&ctx).await;

    println!("Simulation géo :");
    println!("  IP      : {ip}");
    println!("  Hôte    : {host}");
    println!(
        "  Pays    : {}",
        country.as_deref().unwrap_or("inconnu (aucune plage)")
    );
    if !settings.geolocation.enabled {
        println!("  ⚠️  [geolocation].enabled = false : la géo ne s'applique pas.");
    }
    if result.force_block {
        println!(
            "  Décision: 🚫 BLOCK — {}",
            result.message.as_deref().unwrap_or("politique géo")
        );
    } else {
        println!("  Décision: ✅ PASS (aucun blocage géo pour cet hôte)");
    }
    Ok(())
}

/// Point d'entrée `websec domain`.
///
/// - `test_ip` : simule la décision géo (IP + hôte) sans modifier la config.
/// - `list` (ou aucun changement) : affiche la configuration par domaine.
/// - sinon : valide, applique le changement et réécrit le fichier après sauvegarde.
pub async fn run_domain(
    config_path: &Path,
    change: &DomainChange,
    list: bool,
    test_ip: Option<IpAddr>,
) -> Result<()> {
    let mut settings = load_from_file(config_path).map_err(|e| {
        Error::Config(format!("Impossible de charger {}: {e}", config_path.display()))
    })?;

    // Mode simulation : ne modifie rien.
    if let Some(ip) = test_ip {
        if change.host.is_empty() {
            return Err(Error::Config(
                "Précisez l'hôte à simuler, ex. `websec domain boutique.fr --test 1.2.3.4`."
                    .to_string(),
            ));
        }
        return simulate(&settings, &change.host, ip).await;
    }

    let has_change = !change.remove
        && change.backend.is_none()
        && change.geo_allow.is_none()
        && change.geo_block.is_none()
        && !change.geo_clear;

    if list || (change.host.is_empty() && has_change) {
        print!("{}", render_listing(&settings));
        return Ok(());
    }

    if change.host.is_empty() {
        return Err(Error::Config(
            "Précisez un hôte (ex. `websec domain app.example.com --port 8082`) \
             ou utilisez --list."
                .to_string(),
        ));
    }

    // Valide les codes pays avant d'écrire quoi que ce soit.
    validate_codes(&load_country_db(&settings), change)?;

    let actions = apply_domain_change(&mut settings, change);

    let backup_path = backup(config_path)?;
    let toml_text = toml::to_string_pretty(&settings)
        .map_err(|e| Error::Config(format!("Erreur de sérialisation TOML: {e}")))?;
    fs::write(config_path, toml_text).map_err(Error::Io)?;

    println!("📦 Sauvegarde : {}", backup_path.display());
    for line in &actions {
        println!("✅ {line}");
    }
    println!(
        "ℹ️  Relancez WebSec pour appliquer : systemctl restart websec"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{
        GeolocationConfig, ListenerConfig, LoggingConfig, MetricsConfig, RateLimitConfig,
        ReputationConfig, ServerConfig, Settings, StorageConfig,
    };
    use std::collections::HashMap;

    fn base_settings() -> Settings {
        Settings {
            challenge: crate::config::settings::ChallengeConfig::default(),
            server: ServerConfig {
                listen: "[::]:443".into(),
                backend: "http://127.0.0.1:8443".into(),
                workers: 2,
                listeners: vec![ListenerConfig {
                    listen: "[::]:443".into(),
                    backend: "http://127.0.0.1:8443".into(),
                    tls: None,
                    routes: Vec::new(),
                }],
                trusted_proxies: Vec::new(),
                max_body_size: 1024,
            },
            reputation: ReputationConfig {
                base_score: 100,
                threshold_allow: 70,
                threshold_ratelimit: 40,
                threshold_challenge: 20,
                threshold_block: 0,
                decay_half_life_hours: 24.0,
                correlation_penalty_bonus: 10,
            },
            storage: StorageConfig {
                storage_type: "memory".into(),
                redis_url: None,
                path: None,
                cache_size: 1000,
            },
            geolocation: GeolocationConfig {
                enabled: true,
                database: None,
                penalties: HashMap::new(),
                country_dir: None,
                allow: Vec::new(),
                block: Vec::new(),
                sites: Vec::new(),
            },
            ratelimit: RateLimitConfig {
                normal_rpm: 1000,
                normal_burst: 100,
                suspicious_rpm: 200,
                suspicious_burst: 20,
                aggressive_rpm: 50,
                aggressive_burst: 5,
                window_duration_secs: 60,
            },
            logging: LoggingConfig { level: "info".into(), format: "json".into() },
            metrics: MetricsConfig { enabled: true, port: 9090 },
        }
    }

    fn change(host: &str) -> DomainChange {
        DomainChange { host: host.into(), ..Default::default() }
    }

    #[test]
    fn adds_route_to_all_listeners() {
        let mut s = base_settings();
        let mut c = change("App.Example.com");
        c.backend = Some("http://127.0.0.1:8082".into());
        apply_domain_change(&mut s, &c);
        assert_eq!(s.server.listeners[0].routes.len(), 1);
        assert_eq!(s.server.listeners[0].routes[0].server_name, "app.example.com");
        assert_eq!(s.server.listeners[0].routes[0].backend, "http://127.0.0.1:8082");
    }

    #[test]
    fn route_upsert_replaces_backend() {
        let mut s = base_settings();
        let mut c = change("app.example.com");
        c.backend = Some("http://127.0.0.1:1".into());
        apply_domain_change(&mut s, &c);
        c.backend = Some("http://127.0.0.1:2".into());
        apply_domain_change(&mut s, &c);
        assert_eq!(s.server.listeners[0].routes.len(), 1);
        assert_eq!(s.server.listeners[0].routes[0].backend, "http://127.0.0.1:2");
    }

    #[test]
    fn geo_allow_only_sets_rule() {
        let mut s = base_settings();
        let mut c = change("boutique.fr");
        c.geo_allow = Some(vec!["fr".into()]);
        apply_domain_change(&mut s, &c);
        assert_eq!(s.geolocation.sites.len(), 1);
        assert_eq!(s.geolocation.sites[0].server_name, "boutique.fr");
        assert_eq!(s.geolocation.sites[0].allow, vec!["FR"]);
    }

    #[test]
    fn geo_block_parses_comma_list() {
        let mut s = base_settings();
        let mut c = change("api.example.com");
        c.geo_block = Some(vec!["cn, ru".into(), "kp".into()]);
        apply_domain_change(&mut s, &c);
        assert_eq!(s.geolocation.sites[0].block, vec!["CN", "RU", "KP"]);
    }

    #[test]
    fn geo_flags_merge_on_existing_rule() {
        let mut s = base_settings();
        let mut c = change("x.example.com");
        c.geo_allow = Some(vec!["FR".into()]);
        apply_domain_change(&mut s, &c);
        // now add a block without touching allow
        let mut c2 = change("x.example.com");
        c2.geo_block = Some(vec!["CN".into()]);
        apply_domain_change(&mut s, &c2);
        let rule = &s.geolocation.sites[0];
        assert_eq!(rule.allow, vec!["FR"]);
        assert_eq!(rule.block, vec!["CN"]);
    }

    #[test]
    fn geo_clear_removes_rule() {
        let mut s = base_settings();
        let mut c = change("api.example.com");
        c.geo_block = Some(vec!["CN".into()]);
        apply_domain_change(&mut s, &c);
        let mut clear = change("api.example.com");
        clear.geo_clear = true;
        apply_domain_change(&mut s, &clear);
        assert!(s.geolocation.sites.is_empty());
    }

    fn db3() -> CountryDb {
        CountryDb::from_pairs(&[("fr", "90.114.0.0/16"), ("cn", "1.0.0.0/8")])
    }

    #[test]
    fn validate_rejects_unknown_allow_code() {
        let mut c = change("boutique.fr");
        c.geo_allow = Some(vec!["QQ".into()]);
        assert!(validate_codes(&db3(), &c).is_err());
    }

    #[test]
    fn validate_accepts_known_allow_code() {
        let mut c = change("boutique.fr");
        c.geo_allow = Some(vec!["fr".into()]);
        assert!(validate_codes(&db3(), &c).is_ok());
    }

    #[test]
    fn validate_warns_but_accepts_unknown_block_code() {
        let mut c = change("api.example.com");
        c.geo_block = Some(vec!["QQ".into()]);
        // Unknown block code is only a warning, not an error.
        assert!(validate_codes(&db3(), &c).is_ok());
    }

    #[test]
    fn validate_skips_on_empty_db() {
        let mut c = change("boutique.fr");
        c.geo_allow = Some(vec!["QQ".into()]);
        // No data loaded -> validation is skipped (cannot verify), never errors.
        assert!(validate_codes(&CountryDb::empty(), &c).is_ok());
    }

    #[test]
    fn remove_deletes_route_and_geo() {
        let mut s = base_settings();
        let mut c = change("app.example.com");
        c.backend = Some("http://127.0.0.1:8082".into());
        c.geo_block = Some(vec!["CN".into()]);
        apply_domain_change(&mut s, &c);
        let mut rm = change("app.example.com");
        rm.remove = true;
        apply_domain_change(&mut s, &rm);
        assert!(s.server.listeners[0].routes.is_empty());
        assert!(s.geolocation.sites.is_empty());
    }
}
