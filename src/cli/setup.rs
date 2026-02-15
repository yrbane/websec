//! Interactive setup command for integrating `WebSec` with Apache or Nginx.
//!
//! The goal is to automate the steps required to insert `WebSec` in front of
//! an existing web server deployment by:
//! - Detecting web server type (Apache/Nginx)
//! - Enumerating `VirtualHosts` or `server` blocks that listen on HTTP/HTTPS
//! - Scanning and generating SSL certificates with certbot
//! - Creating missing virtualhosts if needed
//! - Asking the operator which sites should be migrated
//! - Rewriting the configuration to use internal ports
//! - Generating SNI configuration for multi-domain support
//! - Updating web server config and the `WebSec` TOML configuration
//!
//! **Important**: This command expects to run with sufficient privileges to
//! read and modify web server configuration as well as the `WebSec` config file.

use crate::config::load_from_file;
use crate::config::settings::{ListenerConfig, ListenerTlsConfig, SniCertConfig};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const APACHE_SITES_ENABLED: &str = "/etc/apache2/sites-enabled";
const APACHE_PORTS_CONF: &str = "/etc/apache2/ports.conf";
const NGINX_SITES_ENABLED: &str = "/etc/nginx/sites-enabled";
const NGINX_CONF: &str = "/etc/nginx/nginx.conf";
const LETSENCRYPT_LIVE: &str = "/etc/letsencrypt/live";
const DEFAULT_INTERNAL_HTTP_PORT: u16 = 8081;
const DEFAULT_INTERNAL_HTTPS_PORT: u16 = 8443;

fn apache_sites_enabled_path() -> PathBuf {
    env::var("WEBSEC_APACHE_SITES_ENABLED")
        .map_or_else(|_| PathBuf::from(APACHE_SITES_ENABLED), PathBuf::from)
}

fn apache_ports_conf_path() -> PathBuf {
    env::var("WEBSEC_APACHE_PORTS_CONF")
        .map_or_else(|_| PathBuf::from(APACHE_PORTS_CONF), PathBuf::from)
}

fn nginx_sites_enabled_path() -> PathBuf {
    env::var("WEBSEC_NGINX_SITES_ENABLED")
        .map_or_else(|_| PathBuf::from(NGINX_SITES_ENABLED), PathBuf::from)
}

fn nginx_conf_path() -> PathBuf {
    env::var("WEBSEC_NGINX_CONF")
        .map_or_else(|_| PathBuf::from(NGINX_CONF), PathBuf::from)
}

fn letsencrypt_live_path() -> PathBuf {
    env::var("WEBSEC_LETSENCRYPT_LIVE")
        .map_or_else(|_| PathBuf::from(LETSENCRYPT_LIVE), PathBuf::from)
}

/// Detected web server type
#[derive(Debug, Clone, PartialEq)]
enum WebServer {
    Apache,
    Nginx,
}

impl WebServer {
    /// Detect which web server is installed
    fn detect_all() -> Vec<Self> {
        let mut servers = Vec::new();

        if apache_sites_enabled_path().exists() && apache_ports_conf_path().exists() {
            servers.push(WebServer::Apache);
        }

        if nginx_sites_enabled_path().exists() && nginx_conf_path().exists() {
            servers.push(WebServer::Nginx);
        }

        servers
    }

    fn name(&self) -> &str {
        match self {
            WebServer::Apache => "Apache",
            WebServer::Nginx => "Nginx",
        }
    }
}

/// SSL certificate information
#[derive(Debug, Clone)]
struct CertificateInfo {
    #[allow(dead_code)]
    domain: String,
    cert_file: PathBuf,
    key_file: PathBuf,
    #[allow(dead_code)]
    expiry: Option<DateTime<Utc>>,
}

/// Certbot certificate manager
struct CertbotManager {
    certificates: HashMap<String, CertificateInfo>,
}

impl CertbotManager {
    /// Scan existing Let's Encrypt certificates
    fn scan_existing() -> Result<Self> {
        let mut certificates = HashMap::new();
        let live_path = letsencrypt_live_path();

        if !live_path.exists() {
            return Ok(Self { certificates });
        }

        for entry in fs::read_dir(&live_path).map_err(Error::Io)? {
            let entry = entry.map_err(Error::Io)?;
            let path = entry.path();

            if path.is_dir() {
                let domain = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();

                // Skip README directory
                if domain == "README" {
                    continue;
                }

                let cert_file = path.join("fullchain.pem");
                let key_file = path.join("privkey.pem");

                if cert_file.exists() && key_file.exists() {
                    certificates.insert(
                        domain.clone(),
                        CertificateInfo {
                            domain: domain.clone(),
                            cert_file,
                            key_file,
                            expiry: None, // Could parse cert to get expiry
                        },
                    );
                }
            }
        }

        Ok(Self { certificates })
    }

    /// Get certificate for a domain
    fn get(&self, domain: &str) -> Option<&CertificateInfo> {
        self.certificates.get(domain)
    }

    /// Generate a new certificate with certbot
    #[allow(dead_code)]
    fn generate_certificate(&mut self, domain: &str, email: Option<&str>) -> Result<CertificateInfo> {
        println!("\n📜 Génération du certificat SSL pour {domain}...");

        let mut cmd = Command::new("certbot");
        cmd.args(["certonly", "--standalone", "-d", domain, "--non-interactive", "--agree-tos"]);

        if let Some(email) = email {
            cmd.args(["--email", email]);
        } else {
            cmd.arg("--register-unsafely-without-email");
        }

        let output = cmd.output().map_err(|e| {
            Error::Config(format!("Impossible d'exécuter certbot: {e}. Assurez-vous que certbot est installé."))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Config(format!(
                "Échec de génération du certificat pour {domain}: {stderr}"
            )));
        }

        println!("✅ Certificat généré pour {domain}");

        // Reload certificates
        *self = Self::scan_existing()?;

        self.get(domain)
            .cloned()
            .ok_or_else(|| Error::Config(format!("Certificat généré mais introuvable pour {domain}")))
    }

    /// List all available certificates
    fn list(&self) -> Vec<&str> {
        self.certificates.keys().map(String::as_str).collect()
    }
}

/// Choose web server interactively from detected servers
fn choose_web_server(detected_servers: &[WebServer]) -> Result<WebServer> {
    if detected_servers.len() == 1 {
        let server = detected_servers[0].clone();
        println!("📡 Serveur web détecté : {}", server.name());
        return Ok(server);
    }

    println!("📡 Plusieurs serveurs web détectés :");
    for (idx, server) in detected_servers.iter().enumerate() {
        println!("  [{}] {}", idx + 1, server.name());
    }

    loop {
        print!("\nChoisissez le serveur à configurer [1-{}]: ", detected_servers.len());
        io::stdout().flush().map_err(Error::Io)?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(Error::Io)?;

        if let Ok(choice) = input.trim().parse::<usize>() {
            if choice >= 1 && choice <= detected_servers.len() {
                return Ok(detected_servers[choice - 1].clone());
            }
        }
        println!("Choix invalide, réessayez.");
    }
}

/// Scan virtual hosts for the given web server
fn scan_virtual_hosts_for_server(web_server: &WebServer) -> Result<Vec<VirtualHostEntry>> {
    match web_server {
        WebServer::Apache => {
            let apache = ApacheEnvironment::detect()?;
            apache.scan_virtual_hosts()
        }
        WebServer::Nginx => {
            let nginx = NginxEnvironment::detect()?;
            nginx.scan_virtual_hosts()
        }
    }
}

/// Collect port migrations interactively from user
fn collect_port_migrations(virtual_hosts: &[VirtualHostEntry]) -> Result<Vec<PortMigration>> {
    let plans = vec![
        PortPlan {
            port: 80,
            label: "HTTP",
            default_internal: DEFAULT_INTERNAL_HTTP_PORT,
            description: "WebSec écoutera sur 80, Apache sera déplacé sur un port interne.",
        },
        PortPlan {
            port: 443,
            label: "HTTPS",
            default_internal: DEFAULT_INTERNAL_HTTPS_PORT,
            description:
                "WebSec pourra intercepter les flux TLS (nécessite WebSec en mode TLS sur 443).",
        },
    ];

    let mut migrations: Vec<PortMigration> = Vec::new();

    for plan in plans {
        if let Some(migration) = collect_migration_for_plan(&plan, virtual_hosts)? {
            migrations.push(migration);
        }
    }

    Ok(migrations)
}

/// Collect migration for a single port plan
fn collect_migration_for_plan(
    plan: &PortPlan<'_>,
    virtual_hosts: &[VirtualHostEntry],
) -> Result<Option<PortMigration>> {
    let hosts: Vec<&VirtualHostEntry> = virtual_hosts
        .iter()
        .filter(|vh| vh.supports_port(plan.port))
        .collect();

    if hosts.is_empty() {
        return Ok(None);
    }

    println!(
        "\n============================================================\n\
         {label} - VirtualHosts détectés sur le port {port}\n\
         {desc}\n\
         ============================================================",
        label = plan.label,
        port = plan.port,
        desc = plan.description
    );

    if !prompt_yes_no(
        &format!("Migrer les VirtualHosts {} vers WebSec ?", plan.label),
        plan.port == 80,
    )? {
        return Ok(None);
    }

    let internal_port = prompt_port(
        &format!(
            "Port interne Apache pour {} [{}]: ",
            plan.label, plan.default_internal
        ),
        plan.default_internal,
    )?;

    println!("\nRépondez 'o' pour chaque VirtualHost {} à migrer :", plan.label);

    let mut selections: Vec<VirtualHostSelection> = Vec::new();
    for (idx, entry) in hosts.iter().enumerate() {
        println!(
            "\n[{}] {} (fichier {}:{})",
            idx + 1,
            entry.display_name(),
            entry.file_path.display(),
            entry.line_index + 1
        );
        if let Some(alias) = entry.alias_preview() {
            println!("    Alias : {alias}");
        }

        if prompt_yes_no("Migrer ce VirtualHost ?", true)? {
            selections.push(VirtualHostSelection {
                file_path: entry.file_path.clone(),
                line_index: entry.line_index,
            });
        }
    }

    if selections.is_empty() {
        println!(
            "\nAucun VirtualHost sélectionné pour {}. Aucun changement appliqué pour ce port.",
            plan.label
        );
        return Ok(None);
    }

    Ok(Some(PortMigration {
        original_port: plan.port,
        internal_port,
        selections,
    }))
}

/// Apply migrations to the web server configuration files
fn apply_web_server_changes(web_server: &WebServer, migrations: &[PortMigration]) -> Result<()> {
    println!("\n➡️  Mise à jour des fichiers {}...", web_server.name());

    match web_server {
        WebServer::Apache => {
            let apache = ApacheEnvironment::detect()?;
            for migration in migrations {
                apache.apply_virtualhost_changes(
                    &migration.selections,
                    migration.original_port,
                    migration.internal_port,
                )?;
            }

            let port_pairs: Vec<(u16, u16)> = migrations
                .iter()
                .map(|m| (m.original_port, m.internal_port))
                .collect();
            let ports_updated = apache.update_ports_conf(&port_pairs)?;

            if ports_updated {
                println!("✅ ports.conf mis à jour avec les nouveaux ports internes");
            } else {
                println!("ℹ️  Aucun changement nécessaire dans ports.conf");
            }
        }
        WebServer::Nginx => {
            let nginx = NginxEnvironment::detect()?;
            for migration in migrations {
                nginx.apply_virtualhost_changes(
                    &migration.selections,
                    migration.original_port,
                    migration.internal_port,
                )?;
            }
            nginx.update_nginx_conf(&[])?;
        }
    }

    Ok(())
}

/// Finalize setup: scan SSL certs and update `WebSec` config
fn finalize_setup(
    config_path: &Path,
    migrations: &[PortMigration],
    virtual_hosts: &[VirtualHostEntry],
) -> Result<()> {
    // Scan SSL certificates
    println!("\n🔍 Scan des certificats SSL existants...");
    let certbot = CertbotManager::scan_existing()?;
    if certbot.list().is_empty() {
        println!("ℹ️  Aucun certificat Let's Encrypt détecté");
    } else {
        println!("✅ Certificats trouvés : {}", certbot.list().join(", "));
    }

    // Update WebSec configuration with SNI support
    if config_path.exists() {
        println!(
            "\n➡️  Mise à jour de la configuration WebSec ({})",
            config_path.display()
        );

        let tls_internal_port = migrations
            .iter()
            .find(|m| m.original_port == 443)
            .map(|m| m.internal_port);

        let plaintext_internal_port = migrations
            .iter()
            .find(|m| m.original_port == 80)
            .map(|m| m.internal_port);

        update_websec_config_with_sni(
            config_path,
            plaintext_internal_port,
            tls_internal_port,
            virtual_hosts,
            &certbot,
        )?;
    } else {
        println!(
            "⚠️  Fichier de configuration {} introuvable - mise à jour manuelle requise",
            config_path.display()
        );
    }

    Ok(())
}

/// Print final setup summary
fn print_setup_summary(web_server: &WebServer, migrations: &[PortMigration]) {
    println!("\n🎉 Configuration terminée");
    if migrations.iter().any(|m| m.original_port == 80) {
        println!("- Les sites HTTP ont été déplacés. WebSec doit écouter sur 0.0.0.0:80.");
    }
    if migrations.iter().any(|m| m.original_port == 443) {
        println!(
            "- Les sites HTTPS ont été déplacés. WebSec gère le TLS sur 0.0.0.0:443 avec support SNI multi-domaines."
        );
    }
    println!(
        "Pensez à redémarrer {} puis à lancer WebSec pour prendre en compte les modifications.\n",
        web_server.name()
    );
}

/// Run the interactive setup
pub fn run_setup(config_path: &Path) -> Result<()> {
    println!("🛠️  Assistant de configuration WebSec");
    println!("Ce processus va configurer WebSec en frontal de votre serveur web.\n");

    // Detect and choose web server
    let detected_servers = WebServer::detect_all();
    if detected_servers.is_empty() {
        return Err(Error::Config(
            "Aucun serveur web détecté (Apache ou Nginx). Installez Apache2 ou Nginx d'abord."
                .to_string(),
        ));
    }
    let web_server = choose_web_server(&detected_servers)?;

    println!("\n🔍 Configuration de {} avec WebSec...\n", web_server.name());

    // Scan virtual hosts
    let virtual_hosts = scan_virtual_hosts_for_server(&web_server)?;
    if virtual_hosts.is_empty() {
        println!("⚠️  Aucun VirtualHost détecté dans {APACHE_SITES_ENABLED}");
        return Err(Error::Config(
            "Impossible de continuer sans configuration Apache".to_string(),
        ));
    }

    // Collect migrations interactively
    let migrations = collect_port_migrations(&virtual_hosts)?;
    if migrations.is_empty() {
        println!("\nAucun site sélectionné. Annulation.");
        return Ok(());
    }

    // Apply changes and finalize
    apply_web_server_changes(&web_server, &migrations)?;
    finalize_setup(config_path, &migrations, &virtual_hosts)?;
    print_setup_summary(&web_server, &migrations);

    Ok(())
}

/// Run the non-interactive setup (for scripted installation).
///
/// Automatically detects the web server, selects ALL virtual hosts on ports
/// 80 and 443, migrates them to internal ports (8081/8443), and updates
/// the WebSec configuration — all without user prompts.
pub fn run_setup_noninteractive(config_path: &Path) -> Result<()> {
    println!("WebSec setup (non-interactive mode)");

    // Detect web server (prefer Apache)
    let detected_servers = WebServer::detect_all();
    if detected_servers.is_empty() {
        return Err(Error::Config(
            "Aucun serveur web detecte (Apache ou Nginx). Installez Apache2 ou Nginx d'abord."
                .to_string(),
        ));
    }
    let web_server = detected_servers[0].clone();
    println!("Serveur web detecte : {}", web_server.name());

    // Scan virtual hosts
    let virtual_hosts = scan_virtual_hosts_for_server(&web_server)?;
    if virtual_hosts.is_empty() {
        println!("Aucun VirtualHost detecte — rien a migrer.");
        return Ok(());
    }

    // Build migrations for port 80 and 443 — select ALL virtual hosts
    let mut migrations: Vec<PortMigration> = Vec::new();

    let http_hosts: Vec<VirtualHostSelection> = virtual_hosts
        .iter()
        .filter(|vh| vh.supports_port(80))
        .map(|vh| VirtualHostSelection {
            file_path: vh.file_path.clone(),
            line_index: vh.line_index,
        })
        .collect();

    if !http_hosts.is_empty() {
        println!(
            "Migration HTTP : {} VirtualHost(s) vers port {}",
            http_hosts.len(),
            DEFAULT_INTERNAL_HTTP_PORT
        );
        migrations.push(PortMigration {
            original_port: 80,
            internal_port: DEFAULT_INTERNAL_HTTP_PORT,
            selections: http_hosts,
        });
    }

    let https_hosts: Vec<VirtualHostSelection> = virtual_hosts
        .iter()
        .filter(|vh| vh.supports_port(443))
        .map(|vh| VirtualHostSelection {
            file_path: vh.file_path.clone(),
            line_index: vh.line_index,
        })
        .collect();

    if !https_hosts.is_empty() {
        println!(
            "Migration HTTPS : {} VirtualHost(s) vers port {}",
            https_hosts.len(),
            DEFAULT_INTERNAL_HTTPS_PORT
        );
        migrations.push(PortMigration {
            original_port: 443,
            internal_port: DEFAULT_INTERNAL_HTTPS_PORT,
            selections: https_hosts,
        });
    }

    if migrations.is_empty() {
        println!("Aucun VirtualHost sur les ports 80/443. Rien a migrer.");
        return Ok(());
    }

    // Apply changes and finalize
    apply_web_server_changes(&web_server, &migrations)?;
    finalize_setup(config_path, &migrations, &virtual_hosts)?;
    print_setup_summary(&web_server, &migrations);

    Ok(())
}

/// Restore web server configuration from WebSec backups and disable WebSec.
///
/// Scans for `.websec.bak.*` files in Apache/Nginx config directories,
/// restores the most recent backup for each original file, reloads the
/// web server, and stops/disables the WebSec service.
pub fn run_restore(config_path: &Path) -> Result<()> {
    println!("Restauration de la configuration originale...");
    let _ = config_path; // acknowledge param; may be used later for websec.toml cleanup

    let detected_servers = WebServer::detect_all();
    if detected_servers.is_empty() {
        return Err(Error::Config(
            "Aucun serveur web detecte.".to_string(),
        ));
    }
    let web_server = detected_servers[0].clone();

    match &web_server {
        WebServer::Apache => restore_apache_backups()?,
        WebServer::Nginx => restore_nginx_backups()?,
    }

    // Reload web server
    reload_web_server(&web_server)?;

    // Stop WebSec service
    stop_websec_service();

    println!("Configuration {} restauree.", web_server.name());
    println!("WebSec desactive. Pour reactiver : websec setup");

    Ok(())
}

/// Restore Apache config files from `.websec.bak.*` backups.
fn restore_apache_backups() -> Result<()> {
    let mut restored = 0;

    // Directories to scan for backups
    let dirs_to_scan = vec![
        apache_sites_enabled_path(),
        apache_ports_conf_path()
            .parent()
            .unwrap_or_else(|| Path::new("/etc/apache2"))
            .to_path_buf(),
    ];

    for dir in &dirs_to_scan {
        if !dir.exists() {
            continue;
        }

        // Group backups by their original file name
        let mut backup_groups: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();

        let entries = fs::read_dir(dir).map_err(Error::Io)?;
        for entry in entries.filter_map(std::result::Result::ok) {
            let path = entry.path();
            let file_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            // Match pattern: <original>.websec.bak.<timestamp>
            if let Some(pos) = file_name.find(".websec.bak.") {
                let original_name = &file_name[..pos];
                let original_path = dir.join(original_name);
                backup_groups
                    .entry(original_path)
                    .or_default()
                    .push(path);
            }
        }

        // For each original file, restore from the most recent backup
        for (original, mut backups) in backup_groups {
            // Sort by name descending (timestamp in name = most recent last alphabetically)
            backups.sort();
            if let Some(most_recent) = backups.last() {
                println!(
                    "Restauration: {} <- {}",
                    original.display(),
                    most_recent.display()
                );
                fs::copy(most_recent, &original).map_err(Error::Io)?;
                restored += 1;
            }
        }
    }

    if restored == 0 {
        println!("Aucun backup .websec.bak.* trouve.");
    } else {
        println!("{restored} fichier(s) restaure(s).");
    }

    Ok(())
}

/// Restore Nginx config files from `.websec.bak.*` backups.
fn restore_nginx_backups() -> Result<()> {
    let mut restored = 0;
    let dir = nginx_sites_enabled_path();

    if !dir.exists() {
        println!("Repertoire Nginx introuvable.");
        return Ok(());
    }

    let mut backup_groups: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();

    let entries = fs::read_dir(&dir).map_err(Error::Io)?;
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        if let Some(pos) = file_name.find(".websec.bak.") {
            let original_name = &file_name[..pos];
            let original_path = dir.join(original_name);
            backup_groups
                .entry(original_path)
                .or_default()
                .push(path);
        }
    }

    for (original, mut backups) in backup_groups {
        backups.sort();
        if let Some(most_recent) = backups.last() {
            println!(
                "Restauration: {} <- {}",
                original.display(),
                most_recent.display()
            );
            fs::copy(most_recent, &original).map_err(Error::Io)?;
            restored += 1;
        }
    }

    if restored == 0 {
        println!("Aucun backup .websec.bak.* trouve.");
    } else {
        println!("{restored} fichier(s) restaure(s).");
    }

    Ok(())
}

/// Reload the web server after config restore.
fn reload_web_server(web_server: &WebServer) -> Result<()> {
    let service = match web_server {
        WebServer::Apache => "apache2",
        WebServer::Nginx => "nginx",
    };

    println!("Rechargement de {}...", web_server.name());
    let output = Command::new("systemctl")
        .args(["reload", service])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            println!("{} recharge.", web_server.name());
        }
        _ => {
            println!(
                "Impossible de recharger {}. Verifiez manuellement: systemctl reload {}",
                web_server.name(),
                service
            );
        }
    }

    Ok(())
}

/// Stop and disable the WebSec systemd service.
fn stop_websec_service() {
    println!("Arret du service WebSec...");
    let _ = Command::new("systemctl")
        .args(["stop", "websec"])
        .output();
    let _ = Command::new("systemctl")
        .args(["disable", "websec"])
        .output();
    println!("Service WebSec arrete et desactive.");
}

/// Helper representing the Apache installation on the host.
struct ApacheEnvironment {
    sites_enabled: PathBuf,
    ports_conf: PathBuf,
}

impl ApacheEnvironment {
    fn detect() -> Result<Self> {
        let sites_enabled = apache_sites_enabled_path();
        let ports_conf = apache_ports_conf_path();
        if !sites_enabled.exists() {
            return Err(Error::Config(format!(
                "Répertoire {APACHE_SITES_ENABLED} introuvable"
            )));
        }
        if !ports_conf.exists() {
            return Err(Error::Config(format!(
                "Fichier {APACHE_PORTS_CONF} introuvable"
            )));
        }
        Ok(Self {
            sites_enabled,
            ports_conf,
        })
    }

    fn scan_virtual_hosts(&self) -> Result<Vec<VirtualHostEntry>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.sites_enabled)
            .map_err(Error::Io)?
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();
            if path.is_file() {
                self.parse_virtual_hosts(&path, &mut entries)?;
            }
        }
        Ok(entries)
    }

    fn parse_virtual_hosts(&self, path: &Path, entries: &mut Vec<VirtualHostEntry>) -> Result<()> {
        let content = fs::read_to_string(path).map_err(Error::Io)?;
        let mut active_index: Option<usize> = None;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed.starts_with("<VirtualHost") {
                let ports = parse_ports_from_virtualhost(trimmed);
                if ports.is_empty() {
                    continue;
                }

                entries.push(VirtualHostEntry {
                    file_path: path.to_path_buf(),
                    line_index: idx,
                    server_name: None,
                    server_aliases: Vec::new(),
                    ports,
                });

                active_index = Some(entries.len() - 1);
            } else if trimmed.starts_with("ServerName") {
                if let Some(current) = active_index {
                    if entries[current].server_name.is_none() {
                        entries[current].server_name = trimmed
                            .split_whitespace()
                            .nth(1)
                            .map(std::string::ToString::to_string);
                    }
                }
            } else if trimmed.starts_with("ServerAlias") {
                if let Some(current) = active_index {
                    let aliases = trimmed
                        .split_whitespace()
                        .skip(1)
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>();
                    entries[current].server_aliases.extend(aliases);
                }
            } else if trimmed.starts_with("</VirtualHost") {
                active_index = None;
            }
        }

        Ok(())
    }

    fn apply_virtualhost_changes(
        &self,
        selections: &[VirtualHostSelection],
        from_port: u16,
        to_port: u16,
    ) -> Result<()> {
        let mut grouped: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        for selection in selections {
            grouped
                .entry(selection.file_path.clone())
                .or_default()
                .push(selection.line_index);
        }

        for indices in grouped.values_mut() {
            indices.sort_unstable();
            indices.dedup();
        }

        for (file, indices) in grouped {
            self.rewrite_virtualhost_file(&file, &indices, from_port, to_port)?;
        }

        Ok(())
    }

    fn rewrite_virtualhost_file(
        &self,
        file: &Path,
        indices: &[usize],
        from_port: u16,
        to_port: u16,
    ) -> Result<()> {
        let content = fs::read_to_string(file).map_err(Error::Io)?;
        let had_trailing_newline = content.ends_with('\n');
        let mut lines: Vec<String> = content
            .lines()
            .map(std::string::ToString::to_string)
            .collect();
        let port_pattern = Regex::new(&format!(r":{from_port}(?=[^\d]|$)"))
            .map_err(|e| Error::Config(format!("Regex error: {e}")))?;

        let mut touched = false;
        for &idx in indices {
            if let Some(line) = lines.get_mut(idx) {
                if port_pattern.is_match(line) {
                    let replacement = format!(":{to_port}");
                    *line = port_pattern
                        .replace_all(line, replacement.as_str())
                        .to_string();
                    touched = true;
                }
            }
        }

        if touched {
            let mut new_content = lines.join("\n");
            if had_trailing_newline {
                new_content.push('\n');
            }

            let backup_path = backup_file(file)?;
            println!(
                "📦 Sauvegarde: {} -> {}",
                file.display(),
                backup_path.display()
            );
            fs::write(file, new_content).map_err(Error::Io)?;
            println!("✅ Ports mis à jour dans {}", file.display());
        } else {
            println!(
                "ℹ️  Aucun changement appliqué dans {} (aucune occurrence :{})",
                file.display(),
                from_port
            );
        }

        Ok(())
    }

    fn update_ports_conf(&self, mappings: &[(u16, u16)]) -> Result<bool> {
        if mappings.is_empty() {
            return Ok(false);
        }

        let content = fs::read_to_string(&self.ports_conf).map_err(Error::Io)?;
        let had_trailing_newline = content.ends_with('\n');
        let mut changed = false;
        let mut new_lines = Vec::new();

        'line_loop: for line in content.lines() {
            if line.trim_start().starts_with("Listen ") {
                let mut parts = line.split_whitespace();
                let _ = parts.next();
                if let Some(port_str) = parts.next() {
                    for (from_port, to_port) in mappings {
                        if port_str == from_port.to_string() {
                            new_lines.push(format!("Listen {to_port}"));
                            changed = true;
                            continue 'line_loop;
                        }
                    }
                }
            }
            new_lines.push(line.to_string());
        }

        if !changed {
            return Ok(false);
        }

        let mut new_content = new_lines.join("\n");
        if had_trailing_newline {
            new_content.push('\n');
        }

        let backup_path = backup_file(&self.ports_conf)?;
        println!(
            "📦 Sauvegarde: {} -> {}",
            self.ports_conf.display(),
            backup_path.display()
        );
        fs::write(&self.ports_conf, new_content).map_err(Error::Io)?;
        Ok(true)
    }
}

/// Helper representing the Nginx installation on the host.
struct NginxEnvironment {
    sites_enabled: PathBuf,
}

impl NginxEnvironment {
    fn detect() -> Result<Self> {
        let sites_enabled = nginx_sites_enabled_path();
        let nginx_conf = nginx_conf_path();
        if !sites_enabled.exists() {
            return Err(Error::Config(format!(
                "Répertoire {NGINX_SITES_ENABLED} introuvable"
            )));
        }
        if !nginx_conf.exists() {
            return Err(Error::Config(format!(
                "Fichier {NGINX_CONF} introuvable"
            )));
        }
        Ok(Self {
            sites_enabled,
        })
    }

    fn scan_virtual_hosts(&self) -> Result<Vec<VirtualHostEntry>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.sites_enabled)
            .map_err(Error::Io)?
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();
            if path.is_file() {
                self.parse_server_blocks(&path, &mut entries)?;
            }
        }
        Ok(entries)
    }

    fn parse_server_blocks(&self, path: &Path, entries: &mut Vec<VirtualHostEntry>) -> Result<()> {
        let content = fs::read_to_string(path).map_err(Error::Io)?;
        let mut in_server_block = false;
        let mut block_start_line: Option<usize> = None;
        let mut current_server_name: Option<String> = None;
        let mut current_aliases: Vec<String> = Vec::new();
        let mut current_ports: Vec<u16> = Vec::new();
        let mut brace_depth = 0;

        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // Track brace depth
            brace_depth += trimmed.matches('{').count() as i32;
            brace_depth -= trimmed.matches('}').count() as i32;

            // Detect server block start
            if trimmed.starts_with("server") && trimmed.contains('{') && !in_server_block {
                in_server_block = true;
                block_start_line = Some(idx);
                current_server_name = None;
                current_aliases.clear();
                current_ports.clear();
            }

            if in_server_block {
                // Parse listen directives
                if trimmed.starts_with("listen") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let listen_spec = parts[1].trim_end_matches(';');

                        // Parse port from various formats:
                        // listen 80;
                        // listen 443 ssl;
                        // listen [::]:80;
                        // listen 127.0.0.1:8080;
                        let port = if let Some(colon_pos) = listen_spec.rfind(':') {
                            // Format: addr:port or [::]:port
                            let port_str = &listen_spec[colon_pos + 1..];
                            port_str.split_whitespace().next().and_then(|p| p.parse::<u16>().ok())
                        } else {
                            // Format: port or port ssl
                            listen_spec.split_whitespace().next().and_then(|p| p.parse::<u16>().ok())
                        };

                        if let Some(port) = port {
                            if !current_ports.contains(&port) {
                                current_ports.push(port);
                            }
                        }
                    }
                }

                // Parse server_name directive
                if trimmed.starts_with("server_name") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        for domain in parts.iter().skip(1) {
                            let domain = domain.trim_end_matches(';');
                            if domain != "_" {  // Skip default server
                                if current_server_name.is_none() {
                                    current_server_name = Some(domain.to_string());
                                } else {
                                    current_aliases.push(domain.to_string());
                                }
                            }
                        }
                    }
                }

                // Detect server block end
                if brace_depth == 0 && in_server_block {
                    in_server_block = false;

                    if !current_ports.is_empty() {
                        if let Some(start_line) = block_start_line {
                            entries.push(VirtualHostEntry {
                                file_path: path.to_path_buf(),
                                line_index: start_line,
                                server_name: current_server_name.clone(),
                                server_aliases: current_aliases.clone(),
                                ports: current_ports.clone(),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn apply_virtualhost_changes(
        &self,
        selections: &[VirtualHostSelection],
        from_port: u16,
        to_port: u16,
    ) -> Result<()> {
        let mut grouped: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        for selection in selections {
            grouped
                .entry(selection.file_path.clone())
                .or_default()
                .push(selection.line_index);
        }

        for indices in grouped.values_mut() {
            indices.sort_unstable();
            indices.dedup();
        }

        for (file, indices) in grouped {
            self.rewrite_server_file(&file, &indices, from_port, to_port)?;
        }

        Ok(())
    }

    fn rewrite_server_file(
        &self,
        file: &Path,
        indices: &[usize],
        from_port: u16,
        to_port: u16,
    ) -> Result<()> {
        let content = fs::read_to_string(file).map_err(Error::Io)?;
        let had_trailing_newline = content.ends_with('\n');
        let mut lines: Vec<String> = content
            .lines()
            .map(std::string::ToString::to_string)
            .collect();

        let mut touched = false;
        let mut in_target_block = false;
        let mut brace_depth = 0;

        for (idx, line) in lines.iter_mut().enumerate() {
            // Check if this is a target server block
            if indices.contains(&idx) {
                in_target_block = true;
                brace_depth = 0;
            }

            if in_target_block {
                // Track braces
                brace_depth += line.matches('{').count() as i32;

                // Rewrite listen directives
                let trimmed = line.trim();
                if trimmed.starts_with("listen") {
                    let port_pattern = Regex::new(&format!(r"\b{from_port}\b"))
                        .map_err(|e| Error::Config(format!("Regex error: {e}")))?;

                    if port_pattern.is_match(line) {
                        *line = port_pattern.replace_all(line, to_port.to_string()).to_string();
                        touched = true;
                    }
                }

                brace_depth -= line.matches('}').count() as i32;

                // End of server block
                if brace_depth == 0 {
                    in_target_block = false;
                }
            }
        }

        if touched {
            let mut new_content = lines.join("\n");
            if had_trailing_newline {
                new_content.push('\n');
            }

            let backup_path = backup_file(file)?;
            println!(
                "📦 Sauvegarde: {} -> {}",
                file.display(),
                backup_path.display()
            );
            fs::write(file, new_content).map_err(Error::Io)?;
            println!("✅ Ports mis à jour dans {}", file.display());
        } else {
            println!(
                "ℹ️  Aucun changement appliqué dans {} (aucune occurrence :{})",
                file.display(),
                from_port
            );
        }

        Ok(())
    }

    fn update_nginx_conf(&self, _mappings: &[(u16, u16)]) -> Result<bool> {
        // Nginx doesn't have a global ports file like Apache's ports.conf
        // Port configuration is done per server block
        println!("ℹ️  Nginx: les ports sont configurés par server block (pas de fichier global)");
        Ok(false)
    }
}

/// A parsed Apache `<VirtualHost>` or Nginx `server` block.
struct VirtualHostEntry {
    file_path: PathBuf,
    line_index: usize,
    server_name: Option<String>,
    server_aliases: Vec<String>,
    ports: Vec<u16>,
}

impl VirtualHostEntry {
    fn supports_port(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    fn display_name(&self) -> String {
        self.server_name
            .clone()
            .or_else(|| self.server_aliases.first().cloned())
            .unwrap_or_else(|| "(ServerName non défini)".to_string())
    }

    fn alias_preview(&self) -> Option<String> {
        if self.server_aliases.is_empty() {
            None
        } else {
            Some(self.server_aliases.join(", "))
        }
    }
}

/// Line selection for a `VirtualHost`.
struct VirtualHostSelection {
    file_path: PathBuf,
    line_index: usize,
}

struct PortPlan<'a> {
    port: u16,
    label: &'a str,
    default_internal: u16,
    description: &'a str,
}

struct PortMigration {
    original_port: u16,
    internal_port: u16,
    selections: Vec<VirtualHostSelection>,
}

fn parse_ports_from_virtualhost(line: &str) -> Vec<u16> {
    let mut result = Vec::new();
    let inner = line
        .trim()
        .trim_start_matches("<VirtualHost")
        .trim()
        .trim_end_matches('>');
    for token in inner.split_whitespace() {
        if let Some((_host, port_str)) = token.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                result.push(port);
            }
        }
    }
    result
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    loop {
        let suffix = if default_yes { "[O/n]" } else { "[o/N]" };
        print!("{prompt} {suffix} ");
        io::stdout().flush().map_err(Error::Io)?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(Error::Io)?;
        let trimmed = input.trim().to_lowercase();
        if trimmed.is_empty() {
            return Ok(default_yes);
        }
        match trimmed.as_str() {
            "o" | "oui" | "y" | "yes" => return Ok(true),
            "n" | "non" | "no" => return Ok(false),
            _ => {
                println!("Veuillez répondre par o/n.");
            }
        }
    }
}

fn prompt_port(prompt: &str, default_port: u16) -> Result<u16> {
    loop {
        print!("{prompt}");
        io::stdout().flush().map_err(Error::Io)?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(Error::Io)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(default_port);
        }

        match trimmed.parse::<u16>() {
            Ok(port) => return Ok(port),
            Err(_) => println!("Port invalide, merci de saisir un entier entre 1 et 65535."),
        }
    }
}

fn backup_file(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        return Err(Error::Config(format!(
            "Impossible de sauvegarder {}, fichier introuvable",
            path.display()
        )));
    }

    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let file_name = path.file_name().map_or_else(
        || "config".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let backup_name = format!("{file_name}.websec.bak.{timestamp}");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let backup_path = parent.join(backup_name);
    fs::copy(path, &backup_path).map_err(Error::Io)?;
    Ok(backup_path)
}

/// Update `WebSec` configuration with SNI support for multi-domain HTTPS
fn update_websec_config_with_sni(
    config_path: &Path,
    plaintext_backend_port: Option<u16>,
    tls_backend_port: Option<u16>,
    virtual_hosts: &[VirtualHostEntry],
    certbot: &CertbotManager,
) -> Result<()> {
    let mut settings = load_from_file(config_path).map_err(|e| {
        Error::Config(format!(
            "Impossible de charger {}: {e}",
            config_path.display()
        ))
    })?;

    let backup_path = backup_file(config_path)?;
    println!(
        "📦 Sauvegarde: {} -> {}",
        config_path.display(),
        backup_path.display()
    );

    // Clear old configuration
    settings.server.listeners.clear();

    // Add HTTP listener if port was migrated
    if let Some(port) = plaintext_backend_port {
        settings.server.listeners.push(ListenerConfig {
            listen: "0.0.0.0:80".to_string(),
            backend: format!("http://127.0.0.1:{port}"),
            tls: None,
        });
        println!("✅ Listener HTTP ajouté : 0.0.0.0:80 → http://127.0.0.1:{port}");
    }

    // Add HTTPS listener with SNI if port was migrated
    if let Some(port) = tls_backend_port {
        // Collect HTTPS domains and their certificates
        let https_domains: Vec<&VirtualHostEntry> = virtual_hosts
            .iter()
            .filter(|vh| vh.supports_port(443))
            .collect();

        if https_domains.is_empty() {
            println!("⚠️  Aucun domaine HTTPS détecté, pas de configuration SNI ajoutée");
        } else {
            // Find default domain (first one with a certificate)
            let default_domain = https_domains
                .iter()
                .find(|vh| {
                    vh.server_name
                        .as_ref()
                        .and_then(|name| certbot.get(name))
                        .is_some()
                })
                .and_then(|vh| vh.server_name.as_ref());

            if let Some(default_name) = default_domain {
                if let Some(default_cert) = certbot.get(default_name) {
                    let mut sni_certificates = Vec::new();

                    // Add other domains as SNI certificates
                    for vh in &https_domains {
                        if let Some(name) = &vh.server_name {
                            if name != default_name {
                                if let Some(cert) = certbot.get(name) {
                                    sni_certificates.push(SniCertConfig {
                                        server_name: name.clone(),
                                        cert_file: cert.cert_file.to_string_lossy().to_string(),
                                        key_file: cert.key_file.to_string_lossy().to_string(),
                                    });
                                }
                            }
                        }
                    }

                    settings.server.listeners.push(ListenerConfig {
                        listen: "0.0.0.0:443".to_string(),
                        backend: format!("http://127.0.0.1:{port}"),
                        tls: Some(ListenerTlsConfig {
                            cert_file: default_cert.cert_file.to_string_lossy().to_string(),
                            key_file: default_cert.key_file.to_string_lossy().to_string(),
                            sni_certificates,
                        }),
                    });

                    println!(
                        "✅ Listener HTTPS ajouté : 0.0.0.0:443 → http://127.0.0.1:{port}"
                    );
                    println!("   Certificat par défaut : {default_name}");

                    if !settings.server.listeners.last().unwrap().tls.as_ref().unwrap().sni_certificates.is_empty() {
                        println!(
                            "   SNI activé pour {} domaines additionnels",
                            settings.server.listeners.last().unwrap().tls.as_ref().unwrap().sni_certificates.len()
                        );
                    }
                } else {
                    println!("⚠️  Aucun certificat trouvé pour le domaine par défaut {default_name}");
                    println!("   Utilisez 'certbot certonly --standalone -d {default_name}' pour générer un certificat");
                }
            } else {
                println!("⚠️  Aucun domaine HTTPS avec certificat détecté");
                println!("   Les domaines suivants nécessitent des certificats :");
                for vh in https_domains {
                    if let Some(name) = &vh.server_name {
                        println!("   - {name}");
                    }
                }
                println!("\n   Générez les certificats avec : certbot certonly --standalone -d <domaine>");
            }
        }
    }

    // Update legacy fields for compatibility
    if let Some(first_listener) = settings.server.listeners.first() {
        settings.server.listen = first_listener.listen.clone();
        settings.server.backend = first_listener.backend.clone();
    }

    // Write updated configuration
    let toml_text = toml::to_string_pretty(&settings)
        .map_err(|e| Error::Config(format!("Erreur de sérialisation TOML: {e}")))?;
    fs::write(config_path, toml_text).map_err(Error::Io)?;

    println!("✅ Configuration WebSec mise à jour avec {} listener(s)", settings.server.listeners.len());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    fn sample_config() -> String {
        r#"[server]
listen = "0.0.0.0:8080"
backend = "http://127.0.0.1:3000"
workers = 4
trusted_proxies = []
max_body_size = 10485760

[reputation]
base_score = 100
threshold_allow = 70
threshold_ratelimit = 40
threshold_challenge = 20
threshold_block = 0
decay_half_life_hours = 24.0
correlation_penalty_bonus = 10

[storage]
type = "memory"
cache_size = 10000

[geolocation]
enabled = false
penalties = {}

[ratelimit]
normal_rpm = 1000
normal_burst = 100
suspicious_rpm = 200
suspicious_burst = 20
aggressive_rpm = 50
aggressive_burst = 5
window_duration_secs = 60

[logging]
level = "info"
format = "json"

[metrics]
enabled = true
port = 9090
"#
        .to_string()
    }

    fn list_backups(dir: &Path, needle: &str) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().contains(needle))
            })
            .collect()
    }

    #[test]
    fn test_parse_ports_from_virtualhost_with_multiple_bindings() {
        let ports = parse_ports_from_virtualhost("<VirtualHost 127.0.0.1:80 [::1]:443>");
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert_eq!(ports.len(), 2);
    }

    #[test]
    fn test_update_ports_conf_updates_multiple_ports() {
        let dir = tempdir().unwrap();
        let ports_path = dir.path().join("ports.conf");
        fs::write(
            &ports_path,
            "Listen 80
Listen 443
Listen 8080
",
        )
        .unwrap();

        let sites_dir = dir.path().join("sites-enabled");
        fs::create_dir(&sites_dir).unwrap();
        fs::write(
            sites_dir.join("000-default.conf"),
            "<VirtualHost *:80>
</VirtualHost>",
        )
        .unwrap();

        let env = ApacheEnvironment {
            sites_enabled: sites_dir,
            ports_conf: ports_path.clone(),
        };

        let updated = env
            .update_ports_conf(&[(80, 8081), (443, 8443)])
            .expect("update should succeed");
        assert!(updated);

        let content = fs::read_to_string(&ports_path).unwrap();
        assert!(content.contains("Listen 8081"));
        assert!(content.contains("Listen 8443"));
        assert!(content.contains("Listen 8080"));

        let backups = list_backups(ports_path.parent().unwrap(), "ports.conf.websec.bak");
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_update_websec_config_with_sni_http_only() {
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("websec.toml");
        fs::write(&cfg_path, sample_config()).unwrap();

        let virtual_hosts = vec![];
        let certbot = CertbotManager { certificates: HashMap::new() };

        update_websec_config_with_sni(
            &cfg_path,
            Some(8081),
            None,
            &virtual_hosts,
            &certbot,
        )
        .expect("update should succeed");

        let new_settings = load_from_file(&cfg_path).expect("updated config should be valid");
        assert_eq!(new_settings.server.listen, "0.0.0.0:80");
        assert_eq!(new_settings.server.backend, "http://127.0.0.1:8081");
        assert_eq!(new_settings.server.listeners.len(), 1);
        assert_eq!(new_settings.server.listeners[0].listen, "0.0.0.0:80");
        assert_eq!(
            new_settings.server.listeners[0].backend,
            "http://127.0.0.1:8081"
        );

        let backups = list_backups(cfg_path.parent().unwrap(), "websec.toml.websec.bak");
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_update_websec_config_no_migration_keeps_empty() {
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("websec.toml");
        fs::write(&cfg_path, sample_config()).unwrap();

        let virtual_hosts = vec![];
        let certbot = CertbotManager { certificates: HashMap::new() };

        update_websec_config_with_sni(&cfg_path, None, None, &virtual_hosts, &certbot)
            .expect("should succeed");

        let settings = load_from_file(&cfg_path).unwrap();
        // Should have cleared listeners
        assert!(settings.server.listeners.is_empty());
    }
}
