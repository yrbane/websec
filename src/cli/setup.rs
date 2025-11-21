//! Interactive setup command for integrating `WebSec` with Apache.
//!
//! The goal is to automate the steps required to insert `WebSec` in front of
//! an existing Apache deployment by:
//! - Detecting Apache configuration directories
//! - Enumerating `VirtualHosts` that listen on HTTP (port 80)
//! - Asking the operator which `VirtualHosts` should be migrated
//! - Rewriting the `<VirtualHost>` directives to use an internal port
//! - Updating Apache's `ports.conf` and the `WebSec` TOML configuration
//!
//! **Important**: This command expects to run with sufficient privileges to
//! read and modify `/etc/apache2/**` as well as the `WebSec` config file. In the
//! current repository the command is implemented but not executed.

use crate::config::load_from_file;
use crate::config::settings::ListenerConfig;
use crate::{Error, Result};
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const APACHE_SITES_ENABLED: &str = "/etc/apache2/sites-enabled";
const APACHE_PORTS_CONF: &str = "/etc/apache2/ports.conf";
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

/// Run the interactive setup for Apache.
pub fn run_setup(config_path: &Path) -> Result<()> {
    println!("🛠️  Assistant de configuration WebSec (Apache)");
    println!("Ce processus va modifier les fichiers Apache pour placer WebSec en frontal.\n");

    let apache = ApacheEnvironment::detect()?;
    let virtual_hosts = apache.scan_virtual_hosts()?;

    if virtual_hosts.is_empty() {
        println!(
            "⚠️  Aucun VirtualHost détecté dans {APACHE_SITES_ENABLED}"
        );
        return Err(Error::Config(
            "Impossible de continuer sans configuration Apache".to_string(),
        ));
    }

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
        let hosts: Vec<&VirtualHostEntry> = virtual_hosts
            .iter()
            .filter(|vh| vh.supports_port(plan.port))
            .collect();
        if hosts.is_empty() {
            continue;
        }

        println!(
            "\n============================================================\n{label} - VirtualHosts détectés sur le port {port}\n{desc}\n============================================================",
            label = plan.label,
            port = plan.port,
            desc = plan.description
        );

        if !prompt_yes_no(
            format!(
                "Migrer les VirtualHosts {label} vers WebSec ?",
                label = plan.label
            )
            .as_str(),
            plan.port == 80,
        )? {
            continue;
        }

        let internal_port = prompt_port(
            format!(
                "Port interne Apache pour {label} [{default}]: ",
                label = plan.label,
                default = plan.default_internal
            )
            .as_str(),
            plan.default_internal,
        )?;

        println!(
            "\nRépondez 'o' pour chaque VirtualHost {label} à migrer :",
            label = plan.label
        );

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
                "\nAucun VirtualHost sélectionné pour {label}. Aucun changement appliqué pour ce port.",
                label = plan.label
            );
            continue;
        }

        migrations.push(PortMigration {
            original_port: plan.port,
            internal_port,
            selections,
        });
    }

    if migrations.is_empty() {
        println!("\nAucun VirtualHost sélectionné. Annulation.");
        return Ok(());
    }

    println!("\n➡️  Mise à jour des fichiers Apache...");
    for migration in &migrations {
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
        println!(
            "ℹ️  Aucun changement nécessaire dans ports.conf (aucun Listen correspondant trouvé)"
        );
    }

    if config_path.exists() {
        println!(
            "\n➡️  Mise à jour de la configuration WebSec ({})",
            config_path.display()
        );
        let http_mapping = migrations
            .iter()
            .find(|m| m.original_port == 80)
            .map(|m| m.internal_port);
        update_websec_config(config_path, http_mapping)?;
    } else {
        println!(
            "⚠️  Fichier de configuration {} introuvable - mise à jour manuelle requise",
            config_path.display()
        );
    }

    println!("\n🎉 Configuration terminée");
    if migrations.iter().any(|m| m.original_port == 80) {
        println!("- Les VirtualHosts HTTP ont été déplacés. WebSec doit écouter sur 0.0.0.0:80.");
    }
    if migrations.iter().any(|m| m.original_port == 443) {
        println!(
            "- Les VirtualHosts HTTPS ont été déplacés. Configurez WebSec en mode TLS sur 0.0.0.0:443 et pointez vers le port interne indiqué."
        );
    }
    println!("Pensez à redémarrer Apache puis à lancer WebSec pour prendre en compte les modifications.\n");

    Ok(())
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
                        entries[current].server_name =
                            trimmed.split_whitespace().nth(1).map(std::string::ToString::to_string);
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
        let mut lines: Vec<String> = content.lines().map(std::string::ToString::to_string).collect();
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

/// A parsed Apache `<VirtualHost>`.
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
    let file_name = path
        .file_name()
        .map_or_else(|| "config".to_string(), |s| s.to_string_lossy().into_owned());
    let backup_name = format!("{file_name}.websec.bak.{timestamp}");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let backup_path = parent.join(backup_name);
    fs::copy(path, &backup_path).map_err(Error::Io)?;
    Ok(backup_path)
}

fn update_websec_config(config_path: &Path, backend_port: Option<u16>) -> Result<()> {
    let Some(port) = backend_port else {
        println!("ℹ️  Aucun VirtualHost HTTP migré - configuration WebSec laissée inchangée.");
        return Ok(());
    };

    let mut settings = load_from_file(config_path).map_err(|e| {
        Error::Config(format!(
            "Impossible de charger {}: {e}",
            config_path.display()
        ))
    })?;

    let old_listen = settings.server.listen.clone();
    settings.server.listen = "0.0.0.0:80".to_string();
    settings.server.backend = format!("http://127.0.0.1:{port}");
    settings.server.listeners = vec![ListenerConfig {
        listen: settings.server.listen.clone(),
        backend: settings.server.backend.clone(),
        tls: None,
    }];

    let backup_path = backup_file(config_path)?;
    println!(
        "📦 Sauvegarde: {} -> {}",
        config_path.display(),
        backup_path.display()
    );

    let toml_text = toml::to_string_pretty(&settings)
        .map_err(|e| Error::Config(format!("Erreur de sérialisation TOML: {e}")))?;
    fs::write(config_path, toml_text).map_err(Error::Io)?;

    println!(
        "✅ Configuration WebSec mise à jour (listen: {} -> {}, backend -> http://127.0.0.1:{port})",
        old_listen, settings.server.listen
    );

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
    fn test_update_websec_config_overrides_backend_and_listen() {
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("websec.toml");
        fs::write(&cfg_path, sample_config()).unwrap();

        update_websec_config(&cfg_path, Some(8081)).expect("update should succeed");

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
    fn test_update_websec_config_no_http_migration_keeps_config() {
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("websec.toml");
        fs::write(&cfg_path, sample_config()).unwrap();

        update_websec_config(&cfg_path, None).expect("should skip changes");
        let settings = load_from_file(&cfg_path).unwrap();
        assert_eq!(settings.server.listen, "0.0.0.0:8080");
        assert_eq!(settings.server.backend, "http://127.0.0.1:3000");
        assert!(settings.server.listeners.is_empty());
    }
}
