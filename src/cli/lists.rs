use crate::{Error, Result};
use regex::Regex;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// File-based blacklist/whitelist helper used by the CLI.
pub struct ListManager {
    dir: PathBuf,
    blacklist: PathBuf,
    whitelist: PathBuf,
}

impl ListManager {
    /// Create a new manager using the provided directory or defaults.
    pub fn new(dir: Option<&Path>) -> Result<Self> {
        let base = dir
            .map(PathBuf::from)
            .or_else(|| env::var("WEBSEC_LISTS_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("lists"));
        fs::create_dir_all(&base).map_err(Error::Io)?;
        let blacklist = base.join("blacklist.txt");
        let whitelist = base.join("whitelist.txt");
        touch(&blacklist)?;
        touch(&whitelist)?;
        Ok(Self {
            dir: base,
            blacklist,
            whitelist,
        })
    }

    /// Append an entry to the blacklist (idempotent).
    pub fn add_blacklist(&self, entry: &str) -> Result<()> {
        self.add_entry(&self.blacklist, entry)
    }

    /// Remove an entry from the blacklist.
    pub fn remove_blacklist(&self, entry: &str) -> Result<()> {
        self.remove_entry(&self.blacklist, entry)
    }

    /// Return all blacklist entries.
    pub fn list_blacklist(&self) -> Result<Vec<String>> {
        self.list_entries(&self.blacklist)
    }

    /// Clear the blacklist file.
    pub fn clear_blacklist(&self) -> Result<()> {
        fs::write(&self.blacklist, "").map_err(Error::Io)
    }

    /// Append an entry to the whitelist (idempotent).
    pub fn add_whitelist(&self, entry: &str) -> Result<()> {
        self.add_entry(&self.whitelist, entry)
    }

    /// Remove an entry from the whitelist.
    pub fn remove_whitelist(&self, entry: &str) -> Result<()> {
        self.remove_entry(&self.whitelist, entry)
    }

    /// Return all whitelist entries.
    pub fn list_whitelist(&self) -> Result<Vec<String>> {
        self.list_entries(&self.whitelist)
    }

    /// Clear the whitelist file.
    pub fn clear_whitelist(&self) -> Result<()> {
        fs::write(&self.whitelist, "").map_err(Error::Io)
    }

    /// Check whether an IP appears in the lists (blacklist, whitelist).
    pub fn check_ip(&self, ip: &str) -> Result<(bool, bool)> {
        Ok((
            self.contains(&self.blacklist, ip)?,
            self.contains(&self.whitelist, ip)?,
        ))
    }

    /// Return the number of entries in each list.
    pub fn stats(&self) -> Result<(usize, usize)> {
        Ok((count_lines(&self.blacklist)?, count_lines(&self.whitelist)?))
    }

    /// Export both lists as JSON or CSV.
    pub fn export(&self, format: ExportFormat) -> Result<String> {
        let blacklist = self.list_blacklist()?;
        let whitelist = self.list_whitelist()?;
        match format {
            ExportFormat::Json => Ok(json!({
                "blacklist": blacklist,
                "whitelist": whitelist,
            })
            .to_string()),
            ExportFormat::Csv => {
                let mut rows = vec!["type,ip".to_string()];
                rows.extend(blacklist.into_iter().map(|ip| format!("blacklist,{ip}")));
                rows.extend(whitelist.into_iter().map(|ip| format!("whitelist,{ip}")));
                Ok(rows.join("\n"))
            }
        }
    }

    /// Import entries from JSON or CSV files.
    pub fn import(&self, path: &Path) -> Result<()> {
        let content = fs::read_to_string(path).map_err(Error::Io)?;
        if content.trim_start().starts_with('{') {
            let value: Value = serde_json::from_str(&content)
                .map_err(|e| Error::Config(format!("JSON invalide: {e}")))?;
            if let Some(items) = value.get("blacklist").and_then(|v| v.as_array()) {
                for entry in items.iter().filter_map(|v| v.as_str()) {
                    self.add_blacklist(entry)?;
                }
            }
            if let Some(items) = value.get("whitelist").and_then(|v| v.as_array()) {
                for entry in items.iter().filter_map(|v| v.as_str()) {
                    self.add_whitelist(entry)?;
                }
            }
            Ok(())
        } else {
            for line in content.lines().skip(1) {
                let mut parts = line.split(',');
                if let (Some(kind), Some(ip)) = (parts.next(), parts.next()) {
                    match kind {
                        "blacklist" => self.add_blacklist(ip.trim())?,
                        "whitelist" => self.add_whitelist(ip.trim())?,
                        _ => {}
                    }
                }
            }
            Ok(())
        }
    }

    /// Return the underlying directory path.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn add_entry(&self, file: &Path, entry: &str) -> Result<()> {
        validate_ip(entry)?;
        let existing = self.list_entries(file)?;
        if existing.iter().any(|line| line == entry) {
            return Ok(());
        }
        let mut lines = existing;
        lines.push(entry.to_string());
        lines.sort();
        fs::write(file, lines.join("\n") + "\n").map_err(Error::Io)
    }

    fn remove_entry(&self, file: &Path, entry: &str) -> Result<()> {
        let lines = self.list_entries(file)?;
        let filtered: Vec<_> = lines.into_iter().filter(|line| line != entry).collect();
        fs::write(
            file,
            filtered.join("\n") + if filtered.is_empty() { "" } else { "\n" },
        )
        .map_err(Error::Io)
    }

    fn list_entries(&self, file: &Path) -> Result<Vec<String>> {
        if !file.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(file).map_err(Error::Io)?;
        Ok(content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect())
    }

    fn contains(&self, file: &Path, entry: &str) -> Result<bool> {
        Ok(self.list_entries(file)?.iter().any(|line| line == entry))
    }
}

#[derive(Clone, Copy)]
/// Supported export formats for `ListManager::export`.
pub enum ExportFormat {
    /// Export as `{ "blacklist": [], "whitelist": [] }` JSON.
    Json,
    /// Export as `type,ip` CSV.
    Csv,
}

fn count_lines(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let content = fs::read_to_string(path).map_err(Error::Io)?;
    Ok(content.lines().filter(|l| !l.trim().is_empty()).count())
}

fn touch(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::write(path, "").map_err(Error::Io)?;
    }
    Ok(())
}

fn validate_ip(entry: &str) -> Result<()> {
    let regex = Regex::new(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
        .map_err(|e| Error::Config(format!("Regex invalide: {e}")))?;
    if regex.is_match(entry) {
        Ok(())
    } else {
        Err(Error::Config(format!("Format IP/CIDR invalide: {entry}")))
    }
}
