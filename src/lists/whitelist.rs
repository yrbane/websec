//! Whitelist management for trusted IPs
//!
//! Whitelisted IPs bypass reputation scoring and are always allowed.
//!
//! # Priority
//!
//! Whitelist has **second priority** (after blacklist):
//! 1. Blacklist → Block (score = 0)
//! 2. **Whitelist** → Allow (score = 100)
//! 3. Normal scoring
//!
//! # Use Cases
//!
//! - Trusted office IPs
//! - Monitoring services (uptime monitors, health checks)
//! - Known good bots (Google, Bing crawlers)
//! - CI/CD pipelines
//!
//! # Example
//!
//! ```rust
//! use websec::lists::Whitelist;
//! use std::net::IpAddr;
//!
//! let mut whitelist = Whitelist::new();
//! let office_ip: IpAddr = "203.0.113.10".parse().unwrap();
//!
//! whitelist.add(office_ip);
//! assert!(whitelist.contains(&office_ip));
//! // This IP will bypass all detectors and always be allowed
//! ```
//!
//! # Thread Safety
//!
//! Thread-safe via `Arc<RwLock<HashSet>>`. Can be cloned cheaply (Arc clone)
//! and shared across threads. Multiple readers can check simultaneously.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// Whitelist of trusted IP addresses
///
/// IPs in the whitelist bypass all scoring logic and detection, receiving
/// perfect score (100) and ALLOW decision regardless of their behavior.
///
/// # Thread Safety
///
/// Uses `RwLock` for thread-safe concurrent access. Multiple readers can check
/// the whitelist simultaneously, while writes (add/remove) require exclusive access.
#[derive(Debug, Clone)]
pub struct Whitelist {
    /// Set of whitelisted IP addresses (exact match)
    ips: Arc<RwLock<HashSet<IpAddr>>>,
    /// Whitelisted CIDR networks: (network address, prefix length).
    /// Permet de whitelister un bloc entier — ex. un /64 IPv6 (les adresses
    /// « privacy » tournent dans le /64) ou un /24 IPv4 — sans lister chaque IP.
    nets: Arc<RwLock<Vec<(IpAddr, u8)>>>,
}

impl Whitelist {
    /// Create a new empty whitelist
    #[must_use]
    pub fn new() -> Self {
        Self {
            ips: Arc::new(RwLock::new(HashSet::new())),
            nets: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a whitelist from a vector of IPs
    #[must_use]
    pub fn from_ips(ips: Vec<IpAddr>) -> Self {
        Self {
            ips: Arc::new(RwLock::new(ips.into_iter().collect())),
            nets: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a CIDR network (e.g. a whole IPv6 /64) to the whitelist.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    pub fn add_cidr(&mut self, network: IpAddr, prefix: u8) {
        self.nets.write().unwrap().push((network, prefix));
    }

    /// Add a textual entry: exact IP (`1.2.3.4`, `::1`) or CIDR
    /// (`10.0.0.0/8`, `2001:db8::/64`). Returns `false` if unparseable.
    pub fn add_entry(&mut self, entry: &str) -> bool {
        if let Some((addr, prefix)) = entry.split_once('/') {
            match (addr.parse::<IpAddr>(), prefix.parse::<u8>()) {
                (Ok(net), Ok(bits)) if bits <= if net.is_ipv4() { 32 } else { 128 } => {
                    self.add_cidr(net, bits);
                    true
                }
                _ => false,
            }
        } else if let Ok(ip) = entry.parse::<IpAddr>() {
            self.add(ip);
            true
        } else {
            false
        }
    }

    /// Add an IP to the whitelist
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (should never happen in normal operation)
    pub fn add(&mut self, ip: IpAddr) {
        self.ips.write().unwrap().insert(ip);
    }

    /// Remove an IP from the whitelist
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    pub fn remove(&mut self, ip: &IpAddr) {
        self.ips.write().unwrap().remove(ip);
    }

    /// Check if an IP is whitelisted
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        if self.ips.read().unwrap().contains(ip) {
            return true;
        }
        self.nets
            .read()
            .unwrap()
            .iter()
            .any(|(network, prefix)| cidr_contains(network, *prefix, ip))
    }

    /// Clear all IPs from the whitelist
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    pub fn clear(&mut self) {
        self.ips.write().unwrap().clear();
        self.nets.write().unwrap().clear();
    }

    /// Get the number of whitelisted IPs
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    #[must_use]
    pub fn len(&self) -> usize {
        self.ips.read().unwrap().len()
    }

    /// Check if the whitelist is empty
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ips.read().unwrap().is_empty() && self.nets.read().unwrap().is_empty()
    }
}

/// Returns true if `ip` belongs to the `network`/`prefix` CIDR block.
/// Different families (v4 vs v6) never match.
fn cidr_contains(network: &IpAddr, prefix: u8, ip: &IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(*net) & mask) == (u32::from(*ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(*net) & mask) == (u128::from(*ip) & mask)
        }
        _ => false,
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod cidr_tests {
    use super::*;

    #[test]
    fn ipv6_64_matches_rotating_privacy_addresses() {
        let mut wl = Whitelist::new();
        assert!(wl.add_entry("2001:863:21d:cc05::/64"));
        // Deux adresses « privacy » distinctes dans le meme /64
        let a: IpAddr = "2001:863:21d:cc05:8bef:aaf4:9723:a193".parse().unwrap();
        let b: IpAddr = "2001:863:21d:cc05:dead:beef:1234:5678".parse().unwrap();
        assert!(wl.contains(&a));
        assert!(wl.contains(&b));
        // Hors du /64
        let out: IpAddr = "2001:863:21d:cc06::1".parse().unwrap();
        assert!(!wl.contains(&out));
    }

    #[test]
    fn ipv4_cidr_and_exact() {
        let mut wl = Whitelist::new();
        assert!(wl.add_entry("10.0.0.0/24"));
        assert!(wl.add_entry("203.0.113.7"));
        assert!(wl.contains(&"10.0.0.42".parse().unwrap()));
        assert!(!wl.contains(&"10.0.1.42".parse().unwrap()));
        assert!(wl.contains(&"203.0.113.7".parse().unwrap()));
        assert!(!wl.contains(&"203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn families_do_not_cross_match() {
        let mut wl = Whitelist::new();
        assert!(wl.add_entry("0.0.0.0/0"));
        // Un /0 IPv4 ne matche pas une IPv6
        assert!(!wl.contains(&"::1".parse().unwrap()));
        assert!(wl.contains(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid_entries() {
        let mut wl = Whitelist::new();
        assert!(!wl.add_entry("not-an-ip"));
        assert!(!wl.add_entry("2001:db8::/999")); // prefixe hors limites
        assert!(!wl.add_entry("10.0.0.0/33"));     // prefixe IPv4 hors limites
    }
}
