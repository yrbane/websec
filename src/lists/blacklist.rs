//! Blacklist management for immediate IP blocking
//!
//! Blacklisted IPs are blocked immediately regardless of reputation score.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// Blacklist of IP addresses to block immediately
///
/// IPs in the blacklist bypass all scoring logic and are blocked at the earliest
/// possible stage of request processing.
///
/// # Thread Safety
///
/// Uses `RwLock` for thread-safe concurrent access. Multiple readers can check
/// the blacklist simultaneously, while writes (add/remove) require exclusive access.
#[derive(Debug, Clone)]
pub struct Blacklist {
    /// Set of blacklisted IP addresses
    ips: Arc<RwLock<HashSet<IpAddr>>>,
}

impl Blacklist {
    /// Create a new empty blacklist
    #[must_use]
    pub fn new() -> Self {
        Self {
            ips: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create a blacklist from a vector of IPs
    #[must_use]
    pub fn from_ips(ips: Vec<IpAddr>) -> Self {
        Self {
            ips: Arc::new(RwLock::new(ips.into_iter().collect())),
        }
    }

    /// Add an IP to the blacklist
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned (should never happen in normal operation)
    pub fn add(&mut self, ip: IpAddr) {
        self.ips.write().unwrap().insert(ip);
    }

    /// Remove an IP from the blacklist
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    pub fn remove(&mut self, ip: &IpAddr) {
        self.ips.write().unwrap().remove(ip);
    }

    /// Check if an IP is blacklisted
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.read().unwrap().contains(ip)
    }

    /// Clear all IPs from the blacklist
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    pub fn clear(&mut self) {
        self.ips.write().unwrap().clear();
    }

    /// Get the number of blacklisted IPs
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    #[must_use]
    pub fn len(&self) -> usize {
        self.ips.read().unwrap().len()
    }

    /// Check if the blacklist is empty
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ips.read().unwrap().is_empty()
    }
}

impl Default for Blacklist {
    fn default() -> Self {
        Self::new()
    }
}
