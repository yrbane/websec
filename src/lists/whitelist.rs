//! Whitelist management for trusted IPs
//!
//! Whitelisted IPs bypass reputation scoring and are always allowed.

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
    /// Set of whitelisted IP addresses
    ips: Arc<RwLock<HashSet<IpAddr>>>,
}

impl Whitelist {
    /// Create a new empty whitelist
    #[must_use]
    pub fn new() -> Self {
        Self {
            ips: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create a whitelist from a vector of IPs
    #[must_use]
    pub fn from_ips(ips: Vec<IpAddr>) -> Self {
        Self {
            ips: Arc::new(RwLock::new(ips.into_iter().collect())),
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
        self.ips.read().unwrap().contains(ip)
    }

    /// Clear all IPs from the whitelist
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned
    pub fn clear(&mut self) {
        self.ips.write().unwrap().clear();
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
        self.ips.read().unwrap().is_empty()
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        Self::new()
    }
}
