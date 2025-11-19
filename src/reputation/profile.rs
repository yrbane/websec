//! IP reputation profile tracking
//!
//! Stores the complete behavioral history and signal accumulation for an IP address.

use super::signal::{Signal, SignalFamily};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Complete reputation profile for an IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationProfile {
    /// IP address being tracked
    pub ip_address: IpAddr,
    /// Current reputation score (0-100)
    pub current_score: u8,
    /// All accumulated signals (historical)
    pub signals: Vec<Signal>,
    /// First time this IP was seen
    pub first_seen: DateTime<Utc>,
    /// Last time this IP made a request
    pub last_seen: DateTime<Utc>,
    /// Total number of requests from this IP
    pub request_count: u64,
    /// Number of requests blocked
    pub blocked_count: u64,
    /// Geographic metadata (optional)
    pub country_code: Option<String>,
    /// Whitelisted status
    pub whitelisted: bool,
    /// Blacklisted status
    pub blacklisted: bool,
}

impl ReputationProfile {
    /// Create a new profile for an IP address with base score
    #[must_use]
    pub fn new(ip_address: IpAddr, base_score: u8) -> Self {
        let now = Utc::now();
        Self {
            ip_address,
            current_score: base_score,
            signals: Vec::new(),
            first_seen: now,
            last_seen: now,
            request_count: 0,
            blocked_count: 0,
            country_code: None,
            whitelisted: false,
            blacklisted: false,
        }
    }

    /// Add a signal to the profile
    ///
    /// This does NOT recalculate the score. Call `recalculate_score()` separately.
    pub fn add_signal(&mut self, signal: Signal) {
        self.signals.push(signal);
    }

    /// Record a request from this IP
    pub fn record_request(&mut self) {
        self.last_seen = Utc::now();
        self.request_count += 1;
    }

    /// Record a blocked request
    pub fn record_blocked(&mut self) {
        self.blocked_count += 1;
    }

    /// Get all unique signal families present in the profile
    ///
    /// Used for calculating correlation penalty bonus.
    #[must_use]
    pub fn signal_families(&self) -> HashSet<SignalFamily> {
        self.signals.iter().map(|s| s.variant.family()).collect()
    }

    /// Calculate total active penalty from all signals with decay
    ///
    /// # Arguments
    ///
    /// * `half_life_hours` - Exponential decay half-life in hours
    #[must_use]
    pub fn calculate_total_penalty(&self, half_life_hours: f64) -> f64 {
        self.signals
            .iter()
            .map(|signal| signal.decayed_weight(half_life_hours))
            .sum()
    }

    /// Get signal count by family
    #[must_use]
    pub fn signals_by_family(&self) -> HashMap<SignalFamily, usize> {
        let mut counts: HashMap<SignalFamily, usize> = HashMap::new();
        for signal in &self.signals {
            *counts.entry(signal.variant.family()).or_insert(0) += 1;
        }
        counts
    }

    /// Check if profile has signals from multiple distinct families
    #[must_use]
    pub fn has_correlated_threats(&self) -> bool {
        self.signal_families().len() >= 2
    }

    /// Get the age of this profile in hours
    #[must_use]
    pub fn age_hours(&self) -> f64 {
        Utc::now()
            .signed_duration_since(self.first_seen)
            .num_seconds() as f64
            / 3600.0
    }

    /// Get the time since last activity in hours
    #[must_use]
    pub fn idle_hours(&self) -> f64 {
        Utc::now()
            .signed_duration_since(self.last_seen)
            .num_seconds() as f64
            / 3600.0
    }

    /// Calculate block rate (percentage of requests blocked)
    #[must_use]
    pub fn block_rate(&self) -> f64 {
        if self.request_count == 0 {
            0.0
        } else {
            (self.blocked_count as f64 / self.request_count as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::signal::SignalVariant;
    use std::str::FromStr;

    #[test]
    fn test_profile_creation() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        assert_eq!(profile.current_score, 100);
        assert_eq!(profile.signals.len(), 0);
        assert!(!profile.whitelisted);
        assert!(!profile.blacklisted);
    }

    #[test]
    fn test_add_signal() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        let signal = Signal::new(SignalVariant::FailedLogin);
        profile.add_signal(signal);

        assert_eq!(profile.signals.len(), 1);
    }

    #[test]
    fn test_signal_families() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        profile.add_signal(Signal::new(SignalVariant::FailedLogin));
        profile.add_signal(Signal::new(SignalVariant::SqlInjectionAttempt));
        profile.add_signal(Signal::new(SignalVariant::FailedLogin)); // Duplicate family

        let families = profile.signal_families();
        assert_eq!(families.len(), 2); // BruteForce and SqlInjection
        assert!(profile.has_correlated_threats());
    }

    #[test]
    fn test_calculate_total_penalty() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        profile.add_signal(Signal::new(SignalVariant::FailedLogin)); // weight 20
        profile.add_signal(Signal::new(SignalVariant::SqlInjectionAttempt)); // weight 30

        // With no decay (signals just created), total should be ~50
        let penalty = profile.calculate_total_penalty(24.0);
        assert!((49.0..=51.0).contains(&penalty), "Penalty should be ~50");
    }

    #[test]
    fn test_record_request() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        assert_eq!(profile.request_count, 0);
        profile.record_request();
        assert_eq!(profile.request_count, 1);
    }

    #[test]
    fn test_block_rate() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        assert_eq!(profile.block_rate(), 0.0);

        profile.request_count = 100;
        profile.blocked_count = 25;
        assert_eq!(profile.block_rate(), 25.0);
    }

    #[test]
    fn test_signals_by_family() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        profile.add_signal(Signal::new(SignalVariant::FailedLogin));
        profile.add_signal(Signal::new(SignalVariant::FailedLogin));
        profile.add_signal(Signal::new(SignalVariant::SqlInjectionAttempt));

        let by_family = profile.signals_by_family();
        assert_eq!(by_family.get(&SignalFamily::BruteForce), Some(&2));
        assert_eq!(by_family.get(&SignalFamily::SqlInjection), Some(&1));
    }
}
