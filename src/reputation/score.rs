//! Reputation scoring calculation engine
//!
//! Implements the core scoring formula:
//! `Score = max(0, min(100, base_score - total_penalty - correlation_bonus))`

use super::profile::ReputationProfile;
use serde::{Deserialize, Serialize};

/// Proxy decision based on reputation score
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyDecision {
    /// Allow request through (score >= threshold_allow)
    Allow,
    /// Apply rate limiting (threshold_ratelimit <= score < threshold_allow)
    RateLimit,
    /// Send challenge (CAPTCHA, etc.) (threshold_challenge <= score < threshold_ratelimit)
    Challenge,
    /// Block request entirely (score < threshold_challenge)
    Block,
}

/// Reputation scoring thresholds
#[derive(Debug, Clone, Copy)]
pub struct ScoringThresholds {
    /// Minimum score for ALLOW (default: 70)
    pub allow: u8,
    /// Minimum score for RATE_LIMIT (default: 40)
    pub ratelimit: u8,
    /// Minimum score for CHALLENGE (default: 20)
    pub challenge: u8,
    /// Minimum score for BLOCK (default: 0)
    pub block: u8,
}

impl Default for ScoringThresholds {
    fn default() -> Self {
        Self {
            allow: 70,
            ratelimit: 40,
            challenge: 20,
            block: 0,
        }
    }
}

/// Calculate reputation score for a profile
///
/// # Formula
///
/// ```text
/// Score = max(0, min(100, base_score - Σ(decayed_weights) - correlation_bonus))
/// ```
///
/// Where:
/// - `base_score`: Starting score (typically 100)
/// - `Σ(decayed_weights)`: Sum of all signal weights with exponential decay
/// - `correlation_bonus`: Additional penalty if multiple attack families present
///
/// # Arguments
///
/// * `profile` - The IP reputation profile
/// * `base_score` - Base starting score (0-100)
/// * `half_life_hours` - Exponential decay half-life
/// * `correlation_penalty_bonus` - Bonus penalty for multiple signal families
#[must_use]
pub fn calculate_score(
    profile: &ReputationProfile,
    base_score: u8,
    half_life_hours: f64,
    correlation_penalty_bonus: u8,
) -> u8 {
    // Whitelist: always maximum score
    if profile.whitelisted {
        return 100;
    }

    // Blacklist: always zero score
    if profile.blacklisted {
        return 0;
    }

    // Calculate base penalty from signals
    let total_penalty = profile.calculate_total_penalty(half_life_hours);

    // Add correlation bonus if multiple attack families detected
    let correlation_bonus = if profile.has_correlated_threats() {
        f64::from(correlation_penalty_bonus)
    } else {
        0.0
    };

    // Apply formula: Score = max(0, min(100, base - penalty - bonus))
    let raw_score = f64::from(base_score) - total_penalty - correlation_bonus;
    let clamped_score = raw_score.clamp(0.0, 100.0);

    clamped_score.round() as u8
}

/// Determine proxy decision based on score and thresholds
#[must_use]
pub fn determine_decision(score: u8, thresholds: &ScoringThresholds) -> ProxyDecision {
    if score >= thresholds.allow {
        ProxyDecision::Allow
    } else if score >= thresholds.ratelimit {
        ProxyDecision::RateLimit
    } else if score >= thresholds.challenge {
        ProxyDecision::Challenge
    } else {
        ProxyDecision::Block
    }
}

/// Recalculate score and update profile
///
/// This is the primary interface for score updates. It calculates the new score
/// and updates the profile's `current_score` field.
pub fn recalculate_and_update(
    profile: &mut ReputationProfile,
    base_score: u8,
    half_life_hours: f64,
    correlation_penalty_bonus: u8,
) {
    let new_score = calculate_score(profile, base_score, half_life_hours, correlation_penalty_bonus);
    profile.current_score = new_score;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::signal::{Signal, SignalVariant};
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_base_score_no_signals() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        let score = calculate_score(&profile, 100, 24.0, 10);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_score_with_single_signal() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        // Add signal with weight 20
        profile.add_signal(Signal::new(SignalVariant::FailedLogin));

        let score = calculate_score(&profile, 100, 24.0, 10);
        // Score should be ~80 (100 - 20, no correlation bonus)
        assert!(score >= 79 && score <= 81, "Score was {}", score);
    }

    #[test]
    fn test_score_with_correlation_bonus() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        // Add signals from two different families
        profile.add_signal(Signal::new(SignalVariant::FailedLogin)); // weight 20
        profile.add_signal(Signal::new(SignalVariant::SqlInjectionAttempt)); // weight 30

        let score = calculate_score(&profile, 100, 24.0, 10);
        // Score should be ~40 (100 - 20 - 30 - 10 correlation bonus)
        assert!(score >= 39 && score <= 41, "Score was {}", score);
    }

    #[test]
    fn test_score_clamping() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        // Add many high-weight signals to exceed penalty
        for _ in 0..10 {
            profile.add_signal(Signal::new(SignalVariant::SqlInjectionAttempt)); // weight 30 each
        }

        let score = calculate_score(&profile, 100, 24.0, 10);
        // Score should be clamped to 0
        assert_eq!(score, 0);
    }

    #[test]
    fn test_whitelist_override() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);
        profile.whitelisted = true;

        // Add signals
        profile.add_signal(Signal::new(SignalVariant::SqlInjectionAttempt));

        let score = calculate_score(&profile, 100, 24.0, 10);
        // Whitelisted IPs always get score 100
        assert_eq!(score, 100);
    }

    #[test]
    fn test_blacklist_override() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);
        profile.blacklisted = true;

        let score = calculate_score(&profile, 100, 24.0, 10);
        // Blacklisted IPs always get score 0
        assert_eq!(score, 0);
    }

    #[test]
    fn test_determine_decision() {
        let thresholds = ScoringThresholds::default();

        assert_eq!(determine_decision(100, &thresholds), ProxyDecision::Allow);
        assert_eq!(determine_decision(70, &thresholds), ProxyDecision::Allow);
        assert_eq!(
            determine_decision(69, &thresholds),
            ProxyDecision::RateLimit
        );
        assert_eq!(
            determine_decision(40, &thresholds),
            ProxyDecision::RateLimit
        );
        assert_eq!(
            determine_decision(39, &thresholds),
            ProxyDecision::Challenge
        );
        assert_eq!(
            determine_decision(20, &thresholds),
            ProxyDecision::Challenge
        );
        assert_eq!(determine_decision(19, &thresholds), ProxyDecision::Block);
        assert_eq!(determine_decision(0, &thresholds), ProxyDecision::Block);
    }

    #[test]
    fn test_recalculate_and_update() {
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let mut profile = ReputationProfile::new(ip, 100);

        profile.add_signal(Signal::new(SignalVariant::FailedLogin)); // weight 20

        recalculate_and_update(&mut profile, 100, 24.0, 10);

        assert!(
            profile.current_score >= 79 && profile.current_score <= 81,
            "Score was {}",
            profile.current_score
        );
    }
}
