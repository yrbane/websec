//! Threat detection signal types
//!
//! Defines all 20+ signal variants used for IP reputation scoring.
//! Each signal has an associated weight (penalty points) and timestamp.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A threat detection signal with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    /// Unique signal ID
    pub id: Uuid,
    /// Signal variant (threat type)
    pub variant: SignalVariant,
    /// When the signal was detected
    pub timestamp: DateTime<Utc>,
    /// Penalty weight (points deducted from reputation)
    pub weight: u8,
    /// Optional context/metadata for debugging
    pub context: Option<String>,
}

/// All threat detection signal types
///
/// Each variant represents a specific threat family or attack pattern.
/// Weights are assigned based on severity and confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalVariant {
    // Bot Detection Signals (US1)
    /// Suspicious User-Agent header (bot signatures, missing UA)
    SuspiciousUserAgent,
    /// Bot-like behavior patterns (no asset requests, rapid navigation)
    BotBehaviorPattern,
    /// Known vulnerability scanner tool detected
    VulnerabilityScan,
    /// Aggressive crawling behavior
    AbusiveClient,

    // Brute Force Signals (US2)
    /// Failed authentication attempt
    FailedLogin,
    /// Rapid sequential login attempts
    LoginAttemptPattern,
    /// Credential stuffing detected (password spray)
    CredentialStuffing,

    // Flood/DDoS Signals (US3)
    /// Request rate exceeds normal thresholds
    RequestFlood,
    /// Connection flood (SYN flood, slowloris)
    ConnectionFlood,
    /// Distributed attack pattern detected
    DistributedAttack,

    // SQL Injection Signals (US4)
    /// SQL injection pattern in query string
    SqlInjectionAttempt,
    /// SQL syntax detected in parameters
    SqlSyntaxPattern,

    // XSS Signals (US6)
    /// Cross-site scripting pattern in input
    XssAttempt,
    /// JavaScript injection detected
    ScriptInjection,

    // Path Traversal Signals (US7)
    /// Directory traversal attempt (../, etc.)
    PathTraversalAttempt,
    /// File access outside allowed paths
    UnauthorizedFileAccess,

    // Command Injection / RCE Signals (US4)
    /// Remote code execution attempt (command injection)
    RceAttempt,

    // Header Manipulation Signals (US10)
    /// HTTP header injection
    HeaderInjection,
    /// Host header manipulation
    HostHeaderAttack,
    /// Referer spoofing detected
    RefererSpoofing,

    // Protocol Violation Signals (US11)
    /// HTTP protocol RFC violation
    ProtocolViolation,
    /// Invalid HTTP method usage
    InvalidHttpMethod,
    /// Malformed request structure
    MalformedRequest,

    // Geographic Signals (US5)
    /// Request from high-risk country
    HighRiskCountry,
    /// Impossible travel detected (geolocation jump)
    ImpossibleTravel,

    // Session Hijacking Signals (US9)
    /// Session token anomaly detected
    SessionTokenAnomaly,
    /// Session fixation attempt
    SessionFixationAttempt,

    // Generic Signals
    /// Repeated blocked requests (persistence)
    BlockedRequestPersistence,
    /// Multiple distinct attack families detected
    CorrelatedThreats,
}

impl SignalVariant {
    /// Get the default penalty weight for this signal type
    ///
    /// Weights are calibrated based on:
    /// - Attack severity (potential impact)
    /// - Detection confidence (false positive rate)
    /// - Attack sophistication
    #[must_use]
    pub const fn default_weight(&self) -> u8 {
        match self {
            // Critical severity - RCE (highest threat)
            Self::RceAttempt => 50,

            // High severity - definitive attacks
            Self::SqlInjectionAttempt | Self::XssAttempt | Self::PathTraversalAttempt => 30,

            // High severity - patterns with high confidence
            Self::CredentialStuffing | Self::VulnerabilityScan | Self::SessionFixationAttempt => 25,

            // Medium-high severity
            Self::FailedLogin
            | Self::LoginAttemptPattern
            | Self::RequestFlood
            | Self::HeaderInjection
            | Self::HostHeaderAttack => 20,

            // Medium severity
            Self::BotBehaviorPattern
            | Self::AbusiveClient
            | Self::ConnectionFlood
            | Self::SqlSyntaxPattern
            | Self::ScriptInjection
            | Self::UnauthorizedFileAccess
            | Self::SessionTokenAnomaly => 15,

            // Low-medium severity
            Self::SuspiciousUserAgent
            | Self::RefererSpoofing
            | Self::ProtocolViolation
            | Self::InvalidHttpMethod
            | Self::MalformedRequest
            | Self::BlockedRequestPersistence => 10,

            // Geographic and behavioral signals
            Self::HighRiskCountry => 15,
            Self::ImpossibleTravel => 20,

            // Meta-signals (composite indicators)
            Self::DistributedAttack | Self::CorrelatedThreats => 10,
        }
    }

    /// Get the signal family for correlation analysis
    ///
    /// Signals from different families increase correlation penalty.
    #[must_use]
    pub const fn family(&self) -> SignalFamily {
        match self {
            Self::SuspiciousUserAgent
            | Self::BotBehaviorPattern
            | Self::VulnerabilityScan
            | Self::AbusiveClient => SignalFamily::BotDetection,

            Self::FailedLogin | Self::LoginAttemptPattern | Self::CredentialStuffing => {
                SignalFamily::BruteForce
            }

            Self::RequestFlood | Self::ConnectionFlood | Self::DistributedAttack => {
                SignalFamily::Flood
            }

            Self::SqlInjectionAttempt | Self::SqlSyntaxPattern => SignalFamily::SqlInjection,

            Self::XssAttempt | Self::ScriptInjection => SignalFamily::Xss,

            Self::PathTraversalAttempt | Self::UnauthorizedFileAccess => {
                SignalFamily::PathTraversal
            }

            Self::RceAttempt => SignalFamily::CommandInjection,

            Self::HeaderInjection | Self::HostHeaderAttack | Self::RefererSpoofing => {
                SignalFamily::HeaderManipulation
            }

            Self::ProtocolViolation | Self::InvalidHttpMethod | Self::MalformedRequest => {
                SignalFamily::ProtocolViolation
            }

            Self::HighRiskCountry | Self::ImpossibleTravel => SignalFamily::Geographic,

            Self::SessionTokenAnomaly | Self::SessionFixationAttempt => {
                SignalFamily::SessionHijacking
            }

            Self::BlockedRequestPersistence | Self::CorrelatedThreats => SignalFamily::Generic,
        }
    }
}

/// Signal family groupings for correlation analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalFamily {
    /// Bot detection and scanner identification
    BotDetection,
    /// Brute force and credential attacks
    BruteForce,
    /// Flood and `DoS` attacks
    Flood,
    /// SQL injection attempts
    SqlInjection,
    /// Cross-site scripting attacks
    Xss,
    /// Path traversal and file access
    PathTraversal,
    /// Command injection and RCE
    CommandInjection,
    /// HTTP header manipulation
    HeaderManipulation,
    /// Protocol violations
    ProtocolViolation,
    /// Geographic threat patterns
    Geographic,
    /// Session hijacking
    SessionHijacking,
    /// Generic/uncategorized
    Generic,
}

impl Signal {
    /// Create a new signal with default weight
    #[must_use]
    pub fn new(variant: SignalVariant) -> Self {
        Self {
            id: Uuid::new_v4(),
            variant,
            timestamp: Utc::now(),
            weight: variant.default_weight(),
            context: None,
        }
    }

    /// Create a new signal with custom weight and context
    #[must_use]
    pub fn with_context(variant: SignalVariant, weight: u8, context: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            variant,
            timestamp: Utc::now(),
            weight,
            context: Some(context),
        }
    }

    /// Calculate the decayed weight based on age
    ///
    /// Uses exponential decay: weight(t) = weight₀ × 2^(-t/half_life)
    ///
    /// # Arguments
    ///
    /// * `half_life_hours` - Half-life duration in hours
    #[must_use]
    pub fn decayed_weight(&self, half_life_hours: f64) -> f64 {
        #[allow(clippy::cast_precision_loss)]
        let age_hours = Utc::now()
            .signed_duration_since(self.timestamp)
            .num_seconds() as f64
            / 3600.0;

        let decay_factor = 2.0_f64.powf(-age_hours / half_life_hours);
        f64::from(self.weight) * decay_factor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_creation() {
        let signal = Signal::new(SignalVariant::SqlInjectionAttempt);
        assert_eq!(signal.weight, 30);
        assert_eq!(signal.variant.family(), SignalFamily::SqlInjection);
    }

    #[test]
    fn test_signal_weights() {
        assert_eq!(SignalVariant::SqlInjectionAttempt.default_weight(), 30);
        assert_eq!(SignalVariant::FailedLogin.default_weight(), 20);
        assert_eq!(SignalVariant::SuspiciousUserAgent.default_weight(), 10);
    }

    #[test]
    fn test_signal_families() {
        assert_eq!(
            SignalVariant::SqlInjectionAttempt.family(),
            SignalFamily::SqlInjection
        );
        assert_eq!(SignalVariant::XssAttempt.family(), SignalFamily::Xss);
        assert_eq!(
            SignalVariant::FailedLogin.family(),
            SignalFamily::BruteForce
        );
    }

    #[test]
    fn test_decayed_weight() {
        let mut signal = Signal::new(SignalVariant::FailedLogin);
        // Simulate signal from 24 hours ago (one half-life)
        signal.timestamp = Utc::now() - chrono::Duration::hours(24);

        let half_life = 24.0;
        let decayed = signal.decayed_weight(half_life);

        // After one half-life, weight should be ~50% of original
        assert!((decayed - 10.0).abs() < 1.0, "Decayed weight should be ~10");
    }

    #[test]
    fn test_signal_with_context() {
        let signal = Signal::with_context(
            SignalVariant::SqlInjectionAttempt,
            35,
            "SELECT * FROM users".to_string(),
        );
        assert_eq!(signal.weight, 35);
        assert_eq!(signal.context.unwrap(), "SELECT * FROM users");
    }
}
