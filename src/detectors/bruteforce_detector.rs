//! Brute force attack detection (RGPD-compliant)
//!
//! Detects brute force attacks through:
//! - Failed login attempt COUNT tracking per IP (no credentials stored)
//! - Rapid authentication attempt patterns
//! - Time-windowed tracking with automatic expiry
//!
//! ## Privacy/RGPD Compliance
//!
//! This detector does NOT store:
//! - Usernames or passwords (even hashed)
//! - Any personally identifiable information (PII)
//!
//! Only timestamps of authentication attempts are tracked for pattern detection.

use super::detector::{DetectionResult, Detector, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;

/// Auth endpoint patterns (login, admin, auth paths)
static AUTH_ENDPOINT_PATTERNS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(?i)/(login|signin|auth|admin/login|api/auth|session|authenticate)").unwrap()
});

/// Thresholds for brute force detection
const FAILED_LOGIN_THRESHOLD: usize = 5; // Generate signal after 5 failures
const PATTERN_THRESHOLD: usize = 8; // Generate pattern signal after 8 rapid attempts
const TIME_WINDOW_MINUTES: i64 = 15; // Track attempts within 15 minute window
// REMOVED: CREDENTIAL_STUFFING_THRESHOLD (RGPD compliance - no credential tracking)

/// Failed login attempt record (RGPD-compliant - NO passwords stored)
#[derive(Debug, Clone)]
struct LoginAttempt {
    timestamp: DateTime<Utc>,
    // REMOVED: username and password_hash for RGPD compliance
    // We only track attempt counts and patterns, not actual credentials
}

/// Tracking data for an IP address
#[derive(Debug, Clone)]
struct IpTrackingData {
    attempts: Vec<LoginAttempt>,
}

impl IpTrackingData {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
        }
    }

    /// Add a failed attempt and clean up expired attempts
    /// Note: We do NOT store credentials for RGPD compliance
    fn add_attempt(&mut self) {
        let now = Utc::now();
        let cutoff = now - Duration::minutes(TIME_WINDOW_MINUTES);

        // Remove expired attempts
        self.attempts.retain(|attempt| attempt.timestamp > cutoff);

        // Add new attempt (just timestamp, no credentials)
        self.attempts.push(LoginAttempt {
            timestamp: now,
        });
    }

    /// Get count of recent attempts
    fn recent_count(&self) -> usize {
        self.attempts.len()
    }

    /// Check if attempts show rapid pattern
    fn has_rapid_pattern(&self) -> bool {
        self.attempts.len() >= PATTERN_THRESHOLD
    }
}

// REMOVED: Credential stuffing tracking for RGPD compliance
// We no longer track credentials across IPs to avoid storing passwords

/// Brute force detector implementation
pub struct BruteForceDetector {
    /// Per-IP tracking (counts only, no credentials stored)
    ip_tracking: Arc<DashMap<IpAddr, IpTrackingData>>,
    enabled: bool,
}

impl BruteForceDetector {
    /// Create a new `BruteForceDetector`
    #[must_use]
    pub fn new() -> Self {
        Self {
            ip_tracking: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Check if path is an authentication endpoint
    fn is_auth_endpoint(path: &str) -> bool {
        AUTH_ENDPOINT_PATTERNS.is_match(path)
    }

    // REMOVED: extract_credentials() - RGPD compliance
    // We no longer extract or store usernames/passwords

    /// Track failed login attempt (counts only, no credentials)
    fn track_attempt(&self, ip: &IpAddr) {
        // Track per-IP (just count, no credentials stored)
        self.ip_tracking
            .entry(*ip)
            .or_insert_with(IpTrackingData::new)
            .add_attempt();
    }

    /// Analyze failed login patterns (RGPD-compliant - no credential storage)
    fn analyze_auth_attempt(&self, context: &HttpRequestContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Track this attempt (count only, no credentials)
        self.track_attempt(&context.ip);

        // Check per-IP attempts
        if let Some(tracking) = self.ip_tracking.get(&context.ip) {
            let count = tracking.recent_count();

            // Generate FailedLogin signal after threshold
            if count >= FAILED_LOGIN_THRESHOLD {
                tracing::warn!(
                    ip = %context.ip,
                    path = %context.path,
                    attempt_count = count,
                    "Brute force detected: multiple failed login attempts"
                );
                signals.push(Signal::new(SignalVariant::FailedLogin));
            }

            // Generate LoginAttemptPattern for rapid attempts
            if tracking.has_rapid_pattern() {
                tracing::warn!(
                    ip = %context.ip,
                    path = %context.path,
                    attempt_count = count,
                    "Login attempt pattern detected"
                );
                signals.push(Signal::new(SignalVariant::LoginAttemptPattern));
            }
        }

        // REMOVED: Credential stuffing detection for RGPD compliance
        // We no longer track credentials across IPs

        signals
    }
}

impl Default for BruteForceDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for BruteForceDetector {
    fn name(&self) -> &'static str {
        "BruteForceDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        // Only analyze POST requests to auth endpoints
        if context.method != "POST" || !Self::is_auth_endpoint(&context.path) {
            return DetectionResult::clean();
        }

        let signals = self.analyze_auth_attempt(context);

        if signals.is_empty() {
            DetectionResult::clean()
        } else {
            DetectionResult::with_signals(signals)
        }
    }

    fn enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn create_context(ip: &str, path: &str, username: &str, password: &str) -> HttpRequestContext {
        let body = format!("username={username}&password={password}");

        HttpRequestContext {
            ip: IpAddr::from_str(ip).unwrap(),
            method: "POST".to_string(),
            path: path.to_string(),
            query: None,
            headers: vec![],
            body: Some(body.into_bytes()),
            user_agent: Some("Mozilla/5.0".to_string()),
            referer: None,
            content_type: Some("application/x-www-form-urlencoded".to_string()),
        }
    }

    #[test]
    fn test_is_auth_endpoint() {
        assert!(BruteForceDetector::is_auth_endpoint("/login"));
        assert!(BruteForceDetector::is_auth_endpoint("/signin"));
        assert!(BruteForceDetector::is_auth_endpoint("/admin/login"));
        assert!(BruteForceDetector::is_auth_endpoint("/api/auth"));
        assert!(!BruteForceDetector::is_auth_endpoint("/api/users"));
        assert!(!BruteForceDetector::is_auth_endpoint("/dashboard"));
    }

    // REMOVED: test_extract_credentials() - Function removed for RGPD compliance

    #[tokio::test]
    async fn test_single_attempt_no_signal() {
        let detector = BruteForceDetector::new();
        let context = create_context("192.168.1.1", "/login", "admin", "wrongpass");

        let result = detector.analyze(&context).await;

        // First attempt should not generate signal
        assert!(!result.suspicious);
        assert!(result.signals.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_attempts_generate_signal() {
        let detector = BruteForceDetector::new();
        let ip = "192.168.1.1";

        // Make 5 failed attempts
        for i in 0..5 {
            let context = create_context(ip, "/login", "admin", &format!("pass{i}"));
            let result = detector.analyze(&context).await;

            if i >= 4 {
                // After 5th attempt (index 4), should generate signal
                assert!(result.suspicious);
                let has_failed_login = result
                    .signals
                    .iter()
                    .any(|s| matches!(s.variant, SignalVariant::FailedLogin));
                assert!(has_failed_login);
            }
        }
    }

    #[tokio::test]
    async fn test_non_auth_endpoint_ignored() {
        let detector = BruteForceDetector::new();
        let mut context = create_context("192.168.1.1", "/api/users", "admin", "pass");
        context.method = "GET".to_string();

        let result = detector.analyze(&context).await;

        assert!(!result.suspicious);
        assert!(result.signals.is_empty());
    }
}
