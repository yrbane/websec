//! Brute force attack detection
//!
//! Detects brute force and credential stuffing attacks through:
//! - Failed login attempt tracking per IP
//! - Rapid authentication attempt patterns
//! - Credential stuffing detection (cross-IP correlation)
//! - Time-windowed tracking with automatic expiry

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
const CREDENTIAL_STUFFING_THRESHOLD: usize = 4; // Same creds from N different IPs

/// Failed login attempt record
#[derive(Debug, Clone)]
struct LoginAttempt {
    timestamp: DateTime<Utc>,
    #[allow(dead_code)]
    username: Option<String>,
    #[allow(dead_code)]
    password_hash: Option<String>, // Simple hash for credential correlation
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
    fn add_attempt(&mut self, username: Option<String>, password: Option<String>) {
        let now = Utc::now();
        let cutoff = now - Duration::minutes(TIME_WINDOW_MINUTES);

        // Remove expired attempts
        self.attempts.retain(|attempt| attempt.timestamp > cutoff);

        // Add new attempt
        let password_hash = password.map(|p| format!("{:x}", md5::compute(p.as_bytes())));
        self.attempts.push(LoginAttempt {
            timestamp: now,
            username,
            password_hash,
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

/// Credential stuffing tracking (cross-IP)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CredentialKey {
    username: String,
    password_hash: String,
}

/// Brute force detector implementation
pub struct BruteForceDetector {
    /// Per-IP tracking
    ip_tracking: Arc<DashMap<IpAddr, IpTrackingData>>,
    /// Credential stuffing tracking (credential -> set of IPs)
    credential_tracking: Arc<DashMap<CredentialKey, Vec<IpAddr>>>,
    enabled: bool,
}

impl BruteForceDetector {
    /// Create a new `BruteForceDetector`
    #[must_use]
    pub fn new() -> Self {
        Self {
            ip_tracking: Arc::new(DashMap::new()),
            credential_tracking: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Check if path is an authentication endpoint
    fn is_auth_endpoint(path: &str) -> bool {
        AUTH_ENDPOINT_PATTERNS.is_match(path)
    }

    /// Extract username and password from request body
    fn extract_credentials(context: &HttpRequestContext) -> (Option<String>, Option<String>) {
        let body = match &context.body {
            Some(b) => String::from_utf8_lossy(b).to_string(),
            None => return (None, None),
        };

        let mut username = None;
        let mut password = None;

        // Parse form-encoded body
        for pair in body.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let decoded_value = urlencoding::decode(value).unwrap_or_default().to_string();
                match key {
                    "username" | "user" | "email" | "login" => username = Some(decoded_value),
                    "password" | "pass" | "pwd" => password = Some(decoded_value),
                    _ => {}
                }
            }
        }

        (username, password)
    }

    /// Track failed login attempt
    fn track_attempt(&self, ip: &IpAddr, username: Option<String>, password: Option<String>) {
        // Track per-IP
        self.ip_tracking
            .entry(*ip)
            .or_insert_with(IpTrackingData::new)
            .add_attempt(username.clone(), password.clone());

        // Track for credential stuffing detection
        if let (Some(user), Some(pass)) = (username, password) {
            let password_hash = format!("{:x}", md5::compute(pass.as_bytes()));
            let key = CredentialKey {
                username: user,
                password_hash,
            };

            self.credential_tracking.entry(key).or_default().push(*ip);
        }
    }

    /// Analyze failed login patterns
    fn analyze_auth_attempt(&self, context: &HttpRequestContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        let (username, password) = Self::extract_credentials(context);

        // Track this attempt
        self.track_attempt(&context.ip, username.clone(), password.clone());

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

        // Check for credential stuffing (same credentials from multiple IPs)
        if let (Some(user), Some(pass)) = (username, password) {
            let password_hash = format!("{:x}", md5::compute(pass.as_bytes()));
            let key = CredentialKey {
                username: user,
                password_hash,
            };

            if let Some(ips) = self.credential_tracking.get(&key) {
                // Count unique IPs
                let unique_ips: std::collections::HashSet<_> = ips.iter().collect();
                if unique_ips.len() >= CREDENTIAL_STUFFING_THRESHOLD {
                    tracing::warn!(
                        ip = %context.ip,
                        unique_ip_count = unique_ips.len(),
                        "Credential stuffing detected: same credentials from multiple IPs"
                    );
                    signals.push(Signal::new(SignalVariant::CredentialStuffing));
                }
            }
        }

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

    #[test]
    fn test_extract_credentials() {
        let context = create_context("192.168.1.1", "/login", "admin", "password123");

        let (username, password) = BruteForceDetector::extract_credentials(&context);

        assert_eq!(username, Some("admin".to_string()));
        assert_eq!(password, Some("password123".to_string()));
    }

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
