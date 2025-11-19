//! Session hijacking detection
//!
//! Detects session-based attacks including hijacking, fixation, and abnormal session patterns.

use super::detector::{DetectionResult, Detector, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Session tracking data per session token
#[derive(Debug, Clone)]
struct SessionData {
    /// IP address that established this session
    ip: IpAddr,
    /// User-Agent that established this session
    user_agent: String,
    /// Number of times session has switched IPs
    ip_changes: usize,
    /// Number of times User-Agent has changed
    ua_changes: usize,
}

impl SessionData {
    fn new(ip: IpAddr, user_agent: String) -> Self {
        Self {
            ip,
            user_agent,
            ip_changes: 0,
            ua_changes: 0,
        }
    }
}

/// Per-IP session switching tracking
#[derive(Debug, Default)]
struct IpSessionData {
    /// Set of unique session tokens seen from this IP
    unique_sessions: std::collections::HashSet<String>,
}

/// Protected paths that require session authentication
const PROTECTED_PATHS: &[&str] = &["/admin", "/dashboard", "/profile", "/settings", "/api"];

/// Suspicious session token patterns (too uniform/predictable)
const SUSPICIOUS_SESSION_PATTERNS: &[&str] = &["AAAA", "1111", "0000", "FFFF"];

/// Session hijacking detector
///
/// Tracks session tokens and detects anomalies including IP changes,
/// User-Agent switches, session fixation, and rapid session switching.
#[derive(Clone)]
pub struct SessionDetector {
    /// Session token -> tracking data
    session_tracking: Arc<DashMap<String, SessionData>>,
    /// IP -> session switching data
    ip_tracking: Arc<DashMap<IpAddr, IpSessionData>>,
    /// Whether the detector is enabled
    enabled: bool,
}

impl SessionDetector {
    /// Create a new `SessionDetector`
    #[must_use]
    pub fn new() -> Self {
        Self {
            session_tracking: Arc::new(DashMap::new()),
            ip_tracking: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Extract session token from Cookie header
    fn extract_session_token(headers: &[(String, String)]) -> Option<String> {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            .and_then(|(_, value)| {
                // Parse cookie: "session=TOKEN; other=value"
                value
                    .split(';')
                    .find(|part| part.trim().starts_with("session="))
                    .map(|part| part.trim().trim_start_matches("session=").to_string())
            })
    }

    /// Check if path requires session authentication
    fn is_protected_path(path: &str) -> bool {
        PROTECTED_PATHS.iter().any(|prefix| path.starts_with(prefix))
    }

    /// Check if session token looks suspicious (fixation attempt)
    fn is_suspicious_session_token(token: &str) -> bool {
        // Too short
        if token.len() < 8 {
            return true;
        }

        // Suspicious patterns
        if SUSPICIOUS_SESSION_PATTERNS.iter().any(|pattern| token.contains(pattern)) {
            return true;
        }

        false
    }

    /// Analyze session for hijacking indicators
    fn analyze_session(&self, context: &HttpRequestContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Extract session token
        let session_token = Self::extract_session_token(&context.headers);

        // Check for missing session on protected path
        if session_token.is_none() && Self::is_protected_path(&context.path) {
            tracing::warn!(
                ip = %context.ip,
                path = %context.path,
                "Missing session token on protected path"
            );
            signals.push(Signal::new(SignalVariant::SessionTokenAnomaly));
            return signals;
        }

        if let Some(token) = session_token {
            // Check for session fixation (suspicious token pattern)
            if Self::is_suspicious_session_token(&token) {
                tracing::warn!(
                    ip = %context.ip,
                    token = %token,
                    "Suspicious session token pattern (fixation attempt)"
                );
                signals.push(Signal::new(SignalVariant::SessionFixationAttempt));
            }

            // Track session data
            let current_ua = context.user_agent.clone().unwrap_or_default();

            let mut entry = self
                .session_tracking
                .entry(token.clone())
                .or_insert_with(|| SessionData::new(context.ip, current_ua.clone()));

            // Check for IP change
            if entry.ip != context.ip {
                entry.ip_changes += 1;

                tracing::warn!(
                    old_ip = %entry.ip,
                    new_ip = %context.ip,
                    session = %token,
                    "Session IP address change detected (potential hijacking)"
                );

                signals.push(Signal::new(SignalVariant::SessionTokenAnomaly));
                entry.ip = context.ip; // Update to new IP
            }

            // Check for User-Agent change
            if !entry.user_agent.is_empty() && entry.user_agent != current_ua {
                entry.ua_changes += 1;

                tracing::warn!(
                    old_ua = %entry.user_agent,
                    new_ua = %current_ua,
                    session = %token,
                    "Session User-Agent change detected (potential hijacking)"
                );

                signals.push(Signal::new(SignalVariant::SessionTokenAnomaly));
                entry.user_agent = current_ua; // Update to new UA
            }

            // Track rapid session switching per IP
            let mut ip_entry = self.ip_tracking.entry(context.ip).or_default();
            ip_entry.unique_sessions.insert(token.clone());

            // Rapid session switching (>5 different sessions from same IP)
            if ip_entry.unique_sessions.len() > 5 {
                tracing::warn!(
                    ip = %context.ip,
                    count = ip_entry.unique_sessions.len(),
                    "Rapid session switching detected"
                );
                signals.push(Signal::new(SignalVariant::SessionTokenAnomaly));
            }
        }

        signals
    }
}

impl Default for SessionDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for SessionDetector {
    fn name(&self) -> &str {
        "SessionDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        if !self.enabled {
            return DetectionResult::clean();
        }

        let signals = self.analyze_session(context);

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

    fn create_context(
        ip: &str,
        path: &str,
        headers: Vec<(String, String)>,
        user_agent: Option<String>,
    ) -> HttpRequestContext {
        HttpRequestContext {
            ip: IpAddr::from_str(ip).unwrap(),
            method: "GET".to_string(),
            path: path.to_string(),
            query: None,
            headers,
            body: None,
            user_agent,
            referer: None,
            content_type: None,
        }
    }

    #[tokio::test]
    async fn test_normal_session() {
        let detector = SessionDetector::new();

        let headers = vec![("Cookie".to_string(), "session=validtoken123".to_string())];
        let ua = Some("Mozilla/5.0".to_string());

        let context = create_context("192.168.1.1", "/dashboard", headers, ua);
        let result = detector.analyze(&context).await;

        assert!(!result.suspicious, "Normal session should not be flagged");
    }

    #[tokio::test]
    async fn test_extract_session_token() {
        let headers = vec![("Cookie".to_string(), "session=abc123; other=value".to_string())];
        let token = SessionDetector::extract_session_token(&headers);
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_protected_path() {
        assert!(SessionDetector::is_protected_path("/admin/users"));
        assert!(SessionDetector::is_protected_path("/dashboard"));
        assert!(!SessionDetector::is_protected_path("/login"));
    }

    #[tokio::test]
    async fn test_suspicious_token() {
        assert!(SessionDetector::is_suspicious_session_token("AAAAAAAA"));
        assert!(SessionDetector::is_suspicious_session_token("short"));
        assert!(!SessionDetector::is_suspicious_session_token("valid_token_12345"));
    }
}
