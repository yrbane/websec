//! Session hijacking detection (token anomaly analysis)
//!
//! Detects session-based attacks by tracking session tokens and monitoring for
//! suspicious changes in IP addresses, User-Agents, and session usage patterns.
//! Critical for preventing account takeover and session-based attacks.
//!
//! # Detection Techniques
//!
//! 1. **IP Address Tracking**: Detects when same session appears from different IPs
//! 2. **User-Agent Tracking**: Flags browser/device changes within same session
//! 3. **Session Fixation Detection**: Identifies suspicious token patterns
//! 4. **Protected Path Validation**: Ensures sessions exist for sensitive resources
//! 5. **Session Switching Detection**: Monitors rapid session changes per IP
//!
//! # Common Attacks Detected
//!
//! - **Session hijacking**: Stolen session tokens used from different IP/device
//! - **Session fixation**: Attacker forces predictable session ID (AAAA, 1111, etc.)
//! - **Session switching**: Rapid enumeration of session tokens
//! - **Missing authentication**: Access to protected paths without valid session
//!
//! # Example
//!
//! ```rust
//! use websec::detectors::{SessionDetector, Detector, HttpRequestContext};
//! use std::net::IpAddr;
//!
//! # async fn example() {
//! let detector = SessionDetector::new();
//!
//! // First request establishes session baseline
//! let headers1 = vec![("Cookie".to_string(), "session=valid_token_abc".to_string())];
//! let context1 = HttpRequestContext {
//!     ip: "192.168.1.10".parse().unwrap(),
//!     method: "GET".to_string(),
//!     path: "/dashboard".to_string(),
//!     query: None,
//!     headers: headers1,
//!     body: None,
//!     user_agent: Some("Mozilla/5.0".to_string()),
//!     referer: None,
//!     content_type: None,
//! };
//! let result1 = detector.analyze(&context1).await;
//! assert!(!result1.suspicious); // Normal - establishes baseline
//!
//! // Same session from different IP (potential hijacking)
//! let headers2 = vec![("Cookie".to_string(), "session=valid_token_abc".to_string())];
//! let context2 = HttpRequestContext {
//!     ip: "10.0.0.99".parse().unwrap(), // Different IP!
//!     method: "GET".to_string(),
//!     path: "/admin".to_string(),
//!     query: None,
//!     headers: headers2,
//!     body: None,
//!     user_agent: Some("Mozilla/5.0".to_string()),
//!     referer: None,
//!     content_type: None,
//! };
//! let result2 = detector.analyze(&context2).await;
//! assert!(result2.suspicious); // Hijacking detected!
//! # }
//! ```
//!
//! # Signal Weights
//!
//! - `SessionTokenAnomaly`: 15 (IP/UA change, missing session, rapid switching)
//! - `SessionFixationAttempt`: 25 (suspicious token pattern)
//!
//! # Performance
//!
//! - **Session lookup**: O(1) DashMap get/insert per token
//! - **IP tracking**: O(1) DashMap get/insert per IP
//! - **Cookie parsing**: O(n) where n = cookie string length
//! - **Memory**: Grows with unique sessions and IPs (consider TTL/cleanup in production)
//!
//! # Protected Paths
//!
//! Default protected paths requiring valid sessions:
//! - `/admin/*` - Administration interfaces
//! - `/dashboard/*` - User dashboards
//! - `/profile/*` - User profiles
//! - `/settings/*` - Account settings
//! - `/api/*` - API endpoints

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
/// Stateful detector that maintains per-session and per-IP tracking to identify
/// session-based attacks through behavioral analysis and token validation.
///
/// # Fields
///
/// - `session_tracking`: Maps session tokens to baseline data (IP, User-Agent, change counters)
/// - `ip_tracking`: Maps IPs to unique session sets for rapid switching detection
/// - `enabled`: Detector activation flag (always true by default)
///
/// # Thread Safety
///
/// Fully thread-safe via `DashMap`. Multiple threads can analyze requests
/// concurrently without blocking. Each session token and IP has independent locks.
///
/// # Detection Strategy
///
/// 1. **First request** with new session token establishes baseline (IP + User-Agent)
/// 2. **Subsequent requests** compare against baseline:
///    - IP change → `SessionTokenAnomaly`
///    - User-Agent change → `SessionTokenAnomaly`
///    - Suspicious token pattern → `SessionFixationAttempt`
/// 3. **Per-IP tracking** monitors unique session count (>5 triggers alarm)
/// 4. **Protected paths** require valid session token (≥8 chars, no suspicious patterns)
///
/// # Memory Management
///
/// Memory grows with number of active sessions and unique IPs. In production:
/// - Consider TTL-based cleanup (expire old sessions)
/// - Implement LRU eviction for `session_tracking`
/// - Monitor memory usage under high session churn
///
/// # Limitations
///
/// - **Mobile networks**: Legitimate IP changes may trigger false positives (cellular roaming)
/// - **VPN users**: VPN reconnects can change IPs legitimately
/// - **Shared IPs**: NAT/proxy environments may cause session collisions
/// - Consider allowing configurable thresholds for production environments
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
    ///
    /// # Arguments
    ///
    /// * `headers` - Request headers as (name, value) tuples
    ///
    /// # Returns
    ///
    /// Session token if present, None otherwise
    ///
    /// # Cookie Format
    ///
    /// Expects cookie format: `session=TOKEN` or `session=TOKEN; other=value`
    /// Case-insensitive header name matching ("Cookie", "cookie", "COOKIE")
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let headers = vec![("Cookie".to_string(), "session=abc123; path=/".to_string())];
    /// let token = SessionDetector::extract_session_token(&headers);
    /// assert_eq!(token, Some("abc123".to_string()));
    ///
    /// let headers = vec![("Cookie".to_string(), "other=value".to_string())];
    /// let token = SessionDetector::extract_session_token(&headers);
    /// assert_eq!(token, None);
    /// ```
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
    ///
    /// # Arguments
    ///
    /// * `path` - Request URI path
    ///
    /// # Returns
    ///
    /// `true` if path is protected and requires authentication, `false` otherwise
    ///
    /// # Protected Paths
    ///
    /// Paths starting with:
    /// - `/admin` - Administration interfaces
    /// - `/dashboard` - User dashboards
    /// - `/profile` - User profiles
    /// - `/settings` - Account settings
    /// - `/api` - API endpoints
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// assert!(SessionDetector::is_protected_path("/admin/users"));
    /// assert!(SessionDetector::is_protected_path("/dashboard"));
    /// assert!(!SessionDetector::is_protected_path("/login"));
    /// assert!(!SessionDetector::is_protected_path("/public/images/logo.png"));
    /// ```
    fn is_protected_path(path: &str) -> bool {
        PROTECTED_PATHS.iter().any(|prefix| path.starts_with(prefix))
    }

    /// Check if session token looks suspicious (fixation attempt)
    ///
    /// # Arguments
    ///
    /// * `token` - Session token string to validate
    ///
    /// # Returns
    ///
    /// `true` if token appears suspicious (potential fixation attack), `false` otherwise
    ///
    /// # Suspicious Patterns
    ///
    /// 1. **Too short**: Tokens < 8 characters (weak entropy)
    /// 2. **Repetitive**: Contains AAAA, 1111, 0000, FFFF (predictable patterns)
    ///
    /// # Session Fixation
    ///
    /// Attackers attempt to force predictable session IDs that they control.
    /// Legitimate session tokens should be:
    /// - Cryptographically random (high entropy)
    /// - Sufficiently long (≥8 characters minimum, 32+ recommended)
    /// - No obvious patterns
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// assert!(SessionDetector::is_suspicious_session_token("AAAAAAAA")); // Repetitive
    /// assert!(SessionDetector::is_suspicious_session_token("short")); // Too short
    /// assert!(SessionDetector::is_suspicious_session_token("test1111")); // Contains 1111
    /// assert!(!SessionDetector::is_suspicious_session_token("a3f9d8e7c2b1")); // Valid
    /// ```
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
    ///
    /// # Arguments
    ///
    /// * `context` - HTTP request context with headers, IP, User-Agent
    ///
    /// # Returns
    ///
    /// Vector of signals (empty if no anomalies detected)
    ///
    /// # Detection Flow
    ///
    /// 1. **Extract session token** from Cookie header
    /// 2. **Missing session check**: If protected path and no token → signal
    /// 3. **Session fixation check**: If token looks suspicious → signal
    /// 4. **IP change detection**: Compare current IP to session baseline
    /// 5. **User-Agent change detection**: Compare current UA to session baseline
    /// 6. **Rapid switching check**: Track unique sessions per IP (>5 → signal)
    ///
    /// # Side Effects
    ///
    /// - Updates `session_tracking` with new/changed session data
    /// - Updates `ip_tracking` with unique session counts
    /// - Increments change counters (ip_changes, ua_changes)
    ///
    /// # Signal Generation
    ///
    /// - `SessionTokenAnomaly` (weight 15): IP/UA changes, missing session, rapid switching
    /// - `SessionFixationAttempt` (weight 25): Suspicious token pattern
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
