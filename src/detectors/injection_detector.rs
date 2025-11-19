//! Injection attack detection (SQL, XSS, Path Traversal, RCE)
//!
//! Detects various injection attacks through pattern matching on user inputs:
//! - **SQL injection**: UNION SELECT, DROP TABLE, OR '1'='1, time-based (SLEEP, WAITFOR)
//! - **XSS**: `<script>`, event handlers (onerror, onload), javascript: protocol
//! - **Path traversal**: `../`, `..\\`, URL-encoded variants (%2e%2e%2f)
//! - **Command injection**: `;cat`, backticks, `$()`, pipe operators
//!
//! # Architecture
//!
//! This detector implements the Strategy pattern via the [`Detector`] trait and
//! reuses parsing utilities from [`crate::utils::parser`] for pattern matching.
//!
//! # Detection Flow
//!
//! 1. Extract all user inputs (query params, POST body, URL path)
//! 2. Check each input against injection patterns (SQL, XSS, path traversal, RCE)
//! 3. Generate appropriate signals for detected threats
//! 4. Return [`DetectionResult`] with accumulated signals
//!
//! # Example
//!
//! ```rust
//! use websec::detectors::{InjectionDetector, Detector, HttpRequestContext};
//! use std::net::IpAddr;
//!
//! # async fn example() {
//! let detector = InjectionDetector::new();
//! let context = HttpRequestContext {
//!     ip: "192.168.1.100".parse().unwrap(),
//!     method: "GET".to_string(),
//!     path: "/api/user".to_string(),
//!     query: Some("id=1' OR '1'='1".to_string()),
//!     headers: vec![],
//!     body: None,
//!     user_agent: Some("Mozilla/5.0".to_string()),
//!     referer: None,
//!     content_type: None,
//! };
//!
//! let result = detector.analyze(&context).await;
//! assert!(result.suspicious); // SQL injection detected
//! # }
//! ```
//!
//! # Signal Weights
//!
//! - `SqlInjectionAttempt`: 30 (high severity)
//! - `XssAttempt`: 30 (high severity)
//! - `PathTraversalAttempt`: 30 (high severity)
//! - `RceAttempt`: 50 (critical severity - highest)

use super::detector::{DetectionResult, Detector, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use crate::utils::{
    contains_command_injection, contains_path_traversal, contains_sql_injection, contains_xss,
    parse_query_string,
};
use async_trait::async_trait;

/// Injection detector implementation
///
/// Analyzes HTTP requests for injection attack patterns across multiple attack families:
/// SQL injection, XSS, path traversal, and command injection (RCE).
///
/// # Fields
///
/// - `enabled`: Whether the detector is active (always true by default)
///
/// # Detection Techniques
///
/// - **Pattern matching**: Uses regex patterns from [`crate::utils::parser`]
/// - **Input extraction**: Scans query params, POST body, and URL path
/// - **Multi-pattern detection**: Can detect multiple injection types in same request
///
/// # Performance
///
/// - Regex patterns are compiled once using `once_cell::Lazy`
/// - URL decoding happens automatically before pattern matching
/// - Average detection time: <1ms per request
pub struct InjectionDetector {
    enabled: bool,
}

impl InjectionDetector {
    /// Create a new InjectionDetector with default settings
    ///
    /// The detector is enabled by default and uses predefined patterns
    /// for SQL, XSS, path traversal, and command injection detection.
    #[must_use]
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Extract all user inputs from request (query, body, path)
    ///
    /// # Returns
    ///
    /// Vector of strings containing all user-controlled inputs that should be
    /// checked for injection patterns. Includes:
    /// - Full query string
    /// - Individual query parameter values
    /// - POST body (if form-encoded)
    /// - Individual POST body parameter values
    /// - URL path
    fn extract_inputs(&self, context: &HttpRequestContext) -> Vec<String> {
        let mut inputs = Vec::new();

        // Query parameters
        if let Some(query) = &context.query {
            inputs.push(query.clone());

            // Parse individual param values
            let params = parse_query_string(query);
            inputs.extend(params.values().cloned());
        }

        // POST body (form-encoded)
        if let Some(body) = &context.body {
            if let Ok(body_str) = String::from_utf8(body.clone()) {
                inputs.push(body_str.clone());

                // Parse form parameters
                let params = parse_query_string(&body_str);
                inputs.extend(params.values().cloned());
            }
        }

        // Path (for path traversal in file paths)
        inputs.push(context.path.clone());

        inputs
    }

    /// Analyze inputs for SQL injection
    fn check_sql_injection(&self, inputs: &[String]) -> bool {
        inputs.iter().any(|input| contains_sql_injection(input))
    }

    /// Analyze inputs for XSS
    fn check_xss(&self, inputs: &[String]) -> bool {
        inputs.iter().any(|input| contains_xss(input))
    }

    /// Analyze inputs for path traversal
    fn check_path_traversal(&self, inputs: &[String]) -> bool {
        inputs.iter().any(|input| contains_path_traversal(input))
    }

    /// Analyze inputs for command injection
    fn check_command_injection(&self, inputs: &[String]) -> bool {
        inputs.iter().any(|input| contains_command_injection(input))
    }

    /// Analyze request for all injection types
    fn analyze_injections(&self, context: &HttpRequestContext) -> Vec<Signal> {
        let mut signals = Vec::new();
        let inputs = self.extract_inputs(context);

        // Check SQL injection
        if self.check_sql_injection(&inputs) {
            tracing::warn!(
                ip = %context.ip,
                path = %context.path,
                method = %context.method,
                "SQL injection attempt detected"
            );
            signals.push(Signal::new(SignalVariant::SqlInjectionAttempt));
        }

        // Check XSS
        if self.check_xss(&inputs) {
            tracing::warn!(
                ip = %context.ip,
                path = %context.path,
                method = %context.method,
                "XSS attempt detected"
            );
            signals.push(Signal::new(SignalVariant::XssAttempt));
        }

        // Check path traversal
        if self.check_path_traversal(&inputs) {
            tracing::warn!(
                ip = %context.ip,
                path = %context.path,
                method = %context.method,
                "Path traversal attempt detected"
            );
            signals.push(Signal::new(SignalVariant::PathTraversalAttempt));
        }

        // Check command injection / RCE
        if self.check_command_injection(&inputs) {
            tracing::warn!(
                ip = %context.ip,
                path = %context.path,
                method = %context.method,
                "Command injection / RCE attempt detected"
            );
            signals.push(Signal::new(SignalVariant::RceAttempt));
        }

        signals
    }
}

impl Default for InjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for InjectionDetector {
    fn name(&self) -> &str {
        "InjectionDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        let signals = self.analyze_injections(context);

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
    use std::net::IpAddr;
    use std::str::FromStr;

    fn create_context(query: Option<&str>, body: Option<&str>) -> HttpRequestContext {
        HttpRequestContext {
            ip: IpAddr::from_str("192.168.1.1").unwrap(),
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: query.map(String::from),
            headers: vec![],
            body: body.map(|b| b.as_bytes().to_vec()),
            user_agent: Some("Mozilla/5.0".to_string()),
            referer: None,
            content_type: None,
        }
    }

    #[tokio::test]
    async fn test_detect_sqli_in_query() {
        let detector = InjectionDetector::new();
        let context = create_context(Some("id=1' OR '1'='1"), None);

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        let has_sqli = result
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::SqlInjectionAttempt));
        assert!(has_sqli);
    }

    #[tokio::test]
    async fn test_detect_xss_in_query() {
        let detector = InjectionDetector::new();
        let context = create_context(Some("q=<script>alert(1)</script>"), None);

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        let has_xss = result
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::XssAttempt));
        assert!(has_xss);
    }

    #[tokio::test]
    async fn test_detect_path_traversal() {
        let detector = InjectionDetector::new();
        let context = create_context(Some("file=../../etc/passwd"), None);

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        let has_traversal = result
            .signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::PathTraversalAttempt));
        assert!(has_traversal);
    }

    #[tokio::test]
    async fn test_detect_multiple_injections() {
        let detector = InjectionDetector::new();
        // Both SQLi and XSS in same request
        let context = create_context(
            Some("id=1' UNION SELECT password"),
            Some("comment=<script>alert(1)</script>"),
        );

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        assert!(
            result.signals.len() >= 2,
            "Should detect multiple injection types"
        );
    }

    #[tokio::test]
    async fn test_clean_request() {
        let detector = InjectionDetector::new();
        let context = create_context(Some("q=hello+world&page=1"), None);

        let result = detector.analyze(&context).await;

        assert!(!result.suspicious);
        assert!(result.signals.is_empty());
    }

    #[test]
    fn test_extract_inputs() {
        let detector = InjectionDetector::new();
        let context = create_context(Some("id=1&name=test"), Some("email=test@example.com"));

        let inputs = detector.extract_inputs(&context);

        // Should include: query string, param values, body, body params, path
        assert!(inputs.len() >= 5);
        assert!(inputs.contains(&"id=1&name=test".to_string()));
        assert!(inputs.contains(&"1".to_string()));
        assert!(inputs.contains(&"test".to_string()));
    }
}
