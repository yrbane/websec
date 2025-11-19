//! HTTP header manipulation detection
//!
//! Detects attacks targeting HTTP headers and HTTP smuggling attempts.
//!
//! # Threat Families Detected
//!
//! - **Header Injection**: CRLF injection (\r\n) to split responses or inject headers
//! - **Host Header Attacks**: Multiple Host headers, cache poisoning attempts
//! - **Referer Spoofing**: Suspicious referrer domains
//! - **X-Forwarded-For Manipulation**: IP spoofing via proxy headers
//! - **Oversized Headers**: Buffer overflow attempts
//!
//! # Implementation Strategy
//!
//! This detector analyzes HTTP headers for manipulation patterns:
//!
//! 1. **CRLF Detection**: Scans for `\r`, `\n`, `\r\n` in header names and values
//! 2. **Host Header Validation**: Ensures single Host header (HTTP/1.1 requirement)
//! 3. **Size Limits**: Enforces 8KB max per header value
//! 4. **Null Byte Detection**: Prevents string termination attacks
//! 5. **Proxy Header Analysis**: Validates X-Forwarded-For chains
//!
//! # Signals Generated
//!
//! - `HeaderInjection` (weight 20): CRLF, null bytes, oversized headers, XFF manipulation
//! - `HostHeaderAttack` (weight 20): Multiple Host headers detected
//! - `RefererSpoofing` (weight 10): Suspicious TLD in Referer header
//!
//! # Attack Examples Detected
//!
//! ```text
//! # CRLF Injection
//! Host: evil.com\r\n
//! X-Injected: malicious
//!
//! # Multiple Host Headers (cache poisoning)
//! Host: legitimate.com
//! Host: evil.com
//!
//! # X-Forwarded-For Spoofing
//! X-Forwarded-For: 127.0.0.1, 127.0.0.1, 127.0.0.1
//! ```
//!
//! # Example Usage
//!
//! ```rust
//! use websec::detectors::{HeaderDetector, Detector, HttpRequestContext};
//! use std::net::IpAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let detector = HeaderDetector::new();
//!
//! let context = HttpRequestContext {
//!     ip: "192.168.1.100".parse()?,
//!     method: "GET".to_string(),
//!     path: "/".to_string(),
//!     query: None,
//!     headers: vec![
//!         ("Host".to_string(), "evil.com\r\nX-Injected: true".to_string()),
//!     ],
//!     body: None,
//!     user_agent: Some("Mozilla/5.0".to_string()),
//!     referer: None,
//!     content_type: None,
//! };
//!
//! let result = detector.analyze(&context).await;
//! if result.suspicious {
//!     println!("Header manipulation: {:?}", result.signals);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Security Notes
//!
//! - **CRLF Injection**: Can lead to HTTP response splitting, cache poisoning
//! - **Host Header Attacks**: Used in cache poisoning, password reset poisoning
//! - **Oversized Headers**: May cause buffer overflows in poorly written parsers
//! - **XFF Manipulation**: Can bypass IP-based access controls
//!
//! # References
//!
//! - [OWASP: HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
//! - [PortSwigger: Host Header Attacks](https://portswigger.net/web-security/host-header)

use crate::detectors::{Detector, DetectionResult, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;

/// Maximum allowed header value length
const MAX_HEADER_VALUE_LENGTH: usize = 8192;

/// HeaderDetector analyzes HTTP headers for manipulation attempts
#[derive(Clone)]
pub struct HeaderDetector {
    /// Whether detector is enabled
    enabled: bool,
}

impl HeaderDetector {
    /// Create a new HeaderDetector
    #[must_use]
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Detect CRLF injection in header values
    ///
    /// CRLF (\r\n) can be used to inject additional headers or split responses
    fn detect_crlf_injection(&self, headers: &[(String, String)]) -> Vec<Signal> {
        let mut signals = Vec::new();

        for (name, value) in headers {
            // Check for CRLF sequences
            if value.contains("\r\n") || value.contains('\r') || value.contains('\n') {
                let signal = Signal::with_context(
                    SignalVariant::HeaderInjection,
                    20, // Weight from signal.rs
                    format!("CRLF injection detected in header '{}': {}", name, value),
                );
                signals.push(signal);
            }

            // Check header name too
            if name.contains("\r\n") || name.contains('\r') || name.contains('\n') {
                let signal = Signal::with_context(
                    SignalVariant::HeaderInjection,
                    20,
                    format!("CRLF injection detected in header name: {}", name),
                );
                signals.push(signal);
            }

            // Check for null bytes
            if value.contains('\0') || name.contains('\0') {
                let signal = Signal::with_context(
                    SignalVariant::HeaderInjection,
                    20,
                    format!("Null byte injection detected in header '{}'", name),
                );
                signals.push(signal);
            }
        }

        signals
    }

    /// Detect multiple Host headers (attack vector)
    fn detect_multiple_host_headers(&self, headers: &[(String, String)]) -> Vec<Signal> {
        let mut signals = Vec::new();

        let host_count = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .count();

        if host_count > 1 {
            let signal = Signal::with_context(
                SignalVariant::HostHeaderAttack,
                20, // Weight from signal.rs
                format!("Multiple Host headers detected: {} instances", host_count),
            );
            signals.push(signal);
        }

        signals
    }

    /// Detect oversized header values (potential buffer overflow)
    fn detect_oversized_headers(&self, headers: &[(String, String)]) -> Vec<Signal> {
        let mut signals = Vec::new();

        for (name, value) in headers {
            if value.len() > MAX_HEADER_VALUE_LENGTH {
                let signal = Signal::with_context(
                    SignalVariant::HeaderInjection,
                    20,
                    format!(
                        "Oversized header '{}': {} bytes (max {})",
                        name,
                        value.len(),
                        MAX_HEADER_VALUE_LENGTH
                    ),
                );
                signals.push(signal);
            }
        }

        signals
    }

    /// Detect suspicious referer patterns
    fn detect_referer_spoofing(
        &self,
        _headers: &[(String, String)],
        referer: &Option<String>,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        if let Some(ref_url) = referer {
            // Check for suspicious TLDs in referer
            let suspicious_tlds = [".ru", ".cn", ".tk", ".ml"];
            for tld in &suspicious_tlds {
                if ref_url.to_lowercase().contains(tld) {
                    let signal = Signal::with_context(
                        SignalVariant::RefererSpoofing,
                        10, // Weight from signal.rs
                        format!("Suspicious referer TLD: {}", ref_url),
                    );
                    signals.push(signal);
                    break;
                }
            }
        }

        signals
    }

    /// Detect X-Forwarded-For manipulation
    fn detect_xff_spoofing(&self, headers: &[(String, String)]) -> Vec<Signal> {
        let mut signals = Vec::new();

        for (name, value) in headers {
            if name.eq_ignore_ascii_case("x-forwarded-for") {
                // Check for excessive localhost entries (spoofing attempt)
                let localhost_count = value.matches("127.0.0.1").count();
                if localhost_count > 2 {
                    let signal = Signal::with_context(
                        SignalVariant::HeaderInjection,
                        15,
                        format!(
                            "Suspicious X-Forwarded-For with {} localhost entries",
                            localhost_count
                        ),
                    );
                    signals.push(signal);
                }
            }
        }

        signals
    }
}

impl Default for HeaderDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for HeaderDetector {
    fn name(&self) -> &str {
        "HeaderDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        if !self.enabled {
            return DetectionResult::clean();
        }

        let mut signals = Vec::new();

        // Check for various header manipulation attempts
        signals.extend(self.detect_crlf_injection(&context.headers));
        signals.extend(self.detect_multiple_host_headers(&context.headers));
        signals.extend(self.detect_oversized_headers(&context.headers));
        signals.extend(self.detect_referer_spoofing(&context.headers, &context.referer));
        signals.extend(self.detect_xff_spoofing(&context.headers));

        if signals.is_empty() {
            DetectionResult::clean()
        } else {
            DetectionResult {
                signals: signals.clone(),
                suspicious: true,
                message: Some(format!(
                    "Header manipulation detected: {} signal(s)",
                    signals.len()
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crlf_detection() {
        let detector = HeaderDetector::new();
        let headers = vec![("Host".to_string(), "evil.com\r\nX-Injected: true".to_string())];

        let signals = detector.detect_crlf_injection(&headers);
        assert!(!signals.is_empty());
        assert!(signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::HeaderInjection)));
    }

    #[test]
    fn test_multiple_host_detection() {
        let detector = HeaderDetector::new();
        let headers = vec![
            ("Host".to_string(), "site1.com".to_string()),
            ("Host".to_string(), "site2.com".to_string()),
        ];

        let signals = detector.detect_multiple_host_headers(&headers);
        assert!(!signals.is_empty());
        assert!(signals
            .iter()
            .any(|s| matches!(s.variant, SignalVariant::HostHeaderAttack)));
    }

    #[test]
    fn test_oversized_header_detection() {
        let detector = HeaderDetector::new();
        let long_value = "A".repeat(10000);
        let headers = vec![("X-Custom".to_string(), long_value)];

        let signals = detector.detect_oversized_headers(&headers);
        assert!(!signals.is_empty());
    }

    #[test]
    fn test_clean_headers() {
        let detector = HeaderDetector::new();
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
        ];

        let signals = detector.detect_crlf_injection(&headers);
        assert!(signals.is_empty());
    }
}
