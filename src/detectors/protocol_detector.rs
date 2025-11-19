//! HTTP protocol violation detection
//!
//! Detects requests that violate HTTP/1.1 RFC specifications.

use crate::detectors::{Detector, DetectionResult, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;

/// Maximum allowed path length (8KB)
const MAX_PATH_LENGTH: usize = 8192;

/// Valid HTTP methods according to RFC 7231 and common extensions
const VALID_HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

/// ProtocolDetector analyzes HTTP requests for RFC violations
#[derive(Clone)]
pub struct ProtocolDetector {
    /// Whether detector is enabled
    enabled: bool,
}

impl ProtocolDetector {
    /// Create a new `ProtocolDetector`
    #[must_use]
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Validate HTTP method
    fn validate_method(method: &str) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Check if method is valid
        if !VALID_HTTP_METHODS.contains(&method) {
            let signal = Signal::with_context(
                SignalVariant::InvalidHttpMethod,
                15, // Weight from signal.rs
                format!("Invalid HTTP method: {}", method),
            );
            signals.push(signal);
        }

        // Check for spaces (HTTP request smuggling)
        if method.contains(' ') {
            let signal = Signal::with_context(
                SignalVariant::ProtocolViolation,
                15,
                format!("HTTP method contains space: '{}'", method),
            );
            signals.push(signal);
        }

        signals
    }

    /// Validate request path
    fn validate_path(path: &str) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Check path length
        if path.len() > MAX_PATH_LENGTH {
            let signal = Signal::with_context(
                SignalVariant::MalformedRequest,
                15,
                format!("Oversized path: {} bytes (max {})", path.len(), MAX_PATH_LENGTH),
            );
            signals.push(signal);
        }

        // Check for null bytes
        if path.contains('\0') {
            let signal = Signal::with_context(
                SignalVariant::MalformedRequest,
                15,
                "Path contains null byte".to_string(),
            );
            signals.push(signal);
        }

        // Check for CRLF injection
        if path.contains('\r') || path.contains('\n') {
            let signal = Signal::with_context(
                SignalVariant::MalformedRequest,
                15,
                "Path contains CRLF characters".to_string(),
            );
            signals.push(signal);
        }

        // Check if path starts with /
        if !path.is_empty() && !path.starts_with('/') {
            let signal = Signal::with_context(
                SignalVariant::MalformedRequest,
                10,
                format!("Path does not start with '/': {}", path),
            );
            signals.push(signal);
        }

        signals
    }

    /// Validate HTTP headers (HTTP/1.1 requires Host header)
    fn validate_headers(headers: &[(String, String)]) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Check for Host header (required in HTTP/1.1)
        let has_host = headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host"));

        if !has_host {
            let signal = Signal::with_context(
                SignalVariant::ProtocolViolation,
                10,
                "Missing Host header (required in HTTP/1.1)".to_string(),
            );
            signals.push(signal);
        }

        signals
    }
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for ProtocolDetector {
    fn name(&self) -> &str {
        "ProtocolDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        if !self.enabled {
            return DetectionResult::clean();
        }

        let mut signals = Vec::new();

        // Validate HTTP method
        signals.extend(Self::validate_method(&context.method));

        // Validate request path
        signals.extend(Self::validate_path(&context.path));

        // Validate headers
        signals.extend(Self::validate_headers(&context.headers));

        if signals.is_empty() {
            DetectionResult::clean()
        } else {
            DetectionResult {
                signals: signals.clone(),
                suspicious: true,
                message: Some(format!(
                    "Protocol violation detected: {} issue(s)",
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
    fn test_valid_methods() {
        for method in VALID_HTTP_METHODS {
            let signals = ProtocolDetector::validate_method(method);
            assert!(signals.is_empty(), "Valid method {} should not generate signals", method);
        }
    }

    #[test]
    fn test_invalid_method() {
        let signals = ProtocolDetector::validate_method("HACK");
        assert!(!signals.is_empty());
        assert!(signals.iter().any(|s| matches!(s.variant, SignalVariant::InvalidHttpMethod)));
    }

    #[test]
    fn test_valid_path() {
        let signals = ProtocolDetector::validate_path("/index.html");
        assert!(signals.is_empty());
    }

    #[test]
    fn test_path_with_null_byte() {
        let signals = ProtocolDetector::validate_path("/path\0malicious");
        assert!(!signals.is_empty());
    }

    #[test]
    fn test_missing_host_header() {
        let headers = vec![];
        let signals = ProtocolDetector::validate_headers(&headers);
        assert!(!signals.is_empty());
    }

    #[test]
    fn test_with_host_header() {
        let headers = vec![("Host".to_string(), "example.com".to_string())];
        let signals = ProtocolDetector::validate_headers(&headers);
        assert!(signals.is_empty());
    }
}
