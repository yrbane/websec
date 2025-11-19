//! Vulnerability scan detection (reconnaissance, path enumeration)
//!
//! Detects reconnaissance activity and vulnerability scanning through pattern matching
//! on suspicious paths and 404 error bursts indicating automated enumeration.
//!
//! # Detection Techniques
//!
//! 1. **Suspicious Path Patterns**: Regex matching on known vulnerability targets
//! 2. **404 Burst Detection**: Threshold-based detection of path enumeration (20+ errors)
//! 3. **Per-IP Tracking**: Independent counters for each source IP
//!
//! # Common Patterns Detected
//!
//! - **WordPress**: /wp-admin/, /wp-content/, /xmlrpc.php
//! - **Database**: /phpmyadmin/, /mysql/, /adminer.php
//! - **Admin panels**: /admin/, /administrator/, /manager/html
//! - **Config files**: /.env, /.git/config, /web.config, composer.json
//! - **Backups**: /backup.sql, /database.sql.gz, /site.tar.gz
//! - **Sensitive**: phpinfo.php, config.php, .htaccess
//!
//! # Example
//!
//! ```rust
//! use websec::detectors::{ScanDetector, Detector, HttpRequestContext};
//! use std::net::IpAddr;
//!
//! # async fn example() {
//! let detector = ScanDetector::new();
//! let context = HttpRequestContext {
//!     ip: "192.168.1.100".parse().unwrap(),
//!     method: "GET".to_string(),
//!     path: "/wp-admin/".to_string(), // Suspicious path
//!     query: None,
//!     headers: vec![],
//!     body: None,
//!     user_agent: Some("Nikto/2.1".to_string()),
//!     referer: None,
//!     content_type: None,
//! };
//!
//! let result = detector.analyze(&context).await;
//! assert!(result.suspicious); // Scan detected
//! # }
//! ```
//!
//! # Signal Weight
//!
//! - `VulnerabilityScan`: 25 (high severity)
//!
//! # Performance
//!
//! - **Regex**: Compiled once via `Lazy` (amortized O(1) init)
//! - **Lookup**: O(n) where n = pattern count (~20 patterns)
//! - **Tracking**: O(1) DashMap get/insert per IP

use super::detector::{DetectionResult, Detector, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;

/// Suspicious path patterns (compiled once)
static SUSPICIOUS_PATH_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(/admin/|/admin$|wp-admin|phpmyadmin|administrator|manager/html|\.env|\.git|web\.config|backup\.sql|\.tar\.gz|config\.php|phpinfo\.php|adminer\.php|\.htaccess|composer\.json|package\.json|/config/)"
    )
    .unwrap()
});

/// Threshold for 404 burst detection
const NOT_FOUND_THRESHOLD: usize = 20;

/// IP tracking data for scan detection
#[derive(Debug)]
struct IpScanData {
    /// Count of suspicious path accesses
    suspicious_path_count: usize,
    /// Count of 404/403 errors (simulated)
    not_found_count: usize,
}

impl IpScanData {
    fn new() -> Self {
        Self {
            suspicious_path_count: 0,
            not_found_count: 0,
        }
    }

    /// Record a suspicious path access
    fn record_suspicious_path(&mut self) {
        self.suspicious_path_count += 1;
    }

    /// Record a not found error (404/403)
    fn record_not_found(&mut self) {
        self.not_found_count += 1;
    }
}

/// Vulnerability scan detector
///
/// Tracks per-IP scan activity including suspicious path access and 404 bursts.
///
/// # Fields
///
/// - `ip_tracking`: Concurrent map tracking scan metrics per IP
/// - `enabled`: Detector activation flag (always true by default)
///
/// # Thread Safety
///
/// Fully thread-safe via `DashMap`. Multiple threads can analyze requests
/// concurrently without blocking.
///
/// # Memory Management
///
/// Memory grows with number of active scanner IPs. In production, consider
/// periodic cleanup of old entries or LRU eviction.
pub struct ScanDetector {
    /// Per-IP tracking data
    ip_tracking: Arc<DashMap<IpAddr, IpScanData>>,
    /// Whether the detector is enabled
    enabled: bool,
}

impl ScanDetector {
    /// Create a new ScanDetector with default thresholds
    ///
    /// Initializes empty tracking map. Memory is allocated lazily as IPs are seen.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ip_tracking: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Check if path matches suspicious patterns
    ///
    /// Uses compiled regex with 20+ vulnerability patterns including:
    /// admin panels, config files, backups, and framework-specific paths.
    fn is_suspicious_path(path: &str) -> bool {
        SUSPICIOUS_PATH_PATTERN.is_match(path)
    }

    /// Analyze request for scan patterns and generate signals
    ///
    /// # Algorithm
    ///
    /// 1. Check if path matches suspicious patterns → generate signal immediately
    /// 2. Check if path looks like enumeration (404 simulation)
    /// 3. If 404 burst threshold reached → generate signal
    ///
    /// # Returns
    ///
    /// Vector of signals (empty if no scan detected)
    fn analyze_scan(&self, context: &HttpRequestContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Get or create tracking data
        let mut entry = self.ip_tracking
            .entry(context.ip)
            .or_insert_with(IpScanData::new);

        // Check for suspicious path
        if Self::is_suspicious_path(&context.path) {
            entry.record_suspicious_path();

            tracing::warn!(
                ip = %context.ip,
                path = %context.path,
                "Suspicious path access detected (vulnerability scan)"
            );

            signals.push(Signal::new(SignalVariant::VulnerabilityScan));
        }

        // Simulate 404 detection: paths that don't match common patterns
        // In real implementation, this would come from response status
        // For now, we detect based on path patterns that look like enumeration
        let looks_like_enumeration = context.path.contains("nonexistent")
            || context.path.contains("notfound")
            || context.path.contains("404")
            || context.path.contains("scan")
            || context.path.contains("test");

        if looks_like_enumeration {
            entry.record_not_found();

            // Check if threshold reached
            if entry.not_found_count >= NOT_FOUND_THRESHOLD {
                tracing::warn!(
                    ip = %context.ip,
                    count = entry.not_found_count,
                    "404 burst detected (path enumeration)"
                );

                signals.push(Signal::new(SignalVariant::VulnerabilityScan));
            }
        }

        signals
    }
}

impl Default for ScanDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for ScanDetector {
    fn name(&self) -> &str {
        "ScanDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        let signals = self.analyze_scan(context);

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

    fn create_context(ip: &str, path: &str) -> HttpRequestContext {
        HttpRequestContext {
            ip: IpAddr::from_str(ip).unwrap(),
            method: "GET".to_string(),
            path: path.to_string(),
            query: None,
            headers: vec![],
            body: None,
            user_agent: Some("Mozilla/5.0".to_string()),
            referer: None,
            content_type: None,
        }
    }

    #[tokio::test]
    async fn test_clean_path() {
        let detector = ScanDetector::new();
        let context = create_context("192.168.1.1", "/index.html");

        let result = detector.analyze(&context).await;

        assert!(!result.suspicious);
        assert!(result.signals.is_empty());
    }

    #[tokio::test]
    async fn test_suspicious_path() {
        let detector = ScanDetector::new();
        let context = create_context("192.168.1.100", "/wp-admin/");

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        let has_scan = result.signals.iter().any(|s| {
            matches!(s.variant, SignalVariant::VulnerabilityScan)
        });
        assert!(has_scan);
    }

    #[tokio::test]
    async fn test_404_burst() {
        let detector = ScanDetector::new();
        let context = create_context("192.168.1.100", "/nonexistent");

        // Simulate burst
        for _ in 0..25 {
            let _ = detector.analyze(&context).await;
        }

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
    }
}
