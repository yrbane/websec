//! Flood/DDoS detection (Request floods, burst patterns)
//!
//! Detects volumetric attacks through sliding window rate limiting and pattern analysis:
//! - **High request volume**: 100+ requests in 60 seconds
//! - **Burst patterns**: 50+ requests in 2 seconds
//! - **Sustained high rate**: Continuous flooding over multiple windows
//!
//! # Architecture
//!
//! Uses sliding window counters with [`DashMap`] for lock-free, thread-safe per-IP tracking.
//! Timestamps are stored as [`Instant`] values and automatically pruned outside the time window.
//!
//! # Detection Flow
//!
//! 1. Record request timestamp for source IP
//! 2. Prune expired timestamps (outside 60s window)
//! 3. Count requests in main window (60s) → if ≥ 100, signal `RequestFlood`
//! 4. Count requests in burst window (2s) → if ≥ 50, signal `RequestFlood`
//! 5. Return detection result with signals
//!
//! # Example
//!
//! ```rust
//! use websec::detectors::{FloodDetector, Detector, HttpRequestContext};
//! use std::net::IpAddr;
//!
//! # async fn example() {
//! let detector = FloodDetector::new();
//! let context = HttpRequestContext {
//!     ip: "192.168.1.100".parse().unwrap(),
//!     method: "GET".to_string(),
//!     path: "/api/data".to_string(),
//!     query: None,
//!     headers: vec![],
//!     body: None,
//!     user_agent: Some("AttackBot/1.0".to_string()),
//!     referer: None,
//!     content_type: None,
//! };
//!
//! // Simulate flood: 150 requests
//! for _ in 0..150 {
//!     let _ = detector.analyze(&context).await;
//! }
//!
//! let result = detector.analyze(&context).await;
//! assert!(result.suspicious); // Flood detected
//! # }
//! ```
//!
//! # Performance
//!
//! - **Memory**: O(n) where n = number of active IPs × requests in window
//! - **Time complexity**: O(m) where m = requests in window (typically < 200)
//! - **Pruning**: Automatic on each request (amortized O(1))
//! - **Concurrency**: Lock-free reads/writes via DashMap
//!
//! # Configuration
//!
//! Default thresholds:
//! - `FLOOD_THRESHOLD`: 100 requests per 60s window
//! - `BURST_THRESHOLD`: 50 requests per 2s window
//! - `TIME_WINDOW_SECS`: 60 seconds
//!
//! # Signal Weights
//!
//! - `RequestFlood`: 20 (medium-high severity)

use super::detector::{DetectionResult, Detector, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Time window for request counting (seconds)
const TIME_WINDOW_SECS: u64 = 60;

/// Request threshold for flood detection (requests per window)
const FLOOD_THRESHOLD: usize = 100;

/// Burst threshold (requests in short window)
const BURST_THRESHOLD: usize = 50;
const BURST_WINDOW_SECS: u64 = 2;

/// IP tracking data for flood detection
#[derive(Debug)]
struct IpFloodData {
    /// Request timestamps in current window
    request_times: Vec<Instant>,
}

impl IpFloodData {
    fn new() -> Self {
        Self {
            request_times: Vec::new(),
        }
    }

    /// Add a request timestamp and prune old entries
    fn add_request(&mut self, now: Instant, window_duration: Duration) {
        // Remove entries older than window
        let cutoff = now - window_duration;
        self.request_times.retain(|&t| t > cutoff);

        // Add current request
        self.request_times.push(now);
    }

    /// Get request count in window
    fn request_count(&self, now: Instant, window_duration: Duration) -> usize {
        let cutoff = now - window_duration;
        self.request_times.iter().filter(|&&t| t > cutoff).count()
    }

    /// Check if burst pattern detected
    fn is_burst(&self, now: Instant, threshold: usize, burst_window: Duration) -> bool {
        let cutoff = now - burst_window;
        let burst_count = self.request_times.iter().filter(|&&t| t > cutoff).count();
        burst_count >= threshold
    }
}

/// Flood detector implementation
///
///  Tracks request rates per IP using sliding window counters and generates
/// `RequestFlood` signals when thresholds are exceeded.
///
/// # Fields
///
/// - `ip_tracking`: Concurrent map of IP → request timestamps
/// - `enabled`: Detector activation flag (always true by default)
///
/// # Thread Safety
///
/// This detector is fully thread-safe and lock-free thanks to [`DashMap`].
/// Multiple threads can analyze requests concurrently without blocking.
///
/// # Memory Management
///
/// Old timestamps are automatically pruned on each request to prevent unbounded growth.
/// Memory usage is bounded by: `active_ips × requests_per_window × sizeof(Instant)`.
pub struct FloodDetector {
    /// Per-IP tracking data
    ip_tracking: Arc<DashMap<IpAddr, IpFloodData>>,
    /// Whether the detector is enabled
    enabled: bool,
}

impl FloodDetector {
    /// Create a new FloodDetector with default thresholds
    ///
    /// Initializes empty tracking map. Memory is allocated lazily as IPs are seen.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ip_tracking: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Track request and check for flood patterns
    ///
    /// # Algorithm
    ///
    /// 1. Get or create tracking entry for source IP
    /// 2. Add current timestamp and prune old entries
    /// 3. Count requests in main window (60s)
    /// 4. Count requests in burst window (2s)
    /// 5. Generate signals if thresholds exceeded
    ///
    /// # Returns
    ///
    /// Vector of signals (empty if no flood detected)
    fn track_and_analyze(&self, context: &HttpRequestContext) -> Vec<Signal> {
        let mut signals = Vec::new();
        let now = Instant::now();
        let window = Duration::from_secs(TIME_WINDOW_SECS);
        let burst_window = Duration::from_secs(BURST_WINDOW_SECS);

        // Get or create tracking data for this IP
        let mut entry = self.ip_tracking
            .entry(context.ip)
            .or_insert_with(IpFloodData::new);

        // Add current request
        entry.add_request(now, window);

        // Check flood threshold
        let request_count = entry.request_count(now, window);
        if request_count >= FLOOD_THRESHOLD {
            tracing::warn!(
                ip = %context.ip,
                count = request_count,
                window_secs = TIME_WINDOW_SECS,
                "Request flood detected"
            );
            signals.push(Signal::new(SignalVariant::RequestFlood));
        }

        // Check burst pattern
        if entry.is_burst(now, BURST_THRESHOLD, burst_window) {
            tracing::warn!(
                ip = %context.ip,
                threshold = BURST_THRESHOLD,
                burst_window_secs = BURST_WINDOW_SECS,
                "Burst pattern detected"
            );
            // Burst is also a form of RequestFlood
            if !signals.iter().any(|s| matches!(s.variant, SignalVariant::RequestFlood)) {
                signals.push(Signal::new(SignalVariant::RequestFlood));
            }
        }

        signals
    }
}

impl Default for FloodDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for FloodDetector {
    fn name(&self) -> &str {
        "FloodDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        let signals = self.track_and_analyze(context);

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

    fn create_context(ip: &str) -> HttpRequestContext {
        HttpRequestContext {
            ip: IpAddr::from_str(ip).unwrap(),
            method: "GET".to_string(),
            path: "/test".to_string(),
            query: None,
            headers: vec![],
            body: None,
            user_agent: Some("Mozilla/5.0".to_string()),
            referer: None,
            content_type: None,
        }
    }

    #[tokio::test]
    async fn test_single_request_clean() {
        let detector = FloodDetector::new();
        let context = create_context("192.168.1.1");

        let result = detector.analyze(&context).await;

        assert!(!result.suspicious);
        assert!(result.signals.is_empty());
    }

    #[tokio::test]
    async fn test_high_volume_triggers_flood() {
        let detector = FloodDetector::new();
        let context = create_context("192.168.1.100");

        // Send 150 requests to exceed threshold
        for _ in 0..150 {
            let _ = detector.analyze(&context).await;
        }

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        let has_flood = result.signals.iter().any(|s| {
            matches!(s.variant, SignalVariant::RequestFlood)
        });
        assert!(has_flood);
    }
}
