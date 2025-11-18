//! Flood/DDoS detection (Request floods, connection floods)
//!
//! Detects volumetric attacks through rate limiting and pattern analysis:
//! - High request volume (1000+ req in 10s)
//! - Burst patterns (50+ req in 2s)
//! - Sustained high rate (100 req/s for 1 min)
//!
//! Uses sliding window counters with DashMap for thread-safe per-IP tracking.

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
pub struct FloodDetector {
    /// Per-IP tracking data
    ip_tracking: Arc<DashMap<IpAddr, IpFloodData>>,
    /// Whether the detector is enabled
    enabled: bool,
}

impl FloodDetector {
    /// Create a new FloodDetector
    #[must_use]
    pub fn new() -> Self {
        Self {
            ip_tracking: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Track request and check for flood patterns
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
