//! Detector registry with Factory pattern
//!
//! Manages all registered detectors and executes them against requests.

use super::detector::{DetectionResult, Detector, HttpRequestContext};
use std::sync::Arc;

/// Registry of all threat detectors
///
/// Manages detector lifecycle and coordinates execution.
/// Uses Factory pattern for detector instantiation.
///
/// # Concurrency
///
/// The registry is thread-safe and can be shared across async tasks.
/// Detectors are executed concurrently using `tokio::spawn`.
pub struct DetectorRegistry {
    /// Registered detectors
    detectors: Vec<Arc<dyn Detector>>,
}

impl DetectorRegistry {
    /// Create an empty registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Register a detector
    ///
    /// # Arguments
    ///
    /// * `detector` - The detector to register
    pub fn register(&mut self, detector: Arc<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Run all enabled detectors against a request
    ///
    /// Executes all detectors concurrently and aggregates results.
    ///
    /// # Arguments
    ///
    /// * `context` - HTTP request context to analyze
    ///
    /// # Returns
    ///
    /// Aggregated `DetectionResult` with all signals from all detectors.
    pub async fn analyze_all(&self, context: &HttpRequestContext) -> DetectionResult {
        let mut all_signals = Vec::new();
        let mut any_suspicious = false;

        // Execute all enabled detectors concurrently
        let futures: Vec<_> = self
            .detectors
            .iter()
            .filter(|d| d.enabled())
            .map(|detector| {
                let ctx = context.clone();
                let det = Arc::clone(detector);
                tokio::spawn(async move { det.analyze(&ctx).await })
            })
            .collect();

        // Collect results
        for future in futures {
            if let Ok(result) = future.await {
                if result.suspicious {
                    any_suspicious = true;
                }
                all_signals.extend(result.signals);
            }
        }

        DetectionResult {
            signals: all_signals,
            suspicious: any_suspicious,
            message: None,
        }
    }

    /// Get count of registered detectors
    #[must_use]
    pub fn count(&self) -> usize {
        self.detectors.len()
    }

    /// Get count of enabled detectors
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.detectors.iter().filter(|d| d.enabled()).count()
    }

    /// Get detector names
    #[must_use]
    pub fn detector_names(&self) -> Vec<String> {
        self.detectors
            .iter()
            .map(|d| d.name().to_string())
            .collect()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation::{Signal, SignalVariant};
    use async_trait::async_trait;
    use std::net::IpAddr;
    use std::str::FromStr;

    struct TestDetector {
        name: String,
        enabled: bool,
        signal_to_generate: Option<SignalVariant>,
    }

    #[async_trait]
    impl Detector for TestDetector {
        fn name(&self) -> &str {
            &self.name
        }

        async fn analyze(&self, _context: &HttpRequestContext) -> DetectionResult {
            if let Some(variant) = &self.signal_to_generate {
                DetectionResult::with_signal(Signal::new(variant.clone()))
            } else {
                DetectionResult::clean()
            }
        }

        fn enabled(&self) -> bool {
            self.enabled
        }
    }

    #[test]
    fn test_new_registry() {
        let registry = DetectorRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_register_detector() {
        let mut registry = DetectorRegistry::new();
        let detector = Arc::new(TestDetector {
            name: "TestDetector".to_string(),
            enabled: true,
            signal_to_generate: None,
        });

        registry.register(detector);
        assert_eq!(registry.count(), 1);
    }

    #[tokio::test]
    async fn test_analyze_all_clean() {
        let mut registry = DetectorRegistry::new();
        let detector = Arc::new(TestDetector {
            name: "CleanDetector".to_string(),
            enabled: true,
            signal_to_generate: None,
        });

        registry.register(detector);

        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let context = HttpRequestContext {
            ip,
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            headers: vec![],
            body: None,
            user_agent: None,
            referer: None,
            content_type: None,
        };

        let result = registry.analyze_all(&context).await;
        assert!(!result.suspicious);
        assert_eq!(result.signals.len(), 0);
    }

    #[tokio::test]
    async fn test_analyze_all_with_signals() {
        let mut registry = DetectorRegistry::new();

        let detector1 = Arc::new(TestDetector {
            name: "BotDetector".to_string(),
            enabled: true,
            signal_to_generate: Some(SignalVariant::SuspiciousUserAgent),
        });

        let detector2 = Arc::new(TestDetector {
            name: "SqlDetector".to_string(),
            enabled: true,
            signal_to_generate: Some(SignalVariant::SqlInjectionAttempt),
        });

        registry.register(detector1);
        registry.register(detector2);

        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let context = HttpRequestContext {
            ip,
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            headers: vec![],
            body: None,
            user_agent: None,
            referer: None,
            content_type: None,
        };

        let result = registry.analyze_all(&context).await;
        assert!(result.suspicious);
        assert_eq!(result.signals.len(), 2);
    }

    #[tokio::test]
    async fn test_disabled_detector_not_run() {
        let mut registry = DetectorRegistry::new();

        let enabled_detector = Arc::new(TestDetector {
            name: "EnabledDetector".to_string(),
            enabled: true,
            signal_to_generate: Some(SignalVariant::SuspiciousUserAgent),
        });

        let disabled_detector = Arc::new(TestDetector {
            name: "DisabledDetector".to_string(),
            enabled: false,
            signal_to_generate: Some(SignalVariant::SqlInjectionAttempt),
        });

        registry.register(enabled_detector);
        registry.register(disabled_detector);

        assert_eq!(registry.count(), 2);
        assert_eq!(registry.enabled_count(), 1);

        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let context = HttpRequestContext {
            ip,
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            headers: vec![],
            body: None,
            user_agent: None,
            referer: None,
            content_type: None,
        };

        let result = registry.analyze_all(&context).await;
        assert_eq!(result.signals.len(), 1); // Only enabled detector ran
    }

    #[test]
    fn test_detector_names() {
        let mut registry = DetectorRegistry::new();

        let detector1 = Arc::new(TestDetector {
            name: "Detector1".to_string(),
            enabled: true,
            signal_to_generate: None,
        });

        let detector2 = Arc::new(TestDetector {
            name: "Detector2".to_string(),
            enabled: true,
            signal_to_generate: None,
        });

        registry.register(detector1);
        registry.register(detector2);

        let names = registry.detector_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Detector1".to_string()));
        assert!(names.contains(&"Detector2".to_string()));
    }
}
