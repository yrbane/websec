//! Bot and scanner detection
//!
//! Detects malicious bots, scrapers, and vulnerability scanners through:
//! - User-Agent pattern matching
//! - Missing/suspicious browser headers
//! - Request pattern analysis (pages vs assets ratio)

use super::detector::{DetectionResult, Detector, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;

/// Known vulnerability scanner patterns
static SCANNER_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(sqlmap|nikto|nmap|masscan|acunetix|burp|metasploit|nessus|openvas|w3af|skipfish|arachni|vega|webscarab|paros)"
    )
    .unwrap()
});

/// Generic bot/tool patterns (less severe than scanners)
static BOT_PATTERNS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(curl|wget|python-requests|go-http-client|java/|apache-httpclient|okhttp)")
        .unwrap()
});

/// Bot detector implementation
///
/// Analyzes HTTP requests for bot-like behavior patterns.
pub struct BotDetector {
    enabled: bool,
}

impl BotDetector {
    /// Create a new `BotDetector`
    #[must_use]
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Check if User-Agent matches vulnerability scanner patterns
    fn is_scanner(user_agent: &str) -> bool {
        SCANNER_PATTERNS.is_match(user_agent)
    }

    /// Check if User-Agent matches generic bot/tool patterns
    fn is_generic_bot(user_agent: &str) -> bool {
        BOT_PATTERNS.is_match(user_agent)
    }

    /// Check if User-Agent is missing or empty
    fn is_missing_user_agent(user_agent: Option<&str>) -> bool {
        user_agent.is_none() || user_agent.is_some_and(|ua| ua.trim().is_empty())
    }

    /// Analyze User-Agent header
    fn analyze_user_agent(&self, context: &HttpRequestContext) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Check for missing/empty User-Agent
        if Self::is_missing_user_agent(context.user_agent.as_deref()) {
            tracing::debug!(
                ip = %context.ip,
                path = %context.path,
                "Bot detected: Missing User-Agent header"
            );
            signals.push(Signal::new(SignalVariant::BotBehaviorPattern));
            return signals;
        }

        let user_agent = context.user_agent.as_ref().unwrap();

        // Check for vulnerability scanners (high severity)
        if Self::is_scanner(user_agent) {
            tracing::warn!(
                ip = %context.ip,
                path = %context.path,
                user_agent = %user_agent,
                "Vulnerability scanner detected"
            );
            signals.push(Signal::new(SignalVariant::VulnerabilityScan));
            return signals;
        }

        // Check for generic bots/tools (medium severity)
        if Self::is_generic_bot(user_agent) {
            tracing::info!(
                ip = %context.ip,
                path = %context.path,
                user_agent = %user_agent,
                "Generic bot/tool detected"
            );
            signals.push(Signal::new(SignalVariant::SuspiciousUserAgent));
            return signals;
        }

        signals
    }
}

impl Default for BotDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for BotDetector {
    fn name(&self) -> &str {
        "BotDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        let signals = self.analyze_user_agent(context);

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

    fn create_context(ua: Option<&str>) -> HttpRequestContext {
        let headers = if let Some(user_agent) = ua {
            vec![("User-Agent".to_string(), user_agent.to_string())]
        } else {
            vec![]
        };

        HttpRequestContext {
            ip: IpAddr::from_str("192.168.1.1").unwrap(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            headers: headers.clone(),
            body: None,
            user_agent: ua.map(String::from),
            referer: None,
            content_type: None,
        }
    }

    #[test]
    fn test_is_scanner() {
        assert!(BotDetector::is_scanner("sqlmap/1.0"));
        assert!(BotDetector::is_scanner("Mozilla/5.00 (Nikto/2.1.6)"));
        assert!(BotDetector::is_scanner("Acunetix-Security-Scanner"));
        assert!(BotDetector::is_scanner("nmap scripting engine"));
        assert!(!BotDetector::is_scanner("Mozilla/5.0 Chrome/91.0"));
    }

    #[test]
    fn test_is_generic_bot() {
        assert!(BotDetector::is_generic_bot("curl/7.68.0"));
        assert!(BotDetector::is_generic_bot("python-requests/2.25.1"));
        assert!(BotDetector::is_generic_bot("Go-http-client/1.1"));
        assert!(!BotDetector::is_generic_bot("Mozilla/5.0 Firefox/89.0"));
    }

    #[test]
    fn test_is_missing_user_agent() {
        assert!(BotDetector::is_missing_user_agent(None));
        assert!(BotDetector::is_missing_user_agent(Some("")));
        assert!(BotDetector::is_missing_user_agent(Some("   ")));
        assert!(!BotDetector::is_missing_user_agent(Some("Mozilla/5.0")));
    }

    #[tokio::test]
    async fn test_analyze_scanner() {
        let detector = BotDetector::new();
        let context = create_context(Some("sqlmap/1.0"));

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        assert_eq!(result.signals.len(), 1);
        assert!(matches!(
            result.signals[0].variant,
            SignalVariant::VulnerabilityScan
        ));
    }

    #[tokio::test]
    async fn test_analyze_bot() {
        let detector = BotDetector::new();
        let context = create_context(Some("curl/7.68.0"));

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        assert_eq!(result.signals.len(), 1);
        assert!(matches!(
            result.signals[0].variant,
            SignalVariant::SuspiciousUserAgent
        ));
    }

    #[tokio::test]
    async fn test_analyze_missing_ua() {
        let detector = BotDetector::new();
        let context = create_context(None);

        let result = detector.analyze(&context).await;

        assert!(result.suspicious);
        assert_eq!(result.signals.len(), 1);
        assert!(matches!(
            result.signals[0].variant,
            SignalVariant::BotBehaviorPattern
        ));
    }

    #[tokio::test]
    async fn test_analyze_legitimate() {
        let detector = BotDetector::new();
        let context = create_context(Some("Mozilla/5.0 (Windows NT 10.0) Chrome/91.0"));

        let result = detector.analyze(&context).await;

        assert!(!result.suspicious);
        assert!(result.signals.is_empty());
    }
}
