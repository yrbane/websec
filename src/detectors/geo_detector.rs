//! Geographic threat detection
//!
//! Detects threats based on IP geolocation patterns.
//!
//! # Threat Families Detected
//!
//! - **High-Risk Countries**: Requests originating from countries with high attack frequency
//! - **Impossible Travel**: Rapid geolocation changes indicating session hijacking or VPN hopping
//!
//! # Implementation Strategy
//!
//! This detector uses IP geolocation to identify geographic threat patterns:
//!
//! 1. **Country Risk Assessment**: Compares request IP country against configurable risk list
//! 2. **Travel Velocity**: Tracks IP location history to detect impossible geographic jumps
//! 3. **Exemption Rules**: Automatically exempts localhost and private IPs
//!
//! # Signals Generated
//!
//! - `HighRiskCountry` (weight 15): Request from configured risk country
//! - `ImpossibleTravel` (weight 20): Country changed within 1 hour for same IP
//!
//! # Production Integration
//!
//! **Note**: Current implementation uses mock GeoIP lookup for testing.
//! For production, replace `mock_geo_lookup()` with `maxminddb::Reader`:
//!
//! ```ignore
//! use maxminddb::{Reader, geoip2};
//!
//! let reader = Reader::open_readfile("GeoLite2-Country.mmdb")?;
//! let country: geoip2::Country = reader.lookup(ip)?;
//! let country_code = country.country
//!     .and_then(|c| c.iso_code)
//!     .map(String::from);
//! ```
//!
//! # Example Usage
//!
//! ```rust
//! use websec::detectors::{GeoDetector, Detector, HttpRequestContext};
//! use std::net::IpAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create detector with default risk countries
//! let detector = GeoDetector::new();
//!
//! // Or customize risk countries
//! let custom_detector = GeoDetector::with_risk_countries(vec![
//!     "CN".to_string(),
//!     "RU".to_string(),
//! ]);
//!
//! // Analyze request
//! let context = HttpRequestContext {
//!     ip: "1.2.3.4".parse()?,
//!     method: "GET".to_string(),
//!     path: "/".to_string(),
//!     query: None,
//!     headers: vec![],
//!     body: None,
//!     user_agent: Some("Mozilla/5.0".to_string()),
//!     referer: None,
//!     content_type: None,
//! };
//!
//! let result = detector.analyze(&context).await;
//! if result.suspicious {
//!     println!("Geographic threat: {:?}", result.signals);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! - Uses `Arc<HashSet>` for shared risk country list
//! - Uses `DashMap` for concurrent location history tracking
//! - Clone-safe for use across multiple tasks

use crate::detectors::{Detector, HttpRequestContext};
use crate::reputation::{Signal, SignalVariant};
use async_trait::async_trait;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use dashmap::DashMap;

/// Geographic location information
#[derive(Debug, Clone)]
struct GeoLocation {
    country_code: String,
    timestamp: u64,
}

/// GeoDetector analyzes IP geolocation for threat patterns
#[derive(Clone)]
pub struct GeoDetector {
    /// High-risk country codes (ISO 3166-1 alpha-2)
    risk_countries: Arc<HashSet<String>>,
    /// Track IP location history for impossible travel detection
    ip_history: Arc<DashMap<IpAddr, Vec<GeoLocation>>>,
    /// Whether detector is enabled
    enabled: bool,
}

impl GeoDetector {
    /// Create a new GeoDetector with default risk countries
    #[must_use]
    pub fn new() -> Self {
        // Default high-risk countries based on common attack sources
        let risk_countries = vec![
            "CN".to_string(), // China
            "RU".to_string(), // Russia
            "KP".to_string(), // North Korea
            "IR".to_string(), // Iran
            "SY".to_string(), // Syria
        ];

        Self {
            risk_countries: Arc::new(risk_countries.into_iter().collect()),
            ip_history: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Create GeoDetector with custom risk countries
    #[must_use]
    pub fn with_risk_countries(countries: Vec<String>) -> Self {
        Self {
            risk_countries: Arc::new(countries.into_iter().collect()),
            ip_history: Arc::new(DashMap::new()),
            enabled: true,
        }
    }

    /// Extract country code from IP address
    ///
    /// Returns None for:
    /// - Private IPs (RFC1918)
    /// - Localhost
    /// - IPs not in GeoIP database
    fn get_country_code(&self, ip: &IpAddr) -> Option<String> {
        // Exempt localhost and private IPs
        if self.is_exempt_ip(ip) {
            return None;
        }

        // Simulate GeoIP lookup for testing
        // In production, this would use maxminddb::Reader
        self.mock_geo_lookup(ip)
    }

    /// Check if IP should be exempt from geo checks
    fn is_exempt_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // Localhost
                if ipv4.is_loopback() {
                    return true;
                }
                // Private networks (RFC1918)
                if ipv4.is_private() {
                    return true;
                }
                // Link-local
                if ipv4.is_link_local() {
                    return true;
                }
                false
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_unicast_link_local()
            }
        }
    }

    /// Mock GeoIP lookup for testing
    ///
    /// In production, replace with actual maxminddb::Reader lookup
    fn mock_geo_lookup(&self, ip: &IpAddr) -> Option<String> {
        // Simple mock based on IP ranges
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                match octets[0] {
                    1..=2 => Some("CN".to_string()),   // China
                    5..=6 => Some("RU".to_string()),   // Russia
                    8 => Some("US".to_string()),       // US (Google DNS)
                    41 => Some("NG".to_string()),      // Nigeria
                    _ => Some("XX".to_string()),       // Unknown
                }
            }
            IpAddr::V6(_) => Some("XX".to_string()),
        }
    }

    /// Detect impossible travel
    ///
    /// If IP location changes rapidly (e.g., US -> China in minutes),
    /// this may indicate account sharing or session hijacking
    fn detect_impossible_travel(
        &self,
        ip: &IpAddr,
        current_country: &str,
    ) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(mut history) = self.ip_history.get_mut(ip) {
            // Check last location
            if let Some(last_location) = history.last() {
                let time_diff = now - last_location.timestamp;

                // If country changed within 1 hour, flag as impossible travel
                if time_diff < 3600 && last_location.country_code != current_country {
                    return true;
                }
            }

            // Add current location to history
            history.push(GeoLocation {
                country_code: current_country.to_string(),
                timestamp: now,
            });

            // Keep only last 10 locations
            if history.len() > 10 {
                history.remove(0);
            }
        } else {
            // First time seeing this IP
            self.ip_history.insert(
                *ip,
                vec![GeoLocation {
                    country_code: current_country.to_string(),
                    timestamp: now,
                }],
            );
        }

        false
    }
}

impl Default for GeoDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Detector for GeoDetector {
    fn name(&self) -> &str {
        "GeoDetector"
    }

    async fn analyze(&self, context: &HttpRequestContext) -> crate::detectors::DetectionResult {
        use crate::detectors::DetectionResult;

        if !self.enabled {
            return DetectionResult::clean();
        }

        let mut signals = Vec::new();
        let ip = context.ip;

        // Get country code for IP
        let country_code = match self.get_country_code(&ip) {
            Some(code) => code,
            None => return DetectionResult::clean(), // Exempt IP
        };

        // Check if country is high-risk
        if self.risk_countries.contains(&country_code) {
            let signal = Signal::with_context(
                SignalVariant::HighRiskCountry,
                15, // Weight from signal.rs
                format!("Request from high-risk country: {}", country_code),
            );
            signals.push(signal);
        }

        // Check for impossible travel
        if self.detect_impossible_travel(&ip, &country_code) {
            let signal = Signal::with_context(
                SignalVariant::ImpossibleTravel,
                20, // Weight from signal.rs
                format!(
                    "Impossible travel detected for IP {} to country {}",
                    ip, country_code
                ),
            );
            signals.push(signal);
        }

        if signals.is_empty() {
            DetectionResult::clean()
        } else {
            DetectionResult {
                signals: signals.clone(),
                suspicious: true,
                message: Some(format!(
                    "Geographic threat detected: {} signal(s) from country {}",
                    signals.len(),
                    country_code
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exempt_ips() {
        let detector = GeoDetector::new();

        assert!(detector.is_exempt_ip(&IpAddr::from([127, 0, 0, 1])));
        assert!(detector.is_exempt_ip(&IpAddr::from([192, 168, 1, 1])));
        assert!(detector.is_exempt_ip(&IpAddr::from([10, 0, 0, 1])));
        assert!(!detector.is_exempt_ip(&IpAddr::from([8, 8, 8, 8])));
    }

    #[test]
    fn test_mock_geo_lookup() {
        let detector = GeoDetector::new();

        assert_eq!(
            detector.mock_geo_lookup(&IpAddr::from([1, 2, 3, 4])),
            Some("CN".to_string())
        );
        assert_eq!(
            detector.mock_geo_lookup(&IpAddr::from([8, 8, 8, 8])),
            Some("US".to_string())
        );
    }

    #[test]
    fn test_risk_countries() {
        let detector = GeoDetector::new();
        assert!(detector.risk_countries.contains("CN"));
        assert!(detector.risk_countries.contains("RU"));
        assert!(!detector.risk_countries.contains("US"));
    }

    #[test]
    fn test_custom_risk_countries() {
        let countries = vec!["XX".to_string(), "YY".to_string()];
        let detector = GeoDetector::with_risk_countries(countries);

        assert!(detector.risk_countries.contains("XX"));
        assert!(!detector.risk_countries.contains("CN"));
    }
}
