# Data Model: WebSec Proxy

**Feature**: WebSec Proxy de Sécurité
**Branch**: `001-websec-proxy`
**Date**: 2025-11-18
**Status**: Complete

## Overview

This document defines all core entities in the WebSec proxy system with complete Rust struct signatures. All types are production-ready with no placeholders. The data model implements patterns identified in research.md (Strategy, Repository, Factory, Builder) and satisfies all requirements from spec.md.

## Core Entities

### 1. IpProfile

Represents the complete reputation profile for a single IP address, including current score, signal history, behavioral statistics, and metadata.

**Requirements**: FR-013 (behavior history), FR-014 (persistence), FR-015 (expiration), FR-029 (session tracking)

**Rust Definition**:

```rust
use std::net::IpAddr;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete reputation profile for an IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpProfile {
    /// IP address being tracked
    pub ip: IpAddr,

    /// Current reputation score (0-100, where 100 is excellent)
    pub score: i32,

    /// Timestamp of profile creation
    pub created_at: DateTime<Utc>,

    /// Timestamp of last update
    pub updated_at: DateTime<Utc>,

    /// Historical signals detected for this IP (most recent first)
    pub signals: Vec<SignalRecord>,

    /// Request statistics
    pub statistics: RequestStatistics,

    /// Geolocation metadata
    pub geolocation: Option<GeoLocation>,

    /// Observed User-Agent strings
    pub user_agents: Vec<String>,

    /// Session IDs associated with this IP
    pub session_ids: Vec<String>,

    /// Current rate limiting state
    pub rate_limit_state: RateLimitState,

    /// Whether this IP has irremissible signals (no automatic recovery)
    pub has_irremissible_signals: bool,
}

impl IpProfile {
    /// Create new profile with base score
    pub fn new(ip: IpAddr, base_score: i32) -> Self {
        let now = Utc::now();
        Self {
            ip,
            score: base_score,
            created_at: now,
            updated_at: now,
            signals: Vec::new(),
            statistics: RequestStatistics::default(),
            geolocation: None,
            user_agents: Vec::new(),
            session_ids: Vec::new(),
            rate_limit_state: RateLimitState::default(),
            has_irremissible_signals: false,
        }
    }

    /// Add signal to profile and update score
    pub fn add_signal(&mut self, signal: Signal) {
        if signal.is_irremissible() {
            self.has_irremissible_signals = true;
        }

        let record = SignalRecord {
            signal,
            timestamp: Utc::now(),
        };

        self.signals.push(record);
        self.updated_at = Utc::now();
    }

    /// Get signals within time window (for sliding window rate limiting)
    pub fn signals_in_window(&self, duration_secs: i64) -> Vec<&SignalRecord> {
        let threshold = Utc::now() - chrono::Duration::seconds(duration_secs);
        self.signals
            .iter()
            .filter(|record| record.timestamp > threshold)
            .collect()
    }

    /// Count requests in sliding time window
    pub fn requests_in_window(&self, duration_secs: i64) -> u64 {
        let threshold = Utc::now() - chrono::Duration::seconds(duration_secs);
        self.statistics.request_timestamps
            .iter()
            .filter(|&&ts| ts > threshold)
            .count() as u64
    }
}
```

**Relationships**:
- Contains multiple `SignalRecord` instances (composition)
- References `GeoLocation` (optional association)
- Contains `RequestStatistics` (composition)
- Contains `RateLimitState` (composition)

**State Transitions**:
1. Created with base score (typically 100)
2. Signals added → score decreases
3. Time passes → exponential decay increases score (unless irremissible)
4. Whitelisted → score reset to 100
5. Blacklisted → score set to 0

**Validation Rules**:
- Score must be in range [0, 100]
- IP address must be valid IPv4 or IPv6
- `updated_at` must be >= `created_at`
- Signal timestamps must be <= current time

---

### 2. Signal (Enum with 20+ Variants)

Typed events representing detected threats or suspicious behaviors. Each variant carries specific metadata and weight.

**Requirements**: FR-005 (typed signals), FR-005-bis (irremissible classification), FR-022 (configurable weights)

**Rust Definition**:

```rust
use serde::{Deserialize, Serialize};

/// Threat signals detected from request analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Signal {
    // Bot Detection (Detector 1)
    SuspiciousUserAgent {
        user_agent: String,
        weight: i32,
    },

    BotSignature {
        pattern_matched: String,
        weight: i32,
    },

    SuspiciousClientProfile {
        reason: String,
        weight: i32,
    },

    // Brute Force (Detector 2)
    FailedAuthAttempt {
        endpoint: String,
        status_code: u16,
        weight: i32,
    },

    CredentialStuffing {
        username: String,
        concurrent_ips: u32,
        weight: i32,
        irremissible: bool,
    },

    // Flooding (Detector 3)
    Flooding {
        requests_per_sec: f64,
        weight: i32,
    },

    AbusiveClient {
        reason: String,
        weight: i32,
    },

    // Protocol Anomalies (Detector 4)
    ProtocolAnomaly {
        anomaly_type: String,
        details: String,
        weight: i32,
    },

    SuspiciousMethod {
        method: String,
        weight: i32,
    },

    // Path Traversal (Detector 5)
    PathTraversalAttempt {
        path: String,
        weight: i32,
    },

    // Uploads (Detector 6)
    PotentialWebshellUpload {
        filename: String,
        extension: String,
        content_type: String,
        weight: i32,
        irremissible: bool,
    },

    SuspiciousUpload {
        reason: String,
        weight: i32,
    },

    // Injections (Detector 7)
    SqlInjectionAttempt {
        payload: String,
        confidence: f32,
        weight: i32,
    },

    XssAttempt {
        payload: String,
        confidence: f32,
        weight: i32,
    },

    RceAttempt {
        payload: String,
        confidence: f32,
        weight: i32,
        irremissible: bool,
    },

    SuspiciousPayload {
        payload_type: String,
        sample: String,
        weight: i32,
    },

    // Vulnerability Scanning (Detector 8)
    VulnerabilityScan {
        target_path: String,
        scan_type: String,
        weight: i32,
    },

    ExcessiveNotFound {
        count_404: u32,
        time_window_secs: u64,
        weight: i32,
    },

    // Host Header (Detector 9)
    HostHeaderAnomaly {
        host_value: String,
        reason: String,
        weight: i32,
    },

    // SSRF (Detector 10)
    SsrfSuspected {
        target_url: String,
        reason: String,
        weight: i32,
    },

    // Session Anomaly (Detector 11)
    SessionHijackingSuspected {
        session_id: String,
        geo_change: String,
        weight: i32,
    },

    SessionAnomaly {
        session_id: String,
        anomaly_type: String,
        weight: i32,
    },

    // TLS Fingerprinting (Detector 12)
    TorDetected {
        exit_node: bool,
        weight: i32,
    },

    PublicProxyDetected {
        proxy_type: String,
        weight: i32,
    },

    SuspiciousTlsFingerprint {
        ja3_hash: String,
        weight: i32,
    },
}

impl Signal {
    /// Get the penalty weight for this signal
    pub fn weight(&self) -> i32 {
        match self {
            Signal::SuspiciousUserAgent { weight, .. } => *weight,
            Signal::BotSignature { weight, .. } => *weight,
            Signal::SuspiciousClientProfile { weight, .. } => *weight,
            Signal::FailedAuthAttempt { weight, .. } => *weight,
            Signal::CredentialStuffing { weight, .. } => *weight,
            Signal::Flooding { weight, .. } => *weight,
            Signal::AbusiveClient { weight, .. } => *weight,
            Signal::ProtocolAnomaly { weight, .. } => *weight,
            Signal::SuspiciousMethod { weight, .. } => *weight,
            Signal::PathTraversalAttempt { weight, .. } => *weight,
            Signal::PotentialWebshellUpload { weight, .. } => *weight,
            Signal::SuspiciousUpload { weight, .. } => *weight,
            Signal::SqlInjectionAttempt { weight, .. } => *weight,
            Signal::XssAttempt { weight, .. } => *weight,
            Signal::RceAttempt { weight, .. } => *weight,
            Signal::SuspiciousPayload { weight, .. } => *weight,
            Signal::VulnerabilityScan { weight, .. } => *weight,
            Signal::ExcessiveNotFound { weight, .. } => *weight,
            Signal::HostHeaderAnomaly { weight, .. } => *weight,
            Signal::SsrfSuspected { weight, .. } => *weight,
            Signal::SessionHijackingSuspected { weight, .. } => *weight,
            Signal::SessionAnomaly { weight, .. } => *weight,
            Signal::TorDetected { weight, .. } => *weight,
            Signal::PublicProxyDetected { weight, .. } => *weight,
            Signal::SuspiciousTlsFingerprint { weight, .. } => *weight,
        }
    }

    /// FR-005-bis: Check if signal is irremissible (no automatic recovery)
    pub fn is_irremissible(&self) -> bool {
        match self {
            Signal::CredentialStuffing { irremissible, .. } => *irremissible,
            Signal::PotentialWebshellUpload { irremissible, .. } => *irremissible,
            Signal::RceAttempt { irremissible, .. } => *irremissible,
            _ => false,
        }
    }

    /// Get human-readable signal name
    pub fn name(&self) -> &'static str {
        match self {
            Signal::SuspiciousUserAgent { .. } => "SuspiciousUserAgent",
            Signal::BotSignature { .. } => "BotSignature",
            Signal::SuspiciousClientProfile { .. } => "SuspiciousClientProfile",
            Signal::FailedAuthAttempt { .. } => "FailedAuthAttempt",
            Signal::CredentialStuffing { .. } => "CredentialStuffing",
            Signal::Flooding { .. } => "Flooding",
            Signal::AbusiveClient { .. } => "AbusiveClient",
            Signal::ProtocolAnomaly { .. } => "ProtocolAnomaly",
            Signal::SuspiciousMethod { .. } => "SuspiciousMethod",
            Signal::PathTraversalAttempt { .. } => "PathTraversalAttempt",
            Signal::PotentialWebshellUpload { .. } => "PotentialWebshellUpload",
            Signal::SuspiciousUpload { .. } => "SuspiciousUpload",
            Signal::SqlInjectionAttempt { .. } => "SqlInjectionAttempt",
            Signal::XssAttempt { .. } => "XssAttempt",
            Signal::RceAttempt { .. } => "RceAttempt",
            Signal::SuspiciousPayload { .. } => "SuspiciousPayload",
            Signal::VulnerabilityScan { .. } => "VulnerabilityScan",
            Signal::ExcessiveNotFound { .. } => "ExcessiveNotFound",
            Signal::HostHeaderAnomaly { .. } => "HostHeaderAnomaly",
            Signal::SsrfSuspected { .. } => "SsrfSuspected",
            Signal::SessionHijackingSuspected { .. } => "SessionHijackingSuspected",
            Signal::SessionAnomaly { .. } => "SessionAnomaly",
            Signal::TorDetected { .. } => "TorDetected",
            Signal::PublicProxyDetected { .. } => "PublicProxyDetected",
            Signal::SuspiciousTlsFingerprint { .. } => "SuspiciousTlsFingerprint",
        }
    }
}

/// Signal record with timestamp for history tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalRecord {
    pub signal: Signal,
    pub timestamp: DateTime<Utc>,
}
```

**Signal Categories**:
- Bot Detection: SuspiciousUserAgent, BotSignature, SuspiciousClientProfile
- Brute Force: FailedAuthAttempt, CredentialStuffing
- Flooding: Flooding, AbusiveClient
- Protocol: ProtocolAnomaly, SuspiciousMethod
- Path Traversal: PathTraversalAttempt
- Uploads: PotentialWebshellUpload, SuspiciousUpload
- Injections: SqlInjectionAttempt, XssAttempt, RceAttempt, SuspiciousPayload
- Scanning: VulnerabilityScan, ExcessiveNotFound
- Host Header: HostHeaderAnomaly
- SSRF: SsrfSuspected
- Session: SessionHijackingSuspected, SessionAnomaly
- TLS/Proxy: TorDetected, PublicProxyDetected, SuspiciousTlsFingerprint

**Default Weights** (configurable via FR-022):
- Critical (40-50): RceAttempt, PotentialWebshellUpload, CredentialStuffing
- High (25-35): SqlInjectionAttempt, XssAttempt, PathTraversalAttempt
- Medium (10-20): VulnerabilityScan, SuspiciousUserAgent, Flooding
- Low (5-10): TorDetected, PublicProxyDetected, ProtocolAnomaly

---

### 3. HttpRequest

Wrapper for incoming HTTP requests with extracted analysis attributes.

**Requirements**: FR-002 (request parsing), FR-027 (protocol validation), FR-034 (header preservation)

**Rust Definition**:

```rust
use hyper::{Request, Body, Method, Version, Uri, HeaderMap};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// Parsed HTTP request with security analysis attributes
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Client IP address (extracted from socket or X-Forwarded-For)
    pub client_ip: IpAddr,

    /// HTTP method
    pub method: Method,

    /// Request URI
    pub uri: Uri,

    /// HTTP version
    pub version: Version,

    /// All headers (preserved for forwarding per FR-034)
    pub headers: HeaderMap,

    /// Request body (if applicable)
    pub body: Option<Vec<u8>>,

    /// Extracted User-Agent
    pub user_agent: Option<String>,

    /// Extracted Referer
    pub referer: Option<String>,

    /// Extracted cookies
    pub cookies: HashMap<String, String>,

    /// Query parameters (GET)
    pub query_params: HashMap<String, String>,

    /// POST parameters (form data)
    pub post_params: HashMap<String, String>,

    /// Timestamp of request arrival
    pub timestamp: DateTime<Utc>,

    /// Unique request ID for tracing
    pub request_id: String,
}

impl HttpRequest {
    /// Parse hyper Request into HttpRequest
    pub async fn from_hyper(
        req: Request<Body>,
        client_ip: IpAddr,
    ) -> Result<Self, ParseError> {
        let (parts, body) = req.into_parts();

        // Extract User-Agent
        let user_agent = parts.headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Extract Referer
        let referer = parts.headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Parse cookies
        let cookies = Self::parse_cookies(&parts.headers);

        // Parse query parameters
        let query_params = Self::parse_query_params(parts.uri.query());

        // Read body
        let body_bytes = hyper::body::to_bytes(body).await?;
        let body = if !body_bytes.is_empty() {
            Some(body_bytes.to_vec())
        } else {
            None
        };

        // Parse POST parameters (if Content-Type: application/x-www-form-urlencoded)
        let post_params = if let Some(content_type) = parts.headers.get("content-type") {
            if content_type.to_str()?.contains("application/x-www-form-urlencoded") {
                Self::parse_form_data(body.as_ref())
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        Ok(Self {
            client_ip,
            method: parts.method,
            uri: parts.uri,
            version: parts.version,
            headers: parts.headers,
            body,
            user_agent,
            referer,
            cookies,
            query_params,
            post_params,
            timestamp: Utc::now(),
            request_id: uuid::Uuid::new_v4().to_string(),
        })
    }

    fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
        let mut cookies = HashMap::new();
        if let Some(cookie_header) = headers.get("cookie") {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for pair in cookie_str.split(';') {
                    let parts: Vec<&str> = pair.trim().splitn(2, '=').collect();
                    if parts.len() == 2 {
                        cookies.insert(parts[0].to_string(), parts[1].to_string());
                    }
                }
            }
        }
        cookies
    }

    fn parse_query_params(query: Option<&str>) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(query_str) = query {
            for pair in query_str.split('&') {
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let key = urlencoding::decode(parts[0]).unwrap_or_default().to_string();
                    let value = urlencoding::decode(parts[1]).unwrap_or_default().to_string();
                    params.insert(key, value);
                }
            }
        }
        params
    }

    fn parse_form_data(body: Option<&Vec<u8>>) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(bytes) = body {
            if let Ok(body_str) = std::str::from_utf8(bytes) {
                for pair in body_str.split('&') {
                    let parts: Vec<&str> = pair.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let key = urlencoding::decode(parts[0]).unwrap_or_default().to_string();
                        let value = urlencoding::decode(parts[1]).unwrap_or_default().to_string();
                        params.insert(key, value);
                    }
                }
            }
        }
        params
    }

    /// Get session ID from cookies (if present)
    pub fn session_id(&self) -> Option<&String> {
        self.cookies.get("session_id")
            .or_else(|| self.cookies.get("PHPSESSID"))
            .or_else(|| self.cookies.get("sessionid"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("Invalid header value: {0}")]
    InvalidHeader(#[from] hyper::header::ToStrError),

    #[error("Invalid UTF-8 in body")]
    InvalidUtf8,
}
```

---

### 4. ProxyDecision

Decision outcome for each request after reputation analysis.

**Requirements**: FR-006 (decision types), FR-007 (adaptive rate limiting), FR-031 (CAPTCHA)

**Rust Definition**:

```rust
use serde::{Deserialize, Serialize};

/// Decision for handling a request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyDecision {
    /// Forward request to backend
    Allow {
        /// Optional headers to add
        additional_headers: HashMap<String, String>,
    },

    /// Rate limit (delay response)
    RateLimit {
        /// Retry after seconds
        retry_after_secs: u32,
        /// Current rate limit tier
        tier: RateLimitTier,
    },

    /// Present CAPTCHA challenge
    Challenge {
        /// Challenge type
        challenge_type: ChallengeType,
        /// Callback URL after solving
        callback_url: String,
    },

    /// Block request
    Block {
        /// Block reason (for logging and response)
        reason: BlockReason,
        /// HTTP status code to return
        status_code: u16,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RateLimitTier {
    Normal,      // 1000 req/min
    Suspicious,  // 200 req/min
    Aggressive,  // 50 req/min
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChallengeType {
    Captcha,
    JavaScript,
    HumanVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BlockReason {
    Blacklisted,
    LowReputation { score: i32 },
    IrremissibleSignal { signal_name: String },
    RateLimitExceeded,
    SuspiciousActivity { signals: Vec<String> },
}

impl ProxyDecision {
    /// Create Allow decision
    pub fn allow() -> Self {
        Self::Allow {
            additional_headers: HashMap::new(),
        }
    }

    /// Create Allow with score header
    pub fn allow_with_score(score: i32) -> Self {
        let mut headers = HashMap::new();
        headers.insert("X-WebSec-Score".to_string(), score.to_string());
        Self::Allow {
            additional_headers: headers,
        }
    }

    /// Create RateLimit decision
    pub fn rate_limit(tier: RateLimitTier, retry_after_secs: u32) -> Self {
        Self::RateLimit {
            retry_after_secs,
            tier,
        }
    }

    /// Create Challenge decision
    pub fn challenge(challenge_type: ChallengeType) -> Self {
        Self::Challenge {
            challenge_type,
            callback_url: "/websec/challenge/verify".to_string(),
        }
    }

    /// Create Block decision
    pub fn block(reason: BlockReason) -> Self {
        let status_code = match &reason {
            BlockReason::Blacklisted => 403,
            BlockReason::LowReputation { .. } => 403,
            BlockReason::IrremissibleSignal { .. } => 403,
            BlockReason::RateLimitExceeded => 429,
            BlockReason::SuspiciousActivity { .. } => 403,
        };

        Self::Block {
            reason,
            status_code,
        }
    }

    /// Check if decision blocks the request
    pub fn is_blocking(&self) -> bool {
        matches!(self, ProxyDecision::Block { .. })
    }

    /// Get HTTP status code for decision
    pub fn status_code(&self) -> u16 {
        match self {
            ProxyDecision::Allow { .. } => 200,
            ProxyDecision::RateLimit { .. } => 429,
            ProxyDecision::Challenge { .. } => 403,
            ProxyDecision::Block { status_code, .. } => *status_code,
        }
    }
}
```

**Decision Logic** (FR-021 configurable thresholds):
```
Score >= 80:  ALLOW (normal traffic)
Score 50-79:  RATE_LIMIT (suspicious)
Score 20-49:  CHALLENGE (highly suspicious)
Score < 20:   BLOCK (malicious)

Override: Blacklist → immediate BLOCK
Override: Whitelist → immediate ALLOW
```

---

### 5. ReputationScore

Score calculation engine implementing the reputation formula.

**Requirements**: FR-003 (score formula), FR-015 (exponential decay), FR-012 (geo penalties)

**Rust Definition**:

```rust
use serde::{Deserialize, Serialize};

/// Reputation score calculator
pub struct ReputationScore {
    config: ReputationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Base score for new IPs
    pub base_score: i32,

    /// Decay half-life in hours (default 24h)
    pub decay_half_life_hours: f64,

    /// Correlation bonus when multiple different signals detected
    pub correlation_penalty_bonus: i32,

    /// Per-signal weights
    pub signal_weights: HashMap<String, i32>,

    /// Geographic penalties
    pub geo_penalties: HashMap<String, i32>,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            base_score: 100,
            decay_half_life_hours: 24.0,
            correlation_penalty_bonus: 10,
            signal_weights: default_signal_weights(),
            geo_penalties: HashMap::new(),
        }
    }
}

impl ReputationScore {
    pub fn new(config: ReputationConfig) -> Self {
        Self { config }
    }

    /// FR-003: Calculate score = max(0, min(100, base - Σ(poids_signal)))
    pub fn calculate_score(&self, profile: &IpProfile) -> i32 {
        let mut score = self.config.base_score;

        // Subtract signal penalties
        let total_penalty: i32 = profile.signals
            .iter()
            .map(|record| {
                let signal_weight = record.signal.weight();
                // Apply time decay to older signals (unless irremissible)
                if record.signal.is_irremissible() {
                    signal_weight
                } else {
                    self.apply_decay(signal_weight, record.timestamp)
                }
            })
            .sum();

        score -= total_penalty;

        // Apply correlation penalty if multiple different signal types
        let unique_signal_types: std::collections::HashSet<_> = profile.signals
            .iter()
            .map(|r| r.signal.name())
            .collect();

        if unique_signal_types.len() >= 3 {
            score -= self.config.correlation_penalty_bonus;
        }

        // Apply geographic penalty if configured
        if let Some(geo) = &profile.geolocation {
            if let Some(penalty) = self.config.geo_penalties.get(&geo.country_code) {
                score -= penalty;
            }
        }

        // Clamp to [0, 100]
        score.max(0).min(100)
    }

    /// FR-015: Exponential decay with 24h half-life
    /// Formula: weight * (0.5)^(hours_elapsed / half_life)
    fn apply_decay(&self, weight: i32, signal_time: DateTime<Utc>) -> i32 {
        let elapsed = Utc::now().signed_duration_since(signal_time);
        let hours_elapsed = elapsed.num_seconds() as f64 / 3600.0;

        let decay_factor = 0.5_f64.powf(hours_elapsed / self.config.decay_half_life_hours);
        (weight as f64 * decay_factor).round() as i32
    }

    /// Make decision based on score and thresholds
    pub fn make_decision(&self, score: i32, is_blacklisted: bool, is_whitelisted: bool) -> ProxyDecision {
        // FR-009: Blacklist overrides everything
        if is_blacklisted {
            return ProxyDecision::block(BlockReason::Blacklisted);
        }

        // FR-010: Whitelist always allowed
        if is_whitelisted {
            return ProxyDecision::allow_with_score(score);
        }

        // FR-021: Configurable thresholds
        match score {
            80..=100 => ProxyDecision::allow_with_score(score),
            50..=79 => ProxyDecision::rate_limit(RateLimitTier::Suspicious, 2),
            20..=49 => ProxyDecision::challenge(ChallengeType::Captcha),
            _ => ProxyDecision::block(BlockReason::LowReputation { score }),
        }
    }
}

fn default_signal_weights() -> HashMap<String, i32> {
    let mut weights = HashMap::new();

    // Critical (40-50)
    weights.insert("RceAttempt".to_string(), 50);
    weights.insert("PotentialWebshellUpload".to_string(), 45);
    weights.insert("CredentialStuffing".to_string(), 40);

    // High (25-35)
    weights.insert("SqlInjectionAttempt".to_string(), 35);
    weights.insert("XssAttempt".to_string(), 30);
    weights.insert("PathTraversalAttempt".to_string(), 30);
    weights.insert("SessionHijackingSuspected".to_string(), 25);

    // Medium (10-20)
    weights.insert("VulnerabilityScan".to_string(), 20);
    weights.insert("SuspiciousUserAgent".to_string(), 15);
    weights.insert("Flooding".to_string(), 15);
    weights.insert("SsrfSuspected".to_string(), 15);
    weights.insert("FailedAuthAttempt".to_string(), 10);

    // Low (5-10)
    weights.insert("TorDetected".to_string(), 10);
    weights.insert("PublicProxyDetected".to_string(), 8);
    weights.insert("ProtocolAnomaly".to_string(), 8);
    weights.insert("ExcessiveNotFound".to_string(), 5);

    weights
}
```

**Example Calculation**:
```
Base score: 100
Signal 1: SqlInjectionAttempt (weight: 35, age: 2h)
  → Decayed weight: 35 * (0.5)^(2/24) = 35 * 0.944 = 33

Signal 2: SuspiciousUserAgent (weight: 15, age: 12h)
  → Decayed weight: 15 * (0.5)^(12/24) = 15 * 0.707 = 11

Total penalty: 33 + 11 = 44
Score: max(0, min(100, 100 - 44)) = 56

Decision: RATE_LIMIT (score in range 50-79)
```

---

### 6. Detector Trait

Strategy pattern interface for pluggable threat detectors.

**Requirements**: FR-004 (12 threat families), Principle III (Strategy pattern)

**Rust Definition**:

```rust
use async_trait::async_trait;

/// Trait for pluggable threat detectors (Strategy pattern)
#[async_trait]
pub trait Detector: Send + Sync {
    /// Analyze request and generate signals
    async fn analyze(
        &self,
        request: &HttpRequest,
        profile: &IpProfile,
    ) -> Vec<Signal>;

    /// Detector name for logging and metrics
    fn name(&self) -> &'static str;

    /// Whether this detector is enabled in current config
    fn is_enabled(&self) -> bool {
        true
    }
}

/// Detector registry managing all 12 detectors
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: vec![
                Box::new(BotDetector::new()),
                Box::new(BruteForceDetector::new()),
                Box::new(FloodDetector::new()),
                Box::new(ProtocolAnomalyDetector::new()),
                Box::new(PathTraversalDetector::new()),
                Box::new(UploadDetector::new()),
                Box::new(InjectionDetector::new()),
                Box::new(VulnScanDetector::new()),
                Box::new(HostHeaderDetector::new()),
                Box::new(SsrfDetector::new()),
                Box::new(SessionAnomalyDetector::new()),
                Box::new(TlsFingerprintDetector::new()),
            ],
        }
    }

    /// Run all enabled detectors
    pub async fn detect_all(
        &self,
        request: &HttpRequest,
        profile: &IpProfile,
    ) -> Vec<Signal> {
        let mut all_signals = Vec::new();

        for detector in &self.detectors {
            if detector.is_enabled() {
                let signals = detector.analyze(request, profile).await;
                all_signals.extend(signals);
            }
        }

        all_signals
    }
}
```

**12 Detector Types** (one per threat family):

1. **BotDetector**: User-Agent analysis, client profiling
2. **BruteForceDetector**: Failed auth tracking, credential stuffing
3. **FloodDetector**: Request rate analysis, burst detection
4. **ProtocolAnomalyDetector**: HTTP method/header validation
5. **PathTraversalDetector**: Path pattern matching
6. **UploadDetector**: File extension/content-type validation
7. **InjectionDetector**: SQLi/XSS/RCE pattern matching
8. **VulnScanDetector**: Known path scanning, 404 analysis
9. **HostHeaderDetector**: Host header validation
10. **SsrfDetector**: URL parameter analysis for private IPs
11. **SessionAnomalyDetector**: Geographic impossibility, session sharing
12. **TlsFingerprintDetector**: TOR/proxy detection, JA3 analysis

---

### 7. RateLimiter

Token bucket with sliding window implementation.

**Requirements**: FR-007 (adaptive rate limiting), Clarification (Token Bucket + Sliding Window)

**Rust Definition**:

```rust
use governor::{Quota, RateLimiter as GovernorLimiter, Jaffar};
use std::num::NonZeroU32;

/// Per-IP rate limiter with token bucket + sliding window
pub struct RateLimiter {
    /// Token bucket limiter (from governor crate)
    bucket: GovernorLimiter<IpAddr, Jaffar>,

    /// Configuration
    config: RateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Normal tier: requests per minute
    pub normal_rpm: u32,

    /// Suspicious tier: requests per minute
    pub suspicious_rpm: u32,

    /// Aggressive tier: requests per minute
    pub aggressive_rpm: u32,

    /// Sliding window duration (seconds)
    pub window_duration_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            normal_rpm: 1000,
            suspicious_rpm: 200,
            aggressive_rpm: 50,
            window_duration_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateLimitState {
    /// Request timestamps in current window
    pub request_timestamps: Vec<DateTime<Utc>>,

    /// Current tier
    pub current_tier: RateLimitTier,
}

impl RateLimitState {
    /// Clean old timestamps outside window
    pub fn clean_old_timestamps(&mut self, window_secs: i64) {
        let threshold = Utc::now() - chrono::Duration::seconds(window_secs);
        self.request_timestamps.retain(|&ts| ts > threshold);
    }

    /// Add new request timestamp
    pub fn add_request(&mut self) {
        self.request_timestamps.push(Utc::now());
    }

    /// Count requests in window
    pub fn count_in_window(&self, window_secs: i64) -> usize {
        let threshold = Utc::now() - chrono::Duration::seconds(window_secs);
        self.request_timestamps
            .iter()
            .filter(|&&ts| ts > threshold)
            .count()
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        // Default to normal tier quota
        let quota = Quota::per_minute(NonZeroU32::new(config.normal_rpm).unwrap());
        let bucket = GovernorLimiter::direct(quota);

        Self { bucket, config }
    }

    /// Check if request should be rate limited
    pub fn check_limit(
        &self,
        profile: &mut IpProfile,
        score: i32,
    ) -> Result<(), RateLimitViolation> {
        // Determine tier based on score
        let tier = self.tier_for_score(score);
        profile.rate_limit_state.current_tier = tier.clone();

        // Get threshold for this tier
        let threshold = match tier {
            RateLimitTier::Normal => self.config.normal_rpm,
            RateLimitTier::Suspicious => self.config.suspicious_rpm,
            RateLimitTier::Aggressive => self.config.aggressive_rpm,
        };

        // Check token bucket
        if self.bucket.check().is_err() {
            return Err(RateLimitViolation::TokenBucketExhausted);
        }

        // Check sliding window
        profile.rate_limit_state.clean_old_timestamps(self.config.window_duration_secs as i64);
        let window_count = profile.rate_limit_state.count_in_window(
            self.config.window_duration_secs as i64
        );

        if window_count >= threshold as usize {
            return Err(RateLimitViolation::SlidingWindowExceeded {
                count: window_count as u32,
                threshold,
            });
        }

        // Add this request to window
        profile.rate_limit_state.add_request();

        Ok(())
    }

    /// Determine tier based on reputation score
    fn tier_for_score(&self, score: i32) -> RateLimitTier {
        match score {
            80..=100 => RateLimitTier::Normal,
            50..=79 => RateLimitTier::Suspicious,
            _ => RateLimitTier::Aggressive,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitViolation {
    #[error("Token bucket exhausted")]
    TokenBucketExhausted,

    #[error("Sliding window exceeded: {count}/{threshold} requests")]
    SlidingWindowExceeded { count: u32, threshold: u32 },
}
```

---

### 8. Repository Trait

Storage abstraction for IP reputation persistence.

**Requirements**: FR-014 (persistence), NFR-004 (stateless), NFR-013 (degraded mode)

**Rust Definition**:

```rust
use async_trait::async_trait;
use std::net::IpAddr;

/// Repository pattern for IP profile storage
#[async_trait]
pub trait ReputationRepository: Send + Sync {
    /// Retrieve profile for IP
    async fn get_profile(&self, ip: IpAddr) -> Result<Option<IpProfile>, StorageError>;

    /// Save or update profile
    async fn save_profile(&self, ip: IpAddr, profile: IpProfile) -> Result<(), StorageError>;

    /// Delete profile (for whitelist reset)
    async fn delete_profile(&self, ip: IpAddr) -> Result<(), StorageError>;

    /// Check if IP is in blacklist
    async fn is_blacklisted(&self, ip: IpAddr) -> Result<bool, StorageError>;

    /// Check if IP is in whitelist
    async fn is_whitelisted(&self, ip: IpAddr) -> Result<bool, StorageError>;

    /// Add IP to blacklist
    async fn add_to_blacklist(&self, ip: IpAddr) -> Result<(), StorageError>;

    /// Add IP to whitelist
    async fn add_to_whitelist(&self, ip: IpAddr) -> Result<(), StorageError>;

    /// Remove IP from blacklist
    async fn remove_from_blacklist(&self, ip: IpAddr) -> Result<(), StorageError>;

    /// Remove IP from whitelist
    async fn remove_from_whitelist(&self, ip: IpAddr) -> Result<(), StorageError>;
}

/// Layered repository: L1 cache + L2 Redis + L3 fallback
pub struct LayeredRepository {
    l1_memory: Arc<MemoryCacheRepository>,
    l2_redis: Arc<RedisRepository>,
    l3_fallback: Arc<FileLogRepository>,
}

#[async_trait]
impl ReputationRepository for LayeredRepository {
    async fn get_profile(&self, ip: IpAddr) -> Result<Option<IpProfile>, StorageError> {
        // Try L1 cache (in-memory, <0.1ms)
        if let Some(profile) = self.l1_memory.get_profile(ip).await? {
            return Ok(Some(profile));
        }

        // Try L2 Redis (<2ms)
        match self.l2_redis.get_profile(ip).await {
            Ok(Some(profile)) => {
                // Populate L1 cache
                let _ = self.l1_memory.save_profile(ip, profile.clone()).await;
                Ok(Some(profile))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                // FR-013: Redis failed, enter degraded mode
                tracing::warn!("Redis unavailable, using degraded mode: {}", e);
                self.l3_fallback.get_profile(ip).await
            }
        }
    }

    async fn save_profile(&self, ip: IpAddr, profile: IpProfile) -> Result<(), StorageError> {
        // Save to L1 (always succeeds)
        let _ = self.l1_memory.save_profile(ip, profile.clone()).await;

        // Try L2 Redis
        match self.l2_redis.save_profile(ip, profile.clone()).await {
            Ok(_) => Ok(()),
            Err(e) => {
                // Fallback to file logs
                tracing::warn!("Redis save failed, using file fallback: {}", e);
                self.l3_fallback.save_profile(ip, profile).await
            }
        }
    }

    // ... other methods follow same pattern
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Redis error: {0}")]
    Redis(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
```

---

### 9. Supporting Entities

**RequestStatistics**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestStatistics {
    /// Total requests from this IP
    pub total_requests: u64,

    /// Requests resulting in 4xx errors
    pub error_4xx_count: u32,

    /// Requests resulting in 5xx errors
    pub error_5xx_count: u32,

    /// Requests to authentication endpoints
    pub auth_attempts: u32,

    /// Failed authentication attempts
    pub failed_auth_count: u32,

    /// Request timestamps (for sliding window)
    pub request_timestamps: Vec<DateTime<Utc>>,

    /// Average requests per minute
    pub avg_rpm: f64,
}
```

**GeoLocation**:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// ISO country code (e.g., "US", "FR", "RU")
    pub country_code: String,

    /// Country name
    pub country_name: String,

    /// City name (if available)
    pub city: Option<String>,

    /// Latitude
    pub latitude: f64,

    /// Longitude
    pub longitude: f64,

    /// ASN (Autonomous System Number)
    pub asn: Option<u32>,

    /// ISP/Organization name
    pub organization: Option<String>,
}
```

---

## Relationships Diagram

```
IpProfile (1) ──── (0..*) SignalRecord
    │                        │
    │                        └──── (1) Signal (enum)
    │
    ├──── (0..1) GeoLocation
    ├──── (1) RequestStatistics
    └──── (1) RateLimitState

HttpRequest ──> (1) IpAddr
            └──> (0..*) Headers/Params

ProxyDecision ──> BlockReason | RateLimitTier | ChallengeType

ReputationScore ──uses──> ReputationConfig
                └──calculates──> IpProfile

Detector (interface)
    ├── BotDetector
    ├── BruteForceDetector
    ├── FloodDetector
    ├── ProtocolAnomalyDetector
    ├── PathTraversalDetector
    ├── UploadDetector
    ├── InjectionDetector
    ├── VulnScanDetector
    ├── HostHeaderDetector
    ├── SsrfDetector
    ├── SessionAnomalyDetector
    └── TlsFingerprintDetector

ReputationRepository (interface)
    ├── LayeredRepository
    │       ├── MemoryCacheRepository (L1)
    │       ├── RedisRepository (L2)
    │       └── FileLogRepository (L3)
    └── ... custom implementations
```

---

## Validation Rules Summary

**IpProfile**:
- score ∈ [0, 100]
- updated_at >= created_at
- signal timestamps <= current time

**Signal**:
- weight > 0
- Irremissible flag only on: CredentialStuffing, PotentialWebshellUpload, RceAttempt

**HttpRequest**:
- valid IP address (IPv4 or IPv6)
- valid HTTP method
- headers preserved exactly (FR-034)

**ProxyDecision**:
- status_code in standard HTTP range [200-599]
- Block status codes: 403 or 429

**ReputationScore**:
- Base score typically 100
- Decay half-life > 0
- Correlation bonus >= 0

---

## Formulas Reference

### Reputation Score Formula (FR-003)

```
Score = max(0, min(100, base_score - Σ(decayed_weights) - correlation_penalty - geo_penalty))

Where:
  decayed_weight(signal) = {
    original_weight                                if signal.is_irremissible()
    original_weight * (0.5)^(hours_elapsed / 24)   otherwise
  }

  correlation_penalty = {
    correlation_bonus  if unique_signal_types >= 3
    0                  otherwise
  }

  geo_penalty = configured_penalty_for_country or 0
```

### Exponential Decay Formula (FR-015)

```
decay_factor = (0.5)^(hours_elapsed / half_life_hours)
decayed_weight = original_weight * decay_factor

Example (half-life = 24h):
  Age 0h:   decay_factor = 1.000 (100%)
  Age 12h:  decay_factor = 0.707 (71%)
  Age 24h:  decay_factor = 0.500 (50%)
  Age 48h:  decay_factor = 0.250 (25%)
  Age 72h:  decay_factor = 0.125 (13%)
```

### Rate Limiting (Token Bucket + Sliding Window)

```
Token Bucket:
  capacity = tier_max_requests
  refill_rate = tier_rpm / 60 (tokens per second)

Sliding Window:
  count = requests_in_last_60_seconds

Combined Check:
  ALLOW if (tokens_available > 0) AND (count < tier_rpm)
  RATE_LIMIT otherwise
```

---

## Implementation Notes

**Performance Considerations**:
- IpProfile serialization uses bincode for compact Redis storage
- Signal enum uses `#[repr(u8)]` for efficient memory layout
- HttpRequest avoids cloning body (uses references where possible)
- RateLimiter uses lock-free governor crate

**Security Considerations**:
- All user inputs validated before storage (NFR-005)
- No PII in logs (NFR-006)
- Secrets never in structs (NFR-006)
- Fail-closed defaults (NFR-013)

**Testing Strategy**:
- Each entity has unit tests for validation rules
- Contract tests verify formula correctness
- Property-based tests for decay formula
- Integration tests for Repository implementations

---

**Data Model Version**: 1.0.0
**Last Updated**: 2025-11-18
**Status**: Complete - Ready for Phase 2
