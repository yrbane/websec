//! Decision engine for reputation-based request routing
//!
//! Orchestrates the complete decision pipeline:
//! 1. Detect threats using detectors
//! 2. Update reputation profile with signals
//! 3. Recalculate score
//! 4. Determine proxy decision (ALLOW/RATE_LIMIT/CHALLENGE/BLOCK)

use super::profile::ReputationProfile;
use super::score::{determine_decision, recalculate_and_update, ProxyDecision, ScoringThresholds};
use crate::detectors::{DetectionResult, DetectorRegistry, HttpRequestContext};
use crate::lists::{Blacklist, Whitelist};
use crate::storage::ReputationRepository;
use crate::Result;
use std::net::IpAddr;
use std::sync::Arc;

/// Configuration for the decision engine
#[derive(Debug, Clone)]
pub struct DecisionEngineConfig {
    /// Base reputation score for new IPs
    pub base_score: u8,
    /// Exponential decay half-life in hours
    pub decay_half_life_hours: f64,
    /// Correlation penalty bonus
    pub correlation_penalty_bonus: u8,
    /// Scoring thresholds
    pub thresholds: ScoringThresholds,
    /// IP blacklist (block immediately)
    pub blacklist: Option<Blacklist>,
    /// IP whitelist (always allow)
    pub whitelist: Option<Whitelist>,
}

impl DecisionEngineConfig {
    /// Set the blacklist
    pub fn set_blacklist(&mut self, blacklist: Blacklist) {
        self.blacklist = Some(blacklist);
    }

    /// Set the whitelist
    pub fn set_whitelist(&mut self, whitelist: Whitelist) {
        self.whitelist = Some(whitelist);
    }
}

impl Default for DecisionEngineConfig {
    fn default() -> Self {
        Self {
            base_score: 100,
            decay_half_life_hours: 24.0,
            correlation_penalty_bonus: 10,
            thresholds: ScoringThresholds::default(),
            blacklist: None,
            whitelist: None,
        }
    }
}

/// Decision engine result
#[derive(Debug)]
pub struct DecisionEngineResult {
    /// The proxy decision
    pub decision: ProxyDecision,
    /// Current reputation score
    pub score: u8,
    /// Detection result from analyzers
    pub detection: DetectionResult,
    /// Whether this is a new IP
    pub is_new_ip: bool,
}

/// Core decision engine
///
/// Orchestrates threat detection, reputation scoring, and routing decisions.
///
/// # Workflow
///
/// 1. Load or create IP reputation profile
/// 2. Run all detectors against request
/// 3. Add detected signals to profile
/// 4. Recalculate reputation score with decay
/// 5. Determine proxy decision based on thresholds
/// 6. Save updated profile
pub struct DecisionEngine {
    config: DecisionEngineConfig,
    repository: Arc<dyn ReputationRepository>,
    detectors: Arc<DetectorRegistry>,
}

impl DecisionEngine {
    /// Create a new decision engine
    pub fn new(
        config: DecisionEngineConfig,
        repository: Arc<dyn ReputationRepository>,
        detectors: Arc<DetectorRegistry>,
    ) -> Self {
        Self {
            config,
            repository,
            detectors,
        }
    }

    /// Process a request and make a routing decision
    ///
    /// # Arguments
    ///
    /// * `context` - HTTP request context
    ///
    /// # Returns
    ///
    /// `DecisionEngineResult` with decision, score, and detection details.
    ///
    /// # Priority Order
    ///
    /// 1. Check blacklist (highest priority) → immediate BLOCK
    /// 2. Check whitelist → immediate ALLOW with score 100
    /// 3. Normal scoring pipeline
    pub async fn process_request(
        &self,
        context: &HttpRequestContext,
    ) -> Result<DecisionEngineResult> {
        let ip = context.ip;

        // Priority 1: Check blacklist (immediate block)
        if let Some(ref blacklist) = self.config.blacklist {
            if blacklist.contains(&ip) {
                tracing::info!(ip = %ip, "IP in blacklist - blocking immediately");
                return Ok(DecisionEngineResult {
                    decision: ProxyDecision::Block,
                    score: 0,
                    detection: DetectionResult::clean(),
                    is_new_ip: false,
                });
            }
        }

        // Priority 2: Check whitelist (bypass all scoring)
        if let Some(ref whitelist) = self.config.whitelist {
            if whitelist.contains(&ip) {
                tracing::debug!(ip = %ip, "IP in whitelist - allowing with perfect score");
                return Ok(DecisionEngineResult {
                    decision: ProxyDecision::Allow,
                    score: 100,
                    detection: DetectionResult::clean(),
                    is_new_ip: false,
                });
            }
        }

        // Priority 3: Normal scoring pipeline
        // Step 1: Load or create profile
        let mut profile = self.get_or_create_profile(&ip).await?;
        let is_new_ip = profile.request_count == 0;

        // Step 2: Run detectors
        let detection = self.detectors.analyze_all(context).await;

        // Step 3: Add signals to profile
        for signal in &detection.signals {
            profile.add_signal(signal.clone());
        }

        // Step 4: Record request
        profile.record_request();

        // Step 5: Recalculate score
        recalculate_and_update(
            &mut profile,
            self.config.base_score,
            self.config.decay_half_life_hours,
            self.config.correlation_penalty_bonus,
        );

        // Step 6: Determine decision
        let decision = determine_decision(profile.current_score, &self.config.thresholds);

        // Step 7: Record if blocked
        if decision == ProxyDecision::Block {
            profile.record_blocked();
        }

        // Step 8: Save profile
        self.repository.save(&profile).await?;

        Ok(DecisionEngineResult {
            decision,
            score: profile.current_score,
            detection,
            is_new_ip,
        })
    }

    /// Get existing profile or create new one
    async fn get_or_create_profile(&self, ip: &IpAddr) -> Result<ReputationProfile> {
        match self.repository.get(ip).await? {
            Some(profile) => Ok(profile),
            None => Ok(ReputationProfile::new(*ip, self.config.base_score)),
        }
    }

    /// Get current reputation score for an IP (without detection)
    ///
    /// Useful for admin/monitoring endpoints.
    pub async fn get_score(&self, ip: &IpAddr) -> Result<Option<u8>> {
        Ok(self.repository.get(ip).await?.map(|p| p.current_score))
    }

    /// Whitelist an IP (always ALLOW)
    pub async fn whitelist(&self, ip: &IpAddr) -> Result<()> {
        let mut profile = self.get_or_create_profile(ip).await?;
        profile.whitelisted = true;
        profile.current_score = 100;
        self.repository.save(&profile).await
    }

    /// Blacklist an IP (always BLOCK)
    pub async fn blacklist(&self, ip: &IpAddr) -> Result<()> {
        let mut profile = self.get_or_create_profile(ip).await?;
        profile.blacklisted = true;
        profile.current_score = 0;
        self.repository.save(&profile).await
    }

    /// Remove whitelist/blacklist status
    pub async fn reset_list_status(&self, ip: &IpAddr) -> Result<()> {
        if let Some(mut profile) = self.repository.get(ip).await? {
            profile.whitelisted = false;
            profile.blacklisted = false;
            recalculate_and_update(
                &mut profile,
                self.config.base_score,
                self.config.decay_half_life_hours,
                self.config.correlation_penalty_bonus,
            );
            self.repository.save(&profile).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::Detector;
    use crate::reputation::{Signal, SignalVariant};
    use crate::storage::InMemoryRepository;
    use async_trait::async_trait;
    use std::str::FromStr;

    struct AlwaysCleanDetector;

    #[async_trait]
    impl Detector for AlwaysCleanDetector {
        fn name(&self) -> &str {
            "AlwaysClean"
        }

        async fn analyze(&self, _context: &HttpRequestContext) -> DetectionResult {
            DetectionResult::clean()
        }
    }

    struct AlwaysSuspiciousDetector;

    #[async_trait]
    impl Detector for AlwaysSuspiciousDetector {
        fn name(&self) -> &str {
            "AlwaysSuspicious"
        }

        async fn analyze(&self, _context: &HttpRequestContext) -> DetectionResult {
            DetectionResult::with_signal(Signal::new(SignalVariant::FailedLogin))
        }
    }

    fn create_test_context(ip: &str) -> HttpRequestContext {
        HttpRequestContext {
            ip: IpAddr::from_str(ip).unwrap(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            headers: vec![],
            body: None,
            user_agent: None,
            referer: None,
            content_type: None,
        }
    }

    #[tokio::test]
    async fn test_clean_request_allows() {
        let config = DecisionEngineConfig::default();
        let repo = Arc::new(InMemoryRepository::new());
        let mut registry = DetectorRegistry::new();
        registry.register(Arc::new(AlwaysCleanDetector));
        let detectors = Arc::new(registry);

        let engine = DecisionEngine::new(config, repo, detectors);
        let context = create_test_context("192.168.1.1");

        let result = engine.process_request(&context).await.unwrap();

        assert_eq!(result.decision, ProxyDecision::Allow);
        assert_eq!(result.score, 100);
        assert!(result.is_new_ip);
        assert!(!result.detection.suspicious);
    }

    #[tokio::test]
    async fn test_suspicious_request_lowers_score() {
        let config = DecisionEngineConfig::default();
        let repo = Arc::new(InMemoryRepository::new());
        let mut registry = DetectorRegistry::new();
        registry.register(Arc::new(AlwaysSuspiciousDetector));
        let detectors = Arc::new(registry);

        let engine = DecisionEngine::new(config, repo, detectors);
        let context = create_test_context("192.168.1.1");

        let result = engine.process_request(&context).await.unwrap();

        assert!(result.detection.suspicious);
        assert!(result.score < 100);
        assert_eq!(result.detection.signals.len(), 1);
    }

    #[tokio::test]
    async fn test_repeated_attacks_lower_score() {
        let config = DecisionEngineConfig::default();
        let repo = Arc::new(InMemoryRepository::new());
        let mut registry = DetectorRegistry::new();
        registry.register(Arc::new(AlwaysSuspiciousDetector));
        let detectors = Arc::new(registry);

        let engine = DecisionEngine::new(config, repo, detectors);
        let context = create_test_context("192.168.1.1");

        // First request
        let result1 = engine.process_request(&context).await.unwrap();
        let score1 = result1.score;

        // Second request
        let result2 = engine.process_request(&context).await.unwrap();
        let score2 = result2.score;

        // Score should decrease
        assert!(score2 < score1);
    }

    #[tokio::test]
    async fn test_whitelist() {
        let config = DecisionEngineConfig::default();
        let repo = Arc::new(InMemoryRepository::new());
        let registry = DetectorRegistry::new();
        let detectors = Arc::new(registry);

        let engine = DecisionEngine::new(config, repo.clone(), detectors);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        engine.whitelist(&ip).await.unwrap();

        let profile = repo.get(&ip).await.unwrap().unwrap();
        assert!(profile.whitelisted);
        assert_eq!(profile.current_score, 100);
    }

    #[tokio::test]
    async fn test_blacklist() {
        let config = DecisionEngineConfig::default();
        let repo = Arc::new(InMemoryRepository::new());
        let registry = DetectorRegistry::new();
        let detectors = Arc::new(registry);

        let engine = DecisionEngine::new(config, repo.clone(), detectors);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        engine.blacklist(&ip).await.unwrap();

        let profile = repo.get(&ip).await.unwrap().unwrap();
        assert!(profile.blacklisted);
        assert_eq!(profile.current_score, 0);
    }

    #[tokio::test]
    async fn test_reset_list_status() {
        let config = DecisionEngineConfig::default();
        let repo = Arc::new(InMemoryRepository::new());
        let registry = DetectorRegistry::new();
        let detectors = Arc::new(registry);

        let engine = DecisionEngine::new(config, repo.clone(), detectors);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        // Whitelist
        engine.whitelist(&ip).await.unwrap();
        assert!(repo.get(&ip).await.unwrap().unwrap().whitelisted);

        // Reset
        engine.reset_list_status(&ip).await.unwrap();
        let profile = repo.get(&ip).await.unwrap().unwrap();
        assert!(!profile.whitelisted);
        assert!(!profile.blacklisted);
    }

    #[tokio::test]
    async fn test_get_score() {
        let config = DecisionEngineConfig::default();
        let repo = Arc::new(InMemoryRepository::new());
        let registry = DetectorRegistry::new();
        let detectors = Arc::new(registry);

        let engine = DecisionEngine::new(config, repo.clone(), detectors);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        // No profile yet
        assert!(engine.get_score(&ip).await.unwrap().is_none());

        // Create profile
        let profile = ReputationProfile::new(ip, 100);
        repo.save(&profile).await.unwrap();

        // Should return score
        assert_eq!(engine.get_score(&ip).await.unwrap(), Some(100));
    }
}
