# WebSec Contract Test Specifications

**Feature**: WebSec Proxy de Sécurité  
**Branch**: `001-websec-proxy`  
**Date**: 2025-11-18  
**Status**: Complete  

This document defines behavioral contracts for all WebSec components. Each contract specifies **Given-When-Then** scenarios that MUST be satisfied by implementations.

---

## 1. Detector Contracts (12 Detectors)

### Contract 1.1: BotDetector - Known Scanner User-Agents

**GIVEN**: HttpRequest with User-Agent matching known scanner pattern  
**WHEN**: BotDetector.analyze() called  
**THEN**: Returns Signal::SuspiciousUserAgent with weight ≥ 15  

**Examples**:
- `sqlmap/1.7` → SuspiciousUserAgent
- `nikto/2.1.6` → SuspiciousUserAgent  
- `nmap` → SuspiciousUserAgent
- `Chrome/120.0` → No signal (legitimate)

### Contract 1.2: BruteForceDetector - Failed Auth Tracking

**GIVEN**: 5+ requests to `/login` with 401 status from same IP within 60s  
**WHEN**: BruteForceDetector.analyze() called on 5th request  
**THEN**: Returns Signal::FailedAuthAttempt with weight ≥ 10  

### Contract 1.3: FloodDetector - Request Rate

**GIVEN**: IP sends 1000+ requests in 60 seconds  
**WHEN**: FloodDetector.analyze() called  
**THEN**: Returns Signal::Flooding with weight ≥ 15  

### Contract 1.4: InjectionDetector - SQL Injection Pattern

**GIVEN**: Request with parameter containing `' OR '1'='1`  
**WHEN**: InjectionDetector.analyze() called  
**THEN**: Returns Signal::SqlInjectionAttempt with weight ≥ 35  

**Additional patterns**:
- `UNION SELECT` → SqlInjectionAttempt
- `<script>alert(1)</script>` → XssAttempt
- `$(whoami)` → RceAttempt

### Contract 1.5: PathTraversalDetector - Directory Traversal

**GIVEN**: Request path contains `../../../etc/passwd`  
**WHEN**: PathTraversalDetector.analyze() called  
**THEN**: Returns Signal::PathTraversalAttempt with weight ≥ 30  

### Contract 1.6: UploadDetector - Webshell Extension

**GIVEN**: File upload with extension `.php`, `.jsp`, `.asp`  
**WHEN**: UploadDetector.analyze() called  
**THEN**: Returns Signal::PotentialWebshellUpload with weight ≥ 45, irremissible=true  

### Contract 1.7: VulnScanDetector - Known Scan Paths

**GIVEN**: Request to `/admin/config.php`, `/.git/config`, `/wp-admin/`  
**WHEN**: VulnScanDetector.analyze() called  
**THEN**: Returns Signal::VulnerabilityScan with weight ≥ 20  

### Contract 1.8: TorProxyDetector - TOR Exit Node

**GIVEN**: IP is in TOR exit node list  
**WHEN**: TorProxyDetector.analyze() called  
**THEN**: Returns Signal::TorDetected with weight ≥ 10  

**All 12 detectors MUST implement**:
- `async fn analyze(&self, request: &HttpRequest, profile: &IpProfile) -> Vec<Signal>`
- `fn name(&self) -> &'static str`
- Return empty Vec if no threats detected

---

## 2. Reputation Engine Contracts

### Contract 2.1: Score Calculation Formula

**GIVEN**: IpProfile with base_score=100, signals=[SqlInjectionAttempt(weight=35), Flooding(weight=15)]  
**WHEN**: ReputationScore.calculate_score() called  
**THEN**: Returns score = max(0, min(100, 100 - 35 - 15)) = 50  

**Formula**: `Score = max(0, min(100, base - Σ(decayed_weights)))`

### Contract 2.2: Exponential Decay (24h half-life)

**GIVEN**: Signal with weight=40, age=24 hours, half_life=24h  
**WHEN**: Decay applied  
**THEN**: Decayed weight = 40 * (0.5)^(24/24) = 40 * 0.5 = 20  

**Examples**:
- Age 0h: weight × 1.000 (100%)
- Age 12h: weight × 0.707 (71%)  
- Age 24h: weight × 0.500 (50%)
- Age 48h: weight × 0.250 (25%)

### Contract 2.3: Irremissible Signals (No Decay)

**GIVEN**: Signal::RceAttempt with irremissible=true, age=48 hours  
**WHEN**: Decay applied  
**THEN**: Weight remains unchanged (no decay)  

**Irremissible signals**: RceAttempt, PotentialWebshellUpload, CredentialStuffing (with flag)

### Contract 2.4: Correlation Penalty

**GIVEN**: IpProfile with 3+ different signal types detected within short time  
**WHEN**: calculate_score() called  
**THEN**: Additional correlation_penalty_bonus subtracted from score  

**Example**:
- Signals: SqlInjectionAttempt, Flooding, TorDetected (3 types)
- Correlation bonus: -10
- Final score reduced by extra 10 points

### Contract 2.5: Geographic Penalty

**GIVEN**: IP geolocated to country with configured penalty (e.g., RU: -15)  
**WHEN**: calculate_score() called  
**THEN**: Score reduced by geo penalty  

**Example**:
- Base score: 100
- Country: RU
- Geo penalty: -15
- Score: 85 (before other signals)

### Contract 2.6: Score Clamping

**GIVEN**: Calculated score = -50 (negative)  
**WHEN**: calculate_score() called  
**THEN**: Returns 0 (clamped to minimum)  

**GIVEN**: Calculated score = 150 (over 100)  
**WHEN**: calculate_score() called  
**THEN**: Returns 100 (clamped to maximum)  

### Contract 2.7: Decision Thresholds

**GIVEN**: Score=85, thresholds=[allow:70, ratelimit:40, challenge:20, block:0]  
**WHEN**: make_decision() called  
**THEN**: Returns ProxyDecision::Allow  

**Thresholds**:
- Score 70-100: ALLOW
- Score 40-69: RATE_LIMIT
- Score 20-39: CHALLENGE
- Score 0-19: BLOCK

### Contract 2.8: Blacklist Override

**GIVEN**: IP in blacklist, score=100 (perfect)  
**WHEN**: make_decision() called  
**THEN**: Returns ProxyDecision::Block (blacklist overrides score)  

### Contract 2.9: Whitelist Override

**GIVEN**: IP in whitelist, score=0 (worst)  
**WHEN**: make_decision() called  
**THEN**: Returns ProxyDecision::Allow (whitelist overrides score)  

---

## 3. Rate Limiter Contracts

### Contract 3.1: Token Bucket - Allow Under Limit

**GIVEN**: RateLimiter with quota=100 req/min, current usage=50 req in last 60s  
**WHEN**: check_limit() called  
**THEN**: Returns Ok (allowed)  

### Contract 3.2: Token Bucket - Reject Over Limit

**GIVEN**: RateLimiter with quota=100 req/min, current usage=100 req in last 60s  
**WHEN**: check_limit() called  
**THEN**: Returns Err(RateLimitViolation::TokenBucketExhausted)  

### Contract 3.3: Sliding Window - Count in Window

**GIVEN**: IP with request timestamps [t-90s, t-45s, t-10s, t-5s], window=60s  
**WHEN**: count_in_window(60) called  
**THEN**: Returns 3 (only t-45s, t-10s, t-5s within window)  

### Contract 3.4: Sliding Window - Exceed Threshold

**GIVEN**: window_count=200, threshold=200, tier=Suspicious  
**WHEN**: check_limit() called  
**THEN**: Returns Err(RateLimitViolation::SlidingWindowExceeded)  

### Contract 3.5: Adaptive Tier - Score-Based

**GIVEN**: Score=85 (high reputation)  
**WHEN**: tier_for_score() called  
**THEN**: Returns RateLimitTier::Normal (1000 req/min)  

**GIVEN**: Score=55 (suspicious)  
**WHEN**: tier_for_score() called  
**THEN**: Returns RateLimitTier::Suspicious (200 req/min)  

**GIVEN**: Score=15 (malicious)  
**WHEN**: tier_for_score() called  
**THEN**: Returns RateLimitTier::Aggressive (50 req/min)  

### Contract 3.6: Timestamp Cleanup

**GIVEN**: RateLimitState with timestamps [t-120s, t-90s, t-30s], window=60s  
**WHEN**: clean_old_timestamps(60) called  
**THEN**: Retains only [t-30s] (others outside window)  

---

## 4. Storage Repository Contracts

### Contract 4.1: Get Profile - Found

**GIVEN**: IpProfile for 192.0.2.1 exists in storage  
**WHEN**: repository.get_profile(192.0.2.1) called  
**THEN**: Returns Ok(Some(profile)) with correct data  

### Contract 4.2: Get Profile - Not Found

**GIVEN**: No profile for 192.0.2.100 in storage  
**WHEN**: repository.get_profile(192.0.2.100) called  
**THEN**: Returns Ok(None)  

### Contract 4.3: Save Profile - New

**GIVEN**: New IpProfile for 198.51.100.1  
**WHEN**: repository.save_profile(198.51.100.1, profile) called  
**THEN**: Profile stored, subsequent get_profile() returns it  

### Contract 4.4: Save Profile - Update

**GIVEN**: Existing profile with score=80  
**WHEN**: repository.save_profile() called with updated score=60  
**THEN**: Profile updated, get_profile() returns score=60  

### Contract 4.5: Delete Profile

**GIVEN**: Profile exists for 203.0.113.50  
**WHEN**: repository.delete_profile(203.0.113.50) called  
**THEN**: Profile removed, get_profile() returns None  

### Contract 4.6: Blacklist Check - Listed

**GIVEN**: IP 198.51.100.42 in blacklist  
**WHEN**: repository.is_blacklisted(198.51.100.42) called  
**THEN**: Returns Ok(true)  

### Contract 4.7: Blacklist Check - Not Listed

**GIVEN**: IP 192.0.2.1 NOT in blacklist  
**WHEN**: repository.is_blacklisted(192.0.2.1) called  
**THEN**: Returns Ok(false)  

### Contract 4.8: Add to Blacklist

**GIVEN**: IP 203.0.113.10 not in blacklist  
**WHEN**: repository.add_to_blacklist(203.0.113.10) called  
**THEN**: is_blacklisted() subsequently returns true  

### Contract 4.9: Whitelist Check - Listed

**GIVEN**: IP 192.0.2.100 in whitelist  
**WHEN**: repository.is_whitelisted(192.0.2.100) called  
**THEN**: Returns Ok(true)  

### Contract 4.10: Layered Repository - L1 Cache Hit

**GIVEN**: Profile in L1 memory cache  
**WHEN**: layered_repository.get_profile() called  
**THEN**: Returns from L1 without querying L2 Redis (< 0.1ms)  

### Contract 4.11: Layered Repository - L1 Miss, L2 Hit

**GIVEN**: Profile NOT in L1 but EXISTS in L2 Redis  
**WHEN**: layered_repository.get_profile() called  
**THEN**: Returns from L2, populates L1 cache for future hits  

### Contract 4.12: Layered Repository - Degraded Mode

**GIVEN**: Redis connection fails (L2 unavailable)  
**WHEN**: layered_repository.get_profile() called  
**THEN**: Falls back to L3 file logs, returns Ok (degraded mode)  

### Contract 4.13: Repository Error Handling

**GIVEN**: Redis serialization error  
**WHEN**: repository.save_profile() called  
**THEN**: Returns Err(StorageError::Serialization)  

---

## 5. Proxy Decision Contracts

### Contract 5.1: Allow Decision - Headers Added

**GIVEN**: ProxyDecision::Allow with score=85  
**WHEN**: Decision applied to response  
**THEN**: Response includes header `X-WebSec-Score: 85`  

### Contract 5.2: RateLimit Decision - Retry-After

**GIVEN**: ProxyDecision::RateLimit { retry_after_secs: 30 }  
**WHEN**: Decision applied  
**THEN**: Returns HTTP 429 with `Retry-After: 30` header  

### Contract 5.3: Challenge Decision - CAPTCHA

**GIVEN**: ProxyDecision::Challenge { challenge_type: Captcha }  
**WHEN**: Decision applied  
**THEN**: Returns HTTP 403 with CAPTCHA page  

### Contract 5.4: Block Decision - Low Reputation

**GIVEN**: ProxyDecision::Block { reason: LowReputation { score: 5 } }  
**WHEN**: Decision applied  
**THEN**: Returns HTTP 403 with block page  

### Contract 5.5: Block Decision - Blacklisted

**GIVEN**: ProxyDecision::Block { reason: Blacklisted }  
**WHEN**: Decision applied  
**THEN**: Returns HTTP 403, logged with reason "Blacklisted"  

---

## 6. Integration Contracts (End-to-End)

### Contract 6.1: Full Request Pipeline - Legitimate

**GIVEN**: Request from 192.0.2.1 with normal User-Agent, score=100  
**WHEN**: Request processed through full pipeline  
**THEN**: Forwarded to backend with X-WebSec-Score header  

### Contract 6.2: Full Request Pipeline - Malicious

**GIVEN**: Request with `User-Agent: sqlmap/1.7`, `path: /?id=' OR '1'='1`  
**WHEN**: Request processed  
**THEN**: Blocked (score drops below threshold due to multiple signals)  

### Contract 6.3: Transparent Forwarding

**GIVEN**: Legitimate request with custom headers (X-Custom-Header: value)  
**WHEN**: Request forwarded to backend  
**THEN**: All original headers preserved, backend sees exact request  

### Contract 6.4: WebSocket Upgrade

**GIVEN**: Request with `Upgrade: websocket` header  
**WHEN**: Request processed with score ≥ 70  
**THEN**: Connection upgraded transparently to backend  

---

## 7. Performance Contracts

### Contract 7.1: Latency - L1 Cache Hit

**GIVEN**: IpProfile in L1 memory cache  
**WHEN**: get_profile() called  
**THEN**: Completes in < 0.1ms (p95)  

### Contract 7.2: Latency - L2 Redis Hit

**GIVEN**: IpProfile in Redis (L1 miss)  
**WHEN**: get_profile() called  
**THEN**: Completes in < 2ms (p95)  

### Contract 7.3: Latency - Full Request Processing

**GIVEN**: Legitimate request, all detectors enabled  
**WHEN**: Request processed through pipeline  
**THEN**: Total latency < 5ms (p95)  

### Contract 7.4: Throughput - Concurrent Requests

**GIVEN**: 10,000 concurrent requests on 4 CPU cores  
**WHEN**: Load test executed  
**THEN**: Handles > 10,000 req/s without errors  

### Contract 7.5: Memory - Profile Storage

**GIVEN**: 100,000 tracked IP profiles  
**WHEN**: All profiles loaded in L1 cache  
**THEN**: Memory usage < 512 MB  

---

## Contract Test Implementation Guide

### Example Test Structure

```rust
// tests/contract/reputation_tests.rs

use websec::reputation::{ReputationScore, ReputationConfig};
use websec::models::{IpProfile, Signal};

#[test]
fn contract_2_1_score_calculation_formula() {
    // Contract 2.1: Score calculation formula
    
    // GIVEN
    let config = ReputationConfig::default();
    let engine = ReputationScore::new(config);
    let mut profile = IpProfile::new("192.0.2.1".parse().unwrap(), 100);
    
    profile.add_signal(Signal::SqlInjectionAttempt {
        payload: "' OR '1'='1".to_string(),
        confidence: 0.95,
        weight: 35,
    });
    profile.add_signal(Signal::Flooding {
        requests_per_sec: 150.0,
        weight: 15,
    });
    
    // WHEN
    let score = engine.calculate_score(&profile);
    
    // THEN
    assert_eq!(score, 50); // 100 - 35 - 15 = 50
}

#[test]
fn contract_2_2_exponential_decay() {
    // Contract 2.2: Exponential decay (24h half-life)
    
    // GIVEN
    let config = ReputationConfig {
        decay_half_life_hours: 24.0,
        ..Default::default()
    };
    let engine = ReputationScore::new(config);
    
    let signal_time = Utc::now() - chrono::Duration::hours(24);
    let original_weight = 40;
    
    // WHEN
    let decayed = engine.apply_decay(original_weight, signal_time);
    
    // THEN
    assert_eq!(decayed, 20); // 40 * 0.5 = 20
}
```

---

## Contract Compliance Checklist

Before marking implementation complete, verify:

- [ ] All detector contracts implemented (12 detectors × 2-3 contracts each)
- [ ] All reputation engine contracts passing (9 contracts)
- [ ] All rate limiter contracts passing (6 contracts)
- [ ] All storage repository contracts passing (13 contracts)
- [ ] All proxy decision contracts passing (5 contracts)
- [ ] Integration contracts passing (4 contracts)
- [ ] Performance contracts validated (5 contracts)
- [ ] Test coverage > 80% on contract-related code
- [ ] All contract tests execute in < 5 seconds total

**Total Contracts**: 60+ behavioral contracts defined

---

**Contract Version**: 1.0.0  
**Last Updated**: 2025-11-18  
**Status**: Complete - Ready for TDD implementation
