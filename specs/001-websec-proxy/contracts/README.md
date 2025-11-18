# Contract Test Specifications

This directory contains behavioral contract specifications for all major components of WebSec. Contract tests verify that implementations adhere to their documented behavior.

## Contract Files

1. **detector-contracts.md** - Contracts for all 12 threat detectors
2. **reputation-engine-contracts.md** - Contracts for reputation score calculation
3. **ratelimiter-contracts.md** - Contracts for rate limiting behavior
4. **storage-contracts.md** - Contracts for repository implementations

## Usage

Each contract file defines:
- **Given** (preconditions)
- **When** (action)
- **Then** (expected outcome)

These contracts are implemented as Rust tests in `tests/contract/`.

## Example

```rust
// From detector-contracts.md:
// GIVEN: Request with User-Agent "sqlmap/1.7"
// WHEN: BotDetector.analyze() is called
// THEN: Returns Signal::SuspiciousUserAgent with weight >= 15

#[tokio::test]
async fn contract_bot_detector_sqlmap_user_agent() {
    let detector = BotDetector::new();
    let request = HttpRequest::with_user_agent("sqlmap/1.7");
    let profile = IpProfile::new_default();
    
    let signals = detector.analyze(&request, &profile).await;
    
    assert_eq!(signals.len(), 1);
    assert!(matches!(signals[0], Signal::SuspiciousUserAgent { .. }));
    assert!(signals[0].weight() >= 15);
}
```
