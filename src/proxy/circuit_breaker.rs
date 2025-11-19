//! Circuit Breaker pattern for backend protection
//!
//! Prevents cascading failures by temporarily stopping requests to failing backends.
//!
//! # States
//!
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Backend is failing, reject requests immediately
//! - **HalfOpen**: Testing if backend recovered, allow limited requests
//!
//! # State Transitions
//!
//! ```text
//! Closed ──(failures >= threshold)──> Open
//!    ▲                                  │
//!    │                                  │
//!    │                       (timeout expires)
//!    │                                  │
//!    │                                  ▼
//!    └──(success)──── HalfOpen ──(failure)──┐
//!                         │                  │
//!                         └──────────────────┘
//! ```

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
    /// Normal operation
    Closed = 0,
    /// Backend failing, reject requests
    Open = 1,
    /// Testing recovery
    HalfOpen = 2,
}

impl From<u8> for CircuitState {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Closed,
            1 => Self::Open,
            2 => Self::HalfOpen,
            _ => Self::Closed,
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to open circuit
    pub failure_threshold: u64,
    /// Number of consecutive successes to close circuit from half-open
    pub success_threshold: u64,
    /// Timeout before transitioning from open to half-open
    pub timeout: Duration,
    /// Maximum number of requests in half-open state
    pub half_open_max_requests: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            half_open_max_requests: 3,
        }
    }
}

/// Circuit breaker for protecting backends
pub struct CircuitBreaker {
    /// Current circuit state
    state: Arc<AtomicU8>,
    /// Consecutive failure counter
    consecutive_failures: Arc<AtomicU64>,
    /// Consecutive success counter
    consecutive_successes: Arc<AtomicU64>,
    /// Timestamp when circuit opened
    opened_at: Arc<RwLock<Option<Instant>>>,
    /// Configuration
    config: CircuitBreakerConfig,
    /// Backend name for logging
    name: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    ///
    /// # Arguments
    ///
    /// * `name` - Backend name for logging
    /// * `config` - Circuit breaker configuration
    #[must_use]
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            state: Arc::new(AtomicU8::new(CircuitState::Closed as u8)),
            consecutive_failures: Arc::new(AtomicU64::new(0)),
            consecutive_successes: Arc::new(AtomicU64::new(0)),
            opened_at: Arc::new(RwLock::new(None)),
            config,
            name: name.into(),
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults(name: impl Into<String>) -> Self {
        Self::new(name, CircuitBreakerConfig::default())
    }

    /// Get current circuit state
    #[must_use]
    pub fn state(&self) -> CircuitState {
        CircuitState::from(self.state.load(Ordering::SeqCst))
    }

    /// Check if circuit allows request
    ///
    /// Returns `Ok(())` if request is allowed, `Err(())` if circuit is open
    pub async fn call_allowed(&self) -> Result<(), ()> {
        let current_state = self.state();

        match current_state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if timeout expired
                if self.should_attempt_reset().await {
                    self.transition_to_half_open().await;
                    Ok(())
                } else {
                    Err(())
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state
                let successes = self.consecutive_successes.load(Ordering::SeqCst);
                if successes < self.config.half_open_max_requests {
                    Ok(())
                } else {
                    Err(())
                }
            }
        }
    }

    /// Record a successful request
    pub async fn record_success(&self) {
        let current_state = self.state();

        match current_state {
            CircuitState::Closed => {
                // Reset failure counter on success
                self.consecutive_failures.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let successes = self.consecutive_successes.fetch_add(1, Ordering::SeqCst) + 1;

                if successes >= self.config.success_threshold {
                    self.transition_to_closed().await;
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but reset if it does
                warn!(backend = %self.name, "Received success in Open state");
            }
        }
    }

    /// Record a failed request
    pub async fn record_failure(&self) {
        let current_state = self.state();

        match current_state {
            CircuitState::Closed => {
                let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;

                if failures >= self.config.failure_threshold {
                    self.transition_to_open().await;
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open
                self.transition_to_open().await;
            }
            CircuitState::Open => {
                // Already open, ignore
            }
        }
    }

    /// Execute an operation with circuit breaker protection
    ///
    /// # Arguments
    ///
    /// * `operation` - Async closure that returns `Result<T, E>`
    ///
    /// # Returns
    ///
    /// The result of the operation if circuit is closed, or circuit breaker error
    pub async fn execute<F, Fut, T, E>(&self, operation: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        // Check if call is allowed
        self.call_allowed()
            .await
            .map_err(|_| CircuitBreakerError::CircuitOpen)?;

        // Execute operation
        match operation().await {
            Ok(result) => {
                self.record_success().await;
                Ok(result)
            }
            Err(err) => {
                self.record_failure().await;
                Err(CircuitBreakerError::OperationFailed(err))
            }
        }
    }

    /// Check if circuit should attempt reset (open -> half-open)
    async fn should_attempt_reset(&self) -> bool {
        if let Some(opened_at) = *self.opened_at.read().await {
            opened_at.elapsed() >= self.config.timeout
        } else {
            false
        }
    }

    /// Transition to closed state
    async fn transition_to_closed(&self) {
        info!(backend = %self.name, "Circuit breaker: OPEN/HALF_OPEN -> CLOSED");
        self.state.store(CircuitState::Closed as u8, Ordering::SeqCst);
        self.consecutive_failures.store(0, Ordering::SeqCst);
        self.consecutive_successes.store(0, Ordering::SeqCst);
        *self.opened_at.write().await = None;
    }

    /// Transition to open state
    async fn transition_to_open(&self) {
        warn!(
            backend = %self.name,
            failures = self.consecutive_failures.load(Ordering::SeqCst),
            "Circuit breaker: CLOSED/HALF_OPEN -> OPEN"
        );
        self.state.store(CircuitState::Open as u8, Ordering::SeqCst);
        self.consecutive_successes.store(0, Ordering::SeqCst);
        *self.opened_at.write().await = Some(Instant::now());
    }

    /// Transition to half-open state
    async fn transition_to_half_open(&self) {
        info!(backend = %self.name, "Circuit breaker: OPEN -> HALF_OPEN (testing recovery)");
        self.state
            .store(CircuitState::HalfOpen as u8, Ordering::SeqCst);
        self.consecutive_successes.store(0, Ordering::SeqCst);
    }

    /// Get statistics
    #[must_use]
    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            state: self.state(),
            consecutive_failures: self.consecutive_failures.load(Ordering::SeqCst),
            consecutive_successes: self.consecutive_successes.load(Ordering::SeqCst),
        }
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    /// Current circuit state
    pub state: CircuitState,
    /// Number of consecutive failures
    pub consecutive_failures: u64,
    /// Number of consecutive successes
    pub consecutive_successes: u64,
}

/// Circuit breaker error
#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open, request rejected
    #[error("Circuit breaker is open")]
    CircuitOpen,
    /// Operation failed with error
    #[error("Operation failed: {0}")]
    OperationFailed(E),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_starts_closed() {
        let cb = CircuitBreaker::with_defaults("test");
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.call_allowed().await.is_ok());
    }

    #[tokio::test]
    async fn test_circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Record failures
        cb.record_failure().await;
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state(), CircuitState::Open);

        // Now calls should be rejected
        assert!(cb.call_allowed().await.is_err());
    }

    #[tokio::test]
    async fn test_circuit_resets_on_success_in_closed() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        cb.record_failure().await;
        cb.record_failure().await;

        // Success resets counter
        cb.record_success().await;
        assert_eq!(cb.consecutive_failures.load(Ordering::SeqCst), 0);

        // Need 3 more failures to open
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_half_open_to_closed_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Open circuit
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Should transition to half-open
        assert!(cb.call_allowed().await.is_ok());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record successes
        cb.record_success().await;
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success().await;
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_half_open_to_open_on_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Open circuit
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Transition to half-open
        assert!(cb.call_allowed().await.is_ok());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Any failure goes back to open
        cb.record_failure().await;
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn test_execute_success() {
        let cb = CircuitBreaker::with_defaults("test");

        let result = cb
            .execute(|| async { Ok::<_, String>("success") })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    #[tokio::test]
    async fn test_execute_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // First failure
        let result = cb
            .execute(|| async { Err::<String, _>("error") })
            .await;
        assert!(matches!(
            result,
            Err(CircuitBreakerError::OperationFailed(_))
        ));

        // Second failure should open circuit
        let result = cb
            .execute(|| async { Err::<String, _>("error") })
            .await;
        assert!(matches!(
            result,
            Err(CircuitBreakerError::OperationFailed(_))
        ));
        assert_eq!(cb.state(), CircuitState::Open);

        // Third attempt should fail immediately (circuit open)
        let result = cb.execute(|| async { Ok::<_, String>("won't execute") }).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
    }

    #[tokio::test]
    async fn test_stats() {
        let cb = CircuitBreaker::with_defaults("test");

        cb.record_failure().await;
        cb.record_failure().await;

        let stats = cb.stats();
        assert_eq!(stats.state, CircuitState::Closed);
        assert_eq!(stats.consecutive_failures, 2);
        assert_eq!(stats.consecutive_successes, 0);
    }
}
