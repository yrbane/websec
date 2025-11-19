//! Retry logic for backend requests
//!
//! Exponential backoff retry mechanism for transient backend failures.

use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

/// Retry policy configuration
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial retry delay
    pub initial_delay: Duration,
    /// Maximum retry delay (cap for exponential backoff)
    pub max_delay: Duration,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// Create a new retry policy
    #[must_use]
    pub fn new(
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
        backoff_multiplier: f64,
    ) -> Self {
        Self {
            max_retries,
            initial_delay,
            max_delay,
            backoff_multiplier,
        }
    }

    /// No retry policy (fail immediately)
    #[must_use]
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            initial_delay: Duration::from_secs(0),
            max_delay: Duration::from_secs(0),
            backoff_multiplier: 1.0,
        }
    }

    /// Calculate delay for a given attempt using exponential backoff
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_secs(0);
        }

        let delay_ms = self.initial_delay.as_millis() as f64
            * self.backoff_multiplier.powi(attempt as i32 - 1);

        let delay = Duration::from_millis(delay_ms as u64);
        delay.min(self.max_delay)
    }

    /// Retry an async operation with exponential backoff
    ///
    /// # Arguments
    ///
    /// * `operation` - Async closure that returns `Result<T, E>`
    ///
    /// # Returns
    ///
    /// The result of the operation if successful within retry attempts
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use websec::proxy::retry::RetryPolicy;
    ///
    /// # async fn example() -> Result<String, Box<dyn std::error::Error>> {
    /// let policy = RetryPolicy::default();
    ///
    /// let result = policy.retry("fetch_data", || async {
    ///     // Your async operation here
    ///     Ok("data".to_string())
    /// }).await?;
    /// # Ok(result)
    /// # }
    /// ```
    pub async fn retry<F, Fut, T, E>(&self, operation_name: &str, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let mut attempt = 0;

        loop {
            attempt += 1;

            match operation().await {
                Ok(result) => {
                    if attempt > 1 {
                        info!(
                            operation = operation_name,
                            attempt, "Operation succeeded after retry"
                        );
                    }
                    return Ok(result);
                }
                Err(err) => {
                    if attempt > self.max_retries {
                        warn!(
                            operation = operation_name,
                            attempt,
                            error = %err,
                            "Operation failed after max retries"
                        );
                        return Err(err);
                    }

                    let delay = self.delay_for_attempt(attempt);
                    warn!(
                        operation = operation_name,
                        attempt,
                        error = %err,
                        retry_delay_ms = delay.as_millis(),
                        "Operation failed, retrying..."
                    );

                    sleep(delay).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_default_policy() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.initial_delay, Duration::from_millis(100));
    }

    #[test]
    fn test_no_retry_policy() {
        let policy = RetryPolicy::no_retry();
        assert_eq!(policy.max_retries, 0);
    }

    #[test]
    fn test_delay_calculation() {
        let policy = RetryPolicy::default();

        assert_eq!(policy.delay_for_attempt(0), Duration::from_secs(0));
        assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(100));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(200));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_millis(400));
    }

    #[test]
    fn test_delay_cap() {
        let policy = RetryPolicy::new(5, Duration::from_secs(1), Duration::from_secs(3), 2.0);

        // 1s, 2s, 4s (capped), 8s (capped)
        assert_eq!(policy.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_secs(3)); // capped
        assert_eq!(policy.delay_for_attempt(4), Duration::from_secs(3)); // capped
    }

    #[tokio::test]
    async fn test_retry_succeeds_first_attempt() {
        let policy = RetryPolicy::default();
        let counter = Arc::new(AtomicU32::new(0));

        let result = policy
            .retry("test_op", || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, String>("success")
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        let policy = RetryPolicy::new(3, Duration::from_millis(10), Duration::from_millis(50), 2.0);
        let counter = Arc::new(AtomicU32::new(0));

        let result = policy
            .retry("test_op", || {
                let counter = Arc::clone(&counter);
                async move {
                    let attempt = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    if attempt < 3 {
                        Err("temporary failure".to_string())
                    } else {
                        Ok::<_, String>("success")
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_fails_after_max_attempts() {
        let policy = RetryPolicy::new(2, Duration::from_millis(10), Duration::from_millis(50), 2.0);
        let counter = Arc::new(AtomicU32::new(0));

        let result = policy
            .retry("test_op", || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err::<String, _>("permanent failure")
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "permanent failure");
        assert_eq!(counter.load(Ordering::SeqCst), 3); // 1 initial + 2 retries
    }

    #[tokio::test]
    async fn test_no_retry_policy_fails_immediately() {
        let policy = RetryPolicy::no_retry();
        let counter = Arc::new(AtomicU32::new(0));

        let result = policy
            .retry("test_op", || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Err::<String, _>("failure")
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1); // Only 1 attempt
    }
}
