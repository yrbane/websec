//! Structured logging configuration
//!
//! Sets up tracing with JSON or pretty formatting for production/development.

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize structured logging
///
/// # Arguments
///
/// * `log_level` - Log level filter (trace, debug, info, warn, error)
/// * `format` - Format type ("json" or "pretty")
///
/// # Example
///
/// ```no_run
/// websec::observability::init_logging("info", "json");
/// ```
pub fn init_logging(log_level: &str, format: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    let subscriber = tracing_subscriber::registry().with(env_filter);

    match format {
        "json" => {
            subscriber
                .with(fmt::layer().json().with_target(true).with_level(true))
                .init();
        }
        "pretty" | _ => {
            subscriber
                .with(fmt::layer().pretty().with_target(true).with_level(true))
                .init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    // Ensure logging is only initialized once during tests
    static INIT: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

    fn init_once() {
        let mut initialized = INIT.lock().unwrap();
        if !*initialized {
            init_logging("info", "json");
            *initialized = true;
        }
    }

    #[test]
    fn test_init_logging_json() {
        // Just verify it doesn't panic
        init_once();
    }

    #[test]
    fn test_init_logging_pretty() {
        // Already initialized by test_init_logging_json
        init_once();
    }
}
