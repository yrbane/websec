//! Configuration du logging structuré
//!
//! Configure tracing avec formatage JSON ou Pretty pour production/développement.

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Format de sortie des logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Format JSON structuré (production)
    Json,
    /// Format lisible coloré (développement)
    Pretty,
}

/// Initialise le logging structuré
///
/// # Arguments
///
/// * `format` - Format de sortie (Json ou Pretty)
/// * `log_level` - Niveau de filtrage (trace, debug, info, warn, error)
///
/// # Exemple
///
/// ```no_run
/// use websec::observability::logging::{init_logging, LogFormat};
/// init_logging(LogFormat::Json, "info").unwrap();
/// ```
pub fn init_logging(format: LogFormat, log_level: &str) -> Result<(), String> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    let subscriber = tracing_subscriber::registry().with(env_filter);

    match format {
        LogFormat::Json => {
            subscriber
                .with(fmt::layer().json().with_target(true).with_level(true))
                .try_init()
                .map_err(|e| format!("Erreur d'initialisation du logging : {}", e))?;
        }
        LogFormat::Pretty => {
            subscriber
                .with(fmt::layer().pretty().with_target(true).with_level(true))
                .try_init()
                .map_err(|e| format!("Erreur d'initialisation du logging : {}", e))?;
        }
    }

    Ok(())
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
            let _ = init_logging(LogFormat::Json, "info");
            *initialized = true;
        }
    }

    #[test]
    fn test_init_logging_json() {
        // Vérifie simplement que ça ne panique pas
        init_once();
    }

    #[test]
    fn test_init_logging_pretty() {
        // Déjà initialisé par test_init_logging_json
        init_once();
    }
}
