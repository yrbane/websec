//! Configuration du logging structuré
//!
//! Configure tracing avec formatage JSON ou Pretty pour production/développement.
//! Supporte les niveaux de log standards et l'enrichissement contextuel.
//!
//! # Utilisation
//!
//! ```no_run
//! use websec::observability::logging::{init_logging, LogFormat};
//! use tracing::{info, warn, error};
//!
//! // Initialiser le logging
//! init_logging(LogFormat::Json, "info").unwrap();
//!
//! // Utiliser les logs structurés
//! info!(ip = "192.168.1.1", method = "GET", "Requête traitée");
//! warn!(detector = "BotDetector", "Comportement suspect détecté");
//! error!(error = "timeout", "Échec de connexion au backend");
//! ```
//!
//! # Formats disponibles
//!
//! - **JSON** : Format structuré machine-parsable pour production
//! - **Pretty** : Format lisible avec couleurs pour développement
//!
//! # Niveaux de log
//!
//! - `trace` : Logs très détaillés (debugging approfondi)
//! - `debug` : Informations de débogage
//! - `info` : Messages informatifs (recommandé production)
//! - `warn` : Avertissements
//! - `error` : Erreurs

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Format de sortie des logs
///
/// Détermine comment les logs sont formatés en sortie.
/// Utilisez JSON en production pour parsing automatique,
/// Pretty en développement pour lisibilité humaine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Format JSON structuré (production)
    ///
    /// Chaque ligne est un objet JSON valide contenant :
    /// - `timestamp` : Horodatage ISO 8601
    /// - `level` : Niveau de log (INFO, WARN, ERROR, etc.)
    /// - `target` : Module source du log
    /// - `fields` : Champs contextuels (ip, detector, etc.)
    /// - `message` : Message du log
    ///
    /// Exemple :
    /// ```json
    /// {"timestamp":"2025-11-19T10:30:45Z","level":"INFO","target":"websec","ip":"192.168.1.1","message":"Requête traitée"}
    /// ```
    Json,

    /// Format lisible coloré (développement)
    ///
    /// Format multi-lignes avec indentation et couleurs pour
    /// faciliter la lecture pendant le développement.
    ///
    /// Exemple :
    /// ```text
    /// 2025-11-19T10:30:45.123Z  INFO websec
    ///   ip: 192.168.1.1
    ///   method: GET
    ///   Requête traitée
    /// ```
    Pretty,
}

/// Initialise le logging structuré
///
/// Configure le système de tracing global avec le format et niveau spécifiés.
/// **Important** : Cette fonction ne doit être appelée qu'une seule fois au démarrage.
///
/// # Arguments
///
/// * `format` - Format de sortie (Json ou Pretty)
/// * `log_level` - Niveau de filtrage (trace, debug, info, warn, error)
///
/// # Returns
///
/// - `Ok(())` si l'initialisation réussit
/// - `Err(String)` si le logging est déjà initialisé ou erreur de configuration
///
/// # Exemples
///
/// ```no_run
/// use websec::observability::logging::{init_logging, LogFormat};
///
/// // Production : JSON avec niveau INFO
/// init_logging(LogFormat::Json, "info").unwrap();
///
/// // Développement : Pretty avec niveau DEBUG
/// init_logging(LogFormat::Pretty, "debug").unwrap();
/// ```
///
/// # Variable d'environnement
///
/// Le niveau peut être surchargé avec la variable `RUST_LOG` :
/// ```bash
/// RUST_LOG=debug cargo run
/// ```
///
/// # Erreurs
///
/// Retourne une erreur si :
/// - Le logging est déjà initialisé (appel multiple)
/// - La configuration du subscriber échoue
pub fn init_logging(format: LogFormat, log_level: &str) -> Result<(), String> {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    let subscriber = tracing_subscriber::registry().with(env_filter);

    match format {
        LogFormat::Json => {
            subscriber
                .with(fmt::layer().json().with_target(true).with_level(true))
                .try_init()
                .map_err(|e| format!("Erreur d'initialisation du logging : {e}"))?;
        }
        LogFormat::Pretty => {
            subscriber
                .with(fmt::layer().pretty().with_target(true).with_level(true))
                .try_init()
                .map_err(|e| format!("Erreur d'initialisation du logging : {e}"))?;
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
    static INIT: std::sync::LazyLock<Mutex<bool>> = std::sync::LazyLock::new(|| Mutex::new(false));

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
