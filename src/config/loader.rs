//! Configuration loader from TOML files and environment variables

use super::settings::Settings;
use crate::{Error, Result};
use std::path::Path;

/// Load configuration from a TOML file
///
/// # Arguments
///
/// * `path` - Path to the TOML configuration file
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The TOML format is invalid
/// - Required fields are missing
/// - Values are out of valid ranges
pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Settings> {
    let contents = std::fs::read_to_string(path.as_ref())
        .map_err(|e| Error::Config(format!("Failed to read config file: {e}")))?;

    toml::from_str(&contents).map_err(|e| Error::Config(format!("Failed to parse TOML: {e}")))
}

/// Load configuration with environment variable overrides
///
/// Environment variables follow the pattern: `WEBSEC_<SECTION>_<KEY>`
/// Example: `WEBSEC_SERVER_LISTEN=0.0.0.0:8080`
///
/// # Arguments
///
/// * `path` - Path to the base TOML configuration file
///
/// # Errors
///
/// Returns an error if the base configuration cannot be loaded or
/// environment variables contain invalid values.
pub fn load_with_env<P: AsRef<Path>>(path: P) -> Result<Settings> {
    let mut settings = load_from_file(path)?;

    // Override with environment variables if present
    if let Ok(listen) = std::env::var("WEBSEC_SERVER_LISTEN") {
        settings.server.listen = listen;
    }
    if let Ok(backend) = std::env::var("WEBSEC_SERVER_BACKEND") {
        settings.server.backend = backend;
    }
    if let Ok(redis_url) = std::env::var("WEBSEC_STORAGE_REDIS_URL") {
        settings.storage.redis_url = Some(redis_url);
    }
    if let Ok(log_level) = std::env::var("WEBSEC_LOGGING_LEVEL") {
        settings.logging.level = log_level;
    }

    validate(&settings)?;
    Ok(settings)
}

/// Validate configuration values
///
/// Checks that all configuration values are within acceptable ranges
/// and that dependencies are satisfied.
fn validate(settings: &Settings) -> Result<()> {
    // Validate reputation thresholds are properly ordered
    if settings.reputation.threshold_allow <= settings.reputation.threshold_ratelimit {
        return Err(Error::Config(
            "threshold_allow must be > threshold_ratelimit".to_string(),
        ));
    }
    if settings.reputation.threshold_ratelimit <= settings.reputation.threshold_challenge {
        return Err(Error::Config(
            "threshold_ratelimit must be > threshold_challenge".to_string(),
        ));
    }
    if settings.reputation.threshold_challenge <= settings.reputation.threshold_block {
        return Err(Error::Config(
            "threshold_challenge must be > threshold_block".to_string(),
        ));
    }

    // Validate base score is within range
    if settings.reputation.base_score > 100 {
        return Err(Error::Config("base_score must be <= 100".to_string()));
    }

    // Validate decay half-life is positive
    if settings.reputation.decay_half_life_hours <= 0.0 {
        return Err(Error::Config(
            "decay_half_life_hours must be > 0".to_string(),
        ));
    }

    // Validate storage type
    match settings.storage.storage_type.as_str() {
        "redis" => {
            if settings.storage.redis_url.is_none() {
                return Err(Error::Config(
                    "redis_url is required when storage type is 'redis'".to_string(),
                ));
            }
        }
        "memory" => {}
        other => {
            return Err(Error::Config(format!(
                "Invalid storage type '{other}'. Must be 'redis' or 'memory'"
            )));
        }
    }

    // Validate geolocation database path if enabled
    if settings.geolocation.enabled {
        match &settings.geolocation.database {
            None => {
                return Err(Error::Config(
                    "geolocation.database path is required when geolocation is enabled".to_string(),
                ));
            }
            Some(db_path) => {
                let path = std::path::Path::new(db_path);
                if !path.exists() {
                    return Err(Error::Config(format!(
                        "GeoIP database file not found: '{db_path}'. \
                         Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data \
                         or disable geolocation in config."
                    )));
                }
                if !path.is_file() {
                    return Err(Error::Config(format!(
                        "GeoIP database path '{db_path}' is not a file"
                    )));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_example_config() {
        let result = load_from_file("config/websec.toml.example");
        assert!(result.is_ok(), "Example config should be valid");

        let settings = result.unwrap();
        assert_eq!(settings.server.listen, "0.0.0.0:8080");
        assert_eq!(settings.reputation.base_score, 100);
        assert_eq!(settings.storage.storage_type, "redis");
    }

    #[test]
    fn test_validate_threshold_ordering() {
        let mut settings = load_from_file("config/websec.toml.example").unwrap();
        // Disable geolocation for this test (DB file doesn't exist in test env)
        settings.geolocation.enabled = false;

        // Invalid: allow <= ratelimit
        settings.reputation.threshold_allow = 40;
        settings.reputation.threshold_ratelimit = 40;
        assert!(validate(&settings).is_err());

        // Invalid: ratelimit <= challenge
        settings.reputation.threshold_allow = 70;
        settings.reputation.threshold_ratelimit = 20;
        settings.reputation.threshold_challenge = 20;
        assert!(validate(&settings).is_err());

        // Valid ordering
        settings.reputation.threshold_allow = 70;
        settings.reputation.threshold_ratelimit = 40;
        settings.reputation.threshold_challenge = 20;
        settings.reputation.threshold_block = 0;
        assert!(validate(&settings).is_ok());
    }

    #[test]
    fn test_validate_storage_type() {
        let mut settings = load_from_file("config/websec.toml.example").unwrap();
        // Disable geolocation for this test (DB file doesn't exist in test env)
        settings.geolocation.enabled = false;

        settings.storage.storage_type = "invalid".to_string();
        assert!(validate(&settings).is_err());

        settings.storage.storage_type = "memory".to_string();
        assert!(validate(&settings).is_ok());
    }

    #[test]
    fn test_validate_geoip_database() {
        let mut settings = load_from_file("config/websec.toml.example").unwrap();

        // Enabled with non-existent database should fail
        settings.geolocation.enabled = true;
        settings.geolocation.database = Some("/nonexistent/path.mmdb".to_string());
        assert!(validate(&settings).is_err());

        // Disabled with non-existent database should pass
        settings.geolocation.enabled = false;
        assert!(validate(&settings).is_ok());

        // Enabled with None database should fail
        settings.geolocation.enabled = true;
        settings.geolocation.database = None;
        assert!(validate(&settings).is_err());
    }
}
