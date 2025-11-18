//! Configuration loading and validation
//!
//! Loads settings from TOML configuration files and environment variables.
//! Validates all parameters and provides sensible defaults.

pub mod loader;
pub mod settings;

pub use loader::{load_from_file, load_with_env};
pub use settings::Settings;
