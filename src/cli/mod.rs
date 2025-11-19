//! CLI administration interface
//!
//! Provides command-line tools for:
//! - Server execution (normal and dry-run mode)
//! - Configuration validation and display
//! - Storage backend health checks
//! - Live statistics monitoring

pub mod commands;

pub use commands::{check_storage, run_server, show_config, show_stats};
