//! CLI administration interface
//!
//! Provides command-line tools for:
//! - Server execution (normal and dry-run mode)
//! - Configuration validation and display
//! - Storage backend health checks
//! - Live statistics monitoring

pub mod commands;
/// Docker helper commands (build/test)
pub mod docker;
/// E2E test harness and dev backend server
pub mod e2e;
/// Blacklist/whitelist management helpers
pub mod lists;
pub mod setup;

pub use commands::{check_storage, run_server, show_config, show_stats};
pub use setup::{run_setup, run_setup_noninteractive, run_restore};
