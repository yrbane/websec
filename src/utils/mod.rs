//! Utility functions
//!
//! - IP address parsing and validation
//! - Regex pattern compilation (`lazy_static`)
//! - Time utilities (decay calculations)
//! - HTTP header parsing helpers

pub mod parser;

pub use parser::{
    contains_command_injection, contains_path_traversal, contains_sql_injection, contains_xss,
    extract_browser_family, extract_xff_ip, is_bot_user_agent, is_empty_user_agent,
    normalize_method, parse_query_string,
};
