//! IP access control lists (blacklist/whitelist)
//!
//! Provides immediate blocking (blacklist) and trusted bypass (whitelist) functionality.
//!
//! # Priority Order
//!
//! 1. **Blacklist** (highest priority): Block immediately, score = 0
//! 2. **Whitelist**: Allow with perfect score = 100, bypass all detectors
//! 3. **Normal scoring**: Apply reputation-based decision logic
//!
//! # Thread Safety
//!
//! Both `Blacklist` and `Whitelist` are thread-safe and can be shared across
//! multiple threads via `Arc`.

pub mod blacklist;
pub mod whitelist;

pub use blacklist::Blacklist;
pub use whitelist::Whitelist;
