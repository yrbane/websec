//! IP reputation scoring engine
//!
//! Calculates dynamic reputation scores (0-100) using:
//! - Base score: 100 (trust by default)
//! - Signal accumulation: Score = max(0, min(100, base - Σ(signal_weight)))
//! - Exponential decay: weight(t) = weight₀ × 2^(-t/half_life)
//! - Correlation bonus: +10 penalty for multiple distinct signal families
//!
//! Decision thresholds:
//! - ≥70: ALLOW
//! - 40-69: RATE_LIMIT
//! - 20-39: CHALLENGE
//! - <20: BLOCK

pub mod profile;
pub mod score;
pub mod signal;

pub use profile::ReputationProfile;
pub use score::{
    calculate_score, determine_decision, recalculate_and_update, ProxyDecision, ScoringThresholds,
};
pub use signal::{Signal, SignalFamily, SignalVariant};
