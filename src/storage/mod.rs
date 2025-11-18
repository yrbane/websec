//! Multi-tier storage with Repository pattern
//!
//! Three-tier architecture:
//! - L1: LRU in-memory cache (10k IPs, <1ms latency)
//! - L2: Redis centralized store (multi-instance coordination)
//! - L3: File-based fallback (degraded mode when Redis unavailable)
//!
//! Repository trait abstraction allows testing with in-memory implementation.

pub mod memory;
pub mod repository;

pub use memory::InMemoryRepository;
pub use repository::ReputationRepository;
