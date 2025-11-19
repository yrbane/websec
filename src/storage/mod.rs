//! Multi-tier storage with Repository pattern
//!
//! Three-tier architecture:
//! - **L1**: LRU in-memory cache (10k IPs, <1ms latency) - `CachedRepository`
//! - **L2**: Redis centralized store (multi-instance coordination) - `RedisRepository`
//! - **L3**: In-memory fallback (single-instance, testing) - `InMemoryRepository`
//!
//! Repository trait abstraction allows testing with in-memory implementation.
//!
//! # Usage
//!
//! ```no_run
//! use websec::storage::{RedisRepository, CachedRepository};
//! use std::sync::Arc;
//!
//! # async fn example() -> websec::Result<()> {
//! // L2: Redis
//! let redis = Arc::new(RedisRepository::new("redis://localhost:6379").await?);
//!
//! // L1 + L2: Cached Redis
//! let cached = CachedRepository::new(redis, 10000);
//! # Ok(())
//! # }
//! ```

pub mod cached;
pub mod memory;
pub mod redis;
pub mod repository;

pub use cached::{CachedRepository, CacheStats};
pub use memory::InMemoryRepository;
pub use redis::RedisRepository;
pub use repository::ReputationRepository;
