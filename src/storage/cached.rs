//! Cached repository with L1 LRU cache
//!
//! Two-tier storage architecture:
//! - **L1**: LRU in-memory cache (fast, < 1ms latency)
//! - **L2**: Underlying repository (Redis, `InMemory`, etc.)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐
//! │   Request   │
//! └──────┬──────┘
//!        │
//!        ▼
//! ┌─────────────────┐
//! │  L1 LRU Cache   │ <── 10k entries, <1ms
//! │  (DashMap+LRU)  │
//! └────────┬────────┘
//!          │ Miss
//!          ▼
//! ┌─────────────────┐
//! │  L2 Repository  │ <── Redis, InMemory, etc.
//! │   (Persistent)  │
//! └─────────────────┘
//! ```

use super::repository::ReputationRepository;
use crate::reputation::ReputationProfile;
use crate::Result;
use async_trait::async_trait;
use lru::LruCache;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Cached repository with L1 LRU cache
///
/// Wraps any repository implementation with a fast LRU cache layer.
/// Cache hits are served in < 1ms, cache misses fallback to L2.
///
/// # Cache Policy
///
/// - **Read**: Check L1 → Miss? Check L2 → Update L1
/// - **Write**: Update L2 → Update L1
/// - **Delete**: Delete from L2 → Invalidate L1
///
/// # Thread Safety
///
/// Uses `Mutex<LruCache>` for safe concurrent access.
/// LRU eviction is automatic when cache is full.
pub struct CachedRepository<R: ReputationRepository> {
    /// L1 cache (LRU)
    cache: Arc<Mutex<LruCache<IpAddr, ReputationProfile>>>,
    /// L2 underlying repository
    repository: Arc<R>,
}

impl<R: ReputationRepository> CachedRepository<R> {
    /// Create a new cached repository
    ///
    /// # Arguments
    ///
    /// * `repository` - Underlying L2 repository
    /// * `cache_size` - Maximum number of entries in L1 cache
    ///
    /// # Panics
    ///
    /// Panics if default cache size (10000) cannot be converted to `NonZeroUsize`
    ///
    /// # Examples
    ///
    /// ```
    /// use websec::storage::{CachedRepository, InMemoryRepository};
    /// use std::sync::Arc;
    ///
    /// let repo = Arc::new(InMemoryRepository::new());
    /// let cached = CachedRepository::new(repo, 10000);
    /// ```
    #[must_use]
    pub fn new(repository: Arc<R>, cache_size: usize) -> Self {
        let cache_size = NonZeroUsize::new(cache_size).unwrap_or(NonZeroUsize::new(10000).unwrap());
        let cache = Arc::new(Mutex::new(LruCache::new(cache_size)));

        Self { cache, repository }
    }

    /// Create with default cache size (10k entries)
    #[must_use]
    pub fn with_defaults(repository: Arc<R>) -> Self {
        Self::new(repository, 10000)
    }

    /// Get cache statistics
    #[must_use]
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.lock().await;
        CacheStats {
            size: cache.len(),
            capacity: cache.cap().get(),
        }
    }

    /// Clear L1 cache (L2 unchanged)
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.lock().await;
        cache.clear();
    }
}

#[async_trait]
impl<R: ReputationRepository> ReputationRepository for CachedRepository<R> {
    async fn get(&self, ip: &IpAddr) -> Result<Option<ReputationProfile>> {
        // Try L1 cache first
        {
            let mut cache = self.cache.lock().await;
            if let Some(profile) = cache.get(ip) {
                // Cache hit
                return Ok(Some(profile.clone()));
            }
        }

        // Cache miss - fetch from L2
        if let Some(profile) = self.repository.get(ip).await? {
            // Update L1 cache
            let mut cache = self.cache.lock().await;
            cache.put(*ip, profile.clone());
            Ok(Some(profile))
        } else {
            Ok(None)
        }
    }

    async fn save(&self, profile: &ReputationProfile) -> Result<()> {
        // Write to L2 first
        self.repository.save(profile).await?;

        // Update L1 cache
        let mut cache = self.cache.lock().await;
        cache.put(profile.ip_address, profile.clone());

        Ok(())
    }

    async fn delete(&self, ip: &IpAddr) -> Result<bool> {
        // Delete from L2
        let deleted = self.repository.delete(ip).await?;

        // Invalidate L1 cache
        let mut cache = self.cache.lock().await;
        cache.pop(ip);

        Ok(deleted)
    }

    async fn exists(&self, ip: &IpAddr) -> Result<bool> {
        // Check L1 cache first
        {
            let cache = self.cache.lock().await;
            if cache.contains(ip) {
                return Ok(true);
            }
        }

        // Fallback to L2
        self.repository.exists(ip).await
    }

    async fn list_all(&self) -> Result<Vec<IpAddr>> {
        // Always query L2 for complete list
        self.repository.list_all().await
    }

    async fn count(&self) -> Result<usize> {
        // Always query L2 for accurate count
        self.repository.count().await
    }

    async fn clear(&self) -> Result<()> {
        // Clear L2
        self.repository.clear().await?;

        // Clear L1 cache
        let mut cache = self.cache.lock().await;
        cache.clear();

        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        // Health check on L2
        self.repository.health_check().await
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Current number of entries in cache
    pub size: usize,
    /// Maximum cache capacity
    pub capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemoryRepository;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_cached_repo_creation() {
        let repo = Arc::new(InMemoryRepository::new());
        let cached = CachedRepository::new(repo, 100);

        let stats = cached.cache_stats().await;
        assert_eq!(stats.size, 0);
        assert_eq!(stats.capacity, 100);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let repo = Arc::new(InMemoryRepository::new());
        let cached = CachedRepository::new(repo.clone(), 100);

        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        // First write (populates cache)
        cached.save(&profile).await.unwrap();

        // Delete from underlying L2 (but cache still has it)
        repo.delete(&ip).await.unwrap();

        // Should still get from L1 cache
        let result = cached.get(&ip).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().ip_address, ip);

        let stats = cached.cache_stats().await;
        assert_eq!(stats.size, 1);
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let repo = Arc::new(InMemoryRepository::new());
        let cached = CachedRepository::new(repo.clone(), 100);

        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        // Save directly to L2 (bypass cache)
        repo.save(&profile).await.unwrap();

        // Clear L1 cache to force miss
        cached.clear_cache().await;

        // Should fetch from L2 and populate L1
        let result = cached.get(&ip).await.unwrap();
        assert!(result.is_some());

        // Now should be in cache
        let stats = cached.cache_stats().await;
        assert_eq!(stats.size, 1);
    }

    #[tokio::test]
    async fn test_cache_delete_invalidation() {
        let repo = Arc::new(InMemoryRepository::new());
        let cached = CachedRepository::new(repo.clone(), 100);

        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        cached.save(&profile).await.unwrap();
        assert_eq!(cached.cache_stats().await.size, 1);

        // Delete should invalidate cache
        cached.delete(&ip).await.unwrap();
        assert_eq!(cached.cache_stats().await.size, 0);
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        let repo = Arc::new(InMemoryRepository::new());
        let cached = CachedRepository::new(repo.clone(), 3); // Small cache

        // Add 4 profiles (will evict oldest)
        for i in 1..=4 {
            let ip = IpAddr::from_str(&format!("192.168.1.{i}")).unwrap();
            let profile = ReputationProfile::new(ip, 100);
            cached.save(&profile).await.unwrap();
        }

        // Cache should have 3 entries (LRU evicted 1)
        let stats = cached.cache_stats().await;
        assert_eq!(stats.size, 3);
        assert_eq!(stats.capacity, 3);
    }

    #[tokio::test]
    async fn test_exists_cache_check() {
        let repo = Arc::new(InMemoryRepository::new());
        let cached = CachedRepository::new(repo.clone(), 100);

        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        cached.save(&profile).await.unwrap();

        // Should find in cache (fast path)
        assert!(cached.exists(&ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_clear_both_layers() {
        let repo = Arc::new(InMemoryRepository::new());
        let cached = CachedRepository::new(repo.clone(), 100);

        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        cached.save(&profile).await.unwrap();
        assert_eq!(cached.cache_stats().await.size, 1);
        assert_eq!(repo.count().await.unwrap(), 1);

        // Clear should affect both layers
        cached.clear().await.unwrap();

        assert_eq!(cached.cache_stats().await.size, 0);
        assert_eq!(repo.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_list_all_queries_l2() {
        let repo = Arc::new(InMemoryRepository::new());
        let cached = CachedRepository::new(repo.clone(), 100);

        // Add directly to L2
        let ip1 = IpAddr::from_str("192.168.1.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.1.2").unwrap();
        repo.save(&ReputationProfile::new(ip1, 100))
            .await
            .unwrap();
        repo.save(&ReputationProfile::new(ip2, 100))
            .await
            .unwrap();

        // list_all should query L2
        let all = cached.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
    }
}
