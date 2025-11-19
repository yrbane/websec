//! In-memory reputation repository
//!
//! Thread-safe in-memory storage using `DashMap`.
//! Suitable for testing and single-instance deployments.

use super::repository::ReputationRepository;
use crate::reputation::ReputationProfile;
use crate::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// In-memory repository implementation
///
/// Uses `DashMap` for lock-free concurrent access.
/// Profiles are stored in RAM and lost on restart.
///
/// # Thread Safety
///
/// `DashMap` provides interior mutability with sharded locks,
/// allowing concurrent reads/writes without external synchronization.
#[derive(Clone)]
pub struct InMemoryRepository {
    /// Concurrent `HashMap` of IP -> `ReputationProfile`
    storage: Arc<DashMap<IpAddr, ReputationProfile>>,
}

impl InMemoryRepository {
    /// Create a new in-memory repository
    #[must_use]
    pub fn new() -> Self {
        Self {
            storage: Arc::new(DashMap::new()),
        }
    }

    /// Create with initial capacity hint
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            storage: Arc::new(DashMap::with_capacity(capacity)),
        }
    }
}

impl Default for InMemoryRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReputationRepository for InMemoryRepository {
    async fn get(&self, ip: &IpAddr) -> Result<Option<ReputationProfile>> {
        Ok(self.storage.get(ip).map(|entry| entry.value().clone()))
    }

    async fn save(&self, profile: &ReputationProfile) -> Result<()> {
        self.storage.insert(profile.ip_address, profile.clone());
        Ok(())
    }

    async fn delete(&self, ip: &IpAddr) -> Result<bool> {
        Ok(self.storage.remove(ip).is_some())
    }

    async fn exists(&self, ip: &IpAddr) -> Result<bool> {
        Ok(self.storage.contains_key(ip))
    }

    async fn list_all(&self) -> Result<Vec<IpAddr>> {
        Ok(self.storage.iter().map(|entry| *entry.key()).collect())
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.storage.len())
    }

    async fn clear(&self) -> Result<()> {
        self.storage.clear();
        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        // In-memory storage is always healthy
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_new_repository() {
        let repo = InMemoryRepository::new();
        let count = repo.count().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_save_and_get() {
        let repo = InMemoryRepository::new();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        repo.save(&profile).await.unwrap();

        let retrieved = repo.get(&ip).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().ip_address, ip);
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let repo = InMemoryRepository::new();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        let result = repo.get(&ip).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_exists() {
        let repo = InMemoryRepository::new();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        assert!(!repo.exists(&ip).await.unwrap());

        repo.save(&profile).await.unwrap();

        assert!(repo.exists(&ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete() {
        let repo = InMemoryRepository::new();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        repo.save(&profile).await.unwrap();
        assert!(repo.exists(&ip).await.unwrap());

        let deleted = repo.delete(&ip).await.unwrap();
        assert!(deleted);
        assert!(!repo.exists(&ip).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_nonexistent() {
        let repo = InMemoryRepository::new();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        let deleted = repo.delete(&ip).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn test_list_all() {
        let repo = InMemoryRepository::new();
        let ip1 = IpAddr::from_str("192.168.1.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.1.2").unwrap();

        repo.save(&ReputationProfile::new(ip1, 100)).await.unwrap();
        repo.save(&ReputationProfile::new(ip2, 100)).await.unwrap();

        let all = repo.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&ip1));
        assert!(all.contains(&ip2));
    }

    #[tokio::test]
    async fn test_count() {
        let repo = InMemoryRepository::new();
        assert_eq!(repo.count().await.unwrap(), 0);

        let ip1 = IpAddr::from_str("192.168.1.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.1.2").unwrap();

        repo.save(&ReputationProfile::new(ip1, 100)).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 1);

        repo.save(&ReputationProfile::new(ip2, 100)).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_clear() {
        let repo = InMemoryRepository::new();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        repo.save(&ReputationProfile::new(ip, 100)).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 1);

        repo.clear().await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let repo = InMemoryRepository::new();
        assert!(repo.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        use tokio::task;

        let repo = InMemoryRepository::new();
        let repo_clone1 = repo.clone();
        let repo_clone2 = repo.clone();

        let handle1 = task::spawn(async move {
            for i in 0..100 {
                let ip = IpAddr::from_str(&format!("192.168.1.{i}")).unwrap();
                let profile = ReputationProfile::new(ip, 100);
                repo_clone1.save(&profile).await.unwrap();
            }
        });

        let handle2 = task::spawn(async move {
            for i in 100..200 {
                let ip = IpAddr::from_str(&format!("192.168.1.{}", i % 256)).unwrap();
                let profile = ReputationProfile::new(ip, 100);
                repo_clone2.save(&profile).await.unwrap();
            }
        });

        handle1.await.unwrap();
        handle2.await.unwrap();

        let count = repo.count().await.unwrap();
        assert!(count > 0);
    }
}
