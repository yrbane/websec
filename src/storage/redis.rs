//! Redis-based reputation repository
//!
//! Centralized persistent storage using Redis for distributed WebSec deployments.
//! Supports clustering and provides reliable reputation data across instances.

use super::repository::ReputationRepository;
use crate::reputation::ReputationProfile;
use crate::{Error, Result};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use std::net::IpAddr;
use std::time::Duration;

/// Redis repository implementation
///
/// Uses Redis as backend for persistent, centralized IP reputation storage.
/// Supports multiple WebSec instances sharing the same Redis cluster.
///
/// # Features
///
/// - Persistent storage across restarts
/// - Multi-instance coordination
/// - Automatic serialization/deserialization
/// - Connection pooling via `ConnectionManager`
/// - Configurable TTL for profiles
pub struct RedisRepository {
    /// Redis connection manager (handles reconnection)
    manager: ConnectionManager,
    /// Key prefix for namespacing
    key_prefix: String,
    /// Default TTL for profiles (None = no expiration)
    default_ttl: Option<Duration>,
}

impl RedisRepository {
    /// Create a new Redis repository
    ///
    /// # Arguments
    ///
    /// * `redis_url` - Redis connection URL (e.g., "redis://localhost:6379")
    ///
    /// # Errors
    ///
    /// Returns error if connection to Redis fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use websec::storage::RedisRepository;
    ///
    /// # async fn example() -> websec::Result<()> {
    /// let repo = RedisRepository::new("redis://localhost:6379").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(redis_url: impl AsRef<str>) -> Result<Self> {
        Self::with_config(redis_url, "websec:ip:", None).await
    }

    /// Create with custom configuration
    ///
    /// # Arguments
    ///
    /// * `redis_url` - Redis connection URL
    /// * `key_prefix` - Prefix for all Redis keys (for namespacing)
    /// * `default_ttl` - Default TTL for profiles (None = no expiration)
    pub async fn with_config(
        redis_url: impl AsRef<str>,
        key_prefix: impl Into<String>,
        default_ttl: Option<Duration>,
    ) -> Result<Self> {
        let client = Client::open(redis_url.as_ref())
            .map_err(|e| Error::Storage(format!("Failed to create Redis client: {e}")))?;

        let manager = ConnectionManager::new(client)
            .await
            .map_err(|e| Error::Storage(format!("Failed to connect to Redis: {e}")))?;

        Ok(Self {
            manager,
            key_prefix: key_prefix.into(),
            default_ttl,
        })
    }

    /// Build Redis key for an IP address
    fn build_key(&self, ip: &IpAddr) -> String {
        format!("{}{}", self.key_prefix, ip)
    }

    /// Serialize profile to JSON
    fn serialize(profile: &ReputationProfile) -> Result<String> {
        serde_json::to_string(profile)
            .map_err(|e| Error::Storage(format!("Failed to serialize profile: {e}")))
    }

    /// Deserialize profile from JSON
    fn deserialize(json: &str) -> Result<ReputationProfile> {
        serde_json::from_str(json)
            .map_err(|e| Error::Storage(format!("Failed to deserialize profile: {e}")))
    }
}

#[async_trait]
impl ReputationRepository for RedisRepository {
    async fn get(&self, ip: &IpAddr) -> Result<Option<ReputationProfile>> {
        let key = self.build_key(ip);
        let mut conn = self.manager.clone();

        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| Error::Storage(format!("Redis GET failed: {e}")))?;

        match value {
            Some(json) => Ok(Some(Self::deserialize(&json)?)),
            None => Ok(None),
        }
    }

    async fn save(&self, profile: &ReputationProfile) -> Result<()> {
        let key = self.build_key(&profile.ip_address);
        let json = Self::serialize(profile)?;
        let mut conn = self.manager.clone();

        match self.default_ttl {
            Some(ttl) => {
                let ttl_secs = ttl.as_secs();
                let _: () = conn
                    .set_ex(&key, json, ttl_secs)
                    .await
                    .map_err(|e| Error::Storage(format!("Redis SETEX failed: {e}")))?;
            }
            None => {
                let _: () = conn
                    .set(&key, json)
                    .await
                    .map_err(|e| Error::Storage(format!("Redis SET failed: {e}")))?;
            }
        }

        Ok(())
    }

    async fn delete(&self, ip: &IpAddr) -> Result<bool> {
        let key = self.build_key(ip);
        let mut conn = self.manager.clone();

        let deleted: i32 = conn
            .del(&key)
            .await
            .map_err(|e| Error::Storage(format!("Redis DEL failed: {e}")))?;

        Ok(deleted > 0)
    }

    async fn exists(&self, ip: &IpAddr) -> Result<bool> {
        let key = self.build_key(ip);
        let mut conn = self.manager.clone();

        conn.exists(&key)
            .await
            .map_err(|e| Error::Storage(format!("Redis EXISTS failed: {e}")))
    }

    async fn list_all(&self) -> Result<Vec<IpAddr>> {
        let pattern = format!("{}*", self.key_prefix);
        let mut conn = self.manager.clone();

        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(|e| Error::Storage(format!("Redis KEYS failed: {e}")))?;

        let mut ips = Vec::new();
        for key in keys {
            // Extract IP from key by removing prefix
            if let Some(ip_str) = key.strip_prefix(&self.key_prefix) {
                if let Ok(ip) = ip_str.parse() {
                    ips.push(ip);
                }
            }
        }

        Ok(ips)
    }

    async fn count(&self) -> Result<usize> {
        // Use list_all for simplicity (could optimize with Redis count)
        self.list_all().await.map(|ips| ips.len())
    }

    async fn clear(&self) -> Result<()> {
        let pattern = format!("{}*", self.key_prefix);
        let mut conn = self.manager.clone();

        let keys: Vec<String> = conn
            .keys(&pattern)
            .await
            .map_err(|e| Error::Storage(format!("Redis KEYS failed: {e}")))?;

        if !keys.is_empty() {
            let _: () = conn
                .del(keys)
                .await
                .map_err(|e| Error::Storage(format!("Redis DEL failed: {e}")))?;
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        let mut conn = self.manager.clone();

        let pong: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|e| Error::Storage(format!("Redis PING failed: {e}")))?;

        Ok(pong == "PONG")
    }
}

// Implement Clone for RedisRepository
impl Clone for RedisRepository {
    fn clone(&self) -> Self {
        Self {
            manager: self.manager.clone(),
            key_prefix: self.key_prefix.clone(),
            default_ttl: self.default_ttl,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Note: Ces tests nécessitent une instance Redis running
    // Pour exécuter : docker run -d -p 6379:6379 redis:7-alpine
    // Puis : cargo test --lib storage::redis -- --ignored

    #[tokio::test]
    #[ignore] // Nécessite Redis
    async fn test_redis_connection() {
        let repo = RedisRepository::new("redis://localhost:6379")
            .await
            .unwrap();

        assert!(repo.health_check().await.unwrap());
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_save_and_get() {
        let repo = RedisRepository::new("redis://localhost:6379")
            .await
            .unwrap();

        // Clear pour éviter conflicts
        repo.clear().await.unwrap();

        let ip = IpAddr::from_str("192.168.1.100").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        repo.save(&profile).await.unwrap();

        let retrieved = repo.get(&ip).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().ip_address, ip);

        // Cleanup
        repo.clear().await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_delete() {
        let repo = RedisRepository::new("redis://localhost:6379")
            .await
            .unwrap();

        repo.clear().await.unwrap();

        let ip = IpAddr::from_str("192.168.1.100").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        repo.save(&profile).await.unwrap();
        assert!(repo.exists(&ip).await.unwrap());

        let deleted = repo.delete(&ip).await.unwrap();
        assert!(deleted);
        assert!(!repo.exists(&ip).await.unwrap());

        repo.clear().await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_list_all() {
        let repo = RedisRepository::new("redis://localhost:6379")
            .await
            .unwrap();

        repo.clear().await.unwrap();

        let ip1 = IpAddr::from_str("192.168.1.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.1.2").unwrap();

        repo.save(&ReputationProfile::new(ip1, 100))
            .await
            .unwrap();
        repo.save(&ReputationProfile::new(ip2, 100))
            .await
            .unwrap();

        let all = repo.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&ip1));
        assert!(all.contains(&ip2));

        repo.clear().await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_ttl() {
        let repo = RedisRepository::with_config(
            "redis://localhost:6379",
            "websec:test:",
            Some(Duration::from_secs(2)),
        )
        .await
        .unwrap();

        repo.clear().await.unwrap();

        let ip = IpAddr::from_str("192.168.1.100").unwrap();
        let profile = ReputationProfile::new(ip, 100);

        repo.save(&profile).await.unwrap();
        assert!(repo.exists(&ip).await.unwrap());

        // Wait for TTL expiration
        tokio::time::sleep(Duration::from_secs(3)).await;

        assert!(!repo.exists(&ip).await.unwrap());
    }
}
