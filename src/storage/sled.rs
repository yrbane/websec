//! Sled (embedded DB) implementation of `ReputationRepository`
//!
//! Uses the `sled` crate to provide a high-performance embedded key-value store.
//! This allows for persistence without requiring an external database like Redis.

use super::repository::ReputationRepository;
use crate::reputation::profile::ReputationProfile;
use crate::{Error, Result};
use async_trait::async_trait;
use sled::Db;
use std::net::IpAddr;
use std::path::Path;

/// Repository implementation using Sled embedded DB
#[derive(Clone)]
pub struct SledRepository {
    db: Db,
}

impl SledRepository {
    /// Create a new `SledRepository` at the specified path
    ///
    /// # Errors
    ///
    /// Returns error if database cannot be opened or created
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path).map_err(|e| Error::Storage(format!("Sled open error: {e}")))?;
        Ok(Self { db })
    }

    /// Create a temporary SledRepository (useful for tests)
    #[cfg(test)]
    pub fn new_temporary() -> Result<Self> {
        let db =
            sled::Config::new()
                .temporary(true)
                .open()
                .map_err(|e| Error::Storage(format!("Sled temp error: {e}")))?;
        Ok(Self { db })
    }
}

#[async_trait]
impl ReputationRepository for SledRepository {
    async fn get(&self, ip: &IpAddr) -> Result<Option<ReputationProfile>> {
        let key = ip.to_string();
        let db = self.db.clone();

        match db
            .get(key.as_bytes())
            .map_err(|e| Error::Storage(format!("Sled get error: {e}")))?
        {
            Some(ivec) => {
                let profile: ReputationProfile = bincode::deserialize(&ivec)
                    .map_err(|e| Error::Storage(format!("Deserialization error: {e}")))?;
                Ok(Some(profile))
            }
            None => Ok(None),
        }
    }

    async fn save(&self, profile: &ReputationProfile) -> Result<()> {
        let key = profile.ip_address.to_string();
        let encoded = bincode::serialize(profile)
            .map_err(|e| Error::Storage(format!("Serialization error: {e}")))?;
        let db = self.db.clone();

        db.insert(key.as_bytes(), encoded)
            .map_err(|e| Error::Storage(format!("Sled insert error: {e}")))?;
        
        Ok(())
    }

    async fn delete(&self, ip: &IpAddr) -> Result<bool> {
        let key = ip.to_string();
        let db = self.db.clone();

        let result = db.remove(key.as_bytes())
            .map_err(|e| Error::Storage(format!("Sled remove error: {e}")))?;
        Ok(result.is_some())
    }

    async fn exists(&self, ip: &IpAddr) -> Result<bool> {
        let key = ip.to_string();
        let db = self.db.clone();
        db.contains_key(key.as_bytes())
             .map_err(|e| Error::Storage(format!("Sled exists error: {e}")))
    }

    async fn list_all(&self) -> Result<Vec<IpAddr>> {
        let db = self.db.clone();
        let mut ips = Vec::new();

        for item in db.iter() {
            let (key, _) = item.map_err(|e| Error::Storage(format!("Sled iteration error: {e}")))?;
            let ip_str = String::from_utf8(key.to_vec())
                .map_err(|e| Error::Storage(format!("Invalid UTF-8 key: {e}")))?;
            
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                ips.push(ip);
            }
        }

        Ok(ips)
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.db.len())
    }

    async fn clear(&self) -> Result<()> {
        self.db.clear().map_err(|e| Error::Storage(format!("Sled clear error: {e}")))
    }

    async fn health_check(&self) -> Result<bool> {
        // Sled doesn't have a specific "ping", but if we can check the checksums or size, it's alive.
        Ok(self.db.checksum().is_ok())
    }
}
