//! Repository trait for reputation storage
//!
//! Defines the Repository pattern interface for IP reputation persistence.
//! Abstracts storage backend (Redis, in-memory, file-based fallback).

use crate::reputation::ReputationProfile;
use crate::Result;
use async_trait::async_trait;
use std::net::IpAddr;

/// Repository trait for IP reputation profiles
///
/// Abstracts the storage layer using the Repository pattern.
/// Implementations can use Redis, in-memory HashMap, or file-based storage.
///
/// # Design Pattern: Repository
///
/// Benefits:
/// - Testability: Use in-memory implementation for tests
/// - Flexibility: Swap backends without changing business logic
/// - Degraded mode: Fallback to file storage when Redis unavailable
#[async_trait]
pub trait ReputationRepository: Send + Sync {
    /// Get a reputation profile by IP address
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to look up
    ///
    /// # Returns
    ///
    /// - `Ok(Some(profile))` if found
    /// - `Ok(None)` if not found
    /// - `Err(...)` on storage errors
    async fn get(&self, ip: &IpAddr) -> Result<Option<ReputationProfile>>;

    /// Save or update a reputation profile
    ///
    /// # Arguments
    ///
    /// * `profile` - The profile to save
    ///
    /// # Returns
    ///
    /// - `Ok(())` on success
    /// - `Err(...)` on storage errors
    async fn save(&self, profile: &ReputationProfile) -> Result<()>;

    /// Delete a reputation profile
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to delete
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if deleted
    /// - `Ok(false)` if not found
    /// - `Err(...)` on storage errors
    async fn delete(&self, ip: &IpAddr) -> Result<bool>;

    /// Check if a profile exists
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to check
    async fn exists(&self, ip: &IpAddr) -> Result<bool>;

    /// Get all tracked IPs (for admin/stats)
    ///
    /// # Returns
    ///
    /// Vector of all tracked IP addresses.
    /// May be expensive for large datasets.
    async fn list_all(&self) -> Result<Vec<IpAddr>>;

    /// Get count of tracked IPs
    async fn count(&self) -> Result<usize>;

    /// Clear all profiles (for testing/admin)
    async fn clear(&self) -> Result<()>;

    /// Health check for storage backend
    ///
    /// Returns `Ok(true)` if the storage backend is healthy and reachable.
    async fn health_check(&self) -> Result<bool>;
}
