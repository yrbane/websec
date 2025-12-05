use std::net::IpAddr;
use std::str::FromStr;
use websec::reputation::profile::ReputationProfile;
use websec::storage::{ReputationRepository, SledRepository};
use tempfile::tempdir;

#[tokio::test]
async fn test_sled_repo_lifecycle() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_db");
    let path_str = db_path.to_str().unwrap();

    // 1. Initialize
    let repo = SledRepository::new(path_str).expect("Failed to create SledRepository");

    // 2. Save a profile
    let ip = IpAddr::from_str("192.168.1.42").unwrap();
    let mut profile = ReputationProfile::new(ip, 100);
    profile.current_score = 50; // Modify score to verify persistence

    repo.save(&profile).await.expect("Failed to save profile");

    // 3. Get the profile
    let loaded = repo.get(&ip).await.expect("Failed to get profile");
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().current_score, 50);

    // 4. Count
    let count = repo.count().await.expect("Failed to count");
    assert_eq!(count, 1);

    // 5. Delete
    repo.delete(&ip).await.expect("Failed to delete");
    let loaded_after = repo.get(&ip).await.expect("Failed to get after delete");
    assert!(loaded_after.is_none());
}

#[tokio::test]
async fn test_sled_persistence() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("persist_db");
    let path_str = db_path.to_str().unwrap();
    let ip = IpAddr::from_str("10.0.0.1").unwrap();

    {
        let repo = SledRepository::new(path_str).expect("Failed to create repo 1");
        let mut profile = ReputationProfile::new(ip, 100);
        profile.current_score = 10;
        repo.save(&profile).await.unwrap();
    } // repo dropped here

    // Re-open
    let repo = SledRepository::new(path_str).expect("Failed to re-open repo");
    let loaded = repo.get(&ip).await.unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().current_score, 10);
}
