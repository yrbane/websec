//! Unit tests for Whitelist
//!
//! TDD RED PHASE: These tests MUST fail before implementation
//!
//! Testing:
//! - T106: IP whitelistée est autorisée
//! - Whitelist contains IP check
//! - Whitelist add/remove operations
//! - Whitelist always allows (bypasses scoring)

use websec::lists::Whitelist;
use std::net::IpAddr;
use std::str::FromStr;

// ============================================================================
// T106: Whitelist Bypass Tests
// ============================================================================

#[test]
fn test_whitelisted_ip_is_allowed() {
    let mut whitelist = Whitelist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    // Add IP to whitelist
    whitelist.add(ip);

    // IP should be whitelisted
    assert!(whitelist.contains(&ip), "Whitelisted IP should be allowed");
}

#[test]
fn test_non_whitelisted_ip_not_bypassed() {
    let whitelist = Whitelist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    // IP not in whitelist
    assert!(!whitelist.contains(&ip), "Non-whitelisted IP should go through normal scoring");
}

#[test]
fn test_add_multiple_ips_to_whitelist() {
    let mut whitelist = Whitelist::new();

    let ips = vec![
        "192.168.1.100",
        "10.0.0.50",
        "172.16.0.1",
    ];

    for ip_str in &ips {
        let ip = IpAddr::from_str(ip_str).unwrap();
        whitelist.add(ip);
    }

    // All IPs should be whitelisted
    for ip_str in &ips {
        let ip = IpAddr::from_str(ip_str).unwrap();
        assert!(whitelist.contains(&ip), "IP {} should be whitelisted", ip);
    }
}

#[test]
fn test_remove_ip_from_whitelist() {
    let mut whitelist = Whitelist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    // Add then remove
    whitelist.add(ip);
    assert!(whitelist.contains(&ip));

    whitelist.remove(&ip);
    assert!(!whitelist.contains(&ip), "Removed IP should no longer be whitelisted");
}

#[test]
fn test_empty_whitelist() {
    let whitelist = Whitelist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    assert!(!whitelist.contains(&ip), "Empty whitelist should not bypass any IP");
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

#[test]
fn test_whitelist_clone() {
    let mut whitelist = Whitelist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    whitelist.add(ip);

    // Clone should have same IPs
    let cloned = whitelist.clone();
    assert!(cloned.contains(&ip), "Cloned whitelist should contain same IPs");
}

// ============================================================================
// Bulk Operations Tests
// ============================================================================

#[test]
fn test_whitelist_from_vec() {
    let ips = vec![
        IpAddr::from_str("192.168.1.100").unwrap(),
        IpAddr::from_str("10.0.0.50").unwrap(),
    ];

    let whitelist = Whitelist::from_ips(ips.clone());

    for ip in &ips {
        assert!(whitelist.contains(ip), "Whitelist should contain IP {}", ip);
    }
}

#[test]
fn test_whitelist_clear() {
    let mut whitelist = Whitelist::new();
    whitelist.add(IpAddr::from_str("192.168.1.100").unwrap());
    whitelist.add(IpAddr::from_str("10.0.0.50").unwrap());

    whitelist.clear();

    assert!(!whitelist.contains(&IpAddr::from_str("192.168.1.100").unwrap()));
    assert!(!whitelist.contains(&IpAddr::from_str("10.0.0.50").unwrap()));
}

#[test]
fn test_whitelist_count() {
    let mut whitelist = Whitelist::new();

    assert_eq!(whitelist.len(), 0);

    whitelist.add(IpAddr::from_str("192.168.1.100").unwrap());
    assert_eq!(whitelist.len(), 1);

    whitelist.add(IpAddr::from_str("10.0.0.50").unwrap());
    assert_eq!(whitelist.len(), 2);

    // Adding same IP again should not increase count
    whitelist.add(IpAddr::from_str("192.168.1.100").unwrap());
    assert_eq!(whitelist.len(), 2);
}

// ============================================================================
// IPv4 and IPv6 Tests
// ============================================================================

#[test]
fn test_whitelist_ipv4() {
    let mut whitelist = Whitelist::new();
    let ipv4 = IpAddr::from_str("192.168.1.100").unwrap();

    whitelist.add(ipv4);
    assert!(whitelist.contains(&ipv4));
}

#[test]
fn test_whitelist_ipv6() {
    let mut whitelist = Whitelist::new();
    let ipv6 = IpAddr::from_str("2001:0db8::1").unwrap();

    whitelist.add(ipv6);
    assert!(whitelist.contains(&ipv6));
}

#[test]
fn test_whitelist_mixed_ip_versions() {
    let mut whitelist = Whitelist::new();
    let ipv4 = IpAddr::from_str("192.168.1.100").unwrap();
    let ipv6 = IpAddr::from_str("2001:0db8::1").unwrap();

    whitelist.add(ipv4);
    whitelist.add(ipv6);

    assert!(whitelist.contains(&ipv4));
    assert!(whitelist.contains(&ipv6));
}
