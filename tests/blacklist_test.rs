//! Unit tests for Blacklist
//!
//! TDD RED PHASE: These tests MUST fail before implementation
//!
//! Testing:
//! - T105: IP blacklistée est bloquée immédiatement
//! - Blacklist contains IP check
//! - Blacklist add/remove operations
//! - CIDR range support

use std::net::IpAddr;
use std::str::FromStr;
use websec::lists::Blacklist;

// ============================================================================
// T105: Blacklist Immediate Block Tests
// ============================================================================

#[test]
fn test_blacklisted_ip_is_blocked() {
    let mut blacklist = Blacklist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    // Add IP to blacklist
    blacklist.add(ip);

    // IP should be blacklisted
    assert!(blacklist.contains(&ip), "Blacklisted IP should be blocked");
}

#[test]
fn test_non_blacklisted_ip_allowed() {
    let blacklist = Blacklist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    // IP not in blacklist
    assert!(
        !blacklist.contains(&ip),
        "Non-blacklisted IP should be allowed"
    );
}

#[test]
fn test_add_multiple_ips_to_blacklist() {
    let mut blacklist = Blacklist::new();

    let ips = vec!["192.168.1.100", "10.0.0.50", "172.16.0.1"];

    for ip_str in &ips {
        let ip = IpAddr::from_str(ip_str).unwrap();
        blacklist.add(ip);
    }

    // All IPs should be blacklisted
    for ip_str in &ips {
        let ip = IpAddr::from_str(ip_str).unwrap();
        assert!(blacklist.contains(&ip), "IP {} should be blacklisted", ip);
    }
}

#[test]
fn test_remove_ip_from_blacklist() {
    let mut blacklist = Blacklist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    // Add then remove
    blacklist.add(ip);
    assert!(blacklist.contains(&ip));

    blacklist.remove(&ip);
    assert!(
        !blacklist.contains(&ip),
        "Removed IP should no longer be blacklisted"
    );
}

#[test]
fn test_empty_blacklist() {
    let blacklist = Blacklist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    assert!(
        !blacklist.contains(&ip),
        "Empty blacklist should not block any IP"
    );
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

#[test]
fn test_blacklist_clone() {
    let mut blacklist = Blacklist::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    blacklist.add(ip);

    // Clone should have same IPs
    let cloned = blacklist.clone();
    assert!(
        cloned.contains(&ip),
        "Cloned blacklist should contain same IPs"
    );
}

// ============================================================================
// Bulk Operations Tests
// ============================================================================

#[test]
fn test_blacklist_from_vec() {
    let ips = vec![
        IpAddr::from_str("192.168.1.100").unwrap(),
        IpAddr::from_str("10.0.0.50").unwrap(),
    ];

    let blacklist = Blacklist::from_ips(ips.clone());

    for ip in &ips {
        assert!(blacklist.contains(ip), "Blacklist should contain IP {}", ip);
    }
}

#[test]
fn test_blacklist_clear() {
    let mut blacklist = Blacklist::new();
    blacklist.add(IpAddr::from_str("192.168.1.100").unwrap());
    blacklist.add(IpAddr::from_str("10.0.0.50").unwrap());

    blacklist.clear();

    assert!(!blacklist.contains(&IpAddr::from_str("192.168.1.100").unwrap()));
    assert!(!blacklist.contains(&IpAddr::from_str("10.0.0.50").unwrap()));
}

#[test]
fn test_blacklist_count() {
    let mut blacklist = Blacklist::new();

    assert_eq!(blacklist.len(), 0);

    blacklist.add(IpAddr::from_str("192.168.1.100").unwrap());
    assert_eq!(blacklist.len(), 1);

    blacklist.add(IpAddr::from_str("10.0.0.50").unwrap());
    assert_eq!(blacklist.len(), 2);

    // Adding same IP again should not increase count
    blacklist.add(IpAddr::from_str("192.168.1.100").unwrap());
    assert_eq!(blacklist.len(), 2);
}

// ============================================================================
// IPv4 and IPv6 Tests
// ============================================================================

#[test]
fn test_blacklist_ipv4() {
    let mut blacklist = Blacklist::new();
    let ipv4 = IpAddr::from_str("192.168.1.100").unwrap();

    blacklist.add(ipv4);
    assert!(blacklist.contains(&ipv4));
}

#[test]
fn test_blacklist_ipv6() {
    let mut blacklist = Blacklist::new();
    let ipv6 = IpAddr::from_str("2001:0db8::1").unwrap();

    blacklist.add(ipv6);
    assert!(blacklist.contains(&ipv6));
}

#[test]
fn test_blacklist_mixed_ip_versions() {
    let mut blacklist = Blacklist::new();
    let ipv4 = IpAddr::from_str("192.168.1.100").unwrap();
    let ipv6 = IpAddr::from_str("2001:0db8::1").unwrap();

    blacklist.add(ipv4);
    blacklist.add(ipv6);

    assert!(blacklist.contains(&ipv4));
    assert!(blacklist.contains(&ipv6));
}
