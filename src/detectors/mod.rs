//! Threat detection system
//!
//! Implements 12 detector families using the Strategy pattern:
//! - Bot detection (User-Agent analysis, fingerprinting)
//! - Brute force detection (login attempt patterns)
//! - Flood/DDoS detection (request rate anomalies)
//! - SQL injection detection (query string analysis)
//! - XSS detection (script pattern matching)
//! - Path traversal detection (directory manipulation)
//! - Scanner detection (tool signatures, enumeration patterns)
//! - Credential stuffing detection (auth endpoint abuse)
//! - Session hijacking detection (token anomalies)
//! - Header manipulation detection (HTTP header abuse)
//! - Protocol violation detection (RFC non-compliance)
//! - Suspicious geo patterns (impossible travel, high-risk countries)

// Placeholder: Phase 2 (T015) will define Detector trait
// Phase 3+ will implement each detector family
