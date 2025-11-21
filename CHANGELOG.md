# Changelog

All notable changes to WebSec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-11-21

### 🔒 Security Fixes (6 Critical Issues Resolved)

#### [Issue #2](https://github.com/yrbane/websec/issues/2) - IP Spoofing Prevention (CRITICAL)
- **Added** `trusted_proxies` configuration for X-Forwarded-For validation
- **Fixed** IP spoofing vulnerability allowing attackers to bypass IP-based protections
- **Commit**: 4e083de

#### [Issue #4](https://github.com/yrbane/websec/issues/4) - DoS Memory Protection (CRITICAL)
- **Added** `max_body_size` configuration (default: 10 MB, configurable up to 200+ MB)
- **Implemented** `http_body_util::Limited` for early request rejection (HTTP 413)
- **Fixed** Memory exhaustion vulnerability via large request bodies
- **Commit**: 4e083de

#### [Issue #5](https://github.com/yrbane/websec/issues/5) - Header Sanitization (HIGH)
- **Added** `sanitize_request_headers()` function (RFC 7230 compliant)
- **Implemented** Hop-by-hop header removal (Connection, Transfer-Encoding, etc.)
- **Implemented** Multiple Host header detection and removal
- **Implemented** Content-Length/Transfer-Encoding normalization (anti-smuggling)
- **Fixed** Header injection and request smuggling vulnerabilities
- **Commit**: 08aca55

#### [Issue #6](https://github.com/yrbane/websec/issues/6) - RGPD Compliance (MEDIUM/PRIVACY)
- **Removed** `username` and `password_hash` fields from `LoginAttempt` struct
- **Removed** Credential stuffing detection (required storing credentials)
- **Implemented** IP-only tracking for brute-force detection
- **Fixed** RGPD Article 5(1)(c) data minimization violation
- **Commit**: 6d01c89

#### [Issue #3](https://github.com/yrbane/websec/issues/3) - Metrics Endpoint Security (MEDIUM)
- **Isolated** `/metrics` endpoint to dedicated port (9090)
- **Removed** `/metrics` from main proxy router
- **Fixed** Sensitive metrics exposure to public internet
- **Commit**: 9226aa0

#### [Issue #1](https://github.com/yrbane/websec/issues/1) - Improved Error Messages (LOW)
- **Enhanced** "Address already in use" error with process detection
- **Added** Suggestions for resolving port conflicts
- **Commit**: 96fbe6e

### ✨ Features

#### Multi-Listener HTTP/HTTPS Support
- **Added** Multi-listener configuration with `[[server.listeners]]`
- **Added** Native TLS termination with Let's Encrypt certificates
- **Added** Per-listener backend configuration
- **Commit**: 773da26

#### Apache Setup Assistant
- **Added** Interactive CLI assistant (`websec setup`)
- **Implemented** Automatic VirtualHost detection and port migration (80→8080, 443→8443)
- **Implemented** Automatic `websec.toml` configuration generation
- **Added** Backup system for modified files
- **Commit**: faf3e13

#### CLI Improvements
- **Added** `websec docker build` - Docker image builder with BuildKit
- **Added** `websec docker test` - E2E tests with docker-compose stack
- **Added** `websec stats` - Live statistics with auto-refresh
- **Added** `websec check-storage` - Redis health check
- **Added** `websec run --dry-run` - Configuration validation
- **Added** `websec lists` - Blacklist/whitelist management
- **Added** `websec dev-backend` - Built-in test backend
- **Added** `websec e2e` - End-to-end testing suite
- **Commit**: 0e6082a

### 📚 Documentation

#### Comprehensive Guides (6 Guides Added)
- **Added** [Apache HTTP/HTTPS Configuration Guide](docs/apache-configuration-guide.md)
  - TLS termination architecture
  - Step-by-step Apache configuration
  - SSL certificate management
  - Security hardening
  - **Commit**: a7277c5

- **Added** [Production Deployment Checklist](docs/deployment-checklist.md)
  - System preparation
  - SSL/TLS setup
  - WebSec configuration
  - Apache configuration
  - Firewall setup
  - Systemd service
  - Troubleshooting
  - **Commit**: 854d768

- **Added** [Security Audit Plan](docs/security-audit-plan.md)
  - 21 test scenarios for 10 threat families
  - Tools and commands
  - Validation matrix
  - Audit report template
  - **Commit**: 854d768

- **Added** [websec-apache-example.toml](config/websec-apache-example.toml)
  - Complete configuration example for Apache
  - HTTP + HTTPS listeners
  - 200 MB body size for video uploads
  - **Commit**: a7277c5

- **Updated** [README.md](README.md)
  - Complete rewrite for v0.2.0
  - Security issues section with commit hashes
  - Apache configuration prominent section
  - Updated metrics (144 tests, 12 detectors)
  - Simplified structure focused on production
  - **Commit**: 2ea0316

### 🔧 Refactoring

#### Code Quality
- **Fixed** All clippy warnings and errors (54 issues resolved)
- **Created** `ProxyStateConfig` struct (reduced function parameters from 6 to 1)
- **Optimized** String operations (`format!` → `push_str`)
- **Removed** Redundant closures and borrowed expressions
- **Fixed** Doc markdown throughout codebase
- **Commit**: 65d4445

#### Test Updates
- **Fixed** Credential stuffing test for RGPD compliance
- **Removed** Tautological assertions
- **Removed** Useless `len() >= 0` checks
- **Commit**: 03a5d8d

### 🐛 Bug Fixes

- **Fixed** Docker deployment issues (networking, whitelist)
- **Fixed** Retry policy doc test type inference
- **Updated** axum-server to latest version
- **Updated** Redis dependency to 0.27.6

### 🧪 Testing

- **Status**: 144 unit tests passing ✅
- **Status**: 0 clippy warnings ✅
- **Status**: All integration tests passing ✅
- **Added**: Contract tests for detectors
- **Added**: E2E tests with built-in backend

### 📊 Metrics

- **Tests**: 144 passing (0 errors)
- **Detectors**: 12 threat families implemented
- **Security Issues**: 6/6 resolved
- **Code Quality**: 0 clippy warnings
- **Documentation**: 6 comprehensive guides

---

## [0.1.0] - 2025-11-18

### Initial Release

#### Core Features
- **12 Threat Detectors**:
  - BotDetector (User-Agent analysis, behavior patterns)
  - BruteForceDetector (Failed logins, password spraying)
  - FloodDetector (Request floods, burst detection)
  - InjectionDetector (SQLi, XSS, RCE, path traversal)
  - ScanDetector (Vulnerability scanning, 404 bursts)
  - GeoDetector (High-risk countries, impossible travel)
  - HeaderDetector (CRLF injection, host poisoning)
  - SessionDetector (Hijacking, anomalies)
  - ProtocolDetector (HTTP violations)
  - Plus 3 additional detectors

- **Reputation Engine**:
  - Dynamic scoring (0-100 scale)
  - Signal-based penalties with weights
  - Exponential decay (24h half-life)
  - Correlation penalty bonus
  - Decision thresholds (ALLOW/RATE_LIMIT/CHALLENGE/BLOCK)

- **Rate Limiting**:
  - Token Bucket algorithm
  - Sliding window
  - Per-IP tracking
  - Configurable tiers (normal/suspicious/aggressive)

- **Storage**:
  - Redis backend for distributed state
  - L1 LRU cache (10k IPs, <1ms latency)
  - InMemory fallback for testing

- **Observability**:
  - Prometheus metrics endpoint
  - Structured JSON logging
  - Request tracing

- **CLI**:
  - Configuration management
  - List management (blacklist/whitelist)
  - Statistics viewer

#### Architecture
- Rust 1.75+ stable
- Tokio async runtime
- Hyper/Axum HTTP stack
- Redis for state storage
- MaxMind GeoIP2 for geolocation

---

## Version History

- **[0.2.0]** - 2025-11-21 - Production-Ready (6 security fixes, documentation)
- **[0.1.0]** - 2025-11-18 - Initial MVP Release

---

**Legend**:
- 🔒 Security
- ✨ Features
- 🔧 Refactoring
- 🐛 Bug Fixes
- 📚 Documentation
- 🧪 Testing
- 📊 Metrics
