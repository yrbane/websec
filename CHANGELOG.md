# Changelog

All notable changes to WebSec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-08-03

### 🔒 Bug Fixes

#### Écoute IPv6 (dual-stack)
- **Fixed** Les listeners étaient bindés sur `0.0.0.0` (IPv4 uniquement). Un domaine publiant un enregistrement AAAA était injoignable en IPv6 (connexion refusée sur `:443`), le navigateur devant se rabattre sur l'IPv4.
- **Changed** `websec setup` génère désormais les listeners sur `[::]` (dual-stack : IPv4 **et** IPv6 sur un seul socket, `bindv6only=0`). Serveur de métriques également passé en `[::]`.
- **Commits**: 289ab6e, 7435603, a676fce

#### Whitelist jamais chargée au runtime
- **Fixed** Le dossier des listes était résolu en `lists/` **relatif au CWD**. Sous systemd (CWD = `/`), le runtime cherchait `/lists/whitelist.txt` (inexistant) : la whitelist n'était **jamais** chargée en production.
- **Changed** Le dossier des listes est désormais co-localisé avec le fichier de configuration : `<dossier de WEBSEC_CONFIG>/lists` (= `/etc/websec/lists`), côté runtime **et** CLI. Le CLI accepte toujours `--dir` ou `WEBSEC_LISTS_DIR` en surcharge.
- **Note** Utiliser `websec lists whitelist add <ip|cidr> -c /etc/websec/websec.toml` puis redémarrer le service pour que le runtime relise le fichier. Log de démarrage : `Whitelist loaded: N entries`.
- **Commit**: ffbfd3f

#### Whitelist : rejet des adresses IPv6
- **Fixed** `validate_ip` (CLI) n'acceptait qu'une regex IPv4 → toute adresse IPv6 était rejetée (« Format IP/CIDR invalide »), rendant impossible la whitelist d'un client IPv6.
- **Changed** Validation via `std::net::IpAddr` : accepte IPv4, IPv6 et le suffixe CIDR (avec bornes de préfixe par famille : ≤ 32 en IPv4, ≤ 128 en IPv6).
- **Commit**: a676fce

#### `websec setup` : empilement infini de backups
- **Fixed** `scan_virtual_hosts` parcourait tous les fichiers de `sites-enabled`, y compris ses propres backups `*.websec.bak.<timestamp>`, les re-modifiait et créait un backup du backup → noms `x.conf.websec.bak.T1.websec.bak.T2…` à chaque exécution.
- **Changed** Les fichiers `.websec.bak.*` sont désormais ignorés au scan. `websec setup` est **idempotent** (aucun backup recréé si la configuration est déjà migrée).
- **Commit**: 51d18cd

### ✨ Features

#### Whitelist / Blacklist par plage CIDR
- **Added** Matching CIDR au runtime (`whitelist.rs` : `add_cidr` / `add_entry` / `cidr_contains`). On peut whitelister un bloc entier — par exemple un `/64` IPv6 (couvre toutes les adresses « privacy » qui tournent dans le préfixe) ou un `/24` IPv4 — au lieu d'IP exactes uniquement. IPv4 et IPv6 supportés, sans correspondance croisée entre familles.
- **Commit**: ffbfd3f

### 🧪 Testing
- **Added** Tests unitaires du matching CIDR (`/64` IPv6, `/24` IPv4, familles disjointes, entrées invalides).
- **Fixed** Assertions de tests alignées sur les listeners `[::]` ; suppression d'un import mort (`use super::*`) qui bloquait la compilation des tests sous `#![deny(warnings)]`.

---

## [0.2.1] - 2026-02-15

### 🔒 Bug Fixes (Reverse Proxy)

#### TLS / rustls 0.23 Compatibility
- **Fixed** CryptoProvider panic on startup (`rustls::crypto::ring::default_provider().install_default()`)
- **Commit**: c6aae58

#### HTTP/2 Full Support
- **Fixed** HTTP/2 requests failing with `UserUnsupportedVersion` when forwarded to Apache backend
- **Added** Automatic HTTP/1.1 version downgrade for backend forwarding (`backend.rs`)
- **Fixed** HTTP/2 `:authority` pseudo-header not mapped to `Host` header for backend VHost routing
- **Fixed** False positive `ProtocolViolation` signal for HTTP/2 requests missing `Host` header (HTTP/2 uses `:authority`)
- **Commit**: c6aae58

#### Header Handling
- **Fixed** `Host` header being overwritten with backend host (`127.0.0.1:8080`), breaking Apache VHost routing
- **Added** `X-Forwarded-Proto` header (http/https based on listener TLS status)
- **Added** `X-Forwarded-Host` header (original Host preserved)
- **Added** `is_tls` field to `ProxyState` for per-listener protocol detection
- **Commit**: c6aae58

### ✨ Features

#### Production Configuration
- **Updated** `websec.toml` with dual-listener setup: HTTP `:80` + HTTPS `:443`
- **Added** Let's Encrypt certificate paths in default configuration

### 🧪 Testing
- **Updated** `protocol_detector_unit_test.rs` and `protocol_integration_test.rs` for HTTP/2 compatibility

---

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

- **[0.2.1]** - 2026-02-15 - HTTP/2, TLS rustls 0.23, proxy headers fix
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
