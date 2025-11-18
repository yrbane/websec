# WebSec Developer Quickstart Guide

**Feature**: WebSec Proxy de Sécurité
**Branch**: `001-websec-proxy`
**Date**: 2025-11-18
**Status**: Complete

## Overview

This guide will help you set up your development environment, build WebSec, run tests, and start contributing. Follow the steps sequentially for a smooth onboarding experience.

**Prerequisites**: 15-30 minutes for full setup.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Repository Setup](#repository-setup)
3. [Building WebSec](#building-websec)
4. [Running Tests](#running-tests)
5. [Running Locally](#running-locally)
6. [Configuration](#configuration)
7. [Project Structure](#project-structure)
8. [Development Workflow (TDD)](#development-workflow-tdd)
9. [Contributing](#contributing)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

#### 1. Rust Toolchain (1.75+)

**Installation**:
```bash
# Install rustup (Rust toolchain manager)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow prompts, choose default installation

# Verify installation
rustc --version  # Should show 1.75.0 or higher
cargo --version

# Install required components
rustup component add rustfmt clippy
```

**Update existing installation**:
```bash
rustup update stable
```

#### 2. Redis Server (7.0+)

**Linux (Ubuntu/Debian)**:
```bash
sudo apt update
sudo apt install redis-server

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server  # Auto-start on boot

# Verify
redis-cli ping  # Should return "PONG"
```

**macOS**:
```bash
brew install redis

# Start Redis
brew services start redis

# Verify
redis-cli ping
```

**Docker Alternative**:
```bash
docker run -d -p 6379:6379 --name websec-redis redis:7-alpine
```

#### 3. GeoIP2 Database

**Download GeoLite2-City (Free)**:
```bash
# Create account at https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-City.mmdb

# Or use wget (example, URL may vary)
mkdir -p /usr/share/GeoIP
cd /usr/share/GeoIP

# Place GeoLite2-City.mmdb here
# (requires MaxMind account and license key)
```

**Note**: For development, you can use a smaller test database (included in fixtures).

#### 4. Git

```bash
# Verify Git is installed
git --version  # Should be 2.x+

# Configure Git (if not done)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### Optional Tools

- **cargo-watch**: Auto-rebuild on file changes
  ```bash
  cargo install cargo-watch
  ```

- **cargo-tarpaulin**: Code coverage
  ```bash
  cargo install cargo-tarpaulin
  ```

- **rust-analyzer**: IDE support (VSCode, Vim, etc.)
  ```bash
  # VSCode: Install "rust-analyzer" extension
  # Vim/Neovim: Configure with LSP client
  ```

---

## Repository Setup

### 1. Clone Repository

```bash
# Clone via SSH (recommended for contributors)
git clone git@github.com:SinceAndCo/websec.git
cd websec

# Or via HTTPS
git clone https://github.com/SinceAndCo/websec.git
cd websec
```

### 2. Verify Branch

```bash
# Check current branch
git branch
# Should show: * 001-websec-proxy

# If not on feature branch, create it
git checkout -b 001-websec-proxy
```

### 3. Install Dependencies

Rust dependencies are managed by Cargo and will be downloaded automatically on first build.

```bash
# Download and cache dependencies (optional, happens on first build)
cargo fetch
```

---

## Building WebSec

### Debug Build (Fast compilation, slower runtime)

```bash
# Build debug binary
cargo build

# Binary location: target/debug/websec
./target/debug/websec --version
```

**Use for**: Development, testing, debugging.

### Release Build (Slower compilation, optimized runtime)

```bash
# Build release binary with optimizations
cargo build --release

# Binary location: target/release/websec
./target/release/websec --version
```

**Use for**: Benchmarks, performance testing, production.

### Build with All Features

```bash
# Build with TLS support (optional feature)
cargo build --release --all-features
```

### Check Without Building

```bash
# Fast syntax check (no code generation)
cargo check

# Check with clippy lints
cargo clippy
```

---

## Running Tests

WebSec follows strict TDD (Test-Driven Development) with comprehensive test coverage.

### All Tests

```bash
# Run all tests (unit + integration + contract)
cargo test

# Run tests with output (see println! from tests)
cargo test -- --nocapture

# Run tests in parallel (default) or single-threaded
cargo test -- --test-threads=1
```

### Unit Tests

```bash
# Run only unit tests (in src/ with #[cfg(test)])
cargo test --lib
```

### Integration Tests

```bash
# Run all integration tests
cargo test --test '*'

# Run specific integration test file
cargo test --test proxy_tests
```

### Contract Tests

```bash
# Run contract tests for specific module
cargo test --test detector_tests
cargo test --test reputation_tests
```

### Specific Test

```bash
# Run test by name (substring match)
cargo test test_bot_detector

# Run tests matching pattern
cargo test reputation::
```

### Code Coverage

```bash
# Generate coverage report with tarpaulin
cargo tarpaulin --out Html --output-dir coverage/

# Open report
firefox coverage/index.html  # or your browser
```

**Target**: >80% coverage on business logic (NFR-009).

---

## Running Locally

### 1. Create Configuration File

Create `websec.toml` in project root:

```toml
[server]
# Listen on localhost:8080
listen = "127.0.0.1:8080"

# Backend web server (e.g., nginx on 8081)
backend = "http://127.0.0.1:8081"

# Number of worker threads (default: CPU cores)
workers = 4

[reputation]
# Base score for new IPs
base_score = 100

# Score thresholds for decisions
threshold_allow = 70        # >= 70: ALLOW
threshold_ratelimit = 40    # 40-69: RATE_LIMIT
threshold_challenge = 20    # 20-39: CHALLENGE
threshold_block = 0         # < 20: BLOCK

# Decay half-life in hours
decay_half_life_hours = 24.0

# Correlation penalty bonus
correlation_penalty_bonus = 10

[storage]
# Storage type: "redis" or "memory" (for testing)
type = "redis"

# Redis connection URL
redis_url = "redis://127.0.0.1:6379"

# L1 cache size (number of IPs)
cache_size = 10000

[geolocation]
enabled = true

# Path to GeoIP2 database
database = "/usr/share/GeoIP/GeoLite2-City.mmdb"

# Geographic penalties (optional)
[geolocation.penalties]
RU = 15  # Russia: -15 score
CN = 15  # China: -15 score
KP = 30  # North Korea: -30 score

[ratelimit]
# Normal tier (score 80-100)
normal_rpm = 1000
normal_burst = 100

# Suspicious tier (score 50-79)
suspicious_rpm = 200
suspicious_burst = 20

# Aggressive tier (score 20-49)
aggressive_rpm = 50
aggressive_burst = 5

# Sliding window duration (seconds)
window_duration_secs = 60

[logging]
# Log level: trace, debug, info, warn, error
level = "info"

# Log format: "json" or "pretty"
format = "pretty"

[metrics]
# Enable Prometheus metrics
enabled = true

# Metrics HTTP port
port = 9090
```

### 2. Start Backend Server (for testing)

You need a backend web server to forward requests to. Example with Python:

```bash
# Simple HTTP server on port 8081
python3 -m http.server 8081
```

Or use nginx, Apache, or any web server listening on port 8081.

### 3. Run WebSec

```bash
# Run with default config (websec.toml)
cargo run

# Run with custom config
cargo run -- --config /path/to/custom.toml

# Run with verbose logging
RUST_LOG=debug cargo run

# Run in release mode (faster)
cargo run --release
```

### 4. Test the Proxy

In another terminal:

```bash
# Send request through WebSec proxy
curl -v http://localhost:8080/

# Check metrics
curl http://localhost:9090/metrics

# Test with suspicious User-Agent
curl -H "User-Agent: sqlmap/1.7" http://localhost:8080/
# Should be blocked or rate-limited
```

### 5. Monitor Logs

```bash
# WebSec logs appear in stdout (JSON format in production)
# Example log entry:
{
  "timestamp": "2025-11-18T10:30:45Z",
  "level": "warn",
  "message": "Request blocked",
  "ip": "127.0.0.1",
  "user_agent": "sqlmap/1.7",
  "score": 15,
  "decision": "BLOCK",
  "reason": "LowReputation"
}
```

---

## Configuration

### Environment Variables

Override config values with environment variables:

```bash
# Example: Override Redis URL
export WEBSEC_STORAGE__REDIS_URL="redis://remote-server:6379"

# Example: Override log level
export WEBSEC_LOGGING__LEVEL="debug"

cargo run
```

**Pattern**: `WEBSEC_<SECTION>__<KEY>` (double underscore for nested keys).

### Hot Reload (FR-020)

WebSec supports hot configuration reload without downtime:

```bash
# Modify websec.toml
vim websec.toml

# Reload via CLI (once implemented)
websec-cli config reload

# Or send SIGHUP signal
kill -HUP $(pidof websec)
```

**Performance**: <100ms reload time (SC-007).

---

## Project Structure

### Directory Layout

```
websec/
   Cargo.toml              # Workspace manifest
   Cargo.lock              # Dependency lock file
   websec.toml             # Default configuration
   README.md               # Project overview
   CHANGELOG.md            # Version history

   src/                    # Source code
      main.rs             # Entry point
      config.rs           # Configuration loading
      server.rs           # HTTP proxy server
      cli.rs              # CLI commands
   
      models/             # Domain entities (data-model.md)
         mod.rs
         ip_profile.rs
         signal.rs
         request.rs
         decision.rs
         reputation_score.rs
   
      detectors/          # 12 threat detectors (Strategy pattern)
         mod.rs
         trait_detector.rs
         bot_detector.rs
         bruteforce_detector.rs
         flood_detector.rs
         injection_detector.rs
         path_traversal_detector.rs
         upload_detector.rs
         vuln_scan_detector.rs
         protocol_anomaly_detector.rs
         host_header_detector.rs
         ssrf_detector.rs
         session_anomaly_detector.rs
         tls_fingerprint_detector.rs
   
      reputation/         # Reputation engine
         mod.rs
         engine.rs
         decay.rs
         weights.rs
   
      ratelimit/          # Rate limiting (Token Bucket + Sliding Window)
         mod.rs
         token_bucket.rs
         limiter.rs
   
      storage/            # Repository pattern (L1 cache + L2 Redis + L3 fallback)
         mod.rs
         trait_repository.rs
         redis_repository.rs
         memory_cache.rs
         fallback_logs.rs
   
      geolocation/        # GeoIP lookup
         mod.rs
         maxmind.rs
   
      proxy/              # HTTP proxy logic
         mod.rs
         handler.rs
         forwarder.rs
         response.rs
   
      observability/      # Metrics + logging
         mod.rs
         metrics.rs
         logging.rs
   
      utils/              # Utilities
          mod.rs
          ip_utils.rs
          patterns.rs

   tests/                  # Integration & contract tests
      contract/           # Contract tests (TDD Phase 1)
         detector_tests.rs
         reputation_tests.rs
         ratelimit_tests.rs
         storage_tests.rs
   
      integration/        # End-to-end tests
         proxy_tests.rs
         scenarios/      # 13 user scenarios from spec
            bot_detection.rs
            bruteforce.rs
            flood.rs
            injections.rs
            ...
         cli_tests.rs
   
      fixtures/           # Test data
          requests.json
          geoip_test.mmdb

   benches/                # Performance benchmarks
      detector_bench.rs
      reputation_bench.rs
      proxy_bench.rs

   docs/                   # Documentation
      IDEA.md             # Original concept
      Menaces.md          # Threat taxonomy
      architecture.md     # System architecture
      deployment.md       # Production deployment

   specs/                  # Design specifications
      001-websec-proxy/
          spec.md         # Functional specification
          plan.md         # Implementation plan
          research.md     # Technical decisions
          data-model.md   # Data model
          quickstart.md   # This file
          contracts/      # Contract test specs
          tasks.md        # Task breakdown

   .github/
       workflows/
           ci.yml          # CI pipeline (clippy, test, audit, coverage)
```

### Key Modules

**Core Flow**:
```
main.rs ’ server.rs ’ handler.rs ’ [detectors] ’ reputation ’ decision ’ forwarder
```

**Data Flow**:
```
HttpRequest ’ DetectorRegistry ’ Signals ’ ReputationEngine ’ ProxyDecision
```

---

## Development Workflow (TDD)

WebSec strictly follows **Test-Driven Development** (Constitution Principle II).

### Red-Green-Refactor Cycle

#### 1. **RED**: Write Failing Test

```bash
# Create test file (if new feature)
touch tests/contract/my_detector_tests.rs
```

```rust
// tests/contract/my_detector_tests.rs
use websec::detectors::{MyDetector, Detector};
use websec::models::{HttpRequest, IpProfile, Signal};

#[tokio::test]
async fn test_my_detector_identifies_threat() {
    // Arrange
    let detector = MyDetector::new();
    let request = create_suspicious_request();
    let profile = IpProfile::new("192.0.2.1".parse().unwrap(), 100);

    // Act
    let signals = detector.analyze(&request, &profile).await;

    // Assert
    assert_eq!(signals.len(), 1);
    assert!(matches!(signals[0], Signal::MyThreat { .. }));
}
```

**Run test** (should fail):
```bash
cargo test test_my_detector_identifies_threat
# L Test fails: MyDetector not implemented
```

#### 2. **GREEN**: Implement Minimal Code

```rust
// src/detectors/my_detector.rs
use crate::models::{HttpRequest, IpProfile, Signal};
use async_trait::async_trait;

pub struct MyDetector;

impl MyDetector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Detector for MyDetector {
    async fn analyze(&self, request: &HttpRequest, _profile: &IpProfile) -> Vec<Signal> {
        // Minimal implementation to pass test
        if self.is_suspicious(request) {
            vec![Signal::MyThreat { weight: 20 }]
        } else {
            vec![]
        }
    }

    fn name(&self) -> &'static str {
        "MyDetector"
    }
}
```

**Run test** (should pass):
```bash
cargo test test_my_detector_identifies_threat
#  Test passes
```

#### 3. **REFACTOR**: Improve Code Quality

- Extract helper functions
- Improve naming
- Add documentation
- Optimize performance

```rust
impl MyDetector {
    /// Check if request exhibits suspicious pattern
    fn is_suspicious(&self, request: &HttpRequest) -> bool {
        // Refactored logic with clear naming
        self.matches_known_patterns(request)
            && !self.is_whitelisted_client(request)
    }

    fn matches_known_patterns(&self, request: &HttpRequest) -> bool {
        // ...
    }

    fn is_whitelisted_client(&self, request: &HttpRequest) -> bool {
        // ...
    }
}
```

**Run tests again** (ensure still passing):
```bash
cargo test
#  All tests pass
```

### Quality Checks Before Commit

```bash
# 1. Format code
cargo fmt

# 2. Run clippy (strict lints)
cargo clippy -- -D warnings

# 3. Run all tests
cargo test

# 4. Check for vulnerabilities
cargo audit

# 5. Build documentation
cargo doc --no-deps
```

**All must pass** before committing (enforced in CI).

---

## Contributing

### Workflow

1. **Create feature branch** (if not exists):
   ```bash
   git checkout -b 001-websec-proxy
   ```

2. **Make changes** following TDD workflow above.

3. **Commit** with conventional commit format:
   ```bash
   git add .
   git commit -m "feat(detector): ajouter détecteur de bots malveillants"
   ```

   **Commit format** (Constitution):
   - `type(scope): description` (en français)
   - Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`
   - **INTERDIT**: Aucune référence à des outils d'IA dans les commits

4. **Push changes**:
   ```bash
   git push origin 001-websec-proxy
   ```

5. **Open Pull Request** on GitHub.

### Code Review Checklist

Reviewers will verify:
-  Tests written **before** implementation (TDD)
-  All tests passing
-  Code coverage >80% on new code
-  Clippy warnings resolved
-  Code formatted with rustfmt
-  Documentation added (rustdoc `///`)
-  Design pattern documented (if applicable)
-  Security considerations addressed
-  No panics in production code

### Continuous Integration

GitHub Actions runs on every push:

```yaml
# .github/workflows/ci.yml
- cargo fmt --check
- cargo clippy -- -D warnings
- cargo test
- cargo audit
- cargo doc --no-deps
- cargo tarpaulin (coverage report)
```

**All checks must pass** before merge.

---

## Troubleshooting

### Common Issues

#### 1. **Redis Connection Failed**

**Error**:
```
Error: Redis error: Connection refused (os error 111)
```

**Solution**:
```bash
# Check Redis is running
sudo systemctl status redis-server

# Start Redis
sudo systemctl start redis-server

# Or use Docker
docker run -d -p 6379:6379 redis:7-alpine
```

#### 2. **GeoIP Database Not Found**

**Error**:
```
Error: GeoIP database not found: /usr/share/GeoIP/GeoLite2-City.mmdb
```

**Solution**:
```bash
# Download GeoLite2 database (requires MaxMind account)
# Or use test database for development

# Temporary: Disable geolocation in config
[geolocation]
enabled = false
```

#### 3. **Compilation Errors (Missing Dependencies)**

**Error**:
```
error: linker `cc` not found
```

**Solution (Linux)**:
```bash
sudo apt install build-essential
```

**Solution (macOS)**:
```bash
xcode-select --install
```

#### 4. **Tests Hanging on macOS**

**Issue**: tokio tests may hang on macOS with certain configurations.

**Solution**:
```bash
# Run tests single-threaded
cargo test -- --test-threads=1
```

#### 5. **Clippy Warnings**

**Error**:
```
warning: unused variable: `foo`
```

**Solution**:
```rust
// Prefix with underscore if intentionally unused
let _foo = 42;

// Or remove if truly not needed
```

#### 6. **Port Already in Use**

**Error**:
```
Error: Address already in use (os error 98)
```

**Solution**:
```bash
# Find process using port 8080
lsof -i :8080

# Kill process
kill -9 <PID>

# Or change port in websec.toml
[server]
listen = "127.0.0.1:8090"
```

### Getting Help

- **Documentation**: Check `docs/` directory
- **Spec Questions**: See `specs/001-websec-proxy/spec.md`
- **Architecture**: See `specs/001-websec-proxy/plan.md`
- **Data Model**: See `specs/001-websec-proxy/data-model.md`
- **Issues**: Open issue on GitHub
- **Discussions**: GitHub Discussions

---

## Performance Tips

### Fast Iteration During Development

```bash
# Use cargo-watch to auto-rebuild on changes
cargo watch -x check -x test

# Or with auto-run
cargo watch -x 'run -- --config websec.toml'
```

### Faster Compilation

```bash
# Enable incremental compilation (default in debug)
export CARGO_INCREMENTAL=1

# Use mold linker (Linux, much faster)
# Install: cargo install mold
# Add to .cargo/config.toml:
[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=mold"]
```

### Release Builds for Benchmarks

```bash
# Always use release mode for benchmarks
cargo bench

# Or manual release build
cargo build --release
./target/release/websec
```

---

## Next Steps

1.  **Setup complete** - You can now build and run WebSec
2. =Ö **Read the spec** - Understand requirements: `specs/001-websec-proxy/spec.md`
3. <× **Review architecture** - Study design: `specs/001-websec-proxy/plan.md`
4. =Ê **Understand data model** - Learn entities: `specs/001-websec-proxy/data-model.md`
5.  **Pick a task** - See task breakdown: `specs/001-websec-proxy/tasks.md`
6. =4 **Write tests first** - Follow TDD cycle (Red-Green-Refactor)
7. =š **Implement feature** - Make tests pass
8. =' **Refactor** - Improve code quality
9. =Ý **Document** - Add rustdoc comments
10. =€ **Open PR** - Submit for review

---

## Useful Commands Reference

```bash
# Build
cargo build                    # Debug build
cargo build --release          # Release build (optimized)
cargo check                    # Fast syntax check

# Test
cargo test                     # All tests
cargo test --lib               # Unit tests only
cargo test --test proxy_tests  # Specific integration test
cargo bench                    # Run benchmarks

# Quality
cargo fmt                      # Format code
cargo clippy                   # Lint code
cargo audit                    # Check vulnerabilities
cargo tarpaulin --out Html     # Coverage report

# Run
cargo run                      # Run with default config
cargo run -- --config custom.toml  # Custom config
RUST_LOG=debug cargo run       # Verbose logging

# Documentation
cargo doc --open               # Build and open docs
cargo doc --no-deps            # Docs without dependencies

# Clean
cargo clean                    # Remove build artifacts
```

---

**Quickstart Version**: 1.0.0
**Last Updated**: 2025-11-18
**Status**: Complete - Ready for developers

**Welcome to the WebSec project! Happy coding! >€=**
