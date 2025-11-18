# Implementation Plan: WebSec Proxy de Sécurité

**Branch**: `001-websec-proxy` | **Date**: 2025-11-18 | **Spec**: `/home/seb/Dev/websec/specs/001-websec-proxy/spec.md`
**Input**: Feature specification from `/home/seb/Dev/websec/specs/001-websec-proxy/spec.md`

**Note**: This plan follows the template at `.specify/templates/plan-template.md` and is filled by the `/speckit.plan` command.

## Summary

WebSec is a high-performance security reverse proxy written in Rust that intercepts all HTTP(S) requests before they reach backend web servers. It analyzes each request in real-time, calculates an IP reputation score based on 12 threat families (bots, brute force, injections, SSRF, session anomalies, etc.), and takes adaptive actions (allow, rate-limit, challenge, block) based on the computed score using the formula `Score = max(0, min(100, base - Σ(poids_signal)))` with exponential reputation recovery (24h half-life). The system operates transparently without requiring backend configuration, uses Token Bucket with sliding window rate limiting, and stores state in Redis with local L1 caching to achieve <5ms p95 latency at 10k+ req/s. Administration is performed via a CLI for whitelist/blacklist management, IP profile inspection, and live statistics monitoring.

## Technical Context

**Language/Version**: Rust 1.75+ (stable toolchain)
**Primary Dependencies**:
- HTTP framework: hyper 1.0 (async HTTP proxy implementation)
- Async runtime: tokio 1.35 (high-performance async executor)
- Storage: redis 0.24 with tokio support (reputation state)
- Rate limiting: governor 0.6 (token bucket implementation)
- Geolocation: maxminddb 0.24 (GeoIP2 database reader)
- Logging: tracing 0.1 + tracing-subscriber (structured logging)
- Metrics: prometheus 0.13 (observability)
- TLS: rustls 0.22 (if TLS termination enabled)
- Config: config 0.14 (TOML parsing)
- Testing: cargo test + criterion 0.5 (benchmarks) + tarpaulin (coverage)

**Storage**:
- Primary: Redis 7.0+ (centralized reputation state, L2 cache)
- Cache: In-memory LRU (L1 cache for <5ms latency)
- Fallback: File-based logs (degraded mode when Redis unavailable)

**Testing**:
- Unit: cargo test (logic métier >80% coverage)
- Integration: cargo test integration tests
- Contract: Contract tests for detectors and reputation engine
- Benchmarks: criterion (performance regression detection)
- Coverage: tarpaulin (>80% on business logic)

**Target Platform**: Linux x86_64 server (Ubuntu 22.04+, RHEL 8+)

**Project Type**: Single Rust project (binary with library crate)

**Performance Goals**:
- Throughput: 10,000+ req/s on 4 CPU cores
- Latency: <5ms p95, <2ms p50 for legitimate requests
- Memory: <512MB RAM for 100k tracked IPs
- Startup: <1s cold start, <100ms config reload

**Constraints**:
- Stateless architecture (horizontal scaling)
- Zero backend configuration (transparent deployment)
- Graceful degradation (continue without Redis)
- No panics in production (Result/Option only)
- Security: pass cargo audit, no hardcoded secrets

**Scale/Scope**:
- Support 100k+ concurrent tracked IPs
- Handle 12 threat families with 20+ signal types
- Process 1M+ req/day per instance
- Maintain <0.1% false positive rate

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Based on Constitution v1.1.0 (`/home/seb/Dev/websec/.specify/memory/constitution.md`):

### Rust-First (Principle I)
- **Status**: ✅ PASS
- **Evidence**: Language is Rust 1.75+ stable. All implementation in Rust.
- **Gate**: Use Rust stable toolchain, cargo as build system, exploit ownership/borrowing.

### TDD (Principle II)
- **Status**: ✅ PASS
- **Evidence**: Specification defines 13 user scenarios with acceptance criteria. Test structure planned in Phase 1 (contracts/). Implementation Phase 3 follows Red-Green-Refactor.
- **Gate**: Tests written first, user approval of test cases, coverage >80% on business logic, organized tests/ structure (unit/, integration/, contract/).

### Design Patterns & Architecture (Principle III)
- **Status**: ✅ PASS
- **Evidence**: Architecture uses Strategy (detectors), Repository (reputation storage), Factory (signal creation), Builder (configuration). Documented in research.md and data-model.md.
- **Gate**: Apply appropriate patterns, document choices in code comments, avoid anti-patterns, follow SOLID principles.

### Documentation Excellence (Principle IV)
- **Status**: ✅ PASS
- **Evidence**: Plan includes rustdoc requirements, README generation in Phase 1 (quickstart.md), inline comments for complex logic, security considerations documented.
- **Gate**: Rustdoc (`///`) for all public APIs, inline comments explaining "why", README with quickstart/architecture, security/threat model documentation, changelog.

### Quality Triad (Principle V)
- **Status**: ✅ PASS
- **Evidence**: CI pipeline includes clippy (strict), rustfmt, cargo audit. Benchmarks with criterion. Performance targets defined (<5ms p95, 10k req/s).
- **Gate**:
  - Quality: clippy strict, rustfmt, peer review
  - Security: cargo audit passing, input validation, least privilege, no hardcoded secrets
  - Performance: criterion benchmarks, profiling before optimization, document characteristics, consider Big-O

**Overall Constitution Compliance**: ✅ ALL GATES PASS

## Project Structure

### Documentation (this feature)

```text
specs/001-websec-proxy/
├── plan.md              # This file (/speckit.plan output)
├── research.md          # Phase 0: Technical decisions, library choices
├── data-model.md        # Phase 1: All entities (IpProfile, Signal, Detector, etc.)
├── quickstart.md        # Phase 1: Developer getting started guide
├── contracts/           # Phase 1: Contract test specifications
│   ├── detector-contracts.md
│   ├── reputation-engine-contracts.md
│   ├── ratelimiter-contracts.md
│   └── storage-contracts.md
└── tasks.md             # Phase 2: Generated by /speckit.tasks (NOT by this command)
```

### Source Code (repository root)

```text
websec/                    # Repository root
├── Cargo.toml             # Workspace root
├── Cargo.lock
├── .github/
│   └── workflows/
│       └── ci.yml         # Clippy, rustfmt, test, audit, coverage
├── README.md              # Project overview, quickstart
├── CHANGELOG.md           # Keep a Changelog format
├── websec.example.toml    # Example configuration
│
├── src/                   # Main binary crate
│   ├── main.rs            # Entry point: CLI parsing, server start
│   ├── config.rs          # Configuration loading (TOML)
│   ├── server.rs          # HTTP proxy server (hyper)
│   ├── cli.rs             # CLI commands (admin, stats, etc.)
│   │
│   ├── models/            # Domain entities
│   │   ├── mod.rs
│   │   ├── ip_profile.rs      # IpProfile entity
│   │   ├── signal.rs          # Signal types enum + metadata
│   │   ├── request.rs         # HttpRequest wrapper
│   │   ├── decision.rs        # ProxyDecision enum (Allow/Block/etc.)
│   │   └── reputation_score.rs # Score calculation
│   │
│   ├── detectors/         # Strategy pattern: 12 threat detectors
│   │   ├── mod.rs
│   │   ├── trait_detector.rs  # Detector trait
│   │   ├── bot_detector.rs
│   │   ├── bruteforce_detector.rs
│   │   ├── flood_detector.rs
│   │   ├── protocol_anomaly_detector.rs
│   │   ├── path_traversal_detector.rs
│   │   ├── upload_detector.rs
│   │   ├── injection_detector.rs
│   │   ├── vuln_scan_detector.rs
│   │   ├── host_header_detector.rs
│   │   ├── ssrf_detector.rs
│   │   ├── session_anomaly_detector.rs
│   │   └── tls_fingerprint_detector.rs
│   │
│   ├── reputation/        # Reputation engine
│   │   ├── mod.rs
│   │   ├── engine.rs          # Score aggregation, formula
│   │   ├── decay.rs           # Exponential decay (24h half-life)
│   │   └── weights.rs         # Signal weights config
│   │
│   ├── ratelimit/         # Rate limiting
│   │   ├── mod.rs
│   │   ├── token_bucket.rs    # Token bucket + sliding window
│   │   └── limiter.rs         # Per-IP rate limiter
│   │
│   ├── storage/           # Repository pattern: state persistence
│   │   ├── mod.rs
│   │   ├── trait_repository.rs # Repository trait
│   │   ├── redis_repository.rs # Redis implementation (L2)
│   │   ├── memory_cache.rs     # LRU cache (L1)
│   │   └── fallback_logs.rs    # File logs (degraded mode)
│   │
│   ├── geolocation/       # GeoIP lookup
│   │   ├── mod.rs
│   │   └── maxmind.rs         # MaxMind GeoIP2 reader
│   │
│   ├── proxy/             # HTTP proxy logic
│   │   ├── mod.rs
│   │   ├── handler.rs         # Request handler pipeline
│   │   ├── forwarder.rs       # Backend forwarding
│   │   └── response.rs        # Response generation (block/challenge)
│   │
│   ├── observability/     # Metrics + logging
│   │   ├── mod.rs
│   │   ├── metrics.rs         # Prometheus metrics
│   │   └── logging.rs         # Tracing setup
│   │
│   └── utils/             # Utilities
│       ├── mod.rs
│       ├── ip_utils.rs        # IP parsing, CIDR checks
│       └── patterns.rs        # Regex patterns (SQLi, XSS, etc.)
│
├── tests/                 # Integration & contract tests
│   ├── contract/          # Contract tests (TDD Phase 1)
│   │   ├── detector_tests.rs
│   │   ├── reputation_tests.rs
│   │   ├── ratelimit_tests.rs
│   │   └── storage_tests.rs
│   ├── integration/       # End-to-end tests
│   │   ├── proxy_tests.rs
│   │   ├── scenarios/
│   │   │   ├── bot_detection.rs
│   │   │   ├── bruteforce.rs
│   │   │   ├── flood.rs
│   │   │   └── injections.rs
│   │   └── cli_tests.rs
│   └── fixtures/          # Test data
│       ├── requests.json
│       └── geoip_test.mmdb
│
├── benches/               # Performance benchmarks
│   ├── detector_bench.rs
│   ├── reputation_bench.rs
│   └── proxy_bench.rs
│
└── docs/                  # Additional documentation
    ├── IDEA.md            # Original concept (existing)
    ├── Menaces.md         # Threat taxonomy (existing)
    ├── architecture.md    # System architecture diagrams
    └── deployment.md      # Production deployment guide
```

**Structure Decision**: Single Rust project structure selected. This is a monolithic binary with a library crate that can be imported for testing. The project follows Rust conventions with `src/` for implementation and `tests/` for integration/contract tests. The modular structure uses Strategy pattern for detectors, Repository pattern for storage, and clear separation of concerns across models, services, and infrastructure layers. This structure supports the constitution requirements for testability, maintainability, and clear pattern documentation.

## Complexity Tracking

> **No violations - all Constitution gates pass. This section is intentionally empty.**

## Phase 0: Research

**Objective**: Document all technical decisions with justification.

**Output**: `/home/seb/Dev/websec/specs/001-websec-proxy/research.md`

**Content**: Comprehensive research document covering:
1. HTTP proxy framework evaluation (hyper vs axum vs actix-web)
2. Redis client library selection
3. Rate limiting algorithm implementation (Token Bucket + Sliding Window)
4. Geolocation library (MaxMind GeoIP2)
5. Logging framework (tracing ecosystem)
6. Metrics framework (prometheus crate)
7. Testing strategy (cargo test + criterion + tarpaulin)
8. TLS library (rustls for optional TLS termination)
9. Configuration management (config crate + TOML)
10. Architecture patterns (Strategy, Repository, Factory, Builder)

**Status**: To be created by this command execution.

## Phase 1: Design

**Objective**: Create detailed design artifacts for TDD implementation.

**Outputs**:

### 1. Data Model (`data-model.md`)
Complete entity definitions for:
- `IpProfile`: IP reputation profile with score, signal history, metadata
- `Signal`: Typed events (20+ variants from 12 threat families)
- `HttpRequest`: Parsed request with all extractable attributes
- `ProxyDecision`: Decision enum (Allow/RateLimit/Challenge/Block)
- `ReputationScore`: Score calculation with formula and decay
- `Detector`: Trait for pluggable threat detectors
- `RateLimiter`: Token bucket state machine
- `Repository`: Storage abstraction for state persistence

### 2. Contracts (`contracts/`)
Contract test specifications defining behavioral contracts for:
- **Detector Contracts**: Each of 12 detectors with input/output scenarios
- **Reputation Engine Contracts**: Score calculation with exact formula verification
- **Rate Limiter Contracts**: Token bucket behavior under various scenarios
- **Storage Contracts**: Repository interface with Redis and fallback modes

### 3. Quickstart Guide (`quickstart.md`)
Developer onboarding document with:
- Prerequisites (Rust toolchain, Redis, GeoIP2 database)
- Build instructions (cargo build)
- Configuration (websec.toml example)
- Running locally (cargo run)
- Running tests (cargo test)
- Running benchmarks (cargo bench)
- Project structure walkthrough
- Contributing guidelines

**Status**: To be created by this command execution.

## Phase 2: Task Generation

**Objective**: Break design into actionable, dependency-ordered implementation tasks.

**Output**: `/home/seb/Dev/websec/specs/001-websec-proxy/tasks.md`

**Process**: Execute `/speckit.tasks` command (separate from this plan generation).

**Expected Structure**:
- Infrastructure setup (project, CI, dependencies)
- Core models implementation (test-driven)
- Detector implementation (12 detectors, each with tests first)
- Reputation engine (formula, decay, aggregation)
- Rate limiter (token bucket + sliding window)
- Storage layer (Redis + cache + fallback)
- Proxy server (request pipeline, forwarding)
- CLI (admin commands)
- Integration tests (13 user scenarios)
- Documentation (rustdoc, README)
- Performance tuning (benchmarks, profiling)

**Status**: NOT created by this command. Run `/speckit.tasks` after this plan.

## Phase 3: Implementation

**Objective**: Execute tasks following TDD Red-Green-Refactor cycle.

**Process**: Execute `/speckit.implement` command (separate from this plan generation).

**Workflow**:
1. For each task in `tasks.md`:
   - Red: Write failing test based on contract
   - Green: Implement minimal code to pass
   - Refactor: Improve design while keeping tests green
2. Run quality gates (clippy, rustfmt, audit)
3. Update documentation
4. Create commit following convention

**Status**: NOT started. Execute after Phase 2 task generation.

## Success Criteria

The implementation is complete when:

### Functional Completeness
- ✅ All 13 user scenarios pass acceptance tests
- ✅ All 12 threat detectors implemented and tested
- ✅ Reputation formula matches specification (exact formula with decay)
- ✅ Rate limiting works per specification (Token Bucket + Sliding Window)
- ✅ CLI provides all required commands (whitelist, stats, reload, etc.)
- ✅ Transparent deployment (zero backend configuration)

### Performance Targets (SC-003, SC-004, SC-014)
- ✅ <5ms p95 latency, <2ms p50 on legitimate requests
- ✅ 10k+ req/s on 4 CPU cores with <10% CPU usage
- ✅ <512MB RAM for 100k tracked IPs
- ✅ Stable latency (<10ms p99) under 20k req/s + attack load

### Detection Accuracy (SC-001, SC-002, SC-005, SC-006, SC-009-SC-013)
- ✅ 99% detection of known scanner User-Agents
- ✅ Brute force detected within 5 failed attempts
- ✅ <0.1% false positive rate
- ✅ 95% detection of SQL/XSS injection patterns
- ✅ 90% detection of TOR exit nodes (daily list update)
- ✅ 85% detection of webshell uploads
- ✅ 95% detection of path traversal
- ✅ 90% detection of SSRF attempts
- ✅ 80% detection of session hijacking (<5% false positives)

### Quality & Reliability (SC-008, SC-015, SC-016)
- ✅ >80% test coverage on business logic
- ✅ 24h continuous operation without memory leak (±5% stability)
- ✅ 99.9% uptime (graceful degradation when Redis unavailable)
- ✅ All clippy warnings resolved
- ✅ All rustfmt checks passing
- ✅ cargo audit passing (no known vulnerabilities)

### Operational Requirements (SC-017-SC-024)
- ✅ False positive correction <2 minutes via CLI
- ✅ 20+ Prometheus metrics exported
- ✅ 100% blocking decisions logged with full context
- ✅ 95% geolocation accuracy for public IPs
- ✅ CLI response <500ms for queries
- ✅ CLI modifications applied <100ms
- ✅ Zero backend configuration required (tested with Apache, Nginx, Caddy)
- ✅ Backend receives real client IP via X-Forwarded-For

### Constitution Compliance
- ✅ All code in Rust
- ✅ TDD cycle followed (tests before implementation)
- ✅ Design patterns documented (Strategy, Repository, Factory, Builder)
- ✅ Rustdoc complete for all public APIs
- ✅ Clippy strict mode passing
- ✅ Rustfmt applied
- ✅ cargo audit clean
- ✅ Benchmarks for critical paths
- ✅ No panics in production code

## Risk Mitigation

### Technical Risks

**Risk 1: Redis unavailability causing service disruption**
- Mitigation: Degraded mode with local detection + file logs
- Fallback: Continue processing without historical reputation
- Recovery: Automatic reconnection with exponential backoff

**Risk 2: Performance degradation under attack load**
- Mitigation: Early benchmarking in Phase 1
- Monitoring: Continuous profiling with criterion
- Optimization: Hot path optimization with zero-cost abstractions

**Risk 3: False positive rate exceeding 0.1% threshold**
- Mitigation: Extensive testing with real traffic patterns
- Tuning: Configurable weights per signal type
- Response: <2min correction via CLI whitelist

**Risk 4: Memory leaks with 100k+ tracked IPs**
- Mitigation: LRU cache with TTL expiration
- Testing: 24h stability tests in Phase 3
- Monitoring: Memory usage metrics in Prometheus

### Operational Risks

**Risk 5: Complex configuration leading to misconfiguration**
- Mitigation: Sensible defaults with minimal required config
- Validation: Config validation at startup with clear errors
- Documentation: Comprehensive examples in quickstart.md

**Risk 6: Difficult debugging of false positives**
- Mitigation: Comprehensive logging with structured context
- Tooling: CLI commands for IP profile inspection
- Tracing: Request IDs for end-to-end tracing

## Dependencies & Prerequisites

### Development Environment
- Rust 1.75+ (stable toolchain)
- cargo, rustc, rustfmt, clippy
- Redis 7.0+ (for local testing)
- MaxMind GeoIP2 database (GeoLite2-City.mmdb)

### CI/CD Requirements
- GitHub Actions (already available)
- Rust CI pipeline (cargo commands)
- Code coverage reporting (tarpaulin)
- Benchmark tracking (criterion)

### External Dependencies
- Redis server (production deployment)
- GeoIP2 database subscription (production)
- TLS certificates (if terminating TLS)

### Team Knowledge
- Rust async programming (tokio)
- HTTP protocol internals
- Security threat landscape
- Performance optimization techniques

## Next Steps

1. ✅ **Phase 0 Complete**: Review and approve `research.md`
2. ✅ **Phase 1 Complete**: Review and approve design artifacts (`data-model.md`, `contracts/`, `quickstart.md`)
3. ⏭️ **Phase 2 Start**: Execute `/speckit.tasks` to generate `tasks.md`
4. ⏭️ **Phase 3 Start**: Execute `/speckit.implement` to begin TDD implementation
5. ⏭️ **Validation**: Run full test suite and benchmarks
6. ⏭️ **Deployment**: Create deployment guide and production configuration

---

**Plan Version**: 1.0.0
**Last Updated**: 2025-11-18
**Approved By**: [Pending]
**Status**: Phase 0 & Phase 1 artifacts generated, ready for Phase 2
