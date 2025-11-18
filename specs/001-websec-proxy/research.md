# Phase 0: Technical Research

**Feature**: WebSec Proxy de Sécurité
**Branch**: `001-websec-proxy`
**Date**: 2025-11-18
**Status**: Complete

## Overview

This document records all technical decisions and research outcomes for the WebSec proxy implementation. Each decision is justified based on performance requirements (<5ms p95 latency, 10k+ req/s), constitution principles (Rust-first, TDD, patterns), and operational needs (transparency, observability, maintainability).

## 1. HTTP Proxy Framework

### Requirement
Build a high-performance reverse proxy that intercepts HTTP(S) requests, analyzes them, and forwards to backend servers with <5ms p95 latency at 10k+ req/s.

### Options Evaluated

#### Option 1: hyper 1.0 (SELECTED)
- **Pros**:
  - Pure HTTP library, full control over request/response pipeline
  - Excellent performance (zero-copy where possible)
  - Mature async/await support with tokio integration
  - Direct access to raw headers and body streams
  - Lower-level control for custom inspection logic
  - Battle-tested in production (used by AWS, Cloudflare)
- **Cons**:
  - More boilerplate for request routing
  - Manual handling of connection pooling
- **Performance**: 50k+ req/s single core, <1ms overhead
- **Justification**: Maximum control needed for deep packet inspection, custom header manipulation, and transparent forwarding

#### Option 2: axum 0.7
- **Pros**:
  - Ergonomic routing and middleware
  - Built on hyper + tokio
  - Excellent ecosystem integration
- **Cons**:
  - Higher-level abstractions reduce inspection flexibility
  - Extra layers for simple forwarding use case
  - Routing overhead not needed (single forward target)
- **Performance**: Slightly slower than raw hyper
- **Rejection reason**: WebSec is not a traditional API server with routes - it's a transparent proxy that needs direct HTTP control

#### Option 3: actix-web 4.0
- **Pros**:
  - Very fast (benchmarks well)
  - Rich middleware ecosystem
- **Cons**:
  - Uses actix actor system (different async runtime)
  - Less direct hyper integration
  - Opinionated structure less suitable for proxy
- **Performance**: Excellent for APIs, but proxy use case differs
- **Rejection reason**: Tokio standardization preferred for ecosystem compatibility; actor model adds complexity for our use case

### Decision: hyper 1.0
**Rationale**: Direct control over HTTP primitives essential for transparent proxying. Hyper provides the foundation without imposing unnecessary routing/framework overhead. Aligns with constitution principle of justified complexity.

### Implementation Notes
```rust
// Key hyper usage patterns
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, Body};

// Custom service for each connection
async fn proxy_service(req: Request<Body>) -> Result<Response<Body>, Error> {
    // 1. Extract & analyze request
    // 2. Calculate reputation
    // 3. Make decision
    // 4. Forward or block
}
```

## 2. Redis Client Library

### Requirement
High-performance Redis client for storing IP reputation state with <2ms p95 Redis latency, connection pooling, automatic reconnection, and async tokio support.

### Options Evaluated

#### Option 1: redis 0.24 with tokio feature (SELECTED)
- **Pros**:
  - Official Rust Redis client
  - Full tokio async support
  - Connection pooling via ConnectionManager
  - Automatic reconnection with backoff
  - Pipeline and transaction support
  - Comprehensive command coverage
  - Well-maintained, active development
- **Cons**:
  - Slightly verbose API for complex operations
- **Performance**: Sub-millisecond latency for simple operations
- **Justification**: Industry standard, proven reliability, excellent async support

#### Option 2: deadpool-redis 0.14
- **Pros**:
  - Connection pool management
  - Built on redis crate
  - Good for high concurrency
- **Cons**:
  - Extra dependency layer
  - ConnectionManager in redis crate often sufficient
- **Rejection reason**: redis::ConnectionManager provides adequate pooling without extra dependency

#### Option 3: fred 7.0
- **Pros**:
  - Modern async-first design
  - Automatic cluster support
- **Cons**:
  - Less mature than redis crate
  - Smaller community
  - Potential stability concerns
- **Rejection reason**: redis crate more battle-tested and widely adopted

### Decision: redis 0.24 with tokio feature
**Rationale**: Official client with proven reliability. ConnectionManager handles pooling and reconnection. Meets all performance and reliability requirements (NFR-013 degraded mode, NFR-004 stateless).

### Implementation Notes
```rust
use redis::{Client, AsyncCommands, RedisResult};
use redis::aio::ConnectionManager;

// Configuration
let client = Client::open("redis://127.0.0.1/")?;
let manager = ConnectionManager::new(client).await?;

// Usage with error handling for degraded mode
match manager.get::<_, String>(&key).await {
    Ok(value) => { /* use cached reputation */ },
    Err(_) => { /* enter degraded mode (FR-013) */ }
}
```

## 3. Rate Limiting Algorithm

### Requirement
Implement Token Bucket with sliding window (clarification answer) supporting adaptive rate limits based on reputation score. Must handle 10k req/s with minimal CPU overhead.

### Algorithm: Token Bucket + Sliding Window (HYBRID)

#### Core Mechanism: Token Bucket
- **Capacity**: Maximum burst size (e.g., 100 tokens)
- **Refill rate**: Tokens per second (e.g., 10 tokens/sec)
- **Operation**: Each request consumes 1 token. If tokens available, allow; else, rate limit.

#### Enhancement: Sliding Window Counter
- **Purpose**: Prevent "gaming" at bucket refill boundaries
- **Mechanism**: Track request count in rolling time windows (e.g., last 60 seconds)
- **Check**: Enforce max requests per window even if tokens available

#### Adaptive Rates Based on Reputation
```
Score 100-80: 1000 req/min (normal traffic)
Score 79-50:  200 req/min (suspicious, rate-limited)
Score 49-20:  50 req/min (aggressive rate-limiting)
Score <20:    0 req/min (blocked)
```

### Implementation Library

#### Option 1: governor 0.6 (SELECTED)
- **Pros**:
  - Pure token bucket implementation
  - Generic Cell Rate Algorithm (GCRA) variant
  - High performance (lock-free in hot path)
  - Built-in support for per-key limits
  - Excellent for per-IP rate limiting
- **Cons**:
  - Doesn't include sliding window (we add this)
- **Justification**: Best performance for token bucket core; we layer sliding window on top

#### Option 2: Custom implementation
- **Pros**:
  - Full control over hybrid algorithm
  - Optimize for exact use case
- **Cons**:
  - Risk of bugs in critical security component
  - Time investment vs proven library
- **Rejection reason**: Governor provides well-tested token bucket; we add sliding window tracking in reputation profile

### Decision: governor 0.6 + custom sliding window
**Rationale**: Use proven library for token bucket core (avoiding security bugs), extend with sliding window logic in reputation engine. Balances safety with requirement for hybrid approach.

### Implementation Notes
```rust
use governor::{Quota, RateLimiter, Jaffar};
use std::num::NonZeroU32;

// Per-IP rate limiter
let quota = Quota::per_second(NonZeroU32::new(10).unwrap());
let limiter = RateLimiter::direct(quota);

// Check in request handler
if limiter.check().is_ok() {
    // Additionally check sliding window
    let window_count = profile.requests_in_window(60); // last 60 sec
    if window_count < threshold_for_score(profile.score) {
        // Allow
    } else {
        // Rate limit (sliding window exceeded)
    }
} else {
    // Rate limit (token bucket exhausted)
}
```

## 4. Geolocation Library

### Requirement
Fast IP geolocation for country/region detection with <1ms lookup latency. Support for penalty-by-geography (FR-012). Must work offline (no API calls).

### Options Evaluated

#### Option 1: maxminddb 0.24 (SELECTED)
- **Pros**:
  - Pure Rust MaxMind DB reader
  - Memory-mapped file (very fast lookups)
  - Supports GeoIP2 and GeoLite2 databases
  - Zero network calls (offline operation)
  - 95%+ accuracy on public IPs (SC-020)
  - Widely used in production
- **Cons**:
  - Requires periodic database updates (cron job)
  - Database file size (~70MB for GeoLite2-City)
- **Performance**: <100μs per lookup (memory-mapped)
- **Justification**: Industry standard, excellent performance, offline operation

#### Option 2: ip2location-rust
- **Pros**:
  - Alternative commercial database
  - Similar performance characteristics
- **Cons**:
  - Less widespread adoption
  - Commercial licensing concerns
  - Smaller Rust ecosystem support
- **Rejection reason**: MaxMind more established, GeoLite2 free tier available

#### Option 3: geoip2 (C bindings)
- **Pros**:
  - Official MaxMind library
- **Cons**:
  - C FFI overhead
  - Unsafe code considerations
  - Pure Rust alternative exists (maxminddb)
- **Rejection reason**: Pure Rust preferred per constitution (safety guarantees)

### Decision: maxminddb 0.24
**Rationale**: Best performance with pure Rust safety. GeoLite2 database provides free tier for development and small deployments. Memory-mapped reads meet <1ms requirement easily.

### Implementation Notes
```rust
use maxminddb::{Reader, geoip2};
use std::net::IpAddr;

// Load database (once at startup)
let reader = Reader::open_readfile("GeoLite2-City.mmdb")?;

// Lookup (per request)
let ip: IpAddr = "8.8.8.8".parse()?;
let city: geoip2::City = reader.lookup(ip)?;

let country_code = city.country
    .and_then(|c| c.iso_code)
    .unwrap_or("UNKNOWN");

// Apply penalty based on geography (FR-012)
let geo_penalty = calculate_geo_penalty(country_code);
```

## 5. Logging Framework

### Requirement
Structured logging with JSON output (FR-018), tracing for debugging, minimal performance overhead, integration with async tokio runtime.

### Options Evaluated

#### Option 1: tracing + tracing-subscriber (SELECTED)
- **Pros**:
  - Modern structured logging and tracing
  - Spans for request context propagation
  - Excellent async support
  - JSON formatting via tracing-subscriber
  - Low overhead (compile-time filtering)
  - Rich ecosystem (tracing-appender, tracing-log bridge)
  - De facto standard in async Rust
- **Cons**:
  - Slightly steeper learning curve than log crate
- **Performance**: <1μs per log statement with filtering
- **Justification**: Best for async systems, spans enable request tracing (SC-019 full context)

#### Option 2: slog
- **Pros**:
  - Structured logging pioneer in Rust
  - Very flexible
- **Cons**:
  - More boilerplate
  - Less ergonomic with async
  - Smaller ecosystem vs tracing
- **Rejection reason**: tracing better async integration, modern standard

#### Option 3: env_logger + log
- **Pros**:
  - Simple API
  - Lightweight
- **Cons**:
  - Unstructured by default
  - No span/context tracking
  - Basic JSON support
- **Rejection reason**: Structured logging required (FR-018), span tracking useful for debugging

### Decision: tracing 0.1 + tracing-subscriber
**Rationale**: Industry standard for async Rust. Spans enable end-to-end request tracing. JSON formatting meets FR-018. Excellent performance with compile-time filtering.

### Implementation Notes
```rust
use tracing::{info, warn, error, instrument};
use tracing_subscriber::{fmt, EnvFilter};

// Setup (main.rs)
tracing_subscriber::fmt()
    .json() // FR-018: JSON structured output
    .with_env_filter(EnvFilter::from_default_env())
    .init();

// Usage with spans for context
#[instrument(skip(request), fields(ip = %request.ip, path = %request.path))]
async fn handle_request(request: HttpRequest) -> ProxyDecision {
    info!("Processing request");
    let decision = make_decision(&request).await;

    // FR-016: Log all blocking decisions with context
    if matches!(decision, ProxyDecision::Block) {
        warn!(
            score = request.reputation.score,
            signals = ?request.reputation.signals,
            reason = %decision.reason(),
            "Blocked request"
        );
    }

    decision
}
```

## 6. Metrics Framework

### Requirement
Prometheus-compatible metrics export (SC-018: 20+ metrics), low overhead (<0.5% CPU), counters/gauges/histograms support.

### Options Evaluated

#### Option 1: prometheus 0.13 (SELECTED)
- **Pros**:
  - Official Rust Prometheus client
  - All metric types (Counter, Gauge, Histogram, Summary)
  - Efficient implementation (lock-free where possible)
  - Easy HTTP endpoint integration
  - Standard exposition format
- **Cons**:
  - Global registry can be awkward in some patterns
- **Performance**: <100ns per metric update
- **Justification**: Official client, proven production use, meets SC-018

#### Option 2: metrics + metrics-exporter-prometheus
- **Pros**:
  - Facade pattern (backend-agnostic)
  - Modern API design
- **Cons**:
  - Extra abstraction layer
  - Less mature than prometheus crate
  - Unnecessary flexibility for our use case
- **Rejection reason**: Direct Prometheus client sufficient, simpler

#### Option 3: Custom implementation
- **Pros**:
  - Minimal dependencies
- **Cons**:
  - Reinventing well-solved problem
  - Risk of incorrect exposition format
  - No performance benefit
- **Rejection reason**: Unjustified complexity (constitution principle)

### Decision: prometheus 0.13
**Rationale**: Official client with proven reliability. Simple integration. Meets SC-018 requirement for 20+ metrics. Zero-cost abstractions align with Rust philosophy.

### Implementation Notes
```rust
use prometheus::{
    Counter, Gauge, Histogram, HistogramOpts, Registry, Encoder, TextEncoder
};
use lazy_static::lazy_static;

lazy_static! {
    // SC-018: 20+ metrics
    pub static ref REQUESTS_TOTAL: Counter = Counter::new(
        "websec_requests_total", "Total HTTP requests"
    ).unwrap();

    pub static ref REQUESTS_BLOCKED: Counter = Counter::new(
        "websec_requests_blocked_total", "Blocked requests"
    ).unwrap();

    pub static ref REQUEST_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new("websec_request_duration_seconds", "Request latency")
            .buckets(vec![0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1])
    ).unwrap();

    pub static ref REPUTATION_SCORE: Histogram = Histogram::with_opts(
        HistogramOpts::new("websec_reputation_score", "IP reputation scores")
            .buckets(vec![0.0, 20.0, 40.0, 60.0, 80.0, 100.0])
    ).unwrap();

    // ... 16+ more metrics
}

// HTTP endpoint: GET /metrics
async fn metrics_handler() -> Response<Body> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    Response::new(Body::from(buffer))
}
```

## 7. Testing Strategy

### Requirement
TDD with >80% coverage (NFR-009), unit/integration/contract tests, performance regression detection, constitution compliance (Principle II).

### Framework: cargo test (SELECTED)

#### Rationale
- Built into Rust toolchain (no extra dependency)
- Fast parallel execution
- Excellent IDE integration
- Standard in Rust ecosystem

#### Test Organization

```
tests/
├── contract/          # Contract tests (TDD Phase 1)
│   ├── detector_tests.rs      # Each detector's behavioral contract
│   ├── reputation_tests.rs    # Score calculation verification
│   ├── ratelimit_tests.rs     # Token bucket + sliding window
│   └── storage_tests.rs       # Repository interface compliance
├── integration/       # End-to-end tests
│   ├── proxy_tests.rs         # Full request pipeline
│   ├── scenarios/             # 13 user scenarios from spec
│   │   ├── bot_detection.rs
│   │   ├── bruteforce.rs
│   │   ├── flood.rs
│   │   ├── injections.rs
│   │   ├── path_traversal.rs
│   │   ├── uploads.rs
│   │   ├── ssrf.rs
│   │   ├── session_anomaly.rs
│   │   └── ...
│   └── cli_tests.rs
└── fixtures/          # Test data
    ├── requests.json
    └── geoip_test.mmdb
```

### Coverage: tarpaulin 0.27

#### Option 1: tarpaulin (SELECTED)
- **Pros**:
  - Rust-specific coverage tool
  - Line and branch coverage
  - Accurate results (unlike gcov hacks)
  - CI integration (Codecov, Coveralls)
- **Cons**:
  - Linux-only (acceptable for CI)
- **Justification**: Best Rust coverage tool, meets NFR-009 (>80%)

#### Option 2: llvm-cov
- **Pros**:
  - Part of LLVM toolchain
  - Cross-platform
- **Cons**:
  - More setup complexity
  - Less Rust-specific
- **Rejection reason**: tarpaulin more turnkey for Rust

### Decision: cargo test + tarpaulin
**Rationale**: Standard Rust testing with specialized coverage tool. Meets constitution TDD requirements. Clear test organization by type.

### Benchmarks: criterion 0.5

#### Requirement
Performance regression detection for critical paths (Principle V: Performance).

#### Framework: criterion (SELECTED)
- **Pros**:
  - Statistical analysis of benchmark results
  - Regression detection
  - HTML reports with plots
  - Comparison across runs
- **Cons**:
  - Slower than raw benches (due to statistics)
- **Performance**: Accurate microsecond-level measurements
- **Justification**: Detect regressions in detector performance, reputation calculation, proxy forwarding

#### Usage
```rust
// benches/detector_bench.rs
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_bot_detector(c: &mut Criterion) {
    let detector = BotDetector::new();
    let request = create_test_request();

    c.bench_function("bot_detector", |b| {
        b.iter(|| detector.analyze(&request))
    });
}

criterion_group!(detectors, bench_bot_detector);
criterion_main!(detectors);
```

## 8. TLS Library

### Requirement
Optional TLS termination (FR-030: JA3 fingerprinting). Must use validated cryptographic libraries (NFR-007). Performance <2ms TLS handshake overhead.

### Options Evaluated

#### Option 1: rustls 0.22 (SELECTED)
- **Pros**:
  - Pure Rust TLS 1.3/1.2 implementation
  - Memory-safe (no C dependencies)
  - Excellent performance
  - Modern ciphersuite support
  - ring for cryptographic primitives (NFR-007)
  - No OpenSSL baggage
  - Actively maintained
- **Cons**:
  - Less battle-tested than OpenSSL (but maturing rapidly)
- **Performance**: ~1ms handshake overhead on modern CPU
- **Justification**: Pure Rust aligns with constitution, excellent security posture

#### Option 2: native-tls (OpenSSL)
- **Pros**:
  - Wraps system TLS (OpenSSL/Schannel/Secure Transport)
  - Maximum compatibility
  - Decades of battle-testing
- **Cons**:
  - C dependencies (unsafe, CVE history)
  - Platform-dependent behavior
  - Contradicts Rust-first principle
- **Rejection reason**: Constitution Principle I (Rust-first), unsafe C code

#### Option 3: boring-tls (BoringSSL)
- **Pros**:
  - Google's OpenSSL fork
  - Used in Chrome
- **Cons**:
  - Still C code
  - Complex build process
- **Rejection reason**: Same as native-tls (C dependencies)

### Decision: rustls 0.22
**Rationale**: Only pure Rust option. Aligns with constitution Principle I. Uses validated crypto (ring). Performance meets requirements. Enables JA3 fingerprinting via TLS inspection (FR-030).

### Implementation Notes
```rust
use rustls::{ServerConfig, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

// Optional TLS termination
if config.tls_enabled {
    let certs = load_certs(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;

    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Accept TLS connections
    let tls_stream = acceptor.accept(tcp_stream).await?;

    // FR-030: Extract JA3 fingerprint for suspicious client detection
    let ja3 = compute_ja3_fingerprint(&tls_stream.client_hello());
}
```

## 9. Configuration Management

### Requirement
TOML configuration file (FR-019), hot reload without downtime (FR-020, SC-007: <100ms), validation at startup, sensible defaults.

### Options Evaluated

#### Option 1: config 0.14 (SELECTED)
- **Pros**:
  - Multiple format support (TOML, YAML, JSON, etc.)
  - Environment variable overlay
  - Hierarchical configuration
  - Type-safe deserialization (serde)
  - Configuration merging
- **Cons**:
  - Slightly heavyweight for simple cases
- **Justification**: Flexible, type-safe, standard in Rust ecosystem

#### Option 2: toml 0.8
- **Pros**:
  - Minimal, just TOML parsing
  - Direct serde integration
- **Cons**:
  - No environment variable overlay
  - No hot reload support built-in
  - Manual file watching needed
- **Rejection reason**: config crate provides more features we need

#### Option 3: figment 0.10
- **Pros**:
  - Very ergonomic API
  - Provider-based architecture
- **Cons**:
  - Less mature than config
  - Smaller community
- **Rejection reason**: config more established, adequate for needs

### Decision: config 0.14
**Rationale**: Type-safe configuration with serde. Environment overlays useful for deployment. We implement hot reload with file watcher (notify crate).

### Implementation Notes
```rust
use config::{Config, File, Environment};
use serde::{Deserialize, Serialize};
use notify::{Watcher, RecursiveMode, watcher};

#[derive(Debug, Deserialize, Serialize)]
pub struct WebSecConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    #[serde(default = "default_backend")]
    pub backend_url: String,

    pub redis_url: String,
    pub geoip_db_path: String,

    #[serde(default)]
    pub reputation: ReputationConfig,

    #[serde(default)]
    pub rate_limits: RateLimitConfig,
}

fn default_bind_addr() -> String { "127.0.0.1:8080".to_string() }
fn default_backend() -> String { "http://127.0.0.1:8081".to_string() }

// Load configuration
pub fn load_config() -> Result<WebSecConfig, config::ConfigError> {
    let config = Config::builder()
        .add_source(File::with_name("websec").required(false))
        .add_source(Environment::with_prefix("WEBSEC"))
        .build()?;

    config.try_deserialize()
}

// FR-020: Hot reload with file watcher (SC-007: <100ms)
pub async fn watch_config_changes(config_path: &Path) {
    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::from_secs(1)).unwrap();
    watcher.watch(config_path, RecursiveMode::NonRecursive).unwrap();

    while let Ok(event) = rx.recv() {
        match event {
            DebouncedEvent::Write(_) => {
                // Reload config
                let new_config = load_config()?;
                // Apply atomically (Arc<RwLock<Config>>)
                update_config(new_config).await;
                info!("Configuration reloaded");
            }
            _ => {}
        }
    }
}
```

## 10. Architecture Patterns

### Requirement
Clean architecture with documented patterns (Principle III), SOLID principles, testability, maintainability.

### Pattern Decisions

#### Strategy Pattern: Detectors (SELECTED)
**Usage**: 12 threat detectors implementing common `Detector` trait.

**Justification**:
- Plug-and-play detectors (easy to add new threats)
- Isolated testing per detector
- Clear separation of concerns
- SOLID: Open/Closed Principle

**Implementation**:
```rust
#[async_trait]
pub trait Detector: Send + Sync {
    /// Analyze request and generate signals
    async fn analyze(&self, request: &HttpRequest, profile: &IpProfile)
        -> Vec<Signal>;

    /// Detector name for logging/metrics
    fn name(&self) -> &'static str;
}

// Concrete implementations
pub struct BotDetector { /* ... */ }
pub struct BruteForceDetector { /* ... */ }
pub struct InjectionDetector { /* ... */ }
// ... 9 more

// Usage in pipeline
let detectors: Vec<Box<dyn Detector>> = vec![
    Box::new(BotDetector::new()),
    Box::new(BruteForceDetector::new()),
    // ...
];

let mut signals = Vec::new();
for detector in &detectors {
    signals.extend(detector.analyze(&request, &profile).await);
}
```

#### Repository Pattern: Storage (SELECTED)
**Usage**: Abstract storage layer for IP reputation state.

**Justification**:
- Swap implementations (Redis, in-memory, file) without changing business logic
- Easy mocking for tests
- SOLID: Dependency Inversion Principle
- Enables degraded mode (FR-013)

**Implementation**:
```rust
#[async_trait]
pub trait ReputationRepository: Send + Sync {
    async fn get_profile(&self, ip: IpAddr) -> Result<Option<IpProfile>>;
    async fn save_profile(&self, ip: IpAddr, profile: IpProfile) -> Result<()>;
    async fn delete_profile(&self, ip: IpAddr) -> Result<()>;
}

// Implementations
pub struct RedisRepository { /* ... */ }        // Primary
pub struct MemoryCacheRepository { /* ... */ }  // L1 cache
pub struct FallbackFileRepository { /* ... */ } // Degraded mode

// Layered repository (L1 cache + L2 Redis + L3 fallback)
pub struct LayeredRepository {
    l1_cache: Arc<MemoryCacheRepository>,
    l2_redis: Arc<RedisRepository>,
    l3_fallback: Arc<FallbackFileRepository>,
}

impl LayeredRepository {
    async fn get_profile(&self, ip: IpAddr) -> Result<Option<IpProfile>> {
        // Try L1 cache
        if let Some(profile) = self.l1_cache.get_profile(ip).await? {
            return Ok(Some(profile));
        }

        // Try L2 Redis
        match self.l2_redis.get_profile(ip).await {
            Ok(Some(profile)) => {
                // Populate L1 cache
                self.l1_cache.save_profile(ip, profile.clone()).await?;
                Ok(Some(profile))
            }
            Ok(None) => Ok(None),
            Err(_) => {
                // Redis failed: try L3 fallback (degraded mode)
                self.l3_fallback.get_profile(ip).await
            }
        }
    }
}
```

#### Factory Pattern: Signal Creation (SELECTED)
**Usage**: Create typed signals from detection results.

**Justification**:
- Centralized signal creation logic
- Type safety (enum variants)
- Easy extension for new signal types

**Implementation**:
```rust
pub enum Signal {
    // 20+ variants from 12 threat families
    SuspiciousUserAgent { user_agent: String, weight: i32 },
    SqlInjectionAttempt { payload: String, weight: i32 },
    Flooding { requests_per_sec: f64, weight: i32 },
    SessionHijackingSuspected { session_id: String, weight: i32 },
    // ...
}

impl Signal {
    pub fn weight(&self) -> i32 {
        match self {
            Signal::SuspiciousUserAgent { weight, .. } => *weight,
            Signal::SqlInjectionAttempt { weight, .. } => *weight,
            // ...
        }
    }

    pub fn is_irremissible(&self) -> bool {
        // FR-005-bis: No automatic recovery for severe signals
        matches!(self,
            Signal::PotentialWebshellUpload { .. } |
            Signal::RceAttempt { .. } |
            Signal::CredentialStuffing { .. }
        )
    }
}

// Factory methods
impl Signal {
    pub fn suspicious_user_agent(user_agent: String) -> Self {
        Signal::SuspiciousUserAgent {
            user_agent,
            weight: 15, // Configurable
        }
    }

    pub fn sql_injection(payload: String) -> Self {
        Signal::SqlInjectionAttempt {
            payload,
            weight: 40, // High severity
        }
    }
}
```

#### Builder Pattern: Configuration (SELECTED)
**Usage**: Construct complex configuration objects.

**Justification**:
- Many optional parameters
- Sensible defaults
- Type-safe construction

**Implementation**:
```rust
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    pub base_score: i32,
    pub decay_half_life_hours: u32,
    pub signal_correlation_bonus: i32,
    pub weights: HashMap<String, i32>,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            base_score: 100,
            decay_half_life_hours: 24,
            signal_correlation_bonus: 10,
            weights: default_signal_weights(),
        }
    }
}

pub struct ReputationConfigBuilder {
    config: ReputationConfig,
}

impl ReputationConfigBuilder {
    pub fn new() -> Self {
        Self { config: ReputationConfig::default() }
    }

    pub fn base_score(mut self, score: i32) -> Self {
        self.config.base_score = score;
        self
    }

    pub fn decay_half_life(mut self, hours: u32) -> Self {
        self.config.decay_half_life_hours = hours;
        self
    }

    pub fn signal_weight(mut self, signal: &str, weight: i32) -> Self {
        self.config.weights.insert(signal.to_string(), weight);
        self
    }

    pub fn build(self) -> ReputationConfig {
        self.config
    }
}

// Usage
let config = ReputationConfigBuilder::new()
    .base_score(100)
    .decay_half_life(24)
    .signal_weight("SqlInjectionAttempt", 50)
    .build();
```

### Anti-Patterns to Avoid (Constitution Principle III)

1. **God Object**: Don't put all logic in one massive struct
   - Solution: Separate detectors, reputation engine, rate limiter, storage

2. **Circular Dependencies**: Modules importing each other
   - Solution: Clear layered architecture (models -> detectors -> reputation -> proxy)

3. **Tight Coupling**: Concrete types everywhere
   - Solution: Traits for abstraction (Detector, Repository)

4. **Premature Optimization**: Optimizing before measuring
   - Solution: Benchmark first (criterion), profile, then optimize

## Summary

All technical decisions documented and justified. Selected libraries and patterns align with:

- **Constitution Principle I (Rust-First)**: All libraries pure Rust or essential dependencies (Redis protocol)
- **Constitution Principle II (TDD)**: Test framework and structure planned (cargo test, tarpaulin, criterion)
- **Constitution Principle III (Patterns)**: Strategy, Repository, Factory, Builder patterns selected and justified
- **Constitution Principle IV (Documentation)**: rustdoc, tracing for observability, structured logging
- **Constitution Principle V (Quality Triad)**:
  - Quality: clippy, rustfmt planned
  - Security: rustls (validated crypto), cargo audit, input validation
  - Performance: criterion benchmarks, async tokio, zero-copy where possible

### Key Dependency Summary

```toml
[dependencies]
# Core
hyper = { version = "1.0", features = ["full"] }
tokio = { version = "1.35", features = ["full"] }

# Storage
redis = { version = "0.24", features = ["tokio-comp"] }

# Rate limiting
governor = "0.6"

# Geolocation
maxminddb = "0.24"

# Observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
prometheus = "0.13"

# TLS (optional)
rustls = "0.22"
tokio-rustls = "0.25"

# Configuration
config = "0.14"
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"

# Utilities
async-trait = "0.1"
thiserror = "1.0"
lazy_static = "1.4"

[dev-dependencies]
criterion = { version = "0.5", features = ["async_tokio"] }
tarpaulin = "0.27"
```

### Performance Budget Allocation

Based on <5ms p95 latency target:

- Network I/O (receive + send): ~1.5ms
- Detection pipeline (12 detectors): ~1.0ms
- Reputation lookup (L1 cache hit): ~0.1ms
- Rate limit check: ~0.05ms
- Backend forwarding: ~1.5ms
- Overhead/margin: ~0.85ms

**Total**: ~5ms (meeting SC-003 requirement)

### Next Phase

Phase 1 (Design) ready to begin:
- data-model.md: Define all entities with Rust struct signatures
- contracts/: Write behavioral contracts for TDD
- quickstart.md: Developer onboarding guide

---

**Research Status**: ✅ COMPLETE
**Approved By**: [Pending]
**Date**: 2025-11-18
