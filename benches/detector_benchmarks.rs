//! Benchmarks pour les détecteurs de menaces
//!
//! Mesure les performances des détecteurs individuels et du registry complet.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::{
    BotDetector, BruteForceDetector, Detector, DetectorRegistry, FloodDetector,
    GeoDetector, HeaderDetector, HttpRequestContext, InjectionDetector,
    ProtocolDetector, ScanDetector, SessionDetector,
};

fn create_normal_request() -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.100").unwrap(),
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        query: Some("page=1&limit=10".to_string()),
        headers: vec![
            ("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: Some(b"{\"username\":\"john\"}".to_vec()),
        user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
        referer: Some("https://example.com/login".to_string()),
        content_type: Some("application/json".to_string()),
    }
}

fn create_malicious_request() -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str("1.2.3.4").unwrap(),
        method: "POST".to_string(),
        path: "/../../etc/passwd".to_string(),
        query: Some("id=1' OR '1'='1".to_string()),
        headers: vec![
            ("User-Agent".to_string(), "sqlmap/1.0".to_string()),
            ("Accept".to_string(), "*/*".to_string()),
        ],
        body: Some(b"<script>alert('XSS')</script>".to_vec()),
        user_agent: Some("sqlmap/1.0".to_string()),
        referer: None,
        content_type: Some("text/html".to_string()),
    }
}

fn bench_individual_detectors(c: &mut Criterion) {
    let normal_ctx = create_normal_request();
    let malicious_ctx = create_malicious_request();

    // Bot Detector
    let bot_detector = BotDetector::new();
    c.bench_function("bot_detector/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(bot_detector.analyze(black_box(&normal_ctx)).await) });
    });
    c.bench_function("bot_detector/malicious", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(bot_detector.analyze(black_box(&malicious_ctx)).await) });
    });

    // Injection Detector
    let injection_detector = InjectionDetector::new();
    c.bench_function("injection_detector/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(injection_detector.analyze(black_box(&normal_ctx)).await) });
    });
    c.bench_function("injection_detector/malicious", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(injection_detector.analyze(black_box(&malicious_ctx)).await) });
    });

    // Scan Detector
    let scan_detector = ScanDetector::new();
    c.bench_function("scan_detector/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(scan_detector.analyze(black_box(&normal_ctx)).await) });
    });

    // Header Detector
    let header_detector = HeaderDetector::new();
    c.bench_function("header_detector/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(header_detector.analyze(black_box(&normal_ctx)).await) });
    });
}

fn bench_detector_registry(c: &mut Criterion) {
    let mut registry = DetectorRegistry::new();

    // Enregistrer tous les détecteurs
    registry.register(Arc::new(BotDetector::new()));
    registry.register(Arc::new(BruteForceDetector::new()));
    registry.register(Arc::new(FloodDetector::new()));
    registry.register(Arc::new(InjectionDetector::new()));
    registry.register(Arc::new(ScanDetector::new()));
    registry.register(Arc::new(HeaderDetector::new()));
    registry.register(Arc::new(GeoDetector::new()));
    registry.register(Arc::new(ProtocolDetector::new()));
    registry.register(Arc::new(SessionDetector::new()));

    let normal_ctx = create_normal_request();
    let malicious_ctx = create_malicious_request();

    c.bench_function("registry/all_detectors/normal", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(registry.analyze_all(black_box(&normal_ctx)).await) });
    });

    c.bench_function("registry/all_detectors/malicious", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(registry.analyze_all(black_box(&malicious_ctx)).await) });
    });
}

fn bench_detector_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("detector_scalability");

    let registry = Arc::new({
        let mut r = DetectorRegistry::new();
        r.register(Arc::new(BotDetector::new()));
        r.register(Arc::new(InjectionDetector::new()));
        r.register(Arc::new(ScanDetector::new()));
        r
    });

    // Test avec différents nombres de requêtes simultanées
    for concurrent_requests in [1, 10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrent_requests),
            concurrent_requests,
            |b, &concurrent| {
                b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
                    let registry = registry.clone();
                    let mut handles = Vec::new();

                    for _ in 0..concurrent {
                        let registry = registry.clone();
                        let ctx = create_normal_request();
                        let handle = tokio::spawn(async move {
                            registry.analyze_all(&ctx).await
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        let _ = handle.await;
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_individual_detectors,
    bench_detector_registry,
    bench_detector_scalability
);
criterion_main!(benches);
