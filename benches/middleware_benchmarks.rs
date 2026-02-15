//! Benchmarks pour le middleware proxy
//!
//! Mesure la latence du pipeline de sanitization des headers,
//! la construction du contexte HTTP, et l'extraction d'IP.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::IpAddr;
use std::str::FromStr;
use websec::detectors::HttpRequestContext;

fn create_request_context_simple() -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str("203.0.113.42").unwrap(),
        method: "GET".to_string(),
        path: "/".to_string(),
        query: None,
        headers: vec![
            ("Host".to_string(), "example.com".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
        ],
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    }
}

fn create_request_context_complex() -> HttpRequestContext {
    HttpRequestContext {
        ip: IpAddr::from_str("198.51.100.7").unwrap(),
        method: "POST".to_string(),
        path: "/api/v2/users/search".to_string(),
        query: Some("q=test&page=3&limit=50&sort=name&order=asc".to_string()),
        headers: vec![
            ("Host".to_string(), "api.example.com".to_string()),
            (
                "User-Agent".to_string(),
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
                    .to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
            (
                "Accept-Language".to_string(),
                "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7".to_string(),
            ),
            ("Accept-Encoding".to_string(), "gzip, deflate, br".to_string()),
            (
                "Content-Type".to_string(),
                "application/json; charset=utf-8".to_string(),
            ),
            (
                "Authorization".to_string(),
                "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U".to_string(),
            ),
            (
                "Cookie".to_string(),
                "session=abc123def456; csrf=xyz789; theme=dark".to_string(),
            ),
            (
                "Referer".to_string(),
                "https://api.example.com/users".to_string(),
            ),
            ("Origin".to_string(), "https://example.com".to_string()),
            ("X-Request-ID".to_string(), "req-abc-123-def-456".to_string()),
            ("Cache-Control".to_string(), "no-cache".to_string()),
        ],
        body: Some(
            br#"{"query":"test","filters":{"status":"active","role":"admin"},"pagination":{"page":3,"limit":50}}"#
                .to_vec(),
        ),
        user_agent: Some(
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
        ),
        referer: Some("https://api.example.com/users".to_string()),
        content_type: Some("application/json; charset=utf-8".to_string()),
    }
}

fn bench_context_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("http_context");

    group.bench_function("build/simple", |b| {
        b.iter(|| black_box(create_request_context_simple()));
    });

    group.bench_function("build/complex", |b| {
        b.iter(|| black_box(create_request_context_complex()));
    });

    // Bench header lookup patterns (mirrors what detectors do)
    let ctx = create_request_context_complex();
    group.bench_function("header_lookup/user_agent", |b| {
        b.iter(|| {
            black_box(
                ctx.headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("user-agent")),
            )
        });
    });

    group.bench_function("header_lookup/host", |b| {
        b.iter(|| {
            black_box(
                ctx.headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("host")),
            )
        });
    });

    group.bench_function("header_lookup/missing", |b| {
        b.iter(|| {
            black_box(
                ctx.headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("x-nonexistent")),
            )
        });
    });

    group.finish();
}

fn bench_ip_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ip_parsing");

    group.bench_function("ipv4", |b| {
        b.iter(|| black_box(IpAddr::from_str(black_box("203.0.113.42")).unwrap()));
    });

    group.bench_function("ipv6", |b| {
        b.iter(|| {
            black_box(IpAddr::from_str(black_box("2001:db8::1")).unwrap());
        });
    });

    group.bench_function("ipv4_in_xff", |b| {
        let xff = "203.0.113.195, 70.41.3.18, 150.172.238.178";
        b.iter(|| {
            let first = black_box(xff).split(',').next().unwrap().trim();
            black_box(IpAddr::from_str(first).unwrap())
        });
    });

    group.finish();
}

fn bench_header_count_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_count_scaling");

    for header_count in [2, 5, 10, 20, 50] {
        let headers: Vec<(String, String)> = (0..header_count)
            .map(|i| (format!("X-Custom-Header-{i}"), format!("value-{i}")))
            .collect();

        let ctx = HttpRequestContext {
            ip: IpAddr::from_str("192.168.1.1").unwrap(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            headers: headers.clone(),
            body: None,
            user_agent: None,
            referer: None,
            content_type: None,
        };

        group.bench_with_input(
            BenchmarkId::from_parameter(header_count),
            &ctx,
            |b, ctx| {
                b.iter(|| {
                    // Simulate what detectors do: scan all headers
                    let has_host = ctx
                        .headers
                        .iter()
                        .any(|(name, _)| name.eq_ignore_ascii_case("host"));
                    black_box(has_host)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_context_construction,
    bench_ip_parsing,
    bench_header_count_scaling
);
criterion_main!(benches);
