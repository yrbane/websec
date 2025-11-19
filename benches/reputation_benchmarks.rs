//! Benchmarks pour le système de réputation
//!
//! Mesure les performances du scoring, decay, et décisions.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use websec::detectors::{DetectorRegistry, HttpRequestContext};
use websec::reputation::decision::{DecisionEngine, DecisionEngineConfig};
use websec::reputation::profile::ReputationProfile;
use websec::reputation::score::{calculate_score, determine_decision, ScoringThresholds};
use websec::reputation::signal::{Signal, SignalVariant};
use websec::storage::{InMemoryRepository, ReputationRepository};

fn create_profile_with_signals(count: usize) -> ReputationProfile {
    let mut profile = ReputationProfile::new(IpAddr::from_str("192.168.1.1").unwrap(), 100);

    for i in 0..count {
        let variant = match i % 5 {
            0 => SignalVariant::FailedLogin,
            1 => SignalVariant::SqlSyntaxPattern,
            2 => SignalVariant::BotBehaviorPattern,
            3 => SignalVariant::SuspiciousUserAgent,
            _ => SignalVariant::HighRiskCountry,
        };
        profile.add_signal(Signal::new(variant));
    }

    profile
}

fn bench_score_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("score_calculation");

    for signal_count in [0, 10, 50, 100, 500].iter() {
        let profile = create_profile_with_signals(*signal_count);

        group.bench_with_input(
            BenchmarkId::from_parameter(signal_count),
            signal_count,
            |b, _| {
                b.iter(|| {
                    black_box(calculate_score(
                        black_box(&profile),
                        100,
                        24.0,
                        10,
                    ))
                });
            },
        );
    }

    group.finish();
}

fn bench_decision_determination(c: &mut Criterion) {
    let thresholds = ScoringThresholds::default();

    let scores = vec![100, 80, 60, 40, 20, 10, 0];

    for score in scores {
        c.bench_function(&format!("determine_decision/score_{score}"), |b| {
            b.iter(|| {
                black_box(determine_decision(
                    black_box(score),
                    black_box(&thresholds),
                ))
            });
        });
    }
}

fn bench_decision_engine_e2e(c: &mut Criterion) {
    let config = DecisionEngineConfig::default();
    let repository = Arc::new(InMemoryRepository::new());
    let detectors = Arc::new(DetectorRegistry::new());

    let engine = DecisionEngine::new(config, repository, detectors);

    let context = HttpRequestContext {
        ip: IpAddr::from_str("192.168.1.100").unwrap(),
        method: "GET".to_string(),
        path: "/api/users".to_string(),
        query: None,
        headers: vec![
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
        ],
        body: None,
        user_agent: Some("Mozilla/5.0".to_string()),
        referer: None,
        content_type: None,
    };

    c.bench_function("decision_engine/process_request", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
            black_box(engine.process_request(black_box(&context)).await.unwrap())
        });
    });
}

fn bench_repository_operations(c: &mut Criterion) {
    let repository = InMemoryRepository::new();
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    c.bench_function("repository/get/miss", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
            black_box(repository.get(black_box(&ip)).await.unwrap())
        });
    });

    // Pré-charger un profil
    let profile = create_profile_with_signals(50);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        repository.save(&profile).await.unwrap();
    });

    c.bench_function("repository/get/hit", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
            black_box(repository.get(black_box(&ip)).await.unwrap())
        });
    });

    c.bench_function("repository/save", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
            let profile = create_profile_with_signals(50);
            black_box(repository.save(black_box(&profile)).await.unwrap())
        });
    });
}

criterion_group!(
    benches,
    bench_score_calculation,
    bench_decision_determination,
    bench_decision_engine_e2e,
    bench_repository_operations
);
criterion_main!(benches);
