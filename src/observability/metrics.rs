//! Métriques Prometheus pour monitoring
//!
//! Collecte et expose des métriques au format Prometheus pour le monitoring
//! des performances et de la sécurité du proxy.
//!
//! # Utilisation
//!
//! ```rust
//! use websec::observability::metrics::MetricsRegistry;
//!
//! let metrics = MetricsRegistry::new();
//!
//! // Incrémenter les compteurs
//! metrics.increment_counter("requests_total");
//! metrics.increment_detection("BotDetector");
//!
//! // Enregistrer la latence
//! metrics.observe_latency(0.042); // 42ms
//!
//! // Mettre à jour le score de réputation
//! metrics.set_reputation_score("192.168.1.1", 85.0);
//!
//! // Compter les décisions
//! metrics.increment_decision("block");
//!
//! // Exporter au format Prometheus
//! let export = metrics.export_prometheus();
//! println!("{}", export);
//! ```
//!
//! # Métriques disponibles
//!
//! ## Compteurs
//!
//! - `requests_total` : Nombre total de requêtes traitées
//! - `detections_total` : Nombre total de menaces détectées
//! - `detections_by_detector{detector}` : Détections par type de détecteur
//! - `decisions_by_type{decision}` : Décisions par type (allow, block, etc.)
//!
//! ## Histogrammes
//!
//! - `request_duration_seconds` : Distribution de latence des requêtes
//!   - Buckets : 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s
//!
//! ## Jauges
//!
//! - `reputation_score` : Score de réputation actuel
//! - `reputation_by_ip{ip}` : Score de réputation par adresse IP
//!
//! # Exposition Prometheus
//!
//! Les métriques sont exposées au format texte Prometheus :
//! ```text
//! # HELP requests_total Total des requêtes traitées
//! # TYPE requests_total counter
//! requests_total 1234
//!
//! # HELP request_duration_seconds Durée de traitement des requêtes en secondes
//! # TYPE request_duration_seconds histogram
//! request_duration_seconds_bucket{le="0.005"} 100
//! request_duration_seconds_bucket{le="0.01"} 250
//! ...
//! ```

use prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Registry de métriques Prometheus
///
/// Gère l'ensemble des métriques du système avec support thread-safe.
/// Toutes les métriques sont créées automatiquement à l'initialisation.
///
/// # Thread Safety
///
/// Complètement thread-safe grâce à `Arc<Mutex<HashMap>>` pour le stockage
/// des métriques. Plusieurs threads peuvent mettre à jour les métriques
/// simultanément sans verrouillage global.
///
/// # Performance
///
/// - Recherche de métrique : O(1) via HashMap
/// - Incrémentation : O(1) opération atomique Prometheus
/// - Export : O(n) où n = nombre de métriques
pub struct MetricsRegistry {
    registry: Registry,
    counters: Arc<Mutex<HashMap<String, IntCounter>>>,
    counter_vecs: Arc<Mutex<HashMap<String, IntCounterVec>>>,
    gauges: Arc<Mutex<HashMap<String, IntGauge>>>,
    gauge_vecs: Arc<Mutex<HashMap<String, IntGaugeVec>>>,
    histograms: Arc<Mutex<HashMap<String, Histogram>>>,
}

impl MetricsRegistry {
    /// Crée un nouveau registry de métriques
    #[must_use]
    pub fn new() -> Self {
        let registry = Registry::new();
        let counters = Arc::new(Mutex::new(HashMap::new()));
        let counter_vecs = Arc::new(Mutex::new(HashMap::new()));
        let gauges = Arc::new(Mutex::new(HashMap::new()));
        let gauge_vecs = Arc::new(Mutex::new(HashMap::new()));
        let histograms = Arc::new(Mutex::new(HashMap::new()));

        let metrics = Self {
            registry,
            counters,
            counter_vecs,
            gauges,
            gauge_vecs,
            histograms,
        };

        // Créer les métriques de base
        metrics.create_base_metrics();
        metrics
    }

    fn create_base_metrics(&self) {
        // Compteur total de requêtes
        let requests_total = IntCounter::new("requests_total", "Total des requêtes traitées")
            .expect("Création métrique requests_total");
        self.registry
            .register(Box::new(requests_total.clone()))
            .expect("Enregistrement requests_total");
        self.counters
            .lock()
            .unwrap()
            .insert("requests_total".to_string(), requests_total);

        // Compteur total de détections
        let detections_total =
            IntCounter::new("detections_total", "Total des détections de menaces")
                .expect("Création métrique detections_total");
        self.registry
            .register(Box::new(detections_total.clone()))
            .expect("Enregistrement detections_total");
        self.counters
            .lock()
            .unwrap()
            .insert("detections_total".to_string(), detections_total);

        // Histogramme de latence
        let duration_opts = HistogramOpts::new(
            "request_duration_seconds",
            "Durée de traitement des requêtes en secondes",
        )
        .buckets(vec![
            0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0,
        ]);
        let request_duration =
            Histogram::with_opts(duration_opts).expect("Création métrique request_duration");
        self.registry
            .register(Box::new(request_duration.clone()))
            .expect("Enregistrement request_duration");
        self.histograms
            .lock()
            .unwrap()
            .insert("request_duration_seconds".to_string(), request_duration);

        // Jauge pour les scores de réputation
        let reputation_score =
            IntGauge::new("reputation_score", "Score de réputation actuel d'une IP")
                .expect("Création métrique reputation_score");
        self.registry
            .register(Box::new(reputation_score.clone()))
            .expect("Enregistrement reputation_score");
        self.gauges
            .lock()
            .unwrap()
            .insert("reputation_score".to_string(), reputation_score);

        // Compteur par type de détecteur
        let detector_opts = Opts::new(
            "detections_by_detector",
            "Nombre de détections par type de détecteur",
        );
        let detections_by_detector = IntCounterVec::new(detector_opts, &["detector"])
            .expect("Création métrique detections_by_detector");
        self.registry
            .register(Box::new(detections_by_detector.clone()))
            .expect("Enregistrement detections_by_detector");
        self.counter_vecs
            .lock()
            .unwrap()
            .insert("detections_by_detector".to_string(), detections_by_detector);

        // Compteur par type de décision
        let decision_opts =
            Opts::new("decisions_by_type", "Nombre de décisions par type");
        let decisions_by_type = IntCounterVec::new(decision_opts, &["decision"])
            .expect("Création métrique decisions_by_type");
        self.registry
            .register(Box::new(decisions_by_type.clone()))
            .expect("Enregistrement decisions_by_type");
        self.counter_vecs
            .lock()
            .unwrap()
            .insert("decisions_by_type".to_string(), decisions_by_type);

        // Jauge par IP pour score de réputation
        let reputation_opts = Opts::new(
            "reputation_by_ip",
            "Score de réputation par adresse IP",
        );
        let reputation_by_ip = IntGaugeVec::new(reputation_opts, &["ip"])
            .expect("Création métrique reputation_by_ip");
        self.registry
            .register(Box::new(reputation_by_ip.clone()))
            .expect("Enregistrement reputation_by_ip");
        self.gauge_vecs
            .lock()
            .unwrap()
            .insert("reputation_by_ip".to_string(), reputation_by_ip);
    }

    /// Récupère un compteur par nom
    #[must_use]
    pub fn get_counter(&self, name: &str) -> Option<IntCounter> {
        self.counters.lock().unwrap().get(name).cloned()
    }

    /// Récupère un histogramme par nom
    #[must_use]
    pub fn get_histogram(&self, name: &str) -> Option<Histogram> {
        self.histograms.lock().unwrap().get(name).cloned()
    }

    /// Récupère la valeur d'un compteur
    #[must_use]
    pub fn get_counter_value(&self, name: &str) -> f64 {
        self.get_counter(name).map_or(0.0, |c| c.get() as f64)
    }

    /// Incrémente un compteur
    pub fn increment_counter(&self, name: &str) {
        if let Some(counter) = self.get_counter(name) {
            counter.inc();
        }
    }

    /// Incrémente le compteur de détections par détecteur
    pub fn increment_detection(&self, detector_name: &str) {
        self.increment_counter("detections_total");

        if let Some(vec) = self
            .counter_vecs
            .lock()
            .unwrap()
            .get("detections_by_detector")
        {
            vec.with_label_values(&[detector_name]).inc();
        }
    }

    /// Récupère le nombre de détections par détecteur
    #[must_use]
    pub fn get_detector_count(&self, detector_name: &str) -> u64 {
        self.counter_vecs
            .lock()
            .unwrap()
            .get("detections_by_detector")
            .map_or(0, |vec| vec.with_label_values(&[detector_name]).get())
    }

    /// Enregistre une observation de latence
    pub fn observe_latency(&self, duration_seconds: f64) {
        if let Some(histogram) = self.get_histogram("request_duration_seconds") {
            histogram.observe(duration_seconds);
        }
    }

    /// Définit le score de réputation pour une IP
    pub fn set_reputation_score(&self, ip: &str, score: f64) {
        if let Some(vec) = self.gauge_vecs.lock().unwrap().get("reputation_by_ip") {
            vec.with_label_values(&[ip]).set(score as i64);
        }
    }

    /// Récupère le score de réputation pour une IP
    #[must_use]
    pub fn get_reputation_score(&self, ip: &str) -> f64 {
        self.gauge_vecs
            .lock()
            .unwrap()
            .get("reputation_by_ip")
            .map_or(0.0, |vec| vec.with_label_values(&[ip]).get() as f64)
    }

    /// Incrémente le compteur de décisions par type
    pub fn increment_decision(&self, decision_type: &str) {
        if let Some(vec) = self.counter_vecs.lock().unwrap().get("decisions_by_type") {
            vec.with_label_values(&[decision_type]).inc();
        }
    }

    /// Récupère le nombre de décisions par type
    #[must_use]
    pub fn get_decision_count(&self, decision_type: &str) -> u64 {
        self.counter_vecs
            .lock()
            .unwrap()
            .get("decisions_by_type")
            .map_or(0, |vec| vec.with_label_values(&[decision_type]).get())
    }

    /// Exporte toutes les métriques au format Prometheus
    #[must_use]
    pub fn export_prometheus(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialise le système de métriques
#[must_use]
pub fn init_metrics() -> Result<MetricsRegistry, String> {
    Ok(MetricsRegistry::new())
}
