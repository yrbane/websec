# Architecture - WebSec

## Vue d'ensemble

WebSec est un reverse proxy de sécurité construit en Rust utilisant le framework axum et implémentant un système de réputation dynamique pour la détection et la mitigation des menaces en temps réel.

## Diagramme global

```
┌──────────────────────────────────────────────────────────────┐
│                        Client HTTP                            │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                    ProxyServer (Axum)                         │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  proxy_handler (Middleware)                            │  │
│  │  1. Extract IP (X-Forwarded-For, X-Real-IP)           │  │
│  │  2. Build HttpRequestContext                          │  │
│  │  3. Call DecisionEngine                               │  │
│  └──────────────┬─────────────────────────────────────────┘  │
└─────────────────┼────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────┐
│               DecisionEngine                                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  1. Load/Create ReputationProfile                     │  │
│  │  2. Run DetectorRegistry.analyze_all()                │  │
│  │  3. Add detected signals to profile                   │  │
│  │  4. Recalculate score with decay                      │  │
│  │  5. Determine decision (ALLOW/BLOCK/etc.)             │  │
│  │  6. Save updated profile                              │  │
│  └──────────────┬─────────────────────────────────────────┘  │
└─────────────────┼────────────────────────────────────────────┘
                  │
          ┌───────┴────────┬──────────┬──────────────┐
          ▼                ▼          ▼              ▼
     ┌─────────┐    ┌──────────┐  ┌─────────┐  ┌─────────┐
     │Detector │    │Detector  │  │Detector │  │ ... (9) │
     │Registry │    │Bot       │  │Injection│  │         │
     └─────────┘    └──────────┘  └─────────┘  └─────────┘

     Decision Result
     ├── ALLOW → BackendClient.forward() → Backend
     ├── BLOCK → HTTP 403
     ├── CHALLENGE → ChallengeManager.create_challenge()
     └── RATE_LIMIT → HTTP 429
```

## Composants principaux

### 1. ProxyServer

**Rôle**: Point d'entrée HTTP, orchestrateur principal

**Responsabilités**:
- Binding TCP sur une ou plusieurs adresses configurées (listeners HTTP/HTTPS)
- Initialisation de tous les composants au démarrage
- Routing des requêtes vers le middleware
- Graceful shutdown sur SIGTERM/SIGINT
- Gestion optionnelle du TLS (via `server.listeners.tls`)

**Composants initialisés**:
- `InMemoryRepository` (ou RedisRepository)
- `DetectorRegistry` avec 9 détecteurs
- `DecisionEngine`
- `BackendClient`
- `ChallengeManager`
- `MetricsRegistry`
- `ListenerRuntime` (multi-port, TLS rustls)

**Fichier**: `src/proxy/server.rs`

---

### 2. Middleware (proxy_handler)

**Rôle**: Interception et analyse de chaque requête

**Flux**:
1. **Extraction IP**: Priorité X-Forwarded-For > X-Real-IP > SocketAddr
2. **Lecture body**: Collecte complète du body pour analyse
3. **Construction contexte**: Création de `HttpRequestContext`
4. **Appel DecisionEngine**: Analyse et décision
5. **Action selon décision**:
   - ALLOW: Forward au backend
   - BLOCK: Réponse 403 avec score
   - CHALLENGE: HTML CAPTCHA
   - RATE_LIMIT: Réponse 429
6. **Métriques**: Enregistrement latence, compteurs, scores

**Fichier**: `src/proxy/middleware.rs`

---

### 3. DecisionEngine

**Rôle**: Cœur logique de la décision de sécurité

**Algorithme**:
```rust
async fn process_request(context: &HttpRequestContext) -> DecisionEngineResult {
    // 1. Charger ou créer le profil
    let mut profile = repository.get(context.ip)
        .unwrap_or_else(|| ReputationProfile::new(context.ip, base_score));

    // 2. Analyser avec tous les détecteurs
    let detection_result = detectors.analyze_all(context).await;

    // 3. Ajouter signaux détectés au profil
    for signal in detection_result.signals {
        profile.add_signal(signal);
    }

    // 4. Recalculer le score avec decay
    let new_score = recalculate_and_update(
        &mut profile,
        base_score,
        decay_half_life,
        correlation_penalty
    );

    // 5. Déterminer la décision selon les seuils
    let decision = determine_decision(new_score, &thresholds);

    // 6. Sauvegarder le profil mis à jour
    repository.save(&profile).await?;

    DecisionEngineResult { decision, score: new_score, detection_result }
}
```

**Fichier**: `src/reputation/decision.rs`

---

### 4. DetectorRegistry

**Rôle**: Orchestration des détecteurs de menaces

**Détecteurs enregistrés**:
1. **BotDetector**: User-Agent suspects, behavior patterns
2. **BruteForceDetector**: Failed login attempts, timing patterns
3. **FloodDetector**: High request rate, distributed attacks
4. **InjectionDetector**: SQL/XSS/Command injection
5. **ScanDetector**: Vulnerability scanning patterns
6. **HeaderDetector**: Header manipulation, CRLF injection
7. **GeoDetector**: Country-based risk assessment
8. **ProtocolDetector**: HTTP protocol violations
9. **SessionDetector**: Session hijacking, token anomalies

**Méthode principale**:
```rust
async fn analyze_all(&self, context: &HttpRequestContext) -> DetectionResult {
    let mut all_signals = Vec::new();

    for detector in &self.detectors {
        let result = detector.analyze(context).await;
        all_signals.extend(result.signals);
    }

    DetectionResult { signals: all_signals }
}
```

**Fichier**: `src/detectors/registry.rs`

---

### 5. ReputationProfile

**Rôle**: Profil de réputation d'une IP

**Structure**:
```rust
pub struct ReputationProfile {
    pub ip_address: IpAddr,
    pub current_score: u8,          // 0-100
    pub signals: Vec<Signal>,       // Historique des signaux
    pub whitelisted: bool,
    pub blacklisted: bool,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_requests: u64,
    pub blocked_requests: u64,
}
```

**Score Calculation**:
```
Score = max(0, min(100, base_score - Σ(decayed_weights) - correlation_bonus))

où:
- base_score = 100 (défaut)
- decayed_weight = signal.weight * 0.5^(age_hours / decay_half_life)
- correlation_bonus = 10 si multiples familles d'attaques
```

**Fichier**: `src/reputation/profile.rs`

---

### 6. BackendClient

**Rôle**: Forwarding transparent vers le backend

**Responsabilités**:
- Préservation complète de l'URI (path + query)
- Préservation des headers
- Streaming du body
- Gestion des erreurs backend

**Implémentation**:
```rust
async fn forward(&self, request: Request<Full<Bytes>>) -> Result<Response<Incoming>> {
    let target_uri = format!("{}{}", self.backend_url, request.uri().path_and_query());
    *request.uri_mut() = Uri::from_str(&target_uri)?;

    self.client.request(request).await
}
```

**Fichier**: `src/proxy/backend.rs`

---

### 7. ChallengeManager

**Rôle**: Génération et validation de CAPTCHAs

**Types de challenges**:
- `SimpleMath`: Addition, soustraction, multiplication

**Workflow**:
1. Création: `create_challenge(ip, ChallengeType::SimpleMath)`
2. Stockage temporaire avec timeout (5 min)
3. HTML generation: `challenge.to_html()`
4. Validation: `validate(ip, token, answer)`
5. Cleanup automatique des challenges expirés

**Fichier**: `src/challenge/manager.rs`

---

## Flux de données

### 1. Requête normale (score élevé)

```
Client → ProxyServer → Middleware
  → DecisionEngine (score: 85)
  → BackendClient → Backend
  → Response + X-WebSec-Decision: ALLOW
```

### 2. Requête suspecte (score moyen)

```
Client → ProxyServer → Middleware
  → DecisionEngine (score: 55, detect: BotDetector)
  → HTTP 429 + Retry-After: 60
```

### 3. Requête malveillante (score bas)

```
Client → ProxyServer → Middleware
  → DecisionEngine (score: 18, detect: Injection + Scan)
  → ChallengeManager.create_challenge()
  → HTML CAPTCHA + X-WebSec-Decision: CHALLENGE
```

### 4. Attaque confirmée (score très bas)

```
Client → ProxyServer → Middleware
  → DecisionEngine (score: 5, detect: Multiple threats)
  → HTTP 403 + X-WebSec-Score: 5
```

---

## Stockage

### InMemoryRepository

**Type**: `DashMap<IpAddr, ReputationProfile>`
- Thread-safe concurrent hashmap
- Pas de persistance (perte au redémarrage)
- Performance maximale
- Idéal pour: Tests, dev, single-instance

### RedisRepository (futur)

**Type**: Redis avec serialization JSON
- Persistance
- Distribution (multi-instance)
- TTL automatique
- Idéal pour: Production, HA

---

## Concurrence

### Thread-Safety

- **Arc<T>**: Partage immutable entre threads
- **DashMap**: Hashmap concurrent lock-free
- **tokio::Mutex**: Locks async quand nécessaire
- **Immutabilité**: Pattern préféré (clone si besoin)

### Async Runtime

- **Tokio**: Runtime async principal
- **Workers**: N workers tokio (configurable)
- **No blocking**: Toutes les I/O sont async

---

## Performance

### Optimisations

1. **Zero-copy quand possible**: Utilisation de références
2. **Lazy evaluation**: Détecteurs s'arrêtent si score déjà bas
3. **Caching**: Repository cache les profils récents
4. **Connection pooling**: HTTP client réutilise les connexions
5. **Async everywhere**: Pas de blocking I/O

### Benchmarks

Voir `benches/` pour les benchmarks détaillés:
- Détecteurs individuels: ~5-50µs par requête
- Registry complet: ~200-500µs par requête
- DecisionEngine E2E: ~500-1000µs par requête

---

## Extensibilité

### Ajouter un nouveau détecteur

```rust
// 1. Implémenter le trait Detector
pub struct MyDetector;

impl Detector for MyDetector {
    fn name(&self) -> &'static str { "MyDetector" }

    async fn analyze(&self, context: &HttpRequestContext) -> DetectionResult {
        // Logic here
    }
}

// 2. L'enregistrer dans ProxyServer::new()
detector_registry.register(Arc::new(MyDetector));
```

### Ajouter un nouveau type de storage

```rust
// 1. Implémenter ReputationRepository
pub struct MyRepository;

#[async_trait]
impl ReputationRepository for MyRepository {
    async fn get(&self, ip: &IpAddr) -> Result<Option<ReputationProfile>> { ... }
    async fn save(&self, profile: &ReputationProfile) -> Result<()> { ... }
    async fn delete(&self, ip: &IpAddr) -> Result<()> { ... }
}

// 2. Utiliser dans DecisionEngine::new()
```

---

## Sécurité

### Principes

1. **Defense in Depth**: Multiples couches (détecteurs + scoring + décision)
2. **Fail-Open**: En cas d'erreur, allow (disponibilité > sécurité)
3. **Rate Limiting**: Protection contre DoS
4. **Input Validation**: Tous les inputs sont validés
5. **No Logging Secrets**: Pas de tokens/passwords dans les logs

### Limitations connues

- Pas de TLS termination (utiliser nginx devant)
- Pas de WAF complet (complément, pas remplacement)
- Memory-based storage non distribué (utiliser Redis)

---

## Monitoring

### Métriques exposées

```rust
// Compteurs
websec_requests_total
websec_decisions{decision="allow|block|challenge|rate_limit"}

// Histogrammes
websec_latency_seconds

// Gauges
websec_reputation_score{ip="X.X.X.X"}
```

### Logs structurés

Tous les événements sont loggés avec contexte:
```json
{
  "timestamp": "...",
  "level": "WARN",
  "ip": "1.2.3.4",
  "decision": "BLOCK",
  "score": 15,
  "signals": ["SqlInjection", "BotPattern"]
}
```

---

## Déploiement

### Single Instance

```
nginx (TLS) → WebSec → Backend
```

### High Availability

```
                    ┌→ WebSec 1 ┐
nginx (TLS) → LB ──→┼→ WebSec 2 ├→ Backend Pool
                    └→ WebSec 3 ┘
                           ↓
                      Redis (shared state)
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: websec
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: websec
        image: websec:latest
        env:
        - name: BACKEND_URL
          value: "http://backend-service:8000"
        - name: REDIS_URL
          value: "redis://redis-service:6379"
```
