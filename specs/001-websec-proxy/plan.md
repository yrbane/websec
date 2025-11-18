# Plan d'Implémentation : WebSec Proxy de Sécurité

**Branche** : `001-websec-proxy` | **Date** : 2025-11-18 | **Spec** : [spec.md](./spec.md)
**Input** : Spécification de fonctionnalité depuis `specs/001-websec-proxy/spec.md`

## Résumé

WebSec est un proxy/reverse proxy de sécurité écrit en Rust, placé en amont d'un serveur web pour intercepter et analyser toutes les requêtes HTTP(S). Le système calcule un score de réputation dynamique pour chaque IP source basé sur la détection de 12 familles de menaces (bots, brute force, injections, scans, etc.) et prend des décisions automatiques : autoriser, ralentir (rate limiting), challenger (CAPTCHA), ou bloquer les requêtes.

## Contexte Technique

**Langage/Version** : Rust 1.75+ (stable)
**Dépendances Principales** :
  - hyper/tokio (serveur HTTP async)
  - axum (framework web)
  - tower (middleware)
  - serde (sérialisation)
  - tracing (logging structuré)
  - maxminddb (géolocalisation)
  - regex (détection de patterns)
  - redis ou sled (persistance scores)

**Stockage** :
  - En mémoire (cache scores/compteurs actifs)
  - Persistance Redis ou Sled (scores de réputation)
  - Fichiers de configuration (TOML)

**Testing** : cargo test (unit + integration + contract tests)
**Plateforme Cible** : Linux server (production), Docker
**Type de Projet** : Single project (proxy standalone)
**Objectifs de Performance** :
  - 10 000 req/s minimum
  - < 5ms latence p95
  - < 512 MB RAM pour 100k IPs
**Contraintes** :
  - Latence minimale (< 5ms p95)
  - Haute disponibilité (99.9%)
  - Stateless pour scaling horizontal
  - Sécurité maximale (fail-closed)
**Échelle/Portée** :
  - 100k IPs actives simultanées
  - 12 familles de menaces
  - 20+ signaux différents

## Vérification Constitution

*GATE : Doit passer avant Phase 0 recherche. Re-vérifier après Phase 1 design.*

### ✅ I. Rust-First Development
- Toute l'implémentation sera en Rust
- Usage de cargo comme système de build
- Exploitation du système de types et ownership pour la sécurité

### ✅ II. Test-Driven Development (NON-NÉGOCIABLE)
- Tests écrits avant implémentation pour chaque détecteur
- Red-Green-Refactor strictement appliqué
- Tests unitaires pour logique métier, integration tests pour contracts
- Couverture minimum 80%

### ✅ III. Design Patterns & Architecture
- Architecture modulaire avec pattern Strategy pour les détecteurs
- Repository pattern pour la persistance
- Builder pattern pour la configuration
- Factory pattern pour création des détecteurs
- Séparation claire : domain logic / infrastructure / presentation

### ✅ IV. Documentation Excellence
- Rustdoc pour toutes les APIs publiques
- README avec quickstart et architecture
- Documentation des threat models et assumptions de sécurité
- Commentaires inline pour logique complexe de scoring

### ✅ V. Quality Triad: Qualité, Sécurité, Performance
**Qualité** :
- `#![deny(warnings)]` activé
- Clippy avec lints stricts
- rustfmt obligatoire
- Peer review pour toute PR

**Sécurité** :
- cargo audit dans CI
- Validation de tous les inputs
- Pas de panic en production (use Result/Option)
- Secrets jamais hardcodés
- Threat modeling pour nouveaux détecteurs

**Performance** :
- Benchmarks avec criterion pour chemins critiques
- Profiling avant optimisation
- Éviter allocations dans hot paths
- Complexité algorithmique documentée

### Contraintes de Complexité

Aucune violation de la constitution identifiée pour ce projet. L'architecture proposée respecte les principes de simplicité tout en répondant aux exigences fonctionnelles.

## Structure du Projet

### Documentation (cette fonctionnalité)

```text
specs/001-websec-proxy/
├── plan.md              # Ce fichier
├── spec.md              # Spécification fonctionnelle
├── research.md          # Phase 0 output (recherche technique)
├── data-model.md        # Phase 1 output (modèle de données)
├── quickstart.md        # Phase 1 output (guide démarrage rapide)
├── contracts/           # Phase 1 output (contrats API/interfaces)
└── tasks.md             # Phase 2 output (liste des tâches)
```

### Code Source (racine du repository)

```text
src/
├── main.rs                      # Point d'entrée (proxy server)
├── lib.rs                       # Exports publics de la bibliothèque
│
├── config/                      # Configuration
│   ├── mod.rs
│   ├── loader.rs               # Chargement config TOML
│   └── settings.rs             # Structures de configuration
│
├── proxy/                       # Couche proxy HTTP
│   ├── mod.rs
│   ├── server.rs               # Serveur HTTP (hyper/axum)
│   ├── middleware.rs           # Middleware d'interception
│   └── backend.rs              # Client backend (forward requests)
│
├── detector/                    # Détecteurs de menaces
│   ├── mod.rs
│   ├── registry.rs             # Registry pattern pour détecteurs
│   ├── bot_detector.rs         # Détection bots/scrapers
│   ├── bruteforce_detector.rs  # Détection brute force
│   ├── flood_detector.rs       # Détection flood/DDoS
│   ├── injection_detector.rs   # Détection SQLi/XSS/RCE
│   ├── path_detector.rs        # Détection path traversal
│   ├── scan_detector.rs        # Détection scans vulnérabilités
│   ├── protocol_detector.rs    # Détection anomalies protocole
│   ├── upload_detector.rs      # Détection uploads dangereux
│   ├── host_detector.rs        # Détection host header abuse
│   ├── ssrf_detector.rs        # Détection SSRF
│   ├── session_detector.rs     # Détection anomalies sessions
│   └── tls_detector.rs         # Détection TLS/fingerprinting
│
├── reputation/                  # Moteur de réputation
│   ├── mod.rs
│   ├── score.rs                # Calcul score de réputation
│   ├── signal.rs               # Définition des signaux
│   ├── profile.rs              # Profil IP (historique)
│   └── decision.rs             # Règles de décision (allow/rate/block)
│
├── storage/                     # Couche persistance
│   ├── mod.rs
│   ├── repository.rs           # Repository trait
│   ├── memory.rs               # Implémentation in-memory (cache)
│   ├── redis.rs                # Implémentation Redis
│   └── sled.rs                 # Implémentation Sled (alternative)
│
├── geolocation/                 # Géolocalisation
│   ├── mod.rs
│   ├── provider.rs             # Trait provider
│   └── maxmind.rs              # Implémentation MaxMind GeoIP2
│
├── ratelimit/                   # Rate limiting
│   ├── mod.rs
│   ├── limiter.rs              # Algorithmes rate limiting
│   └── adaptive.rs             # Rate limiting adaptatif
│
├── lists/                       # Listes de contrôle
│   ├── mod.rs
│   ├── blacklist.rs            # Liste noire
│   └── whitelist.rs            # Liste blanche
│
├── metrics/                     # Observabilité
│   ├── mod.rs
│   └── collector.rs            # Collecte métriques (Prometheus)
│
└── utils/                       # Utilitaires
    ├── mod.rs
    ├── parser.rs               # Parseurs (URL, User-Agent, etc.)
    └── patterns.rs             # Patterns regex réutilisables

tests/
├── contract/                    # Tests de contrats
│   ├── detector_contract_test.rs
│   └── repository_contract_test.rs
│
├── integration/                 # Tests d'intégration
│   ├── proxy_flow_test.rs      # Test flux complet proxy
│   ├── reputation_test.rs      # Test moteur de réputation
│   └── config_reload_test.rs   # Test rechargement config
│
└── unit/                        # Tests unitaires (miroir de src/)
    ├── detector/
    ├── reputation/
    └── ratelimit/

benches/                         # Benchmarks
├── proxy_throughput.rs
└── reputation_scoring.rs

config/                          # Fichiers de configuration
├── websec.toml.example
└── rules.toml.example
```

**Décision de Structure** : Architecture single project avec séparation claire des responsabilités. Le proxy est un service standalone qui peut être déployé devant n'importe quel backend web. Structure modulaire permettant l'ajout facile de nouveaux détecteurs (principe Open/Closed).

## Architecture Détaillée

### Flux de Traitement d'une Requête

```
1. Requête HTTP(S) arrive
   ↓
2. Proxy Server (hyper/axum) intercepte
   ↓
3. Middleware d'analyse :
   - Extraction IP source, headers, URL, params
   - Création objet Request enrichi
   ↓
4. Vérification listes de contrôle :
   - Si IP en blacklist → BLOCK immédiat
   - Si IP en whitelist → ALLOW avec minimal checks
   ↓
5. Récupération Profil IP depuis Storage
   - Cache mémoire d'abord
   - Puis Redis/Sled si pas en cache
   ↓
6. Exécution Détecteurs (parallèle) :
   - Chaque détecteur analyse la requête
   - Génération de signaux typés
   ↓
7. Calcul Score de Réputation :
   - Agrégation des signaux
   - Application des poids configurés
   - Prise en compte de l'historique
   - Facteur géolocalisation
   ↓
8. Décision (Decision Engine) :
   - Score > threshold_allow → ALLOW
   - threshold_ratelimit < Score < threshold_allow → RATE_LIMIT
   - threshold_block < Score < threshold_ratelimit → CHALLENGE
   - Score < threshold_block → BLOCK
   ↓
9. Application Action :
   - ALLOW : Forward au backend
   - RATE_LIMIT : Appliquer rate limiter, puis forward si OK
   - CHALLENGE : Retourner page CAPTCHA (future)
   - BLOCK : Retourner 403/429 avec message
   ↓
10. Mise à jour Profil IP :
    - Update score
    - Persist dans storage
    - Update cache
    ↓
11. Logging & Metrics :
    - Log décision avec contexte
    - Update compteurs Prometheus
    ↓
12. Retour réponse au client
```

### Patterns de Design Appliqués

1. **Strategy Pattern** : Interface `Detector` commune, implémentations spécifiques par menace
2. **Repository Pattern** : Interface `ReputationRepository`, implémentations Memory/Redis/Sled
3. **Builder Pattern** : Construction de la configuration avec validation
4. **Factory Pattern** : `DetectorRegistry` pour créer et gérer les détecteurs
5. **Observer Pattern** : Metrics collector observe les événements du proxy
6. **Chain of Responsibility** : Middleware chain pour traitement requête

## Phases d'Implémentation

### Phase 0 : Recherche Technique

Documenter dans `research.md` :
- Comparatif hyper vs actix-web vs axum pour le proxy
- Stratégie de persistance : Redis vs Sled vs autre
- Bibliothèques de détection : regex, aho-corasick pour pattern matching
- Format de géolocalisation : MaxMind GeoIP2
- Algorithmes de rate limiting : Token bucket, leaky bucket, sliding window
- Stratégie de parallélisation des détecteurs (rayon, tokio tasks)
- Format de configuration : TOML vs YAML
- Benchmarking strategy avec criterion

### Phase 1 : Design Détaillé

Documenter dans `data-model.md` :
- Structures de données : Request, Signal, ReputationProfile, Score
- Schémas de persistance : format Redis keys, structure Sled
- Format de configuration TOML complet
- Définition des 20+ signaux typés

Documenter dans `contracts/` :
- `detector.rs` : Interface Detector trait
- `repository.rs` : Interface ReputationRepository trait
- `decision.rs` : Interface DecisionEngine trait

Documenter dans `quickstart.md` :
- Installation des dépendances
- Compilation du projet
- Configuration minimale pour démarrage
- Exemples de tests basiques

### Phase 2 : Génération des Tâches

Exécuter `/speckit.tasks` pour générer `tasks.md` avec :
- Organisation par user story (P1, P2, P3)
- Tests écrits AVANT implémentation (TDD strict)
- Dépendances entre tâches clairement identifiées
- Marquage des tâches parallélisables [P]

## Risques et Mitigation

| Risque | Impact | Probabilité | Mitigation |
|--------|--------|-------------|------------|
| Performance insuffisante (> 5ms latence) | Élevé | Moyen | Benchmarking continu, profiling, optimisation hot paths |
| Faux positifs élevés (> 0.1%) | Élevé | Moyen | Tuning progressif des seuils, mode apprentissage, whitelist |
| Complexité des détecteurs | Moyen | Élevé | Architecture modulaire, tests exhaustifs, documentation |
| Scaling horizontal complexe | Moyen | Faible | Design stateless dès le début, state partagé dans Redis |
| Dérive mémoire (memory leak) | Élevé | Faible | Expiration automatique, monitoring mémoire, tests de charge |

## Métriques de Succès

- ✅ Latence p95 < 5ms mesurée avec criterion
- ✅ Throughput ≥ 10k req/s sur 4 cores
- ✅ Taux de blocage bots > 99% sans faux positifs navigateurs
- ✅ Détection brute force dans les 5 premières tentatives
- ✅ Couverture de tests > 80%
- ✅ Zéro panic en production sur tests de charge
- ✅ Cargo audit passe (zéro CVE)
- ✅ Documentation complète (rustdoc + guides)

## Prochaines Étapes

1. ✅ Valider ce plan avec les stakeholders
2. → Exécuter Phase 0 : Recherche technique (documenter research.md)
3. → Exécuter Phase 1 : Design détaillé (data-model.md, contracts/, quickstart.md)
4. → Exécuter Phase 2 : Génération des tâches avec `/speckit.tasks`
5. → Commencer implémentation TDD en suivant tasks.md
