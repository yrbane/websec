# Tâches : WebSec Proxy de Sécurité

**Input** : Documents de design depuis `specs/001-websec-proxy/`
**Prérequis** : plan.md (requis), spec.md (requis pour user stories)

**Tests** : Les tests sont OBLIGATOIRES selon le principe TDD de la constitution.

**Organisation** : Les tâches sont groupées par user story pour permettre l'implémentation et les tests indépendants de chaque story.

## Format : `[ID] [P?] [Story] Description`

- **[P]** : Peut être exécuté en parallèle (fichiers différents, pas de dépendances)
- **[Story]** : À quelle user story cette tâche appartient (ex: US1, US2, US3)
- Inclure les chemins exacts de fichiers dans les descriptions

## Conventions de Chemins

- **Single project** : `src/`, `tests/` à la racine du repository
- Les chemins ci-dessous suivent cette structure

---

## Phase 1 : Setup (Infrastructure Partagée)

**Objectif** : Initialisation du projet et structure de base

- [ ] T001 Créer la structure de projet Rust avec `cargo init --lib` et configurer Cargo.toml
- [ ] T002 [P] Ajouter les dépendances principales dans Cargo.toml (hyper, tokio, axum, tower, serde, tracing)
- [ ] T003 [P] Configurer clippy.toml avec lints stricts et activer `#![deny(warnings)]` dans lib.rs
- [ ] T004 [P] Configurer rustfmt.toml avec style du projet
- [ ] T005 [P] Créer structure de répertoires src/ selon plan.md
- [ ] T006 [P] Créer structure de répertoires tests/ (unit, integration, contract)
- [ ] T007 [P] Créer structure de répertoires benches/ pour benchmarks criterion
- [ ] T008 Créer config/websec.toml.example avec configuration minimale

---

## Phase 2 : Fondations (Prérequis Bloquants)

**Objectif** : Infrastructure de base qui DOIT être complète avant TOUTE user story

**⚠️ CRITIQUE** : Aucun travail sur les user stories ne peut commencer avant la fin de cette phase

- [ ] T009 Créer les types de base dans src/lib.rs (Request, Response, IpAddr helpers)
- [ ] T010 Implémenter la structure de configuration dans src/config/settings.rs avec serde
- [ ] T011 Implémenter le chargeur de config TOML dans src/config/loader.rs
- [ ] T012 [P] Définir tous les types de Signal dans src/reputation/signal.rs (enum avec 20+ variantes)
- [ ] T013 [P] Définir la structure ReputationProfile dans src/reputation/profile.rs
- [ ] T014 [P] Définir la structure ReputationScore dans src/reputation/score.rs
- [ ] T015 Créer le trait Detector dans src/detector/mod.rs avec méthode analyze()
- [ ] T016 Créer le trait ReputationRepository dans src/storage/repository.rs
- [ ] T017 Implémenter InMemoryRepository dans src/storage/memory.rs (HashMap thread-safe)
- [ ] T018 Créer DetectorRegistry dans src/detector/registry.rs avec pattern Factory
- [ ] T019 Implémenter le DecisionEngine de base dans src/reputation/decision.rs
- [ ] T020 [P] Configurer tracing/logging structuré dans src/lib.rs
- [ ] T021 [P] Créer les utilitaires de parsing dans src/utils/parser.rs (URL, User-Agent)
- [ ] T022 Créer le serveur proxy HTTP de base dans src/proxy/server.rs avec axum
- [ ] T023 Créer le middleware d'interception dans src/proxy/middleware.rs
- [ ] T024 Créer le client backend dans src/proxy/backend.rs pour forward requests

**Checkpoint** : Fondation prête - l'implémentation des user stories peut maintenant commencer en parallèle

---

## Phase 3 : User Story 1 - Protection contre les Bots Malveillants (Priorité : P1) 🎯 MVP

**Objectif** : Détecter et bloquer les bots malveillants et scrapers agressifs

**Test Indépendant** : Envoyer des requêtes avec différents User-Agent et vérifier le scoring

### Tests pour User Story 1 (TDD - RED phase) ⚠️

> **NOTE : Écrire ces tests EN PREMIER, s'assurer qu'ils ÉCHOUENT avant l'implémentation**

- [ ] T025 [P] [US1] Test unitaire : détection User-Agent suspect dans tests/unit/detector/bot_detector_test.rs
- [ ] T026 [P] [US1] Test unitaire : détection profil client non humain dans tests/unit/detector/bot_detector_test.rs
- [ ] T027 [P] [US1] Test contract : le BotDetector implémente correctement le trait Detector dans tests/contract/detector_contract_test.rs
- [ ] T028 [US1] Test d'intégration : requête avec UA=sqlmap génère signal VulnerabilityScan dans tests/integration/bot_detection_test.rs
- [ ] T029 [US1] Test d'intégration : 100 requêtes sans assets génère signal AbusiveClient dans tests/integration/bot_detection_test.rs

### Implémentation pour User Story 1 (TDD - GREEN phase)

- [ ] T030 [P] [US1] Créer liste de patterns User-Agent suspects dans src/detector/bot_detector.rs (regex)
- [ ] T031 [US1] Implémenter BotDetector::analyze() pour détection User-Agent dans src/detector/bot_detector.rs
- [ ] T032 [US1] Implémenter détection profil non humain (pas de headers standards) dans src/detector/bot_detector.rs
- [ ] T033 [US1] Implémenter comptage ratio assets/pages dans BotDetector (tracking dans ReputationProfile)
- [ ] T034 [US1] Ajouter génération signal SuspiciousUserAgent dans BotDetector
- [ ] T035 [US1] Ajouter génération signal SuspiciousClientProfile dans BotDetector
- [ ] T036 [US1] Ajouter génération signal AbusiveClient dans BotDetector
- [ ] T037 [US1] Enregistrer BotDetector dans DetectorRegistry
- [ ] T038 [US1] Ajouter poids des signaux bot dans configuration (config/websec.toml.example)
- [ ] T039 [US1] Ajouter logging pour détection de bots dans BotDetector

### Refactoring pour User Story 1 (TDD - REFACTOR phase)

- [ ] T040 [US1] Refactoring : extraire patterns regex communs dans src/utils/patterns.rs
- [ ] T041 [US1] Refactoring : optimiser regex compilation (lazy_static)
- [ ] T042 [US1] Documentation rustdoc pour BotDetector avec exemples

**Checkpoint** : À ce point, User Story 1 doit être totalement fonctionnelle et testable indépendamment

---

## Phase 4 : User Story 2 - Protection contre le Brute Force (Priorité : P1) 🎯 MVP

**Objectif** : Détecter et ralentir/bloquer les tentatives de brute force sur les endpoints d'authentification

**Test Indépendant** : Envoyer plusieurs POST /login échoués et vérifier rate limiting puis blocage

### Tests pour User Story 2 (TDD - RED phase) ⚠️

- [ ] T043 [P] [US2] Test unitaire : comptage tentatives échouées par IP dans tests/unit/detector/bruteforce_detector_test.rs
- [ ] T044 [P] [US2] Test unitaire : détection credential stuffing (mêmes credentials, IPs différentes) dans tests/unit/detector/bruteforce_detector_test.rs
- [ ] T045 [US2] Test contract : BruteForceDetector implémente trait Detector dans tests/contract/detector_contract_test.rs
- [ ] T046 [US2] Test d'intégration : 5 tentatives login échouées génère signal FailedAuthAttempt dans tests/integration/bruteforce_test.rs
- [ ] T047 [US2] Test d'intégration : 20 tentatives échouées déclenche blocage dans tests/integration/bruteforce_test.rs

### Implémentation pour User Story 2 (TDD - GREEN phase)

- [ ] T048 [P] [US2] Créer liste d'endpoints sensibles (login, admin) dans src/detector/bruteforce_detector.rs
- [ ] T049 [US2] Implémenter compteur de tentatives échouées par IP dans BruteForceDetector
- [ ] T050 [US2] Implémenter détection de codes retour HTTP 401/403 dans BruteForceDetector
- [ ] T051 [US2] Implémenter fenêtre temporelle glissante pour comptage dans BruteForceDetector
- [ ] T052 [US2] Implémenter détection credential stuffing (corrélation inter-IP) dans BruteForceDetector
- [ ] T053 [US2] Ajouter génération signal FailedAuthAttempt dans BruteForceDetector
- [ ] T054 [US2] Ajouter génération signal CredentialStuffing dans BruteForceDetector
- [ ] T055 [US2] Enregistrer BruteForceDetector dans DetectorRegistry
- [ ] T056 [US2] Implémenter logique de rate limiting dans src/ratelimit/limiter.rs (token bucket)
- [ ] T057 [US2] Intégrer rate limiter dans DecisionEngine
- [ ] T058 [US2] Ajouter configuration seuils brute force dans config/websec.toml.example

### Refactoring pour User Story 2 (TDD - REFACTOR phase)

- [ ] T059 [US2] Refactoring : extraire logique fenêtre temporelle dans module réutilisable
- [ ] T060 [US2] Documentation rustdoc pour BruteForceDetector et RateLimiter

**Checkpoint** : À ce point, User Stories 1 ET 2 doivent fonctionner indépendamment

---

## Phase 5 : User Story 3 - Protection contre le Flood/DDoS (Priorité : P2)

**Objectif** : Limiter automatiquement le nombre de requêtes par IP

**Test Indépendant** : Envoyer un grand volume de requêtes depuis une IP et vérifier rate limiting

### Tests pour User Story 3 (TDD - RED phase) ⚠️

- [ ] T061 [P] [US3] Test unitaire : détection volume anormal de requêtes dans tests/unit/detector/flood_detector_test.rs
- [ ] T062 [P] [US3] Test unitaire : détection de bursts dans tests/unit/detector/flood_detector_test.rs
- [ ] T063 [US3] Test d'intégration : 1000 req en 10s génère signal Flooding dans tests/integration/flood_test.rs

### Implémentation pour User Story 3 (TDD - GREEN phase)

- [ ] T064 [P] [US3] Implémenter compteur de requêtes par IP avec fenêtre glissante dans src/detector/flood_detector.rs
- [ ] T065 [US3] Implémenter détection de bursts (pic soudain) dans FloodDetector
- [ ] T066 [US3] Implémenter détection de taux soutenu anormal dans FloodDetector
- [ ] T067 [US3] Ajouter génération signal Flooding dans FloodDetector
- [ ] T068 [US3] Enregistrer FloodDetector dans DetectorRegistry
- [ ] T069 [US3] Implémenter rate limiting adaptatif dans src/ratelimit/adaptive.rs
- [ ] T070 [US3] Ajouter configuration seuils flood dans config/websec.toml.example

### Refactoring pour User Story 3

- [ ] T071 [US3] Documentation rustdoc pour FloodDetector

**Checkpoint** : User Stories 1, 2 ET 3 fonctionnent indépendamment

---

## Phase 6 : User Story 4 - Détection d'Injections (Priorité : P2)

**Objectif** : Détecter SQLi, XSS, RCE dans paramètres et URLs

**Test Indépendant** : Envoyer requêtes avec payloads d'injection connus

### Tests pour User Story 4 (TDD - RED phase) ⚠️

- [ ] T072 [P] [US4] Test unitaire : détection SQLi patterns dans tests/unit/detector/injection_detector_test.rs
- [ ] T073 [P] [US4] Test unitaire : détection XSS patterns dans tests/unit/detector/injection_detector_test.rs
- [ ] T074 [P] [US4] Test unitaire : détection RCE patterns dans tests/unit/detector/injection_detector_test.rs
- [ ] T075 [US4] Test d'intégration : payload SQLi génère signal SqlInjectionAttempt dans tests/integration/injection_test.rs

### Implémentation pour User Story 4 (TDD - GREEN phase)

- [ ] T076 [P] [US4] Créer patterns SQLi dans src/detector/injection_detector.rs (regex + aho-corasick)
- [ ] T077 [P] [US4] Créer patterns XSS dans src/detector/injection_detector.rs
- [ ] T078 [P] [US4] Créer patterns RCE dans src/detector/injection_detector.rs
- [ ] T079 [P] [US4] Créer patterns LFI/RFI dans src/detector/injection_detector.rs
- [ ] T080 [US4] Implémenter analyse paramètres GET/POST dans InjectionDetector
- [ ] T081 [US4] Implémenter analyse URL path dans InjectionDetector
- [ ] T082 [US4] Ajouter génération signaux (SqlInjectionAttempt, XssAttempt, RceAttempt, FileInclusionAttempt)
- [ ] T083 [US4] Enregistrer InjectionDetector dans DetectorRegistry
- [ ] T084 [US4] Ajouter configuration patterns injection dans config/websec.toml.example

### Refactoring pour User Story 4

- [ ] T085 [US4] Refactoring : optimiser matching multi-patterns avec aho-corasick
- [ ] T086 [US4] Documentation rustdoc pour InjectionDetector avec exemples de patterns

**Checkpoint** : User Stories 1-4 fonctionnent indépendamment

---

## Phase 7 : User Story 5 - Path Traversal (Priorité : P3)

**Objectif** : Bloquer tentatives d'accès à fichiers sensibles

### Tests pour User Story 5 (TDD - RED phase) ⚠️

- [ ] T087 [P] [US5] Test unitaire : détection path traversal patterns dans tests/unit/detector/path_detector_test.rs
- [ ] T088 [P] [US5] Test unitaire : détection fichiers sensibles dans tests/unit/detector/path_detector_test.rs
- [ ] T089 [US5] Test d'intégration : requête avec ../ génère signal SuspiciousPayload dans tests/integration/path_test.rs

### Implémentation pour User Story 5 (TDD - GREEN phase)

- [ ] T090 [P] [US5] Créer patterns path traversal dans src/detector/path_detector.rs (../, encodages)
- [ ] T091 [P] [US5] Créer liste fichiers sensibles dans PathDetector (.env, wp-config, etc.)
- [ ] T092 [US5] Implémenter normalisation de path dans PathDetector
- [ ] T093 [US5] Implémenter détection traversal dans PathDetector
- [ ] T094 [US5] Implémenter détection fichiers sensibles dans PathDetector
- [ ] T095 [US5] Ajouter génération signal SuspiciousPayload dans PathDetector
- [ ] T096 [US5] Enregistrer PathDetector dans DetectorRegistry

### Refactoring pour User Story 5

- [ ] T097 [US5] Documentation rustdoc pour PathDetector

---

## Phase 8 : User Story 6 - Scan de Vulnérabilités (Priorité : P3)

**Objectif** : Identifier phases de reconnaissance et scans automatiques

### Tests pour User Story 6 (TDD - RED phase) ⚠️

- [ ] T098 [P] [US6] Test unitaire : détection scan patterns dans tests/unit/detector/scan_detector_test.rs
- [ ] T099 [US6] Test d'intégration : rafale 404 génère signal VulnerabilityScan dans tests/integration/scan_test.rs

### Implémentation pour User Story 6 (TDD - GREEN phase)

- [ ] T100 [P] [US6] Créer liste chemins suspects dans src/detector/scan_detector.rs (wp-admin, phpmyadmin, etc.)
- [ ] T101 [US6] Implémenter comptage 404/403 par IP dans ScanDetector
- [ ] T102 [US6] Implémenter détection patterns scan dans ScanDetector
- [ ] T103 [US6] Ajouter génération signal VulnerabilityScan dans ScanDetector
- [ ] T104 [US6] Enregistrer ScanDetector dans DetectorRegistry

---

## Phase 9 : User Story 7 - Listes Noires/Blanches (Priorité : P2)

**Objectif** : Contrôle manuel sur certaines IPs

### Tests pour User Story 7 (TDD - RED phase) ⚠️

- [ ] T105 [P] [US7] Test unitaire : IP blacklistée est bloquée immédiatement dans tests/unit/lists/blacklist_test.rs
- [ ] T106 [P] [US7] Test unitaire : IP whitelistée est autorisée dans tests/unit/lists/whitelist_test.rs
- [ ] T107 [US7] Test d'intégration : blacklist override le scoring dans tests/integration/lists_test.rs

### Implémentation pour User Story 7 (TDD - GREEN phase)

- [ ] T108 [P] [US7] Implémenter Blacklist dans src/lists/blacklist.rs (HashSet thread-safe)
- [ ] T109 [P] [US7] Implémenter Whitelist dans src/lists/whitelist.rs
- [ ] T110 [US7] Intégrer vérification blacklist dans middleware (priorité haute)
- [ ] T111 [US7] Intégrer vérification whitelist dans middleware
- [ ] T112 [US7] Implémenter rechargement listes depuis fichier
- [ ] T113 [US7] Ajouter configuration listes dans config/websec.toml.example

---

## Phase 10 : Détecteurs Additionnels (Priorité : P3)

**Objectif** : Compléter les 12 familles de menaces

### Tests et Implémentation (TDD)

- [ ] T114 [P] Tests + implémentation ProtocolDetector dans src/detector/protocol_detector.rs (méthodes HTTP invalides, headers malformés)
- [ ] T115 [P] Tests + implémentation UploadDetector dans src/detector/upload_detector.rs (extensions dangereuses, webshells)
- [ ] T116 [P] Tests + implémentation HostDetector dans src/detector/host_detector.rs (host header abuse)
- [ ] T117 [P] Tests + implémentation SsrfDetector dans src/detector/ssrf_detector.rs (IPs privées dans params)
- [ ] T118 [P] Tests + implémentation SessionDetector dans src/detector/session_detector.rs (session hijacking)
- [ ] T119 [P] Tests + implémentation TlsDetector dans src/detector/tls_detector.rs (fingerprinting TLS)

---

## Phase 11 : Géolocalisation (Priorité : P2)

**Objectif** : Scoring différencié par pays

### Tests et Implémentation (TDD)

- [ ] T120 Créer trait GeoProvider dans src/geolocation/provider.rs
- [ ] T121 Tests + implémentation MaxMindProvider dans src/geolocation/maxmind.rs
- [ ] T122 Intégrer géolocalisation dans calcul de score (src/reputation/score.rs)
- [ ] T123 Ajouter configuration scores géographiques dans config/websec.toml.example

---

## Phase 12 : Persistance Avancée (Priorité : P2)

**Objectif** : Persistence durable pour production

### Tests et Implémentation (TDD)

- [ ] T124 Tests contract + implémentation RedisRepository dans src/storage/redis.rs
- [ ] T125 Tests contract + implémentation SledRepository dans src/storage/sled.rs (alternative embarquée)
- [ ] T126 Implémenter expiration automatique des entrées anciennes
- [ ] T127 Ajouter configuration storage dans config/websec.toml.example

---

## Phase 13 : Observabilité (Priorité : P2)

**Objectif** : Métriques et logging pour production

### Tests et Implémentation

- [ ] T128 [P] Implémenter MetricsCollector dans src/metrics/collector.rs (compteurs Prometheus)
- [ ] T129 [P] Ajouter endpoint /metrics pour exposition Prometheus
- [ ] T130 Implémenter logging structuré JSON pour toutes les décisions
- [ ] T131 Ajouter tracing spans pour performance profiling
- [ ] T132 Créer dashboard Grafana de base (config/)

---

## Phase 14 : Configuration Avancée (Priorité : P3)

**Objectif** : Configurabilité complète

### Tests et Implémentation

- [ ] T133 Tests + implémentation rechargement config à chaud (SIGHUP) dans src/config/loader.rs
- [ ] T134 Implémenter validation exhaustive de config au chargement
- [ ] T135 Créer config/rules.toml.example avec tous les paramètres documentés
- [ ] T136 Créer validation de cohérence des seuils (allow > ratelimit > block)

---

## Phase 15 : Performance & Optimisation (Priorité : P1)

**Objectif** : Atteindre les objectifs de performance

### Benchmarking et Optimisation

- [ ] T137 [P] Créer benchmark throughput proxy dans benches/proxy_throughput.rs
- [ ] T138 [P] Créer benchmark scoring dans benches/reputation_scoring.rs
- [ ] T139 Profiler avec flamegraph et identifier hot paths
- [ ] T140 Optimiser allocations dans hot paths (utiliser arena, object pool)
- [ ] T141 Optimiser parallélisation des détecteurs (rayon ou tokio::spawn)
- [ ] T142 Ajouter caching agressif pour patterns regex compilés
- [ ] T143 Valider latence p95 < 5ms avec criterion
- [ ] T144 Valider throughput > 10k req/s avec load testing (wrk, ab)

---

## Phase 16 : Tests de Charge & Sécurité (Priorité : P1)

**Objectif** : Validation robustesse production

### Tests End-to-End

- [ ] T145 Créer suite de tests E2E dans tests/integration/e2e_test.rs
- [ ] T146 Test de charge avec wrk : 10k req/s pendant 5 minutes
- [ ] T147 Test de stabilité : 24h de trafic continu
- [ ] T148 Test de memory leak : monitoring mémoire sur 24h
- [ ] T149 Test de graceful shutdown : aucune requête perdue
- [ ] T150 Audit de sécurité : cargo audit + revue manuelle code
- [ ] T151 Fuzzing des parseurs avec cargo-fuzz
- [ ] T152 Test des 12 familles de menaces avec payloads réels

---

## Phase 17 : Documentation Finale (Priorité : P2)

**Objectif** : Documentation complète pour utilisateurs et mainteneurs

### Documentation

- [ ] T153 [P] Compléter README.md avec installation, configuration, exemples
- [ ] T154 [P] Créer docs/architecture.md avec schémas
- [ ] T155 [P] Créer docs/threat-model.md avec analyse de sécurité
- [ ] T156 [P] Créer docs/operations.md (déploiement, monitoring, troubleshooting)
- [ ] T157 [P] Créer docs/tuning.md (guide tuning des seuils)
- [ ] T158 Générer rustdoc complète : cargo doc --no-deps
- [ ] T159 Créer CHANGELOG.md
- [ ] T160 Créer CONTRIBUTING.md

---

## Phase 18 : Packaging & Déploiement (Priorité : P2)

**Objectif** : Faciliter déploiement production

### Packaging

- [ ] T161 [P] Créer Dockerfile optimisé (multi-stage build)
- [ ] T162 [P] Créer docker-compose.yml pour stack complète (proxy + redis + backend test)
- [ ] T163 [P] Créer script d'installation pour distributions Linux
- [ ] T164 Créer systemd service file
- [ ] T165 Créer release binaries pour Linux (CI/CD)
- [ ] T166 Tester déploiement sur Kubernetes (manifests exemple)

---

## Dépendances & Ordre d'Exécution

### Dépendances de Phases

- **Setup (Phase 1)** : Aucune dépendance - peut démarrer immédiatement
- **Fondations (Phase 2)** : Dépend de Setup - BLOQUE toutes les user stories
- **User Stories (Phases 3-9)** : Toutes dépendent de Fondations
  - US1, US2, US3, US4 (P1/P2) peuvent être faites en parallèle après Fondations
  - US5, US6 (P3) peuvent être faites en parallèle
  - US7 (P2) peut être fait en parallèle
- **Détecteurs Additionnels (Phase 10)** : Dépend de Fondations
- **Géolocalisation (Phase 11)** : Dépend de Fondations + US1
- **Persistance (Phase 12)** : Dépend de Fondations
- **Observabilité (Phase 13)** : Dépend de Fondations
- **Performance (Phase 15)** : Dépend de toutes les US principales (1-4)
- **Tests de Charge (Phase 16)** : Dépend de Performance
- **Documentation (Phase 17)** : Peut commencer tôt, finalisée en dernier
- **Packaging (Phase 18)** : Dépend de tout le reste

### Au Sein de Chaque User Story

- **Tests TDD DOIVENT être écrits et ÉCHOUER avant implémentation (RED)**
- **Implémentation minimale pour faire passer les tests (GREEN)**
- **Refactoring pour améliorer qualité (REFACTOR)**
- Les tests marqués [P] peuvent être écrits en parallèle
- Les implémentations marquées [P] peuvent être faites en parallèle

### Opportunités de Parallélisation

- Toutes les tâches Setup marquées [P] en parallèle
- Toutes les tâches Fondations marquées [P] en parallèle (dans Phase 2)
- Une fois Fondations complète, toutes les US peuvent démarrer en parallèle (si capacité équipe)
- Tous les détecteurs additionnels (Phase 10) en parallèle
- Documentation (Phase 17) peut progresser en parallèle du développement

---

## Exemple de Parallélisation : User Story 1

```bash
# Lancer tous les tests US1 ensemble (RED phase) :
Task: "Test unitaire : détection User-Agent suspect"
Task: "Test unitaire : détection profil client non humain"
Task: "Test contract : BotDetector implémente trait Detector"

# Une fois tests qui échouent, implémenter :
Task: "Créer liste patterns User-Agent suspects"
Task: "Implémenter BotDetector::analyze()"
# etc.
```

---

## Stratégie d'Implémentation

### MVP First (User Stories 1 + 2)

1. Compléter Phase 1 : Setup
2. Compléter Phase 2 : Fondations (CRITIQUE)
3. Compléter Phase 3 : User Story 1 (Bots)
4. Compléter Phase 4 : User Story 2 (Brute Force)
5. **STOP et VALIDER** : Tester indépendamment, mesurer performance
6. Déployer/démo si prêt

### Livraison Incrémentale

1. Setup + Fondations → Base prête
2. + User Story 1 → Tester indépendamment → Déployer/Demo (MVP!)
3. + User Story 2 → Tester indépendamment → Déployer/Demo
4. + User Story 3 → Tester indépendamment → Déployer/Demo
5. Chaque story ajoute de la valeur sans casser les précédentes

### Stratégie Équipe Parallèle

Avec plusieurs développeurs :

1. Équipe complète Setup + Fondations ensemble
2. Une fois Fondations terminée :
   - Développeur A : User Story 1
   - Développeur B : User Story 2
   - Développeur C : User Story 3
3. Stories complétées et intégrées indépendamment

---

## Notes

- [P] tâches = fichiers différents, pas de dépendances
- [Story] label mappe la tâche à une user story spécifique pour traçabilité
- Chaque user story doit être complétable et testable indépendamment
- **Vérifier que les tests ÉCHOUENT avant d'implémenter (TDD strict)**
- Commit après chaque tâche ou groupe logique
- S'arrêter à n'importe quel checkpoint pour valider la story indépendamment
- À éviter : tâches vagues, conflits sur même fichier, dépendances inter-stories cassant l'indépendance
- **Constitution : TDD est NON-NÉGOCIABLE, les tests viennent TOUJOURS en premier**
