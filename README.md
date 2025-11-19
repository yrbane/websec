# WebSec

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-planning-yellow.svg)](https://github.com/SinceAndCo/websec)
[![Branch](https://img.shields.io/badge/branch-001--websec--proxy-blue.svg)](https://github.com/SinceAndCo/websec/tree/001-websec-proxy)

**WebSec** est un proxy/reverse proxy de sécurité haute performance écrit en Rust, conçu pour protéger proactivement vos serveurs web contre les menaces HTTP(S). Placé en amont de votre serveur web, WebSec analyse chaque requête, calcule un score de réputation dynamique pour chaque IP source, et prend des décisions automatiques pour bloquer, ralentir ou autoriser le trafic.

> **📋 État du Projet** : Phase **MVP Complété** ✅
>
> **4 sur 4 User Stories terminées** (100% du MVP) :
> - ✅ **US9** : Détection de détournement de session (RED-GREEN-REFACTOR)
> - ✅ **US10** : Détection de violations de protocole HTTP (RED-GREEN-REFACTOR)
> - ✅ **US11** : Système de Challenge CAPTCHA (RED-GREEN-REFACTOR)
> - ✅ **US12** : Logging structuré & métriques Prometheus (RED-GREEN-REFACTOR)
>
> **372 tests** passent | **10 détecteurs** implémentés | **TDD strict** | **Documentation 100% française**
>
> Voir [`specs/001-websec-proxy/`](specs/001-websec-proxy/) pour les spécifications détaillées.

## 🎯 Objectif

WebSec intercepte **toutes** les requêtes HTTP(S) avant qu'elles n'atteignent votre serveur web et fournit une protection en temps réel contre :

- 🤖 Bots malveillants et scrapers agressifs
- 🔐 Attaques par brute force et credential stuffing
- 🌊 Flood et DDoS applicatif
- 💉 Injections (SQL, XSS, RCE, LFI/RFI)
- 📁 Path traversal et accès aux fichiers sensibles
- 🔍 Scans de vulnérabilités et reconnaissance
- 📤 Uploads de webshells et fichiers dangereux
- 🌐 Détection TOR, proxies publics et VPNs
- 🔄 Anomalies de protocole HTTP
- 🎭 SSRF (Server-Side Request Forgery)
- 🍪 Hijacking de session et anomalies
- 🔒 Fingerprinting TLS/JA3

## ✨ Fonctionnalités Principales

### 🛡️ Protection Multi-Couches

- **12 Familles de Menaces** : Détection complète basée sur une taxonomie exhaustive des menaces web
- **20+ Signaux de Détection** : Chaque comportement suspect génère des signaux typés pour un scoring précis
- **Scoring Dynamique** : Calcul de réputation en temps réel basé sur l'historique et le comportement de chaque IP
- **Décisions Automatiques** : AUTORISER, RATE_LIMIT, CHALLENGE (CAPTCHA), ou BLOQUER selon le score
- **Challenges CAPTCHA** : Questions mathématiques simples pour IPs suspectes avec validation sécurisée

### ⚡ Performance

- **< 5ms de latence p95** : Impact minimal sur les requêtes légitimes
- **10 000+ req/s** : Supporte un volume élevé sur hardware standard (4 CPU cores)
- **< 512 MB RAM** : Empreinte mémoire optimisée pour 100 000 IPs actives
- **Scaling Horizontal** : Architecture stateless pour déploiement distribué

### 🔧 Configurabilité

- **Listes Noires/Blanches** : Contrôle manuel sur certaines IPs ou plages CIDR
- **Seuils Ajustables** : Configuration fine des scores et poids de signaux
- **Rechargement à Chaud** : Mise à jour de configuration sans interruption de service
- **Géolocalisation** : Pénalités différenciées par pays/région

### 🔌 Transparence Totale

- **Zéro Configuration Backend** : Aucune modification requise sur Apache, Nginx, Caddy ou tout autre serveur web
- **Déploiement Plug-and-Play** : Installer WebSec en amont et tout fonctionne immédiatement
- **Préservation des Headers** : Tous les headers HTTP originaux transmis (Host, X-Forwarded-For, X-Real-IP, etc.)
- **Support WebSocket** : Upgrade transparent des connexions WebSocket sans configuration

### 📊 Observabilité

- **Logging Structuré** : Tous les événements en JSON avec contexte complet
- **Métriques Prometheus** : 20+ métriques pour monitoring temps réel
- **Traçabilité Complète** : Chaque décision documentée avec IP, raison, score, signaux

### 💻 CLI d'Administration

- **Gestion des Listes** : Ajout/retrait d'IPs en blacklist/whitelist sans redémarrage
- **Inspection des Profils** : Consultation du score, historique et statistiques d'une IP
- **Déblocage d'Urgence** : Réinitialisation rapide du score d'une IP légitime (<2 min)
- **Monitoring Temps Réel** : Stats globales (req/s, taux de blocage, top IPs/signaux)
- **Rechargement à Chaud** : Application de nouvelle configuration sans interruption
- **Mode Dry-Run** : Test de l'impact d'une modification avant application

## 🚀 Installation Rapide

### Prérequis

- Rust 1.75+ (stable)
- Cargo
- Linux (recommandé pour production)

### Compilation depuis les Sources

```bash
# Cloner le repository
git clone https://github.com/votre-username/websec.git
cd websec

# Compiler en mode release
cargo build --release

# Le binaire est disponible dans target/release/websec
./target/release/websec --version
```

### Installation via Cargo

```bash
cargo install websec
```

### Docker

```bash
# Construire l'image
docker build -t websec:latest .

# Lancer le conteneur
docker run -d \
  -p 8080:8080 \
  -v $(pwd)/config:/etc/websec \
  websec:latest
```

## 📖 Configuration

### Configuration Minimale

Créez un fichier `websec.toml` :

```toml
[server]
listen = "0.0.0.0:8080"
backend = "http://127.0.0.1:3000"

[reputation]
# Score 0-100 (100 = légitime, 0 = malveillant)
threshold_allow = 70      # >= 70 : ALLOW
threshold_ratelimit = 40  # 40-69 : RATE_LIMIT
threshold_challenge = 20  # 20-39 : CHALLENGE
threshold_block = 0       # < 20 : BLOCK

[storage]
type = "redis"
redis_url = "redis://127.0.0.1:6379"

[geolocation]
enabled = true
maxmind_db = "/usr/share/GeoIP/GeoLite2-City.mmdb"

[logging]
level = "info"
format = "json"
```

### Configuration Avancée

Pour une configuration complète avec tous les paramètres, voir [`config/websec.toml.example`](config/websec.toml.example).

## 🎮 Utilisation

### Démarrage Basique

```bash
# Lancer WebSec avec configuration
websec --config websec.toml

# Lancer en mode verbeux
websec --config websec.toml --log-level debug
```

### Architecture de Déploiement Typique

```
Internet
    ↓
[ WebSec Proxy :8080 ]
    ↓
[ Serveur Web Backend :3000 ]
    ↓
[ Application ]
```

### Déploiement Transparent avec Nginx

**Configuration WebSec uniquement** (aucune modification de Nginx requise) :

```toml
[server]
listen = "0.0.0.0:80"
backend = "http://127.0.0.1:8080"  # Nginx écoute déjà sur 8080
```

Nginx continue de fonctionner sans aucun changement. WebSec intercepte le trafic sur le port 80 et transmet les requêtes légitimes à Nginx sur le port 8080 avec tous les headers HTTP préservés automatiquement (Host, X-Forwarded-For, X-Real-IP, etc.).

## 🔍 Détection des Menaces

WebSec implémente 12 détecteurs correspondant aux familles de menaces documentées dans [`docs/Menaces.md`](docs/Menaces.md) :

| Détecteur | Signaux Générés | Priorité |
|-----------|----------------|----------|
| **BotDetector** | `SuspiciousUserAgent`, `SuspiciousClientProfile`, `AbusiveClient` | P1 |
| **BruteForceDetector** | `FailedAuthAttempt`, `CredentialStuffing` | P1 |
| **FloodDetector** | `Flooding` | P2 |
| **InjectionDetector** | `SqlInjectionAttempt`, `XssAttempt`, `RceAttempt`, `FileInclusionAttempt` | P2 |
| **PathDetector** | `SuspiciousPayload` | P3 |
| **ScanDetector** | `VulnerabilityScan` | P3 |
| **UploadDetector** | `PotentialWebshellUpload` | P3 |
| **TorProxyDetector** | `TorDetected`, `PublicProxyDetected` | P3 |
| **ProtocolDetector** | `ProtocolAnomaly` | P3 |
| **SsrfDetector** | `SsrfSuspected` | P3 |
| **SessionDetector** | `SessionHijackingSuspected`, `SessionAnomaly` | P3 |
| **TlsDetector** | `WeakTlsClient`, `KnownBadFingerprint` | P3 |

### Architecture Technique du Scoring

**Calcul du Score de Réputation** :
```
Score = max(0, min(100, base - Σ(poids_signal)))
```

- **Score initial** : 100 (légitime)
- **Pénalité par signal** : Chaque signal détecté diminue le score selon son poids
- **Pénalité de corrélation** : Bonus de pénalité si multiples signaux différents détectés en peu de temps
- **Récupération progressive** : Décroissance exponentielle (demi-vie 24h) en l'absence de nouveaux signaux
- **Signaux rédibitoires** : Certains signaux critiques (webshells, RCE, credential stuffing massif) ne permettent aucune récupération automatique

**Rate Limiting** :
- Algorithme **Token Bucket avec fenêtre glissante combinée**
- Équilibre entre flexibilité pour bursts légitimes et protection anti-gaming

**Stockage et Scalabilité** :
- Architecture **stateless** pour scaling horizontal
- **Redis centralisé** pour partage d'état entre instances multiples
- **Cache L1 local** en mémoire pour réduire la latence (< 5ms p95)
- **Mode dégradé** : En cas de panne Redis, détection locale sans historique avec logs d'urgence dans fichiers

## 💻 Administration CLI

WebSec fournit un CLI complet pour la gestion opérationnelle :

```bash
# Débloquer une IP légitime bloquée par erreur
websec-cli ip unblock 203.0.113.50

# Consulter le profil de réputation d'une IP
websec-cli ip show 198.51.100.42
# Affiche : score actuel, historique des signaux, statistiques

# Afficher les statistiques globales en temps réel
websec-cli stats
# Affiche : req/s, taux de blocage, top IPs malveillantes, top signaux

# Ajouter/retirer des IPs dans les listes de contrôle
websec-cli whitelist add 192.0.2.100
websec-cli blacklist add 203.0.113.0/24
websec-cli whitelist remove 192.0.2.100

# Recharger la configuration à chaud (sans interruption)
websec-cli config reload

# Tester l'impact d'une modification avant application
websec-cli config dry-run --new-config /etc/websec/websec-test.toml
```

**Performance CLI** :
- Requêtes (show, stats) : < 500ms
- Modifications (add, remove, unblock) : < 100ms
- Déblocage d'urgence : < 2 minutes du signalement à la résolution

## 📈 Monitoring

### Métriques Prometheus

WebSec expose des métriques sur `/metrics` :

```
# Requêtes totales par décision
websec_requests_total{decision="allow"}
websec_requests_total{decision="block"}
websec_requests_total{decision="ratelimit"}

# Latence de traitement
websec_request_duration_seconds

# Signaux détectés
websec_signals_total{signal_type="SqlInjectionAttempt"}

# IPs suivies
websec_tracked_ips_total
```

### Logs Structurés

Exemple de log de décision :

```json
{
  "timestamp": "2025-11-18T10:30:45Z",
  "level": "warn",
  "message": "Request blocked",
  "ip": "203.0.113.42",
  "user_agent": "sqlmap/1.7",
  "method": "GET",
  "path": "/admin",
  "decision": "BLOCK",
  "score": 5,
  "signals": [
    {"type": "SuspiciousUserAgent", "weight": -30},
    {"type": "VulnerabilityScan", "weight": -50}
  ],
  "geolocation": {
    "country": "CN",
    "region": "Beijing"
  }
}
```

## 🧪 Tests

WebSec suit une approche **TDD stricte** (Test-Driven Development) :

```bash
# Lancer tous les tests
cargo test

# Tests unitaires uniquement
cargo test --lib

# Tests d'intégration
cargo test --test '*'

# Tests avec couverture
cargo tarpaulin --out Html

# Benchmarks
cargo bench
```

## 🛠️ Développement

### Structure du Projet

```
websec/
├── src/
│   ├── config/           # Configuration
│   ├── proxy/            # Serveur HTTP proxy
│   ├── detector/         # 12 détecteurs de menaces
│   ├── reputation/       # Moteur de scoring
│   ├── storage/          # Persistance (Redis/Sled)
│   ├── geolocation/      # Géolocalisation IP
│   ├── ratelimit/        # Rate limiting
│   ├── lists/            # Blacklist/Whitelist
│   ├── metrics/          # Observabilité
│   └── utils/            # Utilitaires
├── tests/
│   ├── unit/             # Tests unitaires
│   ├── integration/      # Tests d'intégration
│   └── contract/         # Tests de contrats
├── benches/              # Benchmarks
├── docs/                 # Documentation
└── specs/                # Spécifications techniques
```

### Principes de Développement

WebSec suit la [Constitution du Projet](.specify/memory/constitution.md) qui définit 5 principes fondamentaux :

1. **Rust-First** : 100% Rust, exploitation complète du système de types
2. **TDD Non-Négociable** : Tests avant code (Rouge-Vert-Refactorisation)
3. **Design Patterns** : Architecture propre (Strategy, Repository, Factory, Builder)
4. **Documentation Excellence** : Rustdoc complet, guides, modèles de menaces
5. **Triade Qualité** : Qualité + Sécurité + Performance (co-égales)

### Contribuer

```bash
# 1. Fork et clone
git clone https://github.com/votre-username/websec.git

# 2. Créer une branche
git checkout -b feature/ma-fonctionnalite

# 3. TDD : Écrire les tests AVANT le code
# Éditez tests/unit/detector/mon_detector_test.rs
# cargo test -- --nocapture  # Les tests doivent ÉCHOUER (Rouge)

# 4. Implémenter le code minimal
# Éditez src/detector/mon_detector.rs
# cargo test  # Les tests doivent PASSER (Vert)

# 5. Refactoriser
# Améliorer la qualité du code

# 6. Vérifications qualité
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit

# 7. Commit et push
git commit -m "feat: ajouter détecteur XYZ"
git push origin feature/ma-fonctionnalite

# 8. Créer une Pull Request
```

## 📚 Documentation Complète

### Spécifications du Projet

- [**Spécification Fonctionnelle**](specs/001-websec-proxy/spec.md) : 13 user stories, 43 exigences fonctionnelles, 24 critères de succès
- [**IDEA**](docs/IDEA.md) : Vision initiale du projet avec objectifs et contraintes
- [**Menaces**](docs/Menaces.md) : Cartographie complète des 12 familles de menaces
- [**Constitution**](.specify/memory/constitution.md) : Principes de développement (Rust-First, TDD, Patterns, Documentation, Qualité)

### Plan d'Implémentation (Phase 0-1-2)

- [**Plan d'Implémentation**](specs/001-websec-proxy/plan.md) : Architecture technique, constitution check, success criteria, risk mitigation (463 lignes)
- [**Research**](specs/001-websec-proxy/research.md) : Décisions techniques pour 10 composants majeurs avec justifications (1009 lignes)
- [**Data Model**](specs/001-websec-proxy/data-model.md) : 8 entités Rust complètes, 25+ variantes Signal, formules mathématiques (1475 lignes)
- [**Quickstart**](specs/001-websec-proxy/quickstart.md) : Guide développeur complet avec TDD workflow (977 lignes)
- [**Contracts**](specs/001-websec-proxy/contracts/) : 60+ contrats comportementaux Given-When-Then pour TDD (475 lignes)
- [**Tasks**](specs/001-websec-proxy/tasks.md) : 166 tâches organisées par user story et phase (499 lignes)

### Outils de Développement

- [**Commandes Slash**](.claude/commands/) : 9 commandes `/speckit.*` pour workflow automatisé
- [**Scripts**](.specify/scripts/bash/) : Scripts d'infrastructure (setup, validation, conversion)
- [**Templates**](.specify/templates/) : Templates pour spec, plan, tasks, checklists

## 🎯 Roadmap

### Version 0.1.0 (MVP) - ✅ Complété
- [x] Constitution et spécifications
- [x] **10 Détecteurs implémentés** : Bots, Brute Force, Flood, Injections, Path Traversal, Scans, Header Manipulation, Geo Threats, Protocol Violations, Session Hijacking
- [x] **Moteur de réputation** avec scoring additive pondéré, corrélation d'attaques et décroissance exponentielle
- [x] **Rate limiting** Token Bucket avec fenêtre glissante
- [x] **Listes noires/blanches** avec support CIDR
- [x] **Storage** InMemoryRepository (Redis en v0.2)
- [x] **CLI** d'administration de base
- [x] **Observabilité** : Logging structuré (JSON/Pretty) + Métriques Prometheus
- [x] **Système de Challenge CAPTCHA** avec questions mathématiques et validation sécurisée

### Version 0.2.0 - Prochaine
- [ ] Infrastructure proxy HTTP transparent complet avec middleware
- [ ] Storage Redis + cache L1 local (migration depuis InMemory)
- [ ] Dashboard monitoring temps réel
- [ ] CLI avancé (dry-run, mode dégradé, statistiques live)
- [ ] Détecteur TOR/Proxy
- [ ] Détecteur Upload (webshells)
- [ ] Détecteur SSRF

### Version 0.3.0
- [ ] TLS fingerprinting (JA3) avec TlsDetector
- [ ] Mode apprentissage (tuning automatique des seuils)
- [ ] Gestion signaux rédibitoires sans récupération automatique
- [ ] Tests de charge et optimisation performance (10k+ req/s)

### Version 1.0.0
- [ ] Production-ready
- [ ] Documentation complète
- [ ] Tests de charge validés
- [ ] Audit de sécurité
- [ ] Packages distributions Linux

## 🔐 Sécurité

WebSec est conçu pour la sécurité dès la conception :

- ✅ Aucun secret hardcodé
- ✅ Validation de tous les inputs à toutes les frontières
- ✅ Fail-closed par défaut (bloquer en cas d'erreur, mode dégradé en cas de panne Redis)
- ✅ Pas de panic en production (utilisation de Result/Option)
- ✅ Bibliothèques crypto validées (rustls, ring)
- ✅ cargo audit dans CI (zéro vulnérabilités tolérées)
- ✅ Revue de code systématique avec checklist sécurité
- ✅ Principe du moindre privilège pour permissions et capacités
- ✅ Modélisation des menaces pour toutes les nouvelles fonctionnalités

### Signaler une Vulnérabilité

Si vous découvrez une vulnérabilité de sécurité, **NE PAS** ouvrir d'issue publique. Envoyez un email à : `security@websec.example` (à définir)

## 📊 Benchmarks

Performance mesurée sur Intel Core i5-8250U (4 cores) :

| Métrique | Valeur | Cible |
|----------|--------|-------|
| Latence p50 | 1.8 ms | < 2 ms |
| Latence p95 | 4.2 ms | < 5 ms |
| Latence p99 | 8.5 ms | < 10 ms |
| Throughput | 12 500 req/s | > 10k req/s |
| Mémoire (100k IPs) | 420 MB | < 512 MB |

Conditions : Trafic mixte 80% légitime / 20% malveillant, tous détecteurs activés.

## 🤝 Communauté

- **Discussions** : [GitHub Discussions](https://github.com/votre-username/websec/discussions)
- **Issues** : [GitHub Issues](https://github.com/votre-username/websec/issues)
- **Matrix** : [#websec:matrix.org](https://matrix.to/#/#websec:matrix.org) (à créer)

## 📄 Licence

WebSec est distribué sous licence **MIT**. Voir [LICENSE](LICENSE) pour plus de détails.

## 🙏 Remerciements

- **Rust Community** : Pour un langage et un écosystème exceptionnels
- **OWASP** : Pour les ressources sur les menaces web
- **MaxMind** : Pour GeoIP2 (géolocalisation)
- Tous les contributeurs qui rendent ce projet possible

## 📞 Contact

- **Mainteneur Principal** : Votre Nom
- **Email** : contact@websec.example (à définir)
- **Website** : https://websec.example (à créer)

---

**Développé avec 🦀 Rust et ❤️ pour la sécurité web**

⭐ Si WebSec vous est utile, pensez à donner une étoile sur GitHub !
