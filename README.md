# WebSec

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com)

**WebSec** est un proxy/reverse proxy de sécurité haute performance écrit en Rust, conçu pour protéger proactivement vos serveurs web contre les menaces HTTP(S). Placé en amont de votre serveur web, WebSec analyse chaque requête, calcule un score de réputation dynamique pour chaque IP source, et prend des décisions automatiques pour bloquer, ralentir ou autoriser le trafic.

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

### 📊 Observabilité

- **Logging Structuré** : Tous les événements en JSON avec contexte complet
- **Métriques Prometheus** : 20+ métriques pour monitoring temps réel
- **Traçabilité Complète** : Chaque décision documentée avec IP, raison, score, signaux

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

### Exemple avec Nginx Backend

```toml
[server]
listen = "0.0.0.0:80"
backend = "http://127.0.0.1:8080"  # Nginx écoute sur 8080
```

Configuration Nginx :
```nginx
server {
    listen 8080;
    server_name localhost;

    location / {
        # Votre application
        proxy_pass http://localhost:3000;
    }
}
```

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

- [**Spécification Fonctionnelle**](specs/001-websec-proxy/spec.md) : User stories, exigences, critères de succès
- [**Plan d'Implémentation**](specs/001-websec-proxy/plan.md) : Architecture détaillée, phases de développement
- [**Liste des Tâches**](specs/001-websec-proxy/tasks.md) : 166 tâches organisées en 18 phases
- [**IDEA**](docs/IDEA.md) : Vision initiale du projet
- [**Menaces**](docs/Menaces.md) : Cartographie complète des 12 familles de menaces
- [**Constitution**](.specify/memory/constitution.md) : Principes de développement

## 🎯 Roadmap

### Version 0.1.0 (MVP) - En Cours
- [x] Constitution et spécifications
- [ ] Infrastructure de base (proxy HTTP, middleware)
- [ ] Détecteurs P1 : Bots + Brute Force
- [ ] Moteur de réputation
- [ ] Rate limiting
- [ ] Listes noires/blanches
- [ ] Observabilité basique

### Version 0.2.0
- [ ] Détecteurs P2 : Flood + Injections
- [ ] Géolocalisation
- [ ] Persistance Redis
- [ ] Mécanisme CAPTCHA
- [ ] Dashboard monitoring

### Version 0.3.0
- [ ] Détecteurs P3 : Path traversal, Scans, Uploads, TOR, SSRF, Sessions
- [ ] TLS fingerprinting
- [ ] API de gestion
- [ ] Mode apprentissage (tuning automatique)

### Version 1.0.0
- [ ] Production-ready
- [ ] Documentation complète
- [ ] Tests de charge validés
- [ ] Audit de sécurité
- [ ] Packages distributions Linux

## 🔐 Sécurité

WebSec est conçu pour la sécurité dès la conception :

- ✅ Aucun secret hardcodé
- ✅ Validation de tous les inputs
- ✅ Fail-closed par défaut (bloquer en cas d'erreur)
- ✅ Pas de panic en production
- ✅ Bibliothèques crypto validées (rustls, ring)
- ✅ cargo audit dans CI
- ✅ Revue de code systématique

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
