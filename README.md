```
 ░▒█░░▒█░█▀▀░█▀▀▄░▒█▀▀▀█░█▀▀░█▀▄
 ░▒█▒█▒█░█▀▀░█▀▀▄░░▀▀▀▄▄░█▀▀░█░░
 ░▒▀▄▀▄▀░▀▀▀░▀▀▀▀░▒█▄▄▄█░▀▀▀░▀▀▀
```

# WebSec 🛡️

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-144%20passing-success)](https://github.com/yrbane/websec)
[![Security](https://img.shields.io/badge/security-6%2F6%20issues%20fixed-brightgreen)](https://github.com/yrbane/websec/issues?q=label%3Asecurity)
[![Performance](https://img.shields.io/badge/latency-%3C1ms-brightgreen)](benches/)

**WebSec** est un **reverse proxy de sécurité** haute performance écrit en Rust, conçu pour protéger vos serveurs web contre les menaces HTTP(S) en temps réel. Transparent, configurable et prêt pour la production.

> 🎉 **Version actuelle** : v0.2.0 (Production-Ready)
> ✅ **Performance auditée** : Latence de détection < 400µs (0.4ms)
> ✅ **Qualité** : 144 tests unitaires (0 échec), 0 warning clippy
> ✅ **Sécurité** : 6 failles critiques auditées et corrigées

---

## 🎯 Pourquoi WebSec ?

**Un WAF (Web Application Firewall) moderne qui ne demande AUCUNE modification de votre serveur web.**

WebSec s'installe en amont de votre serveur Apache/Nginx/Node.js et intercepte tout le trafic HTTP(S) :

```
Internet → WebSec :80/:443 → Votre Serveur :8080 (interne)
            ↓
       🛡️ Protection Active
```

### Protection complète contre :

- 🤖 **Bots malveillants** (scrapers, scanners de vulnérabilités, User-Agents suspects)
- 🔐 **Brute-force** (tentatives login, password spraying, credential stuffing)
- 🌊 **Flood/DDoS** (rate limiting adaptatif, protection contre les bursts)
- 💉 **Injections** (SQL, XSS, RCE, path traversal)
- 🔍 **Scans** (wp-admin, .env, .git, fichiers sensibles, sondes 404)
- 🌍 **Géolocalisation** (filtrage par pays à risque, détection "impossible travel")
- 🔒 **Manipulation headers** (CRLF injection, host poisoning, headers anormaux)
- 🍪 **Anomalies de session** (hijacking, fixation)

---

## ⚡ Performance Auditée (Benchmark v0.2.0)

Les benchmarks réalisés sur l'architecture actuelle montrent une latence négligeable :

| Composant | Latence Moyenne | Impact |
|-----------|-----------------|--------|
| **Moteur de Décision** | **~2 ns** | Invisible |
| **Détection Bot** | **~230 ns** | Invisible |
| **Détection Injection** | **~1.6 µs** | Invisible |
| **Pipeline Complet** | **~400 µs** | **< 0.5 ms** |
| **Latence sous charge** | **~0.9 ms** | (à 100 req concurrentes) |

WebSec est conçu pour traiter **10,000+ req/s** sur un matériel standard sans ralentir votre application.

---

## ✨ Fonctionnalités Clés

### 🛡️ Sécurité & Fiabilité

- **Déploiement sans interruption** : Architecture stateless, redémarrage à chaud.
- **Zéro configuration backend** : Apache/Nginx continuent de fonctionner sans changement.
- **Support TLS natif** : Terminaison HTTPS avec support SNI (multi-domaines).
- **Conformité RGPD** : Minimisation des données, aucun stockage de credentials.

### 🔌 Installation & Déploiement

- **Assistant interactif** : Commande `websec setup` pour configurer automatiquement Apache.
- **Docker Ready** : Image Alpine ultra-légère (13MB) avec docker-compose.
- **Mode Standalone** : Binaire unique sans dépendance externe obligatoire.

### 📊 Observabilité

- **Métriques Prometheus** : Exposition native sur port dédié (9090).
- **Logs Structurés** : Format JSON pour intégration facile (ELK, Grafana, Datadog).
- **CLI Admin** : Outil en ligne de commande pour statistiques en temps réel et gestion.

---

## 🚀 Installation Rapide

### Option 1 : Via Script (Recommandé sur Linux)

Le script interactif gère les dépendances, l'utilisateur système et la configuration de base.

```bash
curl -sSL https://raw.githubusercontent.com/yrbane/websec/main/install.sh | sudo bash
```

### Option 2 : Docker

```bash
# Lancer la stack complète (WebSec + Redis + Backend test)
docker-compose up -d

# Vérifier que tout fonctionne
curl -I http://localhost:8080
```

### Option 3 : Compilation Manuelle

```bash
# Prérequis : Rust 1.75+
git clone https://github.com/yrbane/websec.git
cd websec
cargo build --release --features tls

# Lancer
./target/release/websec --config config/websec.toml.example
```

---

## ⚙️ Configuration

WebSec utilise un fichier `websec.toml` simple. Voici un exemple minimal :

```toml
[server]
listen = "0.0.0.0:80"
backend = "http://127.0.0.1:8080" # Votre serveur actuel
workers = 4

[reputation]
threshold_block = 20        # Bloquer en dessous de 20/100
threshold_challenge = 40    # Challenge entre 20 et 40

[storage]
type = "memory"             # ou "redis" pour la production, "sled" pour la persistance locale
path = "websec.db"          # Chemin pour le stockage Sled
```

Voir [config/websec.toml.example](config/websec.toml.example) pour toutes les options commentées en français.

---

## 🛠️ CLI d'Administration

WebSec inclut un outil CLI puissant pour gérer votre instance :

```bash
# Voir les statistiques en temps réel
websec stats

# Ajouter une IP en liste noire
websec lists blacklist add 1.2.3.4

# Vérifier la configuration avant redémarrage
websec run --dry-run

# Tester la connexion au stockage
websec check-storage
```

---

## 📚 Documentation

Toute la documentation est disponible dans le dossier `docs/` :

- **[Guide de Démarrage](docs/getting-started.md)** : Pour commencer rapidement.
- **[Guide Apache](docs/apache-configuration-guide.md)** : Configurer WebSec devant Apache.
- **[Guide de Déploiement](docs/deployment.md)** : Bonnes pratiques pour la production.
- **[Architecture](docs/architecture.md)** : Fonctionnement interne détaillé.
- **[Menaces Gérées](docs/Menaces.md)** : Détail des attaques bloquées.

---

## 🤝 Contribuer

Les contributions sont bienvenues ! WebSec suit une approche stricte de qualité :

1. **Tests d'abord (TDD)** : Toute fonctionnalité doit avoir un test associé.
2. **Zéro Warning** : Le code doit passer `cargo clippy` sans avertissement.
3. **Documentation** : Les nouvelles fonctionnalités doivent être documentées.

```bash
# Lancer la suite de tests complète
cargo test

# Lancer les benchmarks
cargo bench
```

---

## 📄 Licence

Distribué sous licence **MIT**. Voir [LICENSE](LICENSE) pour plus d'informations.

---

**Développé avec 🦀 Rust et ❤️ pour la sécurité web**
