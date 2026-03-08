```
 ░▒█░░▒█░█▀▀░█▀▀▄░▒█▀▀▀█░█▀▀░█▀▄
 ░▒█▒█▒█░█▀▀░█▀▀▄░░▀▀▀▄▄░█▀▀░█░░
 ░▒▀▄▀▄▀░▀▀▀░▀▀▀▀░▒█▄▄▄█░▀▀▀░▀▀▀
```

# WebSec 🛡️

[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-400%2B-success)](https://github.com/yrbane/websec)
[![Security](https://img.shields.io/badge/security-6%2F6%20issues%20fixed-brightgreen)](https://github.com/yrbane/websec/issues?q=label%3Asecurity)
[![Performance](https://img.shields.io/badge/latency-%3C1ms-brightgreen)](benches/)

**WebSec** est un **reverse proxy de sécurité** haute performance écrit en Rust, conçu pour protéger vos serveurs web contre les menaces HTTP(S) en temps réel. Transparent, configurable et prêt pour la production.

> 🎉 **Version actuelle** : v0.3.0
>
> ✅ **Performance auditée** : Latence de détection < 400µs (0.4ms)
>
> ✅ **HTTP/2 natif** : Support complet HTTP/2 frontend + HTTP/1.1 backend
>
> ✅ **TLS natif** : Terminaison HTTPS avec rustls (TLSv1.3, ALPN, SNI)
>
> ✅ **Qualité** : 400+ tests unitaires et d'intégration, 0 warning clippy

---

## 🎯 Pourquoi WebSec ?

**Un WAF (Web Application Firewall) moderne qui ne demande AUCUNE modification de votre serveur web.**

WebSec s'installe en amont de votre serveur Apache/Nginx/Node.js et intercepte tout le trafic HTTP(S) :

```
Internet → WebSec :80/:443 → Votre Serveur :8080 (interne)
              ↓
         🛡️ Protection Active
         🔐 TLS termination (TLSv1.3, HTTP/2)
         📡 X-Forwarded-Proto / X-Forwarded-Host / X-Real-IP
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
- 📡 **Proxy transparent** (X-Forwarded-Proto, X-Forwarded-Host, X-Real-IP automatiques)

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
- **Support TLS natif** : Terminaison HTTPS avec rustls (TLSv1.3, ALPN HTTP/2, SNI multi-domaines).
- **HTTP/2 complet** : Accepte HTTP/2 des clients, forward en HTTP/1.1 au backend.
- **Headers proxy** : `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Real-IP` automatiques.
- **Challenge Proof of Work** : Challenge SHA-256 transparent côté navigateur (pas de CAPTCHA externe).
- **Whitelist / Blacklist** : Gestion par fichier ou CLI, chargées au démarrage.
- **Conformité RGPD** : Minimisation des données, aucun stockage de credentials.

### 🔌 Installation & Déploiement

- **Assistant interactif** : Commande `websec setup` pour configurer automatiquement Apache.
- **Docker Ready** : Image multi-stage Alpine avec docker-compose.
- **Mode Standalone** : Binaire unique (~11 MB) sans dépendance externe obligatoire.

### 📊 Observabilité

- **Métriques Prometheus** : Exposition native sur port dédié (9090).
- **Logs Structurés** : Format JSON ou pretty pour intégration facile (ELK, Grafana, Datadog).
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
# Prérequis : Rust (edition 2021)
git clone https://github.com/yrbane/websec.git
cd websec
cargo build --release --features tls

# Lancer
./target/release/websec --config config/websec.toml.example
```

---

## ⚙️ Configuration

WebSec utilise un fichier `websec.toml` simple. Voici un exemple avec TLS :

```toml
[server]
listen = "[::]:80"                    # Fallback (utilisé si listeners vide)
backend = "http://127.0.0.1:8080"        # Votre serveur actuel
workers = 4

# Listener HTTP (port 80)
[[server.listeners]]
listen = "[::]:80"
backend = "http://127.0.0.1:8080"

# Listener HTTPS (port 443) — TLS terminé par WebSec
[[server.listeners]]
listen = "[::]:443"
backend = "http://127.0.0.1:8080"
[server.listeners.tls]
cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_file = "/etc/letsencrypt/live/example.com/privkey.pem"

[reputation]
base_score = 100            # Score initial (0-100, 100 = confiance totale)
threshold_allow = 70        # >= 70 : autoriser
threshold_ratelimit = 40    # 40-69 : rate limiter
threshold_challenge = 20    # 20-39 : challenge PoW
threshold_block = 0         # < 20  : bloquer

[storage]
type = "redis"              # "redis", "memory" ou "sled"
redis_url = "redis://127.0.0.1:6379"
```

WebSec ajoute automatiquement les headers `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-For` et `X-Real-IP` pour que le backend puisse distinguer HTTP/HTTPS et connaître l'IP du client.

Voir [config/websec.toml.example](config/websec.toml.example) pour toutes les options commentées en français (signal weights, géolocalisation, rate limiting, etc.).

---

## 🛠️ CLI d'Administration

WebSec inclut un outil CLI puissant pour gérer votre instance :

```bash
# Voir les statistiques en temps réel
websec stats

# Gérer les listes noires / blanches
websec lists blacklist add 1.2.3.4
websec lists whitelist add 203.0.113.10

# Configurer Apache automatiquement
websec setup

# Vérifier la configuration avant redémarrage
websec run --dry-run

# Tester la connexion au stockage
websec check-storage

# Afficher la configuration active
websec config
```

---

## 📚 Documentation

Toute la documentation est disponible dans le dossier `docs/` :

- **[Guide de Démarrage](docs/getting-started.md)** : Pour commencer rapidement.
- **[Guide Apache](docs/apache-configuration-guide.md)** : Configurer WebSec devant Apache.
- **[Configuration](docs/configuration.md)** : Référence complète de `websec.toml`.
- **[Guide de Déploiement](docs/deployment.md)** : Bonnes pratiques pour la production.
- **[Checklist Déploiement](docs/deployment-checklist.md)** : Vérifications pré-production.
- **[Architecture](docs/architecture.md)** : Fonctionnement interne détaillé.
- **[Menaces Gérées](docs/Menaces.md)** : Détail des attaques bloquées.
- **[Configuration SNI](docs/sni-configuration.md)** : TLS multi-domaines.
- **[Troubleshooting](docs/troubleshooting-guide.md)** : Résolution de problèmes courants.
- **[Script d'Installation](docs/install-script-guide.md)** : Détail de `install.sh`.

---

## 🤝 Contribuer

Les contributions sont bienvenues ! WebSec suit une approche stricte de qualité :

1. **Tests d'abord (TDD)** : Toute fonctionnalité doit avoir un test associé.
2. **Zéro Warning** : Le code doit passer `cargo clippy` sans avertissement.
3. **Documentation** : Les nouvelles fonctionnalités doivent être documentées.

```bash
# Lancer la suite de tests complète
cargo test --features tls

# Lancer les benchmarks
cargo bench
```

---

## 📄 Licence

Distribué sous licence **MIT**. Voir [LICENSE](LICENSE) pour plus d'informations.

---

**Développé avec 🦀 Rust et ❤️ pour la sécurité web**
