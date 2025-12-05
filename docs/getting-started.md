# Guide de Démarrage Rapide - WebSec

## Introduction

WebSec est un reverse proxy de sécurité intelligent qui protège vos applications web contre les menaces en temps réel grâce à un système de réputation dynamique.

## Installation

### Prérequis

- Rust 1.75 ou supérieur
- Git
- Tokio runtime (inclus automatiquement)

### Compilation depuis les sources

```bash
# Cloner le dépôt
git clone https://github.com/yrbane/websec.git
cd websec

# Compiler en mode release
cargo build --release --features tls

# Le binaire est disponible dans target/release/websec
./target/release/websec --version
```

## Configuration

### Fichier de configuration

WebSec utilise un fichier TOML pour la configuration. Copiez l'exemple fourni:

```bash
cp config/websec.toml.example websec.toml
```

### Configuration minimale

```toml
[server]
listen = "0.0.0.0:8080"           # Adresse d'écoute du proxy
backend = "http://127.0.0.1:3000" # URL de votre application backend
workers = 4                        # Nombre de workers (CPU cores recommandé)

[reputation]
base_score = 100                   # Score initial pour les nouvelles IPs
threshold_allow = 70               # Seuil pour ALLOW (forward)
threshold_ratelimit = 40           # Seuil pour RATE_LIMIT
threshold_challenge = 20           # Seuil pour CHALLENGE (Captcha)
threshold_block = 0                # Seuil pour BLOCK

[logging]
level = "info"                     # debug, info, warn, error
format = "json"                    # json ou pretty

[storage]
type = "redis"
redis_url = "redis://127.0.0.1:6379"
```

## Lancement

### Mode simple

```bash
# Utilise websec.toml par défaut si défini dans la variable d'environnement
export WEBSEC_CONFIG=websec.toml
./target/release/websec run

# Avec une config spécifique
./target/release/websec run --config /path/to/custom.toml
```

### Afficher la configuration

```bash
./target/release/websec show-config --config websec.toml
```

### Mode validation (dry-run)

```bash
./target/release/websec run --dry-run --config websec.toml
```

## Architecture de base

```
Client HTTP → WebSec Proxy → Détecteurs → Moteur de Décision → Backend
                                                ↓
                                    [ALLOW/BLOCK/CHALLENGE/RATE_LIMIT]
```

### Flux de requête

1. **Réception**: WebSec reçoit la requête HTTP
2. **Extraction IP**: Détection de l'IP réelle (X-Forwarded-For, X-Real-IP)
3. **Analyse**: Passage par 9 détecteurs de menaces
4. **Scoring**: Calcul du score de réputation
5. **Décision**: Choix de l'action selon les seuils
6. **Action**:
   - **ALLOW**: Forward au backend
   - **RATE_LIMIT**: HTTP 429 (Too Many Requests)
   - **CHALLENGE**: Afficher CAPTCHA mathématique (à venir)
   - **BLOCK**: HTTP 403 (Forbidden)

## Détecteurs disponibles

WebSec intègre 12 détecteurs de menaces organisés en stratégies:

1. **BotDetector**: Détecte les bots malveillants (User-Agent suspects, comportement)
2. **BruteForceDetector**: Tentatives de force brute sur login et credential stuffing
3. **FloodDetector**: Flooding et attaques DDoS (bursts)
4. **InjectionDetector**: SQL injection, XSS, Command injection, Path traversal
5. **ScanDetector**: Scans de vulnérabilités (404 bursts, fichiers sensibles)
6. **HeaderDetector**: Manipulation de headers HTTP (Host, CRLF)
7. **GeoDetector**: Filtrage géographique (pays à risque, impossible travel)
8. **ProtocolDetector**: Violations de protocole HTTP
9. **SessionDetector**: Hijacking et anomalies de session

## Système de Réputation

### Principe

Chaque IP a un score de 0 à 100:
- **100**: IP parfaitement propre
- **70-99**: IP normale (ALLOW)
- **40-69**: IP suspecte (RATE_LIMIT)
- **20-39**: IP dangereuse (CHALLENGE)
- **0-19**: IP malveillante (BLOCK)

### Decay temporel

Les signaux de menace s'affaiblissent avec le temps (demi-vie configurable):
- **half_life**: 24 heures par défaut
- **Formule**: `poids_actuel = poids_initial * 0.5^(age/half_life)`

### Corrélation

Si plusieurs types d'attaques sont détectés simultanément (ex: SQLi + Scan), un bonus de pénalité est appliqué (par défaut +10).

## Exemples d'utilisation

### Protéger une API REST

```toml
[server]
listen = "0.0.0.0:8080"
backend = "http://localhost:3000"  # Votre API

[reputation]
threshold_allow = 80               # Plus strict pour une API
threshold_challenge = 30
```

```bash
./target/release/websec run --config api.toml
```

### Protéger un site web avec authentification

```toml
[server]
listen = "0.0.0.0:443"
backend = "http://localhost:8000"

[reputation]
base_score = 100
threshold_allow = 70
threshold_challenge = 25
```

### Mode développement

```toml
[logging]
level = "debug"
format = "pretty"                  # Logs lisibles

[reputation]
base_score = 100
threshold_allow = 50               # Moins strict en dev
threshold_block = 10
```

## Monitoring

### Headers de réponse

WebSec ajoute des headers à chaque réponse (sauf si bloqué):

```http
X-WebSec-Decision: ALLOW
X-WebSec-Score: 85
```

### Métriques Prometheus

Les métriques sont exposées sur un port dédié (défaut 9090):

- `websec_requests_total`: Compteur total de requêtes
- `websec_decisions{decision="allow|block|challenge|rate_limit"}`: Décisions par type
- `websec_latency_seconds`: Histogramme de latence
- `websec_reputation_score{ip}`: Score de réputation par IP
- `websec_signals_total{signal_type="..."}`: Compteur par type de menace

### Logs structurés

Format JSON pour intégration avec ELK, Splunk, etc.:

```json
{
  "timestamp": "2025-11-19T10:30:00Z",
  "level": "WARN",
  "ip": "1.2.3.4",
  "path": "/admin/login",
  "decision": "BLOCK",
  "score": 15,
  "signals": ["FailedLogin", "SqlSyntaxPattern"]
}
```

## Troubleshooting

### Le proxy ne démarre pas

```bash
# Vérifier que le port n'est pas déjà utilisé
sudo netstat -tulpn | grep 8080

# Vérifier les permissions (ports < 1024)
sudo setcap 'cap_net_bind_service=+ep' ./target/release/websec
./target/release/websec run
```

### Trop de faux positifs

Augmentez les seuils dans la configuration ou réduisez les poids des signaux spécifiques.

```toml
[reputation]
threshold_allow = 60       # Au lieu de 70
threshold_challenge = 15   # Au lieu de 20
```

### Performances dégradées

```bash
# Augmenter le nombre de workers
[server]
workers = 8  # Nombre de CPU cores

# Vérifier la santé du stockage
./target/release/websec check-storage
```

## Prochaines étapes

- [Configuration avancée](configuration.md)
- [Guide de déploiement](deployment.md)
- [Architecture détaillée](architecture.md)

## Support

- Issues: https://github.com/yrbane/websec/issues
