# Référence de Configuration - WebSec

## Format du fichier

WebSec utilise le format TOML pour sa configuration. Le fichier par défaut est `config/websec.toml`.

## Sections

### [server] - Configuration du serveur

```toml
[server]
listen = "0.0.0.0:8080"           # Obligatoire
backend = "http://127.0.0.1:3000" # Obligatoire
workers = 4                        # Optionnel, défaut: 4
```

#### `listen`
- **Type**: String
- **Format**: `IP:PORT` ou `HOST:PORT`
- **Exemples**:
  - `"0.0.0.0:8080"` - Écoute sur toutes les interfaces
  - `"127.0.0.1:8080"` - Localhost uniquement
  - `"[::]:8080"` - IPv6 toutes interfaces
- **Note**: Ports < 1024 nécessitent les permissions root

#### `backend`
- **Type**: String (URL)
- **Format**: `http://HOST:PORT` ou `https://HOST:PORT`
- **Exemples**:
  - `"http://localhost:3000"`
  - `"http://192.168.1.10:8000"`
  - `"https://backend.internal:443"`
- **Note**: WebSec préserve tous les chemins et query strings

#### `workers`
- **Type**: Integer
- **Défaut**: 4
- **Recommandation**: Nombre de CPU cores
- **Min**: 1, **Max**: 256

---

### [reputation] - Système de réputation

```toml
[reputation]
base_score = 100
threshold_allow = 70
threshold_ratelimit = 40
threshold_challenge = 20
threshold_block = 0
decay_half_life_hours = 24.0
correlation_penalty_bonus = 10
```

#### `base_score`
- **Type**: Integer (0-100)
- **Défaut**: 100
- **Description**: Score initial pour les nouvelles IPs
- **Recommandation**: Toujours 100 (principe du "trust by default")

#### `threshold_allow`
- **Type**: Integer (0-100)
- **Défaut**: 70
- **Description**: Score minimum pour ALLOW (forward au backend)
- **Valeurs typiques**:
  - **80-90**: Très strict (API sensibles)
  - **70**: Normal (défaut)
  - **50-60**: Permissif (développement)

#### `threshold_ratelimit`
- **Type**: Integer (0-100)
- **Défaut**: 40
- **Description**: Score minimum pour RATE_LIMIT
- **Entre**: `threshold_challenge` et `threshold_allow`

#### `threshold_challenge`
- **Type**: Integer (0-100)
- **Défaut**: 20
- **Description**: Score minimum pour CHALLENGE (CAPTCHA)
- **Entre**: `threshold_block` et `threshold_ratelimit`

#### `threshold_block`
- **Type**: Integer (0-100)
- **Défaut**: 0
- **Description**: Score minimum pour BLOCK (HTTP 403)
- **Valeurs typiques**: Toujours 0 (bloquer seulement score = 0)

#### `decay_half_life_hours`
- **Type**: Float
- **Défaut**: 24.0
- **Description**: Demi-vie du decay exponentiel en heures
- **Formule**: `poids = poids_initial * 0.5^(age/half_life)`
- **Valeurs typiques**:
  - **12.0**: Decay rapide (oubli rapide des incidents)
  - **24.0**: Normal (défaut)
  - **48.0**: Decay lent (mémoire longue)

#### `correlation_penalty_bonus`
- **Type**: Integer
- **Défaut**: 10
- **Description**: Pénalité supplémentaire si multiples familles d'attaques
- **Exemple**: SQL injection + XSS détectés → bonus de 10 points de pénalité

---

### [storage] - Stockage des profils

```toml
[storage]
storage_type = "memory"           # "memory" ou "redis"
cache_size = 10000                # Optionnel pour memory
redis_url = "redis://localhost:6379"  # Requis si storage_type = "redis"
```

#### `storage_type`
- **Type**: String
- **Valeurs**: `"memory"` ou `"redis"`
- **Défaut**: `"memory"`
- **Description**:
  - `memory`: InMemoryRepository (hashmap thread-safe)
  - `redis`: RedisRepository (stockage distribué)

#### `cache_size`
- **Type**: Integer
- **Défaut**: 10000
- **Description**: Nombre max de profils en mémoire (memory seulement)

#### `redis_url`
- **Type**: String
- **Format**: `redis://[user:pass@]host:port[/db]`
- **Exemples**:
  - `"redis://localhost:6379"`
  - `"redis://:password@localhost:6379/0"`
  - `"redis://user:pass@redis.internal:6379/1"`

---

### [geolocation] - Filtrage géographique

```toml
[geolocation]
enabled = true
database = "/usr/share/GeoIP/GeoLite2-Country.mmdb"

[geolocation.penalties]
CN = 15   # Chine
RU = 15   # Russie
NG = 20   # Nigeria
```

#### `enabled`
- **Type**: Boolean
- **Défaut**: false
- **Description**: Active/désactive la géolocalisation

#### `database`
- **Type**: String (chemin fichier)
- **Format**: Chemin vers MaxMind GeoLite2/GeoIP2 database
- **Télécharger**: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

#### `penalties`
- **Type**: Table (code pays ISO → pénalité)
- **Codes pays**: ISO 3166-1 alpha-2 (2 lettres)
- **Pénalités**: 0-50 recommandé
- **Exemples**:
  ```toml
  CN = 15  # Chine
  RU = 15  # Russie
  KP = 30  # Corée du Nord
  IR = 25  # Iran
  ```

---

### [ratelimit] - Rate limiting dynamique

```toml
[ratelimit]
normal_rpm = 1000
normal_burst = 100
suspicious_rpm = 200
suspicious_burst = 20
aggressive_rpm = 50
aggressive_burst = 5
window_duration_secs = 60
```

#### Mode Normal (score >= threshold_allow)
- `normal_rpm`: Requêtes/minute (défaut: 1000)
- `normal_burst`: Rafale maximale (défaut: 100)

#### Mode Suspicious (threshold_ratelimit <= score < threshold_allow)
- `suspicious_rpm`: Requêtes/minute (défaut: 200)
- `suspicious_burst`: Rafale maximale (défaut: 20)

#### Mode Aggressive (score < threshold_ratelimit)
- `aggressive_rpm`: Requêtes/minute (défaut: 50)
- `aggressive_burst`: Rafale maximale (défaut: 5)

#### `window_duration_secs`
- **Type**: Integer
- **Défaut**: 60
- **Description**: Taille de la fenêtre glissante en secondes

---

### [logging] - Configuration des logs

```toml
[logging]
level = "info"
format = "json"
```

#### `level`
- **Type**: String
- **Valeurs**: `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`
- **Défaut**: `"info"`
- **Recommandations**:
  - Production: `"info"` ou `"warn"`
  - Staging: `"debug"`
  - Développement: `"trace"`

#### `format`
- **Type**: String
- **Valeurs**: `"json"` ou `"pretty"`
- **Défaut**: `"json"`
- **Description**:
  - `json`: Machine-readable, pour ELK/Splunk
  - `pretty`: Human-readable, pour développement

---

### [metrics] - Métriques Prometheus

```toml
[metrics]
enabled = true
port = 9090
```

#### `enabled`
- **Type**: Boolean
- **Défaut**: true
- **Description**: Active/désactive les métriques

#### `port`
- **Type**: Integer
- **Défaut**: 9090
- **Description**: Port pour l'endpoint `/metrics` (futur)

---

## Configuration complète (exemple)

```toml
# Configuration de production recommandée

[server]
listen = "0.0.0.0:8080"
backend = "http://localhost:3000"
workers = 8  # Ajuster selon CPU

[reputation]
base_score = 100
threshold_allow = 75      # Légèrement plus strict
threshold_ratelimit = 45
threshold_challenge = 25
threshold_block = 0
decay_half_life_hours = 24.0
correlation_penalty_bonus = 10

[storage]
storage_type = "redis"    # Distribution pour HA
redis_url = "redis://redis.internal:6379/0"
cache_size = 10000

[geolocation]
enabled = true
database = "/var/lib/GeoIP/GeoLite2-Country.mmdb"

[geolocation.penalties]
CN = 15
RU = 15
KP = 30
IR = 25

[ratelimit]
normal_rpm = 1000
normal_burst = 100
suspicious_rpm = 150
suspicious_burst = 15
aggressive_rpm = 30
aggressive_burst = 3
window_duration_secs = 60

[logging]
level = "info"
format = "json"

[metrics]
enabled = true
port = 9090
```

## Validation

Pour valider votre configuration:

```bash
./websec --show-config
```

## Variables d'environnement

WebSec supporte le remplacement de variables (futur):

```toml
backend = "${BACKEND_URL}"
redis_url = "${REDIS_URL}"
```

Puis:

```bash
export BACKEND_URL="http://localhost:3000"
export REDIS_URL="redis://localhost:6379"
./websec
```

## Rechargement à chaud

Pour recharger la configuration sans redémarrage (futur):

```bash
kill -HUP $(pidof websec)
```
