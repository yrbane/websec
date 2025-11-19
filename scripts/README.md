# Scripts WebSec

## test-backend.py

Backend HTTP simple pour tests E2E.

**Usage**:
```bash
python3 scripts/test-backend.py [PORT]
```

**Endpoints**:
- `GET /` - Page d'accueil HTML
- `GET /api/health` - Health check JSON
- `GET /api/users` - Liste d'utilisateurs (JSON)
- `GET /slow` - Réponse lente (2s)
- `POST /api/login` - Simule un login
- `POST /api/echo` - Écho du body

**Exemple**:
```bash
# Démarrer sur port 3000 (défaut)
python3 scripts/test-backend.py

# Démarrer sur port custom
python3 scripts/test-backend.py 8000
```

---

## e2e-test.sh

Script complet de test end-to-end.

**Fonctionnalités**:
1. Compile WebSec en mode release
2. Démarre le backend de test
3. Démarre WebSec proxy
4. Exécute une suite de tests fonctionnels
5. Test de charge optionnel (si `ab` installé)
6. Affiche les métriques finales
7. Nettoie automatiquement au exit

**Usage**:
```bash
./scripts/e2e-test.sh
```

**Tests exécutés**:
- ✅ GET / - Requête simple
- ✅ GET /metrics - Endpoint Prometheus
- ✅ GET /api/users - API JSON
- ✅ POST /api/echo - POST avec body
- ✅ Headers WebSec - Vérification headers personnalisés
- ⚡ Test de charge (100 requêtes, 10 concurrent)

**Logs**:
- `/tmp/backend.log` - Logs du backend
- `/tmp/websec.log` - Logs de WebSec
- `/tmp/ab.log` - Résultats ApacheBench

**Prérequis**:
- Python 3
- `curl` (requis)
- `ab` (Apache Bench - optionnel pour tests de charge)

**Exemple de sortie**:
```
🚀 Démarrage des tests E2E WebSec

📦 Compilation de WebSec...
  ✓ WebSec compilé

🔧 Démarrage du backend de test (port 3000)...
  ✓ Backend démarré (PID: 12345)

🛡️  Démarrage de WebSec (port 8080)...
  ✓ WebSec démarré (PID: 12346)

🧪 Tests fonctionnels

  Test 1: GET / ... ✓
  Test 2: GET /metrics ... ✓
  Test 3: GET /api/users ... ✓
  Test 4: POST /api/echo ... ✓
  Test 5: Headers WebSec ... ✓

⚡ Test de charge (Apache Bench)

  100 requêtes, 10 concurrentes...
  ✓ Requêtes/sec: 1234.56
  ✓ Temps moyen: 8.1ms

📊 Métriques finales

  Requêtes totales: 105
  Décisions ALLOW: 105

✅ Tous les tests E2E ont réussi!
```

---

## docker-build.sh

Script de build Docker optimisé avec BuildKit.

**Usage**:
```bash
./scripts/docker-build.sh
```

**Fonctionnalités**:
- Build multi-stage pour image optimisée
- Cache BuildKit pour builds rapides
- Tags avec `latest` et commit SHA
- Affiche la taille de l'image finale

**Exemple**:
```bash
./scripts/docker-build.sh
# 🐳 Building WebSec Docker image
# 📦 Building multi-stage image...
# ✅ Docker image built successfully!
```

---

## docker-test.sh

Script de test complet du stack Docker (docker-compose).

**Usage**:
```bash
./scripts/docker-test.sh
```

**Fonctionnalités**:
1. Démarre le stack complet (backend + Redis + WebSec + Prometheus)
2. Vérifie la santé de tous les services
3. Exécute 5 tests fonctionnels
4. Affiche les statistiques des conteneurs
5. Affiche les métriques WebSec
6. Laisse le stack running pour exploration

**Tests exécutés**:
- ✅ GET / via proxy - Forwarding basique
- ✅ GET /metrics - Métriques Prometheus
- ✅ Headers WebSec - Vérification X-WebSec-Decision
- ✅ GET /api/users - API JSON via proxy
- ✅ POST /api/echo - POST avec body

**Services démarrés**:
- `websec-backend` - Backend de test Python (port 3000)
- `websec-redis` - Redis pour storage (port 6379)
- `websec-proxy` - WebSec reverse proxy (port 8080)
- `websec-prometheus` - Prometheus monitoring (port 9091)

**Exemple de sortie**:
```
🐳 Testing WebSec Docker stack

🚀 Starting Docker Compose stack...
⏳ Waiting for services to be healthy...
  Checking backend... ✓
  Checking WebSec proxy... ✓
  Checking Redis... ✓

🧪 Running functional tests

  Test 1: GET / via proxy... ✓
  Test 2: GET /metrics... ✓
  Test 3: WebSec headers... ✓
  Test 4: GET /api/users... ✓
  Test 5: POST /api/echo... ✓

📊 Container statistics
📈 WebSec metrics
  Total requests: 5

✅ All Docker tests passed!

💡 Stack is running:
   - Backend:    http://localhost:3000
   - WebSec:     http://localhost:8080
   - Metrics:    http://localhost:8080/metrics
   - Prometheus: http://localhost:9091

🛑 To stop the stack:
   docker-compose down
```

**Arrêt du stack**:
```bash
docker-compose down        # Arrête et supprime les conteneurs
docker-compose down -v     # + supprime les volumes
```

---

## websec-lists.sh

Gestionnaire de blacklist/whitelist pour WebSec.

**Usage**:
```bash
./scripts/websec-lists.sh <command> [arguments]
```

**Commandes principales**:

```bash
# Blacklist
./scripts/websec-lists.sh blacklist add 192.168.1.100
./scripts/websec-lists.sh blacklist add 10.0.0.0/8
./scripts/websec-lists.sh blacklist remove 192.168.1.100
./scripts/websec-lists.sh blacklist list
./scripts/websec-lists.sh blacklist clear

# Whitelist
./scripts/websec-lists.sh whitelist add 203.0.113.50
./scripts/websec-lists.sh whitelist add 172.16.0.0/12
./scripts/websec-lists.sh whitelist remove 203.0.113.50
./scripts/websec-lists.sh whitelist list
./scripts/websec-lists.sh whitelist clear

# Utilitaires
./scripts/websec-lists.sh check 192.168.1.100      # Vérifier une IP
./scripts/websec-lists.sh stats                     # Statistiques
./scripts/websec-lists.sh export json > lists.json  # Exporter (JSON/CSV)
./scripts/websec-lists.sh import lists.json         # Importer
```

**Fonctionnalités**:
- Support IP individuelles et réseaux CIDR
- Validation automatique des formats IP
- Export/import en JSON et CSV
- Vérification de doublon
- Statistiques en temps réel
- Code couleur pour meilleure lisibilité

**Variables d'environnement**:
```bash
export WEBSEC_LISTS_DIR=/etc/websec/lists
./scripts/websec-lists.sh stats
```

**Formats d'export**:

*JSON*:
```json
{
  "blacklist": ["192.168.1.100", "10.0.0.0/8"],
  "whitelist": ["203.0.113.50"]
}
```

*CSV*:
```csv
type,ip
blacklist,192.168.1.100
whitelist,203.0.113.50
```

---

## Installation d'Apache Bench (optionnel)

### Ubuntu/Debian
```bash
sudo apt-get install apache2-utils
```

### macOS
```bash
brew install httpd
```

### CentOS/RHEL
```bash
sudo yum install httpd-tools
```
