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
