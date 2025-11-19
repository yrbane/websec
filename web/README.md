# WebSec Dashboard

Dashboard web basique pour monitoring en temps réel de WebSec.

## Fonctionnalités

- 📊 **Métriques en temps réel** : Requêtes totales, bloquées, autorisées
- 🎯 **Taux de blocage** : Visualisation des pourcentages
- 🌐 **IPs suivies** : Nombre d'IPs trackées
- 🔔 **Signaux détectés** : Top 5 des signaux de menaces
- 🔄 **Auto-refresh** : Actualisation automatique toutes les 10 secondes
- 📱 **Responsive** : Compatible mobile et desktop
- 🎨 **Interface moderne** : Design gradient avec cartes

## Installation

### Option 1 : Serveur HTTP Simple (Python)

```bash
# Démarrer WebSec
cargo run --release

# Dans un autre terminal, servir le dashboard
cd web
python3 -m http.server 8000

# Ouvrir http://localhost:8000/dashboard.html
```

### Option 2 : Nginx

```nginx
server {
    listen 80;
    server_name dashboard.websec.local;

    location / {
        root /path/to/websec/web;
        index dashboard.html;
    }

    location /metrics {
        proxy_pass http://localhost:8080/metrics;
        proxy_set_header Host $host;
    }
}
```

### Option 3 : Apache

```apache
<VirtualHost *:80>
    ServerName dashboard.websec.local
    DocumentRoot /path/to/websec/web

    <Directory /path/to/websec/web>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ProxyPass /metrics http://localhost:8080/metrics
    ProxyPassReverse /metrics http://localhost:8080/metrics
</VirtualHost>
```

### Option 4 : Servir depuis WebSec (future feature)

Dans une version future, WebSec pourrait servir le dashboard directement :

```toml
[dashboard]
enabled = true
path = "/dashboard"
static_dir = "./web"
```

## Configuration CORS

Si le dashboard est hébergé sur un domaine différent de WebSec, configurez CORS :

```toml
# config/websec.toml
[server]
cors_origins = ["http://localhost:8000", "https://dashboard.example.com"]
```

## Métriques Disponibles

Le dashboard consomme l'endpoint `/metrics` Prometheus et affiche :

- **Requêtes** :
  - Total
  - Autorisées (ALLOW)
  - Bloquées (BLOCK)
  - Rate limitées (RATE_LIMIT)

- **Taux** :
  - % de blocage
  - % de rate limiting
  - % d'autorisation

- **IPs** :
  - Nombre total d'IPs suivies

- **Signaux** :
  - Top 5 des signaux de menaces détectés
  - Compteurs par type de signal

- **Brutes** :
  - Métriques Prometheus complètes (format texte)

## Personnalisation

### Modifier l'intervalle de refresh

Éditez `dashboard.html` :

```javascript
// Ligne ~360
autoRefreshInterval = setInterval(loadMetrics, 10000); // 10s
```

### Changer l'URL de l'API

Par défaut, le dashboard utilise `window.location.origin`. Pour pointer vers un autre serveur :

```javascript
// Ligne ~288
const API_URL = 'http://websec.example.com:8080';
```

### Ajouter des métriques

1. Vérifiez les métriques disponibles dans `/metrics`
2. Ajoutez le parsing dans `processMetrics()`
3. Créez un nouveau `<div class="card">` dans le HTML

## Exemples de Métriques

```
# HELP requests_total Total number of requests
# TYPE requests_total counter
requests_total{decision="allow"} 12543
requests_total{decision="block"} 89
requests_total{decision="rate_limit"} 23

# HELP tracked_ips_total Number of tracked IPs
# TYPE tracked_ips_total gauge
tracked_ips_total 342

# HELP signals_total Detected security signals
# TYPE signals_total counter
signals_total{signal_type="SqlInjectionAttempt"} 15
signals_total{signal_type="SuspiciousUserAgent"} 32
```

## Capture d'écran

Le dashboard affiche :
- Header avec statut Online/Offline
- Bouton de rafraîchissement manuel
- 4 cartes principales (Requêtes, Taux, IPs, Signaux)
- Section des métriques brutes
- Design responsive avec dégradé violet

## Développement

Le dashboard est un fichier HTML standalone sans dépendances externes :
- Vanilla JavaScript (pas de framework)
- CSS moderne avec Flexbox/Grid
- Fetch API pour les requêtes
- Auto-contenu (pas de CDN)

## Limites Actuelles

- Pas d'historique (données temps réel uniquement)
- Pas de graphiques (future feature)
- Pas d'authentification (à ajouter)
- Pas de notifications push

## Roadmap

- [ ] Graphiques avec Chart.js
- [ ] Historique sur 24h
- [ ] Authentification JWT
- [ ] Notifications WebSocket
- [ ] Export CSV/JSON
- [ ] Mode sombre

## Licence

MIT - Voir LICENSE du projet principal
