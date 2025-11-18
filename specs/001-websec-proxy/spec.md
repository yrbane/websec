# Spécification de Fonctionnalité : WebSec Proxy de Sécurité

**Branche de fonctionnalité** : `001-websec-proxy`
**Créé** : 2025-11-18
**Statut** : Brouillon
**Input** : docs/IDEA.md et docs/Menaces.md

## Scénarios Utilisateur & Tests *(obligatoire)*

### Scénario Utilisateur 1 - Protection contre les Bots Malveillants (Priorité : P1)

En tant qu'administrateur système, je veux que le proxy détecte et bloque automatiquement les bots malveillants et scrapers agressifs pour protéger mon serveur web des accès non humains abusifs.

**Pourquoi cette priorité** : Les bots représentent souvent 40-60% du trafic web malveillant. C'est la menace la plus courante et la plus facile à détecter, rendant ce scénario essentiel pour un MVP viable.

**Test Indépendant** : Peut être testé complètement en envoyant des requêtes avec différents User-Agent (curl, sqlmap, navigateurs légitimes) et en vérifiant que seuls les User-Agent suspects sont pénalisés dans le score de réputation.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une IP envoie une requête avec `User-Agent: sqlmap/1.7`, **Quand** le proxy analyse la requête, **Alors** il génère un signal `VulnerabilityScan` avec une forte pénalité et bloque la requête.

2. **Étant donné** qu'une IP envoie 100 requêtes en 30 secondes sans jamais charger de ressources statiques (.css, .js, images), **Quand** le proxy analyse le profil de comportement, **Alors** il génère des signaux `SuspiciousClientProfile` et `AbusiveClient`.

3. **Étant donné** qu'une IP envoie une requête avec un User-Agent de navigateur légitime et charge normalement les assets, **Quand** le proxy analyse la requête, **Alors** le score de réputation reste bon et la requête est transmise au backend.

---

### Scénario Utilisateur 2 - Protection contre le Brute Force (Priorité : P1)

En tant qu'administrateur, je veux détecter et ralentir/bloquer les tentatives de brute force sur les endpoints d'authentification pour protéger les comptes utilisateurs.

**Pourquoi cette priorité** : Les attaques par brute force sont une menace critique pour la sécurité des comptes. Avec le scénario 1 (bots), cela forme le socle de sécurité minimum viable.

**Test Indépendant** : Peut être testé en envoyant plusieurs requêtes POST échouées vers `/login` depuis la même IP et en vérifiant que le rate limiting s'active puis que l'IP est bloquée après un seuil.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une IP envoie 5 tentatives de login échouées (401/403) en 1 minute sur `/login`, **Quand** le proxy détecte ces échecs, **Alors** il génère des signaux `FailedAuthAttempt` et active le rate limiting.

2. **Étant donné** qu'une IP continue et atteint 20 tentatives échouées en 5 minutes, **Quand** le seuil critique est atteint, **Alors** le proxy bloque complètement l'IP et retourne une erreur 429.

3. **Étant donné** que plusieurs IPs différentes testent le même couple login/password, **Quand** le proxy corrèle ces tentatives, **Alors** il génère un signal `CredentialStuffing` et pénalise toutes les IPs impliquées.

---

### Scénario Utilisateur 3 - Protection contre le Flood/DDoS (Priorité : P2)

En tant qu'administrateur, je veux limiter automatiquement le nombre de requêtes par IP pour protéger mon serveur contre les attaques par flood et DDoS applicatif.

**Pourquoi cette priorité** : Essentiel pour la disponibilité du service, mais moins critique que les scénarios P1 car nécessite un volume d'attaque plus important pour causer des dommages.

**Test Indépendant** : Peut être testé en envoyant un grand volume de requêtes légitimes depuis une IP et en vérifiant que le rate limiting s'active automatiquement.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une IP envoie 1000 requêtes en 10 secondes, **Quand** le proxy détecte ce volume anormal, **Alors** il génère des signaux `Flooding` et active un rate limiting agressif.

2. **Étant donné** qu'une IP maintient un taux soutenu de 100 req/s pendant 1 minute sur `/search`, **Quand** le proxy analyse ce pattern, **Alors** il dégrade progressivement le score de réputation jusqu'au blocage.

3. **Étant donné** qu'un burst de 50 requêtes arrive en 2 secondes puis l'activité redevient normale, **Quand** le proxy détecte ce burst isolé, **Alors** il applique un rate limiting temporaire mais ne bloque pas immédiatement.

---

### Scénario Utilisateur 4 - Détection d'Injections (SQLi, XSS, RCE) (Priorité : P2)

En tant qu'administrateur, je veux détecter les tentatives d'injection dans les paramètres et URLs pour bloquer les attaques avant qu'elles n'atteignent mon application.

**Pourquoi cette priorité** : Les injections sont des vulnérabilités critiques mais nécessitent que l'application soit vulnérable. La détection au niveau proxy ajoute une couche de défense en profondeur.

**Test Indépendant** : Peut être testé en envoyant des requêtes contenant des payloads d'injection connus et en vérifiant que les signaux appropriés sont générés.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une requête contient `?id=1 UNION SELECT username,password FROM users`, **Quand** le proxy analyse les paramètres, **Alors** il génère des signaux `SqlInjectionAttempt` et `SuspiciousPayload`.

2. **Étant donné** qu'une requête contient `?q=<script>alert(1)</script>`, **Quand** le proxy détecte ce pattern XSS, **Alors** il génère un signal `XssAttempt` et bloque la requête.

3. **Étant donné** qu'une requête contient `;cat /etc/passwd` dans un paramètre, **Quand** le proxy détecte ce pattern de RCE, **Alors** il génère un signal `RceAttempt` avec forte pénalité.

---

### Scénario Utilisateur 5 - Path Traversal et Fichiers Sensibles (Priorité : P3)

En tant qu'administrateur, je veux bloquer les tentatives d'accès à des fichiers sensibles via path traversal pour protéger la configuration et les données du serveur.

**Pourquoi cette priorité** : Important pour la sécurité mais moins fréquent que les autres attaques. La plupart des serveurs web modernes protègent déjà contre cela.

**Test Indépendant** : Peut être testé en envoyant des requêtes avec `../` et des chemins vers des fichiers sensibles connus.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une requête cible `GET /../../etc/passwd`, **Quand** le proxy détecte le pattern de path traversal, **Alors** il génère un signal `SuspiciousPayload` et bloque immédiatement.

2. **Étant donné** qu'une requête cible `GET /.env` ou `GET /wp-config.php`, **Quand** le proxy détecte ces fichiers sensibles, **Alors** il génère un signal `VulnerabilityScan`.

3. **Étant donné** qu'une requête utilise des encodages (`%2e%2e%2f`), **Quand** le proxy normalise et détecte le pattern, **Alors** il applique les mêmes règles de blocage.

---

### Scénario Utilisateur 6 - Scan de Vulnérabilités (Priorité : P3)

En tant qu'administrateur, je veux identifier les phases de reconnaissance et les scans automatiques pour bloquer les attaquants avant qu'ils ne trouvent des vulnérabilités.

**Pourquoi cette priorité** : La reconnaissance précède souvent les attaques, mais un scan seul ne cause pas de dommages directs. Utile pour la détection précoce.

**Test Indépendant** : Peut être testé en envoyant des requêtes vers des chemins typiques d'admin panels et en générant de nombreux 404.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une IP accède en rafale à `/wp-admin/`, `/phpmyadmin/`, `/manager/html`, **Quand** le proxy détecte ce pattern de scan, **Alors** il génère des signaux `VulnerabilityScan` multiples.

2. **Étant donné** qu'une IP génère 50 erreurs 404 en 1 minute sur des chemins variés, **Quand** le proxy analyse ce comportement, **Alors** il augmente le score de suspicion et active le rate limiting.

3. **Étant donné** qu'une IP accède à `/.git/config`, **Quand** le proxy détecte cet accès sensible, **Alors** il génère un signal `VulnerabilityScan` avec forte pénalité.

---

### Scénario Utilisateur 7 - Gestion des Listes Noires/Blanches (Priorité : P2)

En tant qu'administrateur, je veux pouvoir définir des listes noires (blocage immédiat) et blanches (toujours autorisées) pour avoir un contrôle manuel sur certaines IPs.

**Pourquoi cette priorité** : Fonctionnalité opérationnelle critique pour gérer des exceptions et répondre rapidement aux incidents.

**Test Indépendant** : Peut être testé en ajoutant des IPs aux listes et en vérifiant qu'elles sont traitées correctement indépendamment de leur score.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une IP est dans la liste noire, **Quand** elle envoie une requête, **Alors** elle est bloquée immédiatement sans calcul de score.

2. **Étant donné** qu'une IP est dans la liste blanche, **Quand** elle génère des comportements suspects, **Alors** elle est autorisée et son score n'est pas dégradé (ou minimalement).

3. **Étant donné** qu'un administrateur ajoute une IP à la liste noire via l'API, **Quand** la configuration est rechargée, **Alors** les nouvelles requêtes de cette IP sont immédiatement bloquées.

---

### Scénario Utilisateur 8 - Détection d'Uploads Dangereux (Priorité : P3)

En tant qu'administrateur, je veux surveiller et bloquer les tentatives d'upload de fichiers dangereux (webshells, malware) pour empêcher la compromission du serveur.

**Pourquoi cette priorité** : Les uploads malveillants peuvent mener à la prise de contrôle du serveur, mais nécessitent que l'application accepte les uploads. Important pour les applications concernées.

**Test Indépendant** : Peut être testé en uploadant des fichiers avec extensions dangereuses et en vérifiant la détection.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'un upload contient un fichier `shell.php` avec `Content-Type: image/png`, **Quand** le proxy détecte l'incohérence extension/content-type, **Alors** il génère un signal `PotentialWebshellUpload`.

2. **Étant donné** qu'un upload POST contient des extensions dangereuses (.php, .phtml, .jsp, .aspx, .sh), **Quand** le proxy analyse le multipart, **Alors** il génère un signal `SuspiciousPayload` et bloque.

3. **Étant donné** qu'une IP effectue 10 uploads successifs de fichiers suspects, **Quand** le proxy détecte ce pattern, **Alors** il bloque l'IP avec un score très dégradé.

---

### Scénario Utilisateur 9 - Détection TOR et Proxies Publics (Priorité : P3)

En tant qu'administrateur, je veux identifier et pénaliser le trafic provenant de TOR et des proxies publics pour réduire les accès anonymisés potentiellement malveillants.

**Pourquoi cette priorité** : TOR et proxies publics sont souvent utilisés pour masquer l'origine d'attaques, mais certains usages légitimes existent. Pénalité plutôt que blocage systématique.

**Test Indépendant** : Peut être testé en simulant des requêtes depuis des IPs TOR/proxy connues et en vérifiant la pénalité appliquée.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une IP appartient à un nœud de sortie TOR (liste publique), **Quand** elle envoie une requête, **Alors** le proxy génère un signal `TorDetected` avec pénalité de réputation.

2. **Étant donné** qu'une IP est identifiée comme proxy public/VPN dans la base de données, **Quand** elle envoie une requête, **Alors** le proxy génère un signal `PublicProxyDetected`.

3. **Étant donné** qu'une IP TOR génère également des comportements suspects, **Quand** les signaux sont agrégés, **Alors** le score est fortement dégradé (effet cumulatif).

---

### Scénario Utilisateur 10 - Anomalies de Protocole HTTP (Priorité : P3)

En tant qu'administrateur, je veux détecter les anomalies et malformations au niveau protocole HTTP pour bloquer les tentatives d'exploitation ou de contournement.

**Pourquoi cette priorité** : Les anomalies de protocole sont rares mais peuvent indiquer des tentatives d'exploitation avancées. Détection spécialisée utile pour la défense en profondeur.

**Test Indépendant** : Peut être testé en envoyant des requêtes HTTP malformées ou avec méthodes non standards.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'une requête utilise la méthode `TRACE` ou `TRACK`, **Quand** le proxy détecte cette méthode, **Alors** il génère un signal `ProtocolAnomaly`.

2. **Étant donné** qu'une requête contient des headers malformés (CRLF injection, headers dupliqués), **Quand** le proxy valide les headers, **Alors** il génère un signal `ProtocolAnomaly` et bloque.

3. **Étant donné** qu'une requête a une incohérence Content-Length vs taille réelle, **Quand** le proxy détecte cette anomalie, **Alors** il génère un signal `ProtocolAnomaly`.

---

### Scénario Utilisateur 11 - Détection SSRF (Priorité : P3)

En tant qu'administrateur, je veux détecter les tentatives de Server-Side Request Forgery dans les paramètres pour empêcher l'accès aux ressources internes via le backend.

**Pourquoi cette priorité** : SSRF peut exposer des ressources internes, mais nécessite une application vulnérable. Détection au proxy ajoute une couche de protection.

**Test Indépendant** : Peut être testé en envoyant des paramètres URL pointant vers des IPs privées ou metadata endpoints.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'un paramètre `url` contient `http://127.0.0.1:8080/admin`, **Quand** le proxy analyse les paramètres, **Alors** il génère un signal `SsrfSuspected`.

2. **Étant donné** qu'un paramètre contient `http://169.254.169.254/latest/meta-data/`, **Quand** le proxy détecte cet endpoint cloud metadata, **Alors** il génère un signal `SsrfSuspected` avec forte pénalité.

3. **Étant donné** qu'un paramètre contient des IPs privées (10.x, 192.168.x, 172.16.x), **Quand** le proxy détecte ces plages, **Alors** il génère un signal `SsrfSuspected`.

---

### Scénario Utilisateur 12 - Détection d'Anomalies de Sessions (Priorité : P3)

En tant qu'administrateur, je veux détecter les hijacking de session et les partages de session suspects pour identifier les comptes compromis.

**Pourquoi cette priorité** : Le hijacking de session est une menace sérieuse mais moins fréquente. Détection utile pour alerter sur des compromissions potentielles.

**Test Indépendant** : Peut être testé en réutilisant un cookie de session depuis des IPs/pays différents.

**Scénarios d'Acceptation** :

1. **Étant donné** qu'un cookie de session est utilisé depuis la France à 10h00 puis depuis la Russie à 10h05, **Quand** le proxy détecte ce changement géographique impossible, **Alors** il génère un signal `SessionHijackingSuspected`.

2. **Étant donné** qu'un même session_id est utilisé simultanément par 20 IPs différentes, **Quand** le proxy détecte ce partage massif, **Alors** il génère un signal `SessionAnomaly`.

3. **Étant donné** qu'une session change 5 fois de pays en 10 minutes, **Quand** le proxy détecte cette volatilité anormale, **Alors** il génère des signaux `SessionHijackingSuspected` multiples.

---

### Cas Limites

- Que se passe-t-il quand une IP légitime est temporairement bloquée à tort (faux positif) ?
  → Mécanisme de déblocage automatique après une période de calme, possibilité de whitelist manuelle.

- Comment le système gère-t-il les IPs derrière NAT (plusieurs utilisateurs légitimes partageant la même IP) ?
  → Seuils ajustables, possibilité de whitelister des plages d'IPs connues (entreprises, universités).

- Que se passe-t-il en cas de pic de trafic légitime (événement, promotion) ?
  → Rate limiting adaptatif avec seuils configurables, monitoring des taux de faux positifs.

- Comment gérer les IPv6 (espace d'adressage énorme) ?
  → Scoring par préfixe /64 ou /48 en plus de l'IP individuelle.

- Que se passe-t-il si la base de données de réputation devient trop volumineuse ?
  → Expiration automatique des entrées anciennes, nettoyage périodique des IPs inactives.

- Comment gérer les requêtes avec Referer suspect ou manipulé ?
  → Détection de referers en blacklist, validation de cohérence referer/destination, pénalité pour referers manquants sur actions sensibles.

- Que se passe-t-il si le backend est lent ou ne répond pas ?
  → Timeout configurables, mode fail-open (autoriser) vs fail-closed (bloquer), health checks du backend.

- Comment distinguer un trafic légitime d'API automatisé d'un bot malveillant ?
  → Mécanisme d'authentification par API key pour whitelister, analyse du pattern d'usage (régularité vs erratique), User-Agent déclaré comme bot légitime.

- Comment gérer les faux positifs sur la détection de TLS fingerprinting ?
  → Liste blanche de fingerprints connus (navigateurs populaires, bots légitimes), seuils ajustables, mode apprentissage pour calibrer.

## Exigences *(obligatoire)*

### Exigences Fonctionnelles

#### Détection et Analyse

- **FR-001** : Le système DOIT intercepter toutes les requêtes HTTP(S) avant qu'elles n'atteignent le serveur web backend.
- **FR-002** : Le système DOIT extraire et analyser les éléments suivants de chaque requête : IP source, User-Agent, méthode HTTP, URL/URI, paramètres GET/POST, headers HTTP, referer, cookies.
- **FR-003** : Le système DOIT calculer un score de réputation pour chaque IP source basé sur les signaux détectés.
- **FR-004** : Le système DOIT détecter les 12 familles de menaces définies dans docs/Menaces.md.
- **FR-005** : Le système DOIT générer des signaux typés pour chaque comportement suspect détecté (ex: `SqlInjectionAttempt`, `Flooding`, `SuspiciousUserAgent`).

#### Décision et Action

- **FR-006** : Le système DOIT prendre une décision pour chaque requête : AUTORISER (forward au backend), RATE_LIMIT (ralentir), CHALLENGE (CAPTCHA), BLOQUER.
- **FR-007** : Le système DOIT implémenter un rate limiting adaptatif basé sur le score de réputation.
- **FR-008** : Le système DOIT supporter des listes noires (blocage immédiat) et des listes blanches (toujours autorisées).
- **FR-009** : Le système DOIT bloquer immédiatement les IPs en liste noire sans calcul de score.
- **FR-010** : Le système DOIT permettre un traitement privilégié des IPs en liste blanche.

#### Géolocalisation

- **FR-011** : Le système DOIT implémenter une géolocalisation des IPs pour attribution de scores différenciés par pays.
- **FR-012** : Le système DOIT permettre de configurer des pénalités par région géographique.

#### Persistance et Mémoire

- **FR-013** : Le système DOIT maintenir un historique des comportements par IP sur des fenêtres temporelles glissantes.
- **FR-014** : Le système DOIT persister les scores de réputation pour survivre aux redémarrages.
- **FR-015** : Le système DOIT implémenter une expiration automatique des données de réputation anciennes.

#### Observabilité

- **FR-016** : Le système DOIT logger toutes les décisions de blocage avec contexte (IP, raison, score, signaux).
- **FR-017** : Le système DOIT exposer des métriques de performance et de sécurité (nombre de requêtes, taux de blocage, latence).
- **FR-018** : Le système DOIT permettre l'export des logs dans un format structuré (JSON).

#### Configuration

- **FR-019** : Le système DOIT permettre la configuration via fichier (TOML/YAML).
- **FR-020** : Le système DOIT permettre le rechargement de configuration à chaud sans interruption de service.
- **FR-021** : Le système DOIT permettre de configurer les seuils de score pour chaque action (autoriser/rate-limit/bloquer).
- **FR-022** : Le système DOIT permettre de configurer les poids de chaque signal dans le calcul du score.

#### Détection Avancée

- **FR-023** : Le système DOIT détecter et pénaliser les IPs appartenant à des nœuds de sortie TOR (liste publique à jour).
- **FR-024** : Le système DOIT identifier les proxies publics et VPNs commerciaux via base de données spécialisée.
- **FR-025** : Le système DOIT analyser le header Referer et détecter les referers suspects ou en blacklist.
- **FR-026** : Le système DOIT inspecter les uploads multipart pour détecter extensions dangereuses et incohérences content-type.
- **FR-027** : Le système DOIT détecter les anomalies de protocole HTTP (méthodes non standards, headers malformés, incohérences).
- **FR-028** : Le système DOIT analyser les paramètres pour détecter les tentatives de SSRF (IPs privées, metadata endpoints).
- **FR-029** : Le système DOIT tracker les sessions par cookie et détecter les changements géographiques impossibles.
- **FR-030** : Le système DOIT supporter le fingerprinting TLS/JA3 pour identifier clients suspects (si terminaison TLS activée).

#### Mécanismes de Déblocage

- **FR-031** : Le système DOIT supporter l'intégration d'un mécanisme de CAPTCHA pour les IPs en score intermédiaire.
- **FR-032** : Le système DOIT permettre la présentation d'un formulaire de demande de déblocage pour les IPs bloquées à tort.

### Exigences Non Fonctionnelles

#### Performance

- **NFR-001** : Le système DOIT ajouter moins de 5ms de latence en p95 pour les requêtes légitimes.
- **NFR-002** : Le système DOIT supporter au minimum 10 000 requêtes par seconde sur un serveur standard (4 CPU cores).
- **NFR-003** : Le système DOIT utiliser moins de 512 MB de RAM pour 100 000 IPs suivies.
- **NFR-004** : Le système DOIT être stateless pour permettre le scaling horizontal.

#### Sécurité

- **NFR-005** : Le système DOIT valider tous les inputs avant traitement pour éviter les injections.
- **NFR-006** : Le système NE DOIT JAMAIS logger de secrets, mots de passe, ou données sensibles PII.
- **NFR-007** : Le système DOIT utiliser des bibliothèques cryptographiques validées (rustls, ring).
- **NFR-008** : Le système DOIT passer `cargo audit` sans vulnérabilités connues.

#### Qualité

- **NFR-009** : Le système DOIT avoir une couverture de tests unitaires > 80% sur la logique métier.
- **NFR-010** : Le système DOIT passer `cargo clippy` sans warnings.
- **NFR-011** : Le système DOIT passer `cargo fmt --check` (formatting uniforme).
- **NFR-012** : Le système DOIT être documenté avec rustdoc pour toutes les APIs publiques.

#### Fiabilité

- **NFR-013** : Le système DOIT avoir un mode de dégradation gracieuse : en cas d'erreur interne, autoriser la requête plutôt que de bloquer.
- **NFR-014** : Le système DOIT gérer correctement les erreurs et NE DOIT JAMAIS paniquer en production.
- **NFR-015** : Le système DOIT permettre le déploiement sans interruption (graceful shutdown).

### Entités Clés

- **Requête HTTP** : Représente une requête interceptée avec tous ses attributs (IP, headers, body, metadata).
- **Score de Réputation** : Score numérique associé à une IP, calculé dynamiquement sur base des signaux. Échelle typique : 0 (malveillant) à 100 (légitime).
- **Signal** : Événement typé représentant un comportement suspect détecté. 20+ types définis : `SqlInjectionAttempt`, `Flooding`, `SuspiciousUserAgent`, `TorDetected`, `SessionHijackingSuspected`, etc.
- **Profil IP** : Historique et contexte d'une IP source incluant : score actuel, liste des signaux récents avec timestamps, compteurs (requêtes/temps, tentatives auth, 404s), métadonnées de géolocalisation (pays, région, ASN), liste des User-Agents observés, liste des session IDs associés.
- **Règle de Décision** : Configuration des seuils et actions en fonction du score de réputation. Structure : score >= seuil_autoriser → ALLOW, seuil_rate_limit <= score < seuil_autoriser → RATE_LIMIT, seuil_bloquer <= score < seuil_rate_limit → CHALLENGE, score < seuil_bloquer → BLOCK.
- **Liste de Contrôle** : Liste noire (IPs/CIDR à bloquer immédiatement) ou liste blanche (IPs/CIDR toujours autorisées) avec règles de traitement prioritaires sur le scoring.
- **Détecteur** : Composant modulaire responsable d'analyser un aspect spécifique de la requête et générer des signaux. 12 détecteurs principaux correspondant aux 12 familles de menaces.
- **Fenêtre Temporelle** : Période glissante pour comptage d'événements (ex: 1 minute, 5 minutes, 1 heure). Utilisée pour calcul de taux (req/s, tentatives auth/minute).
- **Poids de Signal** : Coefficient multiplicateur appliqué à chaque type de signal pour calcul du score agrégé. Configurable par signal.

## Critères de Succès *(obligatoire)*

### Résultats Mesurables

#### Détection et Blocage

- **SC-001** : Le système bloque 99% des requêtes avec User-Agent de scanner connu (sqlmap, nikto, etc.) sans faux positif sur navigateurs légitimes.
- **SC-002** : Le système détecte et ralentit les attaques de brute force dans les 5 premières tentatives échouées.
- **SC-006** : Le système détecte 95% des tentatives d'injection SQL/XSS contenant des patterns connus.
- **SC-009** : Le système identifie 90% des IPs TOR via la liste publique des nœuds de sortie (mise à jour quotidienne).
- **SC-010** : Le système détecte 85% des tentatives d'upload de webshells basées sur extension et content-type.
- **SC-011** : Le système bloque 95% des tentatives de path traversal incluant les encodages courants.
- **SC-012** : Le système détecte 90% des tentatives de SSRF pointant vers IPs privées ou metadata endpoints.
- **SC-013** : Le système détecte 80% des anomalies de session (hijacking, partage massif) avec moins de 5% de faux positifs.

#### Performance

- **SC-003** : Le système ajoute moins de 5ms de latence p95 et moins de 2ms en p50 sur les requêtes légitimes.
- **SC-004** : Le système supporte 10 000 req/s avec moins de 10% d'utilisation CPU sur un serveur 4 cores.
- **SC-007** : Le temps de rechargement de configuration est inférieur à 100ms sans perte de requêtes.
- **SC-014** : Le système maintient une latence stable (< 10ms p99) même sous charge de 20 000 req/s avec attaque simultanée.

#### Fiabilité et Qualité

- **SC-005** : Le taux de faux positifs (requêtes légitimes bloquées) est inférieur à 0.1%.
- **SC-008** : La couverture de tests atteint au minimum 80% sur la logique de détection.
- **SC-015** : Le système fonctionne 24h en continu sans memory leak (utilisation mémoire stable ± 5%).
- **SC-016** : Le taux de disponibilité du proxy atteint 99.9% (moins de 43 minutes d'indisponibilité par mois).

#### Opérationnel

- **SC-017** : Les faux positifs peuvent être corrigés en moins de 2 minutes via whitelist manuelle.
- **SC-018** : Le système exporte au moins 20 métriques Prometheus pour monitoring complet.
- **SC-019** : 100% des décisions de blocage sont logguées avec contexte complet (IP, raison, score, signaux, timestamp).
- **SC-020** : La géolocalisation identifie correctement le pays pour 95% des IPs publiques.
