# websec

Je veux concevoir, en Rust, un composant de protection proactive pour mon serveur web.
Ce composant doit agir comme un proxy / reverse proxy de sécurité placé en amont du serveur web et intercepter **toutes** les requêtes HTTP(S) avant qu’elles ne l’atteignent.

Pour chaque requête, le système doit :

1. **Analyser la requête** et le contexte de l’adresse IP source.
2. **Calculer un score de réputation** pour cette IP.
3. **Prendre une décision** en fonction de ce score :

   * Autoriser la requête et la transmettre au serveur web.
   * Ralentir / limiter (rate limiting) la requête, éventuellement imposer un CAPTCHA ou un formulaire de demande de déblocage.
   * Bloquer complètement la requête si la réputation est jugée trop mauvaise.

---

### Critères de calcul du score de réputation (liste extensible)

Le score de réputation d’une IP doit être calculé dynamiquement sur la base d’un ensemble de signaux, parmi lesquels :

* **Détection de bots**
  Heuristiques et signaux permettant d’identifier un comportement non humain.

* **Analyse du User-Agent**

  * Détection de `HTTP_USER_AGENT` suspects.
  * Maintien d’une liste des User-Agent observés pour chaque IP.

* **Détection de brute force**

  * Nombre de tentatives d’authentification échouées pour cette IP.
  * Détection de schémas d’essais répétitifs sur les mêmes endpoints sensibles (login, admin, etc.).

* **Détection de flood / protection DDoS**

  * Volume de requêtes par IP sur une période donnée.
  * Pic anormal d’activité provenant d’une IP ou d’un ensemble d’IP corrélées.

* **Analyse des codes de retour HTTP**

  * Taux d’erreurs HTTP (codes >= 400) associés à une IP.

* **Détection d’erreurs côté application (ex. PHP)**

  * Corrélation entre une IP et la génération fréquente d’erreurs serveur / application.

* **Détection de TOR**

  * Identification des IP appartenant à des sorties Tor.

* **Détection de proxies publics**

  * Vérifier si l’IP est répertoriée comme proxy public / VPN ou hébergeur.

* **Détection de scans de failles**

  * Requêtes typiques de scan (patterns connus, chemins sensibles, payloads suspects…).

* **Géolocalisation**

  * Attribution d’un score différencié selon le pays :

    * Moins bonne note pour les pays étrangers,
    * Pénalité accrue hors Europe,
    * Pénalité encore plus forte pour certains pays (ex. Asie, Russie, Afrique, selon la politique de sécurité choisie).

* **Analyse du Referer**

  * Détection de `Referer` suspects.
  * Système de blacklist de domaines / hosts de referer.

* **Inspection des paramètres et URLs**

  * Détection de tentatives de passage de code ou d’injection dans les paramètres (GET/POST) ou dans l’URL.

* **Listes de contrôle**

  * **Liste noire d’IP** à bloquer immédiatement, quel que soit le score.
  * **Liste blanche d’IP** à laisser passer (ou à traiter de manière plus permissive).

* **Horodatage et contexte temporel**

  * Prise en compte de la récurrence, de la durée et de la période des évènements suspects (ex. pics nocturnes répétés).

* **Journalisation des requêtes**

  * Log des URLs et des requêtes associées à des comportements malveillants pour enrichir automatiquement une blacklist de patterns / endpoints non légitimes.

---

### Comportement attendu en fonction de la réputation

En fonction du score calculé pour une IP (et éventuellement pour la combinaison IP + User-Agent + chemin) :

* **Score acceptable** :

  * La requête est transmise immédiatement au serveur web.

* **Score douteux / intermédiaire** :

  * Application de règles de **rate limiting** (ralentissement, quotas).
  * Possibilité de présenter un **CAPTCHA** ou un mécanisme de vérification humaine.
  * Possibilité de proposer un **formulaire de demande de déblocage**.

* **Score très mauvais** :

  * **Blocage immédiat** des requêtes provenant de cette IP.
  * Éventuel retour d’une page d’erreur ou d’un code de statut spécifique.

---

### Contraintes générales

* Le système doit être développé en **Rust**.
* Il doit être **hautement performant** et capable de supporter un volume élevé de requêtes (objectif : 10 000+ req/s, latence < 5ms p95).
* Il doit être **extensible**, de manière à permettre d'ajouter facilement de nouveaux signaux ou règles de scoring.
* Il doit être capable de fonctionner en **production** devant un serveur web (ex. Nginx, Apache, Caddy, etc.) sans introduire de latence excessive.
* Il doit être **totalement transparent** : aucune modification ou configuration requise côté serveur web backend.
* Il doit être capable de détecter les menaces listées dans [Menaces](./Menaces.md)

---

### Administration et Opérations

Le système doit fournir un **CLI (Command Line Interface)** pour :

* **Gestion des listes de contrôle** : Ajouter/retirer des IPs en liste noire ou blanche sans redémarrage
* **Consultation des profils** : Afficher le score de réputation, l'historique des signaux, et les statistiques d'une IP
* **Déblocage d'urgence** : Réinitialiser le score d'une IP légitime bloquée par erreur (< 2 minutes)
* **Monitoring temps réel** : Statistiques globales (req/s, taux de blocage, top IPs malveillantes, top signaux)
* **Rechargement de configuration** : Appliquer une nouvelle configuration à chaud sans interruption
* **Mode dry-run** : Tester l'impact d'une modification de configuration avant application

---

### Architecture Technique

**Calcul du Score de Réputation** :
* Formule additive pondérée : `Score = max(0, min(100, base - Σ(poids_signal)))`
* Bonus de pénalité si multiples signaux différents détectés en peu de temps (corrélation d'attaques)
* Récupération progressive par décroissance exponentielle (demi-vie 24h)
* Exception : signaux rédibitoires (webshells, RCE, credential stuffing massif) sans récupération automatique

**Rate Limiting** :
* Algorithme Token Bucket avec fenêtre glissante combinée
* Équilibre entre flexibilité pour bursts légitimes et protection anti-gaming

**Stockage et Scalabilité** :
* Architecture stateless pour scaling horizontal
* Redis centralisé pour partage d'état entre instances
* Cache L1 local en mémoire pour réduire la latence (< 5ms p95)
* Mode dégradé : détection locale sans historique + logs fichiers en cas de panne Redis