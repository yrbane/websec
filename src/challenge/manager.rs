//! Gestionnaire de challenges thread-safe

use super::types::{Challenge, ChallengeType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Gestionnaire de challenges thread-safe
///
/// Gère la création, validation et expiration des challenges CAPTCHA.
/// Utilise un `HashMap` thread-safe pour stocker les challenges actifs par IP.
///
/// # Thread Safety
///
/// Complètement thread-safe grâce à `Arc<Mutex<HashMap>>`. Plusieurs threads
/// peuvent créer et valider des challenges simultanément.
///
/// # Expiration
///
/// Les challenges expirent automatiquement après le timeout configuré.
/// La méthode `cleanup_expired()` peut être appelée périodiquement pour
/// libérer la mémoire des challenges expirés.
///
/// # Exemples
///
/// ```
/// use websec::challenge::{ChallengeManager, ChallengeType};
/// use std::net::IpAddr;
/// use std::str::FromStr;
/// use std::time::Duration;
///
/// let manager = ChallengeManager::new(Duration::from_secs(300));
/// let ip = IpAddr::from_str("192.168.1.100").unwrap();
///
/// // Créer un challenge
/// let challenge = manager.create_challenge(ip, ChallengeType::SimpleMath).unwrap();
///
/// // Valider la réponse
/// let is_valid = manager.validate(ip, &challenge.token, &challenge.answer);
/// assert!(is_valid);
/// ```
pub struct ChallengeManager {
    /// Challenges actifs par IP
    challenges: Arc<Mutex<HashMap<IpAddr, Challenge>>>,
    /// Durée de validité d'un challenge
    timeout: Duration,
}

impl ChallengeManager {
    /// Crée un nouveau gestionnaire de challenges
    ///
    /// # Arguments
    ///
    /// * `timeout` - Durée de validité d'un challenge (typiquement 5 minutes)
    ///
    /// # Examples
    ///
    /// ```
    /// use websec::challenge::ChallengeManager;
    /// use std::time::Duration;
    ///
    /// let manager = ChallengeManager::new(Duration::from_secs(300));
    /// ```
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            challenges: Arc::new(Mutex::new(HashMap::new())),
            timeout,
        }
    }

    /// Crée un nouveau challenge pour une IP
    ///
    /// Si un challenge existe déjà pour cette IP, il est remplacé.
    /// Cela empêche l'accumulation de challenges et limite à un challenge
    /// actif par IP.
    ///
    /// # Arguments
    ///
    /// * `ip` - Adresse IP pour laquelle créer le challenge
    /// * `challenge_type` - Type de challenge à générer
    ///
    /// # Returns
    ///
    /// Le challenge créé, ou `None` en cas d'erreur
    ///
    /// # Examples
    ///
    /// ```
    /// use websec::challenge::{ChallengeManager, ChallengeType};
    /// use std::net::IpAddr;
    /// use std::str::FromStr;
    /// use std::time::Duration;
    ///
    /// let manager = ChallengeManager::new(Duration::from_secs(300));
    /// let ip = IpAddr::from_str("192.168.1.100").unwrap();
    ///
    /// let challenge = manager.create_challenge(ip, ChallengeType::SimpleMath);
    /// assert!(challenge.is_some());
    /// ```
    #[must_use]
    pub fn create_challenge(&self, ip: IpAddr, challenge_type: ChallengeType) -> Option<Challenge> {
        let challenge = match challenge_type {
            ChallengeType::SimpleMath => Challenge::new_simple_math(),
        };

        let mut challenges = self.challenges.lock().ok()?;
        challenges.insert(ip, challenge.clone());

        Some(challenge)
    }

    /// Valide la réponse à un challenge
    ///
    /// Vérifie que :
    /// 1. Un challenge existe pour cette IP
    /// 2. Le token correspond
    /// 3. Le challenge n'est pas expiré
    /// 4. Il reste des tentatives
    /// 5. La réponse est correcte
    ///
    /// Si la validation réussit, le challenge est supprimé (usage unique).
    /// Si elle échoue, le nombre de tentatives est décrémenté.
    /// Quand il n'y a plus de tentatives, le challenge est supprimé.
    ///
    /// # Arguments
    ///
    /// * `ip` - Adresse IP du client
    /// * `token` - Token du challenge (fourni dans le formulaire)
    /// * `answer` - Réponse proposée par l'utilisateur
    ///
    /// # Returns
    ///
    /// `true` si la validation réussit, `false` sinon
    ///
    /// # Examples
    ///
    /// ```
    /// use websec::challenge::{ChallengeManager, ChallengeType};
    /// use std::net::IpAddr;
    /// use std::str::FromStr;
    /// use std::time::Duration;
    ///
    /// let manager = ChallengeManager::new(Duration::from_secs(300));
    /// let ip = IpAddr::from_str("192.168.1.100").unwrap();
    ///
    /// let challenge = manager.create_challenge(ip, ChallengeType::SimpleMath).unwrap();
    /// let is_valid = manager.validate(ip, &challenge.token, &challenge.answer);
    /// assert!(is_valid);
    /// ```
    #[must_use]
    pub fn validate(&self, ip: IpAddr, token: &str, answer: &str) -> bool {
        let Ok(mut challenges) = self.challenges.lock() else {
            return false;
        };

        // Récupérer le challenge pour cette IP
        let Some(challenge) = challenges.get_mut(&ip) else {
            return false;
        };

        // Vérifier le token
        if challenge.token != token {
            return false;
        }

        // Vérifier l'expiration
        if challenge.is_expired(self.timeout.as_millis()) {
            challenges.remove(&ip);
            return false;
        }

        // Vérifier s'il reste des tentatives
        if challenge.attempts_remaining == 0 {
            challenges.remove(&ip);
            return false;
        }

        // Vérifier la réponse
        if challenge.answer.trim() == answer.trim() {
            // Réponse correcte : supprimer le challenge (usage unique)
            challenges.remove(&ip);
            true
        } else {
            // Réponse incorrecte : décrémenter les tentatives
            challenge.attempts_remaining -= 1;
            if challenge.attempts_remaining == 0 {
                // Plus de tentatives : supprimer le challenge
                challenges.remove(&ip);
            }
            false
        }
    }

    /// Nettoie les challenges expirés
    ///
    /// Parcourt tous les challenges actifs et supprime ceux qui sont expirés.
    /// Cette méthode doit être appelée périodiquement (par exemple toutes les minutes)
    /// pour éviter l'accumulation de challenges expirés en mémoire.
    ///
    /// # Returns
    ///
    /// Le nombre de challenges nettoyés
    ///
    /// # Examples
    ///
    /// ```
    /// use websec::challenge::{ChallengeManager, ChallengeType};
    /// use std::time::Duration;
    ///
    /// let manager = ChallengeManager::new(Duration::from_secs(1));
    /// // ... créer des challenges ...
    /// std::thread::sleep(Duration::from_secs(2));
    /// let cleaned = manager.cleanup_expired();
    /// println!("{} challenges expirés nettoyés", cleaned);
    /// ```
    #[must_use]
    pub fn cleanup_expired(&self) -> usize {
        let Ok(mut challenges) = self.challenges.lock() else {
            return 0;
        };

        let timeout_millis = self.timeout.as_millis();
        let initial_count = challenges.len();

        challenges.retain(|_, challenge| !challenge.is_expired(timeout_millis));

        initial_count - challenges.len()
    }

    /// Récupère le challenge actif pour une IP (usage interne)
    ///
    /// # Arguments
    ///
    /// * `ip` - Adresse IP
    ///
    /// # Returns
    ///
    /// Le challenge s'il existe, `None` sinon
    #[cfg(test)]
    pub fn get_challenge(&self, ip: IpAddr) -> Option<Challenge> {
        self.challenges.lock().ok()?.get(&ip).cloned()
    }
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}
