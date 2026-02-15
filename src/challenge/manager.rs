//! Gestionnaire de challenges thread-safe

use super::types::{Challenge, ChallengeType};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

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
    /// PoW difficulty (leading zero bits)
    pow_difficulty: u8,
    /// HMAC key for signing cookies (random, generated at startup)
    hmac_key: [u8; 32],
    /// Duration of the PoW cookie in seconds
    cookie_ttl_secs: u64,
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
        Self::with_pow_config(timeout, 20, 3600)
    }

    /// Crée un nouveau gestionnaire avec configuration PoW complète
    #[must_use]
    pub fn with_pow_config(timeout: Duration, pow_difficulty: u8, cookie_ttl_secs: u64) -> Self {
        let mut hmac_key = [0u8; 32];
        let mut rng = rand::rng();
        for b in &mut hmac_key {
            *b = rand::Rng::random(&mut rng);
        }
        Self {
            challenges: Arc::new(Mutex::new(HashMap::new())),
            timeout,
            pow_difficulty,
            hmac_key,
            cookie_ttl_secs,
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
            ChallengeType::ProofOfWork => Challenge::new_proof_of_work(self.pow_difficulty),
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

        // Vérifier la réponse selon le type de challenge
        let valid = match challenge.challenge_type {
            ChallengeType::SimpleMath => challenge.answer.trim() == answer.trim(),
            ChallengeType::ProofOfWork => {
                let difficulty: u8 = challenge.answer.parse().unwrap_or(20);
                verify_pow(&challenge.question, answer.trim(), difficulty)
            }
        };

        if valid {
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

    /// Returns the configured PoW difficulty
    #[must_use]
    pub fn pow_difficulty(&self) -> u8 {
        self.pow_difficulty
    }

    /// Génère un cookie PoW signé HMAC-SHA256 pour une IP validée
    ///
    /// Format: `ip|expiry_timestamp|hmac_hex`
    #[must_use]
    pub fn generate_pow_cookie(&self, ip: IpAddr) -> String {
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.cookie_ttl_secs;
        let payload = format!("{}|{}", ip, expiry);
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        format!("{}|{}", payload, signature)
    }

    /// Returns the configured cookie TTL in seconds
    #[must_use]
    pub fn cookie_ttl_secs(&self) -> u64 {
        self.cookie_ttl_secs
    }

    /// Vérifie un cookie PoW signé
    ///
    /// Vérifie que l'IP correspond, que le cookie n'est pas expiré,
    /// et que la signature HMAC est valide.
    #[must_use]
    pub fn verify_pow_cookie(&self, cookie_value: &str, client_ip: IpAddr) -> bool {
        // Format attendu: ip|expiry|signature
        let parts: Vec<&str> = cookie_value.splitn(3, '|').collect();
        if parts.len() != 3 {
            return false;
        }

        let cookie_ip = parts[0];
        let expiry_str = parts[1];
        let signature = parts[2];

        // Vérifier que l'IP correspond
        if cookie_ip != client_ip.to_string() {
            return false;
        }

        // Vérifier l'expiration
        let Ok(expiry) = expiry_str.parse::<u64>() else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > expiry {
            return false;
        }

        // Vérifier la signature HMAC
        let payload = format!("{}|{}", cookie_ip, expiry_str);
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        signature == expected
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
    #[must_use]
    pub fn get_challenge(&self, ip: IpAddr) -> Option<Challenge> {
        self.challenges.lock().ok()?.get(&ip).cloned()
    }
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

/// Vérifie un Proof of Work SHA-256
///
/// Retourne `true` si `SHA-256(challenge + nonce)` commence par au moins
/// `difficulty` bits à zéro.
fn verify_pow(challenge: &str, nonce: &str, difficulty: u8) -> bool {
    use sha2::Digest;
    let hash = Sha256::digest(format!("{challenge}{nonce}"));
    count_leading_zero_bits(&hash) >= difficulty
}

/// Compte le nombre de bits à zéro en tête d'un tableau d'octets
fn count_leading_zero_bits(data: &[u8]) -> u8 {
    let mut bits: u8 = 0;
    for &byte in data {
        if byte == 0 {
            bits += 8;
        } else {
            // Count leading zeros in this byte
            bits += byte.leading_zeros() as u8;
            break;
        }
    }
    bits
}
