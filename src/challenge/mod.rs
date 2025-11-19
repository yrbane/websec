//! Système de challenge CAPTCHA
//!
//! Implémente un mécanisme de challenge pour les IPs avec score de réputation
//! intermédiaire (`ProxyDecision::Challenge`).
//!
//! # Fonctionnalités
//!
//! - Génération de challenges mathématiques simples
//! - Validation sécurisée avec tokens uniques
//! - Expiration automatique après timeout configurable
//! - Thread-safe avec Arc<Mutex>
//! - Limitation du nombre de tentatives
//! - Nettoyage automatique des challenges expirés
//!
//! # Utilisation
//!
//! ```rust
//! use websec::challenge::{ChallengeManager, ChallengeType};
//! use std::net::IpAddr;
//! use std::str::FromStr;
//! use std::time::Duration;
//!
//! let manager = ChallengeManager::new(Duration::from_secs(300));
//! let ip = IpAddr::from_str("192.168.1.100").unwrap();
//!
//! // Créer un challenge
//! let challenge = manager.create_challenge(ip, ChallengeType::SimpleMath).unwrap();
//! println!("Question: {}", challenge.question);
//! println!("HTML: {}", challenge.to_html());
//!
//! // Valider la réponse
//! let is_valid = manager.validate(ip, &challenge.token, "42");
//! if is_valid {
//!     println!("Challenge réussi !");
//! }
//! ```

mod manager;
mod types;

pub use manager::ChallengeManager;
pub use types::{Challenge, ChallengeType};
