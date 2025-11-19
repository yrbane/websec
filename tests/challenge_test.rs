//! Tests pour le système de challenge CAPTCHA
//!
//! TDD PHASE ROUGE : Tests écrits AVANT implémentation
//!
//! Tests :
//! - Génération de challenge CAPTCHA simple (mathématique)
//! - Validation de réponse CAPTCHA correcte
//! - Validation de réponse CAPTCHA incorrecte
//! - Expiration de challenge après timeout
//! - Stockage thread-safe des challenges actifs
//! - Génération de page HTML de challenge
//! - Gestion des tentatives multiples
//! - Upgrade du score après challenge réussi

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use websec::challenge::{Challenge, ChallengeManager, ChallengeType};

#[test]
fn test_challenge_creation() {
    let manager = ChallengeManager::new(Duration::from_secs(300));
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    let challenge = manager.create_challenge(ip, ChallengeType::SimpleMath);

    assert!(challenge.is_some(), "Le challenge doit être créé");
    let challenge = challenge.unwrap();
    assert_eq!(challenge.challenge_type, ChallengeType::SimpleMath);
    assert!(!challenge.token.is_empty(), "Le token doit être généré");
}

#[test]
fn test_simple_math_challenge_generation() {
    let challenge = Challenge::new_simple_math();

    assert_eq!(challenge.challenge_type, ChallengeType::SimpleMath);
    assert!(
        !challenge.question.is_empty(),
        "La question doit être générée"
    );
    assert!(!challenge.token.is_empty(), "Le token doit être généré");

    // Vérifier que la question est du type "Combien font X + Y ?"
    assert!(
        challenge.question.contains('+')
            || challenge.question.contains('-')
            || challenge.question.contains('×'),
        "La question doit contenir une opération mathématique"
    );
}

#[test]
fn test_validate_correct_answer() {
    let manager = ChallengeManager::new(Duration::from_secs(300));
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    let challenge = manager
        .create_challenge(ip, ChallengeType::SimpleMath)
        .unwrap();

    // Extraire la réponse attendue (pour le test, on doit pouvoir la calculer)
    // Dans un vrai système, l'answer est stockée de manière sécurisée
    let token = challenge.token.clone();
    let expected_answer = challenge.answer.clone();

    let is_valid = manager.validate(ip, &token, &expected_answer);
    assert!(is_valid, "La validation avec la bonne réponse doit réussir");
}

#[test]
fn test_validate_incorrect_answer() {
    let manager = ChallengeManager::new(Duration::from_secs(300));
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    let challenge = manager
        .create_challenge(ip, ChallengeType::SimpleMath)
        .unwrap();
    let token = challenge.token.clone();

    let is_valid = manager.validate(ip, &token, "mauvaise_réponse");
    assert!(
        !is_valid,
        "La validation avec une mauvaise réponse doit échouer"
    );
}

#[test]
fn test_challenge_expiration() {
    // Challenge avec expiration très courte (50ms)
    let manager = ChallengeManager::new(Duration::from_millis(50));
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    let challenge = manager
        .create_challenge(ip, ChallengeType::SimpleMath)
        .unwrap();
    let token = challenge.token.clone();
    let answer = challenge.answer.clone();

    // Attendre l'expiration (bien au-delà du timeout)
    std::thread::sleep(Duration::from_millis(200));

    // Le challenge doit être expiré
    let is_valid = manager.validate(ip, &token, &answer);
    assert!(
        !is_valid,
        "La validation d'un challenge expiré doit échouer"
    );
}

#[test]
fn test_challenge_token_uniqueness() {
    let manager = ChallengeManager::new(Duration::from_secs(300));
    let ip1 = IpAddr::from_str("192.168.1.100").unwrap();
    let ip2 = IpAddr::from_str("192.168.1.101").unwrap();

    let challenge1 = manager
        .create_challenge(ip1, ChallengeType::SimpleMath)
        .unwrap();
    let challenge2 = manager
        .create_challenge(ip2, ChallengeType::SimpleMath)
        .unwrap();

    assert_ne!(
        challenge1.token, challenge2.token,
        "Chaque challenge doit avoir un token unique"
    );
}

#[test]
fn test_challenge_html_generation() {
    let challenge = Challenge::new_simple_math();
    let html = challenge.to_html();

    assert!(
        html.contains("<!DOCTYPE html>"),
        "Doit générer du HTML valide"
    );
    assert!(
        html.contains(&challenge.question),
        "Le HTML doit contenir la question"
    );
    assert!(html.contains("form"), "Le HTML doit contenir un formulaire");
    assert!(
        html.contains(&challenge.token),
        "Le HTML doit contenir le token caché"
    );
}

#[test]
fn test_multiple_challenges_per_ip() {
    let manager = ChallengeManager::new(Duration::from_secs(300));
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    // Créer un premier challenge
    let challenge1 = manager
        .create_challenge(ip, ChallengeType::SimpleMath)
        .unwrap();
    let token1 = challenge1.token.clone();

    // Créer un second challenge pour la même IP (remplace le premier)
    let challenge2 = manager
        .create_challenge(ip, ChallengeType::SimpleMath)
        .unwrap();
    let token2 = challenge2.token.clone();

    assert_ne!(
        token1, token2,
        "Le nouveau challenge doit avoir un token différent"
    );

    // Le premier challenge ne doit plus être valide
    let is_valid = manager.validate(ip, &token1, &challenge1.answer);
    assert!(
        !is_valid,
        "L'ancien challenge doit être invalidé par le nouveau"
    );

    // Le second challenge doit être valide
    let is_valid = manager.validate(ip, &token2, &challenge2.answer);
    assert!(is_valid, "Le nouveau challenge doit être valide");
}

#[tokio::test]
async fn test_concurrent_challenge_operations() {
    let manager = Arc::new(ChallengeManager::new(Duration::from_secs(300)));
    let mut handles = vec![];

    // Créer 100 challenges concurrents
    for i in 0..100 {
        let manager_clone = Arc::clone(&manager);
        let handle = tokio::spawn(async move {
            let ip = IpAddr::from_str(&format!("192.168.1.{}", i % 255)).unwrap();
            manager_clone.create_challenge(ip, ChallengeType::SimpleMath)
        });
        handles.push(handle);
    }

    // Attendre que tous les challenges soient créés
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_some(), "Tous les challenges doivent être créés");
    }
}

#[test]
fn test_challenge_max_attempts() {
    let manager = ChallengeManager::new(Duration::from_secs(300));
    let ip = IpAddr::from_str("192.168.1.100").unwrap();

    let challenge = manager
        .create_challenge(ip, ChallengeType::SimpleMath)
        .unwrap();
    let token = challenge.token.clone();

    // Faire 3 tentatives incorrectes
    for _ in 0..3 {
        let is_valid = manager.validate(ip, &token, "mauvaise_réponse");
        assert!(!is_valid);
    }

    // Le challenge doit être invalidé après trop de tentatives
    let is_valid = manager.validate(ip, &token, &challenge.answer);
    assert!(
        !is_valid,
        "Le challenge doit être invalidé après trop de tentatives"
    );
}

#[test]
fn test_cleanup_expired_challenges() {
    let manager = ChallengeManager::new(Duration::from_millis(30));

    // Créer plusieurs challenges
    for i in 0..10 {
        let ip = IpAddr::from_str(&format!("192.168.1.{}", i)).unwrap();
        manager.create_challenge(ip, ChallengeType::SimpleMath);
    }

    // Attendre l'expiration (bien au-delà du timeout)
    std::thread::sleep(Duration::from_millis(150));

    // Nettoyer les challenges expirés
    let cleaned = manager.cleanup_expired();
    assert!(
        cleaned >= 10,
        "Au moins 10 challenges doivent être nettoyés"
    );
}

#[test]
fn test_challenge_types() {
    // Tester que tous les types de challenge sont supportés
    let simple_math = Challenge::new_simple_math();
    assert_eq!(simple_math.challenge_type, ChallengeType::SimpleMath);

    // On pourrait ajouter d'autres types plus tard
    // let word_puzzle = Challenge::new_word_puzzle();
    // assert_eq!(word_puzzle.challenge_type, ChallengeType::WordPuzzle);
}
