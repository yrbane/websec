//! Types de challenges et structure de données

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Type de challenge supporté
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    /// Challenge mathématique simple (addition, soustraction, multiplication)
    SimpleMath,
    /// Proof of Work SHA-256 (transparent pour l'humain, coûteux pour les bots)
    ProofOfWork,
}

/// Structure d'un challenge actif
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Type de challenge
    pub challenge_type: ChallengeType,
    /// Token unique pour identifier ce challenge
    pub token: String,
    /// Question affichée à l'utilisateur
    pub question: String,
    /// Réponse attendue (stockée de manière sécurisée)
    pub answer: String,
    /// Timestamp de création (epoch milliseconds)
    pub created_at: u128,
    /// Nombre de tentatives restantes
    pub attempts_remaining: u8,
}

impl Challenge {
    /// Crée un nouveau challenge mathématique simple
    ///
    /// Génère une question du type "Combien font X + Y ?" avec X et Y entre 1 et 20.
    /// Les opérations supportées sont : addition (+), soustraction (-), multiplication (×).
    ///
    /// # Returns
    ///
    /// Un challenge avec token unique, question et réponse calculée.
    ///
    /// # Examples
    ///
    /// ```
    /// use websec::challenge::Challenge;
    ///
    /// let challenge = Challenge::new_simple_math();
    /// println!("Question: {}", challenge.question);
    /// // Question: Combien font 7 + 12 ?
    /// ```
    ///
    /// # Panics
    ///
    /// Panique si l'horloge système est réglée avant l'époque UNIX (1970-01-01).
    /// Cela ne devrait jamais se produire dans des conditions normales d'utilisation.
    #[must_use]
    pub fn new_simple_math() -> Self {
        let mut rng = rand::rng();
        let operations = ['+', '-', '×'];
        let operation = operations[rng.random_range(0..operations.len())];

        let (num1, num2, answer) = match operation {
            '+' => {
                let n1 = rng.random_range(1..=20);
                let n2 = rng.random_range(1..=20);
                (n1, n2, n1 + n2)
            }
            '-' => {
                let n1 = rng.random_range(10..=30);
                let n2 = rng.random_range(1..=n1); // Éviter les résultats négatifs
                (n1, n2, n1 - n2)
            }
            '×' => {
                let n1 = rng.random_range(2..=10);
                let n2 = rng.random_range(2..=10);
                (n1, n2, n1 * n2)
            }
            _ => unreachable!(),
        };

        let question = format!("Combien font {num1} {operation} {num2} ?");
        let token = Uuid::new_v4().to_string();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        Self {
            challenge_type: ChallengeType::SimpleMath,
            token,
            question,
            answer: answer.to_string(),
            created_at,
            attempts_remaining: 3,
        }
    }

    /// Crée un nouveau challenge Proof of Work SHA-256
    ///
    /// Génère une chaîne aléatoire de 32 octets (hex-encodée) comme challenge.
    /// Le navigateur doit trouver un nonce tel que SHA-256(challenge + nonce)
    /// commence par `difficulty` bits à zéro.
    #[must_use]
    pub fn new_proof_of_work(difficulty: u8) -> Self {
        let mut rng = rand::rng();
        let mut challenge_bytes = [0u8; 32];
        for b in &mut challenge_bytes {
            *b = rng.random();
        }
        let challenge_str = hex::encode(challenge_bytes);
        let token = Uuid::new_v4().to_string();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        Self {
            challenge_type: ChallengeType::ProofOfWork,
            token,
            question: challenge_str,
            answer: difficulty.to_string(),
            created_at,
            attempts_remaining: 1,
        }
    }

    /// Génère une page HTML contenant le formulaire de challenge
    ///
    /// La page inclut :
    /// - Un titre explicatif
    /// - La question du challenge
    /// - Un champ de réponse
    /// - Un champ caché avec le token
    /// - Un bouton de soumission
    ///
    /// # Returns
    ///
    /// HTML complet prêt à être envoyé comme réponse HTTP 403.
    ///
    /// # Examples
    ///
    /// ```
    /// use websec::challenge::Challenge;
    ///
    /// let challenge = Challenge::new_simple_math();
    /// let html = challenge.to_html();
    /// assert!(html.contains("<!DOCTYPE html>"));
    /// ```
    #[must_use]
    pub fn to_html(&self) -> String {
        match self.challenge_type {
            ChallengeType::SimpleMath => self.to_math_html(),
            ChallengeType::ProofOfWork => self.to_pow_html(),
        }
    }

    /// HTML pour le challenge mathématique classique
    fn to_math_html(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vérification de sécurité - WebSec</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 100%;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 24px;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .question {{
            background: #f7f7f7;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 18px;
            color: #333;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        label {{
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 16px;
            box-sizing: border-box;
            transition: border-color 0.3s;
        }}
        input[type="text"]:focus {{
            outline: none;
            border-color: #667eea;
        }}
        button {{
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        button:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }}
        button:active {{
            transform: translateY(0);
        }}
        .footer {{
            margin-top: 20px;
            text-align: center;
            color: #999;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Vérification de sécurité</h1>
        <p class="subtitle">Veuillez répondre à cette question pour continuer</p>

        <div class="question">
            {}
        </div>

        <form method="POST" action="/challenge/verify">
            <input type="hidden" name="token" value="{}">

            <label for="answer">Votre réponse :</label>
            <input type="text" id="answer" name="answer" required autofocus>

            <button type="submit">Valider</button>
        </form>

        <div class="footer">
            Protégé par WebSec - Proxy de sécurité intelligent
        </div>
    </div>
</body>
</html>"#,
            self.question, self.token
        )
    }

    /// HTML pour le challenge Proof of Work SHA-256
    ///
    /// Page auto-exécutable : le navigateur calcule un nonce tel que
    /// SHA-256(challenge + nonce) commence par `difficulty` bits à zéro,
    /// puis soumet automatiquement le formulaire.
    fn to_pow_html(&self) -> String {
        let difficulty: u8 = self.answer.parse().unwrap_or(20);
        format!(
            r##"<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vérification de sécurité - WebSec</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 100%;
            text-align: center;
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 24px;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }}
        .progress-container {{
            background: #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
            height: 24px;
            margin: 20px 0;
        }}
        .progress-bar {{
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 8px;
            transition: width 0.3s ease;
            width: 0%;
        }}
        .status {{
            color: #555;
            font-size: 14px;
            margin-top: 10px;
        }}
        .footer {{
            margin-top: 30px;
            color: #999;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vérification de sécurité</h1>
        <p class="subtitle">Vérification en cours, veuillez patienter...</p>

        <div class="progress-container">
            <div class="progress-bar" id="progress"></div>
        </div>
        <div class="status" id="status">Initialisation...</div>

        <form id="pow-form" method="POST" action="/challenge/verify" style="display:none">
            <input type="hidden" name="token" value="{token}">
            <input type="hidden" name="answer" id="nonce-field" value="">
        </form>

        <div class="footer">
            Protégé par WebSec - Proxy de sécurité intelligent
        </div>
    </div>
    <script>
    (function() {{
        var challenge = "{challenge}";
        var difficulty = {difficulty};
        var BATCH = 5000;
        var nonce = 0;
        var encoder = new TextEncoder();
        var bar = document.getElementById("progress");
        var status = document.getElementById("status");
        // Estimated total attempts: 2^difficulty
        var estimated = Math.pow(2, difficulty);

        function countLeadingZeroBits(buf) {{
            var bits = 0;
            for (var i = 0; i < buf.length; i++) {{
                if (buf[i] === 0) {{
                    bits += 8;
                }} else {{
                    var b = buf[i];
                    while ((b & 0x80) === 0) {{
                        bits++;
                        b <<= 1;
                    }}
                    break;
                }}
            }}
            return bits;
        }}

        function toHex(buf) {{
            var h = "";
            for (var i = 0; i < buf.length; i++) {{
                h += ("0" + buf[i].toString(16)).slice(-2);
            }}
            return h;
        }}

        async function mine() {{
            status.textContent = "Calcul en cours...";
            while (true) {{
                for (var i = 0; i < BATCH; i++) {{
                    var input = challenge + nonce.toString();
                    var data = encoder.encode(input);
                    var hashBuf = await crypto.subtle.digest("SHA-256", data);
                    var hash = new Uint8Array(hashBuf);
                    if (countLeadingZeroBits(hash) >= difficulty) {{
                        // Found!
                        bar.style.width = "100%";
                        status.textContent = "Vérification réussie ! Redirection...";
                        document.getElementById("nonce-field").value = nonce.toString();
                        document.getElementById("pow-form").submit();
                        return;
                    }}
                    nonce++;
                }}
                // Update progress
                var pct = Math.min(99, Math.round((nonce / estimated) * 100));
                bar.style.width = pct + "%";
                status.textContent = "Calcul en cours... " + nonce.toLocaleString() + " tentatives";
                // Yield to UI
                await new Promise(function(r) {{ setTimeout(r, 0); }});
            }}
        }}

        mine();
    }})();
    </script>
</body>
</html>"##,
            token = self.token,
            challenge = self.question,
            difficulty = difficulty
        )
    }

    /// Vérifie si le challenge est expiré
    ///
    /// # Arguments
    ///
    /// * `timeout_millis` - Durée de validité en millisecondes
    ///
    /// # Returns
    ///
    /// `true` si le challenge est expiré, `false` sinon
    ///
    /// # Panics
    ///
    /// Panique si l'horloge système est réglée avant l'époque UNIX (1970-01-01).
    #[must_use]
    pub fn is_expired(&self, timeout_millis: u128) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        now - self.created_at > timeout_millis
    }
}
