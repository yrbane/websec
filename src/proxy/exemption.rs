//! Exemptions de chemin — laisser passer les robots légitimes sur des chemins
//! publics.
//!
//! Le pipeline de réputation suppose un navigateur : un client sans JavaScript
//! qui ne renvoie ni cookie ni en-têtes de navigateur accumule des signaux,
//! voit son score descendre, et finit en CHALLENGE (403 + preuve de travail)
//! puis en BLOCK. C'est le comportement voulu face à un scraper — mais pas
//! face aux robots qui doivent lire des métadonnées publiques : places de
//! marché NFT (OpenSea), moteurs d'indexation, agrégateurs, sondes de
//! disponibilité. Aucun d'eux ne résout un `PoW`.
//!
//! Une exemption dispense un couple (hôte, chemin, méthode) des décisions
//! **comportementales** uniquement. Elle ne relâche jamais les contrôles
//! déterministes : blacklist d'IP et politique GeoIP (globale ou par domaine)
//! restent appliquées — voir `DecisionEngineResult::hard_block`.
//!
//! # Sécurité
//!
//! Le chemin est normalisé avant comparaison (décodage pourcent, résolution de
//! `.` et `..`). Une requête qui tente de sortir de la racine, ou qui contient
//! des caractères de contrôle, n'est jamais exemptée : sans cela,
//! `/media/../admin` hériterait de l'exemption de `/media` alors que le
//! backend, lui, servirait `/admin`.
//!
//! # Exemple de configuration
//!
//! ```toml
//! [[exemptions]]
//! server_name = "minoupix.com"
//! paths = ["/api/nft", "/media"]
//! methods = ["GET", "HEAD"]
//! ```

use crate::config::settings::PathExemption;

/// Hôte visé par une règle d'exemption.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    /// Tous les hôtes (`server_name` vide ou `"*"`).
    Any,
    /// Correspondance exacte, minuscules (`"minoupix.com"`).
    Exact(String),
    /// Suffixe d'un wildcard `*.example.com` → `"example.com"`.
    Suffix(String),
}

impl HostPattern {
    fn parse(raw: &str) -> Self {
        let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() || name == "*" {
            Self::Any
        } else if let Some(suffix) = name.strip_prefix("*.") {
            Self::Suffix(suffix.to_string())
        } else {
            Self::Exact(name)
        }
    }

    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(name) => host == name,
            // `*.example.com` couvre les sous-domaines ET le domaine nu :
            // c'est ce qu'attend un administrateur qui écrit un wildcard.
            Self::Suffix(suffix) => {
                host == suffix
                    || (host.len() > suffix.len()
                        && host.ends_with(suffix)
                        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
            }
        }
    }
}

/// Motif de chemin d'une règle d'exemption.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathPattern {
    /// Préfixe respectant les frontières de segment : `/api/nft` couvre
    /// `/api/nft` et `/api/nft/1`, mais pas `/api/nftx`.
    Segment(String),
    /// Préfixe brut (motif configuré avec un `*` final) : `/media/*` couvre
    /// tout ce qui commence par `/media/`.
    Raw(String),
}

impl PathPattern {
    fn parse(raw: &str) -> Option<Self> {
        let pattern = raw.trim();
        if pattern.is_empty() {
            return None;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return Some(Self::Raw(prefix.to_string()));
        }
        // `/api/nft/` et `/api/nft` désignent la même chose ; on stocke la
        // forme sans slash final pour que la comparaison exacte fonctionne.
        let trimmed = pattern.trim_end_matches('/');
        if trimmed.is_empty() {
            // `/` exempte tout le site.
            return Some(Self::Raw("/".to_string()));
        }
        Some(Self::Segment(trimmed.to_string()))
    }

    fn matches(&self, path: &str) -> bool {
        match self {
            Self::Raw(prefix) => path.starts_with(prefix.as_str()),
            Self::Segment(prefix) => {
                path == prefix
                    || (path.len() > prefix.len()
                        && path.starts_with(prefix.as_str())
                        && path.as_bytes()[prefix.len()] == b'/')
            }
        }
    }
}

/// Une règle d'exemption compilée.
#[derive(Debug)]
struct Rule {
    host: HostPattern,
    paths: Vec<PathPattern>,
    /// Méthodes autorisées, en majuscules. Vide = toutes.
    methods: Vec<String>,
}

impl Rule {
    fn matches(&self, host: &str, method: &str, path: &str) -> bool {
        if !self.host.matches(host) {
            return false;
        }
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m == method) {
            return false;
        }
        self.paths.iter().any(|p| p.matches(path))
    }
}

/// Ensemble compilé des exemptions de chemin, partagé par tous les listeners.
///
/// Construit une fois au démarrage ; `matches` est en lecture seule et sans
/// allocation hors normalisation du chemin.
#[derive(Debug, Default)]
pub struct ExemptionSet {
    rules: Vec<Rule>,
}

impl ExemptionSet {
    /// Compile les règles issues de la configuration.
    ///
    /// Les règles sans chemin exploitable sont ignorées (une règle vide
    /// exempterait tout ou rien selon l'interprétation : on choisit rien).
    #[must_use]
    pub fn new(exemptions: &[PathExemption]) -> Self {
        let mut rules = Vec::new();
        for exemption in exemptions {
            let paths: Vec<PathPattern> = exemption
                .paths
                .iter()
                .filter_map(|p| PathPattern::parse(p))
                .collect();
            if paths.is_empty() {
                tracing::warn!(
                    host = %exemption.server_name,
                    "Exemption ignorée : aucun chemin valide"
                );
                continue;
            }
            let methods: Vec<String> = exemption
                .methods
                .iter()
                .map(|m| m.trim().to_ascii_uppercase())
                .filter(|m| !m.is_empty())
                .collect();
            rules.push(Rule {
                host: HostPattern::parse(&exemption.server_name),
                paths,
                methods,
            });
        }
        Self { rules }
    }

    /// Nombre de règles compilées.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// `true` si aucune règle n'est configurée (cas courant : chemin rapide).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// La requête est-elle exemptée des décisions comportementales ?
    ///
    /// * `host` — valeur brute de l'en-tête `Host` (port toléré).
    /// * `method` — méthode HTTP (`GET`, `POST`, …).
    /// * `path` — chemin brut de l'URI, encodé (`/media/%2E%2E/admin` inclus).
    #[must_use]
    pub fn matches(&self, host: &str, method: &str, path: &str) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        let Some(path) = normalize_path(path) else {
            return false;
        };
        let host = normalize_host(host);
        let method = method.to_ascii_uppercase();
        self.rules.iter().any(|r| r.matches(&host, &method, &path))
    }
}

/// Normalise un en-tête `Host` : minuscules, sans port, sans point final.
fn normalize_host(host: &str) -> String {
    let host = host.rsplit('@').next().unwrap_or(host).trim();
    // Les hôtes routés sont des noms : couper au dernier ':' suffit (une IPv6
    // littérale serait entre crochets et ne correspondrait à aucune règle).
    let host = host.split(':').next().unwrap_or(host);
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Normalise un chemin d'URI avant comparaison.
///
/// Décode les séquences pourcent, résout `.` et `..`, et refuse (`None`) tout
/// chemin qui remonte au-dessus de la racine ou contient un caractère de
/// contrôle : ces requêtes ne doivent jamais hériter d'une exemption, car le
/// backend les résoudra vers un autre chemin que celui qui a été comparé.
fn normalize_path(path: &str) -> Option<String> {
    let decoded = urlencoding::decode(path).ok()?;
    if decoded.chars().any(char::is_control) {
        return None;
    }

    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                // Sortie de la racine : requête ambiguë, jamais exemptée.
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }

    let mut out = String::with_capacity(decoded.len());
    for segment in &segments {
        out.push('/');
        out.push_str(segment);
    }
    if out.is_empty() {
        out.push('/');
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exemption(host: &str, paths: &[&str], methods: &[&str]) -> PathExemption {
        PathExemption {
            server_name: host.to_string(),
            paths: paths.iter().map(|p| (*p).to_string()).collect(),
            methods: methods.iter().map(|m| (*m).to_string()).collect(),
        }
    }

    fn nft_set() -> ExemptionSet {
        ExemptionSet::new(&[exemption(
            "minoupix.com",
            &["/api/nft", "/media"],
            &["GET", "HEAD"],
        )])
    }

    #[test]
    fn empty_set_never_matches() {
        let set = ExemptionSet::new(&[]);
        assert!(set.is_empty());
        assert!(!set.matches("minoupix.com", "GET", "/api/nft/1"));
    }

    #[test]
    fn exact_host_and_prefix_match() {
        let set = nft_set();
        assert!(set.matches("minoupix.com", "GET", "/api/nft/collection"));
        assert!(set.matches("minoupix.com", "GET", "/api/nft/1"));
        assert!(set.matches("minoupix.com", "HEAD", "/media/1.png"));
    }

    #[test]
    fn prefix_matches_the_exact_path_too() {
        let set = nft_set();
        assert!(set.matches("minoupix.com", "GET", "/api/nft"));
        assert!(set.matches("minoupix.com", "GET", "/api/nft/"));
    }

    #[test]
    fn prefix_respects_segment_boundary() {
        let set = nft_set();
        assert!(!set.matches("minoupix.com", "GET", "/api/nftx"));
        assert!(!set.matches("minoupix.com", "GET", "/media-private/1.png"));
    }

    #[test]
    fn other_paths_are_not_exempt() {
        let set = nft_set();
        assert!(!set.matches("minoupix.com", "GET", "/wp-login.php"));
        assert!(!set.matches("minoupix.com", "GET", "/"));
    }

    #[test]
    fn other_hosts_are_not_exempt() {
        let set = nft_set();
        assert!(!set.matches("autre.com", "GET", "/api/nft/1"));
    }

    #[test]
    fn host_port_and_case_are_ignored() {
        let set = nft_set();
        assert!(set.matches("MinouPix.com:443", "GET", "/api/nft/1"));
        assert!(set.matches("minoupix.com.", "GET", "/api/nft/1"));
    }

    #[test]
    fn methods_are_enforced() {
        let set = nft_set();
        assert!(!set.matches("minoupix.com", "POST", "/api/nft/1"));
        assert!(!set.matches("minoupix.com", "DELETE", "/media/1.png"));
    }

    #[test]
    fn method_matching_is_case_insensitive() {
        let set = nft_set();
        assert!(set.matches("minoupix.com", "get", "/api/nft/1"));
    }

    #[test]
    fn empty_methods_allow_every_method() {
        let set = ExemptionSet::new(&[exemption("minoupix.com", &["/hook"], &[])]);
        assert!(set.matches("minoupix.com", "POST", "/hook"));
    }

    #[test]
    fn wildcard_host_covers_subdomains_and_apex() {
        let set = ExemptionSet::new(&[exemption("*.example.com", &["/api"], &["GET"])]);
        assert!(set.matches("cdn.example.com", "GET", "/api/x"));
        assert!(set.matches("example.com", "GET", "/api/x"));
        assert!(!set.matches("notexample.com", "GET", "/api/x"));
        assert!(!set.matches("example.com.evil.net", "GET", "/api/x"));
    }

    #[test]
    fn empty_host_pattern_covers_every_host() {
        let set = ExemptionSet::new(&[exemption("", &["/robots.txt"], &["GET"])]);
        assert!(set.matches("anything.tld", "GET", "/robots.txt"));
        assert!(set.matches("", "GET", "/robots.txt"));
    }

    #[test]
    fn star_suffix_is_a_raw_prefix() {
        let set = ExemptionSet::new(&[exemption("h", &["/media/thumb*"], &["GET"])]);
        assert!(set.matches("h", "GET", "/media/thumbnail.png"));
        assert!(!set.matches("h", "GET", "/media/other.png"));
    }

    #[test]
    fn traversal_is_never_exempt() {
        let set = nft_set();
        assert!(!set.matches("minoupix.com", "GET", "/api/nft/../../admin"));
        assert!(!set.matches("minoupix.com", "GET", "/media/%2e%2e/%2e%2e/etc/passwd"));
    }

    #[test]
    fn traversal_inside_the_prefix_still_matches_normalized_path() {
        let set = nft_set();
        // /api/nft/x/../1 => /api/nft/1 : reste dans le préfixe, donc exempt.
        assert!(set.matches("minoupix.com", "GET", "/api/nft/x/../1"));
    }

    #[test]
    fn encoded_path_is_decoded_before_matching() {
        let set = nft_set();
        assert!(set.matches("minoupix.com", "GET", "/api%2Fnft/1"));
        assert!(set.matches("minoupix.com", "GET", "/media/mon%20image.png"));
    }

    #[test]
    fn control_characters_are_never_exempt() {
        let set = nft_set();
        assert!(!set.matches("minoupix.com", "GET", "/api/nft/1%00.jpg"));
    }

    #[test]
    fn double_slashes_are_collapsed() {
        let set = nft_set();
        assert!(set.matches("minoupix.com", "GET", "//api//nft//1"));
    }

    #[test]
    fn rule_without_usable_path_is_dropped() {
        let set = ExemptionSet::new(&[exemption("h", &["", "   "], &["GET"])]);
        assert!(set.is_empty());
        assert_eq!(set.rule_count(), 0);
    }

    #[test]
    fn root_path_exempts_everything_on_the_host() {
        let set = ExemptionSet::new(&[exemption("open.example.com", &["/"], &["GET"])]);
        assert!(set.matches("open.example.com", "GET", "/anything/here"));
        assert!(!set.matches("other.example.com", "GET", "/anything/here"));
    }

    #[test]
    fn several_rules_are_evaluated_independently() {
        let set = ExemptionSet::new(&[
            exemption("a.com", &["/api"], &["GET"]),
            exemption("b.com", &["/img"], &["GET", "HEAD"]),
        ]);
        assert_eq!(set.rule_count(), 2);
        assert!(set.matches("a.com", "GET", "/api/x"));
        assert!(!set.matches("a.com", "GET", "/img/x"));
        assert!(set.matches("b.com", "HEAD", "/img/x"));
        assert!(!set.matches("b.com", "GET", "/api/x"));
    }

    #[test]
    fn normalize_path_basics() {
        assert_eq!(normalize_path("/a/b").as_deref(), Some("/a/b"));
        assert_eq!(normalize_path("/a/./b/").as_deref(), Some("/a/b"));
        assert_eq!(normalize_path("/").as_deref(), Some("/"));
        assert_eq!(normalize_path("/a/../..").as_deref(), None);
    }
}
