//! Parsing utilities for HTTP requests
//!
//! Provides helpers for parsing URLs, User-Agent strings, and other HTTP fields.

use regex::Regex;
use std::collections::HashMap;

/// Parse query string into key-value pairs
///
/// # Arguments
///
/// * `query` - Query string (without leading '?')
///
/// # Returns
///
/// `HashMap` of parameter name to value
///
/// # Example
///
/// ```
/// use websec::utils::parse_query_string;
///
/// let params = parse_query_string("user=admin&pass=123");
/// assert_eq!(params.get("user"), Some(&"admin".to_string()));
/// ```
#[must_use] pub fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();

    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            params.insert(
                urlencoding::decode(key).unwrap_or_default().to_string(),
                urlencoding::decode(value).unwrap_or_default().to_string(),
            );
        }
    }

    params
}

/// Check if User-Agent matches bot patterns
///
/// # Arguments
///
/// * `user_agent` - User-Agent header string
///
/// # Returns
///
/// `true` if the UA matches known bot/scanner patterns
pub fn is_bot_user_agent(user_agent: &str) -> bool {
    static BOT_PATTERNS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?i)(bot|crawler|spider|scraper|curl|wget|python|java|go-http|nikto|sqlmap|nmap|masscan|acunetix|burp|metasploit|nessus|openvas)",
        )
        .unwrap()
    });

    BOT_PATTERNS.is_match(user_agent)
}

/// Check if User-Agent is empty or missing
#[must_use] pub fn is_empty_user_agent(user_agent: Option<&str>) -> bool {
    user_agent.is_none_or(|ua| ua.trim().is_empty())
}

/// Extract User-Agent browser family
///
/// Returns basic browser classification: Chrome, Firefox, Safari, Edge, etc.
#[must_use] pub fn extract_browser_family(user_agent: &str) -> Option<String> {
    if user_agent.contains("Chrome") && !user_agent.contains("Edge") {
        Some("Chrome".to_string())
    } else if user_agent.contains("Firefox") {
        Some("Firefox".to_string())
    } else if user_agent.contains("Safari") && !user_agent.contains("Chrome") {
        Some("Safari".to_string())
    } else if user_agent.contains("Edge") {
        Some("Edge".to_string())
    } else {
        None
    }
}

/// Check if path contains directory traversal patterns
///
/// # Arguments
///
/// * `path` - URL path component
///
/// # Returns
///
/// `true` if path contains ../, ..\ or encoded variants
pub fn contains_path_traversal(path: &str) -> bool {
    static TRAVERSAL_PATTERNS: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)").unwrap());

    TRAVERSAL_PATTERNS.is_match(&path.to_lowercase())
}

/// Check if string contains SQL injection patterns
///
/// # Arguments
///
/// * `input` - Input string to check (query param, path, etc.)
///
/// # Returns
///
/// `true` if SQL injection patterns detected
pub fn contains_sql_injection(input: &str) -> bool {
    static SQL_PATTERNS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|;\s*drop\b|;\s*delete\b|'.*or.*'.*=.*'|--|\#|/\*|\*/|xp_cmdshell|exec\s*\(|\bsleep\s*\(|\bwaitfor\b|\bbenchmark\s*\()",
        )
        .unwrap()
    });

    SQL_PATTERNS.is_match(input)
}

/// Check if string contains XSS patterns
///
/// # Arguments
///
/// * `input` - Input string to check
///
/// # Returns
///
/// `true` if XSS patterns detected
pub fn contains_xss(input: &str) -> bool {
    static XSS_PATTERNS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?i)(<script|javascript:|onerror=|onload=|<iframe|<object|<embed|eval\(|alert\()",
        )
        .unwrap()
    });

    XSS_PATTERNS.is_match(input)
}

/// Check if string contains command injection patterns
///
/// # Arguments
///
/// * `input` - Input string to check
///
/// # Returns
///
/// `true` if command injection patterns detected
pub fn contains_command_injection(input: &str) -> bool {
    static CMD_PATTERNS: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"(?i)(;\s*(cat|ls|whoami|id|pwd|wget|curl|nc|bash|sh|chmod|chown)|`[^`]+`|\$\([^)]+\)|\|\s*(cat|ls|whoami))",
        )
        .unwrap()
    });

    CMD_PATTERNS.is_match(input)
}

/// Normalize HTTP method to uppercase
#[must_use] pub fn normalize_method(method: &str) -> String {
    method.to_uppercase()
}

/// Extract IP from X-Forwarded-For header (first IP in chain)
///
/// # Arguments
///
/// * `xff_header` - Value of X-Forwarded-For header
///
/// # Returns
///
/// First IP address in the chain, or None if invalid
#[must_use] pub fn extract_xff_ip(xff_header: &str) -> Option<String> {
    xff_header
        .split(',')
        .next()
        .map(|ip| ip.trim().to_string())
        .filter(|ip| !ip.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_string() {
        let params = parse_query_string("user=admin&pass=123&empty=");
        assert_eq!(params.get("user"), Some(&"admin".to_string()));
        assert_eq!(params.get("pass"), Some(&"123".to_string()));
        assert_eq!(params.get("empty"), Some(&String::new()));
    }

    #[test]
    fn test_parse_query_string_encoded() {
        let params = parse_query_string("name=John%20Doe&email=test%40example.com");
        assert_eq!(params.get("name"), Some(&"John Doe".to_string()));
        assert_eq!(params.get("email"), Some(&"test@example.com".to_string()));
    }

    #[test]
    fn test_is_bot_user_agent() {
        assert!(is_bot_user_agent("Mozilla/5.0 (compatible; Googlebot/2.1)"));
        assert!(is_bot_user_agent("curl/7.68.0"));
        assert!(is_bot_user_agent("sqlmap/1.0"));
        assert!(is_bot_user_agent("python-requests/2.25.1"));
        assert!(!is_bot_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0"
        ));
    }

    #[test]
    fn test_is_empty_user_agent() {
        assert!(is_empty_user_agent(None));
        assert!(is_empty_user_agent(Some("")));
        assert!(is_empty_user_agent(Some("   ")));
        assert!(!is_empty_user_agent(Some("Chrome")));
    }

    #[test]
    fn test_extract_browser_family() {
        assert_eq!(
            extract_browser_family("Mozilla/5.0 Chrome/91.0"),
            Some("Chrome".to_string())
        );
        assert_eq!(
            extract_browser_family("Mozilla/5.0 Firefox/89.0"),
            Some("Firefox".to_string())
        );
        assert_eq!(
            extract_browser_family("Mozilla/5.0 Safari/14.0"),
            Some("Safari".to_string())
        );
        assert_eq!(
            extract_browser_family("Mozilla/5.0 Edge/91.0"),
            Some("Edge".to_string())
        );
    }

    #[test]
    fn test_contains_path_traversal() {
        assert!(contains_path_traversal("/etc/../passwd"));
        assert!(contains_path_traversal("/files/..\\windows"));
        assert!(contains_path_traversal("/app/%2e%2e%2fconfig"));
        assert!(!contains_path_traversal("/normal/path/file.txt"));
    }

    #[test]
    fn test_contains_sql_injection() {
        assert!(contains_sql_injection("' OR '1'='1"));
        assert!(contains_sql_injection("1; DROP TABLE users--"));
        assert!(contains_sql_injection("UNION SELECT * FROM passwords"));
        assert!(contains_sql_injection("admin'--"));
        assert!(!contains_sql_injection("normal query string"));
    }

    #[test]
    fn test_contains_xss() {
        assert!(contains_xss("<script>alert('XSS')</script>"));
        assert!(contains_xss("<img onerror='alert(1)'>"));
        assert!(contains_xss("javascript:alert(document.cookie)"));
        assert!(contains_xss("<iframe src='evil.com'>"));
        assert!(!contains_xss("normal text content"));
    }

    #[test]
    fn test_normalize_method() {
        assert_eq!(normalize_method("get"), "GET");
        assert_eq!(normalize_method("POST"), "POST");
        assert_eq!(normalize_method("DeLeTe"), "DELETE");
    }

    #[test]
    fn test_extract_xff_ip() {
        assert_eq!(
            extract_xff_ip("192.168.1.1, 10.0.0.1, 172.16.0.1"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            extract_xff_ip("203.0.113.1"),
            Some("203.0.113.1".to_string())
        );
        assert_eq!(extract_xff_ip(""), None);
    }
}
