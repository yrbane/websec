//! Branded HTML pages served directly by the proxy for decisions that are NOT
//! forwarded to a backend (block / rate-limit), plus the shared visual theme
//! reused by the Proof-of-Work challenge page.
//!
//! Everything is self-contained (inline CSS, no external asset) so the pages
//! render even for a client the proxy is actively blocking. Dark "techno"
//! aesthetic, consistent across BLOCK / RATE_LIMIT / CHALLENGE.

/// Shared `<style>` block. Kept as a single const so the block, rate-limit and
/// challenge pages stay visually identical. Injected via a `{style}` format
/// argument (never inlined in a `format!` template) so its CSS braces don't
/// clash with Rust string interpolation.
pub const PAGE_STYLE: &str = r#"<style>
:root{--bg:#0a0e14;--line:#1e2a3a;--fg:#e2e9f5;--muted:#7d8ba0;--accent:#22d3ee;--accent2:#a855f7;--danger:#f43f5e;--warn:#f59e0b}
*{box-sizing:border-box}
html,body{margin:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;color:var(--fg);
background:radial-gradient(1200px 600px at 18% -10%,rgba(34,211,238,.10),transparent 60%),
radial-gradient(1000px 520px at 100% 110%,rgba(168,85,247,.10),transparent 55%),
linear-gradient(180deg,#070b10,#0a0e14);background-attachment:fixed}
body::before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.45;
background-image:linear-gradient(rgba(120,160,220,.06) 1px,transparent 1px),
linear-gradient(90deg,rgba(120,160,220,.06) 1px,transparent 1px);background-size:42px 42px;
-webkit-mask:radial-gradient(circle at 50% 38%,#000,transparent 78%);mask:radial-gradient(circle at 50% 38%,#000,transparent 78%)}
.card{position:relative;width:100%;max-width:520px;
background:linear-gradient(180deg,rgba(20,28,40,.92),rgba(12,17,25,.94));
border:1px solid var(--line);border-radius:16px;padding:40px 34px;
box-shadow:0 24px 70px rgba(0,0,0,.55),inset 0 1px 0 rgba(255,255,255,.04);
-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px)}
.badge{display:inline-flex;align-items:center;gap:9px;font-size:11px;letter-spacing:.18em;text-transform:uppercase;
color:var(--muted);border:1px solid var(--line);padding:6px 13px;border-radius:999px}
.badge .dot{width:8px;height:8px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px var(--accent)}
.code{font-size:66px;font-weight:800;line-height:1;margin:20px 0 4px;letter-spacing:-.02em;
background:linear-gradient(120deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;color:transparent}
h1{font-size:20px;margin:0 0 12px;font-weight:600}
p{color:var(--muted);font-size:14px;line-height:1.65;margin:0 0 12px}
.meta{margin-top:24px;border-top:1px solid var(--line);padding-top:16px;
display:grid;grid-template-columns:auto 1fr;gap:7px 16px;font-size:12px}
.meta dt{color:var(--muted)}.meta dd{margin:0;color:var(--fg);word-break:break-all;text-align:right}
.footer{margin-top:26px;font-size:11px;color:#54607a;text-align:center;letter-spacing:.06em}
.footer b{color:var(--muted);font-weight:600}
a{color:var(--accent)}
.card.danger .code{background:linear-gradient(120deg,var(--danger),#fb7185);-webkit-background-clip:text;background-clip:text}
.card.danger .badge .dot{background:var(--danger);box-shadow:0 0 12px var(--danger)}
.card.warn .code{background:linear-gradient(120deg,var(--warn),#fbbf24);-webkit-background-clip:text;background-clip:text}
.card.warn .badge .dot{background:var(--warn);box-shadow:0 0 12px var(--warn)}
.bar{height:10px;background:#0c131d;border:1px solid var(--line);border-radius:999px;overflow:hidden;margin:24px 0 10px}
.bar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.status{font-size:12px;color:var(--muted)}
label{display:block;text-align:left;font-size:13px;color:var(--muted);margin:18px 0 8px}
input[type=text]{width:100%;padding:12px;border-radius:10px;border:1px solid var(--line);background:#0c131d;color:var(--fg);font:inherit}
input[type=text]:focus{outline:none;border-color:var(--accent)}
button{width:100%;margin-top:16px;padding:13px;border:0;border-radius:10px;cursor:pointer;font:inherit;font-weight:700;
color:#041018;background:linear-gradient(120deg,var(--accent),var(--accent2))}
button:hover{filter:brightness(1.08)}
</style>"#;

/// HTML-escape the small set of dynamic values we interpolate (IP, host, time).
/// These are attacker-influenceable (Host header), so escape defensively even
/// though they only land in text nodes.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Assemble a page from its parts. `accent` is "" (cyan/default), "danger" or
/// "warn"; `meta_rows` is pre-rendered `<dt>…</dt><dd>…</dd>` markup.
fn shell(accent: &str, badge: &str, code: &str, title: &str, body: &str, meta_rows: &str) -> String {
    let card_class = if accent.is_empty() {
        "card".to_string()
    } else {
        format!("card {accent}")
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{code} · WebSec</title>
{style}
</head>
<body>
<div class="{card_class}">
<span class="badge"><span class="dot"></span>{badge}</span>
<div class="code">{code}</div>
<h1>{title}</h1>
{body}
<dl class="meta">{meta_rows}</dl>
<div class="footer">Protégé par <b>WebSec</b> · proxy de sécurité</div>
</div>
</body>
</html>"#,
        style = PAGE_STYLE,
        card_class = card_class,
        badge = badge,
        code = code,
        title = title,
        body = body,
        meta_rows = meta_rows,
    )
}

/// 403 — request refused by the reputation engine.
pub fn block_page(ip: &str, score: impl std::fmt::Display, host: &str, when: &str) -> String {
    let meta = format!(
        "<dt>Adresse IP</dt><dd>{ip}</dd><dt>Hôte</dt><dd>{host}</dd><dt>Score</dt><dd>{score}</dd><dt>Horodatage</dt><dd>{when}</dd>",
        ip = esc(ip),
        host = esc(host),
        score = score,
        when = esc(when),
    );
    shell(
        "danger",
        "Accès refusé",
        "403",
        "Votre requête a été bloquée",
        "<p>Notre moteur de réputation a jugé cette requête malveillante ou trop peu fiable. \
Si vous pensez qu'il s'agit d'une erreur, réessayez plus tard ou contactez l'administrateur \
du site en indiquant l'horodatage ci-dessous.</p>",
        &meta,
    )
}

/// 429 — client is being rate-limited.
#[must_use]
pub fn rate_limit_page(ip: &str, host: &str, when: &str, retry_after: u64) -> String {
    let meta = format!(
        "<dt>Adresse IP</dt><dd>{ip}</dd><dt>Hôte</dt><dd>{host}</dd><dt>Réessayez dans</dt><dd>{retry}s</dd><dt>Horodatage</dt><dd>{when}</dd>",
        ip = esc(ip),
        host = esc(host),
        retry = retry_after,
        when = esc(when),
    );
    shell(
        "warn",
        "Trop de requêtes",
        "429",
        "Vous allez trop vite",
        "<p>Vous avez envoyé trop de requêtes en peu de temps. Ce n'est pas un blocage définitif : \
patientez quelques instants puis rechargez la page. Les scripts automatisés doivent respecter \
l'en-tête <code>Retry-After</code>.</p>",
        &meta,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_page_is_self_contained_html() {
        let h = block_page("203.0.113.4", 7, "example.com", "2026-01-01 00:00:00 UTC");
        assert!(h.starts_with("<!DOCTYPE html>"));
        assert!(h.contains("403"));
        assert!(h.contains("203.0.113.4"));
        assert!(h.contains("<style>"));
        // no external resource
        assert!(!h.contains("http://"));
        assert!(!h.contains("https://"));
    }

    #[test]
    fn rate_limit_page_shows_retry() {
        let h = rate_limit_page("203.0.113.4", "example.com", "t", 60);
        assert!(h.contains("429"));
        assert!(h.contains("60s"));
    }

    #[test]
    fn escaping_prevents_injection_via_host() {
        let h = block_page("1.2.3.4", 0, "<script>x</script>", "t");
        assert!(!h.contains("<script>x"));
        assert!(h.contains("&lt;script&gt;"));
    }
}
