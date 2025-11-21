use crate::{Error, Result};
use reqwest::Client;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone)]
struct ComposeCommand {
    program: String,
    args: Vec<String>,
}

impl ComposeCommand {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(std::string::ToString::to_string).collect(),
        }
    }

    fn base() -> Result<Self> {
        if Command::new("docker")
            .args(["compose", "version"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            Ok(Self::new("docker", &["compose"]))
        } else if Command::new("docker-compose")
            .arg("--version")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            Ok(Self::new("docker-compose", &[]))
        } else {
            Err(Error::Config(
                "docker compose/docker-compose introuvable dans le PATH".to_string(),
            ))
        }
    }

    fn run(&self, extra: &[&str]) -> Result<()> {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args).args(extra);
        let status = cmd.status().map_err(Error::Io)?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Config(format!(
                "Commande {:?} {:?} échouée ({status})",
                self.program, extra
            )))
        }
    }
}

/// Build the `WebSec` Docker image with tags `latest` and the current git SHA.
pub fn docker_build() -> Result<()> {
    println!("🐳 Building WebSec Docker image\n");

    let git_sha = git_short_sha().unwrap_or_else(|_| "latest".to_string());
    let buildx_available = Command::new("docker")
        .args(["buildx", "version"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let mut cmd = Command::new("docker");
    if buildx_available {
        println!("📦 BuildKit détecté - activation");
        cmd.env("DOCKER_BUILDKIT", "1");
    } else {
        println!("📦 Build classique (BuildKit indisponible)");
    }

    let status = cmd
        .arg("build")
        .args(["--tag", "websec:latest"])
        .args(["--tag", &format!("websec:{git_sha}")])
        .arg("--build-arg")
        .arg("BUILDKIT_INLINE_CACHE=1")
        .arg(".")
        .status()
        .map_err(Error::Io)?;

    if !status.success() {
        return Err(Error::Config("docker build a échoué".to_string()));
    }

    println!("\n✅ Docker image built successfully!");
    let _ = Command::new("docker").args(["images", "websec"]).status();
    Ok(())
}

/// Guard to automatically stop docker-compose on drop
struct ComposeGuard {
    compose: ComposeCommand,
    keep: bool,
}

impl Drop for ComposeGuard {
    fn drop(&mut self) {
        if self.keep {
            println!("Stack laissé en fonctionnement (option --keep-up)");
            return;
        }
        let _ = self.compose.run(["down", "-v"].as_ref());
    }
}

/// Launch the docker-compose stack and run the functional test suite.
pub async fn docker_test(keep_up: bool) -> Result<()> {
    println!("🐳 Testing WebSec Docker stack\n");
    let compose = ComposeCommand::base()?;
    compose.run(["up", "-d"].as_ref())?;

    let _guard = ComposeGuard {
        compose: compose.clone(),
        keep: keep_up,
    };

    println!("⏳ Waiting for services to boot...");
    sleep(Duration::from_secs(10)).await;

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| Error::Http(format!("reqwest error: {e}")))?;

    health_check(&client, "backend", "http://localhost:3000/api/health").await?;
    health_check(&client, "websec", "http://localhost:8080/metrics").await?;
    run_compose_exec(
        &compose,
        &["exec", "-T", "redis", "redis-cli", "ping"],
        "PONG",
    )?;

    println!("\n🧪 Running functional tests\n");
    test_http_status(&client, "GET / via proxy", "http://localhost:8080/", 200).await?;
    test_metrics(&client).await?;
    test_headers(&client).await?;
    test_users(&client).await?;
    test_echo(&client).await?;

    println!("\n📊 Container statistics\n");
    let _ = compose.run(["ps"].as_ref());

    println!("\n📈 WebSec metrics\n");
    let metrics = client
        .get("http://localhost:8080/metrics")
        .send()
        .await
        .map_err(|e| Error::Http(format!("metrics fetch failed: {e}")))?
        .text()
        .await
        .map_err(|e| Error::Http(format!("metrics read failed: {e}")))?;
    if let Some(line) = metrics.lines().find(|l| l.starts_with("requests_total")) {
        println!("Total requests: {line}");
    }

    println!("\n✅ Docker tests completed");
    if keep_up {
        println!("Le stack reste actif. Utilisez 'docker compose down' pour l'arrêter.");
    }
    Ok(())
}

async fn health_check(client: &Client, name: &str, url: &str) -> Result<()> {
    print!("  Checking {name}... ");
    let resp = client.get(url).send().await;
    match resp {
        Ok(r) if r.status().is_success() => {
            println!("✓");
            Ok(())
        }
        _ => Err(Error::Http(format!("{name} health check failed"))),
    }
}

fn run_compose_exec(compose: &ComposeCommand, args: &[&str], expect: &str) -> Result<()> {
    let output = Command::new(&compose.program)
        .args(&compose.args)
        .args(args)
        .output()
        .map_err(Error::Io)?;
    if output.status.success() && String::from_utf8_lossy(&output.stdout).contains(expect) {
        println!("  Redis ping... ✓");
        Ok(())
    } else {
        Err(Error::Config("Redis ping failed".to_string()))
    }
}

async fn test_http_status(client: &Client, label: &str, url: &str, status: u16) -> Result<()> {
    print!("  {label}... ");
    let resp = client.get(url).send().await;
    match resp {
        Ok(r) if r.status().as_u16() == status => {
            println!("✓");
            Ok(())
        }
        Ok(r) => Err(Error::Http(format!(
            "{label} attendu {status}, obtenu {}",
            r.status()
        ))),
        Err(e) => Err(Error::Http(format!("{label} erreur: {e}"))),
    }
}

async fn test_metrics(client: &Client) -> Result<()> {
    print!("  Test metrics... ");
    let body = client
        .get("http://localhost:8080/metrics")
        .send()
        .await
        .map_err(|e| Error::Http(format!("metrics request failed: {e}")))?
        .text()
        .await
        .map_err(|e| Error::Http(format!("metrics body failed: {e}")))?;
    if body.contains("requests_total") {
        println!("✓");
        Ok(())
    } else {
        Err(Error::Http(
            "'requests_total' absent des métriques".to_string(),
        ))
    }
}

async fn test_headers(client: &Client) -> Result<()> {
    print!("  Test headers... ");
    let resp = client
        .get("http://localhost:8080/")
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
        .map_err(|e| Error::Http(format!("headers request failed: {e}")))?;
    if resp.headers().contains_key("x-websec-decision") {
        println!("✓");
        Ok(())
    } else {
        Err(Error::Http("Header X-WebSec-Decision manquant".to_string()))
    }
}

async fn test_users(client: &Client) -> Result<()> {
    print!("  Test /api/users... ");
    let body = client
        .get("http://localhost:8080/api/users")
        .send()
        .await
        .map_err(|e| Error::Http(format!("users request failed: {e}")))?
        .text()
        .await
        .map_err(|e| Error::Http(format!("users body failed: {e}")))?;
    if body.contains("Alice") {
        println!("✓");
        Ok(())
    } else {
        Err(Error::Http("Réponse /api/users inattendue".to_string()))
    }
}

async fn test_echo(client: &Client) -> Result<()> {
    print!("  Test POST /api/echo... ");
    let resp = client
        .post("http://localhost:8080/api/echo")
        .json(&serde_json::json!({ "test": "docker" }))
        .send()
        .await
        .map_err(|e| Error::Http(format!("echo request failed: {e}")))?
        .text()
        .await
        .map_err(|e| Error::Http(format!("echo body failed: {e}")))?;
    if resp.contains("docker") {
        println!("✓");
        Ok(())
    } else {
        Err(Error::Http("Réponse echo inattendue".to_string()))
    }
}

fn git_short_sha() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .map_err(Error::Io)?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(Error::Config(
            "Impossible de récupérer le SHA git".to_string(),
        ))
    }
}
