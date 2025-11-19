//! Utility pour identifier les processus utilisant un port spécifique
//!
//! Ce module fournit des fonctions pour diagnostiquer les conflits de port
//! et identifier quel processus utilise déjà un port donné.

use std::process::Command;

/// Informations sur un processus utilisant un port
#[derive(Debug)]
pub struct PortUser {
    /// PID du processus
    pub pid: String,
    /// Nom du processus
    pub name: String,
    /// Commande complète (optionnelle)
    pub command: Option<String>,
}

/// Trouve le processus utilisant un port spécifique
///
/// Utilise `lsof` sur Linux/Mac pour identifier le processus.
/// Retourne None si le port n'est pas utilisé ou si l'information n'est pas disponible.
///
/// # Arguments
///
/// * `port` - Le numéro de port à vérifier
///
/// # Examples
///
/// ```no_run
/// use websec::utils::port_checker::find_port_user;
///
/// if let Some(user) = find_port_user(8080) {
///     println!("Port 8080 utilisé par {} (PID: {})", user.name, user.pid);
/// }
/// ```
pub fn find_port_user(port: u16) -> Option<PortUser> {
    // Essayer avec lsof (Linux/Mac)
    if let Some(user) = try_lsof(port) {
        return Some(user);
    }

    // Essayer avec ss (Linux moderne)
    if let Some(user) = try_ss(port) {
        return Some(user);
    }

    None
}

/// Essaye d'utiliser lsof pour trouver le processus
fn try_lsof(port: u16) -> Option<PortUser> {
    let output = Command::new("lsof")
        .arg("-i")
        .arg(format!(":{port}"))
        .arg("-n")
        .arg("-P")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Chercher la première ligne non-header
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0].to_string();
            let pid = parts[1].to_string();

            // Essayer d'obtenir la commande complète
            let command = get_process_command(&pid);

            return Some(PortUser {
                pid,
                name,
                command,
            });
        }
    }

    None
}

/// Essaye d'utiliser ss pour trouver le processus (Linux)
fn try_ss(port: u16) -> Option<PortUser> {
    let output = Command::new("ss")
        .arg("-tulpn")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Chercher une ligne contenant le port
    for line in stdout.lines() {
        if line.contains(&format!(":{port}")) && line.contains("users:") {
            // Format ss: users:(("nginx",pid=12345,fd=6))
            if let Some(users_part) = line.split("users:").nth(1) {
                if let Some(name_start) = users_part.find("((\"") {
                    let rest = &users_part[name_start + 3..];
                    if let Some(name_end) = rest.find("\",") {
                        let name = rest[..name_end].to_string();

                        // Extraire le PID
                        if let Some(pid_start) = rest.find("pid=") {
                            let pid_part = &rest[pid_start + 4..];
                            if let Some(pid_end) = pid_part.find(',') {
                                let pid = pid_part[..pid_end].to_string();
                                let command = get_process_command(&pid);

                                return Some(PortUser {
                                    pid,
                                    name,
                                    command,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Obtient la ligne de commande complète d'un processus
fn get_process_command(pid: &str) -> Option<String> {
    // Essayer de lire /proc/{pid}/cmdline
    let cmdline_path = format!("/proc/{pid}/cmdline");
    if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
        // Les arguments sont séparés par des null bytes
        let args: Vec<&str> = cmdline.split('\0').filter(|s| !s.is_empty()).collect();
        if !args.is_empty() {
            return Some(args.join(" "));
        }
    }

    // Fallback: essayer ps
    let output = Command::new("ps")
        .arg("-p")
        .arg(pid)
        .arg("-o")
        .arg("args=")
        .output()
        .ok()?;

    if output.status.success() {
        let command = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_string();
        if !command.is_empty() {
            return Some(command);
        }
    }

    None
}

/// Formate un message d'erreur informatif pour un conflit de port
///
/// # Arguments
///
/// * `port` - Le port en conflit
/// * `addr` - L'adresse complète qui a échoué (pour le contexte)
///
/// # Examples
///
/// ```no_run
/// use websec::utils::port_checker::format_port_conflict_error;
///
/// let error_msg = format_port_conflict_error(8080, "0.0.0.0:8080");
/// eprintln!("{error_msg}");
/// ```
pub fn format_port_conflict_error(port: u16, addr: &str) -> String {
    let mut message = format!("❌ Port {port} is already in use (bind to {addr} failed)\n");

    if let Some(user) = find_port_user(port) {
        message.push_str(&format!("\n🔍 Process using port {port}:\n"));
        message.push_str(&format!("   PID:  {}\n", user.pid));
        message.push_str(&format!("   Name: {}\n", user.name));

        if let Some(cmd) = user.command {
            // Tronquer la commande si trop longue
            let display_cmd = if cmd.len() > 80 {
                format!("{}...", &cmd[..77])
            } else {
                cmd
            };
            message.push_str(&format!("   Command: {display_cmd}\n"));
        }

        message.push_str(&format!("\n💡 To fix this issue:\n"));
        message.push_str(&format!("   • Stop the process: sudo kill {}\n", user.pid));
        message.push_str(&format!("   • Or choose a different port in config/websec.toml\n"));
    } else {
        message.push_str(&format!("\n💡 To find what's using port {port}, try:\n"));
        message.push_str(&format!("   • Linux/Mac: sudo lsof -i :{port}\n"));
        message.push_str(&format!("   • Linux: sudo ss -tulpn | grep :{port}\n"));
        message.push_str(&format!("   • Or choose a different port in config/websec.toml\n"));
    }

    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_message_without_process() {
        let msg = format_port_conflict_error(8080, "0.0.0.0:8080");
        assert!(msg.contains("Port 8080 is already in use"));
        assert!(msg.contains("lsof"));
    }
}
