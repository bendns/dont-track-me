//! SSH key hygiene and configuration security audit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};
use dtm_core::platform::home_dir;

/// Seconds in a year (approximate).
const SECONDS_PER_YEAR: f64 = 365.25 * 24.0 * 3600.0;

/// Key age thresholds in years.
const KEY_AGE_HIGH_YEARS: f64 = 5.0;
const KEY_AGE_MEDIUM_YEARS: f64 = 2.0;

/// OpenSSH key format magic bytes.
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\x00";

// ---------------------------------------------------------------------------
// Algorithm detection
// ---------------------------------------------------------------------------

/// Detected key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAlgorithm {
    Dsa,
    Rsa,
    Ecdsa,
    Ed25519,
    Unknown,
}

impl KeyAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dsa => "dsa",
            Self::Rsa => "rsa",
            Self::Ecdsa => "ecdsa",
            Self::Ed25519 => "ed25519",
            Self::Unknown => "unknown",
        }
    }
}

/// RSA key strength estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsaStrength {
    /// <= 1024 bit
    Weak,
    /// 2048 bit
    Medium,
    /// >= 4096 bit
    Strong,
}

/// Detect the SSH key algorithm from a private key file's contents.
fn detect_key_algorithm(private_key_path: &Path, ssh_dir: &Path) -> KeyAlgorithm {
    let content = match std::fs::read_to_string(private_key_path) {
        Ok(c) => c,
        Err(_) => return KeyAlgorithm::Unknown,
    };

    let first_line = match content.trim().lines().next() {
        Some(l) => l,
        None => return KeyAlgorithm::Unknown,
    };

    if first_line.contains("BEGIN DSA PRIVATE KEY") {
        return KeyAlgorithm::Dsa;
    }
    if first_line.contains("BEGIN RSA PRIVATE KEY") {
        return KeyAlgorithm::Rsa;
    }
    if first_line.contains("BEGIN EC PRIVATE KEY") {
        return KeyAlgorithm::Ecdsa;
    }

    if first_line.contains("BEGIN OPENSSH PRIVATE KEY") {
        // New OpenSSH format -- check the matching .pub file first.
        let pub_name = format!(
            "{}.pub",
            private_key_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );
        let pub_path = ssh_dir.join(pub_name);
        if pub_path.exists() {
            if let Ok(pub_content) = std::fs::read_to_string(&pub_path) {
                if pub_content.contains("ssh-ed25519") {
                    return KeyAlgorithm::Ed25519;
                }
                if pub_content.contains("ssh-rsa") {
                    return KeyAlgorithm::Rsa;
                }
                if pub_content.contains("ecdsa-sha2") {
                    return KeyAlgorithm::Ecdsa;
                }
                if pub_content.contains("ssh-dss") {
                    return KeyAlgorithm::Dsa;
                }
            }
        }

        // Fallback: file size heuristic. Ed25519 private keys are small (~400-500 bytes).
        let file_size = match std::fs::metadata(private_key_path) {
            Ok(m) => m.len(),
            Err(_) => return KeyAlgorithm::Unknown,
        };

        if file_size < 800 {
            return KeyAlgorithm::Ed25519;
        }

        // Larger new-format keys are likely RSA.
        return KeyAlgorithm::Rsa;
    }

    KeyAlgorithm::Unknown
}

// ---------------------------------------------------------------------------
// RSA strength estimation
// ---------------------------------------------------------------------------

/// Estimate RSA key size from private key file size.
///
/// PEM-encoded RSA private key sizes (approximate):
///   1024-bit: ~900 bytes
///   2048-bit: ~1700 bytes
///   4096-bit: ~3200 bytes
fn estimate_rsa_strength(private_key_path: &Path) -> RsaStrength {
    let file_size = match std::fs::metadata(private_key_path) {
        Ok(m) => m.len(),
        Err(_) => return RsaStrength::Medium,
    };

    if file_size < 1100 {
        RsaStrength::Weak
    } else if file_size < 2500 {
        RsaStrength::Medium
    } else {
        RsaStrength::Strong
    }
}

// ---------------------------------------------------------------------------
// Encryption check
// ---------------------------------------------------------------------------

/// Check whether a private key file is passphrase-protected.
fn is_key_encrypted(private_key_path: &Path) -> bool {
    let content = match std::fs::read_to_string(private_key_path) {
        Ok(c) => c,
        Err(_) => return true, // Conservative: assume encrypted if unreadable.
    };

    // PEM-format encrypted keys contain these headers.
    if content.contains("ENCRYPTED") {
        return true;
    }

    // New OpenSSH format: base64-decode and inspect the cipher name field.
    if content.contains("BEGIN OPENSSH PRIVATE KEY") {
        let b64_data: String = content
            .lines()
            .skip_while(|l| !l.contains("BEGIN OPENSSH PRIVATE KEY"))
            .skip(1)
            .take_while(|l| !l.contains("END OPENSSH PRIVATE KEY"))
            .flat_map(|l| l.trim().chars())
            .collect();

        if let Ok(raw) = BASE64.decode(&b64_data) {
            if raw.starts_with(OPENSSH_MAGIC) {
                let offset = OPENSSH_MAGIC.len();
                if raw.len() > offset + 4 {
                    let cipher_len = u32::from_be_bytes([
                        raw[offset],
                        raw[offset + 1],
                        raw[offset + 2],
                        raw[offset + 3],
                    ]) as usize;
                    if raw.len() > offset + 4 + cipher_len {
                        let cipher_name =
                            String::from_utf8_lossy(&raw[offset + 4..offset + 4 + cipher_len]);
                        return cipher_name != "none";
                    }
                }
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Key age
// ---------------------------------------------------------------------------

/// Get the age of a key file in years based on file modification time.
fn get_key_age_years(path: &Path) -> f64 {
    let mtime = match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return 0.0,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let file_time = mtime
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    (now - file_time) / SECONDS_PER_YEAR
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return `true` if a file's first line looks like a PEM private key header.
fn looks_like_private_key(path: &Path) -> bool {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let first_line = match content.lines().next() {
        Some(l) => l.trim(),
        None => return false,
    };
    first_line.contains("BEGIN") && first_line.contains("PRIVATE KEY")
}

/// Collect private key paths from the SSH directory.
fn discover_private_keys(ssh_dir: &Path) -> (Vec<PathBuf>, Vec<Finding>) {
    let mut keys = Vec::new();
    let mut findings = Vec::new();

    let entries = match std::fs::read_dir(ssh_dir) {
        Ok(e) => e,
        Err(_) => {
            findings.push(Finding {
                title: "Cannot read SSH directory".into(),
                description: "Permission denied when reading ~/.ssh directory.".into(),
                threat_level: ThreatLevel::Medium,
                remediation: "Check permissions on your ~/.ssh directory (should be 700).".into(),
            });
            return (keys, findings);
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        // Skip .pub files.
        if name.ends_with(".pub") {
            continue;
        }
        if name.starts_with("id_") || looks_like_private_key(&path) {
            keys.push(path);
        }
    }

    (keys, findings)
}

// ---------------------------------------------------------------------------
// authorized_keys
// ---------------------------------------------------------------------------

/// Audit the `authorized_keys` file for security issues.
fn check_authorized_keys(ssh_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let auth_keys_path = ssh_dir.join("authorized_keys");

    if !auth_keys_path.exists() {
        return findings;
    }

    // Check permissions (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&auth_keys_path) {
            let mode = meta.permissions().mode();
            // Group-writable (0o020) or others-writable (0o002).
            if mode & 0o022 != 0 {
                findings.push(Finding {
                    title: "authorized_keys has unsafe permissions".into(),
                    description: "Your authorized_keys file is writable by group or others. \
                        An attacker with local access could add their own public key \
                        to gain SSH access to your account."
                        .into(),
                    threat_level: ThreatLevel::High,
                    remediation: "Run: chmod 600 ~/.ssh/authorized_keys".into(),
                });
            }
        }
    }

    // Count entries.
    if let Ok(content) = std::fs::read_to_string(&auth_keys_path) {
        let entry_count = content
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
            .count();

        if entry_count > 0 {
            findings.push(Finding {
                title: format!("authorized_keys contains {entry_count} key(s)"),
                description: format!(
                    "Found {entry_count} authorized public key(s). \
                     Each entry grants SSH access to your account. \
                     Review regularly to ensure no unauthorized keys are present."
                ),
                threat_level: ThreatLevel::Info,
                remediation: "Periodically review authorized_keys and remove unused entries."
                    .into(),
            });
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// SSH config
// ---------------------------------------------------------------------------

/// Parse `~/.ssh/config` for dangerous settings.
fn check_ssh_config(ssh_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let config_path = ssh_dir.join("config");

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let lines: Vec<String> = content.lines().map(|l| l.to_lowercase()).collect();

    let mut found_forward_agent = false;
    let mut found_strict_host = false;
    let mut found_password_auth = false;

    for line in &lines {
        let stripped = line.trim();
        if stripped.starts_with('#') {
            continue;
        }

        if !found_forward_agent && stripped.contains("forwardagent") && stripped.contains("yes") {
            findings.push(Finding {
                title: "Agent forwarding enabled in SSH config".into(),
                description: "ForwardAgent yes is set in your SSH config. This allows any \
                    compromised server you connect to to use your local SSH agent \
                    and authenticate as you to other servers. This is a significant \
                    security risk unless you fully trust every server in the chain."
                    .into(),
                threat_level: ThreatLevel::High,
                remediation: "Remove 'ForwardAgent yes' from ~/.ssh/config. \
                    Use ProxyJump (-J) instead of agent forwarding for jump hosts."
                    .into(),
            });
            found_forward_agent = true;
        }

        if !found_strict_host
            && stripped.contains("stricthostkeychecking")
            && stripped.contains("no")
        {
            findings.push(Finding {
                title: "Strict host key checking disabled".into(),
                description: "StrictHostKeyChecking no is set in your SSH config. This disables \
                    verification of server identity, making you vulnerable to \
                    man-in-the-middle attacks. An attacker could impersonate any server \
                    you connect to."
                    .into(),
                threat_level: ThreatLevel::High,
                remediation: "Remove 'StrictHostKeyChecking no' from ~/.ssh/config, \
                    or set it to 'ask' for interactive confirmation of new hosts."
                    .into(),
            });
            found_strict_host = true;
        }

        if !found_password_auth
            && stripped.contains("passwordauthentication")
            && stripped.contains("yes")
        {
            findings.push(Finding {
                title: "Password authentication enabled".into(),
                description: "PasswordAuthentication yes is set in your SSH config. \
                    Password-based authentication is weaker than key-based \
                    authentication and susceptible to brute force attacks."
                    .into(),
                threat_level: ThreatLevel::Medium,
                remediation: "Use key-based authentication and set \
                    'PasswordAuthentication no' in SSH config."
                    .into(),
            });
            found_password_auth = true;
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// known_hosts
// ---------------------------------------------------------------------------

/// Audit `known_hosts` for privacy fingerprinting risks.
///
/// Returns `(findings, unhashed_count)`.
fn check_known_hosts(ssh_dir: &Path) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let known_hosts_path = ssh_dir.join("known_hosts");

    let content = match std::fs::read_to_string(&known_hosts_path) {
        Ok(c) => c,
        Err(_) => return (findings, 0),
    };

    let entries: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let entry_count = entries.len();
    if entry_count == 0 {
        return (findings, 0);
    }

    let unhashed: Vec<&&str> = entries.iter().filter(|e| !e.starts_with("|1|")).collect();
    let hashed_count = entry_count - unhashed.len();
    let unhashed_count = unhashed.len();

    if unhashed_count > 0 {
        findings.push(Finding {
            title: format!("known_hosts contains {unhashed_count} unhashed entries"),
            description: format!(
                "Your known_hosts file has {unhashed_count} entries with \
                 plaintext hostnames. Anyone who gains access to this file can see \
                 every server you have connected to via SSH, revealing your server \
                 infrastructure and travel patterns."
            ),
            threat_level: ThreatLevel::High,
            remediation: "Hash your known_hosts file: ssh-keygen -H\n\
                This replaces plaintext hostnames with cryptographic hashes."
                .into(),
        });
    } else if hashed_count > 0 {
        findings.push(Finding {
            title: format!("known_hosts is properly hashed ({hashed_count} entries)"),
            description: "Your known_hosts file uses hashed hostnames, which prevents \
                casual enumeration of servers you connect to."
                .into(),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed. Consider enabling HashKnownHosts in SSH config.".into(),
        });
    }

    if entry_count > 50 {
        findings.push(Finding {
            title: format!("Large known_hosts file ({entry_count} entries)"),
            description: format!(
                "Your known_hosts file contains {entry_count} entries. A large file \
                 increases fingerprinting surface even when hashed, as the count alone \
                 reveals connection patterns."
            ),
            threat_level: ThreatLevel::Medium,
            remediation: "Periodically prune old entries from known_hosts.".into(),
        });
    }

    (findings, unhashed_count)
}

// ---------------------------------------------------------------------------
// Main audit entry point
// ---------------------------------------------------------------------------

/// Audit SSH configuration for privacy and security issues.
pub async fn audit_ssh(opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut score: i32 = 100;

    let ssh_dir = home_dir()
        .unwrap_or_else(|| PathBuf::from("/"))
        .join(".ssh");
    let mut raw_data = HashMap::new();
    raw_data.insert("ssh_dir_exists".into(), serde_json::json!(ssh_dir.exists()));
    raw_data.insert("keys_found".into(), serde_json::json!([]));
    raw_data.insert("issues".into(), serde_json::json!([]));

    // Allow overriding the path for testing.
    let ssh_dir = opts.path.as_deref().unwrap_or(&ssh_dir);

    if !ssh_dir.exists() {
        findings.push(Finding {
            title: "No SSH directory found".into(),
            description: "No ~/.ssh directory was found. Either SSH is not configured \
                on this system or the directory is in a non-standard location."
                .into(),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed if you don't use SSH.".into(),
        });
        return Ok(AuditResult {
            module_name: "ssh".into(),
            score: 100,
            findings,
            raw_data,
        });
    }

    // Discover private keys.
    let (private_keys, discover_findings) = discover_private_keys(ssh_dir);
    findings.extend(discover_findings);

    let mut keys_found: Vec<serde_json::Value> = Vec::new();
    let mut issues: Vec<String> = Vec::new();

    // Audit each private key.
    for key_path in &private_keys {
        let key_name = key_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let algorithm = detect_key_algorithm(key_path, ssh_dir);

        keys_found.push(serde_json::json!({
            "name": key_name,
            "algorithm": algorithm.as_str(),
        }));

        // -- Algorithm strength --
        match algorithm {
            KeyAlgorithm::Dsa => {
                findings.push(Finding {
                    title: format!("DSA key detected: {key_name}"),
                    description: "DSA keys are cryptographically broken and have been deprecated \
                        since OpenSSH 7.0. They use a fixed 1024-bit key size which \
                        is insufficient for modern security."
                        .into(),
                    threat_level: ThreatLevel::Critical,
                    remediation: format!(
                        "Replace {key_name} with an Ed25519 key: \
                         ssh-keygen -t ed25519 -C 'your_email@example.com'"
                    ),
                });
                score -= 25;
                issues.push(format!("dsa_key:{key_name}"));
            }
            KeyAlgorithm::Rsa => {
                let strength = estimate_rsa_strength(key_path);
                match strength {
                    RsaStrength::Weak => {
                        findings.push(Finding {
                            title: format!("Weak RSA key detected: {key_name} (likely <=1024 bit)"),
                            description:
                                "This RSA key appears to be 1024 bits or smaller, which is \
                                considered cryptographically weak and vulnerable to factoring \
                                attacks with modern hardware."
                                    .into(),
                            threat_level: ThreatLevel::Critical,
                            remediation: format!(
                                "Replace {key_name} with an Ed25519 key: \
                                 ssh-keygen -t ed25519 -C 'your_email@example.com'"
                            ),
                        });
                        score -= 25;
                        issues.push(format!("weak_rsa:{key_name}"));
                    }
                    RsaStrength::Medium => {
                        findings.push(Finding {
                            title: format!("RSA 2048-bit key detected: {key_name}"),
                            description:
                                "This RSA key is likely 2048 bits. While currently acceptable, \
                                NIST recommends transitioning to stronger keys. RSA 2048 may \
                                become vulnerable to quantum computing advances."
                                    .into(),
                            threat_level: ThreatLevel::Medium,
                            remediation: "Consider upgrading to Ed25519: \
                                ssh-keygen -t ed25519 -C 'your_email@example.com'"
                                .into(),
                        });
                        score -= 15;
                        issues.push(format!("medium_rsa:{key_name}"));
                    }
                    RsaStrength::Strong => {
                        findings.push(Finding {
                            title: format!("RSA 4096-bit key detected: {key_name}"),
                            description:
                                "Strong RSA key detected. While secure for now, Ed25519 offers \
                                better performance and smaller key sizes with equivalent security."
                                    .into(),
                            threat_level: ThreatLevel::Info,
                            remediation: "Consider migrating to Ed25519 for improved performance."
                                .into(),
                        });
                    }
                }
            }
            KeyAlgorithm::Ecdsa => {
                findings.push(Finding {
                    title: format!("ECDSA key detected: {key_name}"),
                    description:
                        "ECDSA keys rely on NIST curves which some researchers distrust due \
                        to potential NSA influence in the curve parameters. ECDSA is also \
                        vulnerable to quantum computing attacks."
                            .into(),
                    threat_level: ThreatLevel::Medium,
                    remediation:
                        "Consider switching to Ed25519 which uses the independently-designed \
                        Curve25519: ssh-keygen -t ed25519"
                            .into(),
                });
                issues.push(format!("ecdsa_key:{key_name}"));
            }
            KeyAlgorithm::Ed25519 => {
                findings.push(Finding {
                    title: format!("Ed25519 key detected: {key_name}"),
                    description: "Ed25519 is the current best practice for SSH keys. It offers \
                        strong security, small key sizes, and fast operations."
                        .into(),
                    threat_level: ThreatLevel::Info,
                    remediation: "No action needed. This is the recommended key type.".into(),
                });
            }
            KeyAlgorithm::Unknown => {}
        }

        // -- Passphrase protection --
        if !is_key_encrypted(key_path) {
            findings.push(Finding {
                title: format!("Unencrypted private key: {key_name}"),
                description: "This private key is not protected by a passphrase. If your \
                    device is stolen or compromised, the attacker gains immediate \
                    access to all servers this key authenticates to."
                    .into(),
                threat_level: ThreatLevel::High,
                remediation: format!(
                    "Add a passphrase: ssh-keygen -p -f ~/.ssh/{key_name}\n\
                     Use ssh-agent to avoid retyping the passphrase."
                ),
            });
            score -= 15;
            issues.push(format!("unencrypted:{key_name}"));
        }

        // -- Key age --
        let age_years = get_key_age_years(key_path);
        if age_years > KEY_AGE_HIGH_YEARS {
            findings.push(Finding {
                title: format!("Very old SSH key: {key_name} ({age_years:.1} years)"),
                description: format!(
                    "This key is approximately {age_years:.1} years old. \
                     NIST SP 800-57 recommends rotating cryptographic keys regularly. \
                     Old keys may use outdated algorithms or have been exposed \
                     through forgotten backups."
                ),
                threat_level: ThreatLevel::High,
                remediation: "Generate a new key and rotate it across all authorized servers: \
                    ssh-keygen -t ed25519 -C 'your_email@example.com'"
                    .into(),
            });
            score -= 10;
            issues.push(format!("old_key_5y:{key_name}"));
        } else if age_years > KEY_AGE_MEDIUM_YEARS {
            findings.push(Finding {
                title: format!("Aging SSH key: {key_name} ({age_years:.1} years)"),
                description: format!(
                    "This key is approximately {age_years:.1} years old. \
                     Consider rotating keys every 1-2 years as a security best practice."
                ),
                threat_level: ThreatLevel::Medium,
                remediation: "Plan to rotate this key in the near future.".into(),
            });
            score -= 5;
            issues.push(format!("old_key_2y:{key_name}"));
        }
    }

    // -- authorized_keys --
    let auth_findings = check_authorized_keys(ssh_dir);
    for f in &auth_findings {
        if f.threat_level == ThreatLevel::High {
            score -= 15;
            issues.push("authorized_keys_unsafe_perms".into());
        }
    }
    findings.extend(auth_findings);

    // -- SSH config --
    let config_findings = check_ssh_config(ssh_dir);
    for f in &config_findings {
        if f.title.contains("Agent forwarding") {
            score -= 15;
            issues.push("forward_agent".into());
        } else if f.title.contains("host key checking") {
            score -= 15;
            issues.push("strict_host_key_checking_disabled".into());
        } else if f.title.contains("Password authentication") {
            score -= 5;
            issues.push("password_auth".into());
        }
    }
    findings.extend(config_findings);

    // -- known_hosts --
    let (known_hosts_findings, unhashed_count) = check_known_hosts(ssh_dir);
    findings.extend(known_hosts_findings);
    if unhashed_count > 5 {
        score -= 10;
        issues.push("unhashed_known_hosts".into());
    }

    // Clamp score to 0..=100.
    let score = score.clamp(0, 100) as u32;

    raw_data.insert("keys_found".into(), serde_json::json!(keys_found));
    raw_data.insert("issues".into(), serde_json::json!(issues));

    Ok(AuditResult {
        module_name: "ssh".into(),
        score,
        findings,
        raw_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn ssh_opts(path: PathBuf) -> AuditOpts {
        AuditOpts {
            path: Some(path),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn unhashed_known_hosts_produces_finding() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();

        // Write a known_hosts file with unhashed entries.
        fs::write(
            ssh_dir.join("known_hosts"),
            "github.com ssh-rsa AAAAB3NzaC1yc2EAAAA...\n\
             gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...\n\
             192.168.1.1 ssh-rsa AAAAB3NzaC1yc2EAAAA...\n",
        )
        .unwrap();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        let kh_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.title.contains("unhashed"))
            .collect();
        assert!(
            !kh_findings.is_empty(),
            "Expected unhashed known_hosts finding, got: {:#?}",
            result.findings
        );
        assert!(kh_findings[0].title.contains("3"));
        assert_eq!(kh_findings[0].threat_level, ThreatLevel::High);
    }

    #[tokio::test]
    async fn forward_agent_yes_produces_finding() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();

        fs::write(
            ssh_dir.join("config"),
            "Host *\n    ForwardAgent yes\n    User admin\n",
        )
        .unwrap();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        let fwd_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.title.contains("Agent forwarding"))
            .collect();
        assert!(
            !fwd_findings.is_empty(),
            "Expected ForwardAgent finding, got: {:#?}",
            result.findings
        );
        assert_eq!(fwd_findings[0].threat_level, ThreatLevel::High);
    }

    #[tokio::test]
    async fn empty_ssh_dir_no_critical_findings() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        let critical_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.threat_level == ThreatLevel::Critical)
            .collect();
        assert!(
            critical_findings.is_empty(),
            "Expected no critical findings in empty SSH dir, got: {critical_findings:#?}"
        );
    }

    #[test]
    fn is_key_encrypted_detects_unencrypted_pem() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("id_rsa");
        fs::write(
            &key_path,
            "-----BEGIN RSA PRIVATE KEY-----\n\
             MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF1Z...\n\
             -----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();

        assert!(
            !is_key_encrypted(&key_path),
            "Unencrypted PEM key should return false"
        );
    }

    #[test]
    fn is_key_encrypted_detects_encrypted_pem() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("id_rsa_enc");
        fs::write(
            &key_path,
            "-----BEGIN RSA PRIVATE KEY-----\n\
             Proc-Type: 4,ENCRYPTED\n\
             DEK-Info: AES-128-CBC,2AF...\n\
             \n\
             MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF1Z...\n\
             -----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();

        assert!(
            is_key_encrypted(&key_path),
            "Encrypted PEM key should return true"
        );
    }

    #[test]
    fn detect_key_algorithm_pem_rsa() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("id_rsa");
        fs::write(
            &key_path,
            "-----BEGIN RSA PRIVATE KEY-----\n\
             MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF1Z...\n\
             -----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();

        assert_eq!(
            detect_key_algorithm(&key_path, dir.path()),
            KeyAlgorithm::Rsa
        );
    }

    #[test]
    fn detect_key_algorithm_pem_dsa() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("id_dsa");
        fs::write(
            &key_path,
            "-----BEGIN DSA PRIVATE KEY-----\n\
             MIIBuwIBAAKBgQD...\n\
             -----END DSA PRIVATE KEY-----\n",
        )
        .unwrap();

        assert_eq!(
            detect_key_algorithm(&key_path, dir.path()),
            KeyAlgorithm::Dsa
        );
    }

    #[test]
    fn detect_key_algorithm_pem_ec() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("id_ecdsa");
        fs::write(
            &key_path,
            "-----BEGIN EC PRIVATE KEY-----\n\
             MHQCAQEEIBkg...\n\
             -----END EC PRIVATE KEY-----\n",
        )
        .unwrap();

        assert_eq!(
            detect_key_algorithm(&key_path, dir.path()),
            KeyAlgorithm::Ecdsa
        );
    }

    #[test]
    fn detect_key_algorithm_openssh_with_pub_file() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        // Write a minimal new-format private key header.
        fs::write(
            &key_path,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA...\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        // Matching .pub file tells us the algorithm.
        fs::write(
            dir.path().join("id_ed25519.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@host\n",
        )
        .unwrap();

        assert_eq!(
            detect_key_algorithm(&key_path, dir.path()),
            KeyAlgorithm::Ed25519
        );
    }

    #[tokio::test]
    async fn strict_host_key_checking_no_produces_finding() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();

        fs::write(
            ssh_dir.join("config"),
            "Host *\n    StrictHostKeyChecking no\n",
        )
        .unwrap();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        let strict_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.title.contains("host key checking"))
            .collect();
        assert!(
            !strict_findings.is_empty(),
            "Expected StrictHostKeyChecking finding"
        );
    }

    #[tokio::test]
    async fn unencrypted_key_produces_finding() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();
        let key_path = ssh_dir.join("id_rsa");
        fs::write(
            &key_path,
            "-----BEGIN RSA PRIVATE KEY-----\n\
             MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF1Z...\n\
             -----END RSA PRIVATE KEY-----\n",
        )
        .unwrap();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        let enc_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.title.contains("Unencrypted private key"))
            .collect();
        assert!(
            !enc_findings.is_empty(),
            "Expected unencrypted key finding, got: {:#?}",
            result.findings
        );
    }

    #[tokio::test]
    async fn test_dsa_key_produces_finding() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();
        let key_path = ssh_dir.join("id_dsa");
        fs::write(
            &key_path,
            "-----BEGIN DSA PRIVATE KEY-----\n\
             MIIBuwIBAAKBgQD...\n\
             -----END DSA PRIVATE KEY-----\n",
        )
        .unwrap();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        let dsa_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.title.contains("DSA key detected"))
            .collect();
        assert!(
            !dsa_findings.is_empty(),
            "Expected DSA key finding, got: {:#?}",
            result.findings
        );
        assert_eq!(dsa_findings[0].threat_level, ThreatLevel::Critical);
    }

    #[tokio::test]
    async fn test_rsa_key_small_size() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();
        let key_path = ssh_dir.join("id_rsa");
        // Write a very short RSA key (< 1100 bytes) to trigger Weak detection
        let short_content = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
            "A".repeat(500)
        );
        fs::write(&key_path, &short_content).unwrap();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        let weak_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.title.contains("Weak RSA key"))
            .collect();
        assert!(
            !weak_findings.is_empty(),
            "Expected weak RSA key finding, got: {:#?}",
            result.findings
        );
        assert_eq!(weak_findings[0].threat_level, ThreatLevel::Critical);
    }

    #[tokio::test]
    async fn test_key_age_old() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();
        let key_path = ssh_dir.join("id_ed25519");
        fs::write(
            &key_path,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA...\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        // Write matching .pub file
        fs::write(
            ssh_dir.join("id_ed25519.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@host\n",
        )
        .unwrap();

        // Set the file modification time to 6 years ago
        let six_years_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(6 * 365 * 24 * 3600);
        filetime::set_file_mtime(
            &key_path,
            filetime::FileTime::from_system_time(six_years_ago),
        )
        .unwrap();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        let age_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.title.contains("Very old SSH key"))
            .collect();
        assert!(
            !age_findings.is_empty(),
            "Expected old key finding, got: {:#?}",
            result.findings
        );
        assert_eq!(age_findings[0].threat_level, ThreatLevel::High);
    }

    #[tokio::test]
    async fn test_clean_ssh_dir_high_score() {
        let dir = tempdir().unwrap();
        let ssh_dir = dir.path();

        // Write a well-configured Ed25519 key with encryption
        let key_path = ssh_dir.join("id_ed25519");
        fs::write(
            &key_path,
            "-----BEGIN OPENSSH PRIVATE KEY-----\n\
             ENCRYPTED\n\
             b3BlbnNzaC1rZXktdjEA...\n\
             -----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::write(
            ssh_dir.join("id_ed25519.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... user@host\n",
        )
        .unwrap();

        // Write a properly hashed known_hosts file
        fs::write(
            ssh_dir.join("known_hosts"),
            "|1|abcdef123456|ghijkl789012 ssh-ed25519 AAAAC3...\n",
        )
        .unwrap();

        // Write a clean SSH config
        fs::write(
            ssh_dir.join("config"),
            "Host *\n    IdentityFile ~/.ssh/id_ed25519\n",
        )
        .unwrap();

        let result = audit_ssh(&ssh_opts(ssh_dir.to_path_buf())).await.unwrap();

        // A well-configured SSH dir should have a high score
        assert!(
            result.score >= 70,
            "Expected high score for clean SSH dir, got: {}",
            result.score
        );

        // Should have no Critical findings
        let critical: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.threat_level == ThreatLevel::Critical)
            .collect();
        assert!(
            critical.is_empty(),
            "Expected no critical findings, got: {critical:#?}"
        );
    }
}
