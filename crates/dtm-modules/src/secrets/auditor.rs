use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;

use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};
use dtm_core::platform::home_dir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_LINES: usize = 1000;

static ENV_FILE_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
];

static HISTORY_FILES: &[&str] = &[".bash_history", ".zsh_history"];

static CONFIG_FILES: &[&str] = &[".npmrc", ".pypirc", ".docker/config.json", ".netrc"];

// ---------------------------------------------------------------------------
// Compiled regex patterns (LazyLock — compiled once, never freed)
// ---------------------------------------------------------------------------

static ENV_SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(
            r"(?i)(?:^|[\s])(\w*(?:KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|AUTH)\w*)\s*=\s*\S+",
        )
        .unwrap(),
        Regex::new(r"(?i)(?:^|[\s])(\w*(?:API_KEY|ACCESS_KEY|PRIVATE_KEY)\w*)\s*=\s*\S+").unwrap(),
    ]
});

static HISTORY_SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)\bexport\s+\w*(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH)\w*=").unwrap(),
        Regex::new(r#"(?i)\bcurl\b.*-[Hh]\s+['"]?Authorization:"#).unwrap(),
        Regex::new(r#"(?i)\bcurl\b.*-[Hh]\s+['"]?X-API-Key:"#).unwrap(),
        Regex::new(r"(?i)\bmysql\b.*\s-p\S+").unwrap(),
        Regex::new(r"(?i)\bpsql\b.*password=\S+").unwrap(),
        Regex::new(r"(?i)\bHTTP_PROXY\s*=\s*https?://\w+:\w+@").unwrap(),
    ]
});

static GIT_CREDENTIAL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"url\s*=\s*https?://[^/\s]+:[^/\s]+@").unwrap());

static AWS_KEY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)aws_access_key_id\s*=\s*\S+").unwrap());

static AWS_SECRET_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)aws_secret_access_key\s*=\s*\S+").unwrap());

static CONFIG_SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)(?:_authToken|//registry\.\S+/:_auth)\s*=\s*\S+").unwrap(),
        Regex::new(r"(?i)password\s*=\s*\S+").unwrap(),
        Regex::new(r"(?i)token\s*=\s*\S+").unwrap(),
        Regex::new(r#"(?i)"auth"\s*:\s*"[^"]+""#).unwrap(),
        Regex::new(r"(?i)login\s+\S+\s+password\s+\S+").unwrap(),
    ]
});

// ---------------------------------------------------------------------------
// File reading helper
// ---------------------------------------------------------------------------

/// Read up to `max_lines` from a file, returning an empty vec on any error.
fn read_lines(path: &Path, max_lines: usize) -> Vec<String> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let reader = BufReader::new(file);
    reader
        .lines()
        .take(max_lines)
        .filter_map(|l| l.ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Scanners
// ---------------------------------------------------------------------------

fn scan_env_files(scan_dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for &env_name in ENV_FILE_NAMES {
        let env_path = scan_dir.join(env_name);
        if !env_path.is_file() {
            continue;
        }

        let lines = read_lines(&env_path, MAX_LINES);
        let mut secret_keys: Vec<String> = Vec::new();

        for line in &lines {
            for pattern in ENV_SECRET_PATTERNS.iter() {
                if let Some(caps) = pattern.captures(line) {
                    if let Some(key) = caps.get(1) {
                        let key_name = key.as_str().to_string();
                        if !secret_keys.contains(&key_name) {
                            secret_keys.push(key_name);
                        }
                    }
                }
            }
        }

        if !secret_keys.is_empty() {
            let count = secret_keys.len();
            findings.push(Finding {
                title: format!("Secrets found in {env_name}"),
                description: format!(
                    "Found {count} potential secret(s) in {path}. \
                     Variable names containing sensitive keywords were detected. \
                     These files are often accidentally committed to version control.",
                    path = env_path.display(),
                ),
                threat_level: ThreatLevel::High,
                remediation: format!(
                    "Add {env_name} to your .gitignore file. \
                     Use a secrets manager or encrypted vault for production credentials. \
                     Rotate any secrets that may have been committed to git history."
                ),
            });
        }
    }

    findings
}

fn scan_git_config(scan_dir: &Path) -> Vec<Finding> {
    let git_config = scan_dir.join(".git").join("config");
    if !git_config.is_file() {
        return Vec::new();
    }

    let lines = read_lines(&git_config, MAX_LINES);
    for line in &lines {
        if GIT_CREDENTIAL_PATTERN.is_match(line) {
            return vec![Finding {
                title: "Plaintext credentials in .git/config".to_string(),
                description: format!(
                    "Found embedded credentials in a git remote URL in {path}. \
                     Credentials in remote URLs are stored in plain text and visible \
                     to anyone with access to the repository directory.",
                    path = git_config.display(),
                ),
                threat_level: ThreatLevel::Critical,
                remediation:
                    "Remove credentials from the remote URL. Use a credential helper instead:\n  \
                     git config --global credential.helper osxkeychain  (macOS)\n  \
                     git config --global credential.helper store        (Linux, less secure)\n  \
                     git config --global credential.helper cache        (temporary in-memory)"
                        .to_string(),
            }];
        }
    }

    Vec::new()
}

fn scan_shell_history(home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for &hist_name in HISTORY_FILES {
        let hist_path = home.join(hist_name);
        if !hist_path.is_file() {
            continue;
        }

        let lines = read_lines(&hist_path, MAX_LINES);
        let mut matches_found: u32 = 0;

        for line in &lines {
            for pattern in HISTORY_SECRET_PATTERNS.iter() {
                if pattern.is_match(line) {
                    matches_found += 1;
                    break; // one match per line is enough
                }
            }
        }

        if matches_found > 0 {
            findings.push(Finding {
                title: format!("Secrets found in shell history ({hist_name})"),
                description: format!(
                    "Found {matches_found} command(s) in ~/{hist_name} that appear \
                     to contain secrets (API keys, passwords, tokens). Shell history \
                     files are readable by any process running as your user."
                ),
                threat_level: ThreatLevel::Medium,
                remediation: format!(
                    "Clear sensitive entries from your shell history:\n  \
                     Edit ~/{hist_name} manually and remove lines containing secrets.\n\
                     Prevent future leaks:\n  \
                     For bash: prefix sensitive commands with a space \
                     (requires HISTCONTROL=ignorespace)\n  \
                     For zsh: use setopt HIST_IGNORE_SPACE and prefix commands with a space"
                ),
            });
        }
    }

    findings
}

fn scan_ssh_keys(home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ssh_dir = home.join(".ssh");

    if !ssh_dir.is_dir() {
        return findings;
    }

    let entries = match std::fs::read_dir(&ssh_dir) {
        Ok(e) => e,
        Err(_) => return findings,
    };

    let key_files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("id_"))
        })
        .take(50)
        .collect();

    for key_path in &key_files {
        // Skip public keys
        if key_path.extension().is_some_and(|ext| ext == "pub") {
            continue;
        }
        if !key_path.is_file() {
            continue;
        }

        let lines = read_lines(key_path, 5);
        let content = lines.join("\n");

        if content.starts_with("-----BEGIN") && !content.contains("ENCRYPTED") {
            let key_name = key_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            findings.push(Finding {
                title: format!("Unprotected SSH private key: {key_name}"),
                description: format!(
                    "The SSH private key ~/.ssh/{key_name} does not have a \
                     passphrase. If your device is stolen or compromised, the attacker \
                     gains immediate access to all systems this key authenticates to."
                ),
                threat_level: ThreatLevel::High,
                remediation: format!(
                    "Add a passphrase to the existing key:\n  \
                     ssh-keygen -p -f ~/.ssh/{key_name}\n\
                     Consider using an SSH agent to avoid re-entering the passphrase:\n  \
                     ssh-add ~/.ssh/{key_name}"
                ),
            });
        }
    }

    findings
}

fn scan_aws_credentials(home: &Path) -> Vec<Finding> {
    let aws_creds = home.join(".aws").join("credentials");
    if !aws_creds.is_file() {
        return Vec::new();
    }

    let lines = read_lines(&aws_creds, MAX_LINES);
    let mut has_access_key = false;
    let mut has_secret_key = false;

    for line in &lines {
        if AWS_KEY_PATTERN.is_match(line) {
            has_access_key = true;
        }
        if AWS_SECRET_PATTERN.is_match(line) {
            has_secret_key = true;
        }
    }

    if has_access_key || has_secret_key {
        vec![Finding {
            title: "Plaintext AWS credentials found".to_string(),
            description: "Found AWS access keys in ~/.aws/credentials stored in plain text. \
                 These credentials provide direct access to your AWS account and \
                 are a high-value target for attackers."
                .to_string(),
            threat_level: ThreatLevel::Critical,
            remediation: "Use a credential management tool instead of plaintext files:\n  \
                 - aws-vault: stores credentials in your OS keychain\n  \
                 - AWS SSO: use short-lived session tokens\n  \
                 - Environment variables: slightly better than files \
                 (cleared on reboot)\n\
                 If you must use the credentials file, restrict permissions:\n  \
                 chmod 600 ~/.aws/credentials"
                .to_string(),
        }]
    } else {
        Vec::new()
    }
}

fn scan_config_files(home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for &config_name in CONFIG_FILES {
        let config_path = home.join(config_name);
        if !config_path.is_file() {
            continue;
        }

        let lines = read_lines(&config_path, MAX_LINES);
        let has_secrets = lines.iter().any(|line| {
            CONFIG_SECRET_PATTERNS
                .iter()
                .any(|pattern| pattern.is_match(line))
        });

        if has_secrets {
            findings.push(Finding {
                title: format!("Credentials found in ~/{config_name}"),
                description: format!(
                    "Found tokens or passwords in ~/{config_name}. \
                     Configuration files with embedded credentials are a common \
                     source of credential theft, especially when dotfiles are \
                     synced or backed up without encryption."
                ),
                threat_level: ThreatLevel::Medium,
                remediation: format!(
                    "Remove plaintext credentials from ~/{config_name}.\n\
                     Use a credential manager or OS keychain instead.\n\
                     For npm: use `npm login` which stores tokens securely.\n\
                     For Docker: use `docker-credential-helpers` for OS keychain integration.\n\
                     For pip/PyPI: use `keyring` for secure token storage."
                ),
            });
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn audit_secrets(opts: &AuditOpts) -> Result<AuditResult> {
    let scan_dir = opts
        .path
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let home = home_dir().unwrap_or_else(|| PathBuf::from("/"));

    let mut findings: Vec<Finding> = Vec::new();
    let mut score: i32 = 100;

    // 1. Scan .env files in the target directory
    let env_findings = scan_env_files(&scan_dir);
    score -= 15 * env_findings.len() as i32;
    findings.extend(env_findings);

    // 2. Check .git/config for embedded credentials
    let git_findings = scan_git_config(&scan_dir);
    score -= 20 * git_findings.len() as i32;
    findings.extend(git_findings);

    // 3. Scan shell history for leaked secrets
    let history_findings = scan_shell_history(&home);
    score -= 10 * history_findings.len() as i32;
    findings.extend(history_findings);

    // 4. Check SSH keys for missing passphrase
    let ssh_findings = scan_ssh_keys(&home);
    score -= 15 * ssh_findings.len() as i32;
    findings.extend(ssh_findings);

    // 5. Check AWS credentials
    let aws_findings = scan_aws_credentials(&home);
    score -= 20 * aws_findings.len() as i32;
    findings.extend(aws_findings);

    // 6. Check known config files for tokens
    let config_findings = scan_config_files(&home);
    score -= 10 * config_findings.len() as i32;
    findings.extend(config_findings);

    let score = score.clamp(0, 100) as u32;

    let env_count = findings
        .iter()
        .filter(|f| f.title.starts_with("Secrets found in .env"))
        .count();
    let git_count = findings
        .iter()
        .filter(|f| f.title.contains(".git/config"))
        .count();
    let history_count = findings
        .iter()
        .filter(|f| f.title.contains("shell history"))
        .count();
    let ssh_count = findings
        .iter()
        .filter(|f| f.title.contains("SSH private key"))
        .count();
    let aws_count = findings.iter().filter(|f| f.title.contains("AWS")).count();
    let config_count = findings
        .iter()
        .filter(|f| f.title.starts_with("Credentials found in"))
        .count();

    let mut raw_data = HashMap::new();
    raw_data.insert(
        "scan_dir".to_string(),
        serde_json::Value::String(scan_dir.display().to_string()),
    );
    raw_data.insert(
        "home_dir".to_string(),
        serde_json::Value::String(home.display().to_string()),
    );
    raw_data.insert(
        "env_files_with_secrets".to_string(),
        serde_json::json!(env_count),
    );
    raw_data.insert(
        "git_credential_leaks".to_string(),
        serde_json::json!(git_count),
    );
    raw_data.insert(
        "history_leaks".to_string(),
        serde_json::json!(history_count),
    );
    raw_data.insert(
        "unprotected_ssh_keys".to_string(),
        serde_json::json!(ssh_count),
    );
    raw_data.insert(
        "aws_plaintext_credentials".to_string(),
        serde_json::json!(aws_count),
    );
    raw_data.insert(
        "config_file_leaks".to_string(),
        serde_json::json!(config_count),
    );

    Ok(AuditResult {
        module_name: "secrets".to_string(),
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

    // -----------------------------------------------------------------------
    // Tests that call private scanners directly (no HOME dependency)
    // -----------------------------------------------------------------------

    #[test]
    fn env_file_with_secret_is_detected() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "API_KEY=secret123\nDATABASE_URL=postgres://localhost\n",
        )
        .unwrap();

        let findings = scan_env_files(dir.path());
        assert!(!findings.is_empty(), "Expected at least one .env finding");
        assert!(findings[0].title.contains("Secrets found in .env"));
        assert!(findings[0].description.contains("potential secret"));
        assert_eq!(findings[0].threat_level, ThreatLevel::High);
    }

    #[test]
    fn empty_directory_produces_no_env_findings() {
        let dir = tempdir().unwrap();
        let findings = scan_env_files(dir.path());
        assert!(
            findings.is_empty(),
            "Expected no .env findings in empty dir, got: {findings:#?}"
        );
    }

    #[test]
    fn env_file_without_secrets_produces_no_findings() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "DEBUG=true\nLOG_LEVEL=info\nPORT=8080\n",
        )
        .unwrap();

        let findings = scan_env_files(dir.path());
        assert!(
            findings.is_empty(),
            "Expected no findings for non-secret env vars, got: {findings:#?}"
        );
    }

    #[test]
    fn git_config_with_credentials_is_detected() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n    url = https://user:pass@github.com/repo.git\n",
        )
        .unwrap();

        let findings = scan_git_config(dir.path());
        assert!(!findings.is_empty(), "Expected a .git/config finding");
        assert!(findings[0].title.contains(".git/config"));
        assert_eq!(findings[0].threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn git_config_without_credentials_is_clean() {
        let dir = tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n    url = git@github.com:user/repo.git\n",
        )
        .unwrap();

        let findings = scan_git_config(dir.path());
        assert!(
            findings.is_empty(),
            "Expected no findings for SSH-based git remote"
        );
    }

    #[test]
    fn config_files_npmrc_with_token_is_detected() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".npmrc"), "_authToken = abc123\n").unwrap();

        let findings = scan_config_files(dir.path());
        assert!(
            !findings.is_empty(),
            "Expected a .npmrc credential finding, got: {findings:#?}"
        );
        assert!(findings[0].title.contains(".npmrc"));
        assert_eq!(findings[0].threat_level, ThreatLevel::Medium);
    }

    #[test]
    fn config_files_clean_npmrc_produces_no_findings() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();

        let findings = scan_config_files(dir.path());
        assert!(
            findings.is_empty(),
            "Expected no findings for clean .npmrc, got: {findings:#?}"
        );
    }

    #[test]
    fn aws_credentials_detected() {
        let dir = tempdir().unwrap();
        let aws_dir = dir.path().join(".aws");
        fs::create_dir_all(&aws_dir).unwrap();
        fs::write(
            aws_dir.join("credentials"),
            "[default]\naws_access_key_id = AKIA...\naws_secret_access_key = wJalr...\n",
        )
        .unwrap();

        let findings = scan_aws_credentials(dir.path());
        assert!(!findings.is_empty(), "Expected AWS credential finding");
        assert_eq!(findings[0].threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn no_aws_dir_produces_no_findings() {
        let dir = tempdir().unwrap();
        let findings = scan_aws_credentials(dir.path());
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Integration test through audit_secrets (uses HOME but consolidated
    // into a single test to avoid env var races across parallel tests).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn audit_secrets_integration() {
        // Create a fake HOME with an .npmrc containing a token.
        let fake_home = tempdir().unwrap();
        fs::write(fake_home.path().join(".npmrc"), "_authToken = xyz789\n").unwrap();

        // Create a scan_dir with .env and .git/config secrets.
        let scan_dir = tempdir().unwrap();
        fs::write(scan_dir.path().join(".env"), "SECRET_KEY=hunter2\n").unwrap();
        let git_dir = scan_dir.path().join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(
            git_dir.join("config"),
            "[remote \"origin\"]\n    url = https://admin:s3cret@github.com/r.git\n",
        )
        .unwrap();

        // Set HOME for this test.
        std::env::set_var("HOME", fake_home.path());

        let opts = AuditOpts {
            path: Some(scan_dir.path().to_path_buf()),
            ..Default::default()
        };
        let result = audit_secrets(&opts).await.unwrap();

        // Verify env finding present.
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.title.contains("Secrets found in .env")),
            "Missing .env finding"
        );
        // Verify git finding present.
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.title.contains(".git/config")),
            "Missing .git/config finding"
        );
        // Verify npmrc finding present.
        assert!(
            result.findings.iter().any(|f| f.title.contains(".npmrc")),
            "Missing .npmrc finding"
        );
        // Score should be < 100 with multiple secrets.
        assert!(result.score < 100, "Score should be reduced");
    }

    #[tokio::test]
    async fn audit_secrets_clean_directory_perfect_score() {
        // Use a separate clean tempdir as HOME to avoid picking up real
        // user files. Consolidated with the other HOME-setting test above
        // to minimize race window.
        let fake_home = tempdir().unwrap();
        std::env::set_var("HOME", fake_home.path());

        let scan_dir = tempdir().unwrap();
        let opts = AuditOpts {
            path: Some(scan_dir.path().to_path_buf()),
            ..Default::default()
        };
        let result = audit_secrets(&opts).await.unwrap();
        assert_eq!(result.score, 100, "Expected perfect score with no secrets");
    }

    #[test]
    fn test_shell_history_with_secret() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(".bash_history"),
            "ls -la\nexport SECRET_KEY=hunter2\ncd /tmp\n",
        )
        .unwrap();

        let findings = scan_shell_history(dir.path());
        assert!(
            !findings.is_empty(),
            "Expected shell history finding for exported secret"
        );
        assert!(findings[0].title.contains("shell history"));
        assert_eq!(findings[0].threat_level, ThreatLevel::Medium);
    }

    #[test]
    fn test_secrets_not_exposed_in_findings() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(".env"),
            "API_KEY=super_secret_value_12345\nSECRET_TOKEN=another_secret_abc\n",
        )
        .unwrap();

        let findings = scan_env_files(dir.path());
        assert!(!findings.is_empty(), "Expected .env finding");

        // Verify that the actual secret values are NOT present in the finding
        // description or title -- only the variable names should be mentioned.
        for finding in &findings {
            assert!(
                !finding.description.contains("super_secret_value_12345"),
                "Secret value should not appear in finding description"
            );
            assert!(
                !finding.title.contains("super_secret_value_12345"),
                "Secret value should not appear in finding title"
            );
            assert!(
                !finding.description.contains("another_secret_abc"),
                "Secret value should not appear in finding description"
            );
        }
    }
}
