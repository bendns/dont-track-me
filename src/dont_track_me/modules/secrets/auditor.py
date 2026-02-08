"""Local secrets exposure detection and audit."""

from __future__ import annotations

import contextlib
import itertools
import re
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel

# Patterns that indicate secrets in .env files
_ENV_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|[\s])(\w*(?:KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|AUTH)\w*)\s*=\s*\S+", re.I),
    re.compile(r"(?:^|[\s])(\w*(?:API_KEY|ACCESS_KEY|PRIVATE_KEY)\w*)\s*=\s*\S+", re.I),
]

# Patterns that indicate secrets in shell history
_HISTORY_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bexport\s+\w*(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|AUTH)\w*=", re.I),
    re.compile(r"\bcurl\b.*-[Hh]\s+['\"]?Authorization:", re.I),
    re.compile(r"\bcurl\b.*-[Hh]\s+['\"]?X-API-Key:", re.I),
    re.compile(r"\bmysql\b.*\s-p\S+", re.I),
    re.compile(r"\bpsql\b.*password=\S+", re.I),
    re.compile(r"\bHTTP_PROXY\s*=\s*https?://\w+:\w+@", re.I),
]

# Git remote URL with embedded credentials
_GIT_CREDENTIAL_PATTERN: re.Pattern[str] = re.compile(r"url\s*=\s*https?://[^/\s]+:[^/\s]+@")

# AWS access key pattern (starts with AKIA)
_AWS_KEY_PATTERN: re.Pattern[str] = re.compile(r"aws_access_key_id\s*=\s*\S+", re.I)
_AWS_SECRET_PATTERN: re.Pattern[str] = re.compile(r"aws_secret_access_key\s*=\s*\S+", re.I)

# Token/password patterns in config files
_CONFIG_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:_authToken|//registry\.\S+/:_auth)\s*=\s*\S+", re.I),  # .npmrc
    re.compile(r"password\s*=\s*\S+", re.I),
    re.compile(r"token\s*=\s*\S+", re.I),
    re.compile(r'"auth"\s*:\s*"[^"]+"', re.I),  # docker config.json
    re.compile(r"login\s+\S+\s+password\s+\S+", re.I),  # .netrc
]

# Names of .env file variants to scan
_ENV_FILE_NAMES: list[str] = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
]

# Shell history files
_HISTORY_FILES: list[str] = [
    ".bash_history",
    ".zsh_history",
]

# Config files that may contain tokens
_CONFIG_FILES: list[str] = [
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".netrc",
]

_MAX_LINES = 1000


def _read_lines(path: Path, max_lines: int = _MAX_LINES) -> list[str]:
    """Read up to max_lines from a file, returning an empty list on errors."""
    lines: list[str] = []
    with (
        contextlib.suppress(PermissionError, OSError, UnicodeDecodeError),
        path.open(encoding="utf-8", errors="replace") as f,
    ):
        lines = list(itertools.islice(f, max_lines))
    return lines


def _scan_env_files(scan_dir: Path) -> list[Finding]:
    """Scan a directory for .env files containing secrets."""
    findings: list[Finding] = []
    for env_name in _ENV_FILE_NAMES:
        env_path = scan_dir / env_name
        if not env_path.is_file():
            continue
        lines = _read_lines(env_path)
        secret_keys_found: list[str] = []
        for line in lines:
            for pattern in _ENV_SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    key_name = match.group(1)
                    if key_name not in secret_keys_found:
                        secret_keys_found.append(key_name)
        if secret_keys_found:
            count = len(secret_keys_found)
            findings.append(
                Finding(
                    title=f"Secrets found in {env_name}",
                    description=(
                        f"Found {count} potential secret(s) in {env_path}. "
                        f"Variable names containing sensitive keywords were detected. "
                        f"These files are often accidentally committed to version control."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        f"Add {env_name} to your .gitignore file. "
                        "Use a secrets manager or encrypted vault for production credentials. "
                        "Rotate any secrets that may have been committed to git history."
                    ),
                )
            )
    return findings


def _scan_git_config(scan_dir: Path) -> list[Finding]:
    """Check .git/config for plaintext credentials in remote URLs."""
    findings: list[Finding] = []
    git_config = scan_dir / ".git" / "config"
    if not git_config.is_file():
        return findings
    lines = _read_lines(git_config)
    for line in lines:
        if _GIT_CREDENTIAL_PATTERN.search(line):
            findings.append(
                Finding(
                    title="Plaintext credentials in .git/config",
                    description=(
                        f"Found embedded credentials in a git remote URL in {git_config}. "
                        "Credentials in remote URLs are stored in plain text and visible "
                        "to anyone with access to the repository directory."
                    ),
                    threat_level=ThreatLevel.CRITICAL,
                    remediation=(
                        "Remove credentials from the remote URL. Use a credential helper instead:\n"
                        "  git config --global credential.helper osxkeychain  (macOS)\n"
                        "  git config --global credential.helper store        (Linux, less secure)\n"
                        "  git config --global credential.helper cache        (temporary in-memory)"
                    ),
                )
            )
            break  # one finding per .git/config is enough
    return findings


def _scan_shell_history(home: Path) -> list[Finding]:
    """Scan shell history files for commands that leaked secrets."""
    findings: list[Finding] = []
    for hist_name in _HISTORY_FILES:
        hist_path = home / hist_name
        if not hist_path.is_file():
            continue
        lines = _read_lines(hist_path)
        matches_found = 0
        for line in lines:
            for pattern in _HISTORY_SECRET_PATTERNS:
                if pattern.search(line):
                    matches_found += 1
                    break  # one match per line is enough
        if matches_found > 0:
            findings.append(
                Finding(
                    title=f"Secrets found in shell history ({hist_name})",
                    description=(
                        f"Found {matches_found} command(s) in ~/{hist_name} that appear "
                        "to contain secrets (API keys, passwords, tokens). Shell history "
                        "files are readable by any process running as your user."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation=(
                        "Clear sensitive entries from your shell history:\n"
                        f"  Edit ~/{hist_name} manually and remove lines containing secrets.\n"
                        "Prevent future leaks:\n"
                        "  For bash: prefix sensitive commands with a space "
                        "(requires HISTCONTROL=ignorespace)\n"
                        "  For zsh: use setopt HIST_IGNORE_SPACE and prefix commands with a space"
                    ),
                )
            )
    return findings


def _scan_ssh_keys(home: Path) -> list[Finding]:
    """Check for SSH private keys without passphrase protection."""
    findings: list[Finding] = []
    ssh_dir = home / ".ssh"
    if not ssh_dir.is_dir():
        return findings
    # Use islice to prevent unbounded iteration
    key_files = list(itertools.islice(ssh_dir.glob("id_*"), 50))
    for key_path in key_files:
        # Skip public keys
        if key_path.suffix == ".pub":
            continue
        if not key_path.is_file():
            continue
        lines = _read_lines(key_path, max_lines=5)
        content = "".join(lines)
        if content.startswith("-----BEGIN") and "ENCRYPTED" not in content:
            findings.append(
                Finding(
                    title=f"Unprotected SSH private key: {key_path.name}",
                    description=(
                        f"The SSH private key ~/.ssh/{key_path.name} does not have a "
                        "passphrase. If your device is stolen or compromised, the attacker "
                        "gains immediate access to all systems this key authenticates to."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        "Add a passphrase to the existing key:\n"
                        f"  ssh-keygen -p -f ~/.ssh/{key_path.name}\n"
                        "Consider using an SSH agent to avoid re-entering the passphrase:\n"
                        "  ssh-add ~/.ssh/" + key_path.name
                    ),
                )
            )
    return findings


def _scan_aws_credentials(home: Path) -> list[Finding]:
    """Check for plaintext AWS access keys."""
    findings: list[Finding] = []
    aws_creds = home / ".aws" / "credentials"
    if not aws_creds.is_file():
        return findings
    lines = _read_lines(aws_creds)
    has_access_key = False
    has_secret_key = False
    for line in lines:
        if _AWS_KEY_PATTERN.search(line):
            has_access_key = True
        if _AWS_SECRET_PATTERN.search(line):
            has_secret_key = True
    if has_access_key or has_secret_key:
        findings.append(
            Finding(
                title="Plaintext AWS credentials found",
                description=(
                    "Found AWS access keys in ~/.aws/credentials stored in plain text. "
                    "These credentials provide direct access to your AWS account and "
                    "are a high-value target for attackers."
                ),
                threat_level=ThreatLevel.CRITICAL,
                remediation=(
                    "Use a credential management tool instead of plaintext files:\n"
                    "  - aws-vault: stores credentials in your OS keychain\n"
                    "  - AWS SSO: use short-lived session tokens\n"
                    "  - Environment variables: slightly better than files "
                    "(cleared on reboot)\n"
                    "If you must use the credentials file, restrict permissions:\n"
                    "  chmod 600 ~/.aws/credentials"
                ),
            )
        )
    return findings


def _scan_config_files(home: Path) -> list[Finding]:
    """Check known config files for tokens and passwords."""
    findings: list[Finding] = []
    for config_name in _CONFIG_FILES:
        config_path = home / config_name
        if not config_path.is_file():
            continue
        lines = _read_lines(config_path)
        has_secrets = False
        for line in lines:
            for pattern in _CONFIG_SECRET_PATTERNS:
                if pattern.search(line):
                    has_secrets = True
                    break
            if has_secrets:
                break
        if has_secrets:
            findings.append(
                Finding(
                    title=f"Credentials found in ~/{config_name}",
                    description=(
                        f"Found tokens or passwords in ~/{config_name}. "
                        "Configuration files with embedded credentials are a common "
                        "source of credential theft, especially when dotfiles are "
                        "synced or backed up without encryption."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation=(
                        f"Remove plaintext credentials from ~/{config_name}.\n"
                        "Use a credential manager or OS keychain instead.\n"
                        "For npm: use `npm login` which stores tokens securely.\n"
                        "For Docker: use `docker-credential-helpers` for OS keychain integration.\n"
                        "For pip/PyPI: use `keyring` for secure token storage."
                    ),
                )
            )
    return findings


async def audit_secrets(**kwargs: Any) -> AuditResult:
    """Audit local filesystem for exposed secrets and credentials."""
    path = kwargs.get("path")
    scan_dir = Path(path) if path else Path.cwd()
    home = Path.home()

    findings: list[Finding] = []
    score = 100

    # 1. Scan .env files in the target directory
    env_findings = _scan_env_files(scan_dir)
    findings.extend(env_findings)
    score -= 15 * len(env_findings)

    # 2. Check .git/config for embedded credentials
    git_findings = _scan_git_config(scan_dir)
    findings.extend(git_findings)
    score -= 20 * len(git_findings)

    # 3. Scan shell history for leaked secrets
    history_findings = _scan_shell_history(home)
    findings.extend(history_findings)
    score -= 10 * len(history_findings)

    # 4. Check SSH keys for missing passphrase
    ssh_findings = _scan_ssh_keys(home)
    findings.extend(ssh_findings)
    score -= 15 * len(ssh_findings)

    # 5. Check AWS credentials
    aws_findings = _scan_aws_credentials(home)
    findings.extend(aws_findings)
    score -= 20 * len(aws_findings)

    # 6. Check known config files for tokens
    config_findings = _scan_config_files(home)
    findings.extend(config_findings)
    score -= 10 * len(config_findings)

    score = max(0, min(100, score))

    return AuditResult(
        module_name="secrets",
        score=score,
        findings=findings,
        raw_data={
            "scan_dir": str(scan_dir),
            "home_dir": str(home),
            "env_files_with_secrets": len(env_findings),
            "git_credential_leaks": len(git_findings),
            "history_leaks": len(history_findings),
            "unprotected_ssh_keys": len(ssh_findings),
            "aws_plaintext_credentials": len(aws_findings),
            "config_file_leaks": len(config_findings),
        },
    )
