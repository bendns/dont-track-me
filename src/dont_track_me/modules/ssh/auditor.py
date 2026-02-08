"""SSH key hygiene and configuration security audit."""

from __future__ import annotations

import contextlib
import os
import stat
import time
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel

# Seconds in a year (approximate)
_SECONDS_PER_YEAR = 365.25 * 24 * 3600

# Key age thresholds
_KEY_AGE_HIGH_YEARS = 5
_KEY_AGE_MEDIUM_YEARS = 2

# Private key file patterns (excludes .pub files)
_PRIVATE_KEY_PREFIXES = ("id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "id_xmss")


def _detect_key_algorithm(private_key_path: Path, ssh_dir: Path) -> str:
    """Detect the SSH key algorithm from the private key file contents.

    Returns one of: "dsa", "rsa", "ecdsa", "ed25519", "unknown".
    """
    try:
        content = private_key_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return "unknown"

    first_line = content.strip().splitlines()[0] if content.strip() else ""

    if "BEGIN DSA PRIVATE KEY" in first_line:
        return "dsa"

    if "BEGIN RSA PRIVATE KEY" in first_line:
        return "rsa"

    if "BEGIN EC PRIVATE KEY" in first_line:
        return "ecdsa"

    if "BEGIN OPENSSH PRIVATE KEY" in first_line:
        # New OpenSSH format -- could be Ed25519, RSA, or ECDSA.
        # Check the matching .pub file for a definitive answer.
        pub_path = ssh_dir / (private_key_path.name + ".pub")
        if pub_path.exists():
            with contextlib.suppress(PermissionError, OSError):
                pub_content = pub_path.read_text(encoding="utf-8", errors="replace")
                if "ssh-ed25519" in pub_content:
                    return "ed25519"
                if "ssh-rsa" in pub_content:
                    return "rsa"
                if "ecdsa-sha2" in pub_content:
                    return "ecdsa"
                if "ssh-dss" in pub_content:
                    return "dsa"

        # Fallback: use file size heuristic. Ed25519 private keys are small (~400-500 bytes).
        try:
            file_size = private_key_path.stat().st_size
        except OSError:
            return "unknown"

        if file_size < 800:
            return "ed25519"

        # Larger new-format keys are likely RSA
        return "rsa"

    return "unknown"


def _estimate_rsa_strength(private_key_path: Path) -> str:
    """Estimate RSA key size from private key file size.

    Returns "weak" (<=1024), "medium" (2048), or "strong" (>=4096).
    """
    try:
        file_size = private_key_path.stat().st_size
    except OSError:
        return "medium"  # assume medium if we can't read

    # PEM-encoded RSA private key sizes (approximate):
    # 1024-bit: ~900 bytes
    # 2048-bit: ~1700 bytes
    # 4096-bit: ~3200 bytes
    # New OpenSSH format is slightly different but similar ratios.
    if file_size < 1100:
        return "weak"
    if file_size < 2500:
        return "medium"
    return "strong"


def _is_key_encrypted(private_key_path: Path) -> bool:
    """Check if a private key file is passphrase-protected.

    Looks for encryption indicators in the key file header.
    """
    try:
        content = private_key_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return True  # assume encrypted if we can't read (conservative)

    # PEM-format encrypted keys contain these headers
    if "ENCRYPTED" in content:
        return True

    if "Proc-Type: 4,ENCRYPTED" in content:
        return True

    # New OpenSSH format: check for bcrypt/aes markers in the binary blob.
    # Unencrypted new-format keys contain "none" as the cipher name after the
    # auth magic. We check the raw bytes for the "none" cipher indicator.
    if "BEGIN OPENSSH PRIVATE KEY" in content:
        # The cipher name "none" appears in plaintext in unencrypted keys.
        # Encrypted keys use "aes256-ctr" or similar instead.
        # We look for the literal bytes after base64 decoding would show "none",
        # but since we're reading as text, we check for common unencrypted patterns.
        # In base64-decoded form, unencrypted keys have "none" as cipher.
        # A pragmatic check: if the file is new-format and does NOT have ENCRYPTED,
        # look for "none" in the base64-decoded content.
        import base64

        lines = content.strip().splitlines()
        b64_data = ""
        in_key = False
        for line in lines:
            if "BEGIN OPENSSH PRIVATE KEY" in line:
                in_key = True
                continue
            if "END OPENSSH PRIVATE KEY" in line:
                break
            if in_key:
                b64_data += line.strip()

        with contextlib.suppress(Exception):
            raw = base64.b64decode(b64_data)
            # The cipher name appears after "openssh-key-v1\0" magic (15 bytes)
            # followed by a 4-byte length prefix for the cipher name string.
            magic = b"openssh-key-v1\x00"
            if raw.startswith(magic):
                offset = len(magic)
                if len(raw) > offset + 4:
                    cipher_len = int.from_bytes(raw[offset : offset + 4], "big")
                    if len(raw) > offset + 4 + cipher_len:
                        cipher_name = raw[offset + 4 : offset + 4 + cipher_len].decode(
                            "ascii", errors="replace"
                        )
                        return cipher_name != "none"

    return False


def _get_key_age_years(private_key_path: Path) -> float:
    """Get the age of a key file in years based on file modification time."""
    try:
        mtime = os.path.getmtime(private_key_path)
    except OSError:
        return 0.0

    age_seconds = time.time() - mtime
    return age_seconds / _SECONDS_PER_YEAR


def _check_authorized_keys(ssh_dir: Path) -> list[Finding]:
    """Audit the authorized_keys file for security issues."""
    findings: list[Finding] = []
    auth_keys_path = ssh_dir / "authorized_keys"

    if not auth_keys_path.exists():
        return findings

    # Check permissions
    try:
        st = os.stat(auth_keys_path)
        mode = st.st_mode

        # Check if group or others have write permission
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            findings.append(
                Finding(
                    title="authorized_keys has unsafe permissions",
                    description=(
                        "Your authorized_keys file is writable by group or others. "
                        "An attacker with local access could add their own public key "
                        "to gain SSH access to your account."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation="Run: chmod 600 ~/.ssh/authorized_keys",
                )
            )
    except OSError:
        pass

    # Count entries
    try:
        content = auth_keys_path.read_text(encoding="utf-8", errors="replace")
        entries = [
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        entry_count = len(entries)

        if entry_count > 0:
            findings.append(
                Finding(
                    title=f"authorized_keys contains {entry_count} key(s)",
                    description=(
                        f"Found {entry_count} authorized public key(s). "
                        "Each entry grants SSH access to your account. "
                        "Review regularly to ensure no unauthorized keys are present."
                    ),
                    threat_level=ThreatLevel.INFO,
                    remediation="Periodically review authorized_keys and remove unused entries.",
                )
            )
    except (PermissionError, OSError):
        pass

    return findings


def _check_ssh_config(ssh_dir: Path) -> list[Finding]:
    """Parse SSH config for security issues."""
    findings: list[Finding] = []
    config_path = ssh_dir / "config"

    if not config_path.exists():
        return findings

    try:
        content = config_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings

    lines = content.lower().splitlines()

    for line in lines:
        stripped = line.strip()

        # Skip comments
        if stripped.startswith("#"):
            continue

        if "forwardagent" in stripped and "yes" in stripped:
            findings.append(
                Finding(
                    title="Agent forwarding enabled in SSH config",
                    description=(
                        "ForwardAgent yes is set in your SSH config. This allows any "
                        "compromised server you connect to to use your local SSH agent "
                        "and authenticate as you to other servers. This is a significant "
                        "security risk unless you fully trust every server in the chain."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        "Remove 'ForwardAgent yes' from ~/.ssh/config. "
                        "Use ProxyJump (-J) instead of agent forwarding for jump hosts."
                    ),
                )
            )
            break

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if "stricthostkeychecking" in stripped and "no" in stripped:
            findings.append(
                Finding(
                    title="Strict host key checking disabled",
                    description=(
                        "StrictHostKeyChecking no is set in your SSH config. This disables "
                        "verification of server identity, making you vulnerable to "
                        "man-in-the-middle attacks. An attacker could impersonate any server "
                        "you connect to."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        "Remove 'StrictHostKeyChecking no' from ~/.ssh/config, "
                        "or set it to 'ask' for interactive confirmation of new hosts."
                    ),
                )
            )
            break

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if "passwordauthentication" in stripped and "yes" in stripped:
            findings.append(
                Finding(
                    title="Password authentication enabled",
                    description=(
                        "PasswordAuthentication yes is set in your SSH config. "
                        "Password-based authentication is weaker than key-based "
                        "authentication and susceptible to brute force attacks."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation=(
                        "Use key-based authentication and set "
                        "'PasswordAuthentication no' in SSH config."
                    ),
                )
            )
            break

    return findings


def _check_known_hosts(ssh_dir: Path) -> tuple[list[Finding], int]:
    """Audit known_hosts for privacy fingerprinting risks.

    Returns (findings, entry_count).
    """
    findings: list[Finding] = []
    known_hosts_path = ssh_dir / "known_hosts"

    if not known_hosts_path.exists():
        return findings, 0

    try:
        content = known_hosts_path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return findings, 0

    entries = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    entry_count = len(entries)

    if entry_count == 0:
        return findings, 0

    # Check if entries are hashed (hashed entries start with |1|)
    unhashed_entries = [e for e in entries if not e.startswith("|1|")]
    hashed_entries = [e for e in entries if e.startswith("|1|")]

    if unhashed_entries:
        findings.append(
            Finding(
                title=f"known_hosts contains {len(unhashed_entries)} unhashed entries",
                description=(
                    f"Your known_hosts file has {len(unhashed_entries)} entries with "
                    "plaintext hostnames. Anyone who gains access to this file can see "
                    "every server you have connected to via SSH, revealing your server "
                    "infrastructure and travel patterns."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Hash your known_hosts file: ssh-keygen -H\n"
                    "This replaces plaintext hostnames with cryptographic hashes."
                ),
            )
        )
    elif hashed_entries:
        findings.append(
            Finding(
                title=f"known_hosts is properly hashed ({len(hashed_entries)} entries)",
                description=(
                    "Your known_hosts file uses hashed hostnames, which prevents "
                    "casual enumeration of servers you connect to."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed. Consider enabling HashKnownHosts in SSH config.",
            )
        )

    if entry_count > 50:
        findings.append(
            Finding(
                title=f"Large known_hosts file ({entry_count} entries)",
                description=(
                    f"Your known_hosts file contains {entry_count} entries. A large file "
                    "increases fingerprinting surface even when hashed, as the count alone "
                    "reveals connection patterns."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation="Periodically prune old entries from known_hosts.",
            )
        )

    return findings, len(unhashed_entries)


async def audit_ssh(**kwargs: Any) -> AuditResult:
    """Audit SSH configuration for privacy and security issues."""
    findings: list[Finding] = []
    score = 100
    ssh_dir = Path.home() / ".ssh"
    raw_data: dict[str, Any] = {
        "ssh_dir_exists": ssh_dir.exists(),
        "keys_found": [],
        "issues": [],
    }

    if not ssh_dir.exists():
        findings.append(
            Finding(
                title="No SSH directory found",
                description=(
                    "No ~/.ssh directory was found. Either SSH is not configured "
                    "on this system or the directory is in a non-standard location."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed if you don't use SSH.",
            )
        )
        return AuditResult(
            module_name="ssh",
            score=100,
            findings=findings,
            raw_data=raw_data,
        )

    # Scan for private key files
    private_keys: list[Path] = []
    try:
        for entry in ssh_dir.iterdir():
            if (
                entry.is_file()
                and not entry.name.endswith(".pub")
                and (entry.name.startswith("id_") or _looks_like_private_key(entry))
            ):
                private_keys.append(entry)
    except PermissionError:
        findings.append(
            Finding(
                title="Cannot read SSH directory",
                description="Permission denied when reading ~/.ssh directory.",
                threat_level=ThreatLevel.MEDIUM,
                remediation="Check permissions on your ~/.ssh directory (should be 700).",
            )
        )

    # Audit each private key
    for key_path in private_keys:
        key_name = key_path.name
        algorithm = _detect_key_algorithm(key_path, ssh_dir)
        raw_data["keys_found"].append({"name": key_name, "algorithm": algorithm})

        # Check algorithm strength
        if algorithm == "dsa":
            findings.append(
                Finding(
                    title=f"DSA key detected: {key_name}",
                    description=(
                        "DSA keys are cryptographically broken and have been deprecated "
                        "since OpenSSH 7.0. They use a fixed 1024-bit key size which "
                        "is insufficient for modern security."
                    ),
                    threat_level=ThreatLevel.CRITICAL,
                    remediation=(
                        f"Replace {key_name} with an Ed25519 key: "
                        "ssh-keygen -t ed25519 -C 'your_email@example.com'"
                    ),
                )
            )
            score -= 25
            raw_data["issues"].append(f"dsa_key:{key_name}")

        elif algorithm == "rsa":
            strength = _estimate_rsa_strength(key_path)
            if strength == "weak":
                findings.append(
                    Finding(
                        title=f"Weak RSA key detected: {key_name} (likely <=1024 bit)",
                        description=(
                            "This RSA key appears to be 1024 bits or smaller, which is "
                            "considered cryptographically weak and vulnerable to factoring "
                            "attacks with modern hardware."
                        ),
                        threat_level=ThreatLevel.CRITICAL,
                        remediation=(
                            f"Replace {key_name} with an Ed25519 key: "
                            "ssh-keygen -t ed25519 -C 'your_email@example.com'"
                        ),
                    )
                )
                score -= 25
                raw_data["issues"].append(f"weak_rsa:{key_name}")
            elif strength == "medium":
                findings.append(
                    Finding(
                        title=f"RSA 2048-bit key detected: {key_name}",
                        description=(
                            "This RSA key is likely 2048 bits. While currently acceptable, "
                            "NIST recommends transitioning to stronger keys. RSA 2048 may "
                            "become vulnerable to quantum computing advances."
                        ),
                        threat_level=ThreatLevel.MEDIUM,
                        remediation=(
                            "Consider upgrading to Ed25519: "
                            "ssh-keygen -t ed25519 -C 'your_email@example.com'"
                        ),
                    )
                )
                score -= 15
                raw_data["issues"].append(f"medium_rsa:{key_name}")
            else:
                findings.append(
                    Finding(
                        title=f"RSA 4096-bit key detected: {key_name}",
                        description=(
                            "Strong RSA key detected. While secure for now, Ed25519 offers "
                            "better performance and smaller key sizes with equivalent security."
                        ),
                        threat_level=ThreatLevel.INFO,
                        remediation="Consider migrating to Ed25519 for improved performance.",
                    )
                )

        elif algorithm == "ecdsa":
            findings.append(
                Finding(
                    title=f"ECDSA key detected: {key_name}",
                    description=(
                        "ECDSA keys rely on NIST curves which some researchers distrust due "
                        "to potential NSA influence in the curve parameters. ECDSA is also "
                        "vulnerable to quantum computing attacks."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation=(
                        "Consider switching to Ed25519 which uses the independently-designed "
                        "Curve25519: ssh-keygen -t ed25519"
                    ),
                )
            )
            raw_data["issues"].append(f"ecdsa_key:{key_name}")

        elif algorithm == "ed25519":
            findings.append(
                Finding(
                    title=f"Ed25519 key detected: {key_name}",
                    description=(
                        "Ed25519 is the current best practice for SSH keys. It offers "
                        "strong security, small key sizes, and fast operations."
                    ),
                    threat_level=ThreatLevel.INFO,
                    remediation="No action needed. This is the recommended key type.",
                )
            )

        # Check passphrase protection
        if not _is_key_encrypted(key_path):
            findings.append(
                Finding(
                    title=f"Unencrypted private key: {key_name}",
                    description=(
                        "This private key is not protected by a passphrase. If your "
                        "device is stolen or compromised, the attacker gains immediate "
                        "access to all servers this key authenticates to."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        f"Add a passphrase: ssh-keygen -p -f ~/.ssh/{key_name}\n"
                        "Use ssh-agent to avoid retyping the passphrase."
                    ),
                )
            )
            score -= 15
            raw_data["issues"].append(f"unencrypted:{key_name}")

        # Check key age
        age_years = _get_key_age_years(key_path)
        if age_years > _KEY_AGE_HIGH_YEARS:
            findings.append(
                Finding(
                    title=f"Very old SSH key: {key_name} ({age_years:.1f} years)",
                    description=(
                        f"This key is approximately {age_years:.1f} years old. "
                        "NIST SP 800-57 recommends rotating cryptographic keys regularly. "
                        "Old keys may use outdated algorithms or have been exposed "
                        "through forgotten backups."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        "Generate a new key and rotate it across all authorized servers: "
                        "ssh-keygen -t ed25519 -C 'your_email@example.com'"
                    ),
                )
            )
            score -= 10
            raw_data["issues"].append(f"old_key_5y:{key_name}")
        elif age_years > _KEY_AGE_MEDIUM_YEARS:
            findings.append(
                Finding(
                    title=f"Aging SSH key: {key_name} ({age_years:.1f} years)",
                    description=(
                        f"This key is approximately {age_years:.1f} years old. "
                        "Consider rotating keys every 1-2 years as a security best practice."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation="Plan to rotate this key in the near future.",
                )
            )
            score -= 5
            raw_data["issues"].append(f"old_key_2y:{key_name}")

    # Check authorized_keys
    auth_findings = _check_authorized_keys(ssh_dir)
    findings.extend(auth_findings)
    for f in auth_findings:
        if f.threat_level == ThreatLevel.HIGH:
            score -= 15
            raw_data["issues"].append("authorized_keys_unsafe_perms")

    # Check SSH config
    config_findings = _check_ssh_config(ssh_dir)
    findings.extend(config_findings)
    for f in config_findings:
        if "Agent forwarding" in f.title:
            score -= 15
            raw_data["issues"].append("forward_agent")
        elif "host key checking" in f.title:
            score -= 15
            raw_data["issues"].append("strict_host_key_checking_disabled")
        elif "Password authentication" in f.title:
            score -= 5
            raw_data["issues"].append("password_auth")

    # Check known_hosts
    known_hosts_findings, unhashed_count = _check_known_hosts(ssh_dir)
    findings.extend(known_hosts_findings)
    if unhashed_count > 5:
        score -= 10
        raw_data["issues"].append("unhashed_known_hosts")

    score = max(0, min(100, score))

    return AuditResult(
        module_name="ssh",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )


def _looks_like_private_key(path: Path) -> bool:
    """Check if a file looks like an SSH private key based on its content."""
    try:
        # Read just the first line
        with path.open(encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()
        return "BEGIN" in first_line and "PRIVATE KEY" in first_line
    except (PermissionError, OSError):
        return False
