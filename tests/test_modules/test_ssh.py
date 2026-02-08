"""Tests for the SSH key hygiene audit module."""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from dont_track_me.modules.ssh.auditor import audit_ssh
from dont_track_me.modules.ssh.module import SshModule
from dont_track_me.modules.ssh.protector import protect_ssh


def _make_ssh_dir(tmp_path: Path) -> Path:
    """Create a fake ~/.ssh directory structure."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    return ssh_dir


def _write_key(ssh_dir: Path, name: str, content: str, *, age_years: float = 0.0) -> Path:
    """Write a fake private key file and optionally backdate it."""
    key_path = ssh_dir / name
    key_path.write_text(content)
    key_path.chmod(0o600)

    if age_years > 0:
        age_seconds = age_years * 365.25 * 24 * 3600
        old_time = time.time() - age_seconds
        os.utime(key_path, (old_time, old_time))

    return key_path


# --- Unencrypted OpenSSH new-format key (cipher=none) ---
# This is a minimal fake that triggers "none" cipher detection.
# The base64 decodes to the openssh-key-v1 magic followed by cipher name "none".
_UNENCRYPTED_OPENSSH_KEY = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBfaWRlbnRpdHlfZmFrZV90ZXN0X2tleV9kYXRhAAAAAAAA
-----END OPENSSH PRIVATE KEY-----
"""

# --- Encrypted OpenSSH new-format key (cipher=aes256-ctr) ---
_ENCRYPTED_OPENSSH_KEY = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBhZXMy
NTYtY3RyIGVuY3J5cHRlZAAAABQAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBfaWRl
bnRpdHlfZmFrZV90ZXN0X2tleV9kYXRhAAAAAAAA
-----END OPENSSH PRIVATE KEY-----
"""


@pytest.mark.asyncio
async def test_audit_returns_result(tmp_path: Path):
    """Audit runs and returns AuditResult with module_name='ssh'."""
    ssh_dir = _make_ssh_dir(tmp_path)
    _write_key(ssh_dir, "id_ed25519", _UNENCRYPTED_OPENSSH_KEY)

    with patch("dont_track_me.modules.ssh.auditor.Path.home", return_value=tmp_path):
        result = await audit_ssh()

    assert result.module_name == "ssh"
    assert isinstance(result.findings, list)
    assert "ssh_dir_exists" in result.raw_data


@pytest.mark.asyncio
async def test_audit_score_range(tmp_path: Path):
    """Score is always clamped between 0 and 100."""
    ssh_dir = _make_ssh_dir(tmp_path)
    _write_key(ssh_dir, "id_ed25519", _UNENCRYPTED_OPENSSH_KEY)

    with patch("dont_track_me.modules.ssh.auditor.Path.home", return_value=tmp_path):
        result = await audit_ssh()

    assert 0 <= result.score <= 100


@pytest.mark.asyncio
async def test_protect_dry_run(tmp_path: Path):
    """Protect in dry-run mode returns ProtectionResult with dry_run=True."""
    ssh_dir = _make_ssh_dir(tmp_path)
    _write_key(ssh_dir, "id_ed25519", _UNENCRYPTED_OPENSSH_KEY)

    with patch("dont_track_me.modules.ssh.protector.Path.home", return_value=tmp_path):
        result = await protect_ssh(dry_run=True)

    assert result.module_name == "ssh"
    assert result.dry_run is True
    assert len(result.actions_taken) == 0
    assert len(result.actions_available) > 0


def test_module_attributes():
    """Module has correct name, display_name, and description."""
    module = SshModule()
    assert module.name == "ssh"
    assert module.display_name == "SSH Key Hygiene Audit"
    assert "SSH" in module.description


def test_module_educational_content():
    """Educational content mentions SSH and is substantial."""
    module = SshModule()
    content = module.get_educational_content()
    assert "SSH" in content
    assert len(content) > 500


@pytest.mark.asyncio
async def test_detect_unencrypted_key(tmp_path: Path):
    """Detect unencrypted private key and flag it."""
    ssh_dir = _make_ssh_dir(tmp_path)
    _write_key(ssh_dir, "id_ed25519", _UNENCRYPTED_OPENSSH_KEY)

    # Create matching .pub file so algorithm detection works
    pub_path = ssh_dir / "id_ed25519.pub"
    pub_path.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKey user@host\n")

    with patch("dont_track_me.modules.ssh.auditor.Path.home", return_value=tmp_path):
        result = await audit_ssh()

    unencrypted_findings = [f for f in result.findings if "Unencrypted" in f.title]
    assert len(unencrypted_findings) >= 1
    assert unencrypted_findings[0].threat_level == "high"


@pytest.mark.asyncio
async def test_detect_forward_agent(tmp_path: Path):
    """Detect ForwardAgent yes in SSH config."""
    ssh_dir = _make_ssh_dir(tmp_path)

    config_path = ssh_dir / "config"
    config_path.write_text("Host *\n  ForwardAgent yes\n")
    config_path.chmod(0o600)

    with patch("dont_track_me.modules.ssh.auditor.Path.home", return_value=tmp_path):
        result = await audit_ssh()

    agent_findings = [f for f in result.findings if "Agent forwarding" in f.title]
    assert len(agent_findings) == 1
    assert agent_findings[0].threat_level == "high"


@pytest.mark.asyncio
async def test_detect_unhashed_known_hosts(tmp_path: Path):
    """Detect unhashed entries in known_hosts."""
    ssh_dir = _make_ssh_dir(tmp_path)

    known_hosts_path = ssh_dir / "known_hosts"
    # Write several unhashed entries to trigger the finding
    entries = [
        "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...",
        "gitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD...",
        "192.168.1.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...",
        "server1.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQA...",
        "server2.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQA...",
        "server3.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQA...",
    ]
    known_hosts_path.write_text("\n".join(entries) + "\n")

    with patch("dont_track_me.modules.ssh.auditor.Path.home", return_value=tmp_path):
        result = await audit_ssh()

    unhashed_findings = [f for f in result.findings if "unhashed" in f.title]
    assert len(unhashed_findings) == 1
    assert unhashed_findings[0].threat_level == "high"
    # Score should be penalized for unhashed known_hosts with >5 entries
    assert "unhashed_known_hosts" in result.raw_data["issues"]


@pytest.mark.asyncio
async def test_clean_ssh_dir(tmp_path: Path):
    """A clean SSH dir with an encrypted Ed25519 key scores high."""
    ssh_dir = _make_ssh_dir(tmp_path)

    # Write encrypted Ed25519 key (recent, within last year)
    _write_key(ssh_dir, "id_ed25519", _ENCRYPTED_OPENSSH_KEY)

    # Matching .pub file
    pub_path = ssh_dir / "id_ed25519.pub"
    pub_path.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestKey user@host\n")

    # Properly hashed known_hosts
    known_hosts_path = ssh_dir / "known_hosts"
    known_hosts_path.write_text(
        "|1|abc123=|def456= ssh-rsa AAAAB3...\n|1|ghi789=|jkl012= ssh-ed25519 AAAAC3...\n"
    )

    # Clean config
    config_path = ssh_dir / "config"
    config_path.write_text(
        "Host *\n    HashKnownHosts yes\n    StrictHostKeyChecking ask\n    ForwardAgent no\n"
    )
    config_path.chmod(0o600)

    with patch("dont_track_me.modules.ssh.auditor.Path.home", return_value=tmp_path):
        result = await audit_ssh()

    # Should be a high score -- no penalties
    assert result.score >= 90
    assert result.module_name == "ssh"
