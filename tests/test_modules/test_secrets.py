"""Tests for the secrets module."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from dont_track_me.modules.secrets.auditor import audit_secrets
from dont_track_me.modules.secrets.module import SecretsModule
from dont_track_me.modules.secrets.protector import protect_secrets


@pytest.mark.asyncio
async def test_audit_returns_result(tmp_path: Path):
    """Basic audit runs and returns AuditResult with correct module name."""
    with patch("dont_track_me.modules.secrets.auditor.Path.home", return_value=tmp_path):
        result = await audit_secrets(path=str(tmp_path))

    assert result.module_name == "secrets"
    assert isinstance(result.findings, list)
    assert "scan_dir" in result.raw_data


@pytest.mark.asyncio
async def test_audit_score_range(tmp_path: Path):
    """Audit score is always clamped to 0-100."""
    with patch("dont_track_me.modules.secrets.auditor.Path.home", return_value=tmp_path):
        result = await audit_secrets(path=str(tmp_path))

    assert 0 <= result.score <= 100


@pytest.mark.asyncio
async def test_protect_dry_run(tmp_path: Path):
    """Protect returns ProtectionResult with dry_run=True by default."""
    with patch("dont_track_me.modules.secrets.auditor.Path.home", return_value=tmp_path):
        result = await protect_secrets(dry_run=True, path=str(tmp_path))

    assert result.module_name == "secrets"
    assert result.dry_run is True
    assert isinstance(result.actions_available, list)
    assert len(result.actions_available) > 0  # at least the general recommendations


def test_module_attributes():
    """Module has required name, display_name, and description."""
    mod = SecretsModule()
    assert mod.name == "secrets"
    assert mod.display_name == "Local Secrets Exposure Audit"
    assert len(mod.description) > 0


def test_module_educational_content():
    """Educational content is loaded and contains relevant keywords."""
    mod = SecretsModule()
    content = mod.get_educational_content()
    assert len(content) > 500
    content_lower = content.lower()
    assert "secrets" in content_lower or "credentials" in content_lower


@pytest.mark.asyncio
async def test_env_pattern_detection(tmp_path: Path):
    """A .env file with SECRET_KEY=abc123 is detected as containing secrets."""
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET_KEY=abc123\nDATABASE_URL=postgres://localhost/db\n")

    with patch("dont_track_me.modules.secrets.auditor.Path.home", return_value=tmp_path):
        result = await audit_secrets(path=str(tmp_path))

    env_findings = [f for f in result.findings if ".env" in f.title]
    assert len(env_findings) >= 1
    assert result.score < 100


@pytest.mark.asyncio
async def test_git_credential_detection(tmp_path: Path):
    """Plaintext credentials in .git/config are detected."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    git_config = git_dir / "config"
    git_config.write_text(
        '[remote "origin"]\n'
        "    url = https://user:pass@github.com/user/repo.git\n"
        "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
    )

    with patch("dont_track_me.modules.secrets.auditor.Path.home", return_value=tmp_path):
        result = await audit_secrets(path=str(tmp_path))

    git_findings = [f for f in result.findings if "git" in f.title.lower()]
    assert len(git_findings) >= 1
    assert result.score < 100
    # Ensure the actual password value is NOT in the finding description
    for finding in git_findings:
        assert (
            "pass" not in finding.description.split("@")[0] if "@" in finding.description else True
        )


@pytest.mark.asyncio
async def test_no_false_positives_on_clean_dir(tmp_path: Path):
    """A clean temporary directory should score high (>= 80)."""
    with patch("dont_track_me.modules.secrets.auditor.Path.home", return_value=tmp_path):
        result = await audit_secrets(path=str(tmp_path))

    assert result.score >= 80
    # No env, git, ssh, aws, or config findings expected
    assert result.raw_data["env_files_with_secrets"] == 0
    assert result.raw_data["git_credential_leaks"] == 0


@pytest.mark.asyncio
async def test_ssh_key_detection(tmp_path: Path):
    """Unencrypted SSH private keys are detected."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    # Create an unencrypted private key stub
    key_file = ssh_dir / "id_rsa"
    key_file.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    # Create a public key (should be ignored)
    pub_file = ssh_dir / "id_rsa.pub"
    pub_file.write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@host\n")

    with patch("dont_track_me.modules.secrets.auditor.Path.home", return_value=tmp_path):
        result = await audit_secrets(path=str(tmp_path))

    ssh_findings = [f for f in result.findings if "ssh" in f.title.lower()]
    assert len(ssh_findings) >= 1
    assert result.score < 100


@pytest.mark.asyncio
async def test_aws_credential_detection(tmp_path: Path):
    """Plaintext AWS credentials are detected."""
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    creds_file = aws_dir / "credentials"
    creds_file.write_text(
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )

    with patch("dont_track_me.modules.secrets.auditor.Path.home", return_value=tmp_path):
        result = await audit_secrets(path=str(tmp_path))

    aws_findings = [f for f in result.findings if "aws" in f.title.lower()]
    assert len(aws_findings) >= 1
    assert result.score < 100
    # Ensure actual key values are NOT in the description
    for finding in aws_findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.description
        assert "wJalrXUtnFEMI" not in finding.description
