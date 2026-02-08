"""SSH privacy protections -- recommend and apply secure SSH configuration."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.ssh.auditor import (
    _detect_key_algorithm,
    _estimate_rsa_strength,
    _is_key_encrypted,
    _looks_like_private_key,
)


async def protect_ssh(
    dry_run: bool = True,
    **kwargs: Any,
) -> ProtectionResult:
    """Apply SSH hardening protections.

    In dry-run mode, reports all recommended actions without making changes.
    When apply mode is enabled (dry_run=False), only performs safe operations:
    - Hash known_hosts (ssh-keygen -H)
    - Fix file permissions (os.chmod)

    Key generation and config modifications are never done automatically.
    """
    actions_available: list[str] = []
    actions_taken: list[str] = []
    ssh_dir = Path.home() / ".ssh"

    if not ssh_dir.exists():
        actions_available.append(
            "Create ~/.ssh directory and generate an Ed25519 key: "
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            "ssh-keygen -t ed25519 -C 'your_email@example.com'"
        )
        return ProtectionResult(
            module_name="ssh",
            dry_run=dry_run,
            actions_taken=actions_taken,
            actions_available=actions_available,
        )

    # Check SSH directory permissions
    try:
        ssh_dir_mode = os.stat(ssh_dir).st_mode
        if ssh_dir_mode & (stat.S_IRWXG | stat.S_IRWXO):
            action = "Fix ~/.ssh directory permissions to 700 (owner-only access)"
            actions_available.append(action)
            if not dry_run:
                os.chmod(ssh_dir, 0o700)
                actions_taken.append(action)
    except OSError:
        pass

    # Scan private keys for recommendations
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
        pass

    for key_path in private_keys:
        key_name = key_path.name
        algorithm = _detect_key_algorithm(key_path, ssh_dir)

        # Recommend upgrading weak keys
        if algorithm == "dsa":
            actions_available.append(
                f"Replace DSA key '{key_name}' with Ed25519 (DSA is broken): "
                "ssh-keygen -t ed25519 -C 'your_email@example.com'"
            )
        elif algorithm == "rsa":
            strength = _estimate_rsa_strength(key_path)
            if strength in ("weak", "medium"):
                actions_available.append(
                    f"Replace RSA key '{key_name}' with Ed25519 (stronger and faster): "
                    "ssh-keygen -t ed25519 -C 'your_email@example.com'"
                )
        elif algorithm == "ecdsa":
            actions_available.append(
                f"Consider replacing ECDSA key '{key_name}' with Ed25519: "
                "ssh-keygen -t ed25519 -C 'your_email@example.com'"
            )

        # Recommend adding passphrase to unprotected keys
        if not _is_key_encrypted(key_path):
            actions_available.append(
                f"Add passphrase to unencrypted key '{key_name}': "
                f"ssh-keygen -p -f ~/.ssh/{key_name}"
            )

        # Fix private key permissions if too open
        try:
            key_mode = os.stat(key_path).st_mode
            if key_mode & (stat.S_IRWXG | stat.S_IRWXO):
                action = f"Fix permissions on '{key_name}' to 600 (owner read/write only)"
                actions_available.append(action)
                if not dry_run:
                    os.chmod(key_path, 0o600)
                    actions_taken.append(action)
        except OSError:
            pass

    # Hash known_hosts
    known_hosts_path = ssh_dir / "known_hosts"
    if known_hosts_path.exists():
        try:
            content = known_hosts_path.read_text(encoding="utf-8", errors="replace")
            entries = [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            unhashed = [e for e in entries if not e.startswith("|1|")]

            if unhashed:
                action = "Hash known_hosts to hide server hostnames: ssh-keygen -H"
                actions_available.append(action)
                if not dry_run:
                    try:
                        result = subprocess.run(
                            ["ssh-keygen", "-H", "-f", str(known_hosts_path)],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                        if result.returncode == 0:
                            actions_taken.append(action)
                            # ssh-keygen -H creates a .old backup file; clean it up
                            old_file = known_hosts_path.with_suffix(".old")
                            if old_file.exists():
                                old_file.unlink()
                        else:
                            actions_taken.append(
                                f"Failed to hash known_hosts: {result.stderr.strip()}"
                            )
                    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                        actions_taken.append(f"Failed to hash known_hosts: {e}")
        except (PermissionError, OSError):
            pass

    # Fix authorized_keys permissions
    auth_keys_path = ssh_dir / "authorized_keys"
    if auth_keys_path.exists():
        try:
            auth_mode = os.stat(auth_keys_path).st_mode
            if auth_mode & (stat.S_IWGRP | stat.S_IWOTH):
                action = "Fix authorized_keys permissions to 600"
                actions_available.append(action)
                if not dry_run:
                    os.chmod(auth_keys_path, 0o600)
                    actions_taken.append(action)
        except OSError:
            pass

    # SSH config recommendations (never auto-modified)
    config_path = ssh_dir / "config"
    if config_path.exists():
        try:
            config_content = config_path.read_text(encoding="utf-8", errors="replace")
            config_lower = config_content.lower()

            if "forwardagent yes" in config_lower.replace(" ", "").replace("\t", ""):
                actions_available.append(
                    "Remove 'ForwardAgent yes' from ~/.ssh/config. "
                    "Use 'ProxyJump' (-J flag) instead for jump hosts."
                )

            if "stricthostkeychecking no" in config_lower.replace(" ", "").replace("\t", ""):
                actions_available.append(
                    "Change 'StrictHostKeyChecking no' to 'StrictHostKeyChecking ask' "
                    "in ~/.ssh/config to restore MITM protection."
                )
        except (PermissionError, OSError):
            pass
    else:
        actions_available.append(
            "Create ~/.ssh/config with secure defaults:\n"
            "  Host *\n"
            "    HashKnownHosts yes\n"
            "    StrictHostKeyChecking ask\n"
            "    ForwardAgent no\n"
            "    AddKeysToAgent yes"
        )

    return ProtectionResult(
        module_name="ssh",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
