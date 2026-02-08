"""Secrets protection — recommend and apply remediation for exposed credentials."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.secrets.auditor import audit_secrets


async def protect_secrets(dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
    """Generate protection recommendations for exposed secrets.

    In dry-run mode (default), lists all remediation steps without making changes.
    """
    actions_available: list[str] = []
    actions_taken: list[str] = []

    # Run the audit to discover current issues
    audit_result = await audit_secrets(**kwargs)

    path = kwargs.get("path")
    scan_dir = Path(path) if path else Path.cwd()

    for finding in audit_result.findings:
        # Add every finding's remediation as an available action
        actions_available.append(
            f"[{finding.threat_level.upper()}] {finding.title}: {finding.remediation}"
        )

    # Add general best-practice recommendations regardless of findings
    actions_available.append(
        "Install a pre-commit hook to prevent secrets from being committed:\n"
        "  Use git-secrets, gitleaks, or trufflehog as a pre-commit hook.\n"
        "  Example: pip install pre-commit && pre-commit install"
    )
    actions_available.append(
        "Enable .gitignore protection for common secret files:\n"
        "  Ensure .env, .env.local, .env.production, .env.staging, "
        ".env.development are all listed in .gitignore."
    )

    if not dry_run:
        # Non-dry-run: apply safe, non-destructive fixes
        # 1. Add .env files to .gitignore if it exists
        gitignore_path = scan_dir / ".gitignore"
        env_entries = [".env", ".env.local", ".env.production", ".env.staging", ".env.development"]

        if gitignore_path.exists():
            existing_content = gitignore_path.read_text(encoding="utf-8")
            existing_lines = {line.strip() for line in existing_content.splitlines()}
            missing_entries = [e for e in env_entries if e not in existing_lines]
            if missing_entries:
                with gitignore_path.open("a", encoding="utf-8") as f:
                    f.write("\n# Added by dont-track-me — prevent secrets from being committed\n")
                    for entry in missing_entries:
                        f.write(f"{entry}\n")
                actions_taken.append(f"Added {', '.join(missing_entries)} to .gitignore")
        else:
            # Create .gitignore with secret file patterns
            with gitignore_path.open("w", encoding="utf-8") as f:
                f.write("# Created by dont-track-me — prevent secrets from being committed\n")
                for entry in env_entries:
                    f.write(f"{entry}\n")
            actions_taken.append(
                f"Created .gitignore with secret file patterns: {', '.join(env_entries)}"
            )

        # 2. Fix permissions on sensitive files in home directory
        home = Path.home()
        sensitive_paths = [
            home / ".aws" / "credentials",
            home / ".ssh",
            home / ".netrc",
            home / ".npmrc",
            home / ".pypirc",
        ]
        for sensitive_path in sensitive_paths:
            if sensitive_path.exists():
                current_mode = sensitive_path.stat().st_mode & 0o777
                target_mode = 0o700 if sensitive_path.is_dir() else 0o600
                if current_mode != target_mode:
                    sensitive_path.chmod(target_mode)
                    actions_taken.append(
                        f"Set permissions on {sensitive_path} to {oct(target_mode)}"
                    )

    return ProtectionResult(
        module_name="secrets",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
