"""Local secrets exposure audit module."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.secrets.auditor import audit_secrets
from dont_track_me.modules.secrets.protector import protect_secrets


class SecretsModule(BaseModule):
    name = "secrets"
    display_name = "Local Secrets Exposure Audit"
    description = "Detect leaked credentials, API keys, and secrets in local files"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_secrets(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_secrets(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_dependencies(self) -> list[str]:
        return []
