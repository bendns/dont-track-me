"""SSH key hygiene audit module."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.ssh.auditor import audit_ssh
from dont_track_me.modules.ssh.protector import protect_ssh


class SshModule(BaseModule):
    name = "ssh"
    display_name = "SSH Key Hygiene Audit"
    description = "Audit SSH key strength, age, and configuration security"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_ssh(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_ssh(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_dependencies(self) -> list[str]:
        return []  # Uses only stdlib
