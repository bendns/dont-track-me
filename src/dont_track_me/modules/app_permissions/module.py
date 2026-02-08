"""macOS app permission audit module."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.app_permissions.auditor import audit_app_permissions
from dont_track_me.modules.app_permissions.protector import protect_app_permissions


class AppPermissionsModule(BaseModule):
    name = "app_permissions"
    display_name = "macOS App Permission Audit"
    description = "Audit macOS TCC permissions for over-permissioned apps"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_app_permissions(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_app_permissions(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_dependencies(self) -> list[str]:
        return []  # Uses only stdlib
