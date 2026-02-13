"""Location data leakage audit module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.location.auditor import audit_location
from dont_track_me.modules.location.protector import protect_location


class LocationModule(BaseModule):
    name = "location"
    display_name = "Location Data Leakage Audit"
    description = "Audit Wi-Fi history, location permissions, and timezone/VPN mismatches"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_location(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_location(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return []  # httpx is a core dep, plistlib/sqlite3 are stdlib
