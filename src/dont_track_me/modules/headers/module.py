"""HTTP headers tracking vector module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.headers.auditor import audit_headers
from dont_track_me.modules.headers.protector import protect_headers


class HeadersModule(BaseModule):
    name = "headers"
    display_name = "HTTP Header Analysis"
    description = "Analyze HTTP headers for identity leaks and tracking signals"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_headers(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_headers(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return []  # httpx is a core dependency
