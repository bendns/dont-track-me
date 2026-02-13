"""Search noise module — obfuscate your search engine profile."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.search_noise.auditor import audit_search_noise
from dont_track_me.modules.search_noise.protector import protect_search_noise


class SearchNoiseModule(BaseModule):
    name = "search_noise"
    display_name = "Search Query Obfuscation"
    description = "Generate balanced search noise to prevent ideological profiling"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_search_noise(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_search_noise(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return []  # httpx is a core dependency
