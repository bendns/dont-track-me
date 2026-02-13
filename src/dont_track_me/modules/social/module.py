"""Social media tracker detection module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.social.auditor import audit_social
from dont_track_me.modules.social.protector import protect_social


class SocialModule(BaseModule):
    name = "social"
    display_name = "Social Media Tracker Detection"
    description = "Detect social media tracking pixels, cookies, and browser protection gaps"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_social(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_social(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return []
