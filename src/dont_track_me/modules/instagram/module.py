"""Instagram module — interactive privacy checklist."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.core.checklist import PrivacyCheck
from dont_track_me.modules.instagram.auditor import audit_instagram
from dont_track_me.modules.instagram.checks import PRIVACY_CHECKS
from dont_track_me.modules.instagram.protector import protect_instagram


class InstagramModule(BaseModule):
    name = "instagram"
    display_name = "Instagram Privacy Audit"
    description = "Interactive privacy checklist for Instagram settings"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_instagram(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_instagram(dry_run=dry_run, **kwargs)

    def get_checklist(self) -> list[PrivacyCheck]:
        return PRIVACY_CHECKS
