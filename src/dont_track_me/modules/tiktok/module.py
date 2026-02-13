"""TikTok module — interactive privacy checklist."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.core.checklist import PrivacyCheck
from dont_track_me.modules.tiktok.auditor import audit_tiktok
from dont_track_me.modules.tiktok.checks import PRIVACY_CHECKS
from dont_track_me.modules.tiktok.protector import protect_tiktok


class TikTokModule(BaseModule):
    name = "tiktok"
    display_name = "TikTok Privacy Audit"
    description = "Interactive privacy checklist for TikTok settings"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_tiktok(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_tiktok(dry_run=dry_run, **kwargs)

    def get_checklist(self) -> list[PrivacyCheck]:
        return PRIVACY_CHECKS
