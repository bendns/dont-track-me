"""Facebook module — interactive privacy checklist."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.core.checklist import PrivacyCheck
from dont_track_me.modules.facebook.auditor import audit_facebook
from dont_track_me.modules.facebook.checks import PRIVACY_CHECKS
from dont_track_me.modules.facebook.protector import protect_facebook


class FacebookModule(BaseModule):
    name = "facebook"
    display_name = "Facebook Privacy Audit"
    description = "Interactive privacy checklist for Facebook settings"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_facebook(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_facebook(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_checklist(self) -> list[PrivacyCheck]:
        return PRIVACY_CHECKS
