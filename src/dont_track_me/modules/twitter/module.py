"""Twitter/X privacy audit module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.core.checklist import PrivacyCheck
from dont_track_me.modules.twitter.auditor import audit_twitter
from dont_track_me.modules.twitter.checks import PRIVACY_CHECKS
from dont_track_me.modules.twitter.protector import protect_twitter


class TwitterModule(BaseModule):
    name = "twitter"
    display_name = "Twitter/X Privacy Audit"
    description = "Interactive privacy checklist for Twitter/X settings"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_twitter(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_twitter(dry_run=dry_run, **kwargs)

    def get_checklist(self) -> list[PrivacyCheck]:
        return PRIVACY_CHECKS

    def get_dependencies(self) -> list[str]:
        return []
