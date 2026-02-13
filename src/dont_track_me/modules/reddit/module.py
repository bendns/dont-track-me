"""Reddit module — audit and harden Reddit privacy settings."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.auth import OAuthModule
from dont_track_me.core.base import AuditResult, ProtectionResult
from dont_track_me.modules.reddit.auditor import audit_reddit
from dont_track_me.modules.reddit.protector import protect_reddit


class RedditModule(OAuthModule):
    name = "reddit"
    display_name = "Reddit Privacy Hardening"
    description = "Audit and harden Reddit privacy settings, diversify subscriptions"
    platform_name = "reddit"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_reddit(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_reddit(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return ["keyring"]

    def _get_token_url(self) -> str:
        return "https://www.reddit.com/api/v1/access_token"
