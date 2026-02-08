"""YouTube module — audit and diversify YouTube subscriptions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.auth import OAuthModule
from dont_track_me.core.base import AuditResult, ProtectionResult
from dont_track_me.modules.youtube.auditor import audit_youtube
from dont_track_me.modules.youtube.protector import protect_youtube


class YouTubeModule(OAuthModule):
    name = "youtube"
    display_name = "YouTube Subscription Diversification"
    description = "Audit subscription bias and diversify YouTube profile"
    platform_name = "youtube"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_youtube(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_youtube(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_dependencies(self) -> list[str]:
        return ["keyring"]

    def _get_token_url(self) -> str:
        return "https://oauth2.googleapis.com/token"
