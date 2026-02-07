"""Social noise module — obfuscate your social media profile."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.social_noise.auditor import audit_social_noise
from dont_track_me.modules.social_noise.protector import protect_social_noise


class SocialNoiseModule(BaseModule):
    name = "social_noise"
    display_name = "Social Media Profile Obfuscation"
    description = "Generate balanced follow lists to prevent social media profiling"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_social_noise(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_social_noise(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_dependencies(self) -> list[str]:
        return []  # No external dependencies
