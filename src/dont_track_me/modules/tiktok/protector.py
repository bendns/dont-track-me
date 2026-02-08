"""TikTok protector — step-by-step privacy hardening guide."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.core.checklist import protect_checklist_module
from dont_track_me.modules.tiktok.checks import PRIVACY_CHECKS


async def protect_tiktok(
    dry_run: bool = True,
    responses: dict[str, bool] | None = None,
    **kwargs: Any,
) -> ProtectionResult:
    """Generate TikTok privacy hardening guide."""
    return await protect_checklist_module(
        module_name="tiktok",
        display_name="TikTok",
        checks=PRIVACY_CHECKS,
        responses=responses,
    )
