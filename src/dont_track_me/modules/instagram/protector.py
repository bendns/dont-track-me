"""Instagram protector — step-by-step privacy hardening guide."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.core.checklist import protect_checklist_module
from dont_track_me.modules.instagram.checks import PRIVACY_CHECKS


async def protect_instagram(
    dry_run: bool = True,
    responses: dict[str, bool] | None = None,
    **kwargs: Any,
) -> ProtectionResult:
    """Generate Instagram privacy hardening guide."""
    return await protect_checklist_module(
        module_name="instagram",
        display_name="Instagram",
        checks=PRIVACY_CHECKS,
        responses=responses,
    )
