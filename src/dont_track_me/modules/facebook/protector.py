"""Facebook protector — step-by-step privacy hardening guide."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.core.checklist import protect_checklist_module
from dont_track_me.modules.facebook.checks import PRIVACY_CHECKS


async def protect_facebook(
    dry_run: bool = True,
    responses: dict[str, bool] | None = None,
    **kwargs: Any,
) -> ProtectionResult:
    """Generate Facebook privacy hardening guide."""
    return await protect_checklist_module(
        module_name="facebook",
        display_name="Facebook",
        checks=PRIVACY_CHECKS,
        responses=responses,
    )
