"""Advertising data ecosystem audit module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.ad_tracking.auditor import audit_ad_tracking
from dont_track_me.modules.ad_tracking.protector import protect_ad_tracking


class AdTrackingModule(BaseModule):
    name = "ad_tracking"
    display_name = "Advertising Data Ecosystem Audit"
    description = "Audit advertising ID exposure, Safari tracking prevention, and data broker risks"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_ad_tracking(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_ad_tracking(dry_run=dry_run, **kwargs)

