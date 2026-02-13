"""Email tracking pixel detection module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.email.auditor import audit_email
from dont_track_me.modules.email.protector import protect_email


class EmailModule(BaseModule):
    name = "email"
    display_name = "Email Tracking Pixel Detection"
    description = "Detect and strip email tracking pixels in .eml files"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_email(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_email(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return []  # Uses only stdlib (email, html.parser, re)
