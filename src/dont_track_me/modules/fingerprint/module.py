"""Browser fingerprint detection module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.fingerprint.auditor import audit_fingerprint
from dont_track_me.modules.fingerprint.protector import protect_fingerprint


class FingerprintModule(BaseModule):
    name = "fingerprint"
    display_name = "Browser Fingerprint Detection"
    description = "Detect browser fingerprinting exposure and anti-fingerprinting protections"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_fingerprint(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_fingerprint(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return []  # Core works without deps; Playwright enhances if available
