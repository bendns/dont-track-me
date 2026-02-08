"""Browser cookie analysis module."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.cookies.auditor import audit_cookies
from dont_track_me.modules.cookies.protector import protect_cookies


class CookiesModule(BaseModule):
    name = "cookies"
    display_name = "Browser Cookie Analysis"
    description = "Analyze browser cookies for third-party tracking"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_cookies(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_cookies(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_dependencies(self) -> list[str]:
        return []  # Uses only stdlib sqlite3
