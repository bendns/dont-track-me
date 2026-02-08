"""TLS certificate trust store audit module."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.certificates.auditor import audit_certificates
from dont_track_me.modules.certificates.protector import protect_certificates


class CertificatesModule(BaseModule):
    name = "certificates"
    display_name = "TLS Certificate Trust Audit"
    description = "Audit system certificate trust stores for expired, weak, or suspicious CAs"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_certificates(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_certificates(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_dependencies(self) -> list[str]:
        return []  # Uses only stdlib ssl module
