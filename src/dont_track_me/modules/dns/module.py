"""DNS tracking vector module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.dns.auditor import audit_dns
from dont_track_me.modules.dns.protector import protect_dns


class DnsModule(BaseModule):
    name = "dns"
    display_name = "DNS Leak Detection"
    description = "Detect DNS configuration leaks and tracking DNS providers"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_dns(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_dns(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return []  # Uses only stdlib subprocess + /etc/resolv.conf
