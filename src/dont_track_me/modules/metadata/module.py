"""Metadata tracking vector module."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.metadata.auditor import audit_metadata
from dont_track_me.modules.metadata.protector import protect_metadata


class MetadataModule(BaseModule):
    name = "metadata"
    display_name = "File Metadata Scanner"
    description = "Detect and strip privacy-leaking metadata from images and documents"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_metadata(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_metadata(dry_run=dry_run, **kwargs)

    def get_dependencies(self) -> list[str]:
        return ["Pillow", "pypdf"]
