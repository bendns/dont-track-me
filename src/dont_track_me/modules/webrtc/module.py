"""WebRTC IP leak detection module."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, BaseModule, ProtectionResult
from dont_track_me.modules.webrtc.auditor import audit_webrtc
from dont_track_me.modules.webrtc.protector import protect_webrtc


class WebrtcModule(BaseModule):
    name = "webrtc"
    display_name = "WebRTC IP Leak Detection"
    description = "Detect WebRTC-based IP address leaks that bypass VPNs"

    async def audit(self, **kwargs: Any) -> AuditResult:
        return await audit_webrtc(**kwargs)

    async def protect(self, dry_run: bool = True, **kwargs: Any) -> ProtectionResult:
        return await protect_webrtc(dry_run=dry_run, **kwargs)

    def get_educational_content(self) -> str:
        info_path = Path(__file__).parent / "info.md"
        return info_path.read_text()

    def get_dependencies(self) -> list[str]:
        return []  # Uses only stdlib socket
