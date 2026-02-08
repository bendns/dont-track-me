"""WebRTC privacy protections — browser hardening recommendations."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import ProtectionResult

# Browser-specific WebRTC hardening instructions
BROWSER_RECOMMENDATIONS = [
    {
        "browser": "Firefox",
        "action": (
            "Disable WebRTC: open about:config, search for "
            "'media.peerconnection.enabled' and set it to false"
        ),
    },
    {
        "browser": "Chrome / Chromium",
        "action": (
            "Install the 'WebRTC Leak Prevent' extension from the Chrome Web Store, "
            "or launch Chrome with --enforce-webrtc-ip-permission-check flag"
        ),
    },
    {
        "browser": "Brave",
        "action": (
            "Settings → Privacy and Security → WebRTC IP Handling Policy → "
            "select 'Disable non-proxied UDP'"
        ),
    },
    {
        "browser": "Safari",
        "action": (
            "Develop menu → Experimental Features → disable WebRTC. "
            "Enable the Develop menu in Safari → Settings → Advanced → "
            "Show features for web developers"
        ),
    },
    {
        "browser": "Tor Browser",
        "action": (
            "WebRTC is disabled by default in Tor Browser. "
            "Verify: open about:config and confirm media.peerconnection.enabled = false"
        ),
    },
]


async def protect_webrtc(
    dry_run: bool = True,
    **kwargs: Any,
) -> ProtectionResult:
    """Provide WebRTC hardening recommendations for browsers.

    WebRTC settings live inside browsers and cannot be changed programmatically
    from outside, so this protector always provides guidance (actions_available)
    rather than making system changes.
    """
    actions_available: list[str] = []

    for rec in BROWSER_RECOMMENDATIONS:
        actions_available.append(f"{rec['browser']}: {rec['action']}")

    # General recommendation
    actions_available.append(
        "General: if you use a VPN, verify WebRTC is not leaking your real IP "
        "by visiting a WebRTC leak test site (e.g., browserleaks.com/webrtc)"
    )

    return ProtectionResult(
        module_name="webrtc",
        dry_run=dry_run,
        actions_taken=[],
        actions_available=actions_available,
    )
