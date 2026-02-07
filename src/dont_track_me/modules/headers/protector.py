"""HTTP header protections — recommend browser and proxy configurations."""

from __future__ import annotations

from dont_track_me.core.base import ProtectionResult

FIREFOX_RECOMMENDATIONS = [
    "Set privacy.resistFingerprinting = true in about:config (generalizes User-Agent, language, timezone)",
    "Set network.http.referer.XOriginPolicy = 2 (send Referer only for same-origin)",
    "Set network.http.referer.XOriginTrimmingPolicy = 2 (send only origin, not full URL)",
    "Set network.http.sendRefererHeader = 1 (send Referer only on clicks, not subresources)",
    "Enable Enhanced Tracking Protection (Strict mode)",
    "Install uBlock Origin for additional header/tracker blocking",
]

CHROME_RECOMMENDATIONS = [
    "Use the 'Reduce User-Agent' flag (chrome://flags/#reduce-user-agent)",
    "Set 'Send a Do Not Track request' in Privacy settings",
    "Install uBlock Origin to block tracking requests",
    "Consider switching to Brave Browser (Chromium-based with built-in privacy)",
]

GENERAL_RECOMMENDATIONS = [
    "Use a browser that supports privacy.resistFingerprinting (Firefox, Tor Browser)",
    "Avoid browser extensions that modify headers visibly (they increase fingerprint uniqueness)",
    "Use Tor Browser for maximum header privacy (all users have identical headers)",
]


async def protect_headers(dry_run: bool = True, **kwargs) -> ProtectionResult:
    """Provide header privacy recommendations."""
    actions_available: list[str] = []

    actions_available.append("--- Firefox ---")
    actions_available.extend(FIREFOX_RECOMMENDATIONS)
    actions_available.append("--- Chrome/Chromium ---")
    actions_available.extend(CHROME_RECOMMENDATIONS)
    actions_available.append("--- General ---")
    actions_available.extend(GENERAL_RECOMMENDATIONS)

    return ProtectionResult(
        module_name="headers",
        dry_run=dry_run,
        actions_taken=[],  # Header protection is recommendation-only
        actions_available=actions_available,
    )
