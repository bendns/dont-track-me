"""Advertising data ecosystem protection — disable IDFA, recommend opt-outs."""

from __future__ import annotations

import platform
import subprocess
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.ad_tracking.auditor import _ADLIB_DOMAIN, audit_ad_tracking
from dont_track_me.modules.ad_tracking.brokers import load_brokers


def _defaults_write(domain: str, key: str, value: str) -> bool:
    """Write a boolean value to a macOS defaults domain.

    Returns True on success.
    """
    try:
        result = subprocess.run(
            ["defaults", "write", domain, key, "-bool", value],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

    return result.returncode == 0


async def protect_ad_tracking(
    dry_run: bool = True,
    **kwargs: Any,
) -> ProtectionResult:
    """Protect against advertising data ecosystem tracking.

    With --apply on macOS: disables IDFA and Apple personalized ads via
    defaults write (safe, reversible, no root required).
    All other protections are recommendations only.
    """
    actions_available: list[str] = []
    actions_taken: list[str] = []

    country = kwargs.get("country", "us")
    audit_result = await audit_ad_tracking(**kwargs)
    raw = audit_result.raw_data

    is_macos = platform.system() == "Darwin"

    # --- Advertising ID protections ---
    if raw.get("allowIdentifierForAdvertising") == "1":
        actions_available.append(
            "Disable advertising identifier (IDFA): "
            "System Settings > Privacy & Security > Apple Advertising > "
            "Personalized Ads > off"
        )

        if (
            not dry_run
            and is_macos
            and _defaults_write(_ADLIB_DOMAIN, "allowIdentifierForAdvertising", "false")
        ):
            actions_taken.append("Disabled advertising identifier (allowIdentifierForAdvertising)")

    if raw.get("allowApplePersonalizedAdvertising") == "1":
        actions_available.append(
            "Disable Apple personalized advertising: "
            "System Settings > Privacy & Security > Apple Advertising > "
            "Personalized Ads > off"
        )

        if (
            not dry_run
            and is_macos
            and _defaults_write(_ADLIB_DOMAIN, "allowApplePersonalizedAdvertising", "false")
        ):
            actions_taken.append(
                "Disabled Apple personalized ads (allowApplePersonalizedAdvertising)"
            )

    # --- Safari protections (recommend-only, sandboxed prefs can't be written) ---
    if raw.get("safari_prefs_readable"):
        if not raw.get("safari_dnt"):
            actions_available.append(
                "Enable Do Not Track in Safari: "
                "Safari > Settings > Privacy > Prevent cross-site tracking"
            )

        if raw.get("safari_block_storage_policy") == 0:
            actions_available.append(
                "Block third-party cookies in Safari: "
                "Safari > Settings > Privacy > Block all cookies "
                "(or enable Prevent cross-site tracking)"
            )

        if raw.get("safari_hide_ip") == 0:
            actions_available.append(
                "Hide IP address from trackers in Safari: "
                "Safari > Settings > Privacy > Hide IP Address > From Trackers"
            )

    # --- Browser ad-tracking recommendations ---
    if raw.get("firefox_dnt") is False:
        actions_available.append(
            "Enable Do Not Track in Firefox: "
            "Settings > Privacy & Security > "
            "Send websites a 'Do Not Track' request"
        )

    if raw.get("firefox_cookie_behavior") == 0:
        actions_available.append(
            "Set Firefox Enhanced Tracking Protection to Strict: "
            "Settings > Privacy & Security > Enhanced Tracking Protection > Strict"
        )

    if raw.get("chrome_dnt") is False:
        actions_available.append(
            "Enable Do Not Track in Chrome: "
            'Settings > Privacy and security > Send a "Do Not Track" request'
        )

    if raw.get("chrome_topics_enabled"):
        actions_available.append(
            "Disable Chrome Topics API: "
            "Settings > Privacy and security > Ad privacy > Ad topics > turn off"
        )

    if raw.get("chrome_fledge_enabled"):
        actions_available.append(
            "Disable Chrome Protected Audiences: "
            "Settings > Privacy and security > Ad privacy > "
            "Site-suggested ads > turn off"
        )

    # --- Mobile device recommendations (always shown) ---
    actions_available.append(
        "Reset advertising ID on iOS: "
        "Settings > Privacy & Security > Apple Advertising > "
        "Personalized Ads > off (zeroes out IDFA)"
    )
    actions_available.append(
        "Reset advertising ID on Android: Settings > Privacy > Ads > Delete advertising ID"
    )

    # --- Data broker opt-outs ---
    brokers = load_brokers(country)
    for broker in brokers:
        opt_out = broker.get("opt_out_url", "")
        if opt_out:
            actions_available.append(f"Request data deletion from {broker['name']}: {opt_out}")

    actions_available.append(
        "Consider a data removal service (Incogni, DeleteMe, Optery) to "
        "automate opt-out requests across hundreds of brokers"
    )

    return ProtectionResult(
        module_name="ad_tracking",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
