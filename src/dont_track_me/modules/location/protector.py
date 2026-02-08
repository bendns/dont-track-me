"""Location data leakage protection — recommend-only, no auto-modifications."""

from __future__ import annotations

import platform
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.location.auditor import audit_location


async def protect_location(
    dry_run: bool = True,
    **kwargs: Any,
) -> ProtectionResult:
    """Provide protection recommendations for location data leakage.

    Location-related changes (removing Wi-Fi networks, changing timezone
    settings, revoking permissions) can break workflows. All actions are
    recommendations only, even when dry_run=False.
    """
    actions_available: list[str] = []
    actions_taken: list[str] = []

    audit_result = await audit_location(**kwargs)
    raw = audit_result.raw_data

    is_macos = platform.system() == "Darwin"

    # --- Wi-Fi recommendations ---
    revealing_ssids: dict[str, list[str]] = raw.get("revealing_ssids", {})
    open_networks: list[str] = raw.get("open_networks", [])
    wifi_count: int = raw.get("wifi_networks_count", 0)

    if revealing_ssids:
        all_ssids = [s for ssids in revealing_ssids.values() for s in ssids]
        for ssid in sorted(all_ssids)[:10]:
            actions_available.append(
                f"Remove location-revealing Wi-Fi network '{ssid}': "
                f"networksetup -removepreferredwirelessnetwork en0 '{ssid}'"
            )
        if len(all_ssids) > 10:
            actions_available.append(
                f"... and {len(all_ssids) - 10} more location-revealing networks to review"
            )

    if open_networks:
        for ssid in sorted(open_networks)[:5]:
            actions_available.append(
                f"Remove open (unsecured) network '{ssid}' or disable auto-join: "
                f"System Settings > Wi-Fi > click (i) next to '{ssid}' > Auto-Join off"
            )

    if wifi_count > 20:
        actions_available.append(
            "Periodically clear unused Wi-Fi networks to reduce your location fingerprint: "
            "System Settings > Wi-Fi > review and forget networks you no longer use"
        )

    if is_macos:
        actions_available.append(
            "Disable auto-join for public networks: "
            "System Settings > Wi-Fi > click (i) next to each network > Auto-Join off"
        )

    # --- Timezone recommendations ---
    if raw.get("timezone_match") is False:
        system_tz = raw.get("system_timezone", "unknown")
        ip_tz = raw.get("ip_timezone", "unknown")
        actions_available.append(
            f"Set timezone manually to match your VPN exit ({ip_tz}) instead of "
            f"current system timezone ({system_tz}): "
            "System Settings > General > Date & Time > disable 'Set time zone automatically'"
        )
    elif raw.get("timezone_match") is True:
        actions_available.append(
            "Your timezone matches your IP location. If using a VPN, consider "
            "disabling automatic timezone to prevent future mismatches: "
            "System Settings > General > Date & Time > Set time zone automatically > off"
        )

    # --- Location Services recommendations ---
    location_apps: list[str] = raw.get("location_apps", [])
    tracking_suite_apps: list[str] = raw.get("tracking_suite_apps", [])

    if tracking_suite_apps:
        for app in tracking_suite_apps:
            actions_available.append(
                f"'{app}' has Location + Camera + Microphone (full tracking suite). "
                f"Revoke unnecessary permissions: "
                f"System Settings > Privacy & Security > Location Services / Camera / Microphone"
            )

    for app in sorted(location_apps):
        if app not in tracking_suite_apps:
            actions_available.append(
                f"Revoke Location access for '{app}': "
                f"System Settings > Privacy & Security > Location Services > toggle off '{app}'"
            )

    if is_macos:
        actions_available.append(
            "Review Location Services grants quarterly: "
            "System Settings > Privacy & Security > Location Services"
        )

    # Even with --apply, we don't auto-modify
    if not dry_run:
        actions_taken.append(
            "Location-related modifications require manual action for safety. "
            "Removing Wi-Fi networks or revoking permissions could break connectivity "
            "or apps you rely on. Please follow the recommendations in actions_available."
        )

    return ProtectionResult(
        module_name="location",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
