"""macOS app permission protection — recommend permission revocations."""

from __future__ import annotations

import platform
from typing import Any

from dont_track_me.core.base import ProtectionResult, ThreatLevel
from dont_track_me.modules.app_permissions.auditor import (
    _SERVICE_INFO,
    _find_camera_mic_combo,
    _find_over_permissioned,
    _friendly_service_name,
    audit_app_permissions,
)


async def protect_app_permissions(
    dry_run: bool = True,
    **kwargs: Any,
) -> ProtectionResult:
    """Provide protection recommendations for macOS app permissions.

    TCC database modifications are inherently dangerous — revoking the wrong
    permission can break applications. Therefore, all actions are recommendations
    only, even when dry_run=False. No automatic modifications are made.
    """
    actions_available: list[str] = []
    actions_taken: list[str] = []

    if platform.system() != "Darwin":
        actions_available.append(
            "App permission audit is macOS-only. No actions available on this platform."
        )
        return ProtectionResult(
            module_name="app_permissions",
            dry_run=dry_run,
            actions_taken=actions_taken,
            actions_available=actions_available,
        )

    # Run the audit to discover current permissions
    audit_result = await audit_app_permissions(**kwargs)
    by_service = audit_result.raw_data.get("by_service", {})

    # Generate per-app revocation instructions for high-risk services
    for _service, (friendly_name, threat_level, _penalty, _cap) in _SERVICE_INFO.items():
        if threat_level not in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            continue

        # by_service uses friendly names as keys (from raw_data)
        apps = by_service.get(friendly_name, [])
        for app in sorted(apps):
            actions_available.append(
                f"Revoke {friendly_name} access for '{app}': "
                f"System Settings > Privacy & Security > {friendly_name} > "
                f"toggle off '{app}'"
            )

    # Camera + Mic combo recommendation
    # Rebuild by_service with raw service keys for combo detection
    raw_by_service: dict[str, list[str]] = {}
    for service, (friendly_name, *_rest) in _SERVICE_INFO.items():
        apps = by_service.get(friendly_name, [])
        if apps:
            raw_by_service[service] = apps

    combo_apps = _find_camera_mic_combo(raw_by_service)
    if combo_apps:
        for app in combo_apps:
            actions_available.append(
                f"'{app}' has both Camera and Microphone — consider revoking at least one: "
                "System Settings > Privacy & Security > Camera / Microphone"
            )

    # Over-permissioned app recommendations
    over_permissioned = _find_over_permissioned(raw_by_service)
    for app, services in over_permissioned:
        friendly_services = [_friendly_service_name(s) for s in services]
        actions_available.append(
            f"'{app}' has {len(services)} high-risk permissions ({', '.join(friendly_services)}). "
            "Audit whether it truly needs all of them."
        )

    # General recommendations
    actions_available.append(
        "Review all permissions periodically: "
        "System Settings > Privacy & Security — check each category"
    )
    actions_available.append(
        "Prefer browser-based alternatives over native apps to limit permission scope. "
        "Browsers operate within a more restricted sandbox than native macOS apps."
    )

    # Even with --apply, we don't auto-modify TCC
    if not dry_run:
        actions_taken.append(
            "TCC database modifications require manual action for safety. "
            "Automatically revoking permissions could break applications you rely on. "
            "Please follow the recommendations in actions_available."
        )

    return ProtectionResult(
        module_name="app_permissions",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
