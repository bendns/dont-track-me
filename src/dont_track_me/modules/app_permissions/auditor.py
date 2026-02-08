"""macOS app permission audit via the TCC (Transparency, Consent, and Control) database."""

from __future__ import annotations

import platform
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel

# TCC service identifiers mapped to human-readable names and risk tiers.
# Risk tiers determine the score penalty per granted app.
_SERVICE_INFO: dict[str, tuple[str, ThreatLevel, int, int]] = {
    # service -> (friendly_name, threat_level, per_app_penalty, cap)
    "kTCCServiceAccessibility": ("Accessibility", ThreatLevel.CRITICAL, 10, 30),
    "kTCCServiceSystemPolicyAllFiles": ("Full Disk Access", ThreatLevel.CRITICAL, 5, 20),
    "kTCCServiceScreenCapture": ("Screen Recording", ThreatLevel.HIGH, 5, 15),
    "kTCCServiceCamera": ("Camera", ThreatLevel.HIGH, 3, 15),
    "kTCCServiceMicrophone": ("Microphone", ThreatLevel.HIGH, 3, 15),
    "kTCCServiceAddressBook": ("Contacts", ThreatLevel.MEDIUM, 2, 10),
    "kTCCServiceCalendar": ("Calendar", ThreatLevel.MEDIUM, 2, 10),
    "kTCCServicePhotos": ("Photos", ThreatLevel.MEDIUM, 2, 10),
    "kTCCServiceLocation": ("Location", ThreatLevel.MEDIUM, 2, 10),
    "kTCCServiceReminders": ("Reminders", ThreatLevel.LOW, 1, 5),
    "kTCCServiceMediaLibrary": ("Media Library", ThreatLevel.LOW, 1, 5),
    "kTCCServiceBluetoothPeripheral": ("Bluetooth", ThreatLevel.LOW, 1, 5),
}

# Services considered "high-risk" for over-permission detection
_HIGH_RISK_SERVICES: frozenset[str] = frozenset(
    {
        "kTCCServiceAccessibility",
        "kTCCServiceSystemPolicyAllFiles",
        "kTCCServiceScreenCapture",
        "kTCCServiceCamera",
        "kTCCServiceMicrophone",
        "kTCCServiceAddressBook",
        "kTCCServiceLocation",
    }
)

# TCC auth_value for "allowed"
_AUTH_ALLOWED = 2


def _friendly_service_name(service: str) -> str:
    """Map a TCC service identifier to a human-readable name."""
    info = _SERVICE_INFO.get(service)
    if info:
        return info[0]
    # Strip the kTCCService prefix for unknown services
    if service.startswith("kTCCService"):
        return service[len("kTCCService") :]
    return service


def _get_tcc_db_path() -> Path:
    """Return the path to the user-level TCC database."""
    return Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"


def _read_tcc_db(db_path: Path) -> list[tuple[str, str, int]]:
    """Read granted permissions from the TCC database.

    Returns a list of (service, client, auth_value) tuples.
    Opens the database in read-only mode to guarantee no modifications.
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT service, client, auth_value FROM access")
        return cursor.fetchall()
    finally:
        conn.close()


def _classify_permissions(
    rows: list[tuple[str, str, int]],
) -> dict[str, list[str]]:
    """Group granted apps by service.

    Only includes rows where auth_value == 2 (allowed).
    Returns {service: [app1, app2, ...]}.
    """
    by_service: dict[str, list[str]] = defaultdict(list)
    for service, client, auth_value in rows:
        if auth_value == _AUTH_ALLOWED:
            by_service[service].append(client)
    return dict(by_service)


def _find_over_permissioned(
    by_service: dict[str, list[str]],
) -> list[tuple[str, list[str]]]:
    """Find apps that have 3 or more high-risk permissions.

    Returns [(app, [service1, service2, ...]), ...].
    """
    app_permissions: dict[str, list[str]] = defaultdict(list)
    for service, apps in by_service.items():
        if service in _HIGH_RISK_SERVICES:
            for app in apps:
                app_permissions[app].append(service)

    return [
        (app, services) for app, services in sorted(app_permissions.items()) if len(services) >= 3
    ]


def _find_camera_mic_combo(by_service: dict[str, list[str]]) -> list[str]:
    """Find apps that have both Camera and Microphone access."""
    camera_apps = set(by_service.get("kTCCServiceCamera", []))
    mic_apps = set(by_service.get("kTCCServiceMicrophone", []))
    return sorted(camera_apps & mic_apps)


async def audit_app_permissions(**kwargs: Any) -> AuditResult:
    """Audit macOS app permissions via the TCC database."""
    findings: list[Finding] = []
    score = 100
    raw_data: dict[str, Any] = {"platform": platform.system()}

    # Platform guard — macOS only
    if platform.system() != "Darwin":
        findings.append(
            Finding(
                title="App permission audit is macOS-only",
                description=(
                    "The TCC (Transparency, Consent, and Control) permission database "
                    "is a macOS feature. This audit is not applicable on other platforms."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed on this platform.",
            )
        )
        return AuditResult(
            module_name="app_permissions",
            score=100,
            findings=findings,
            raw_data=raw_data,
        )

    # Read TCC database
    db_path = _get_tcc_db_path()
    if not db_path.exists():
        findings.append(
            Finding(
                title="TCC database not found",
                description=(
                    f"Could not find the TCC database at {db_path}. "
                    "This may indicate a non-standard macOS installation."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation="Verify your macOS installation is up to date.",
            )
        )
        return AuditResult(
            module_name="app_permissions",
            score=80,
            findings=findings,
            raw_data=raw_data,
        )

    try:
        rows = _read_tcc_db(db_path)
    except (sqlite3.OperationalError, PermissionError, OSError):
        findings.append(
            Finding(
                title="Cannot read TCC database",
                description=(
                    "Permission denied when reading the TCC database. "
                    "Your terminal application needs Full Disk Access to read "
                    "app permission records."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Grant Full Disk Access to your terminal:\n"
                    "System Settings > Privacy & Security > Full Disk Access > "
                    "toggle on your terminal app (Terminal, iTerm2, etc.)"
                ),
            )
        )
        return AuditResult(
            module_name="app_permissions",
            score=50,
            findings=findings,
            raw_data=raw_data,
        )

    by_service = _classify_permissions(rows)
    total_grants = sum(len(apps) for apps in by_service.values())
    raw_data["total_grants"] = total_grants
    raw_data["by_service"] = {_friendly_service_name(s): apps for s, apps in by_service.items()}

    # --- Per-service findings ---
    for service, (friendly_name, threat_level, penalty, cap) in _SERVICE_INFO.items():
        apps = by_service.get(service, [])
        if not apps:
            continue

        count = len(apps)
        app_list = ", ".join(sorted(apps))

        if threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            description_extra = {
                "Accessibility": (
                    "Accessibility access is the most powerful permission on macOS. "
                    "Apps with this permission can simulate keyboard/mouse input, "
                    "read screen contents, and monitor all user activity — effectively "
                    "acting as a keylogger."
                ),
                "Full Disk Access": (
                    "Full Disk Access grants unrestricted file system access including "
                    "SSH keys, .env files, browser databases, email, and encrypted vaults. "
                    "A compromised app with FDA can exfiltrate all your data."
                ),
                "Screen Recording": (
                    "Screen Recording access allows an app to capture everything visible "
                    "on your screen, including passwords as you type them, private messages, "
                    "and confidential documents."
                ),
                "Camera": (
                    "Camera access allows an app to capture video at any time while it's "
                    "running. A compromised app could surveil you without your knowledge."
                ),
                "Microphone": (
                    "Microphone access allows an app to record audio at any time while it's "
                    "running. A compromised app could eavesdrop on conversations."
                ),
            }.get(friendly_name, "")

            findings.append(
                Finding(
                    title=f"{count} app(s) with {friendly_name} access",
                    description=(
                        f"The following apps have {friendly_name} permission: {app_list}. "
                        f"{description_extra}"
                    ),
                    threat_level=threat_level,
                    remediation=(
                        f"Review each app's need for {friendly_name} access. Revoke in: "
                        f"System Settings > Privacy & Security > {friendly_name}"
                    ),
                )
            )
        elif threat_level == ThreatLevel.MEDIUM:
            findings.append(
                Finding(
                    title=f"{count} app(s) with {friendly_name} access",
                    description=(
                        f"The following apps have {friendly_name} permission: {app_list}. "
                        f"Review whether each app genuinely needs access to your {friendly_name.lower()} data."
                    ),
                    threat_level=threat_level,
                    remediation=(
                        f"Revoke unnecessary {friendly_name} access in: "
                        f"System Settings > Privacy & Security > {friendly_name}"
                    ),
                )
            )

        # Apply score penalty with cap
        deduction = min(count * penalty, cap)
        score -= deduction

    # --- Camera + Microphone combo ---
    combo_apps = _find_camera_mic_combo(by_service)
    if combo_apps:
        findings.append(
            Finding(
                title=f"{len(combo_apps)} app(s) with Camera + Microphone access",
                description=(
                    f"The following apps have both Camera and Microphone access: "
                    f"{', '.join(combo_apps)}. This combination creates full audio-visual "
                    "surveillance capability. If any of these apps is compromised, an "
                    "attacker can watch and listen to you simultaneously."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Review whether each app truly needs both Camera and Microphone. "
                    "Revoke in: System Settings > Privacy & Security > Camera / Microphone"
                ),
            )
        )

    # --- Over-permissioned apps ---
    over_permissioned = _find_over_permissioned(by_service)
    raw_data["over_permissioned_apps"] = [
        {"app": app, "permissions": [_friendly_service_name(s) for s in services]}
        for app, services in over_permissioned
    ]

    for app, services in over_permissioned:
        friendly_services = [_friendly_service_name(s) for s in services]
        findings.append(
            Finding(
                title=f"Over-permissioned app: {app}",
                description=(
                    f"{app} has {len(services)} high-risk permissions: "
                    f"{', '.join(friendly_services)}. An app with this many sensitive "
                    "permissions represents a significant attack surface. If compromised, "
                    "it could access multiple categories of private data simultaneously."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    f"Audit {app}'s actual functionality and revoke any permissions "
                    "it doesn't strictly need. Consider using a less permissive alternative."
                ),
            )
        )
        score -= 5

    # --- Summary ---
    findings.append(
        Finding(
            title=f"Total: {total_grants} permission grant(s) across {len(by_service)} categories",
            description=(
                "This is the total number of app permission grants found in your TCC database. "
                "Each grant represents a trust decision — fewer grants means a smaller attack surface."
            ),
            threat_level=ThreatLevel.INFO,
            remediation="Review permissions periodically in System Settings > Privacy & Security.",
        )
    )

    score = max(0, min(100, score))

    return AuditResult(
        module_name="app_permissions",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
