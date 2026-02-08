"""Location data leakage audit — Wi-Fi history, timezone mismatch, location grants."""

from __future__ import annotations

import os
import platform
import plistlib
import re
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel

# --- Wi-Fi SSID patterns that reveal physical locations ---

_HOTEL_PATTERN = re.compile(
    r"Marriott|Hilton|Hyatt|Holiday.?Inn|Best.?Western|Sheraton|Radisson|"
    r"Westin|Courtyard|Hampton|Fairfield|Residence.?Inn|Crowne.?Plaza|"
    r"InterContinental|Novotel|Mercure|Ibis|Accor|Wyndham|La.?Quinta|"
    r"Comfort.?Inn|Quality.?Inn|Days.?Inn|Motel|Airbnb",
    re.IGNORECASE,
)

_AIRPORT_PATTERN = re.compile(
    r"(?:^|\b)(?:SFO|LAX|JFK|CDG|LHR|ORD|ATL|DFW|DEN|MIA|SEA|BOS|"
    r"EWR|IAD|PHX|MCO|MSP|DTW|FLL|IAH|SAN|TPA|PDX|STL|SLC|AUS|"
    r"RDU|BNA|MCI|OAK|SMF|SJC|HNL|FCO|AMS|FRA|MAD|BCN|MUC|ZRH|"
    r"NRT|HND|ICN|SIN|HKG|BKK|DXB|DOH)(?:\b|[-_. ])"
    r"|Airport|Terminal|Lounge|Gate.?\d",
    re.IGNORECASE,
)

_PUBLIC_PATTERN = re.compile(
    r"Starbucks|McDonald|Dunkin|Panera|Chipotle|Subway|"
    r"Amtrak|Greyhound|Metro|Transit|"
    r"Library|Hospital|Clinic|University|College|School|Campus|"
    r"Museum|Convention|Conference|Arena|Stadium|"
    r"Free.?Wi.?Fi|Guest|Public|Visitor",
    re.IGNORECASE,
)

# macOS Wi-Fi preferences plist paths
_WIFI_PLIST_PATHS = [
    Path("/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"),
    Path("/Library/Preferences/com.apple.wifi.known-networks.plist"),
]

# TCC auth_value for "allowed"
_AUTH_ALLOWED = 2


# ---------------------------------------------------------------------------
# Phase 1: Wi-Fi SSID history (macOS only)
# ---------------------------------------------------------------------------


def _read_wifi_plist() -> list[dict[str, Any]] | None:
    """Read remembered Wi-Fi networks from macOS plist files.

    Returns a list of network dicts with at least an 'SSID' key,
    or None if the plist cannot be read.
    """
    for plist_path in _WIFI_PLIST_PATHS:
        if not plist_path.exists():
            continue
        try:
            with plist_path.open("rb") as f:
                data = plistlib.load(f)
        except (PermissionError, OSError, plistlib.InvalidFileException):
            continue

        # Legacy format: KnownNetworks or RememberedNetworks list
        networks: list[dict[str, Any]] = []

        # com.apple.airport.preferences.plist format
        if "KnownNetworks" in data:
            for _key, net_info in data["KnownNetworks"].items():
                ssid = net_info.get("SSIDString", net_info.get("SSID_STR", ""))
                if ssid:
                    networks.append(
                        {
                            "SSID": ssid,
                            "SecurityType": net_info.get("SecurityType", ""),
                        }
                    )
            if networks:
                return networks

        # com.apple.wifi.known-networks.plist format (macOS 14+)
        # Keys are SSIDs directly or network identifiers
        if isinstance(data, dict) and not networks:
            for key, net_info in data.items():
                if isinstance(net_info, dict):
                    ssid = net_info.get("SSIDString", key)
                    networks.append(
                        {
                            "SSID": str(ssid),
                            "SecurityType": net_info.get("SecurityType", ""),
                        }
                    )
            if networks:
                return networks

    return None


def _read_wifi_networksetup() -> list[dict[str, Any]] | None:
    """Fall back to networksetup CLI to list preferred Wi-Fi networks."""
    try:
        result = subprocess.run(
            ["networksetup", "-listpreferredwirelessnetworks", "en0"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    networks: list[dict[str, Any]] = []
    for line in result.stdout.splitlines()[1:]:  # skip header line
        ssid = line.strip()
        if ssid:
            networks.append({"SSID": ssid, "SecurityType": ""})

    return networks if networks else None


def _classify_ssid(ssid: str) -> str | None:
    """Check if an SSID reveals a physical location.

    Returns the category name or None.
    """
    if _HOTEL_PATTERN.search(ssid):
        return "hotel"
    if _AIRPORT_PATTERN.search(ssid):
        return "airport/transit"
    if _PUBLIC_PATTERN.search(ssid):
        return "public venue"
    return None


def _is_open_network(security_type: str) -> bool:
    """Check if a network has no security (open network)."""
    if not security_type:
        return False  # unknown security, don't flag
    lower = security_type.lower()
    return "none" in lower or "open" in lower


def _audit_wifi_history() -> tuple[list[Finding], int, dict[str, Any]]:
    """Audit remembered Wi-Fi networks for location-revealing SSIDs."""
    findings: list[Finding] = []
    deduction = 0
    raw: dict[str, Any] = {}

    if platform.system() != "Darwin":
        return findings, 0, raw

    # Try plist first, fall back to networksetup
    networks = _read_wifi_plist()
    if networks is None:
        networks = _read_wifi_networksetup()

    if networks is None:
        findings.append(
            Finding(
                title="Cannot read Wi-Fi network history",
                description=(
                    "Unable to read remembered Wi-Fi networks. The Wi-Fi preferences "
                    "plist may require elevated permissions to read."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Run the audit with elevated permissions, or check manually:\n"
                    "networksetup -listpreferredwirelessnetworks en0"
                ),
            )
        )
        return findings, 0, raw

    ssids = [n["SSID"] for n in networks]
    raw["wifi_networks_count"] = len(ssids)
    raw["ssids"] = ssids

    # Check 1: Large history
    if len(ssids) > 20:
        findings.append(
            Finding(
                title=f"Large Wi-Fi history ({len(ssids)} remembered networks)",
                description=(
                    f"Your device remembers {len(ssids)} Wi-Fi networks. Each remembered "
                    "network is a location marker — SSIDs like hotel names, airport codes, "
                    "and workplace networks reveal your movement history to anyone with "
                    "access to your device."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Remove networks you no longer use:\n"
                    "System Settings > Wi-Fi > click (i) next to each network > "
                    "Forget This Network"
                ),
            )
        )
        deduction += 10

    # Check 2: Location-revealing SSIDs
    revealing: dict[str, list[str]] = {}
    for ssid in ssids:
        category = _classify_ssid(ssid)
        if category:
            revealing.setdefault(category, []).append(ssid)

    raw["revealing_ssids"] = revealing

    if revealing:
        all_revealing = []
        for cat, cat_ssids in revealing.items():
            all_revealing.extend(f"{s} ({cat})" for s in cat_ssids)

        findings.append(
            Finding(
                title=f"Location-revealing Wi-Fi networks ({len(all_revealing)} found)",
                description=(
                    "The following remembered Wi-Fi networks reveal specific locations "
                    "you have visited:\n"
                    + "\n".join(f"  - {s}" for s in all_revealing[:15])
                    + (
                        f"\n  ... and {len(all_revealing) - 15} more"
                        if len(all_revealing) > 15
                        else ""
                    )
                    + "\n\nAnyone with access to your device can reconstruct your travel "
                    "history from this data."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Remove location-revealing networks you no longer need:\n"
                    "System Settings > Wi-Fi > click (i) > Forget This Network\n"
                    "Or via CLI: networksetup -removepreferredwirelessnetwork en0 'SSID'"
                ),
            )
        )
        deduction += min(len(all_revealing) * 5, 15)

    # Check 3: Open/unsecured networks
    open_networks = [n["SSID"] for n in networks if _is_open_network(n.get("SecurityType", ""))]
    raw["open_networks"] = open_networks

    if open_networks:
        findings.append(
            Finding(
                title=f"Open (unsecured) Wi-Fi networks remembered ({len(open_networks)})",
                description=(
                    "The following remembered networks have no encryption: "
                    + ", ".join(open_networks[:10])
                    + ". Open networks allow anyone nearby to intercept your traffic. "
                    "Your device will auto-join these networks when in range."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Remove open networks and disable auto-join for any you must keep:\n"
                    "System Settings > Wi-Fi > click (i) > Auto-Join off"
                ),
            )
        )
        deduction += min(len(open_networks) * 5, 10)

    return findings, deduction, raw


# ---------------------------------------------------------------------------
# Phase 2: Timezone vs VPN mismatch (cross-platform)
# ---------------------------------------------------------------------------

_GEOLOCATION_API = "https://ipapi.co/json/"
_API_TIMEOUT = 5.0


def _get_system_timezone() -> str:
    """Get the system timezone name (e.g., 'America/New_York')."""
    # Try resolving /etc/localtime symlink (macOS/Linux)
    localtime = Path("/etc/localtime")
    if localtime.is_symlink():
        target = str(os.readlink(localtime))
        # Extract timezone from path like /usr/share/zoneinfo/America/New_York
        if "zoneinfo/" in target:
            return target.split("zoneinfo/", 1)[1]

    # Fallback: use time.tzname
    tz = time.tzname[0]
    return tz if tz else "Unknown"


def _get_timezone_region(tz_name: str) -> str:
    """Extract the broad geographic region from a timezone name.

    'America/New_York' -> 'America'
    'Europe/London' -> 'Europe'
    'EST' -> 'Unknown'
    """
    if "/" in tz_name:
        return tz_name.split("/", 1)[0]
    return "Unknown"


async def _audit_timezone_mismatch() -> tuple[list[Finding], int, dict[str, Any]]:
    """Compare system timezone against IP geolocation to detect VPN leaks."""
    findings: list[Finding] = []
    deduction = 0
    raw: dict[str, Any] = {}

    system_tz = _get_system_timezone()
    raw["system_timezone"] = system_tz

    # Query IP geolocation
    try:
        async with httpx.AsyncClient(timeout=_API_TIMEOUT) as client:
            resp = await client.get(_GEOLOCATION_API)
            resp.raise_for_status()
            geo_data = resp.json()
    except (httpx.HTTPError, ValueError, KeyError):
        raw["ip_timezone"] = None
        raw["timezone_match"] = None
        findings.append(
            Finding(
                title="Could not check timezone/IP mismatch",
                description=(
                    "Unable to query IP geolocation service. The timezone vs VPN "
                    "mismatch check requires network access."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="Ensure you have internet access and retry.",
            )
        )
        return findings, 0, raw

    ip_tz = geo_data.get("timezone", "")
    raw["ip_timezone"] = ip_tz
    raw["ip_country"] = geo_data.get("country_name", "")
    raw["ip_city"] = geo_data.get("city", "")

    system_region = _get_timezone_region(system_tz)
    ip_region = _get_timezone_region(ip_tz)

    # Only flag if both regions are known and they differ
    if system_region != "Unknown" and ip_region != "Unknown" and system_region != ip_region:
        raw["timezone_match"] = False
        findings.append(
            Finding(
                title="Timezone/IP mismatch detected",
                description=(
                    f"Your system timezone is {system_tz} ({system_region}) but your "
                    f"IP address geolocates to {ip_tz} ({ip_region}). "
                    "This mismatch reveals your true geographic region even when using "
                    "a VPN. Websites and trackers can compare your browser's timezone "
                    "against your IP location to detect VPN use and infer your real location."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Set your timezone to match your VPN exit location:\n"
                    "System Settings > General > Date & Time > disable 'Set time zone "
                    "automatically' > select the timezone matching your VPN server"
                ),
            )
        )
        deduction += 15
    else:
        raw["timezone_match"] = True
        findings.append(
            Finding(
                title="Timezone consistent with IP location",
                description=(
                    f"Your system timezone ({system_tz}) is in the same region as "
                    f"your IP geolocation ({ip_tz}). No timezone-based location leak detected."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )

    return findings, deduction, raw


# ---------------------------------------------------------------------------
# Phase 3: Location Services grants (macOS only)
# ---------------------------------------------------------------------------


def _get_tcc_db_path() -> Path:
    """Return the path to the user-level TCC database."""
    return Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"


def _audit_location_grants() -> tuple[list[Finding], int, dict[str, Any]]:
    """Audit which apps have Location access via the TCC database."""
    findings: list[Finding] = []
    deduction = 0
    raw: dict[str, Any] = {}

    if platform.system() != "Darwin":
        return findings, 0, raw

    db_path = _get_tcc_db_path()
    if not db_path.exists():
        return findings, 0, raw

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except (sqlite3.OperationalError, PermissionError, OSError):
        findings.append(
            Finding(
                title="Cannot read Location Services permissions",
                description=(
                    "Unable to read the TCC database. Your terminal needs Full Disk "
                    "Access to check location permission grants."
                ),
                threat_level=ThreatLevel.INFO,
                remediation=(
                    "Grant Full Disk Access to your terminal:\n"
                    "System Settings > Privacy & Security > Full Disk Access"
                ),
            )
        )
        return findings, 0, raw

    try:
        cursor = conn.cursor()

        # Get apps with location access
        cursor.execute(
            "SELECT client FROM access WHERE service = 'kTCCServiceLocation' AND auth_value = ?",
            (_AUTH_ALLOWED,),
        )
        location_apps = [row[0] for row in cursor.fetchall()]
        raw["location_apps_count"] = len(location_apps)
        raw["location_apps"] = location_apps

        # Cross-reference with camera and microphone for "tracking suite" detection
        cursor.execute(
            "SELECT client FROM access WHERE service = 'kTCCServiceCamera' AND auth_value = ?",
            (_AUTH_ALLOWED,),
        )
        camera_apps = {row[0] for row in cursor.fetchall()}

        cursor.execute(
            "SELECT client FROM access WHERE service = 'kTCCServiceMicrophone' AND auth_value = ?",
            (_AUTH_ALLOWED,),
        )
        mic_apps = {row[0] for row in cursor.fetchall()}
    finally:
        conn.close()

    # Check: many apps with location access
    if len(location_apps) > 5:
        findings.append(
            Finding(
                title=f"{len(location_apps)} apps with Location access",
                description=(
                    f"The following apps have Location permission: "
                    f"{', '.join(sorted(location_apps))}. "
                    "Each app with location access can track your physical movements. "
                    "Review whether each app genuinely needs this permission."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Revoke unnecessary Location access:\n"
                    "System Settings > Privacy & Security > Location Services"
                ),
            )
        )
        deduction += 10

    # Check: apps with location + camera + microphone (full tracking suite)
    location_set = set(location_apps)
    tracking_suite_apps = sorted(location_set & camera_apps & mic_apps)
    raw["tracking_suite_apps"] = tracking_suite_apps

    if tracking_suite_apps:
        findings.append(
            Finding(
                title=f"Full tracking suite: {len(tracking_suite_apps)} app(s) with Location + Camera + Microphone",
                description=(
                    f"The following apps have Location, Camera, and Microphone access: "
                    f"{', '.join(tracking_suite_apps)}. "
                    "An app with all three permissions is a complete surveillance toolkit — "
                    "it can track where you are, watch you, and listen to you simultaneously. "
                    "If compromised, an attacker has full physical surveillance capability."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Review each app's need for all three permissions. "
                    "Revoke any that aren't strictly necessary:\n"
                    "System Settings > Privacy & Security > Location Services / Camera / Microphone"
                ),
            )
        )
        deduction += min(len(tracking_suite_apps) * 5, 15)

    return findings, deduction, raw


# ---------------------------------------------------------------------------
# Main audit function
# ---------------------------------------------------------------------------


async def audit_location(**kwargs: Any) -> AuditResult:
    """Audit location data leakage across Wi-Fi, timezone, and permissions."""
    findings: list[Finding] = []
    total_deduction = 0
    raw_data: dict[str, Any] = {"platform": platform.system()}

    # Phase 1: Wi-Fi SSID history (macOS only)
    wifi_findings, wifi_deduction, wifi_raw = _audit_wifi_history()
    findings.extend(wifi_findings)
    total_deduction += wifi_deduction
    raw_data.update(wifi_raw)

    # Phase 2: Timezone vs VPN mismatch (cross-platform)
    tz_findings, tz_deduction, tz_raw = await _audit_timezone_mismatch()
    findings.extend(tz_findings)
    total_deduction += tz_deduction
    raw_data.update(tz_raw)

    # Phase 3: Location Services grants (macOS only)
    loc_findings, loc_deduction, loc_raw = _audit_location_grants()
    findings.extend(loc_findings)
    total_deduction += loc_deduction
    raw_data.update(loc_raw)

    score = max(0, min(100, 100 - total_deduction))

    return AuditResult(
        module_name="location",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
