"""Social media tracker detection — audit browser defenses and exposure."""

from __future__ import annotations

import platform
import re
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.modules.fingerprint.browsers import (
    BrowserProfile,
    _safe_read_json,
    find_browser_profiles,
)
from dont_track_me.modules.social.trackers import (
    ANTI_TRACKER_EXTENSIONS,
    ANTI_TRACKER_NAME_PATTERNS,
    SOCIAL_HOSTS_BLOCKLIST,
    TRACKER_BLOCKING_DNS,
    is_social_tracker,
)

MAX_DB_SIZE = 500 * 1024 * 1024  # 500 MB


def _check_tracking_protection(
    profiles: list[BrowserProfile],
) -> tuple[list[Finding], int]:
    """Check browser tracking protection level."""
    findings: list[Finding] = []
    score_delta = 0

    firefox_profiles = [p for p in profiles if p.browser == "firefox"]
    chrome_profiles = [p for p in profiles if p.browser in ("chrome", "brave")]

    # Firefox Enhanced Tracking Protection
    if firefox_profiles:
        best_category = "standard"
        social_tp = False

        for profile in firefox_profiles:
            category = profile.prefs.get("browser.contentblocking.category", "standard")
            if category == "strict":
                best_category = "strict"
            elif category == "custom" and best_category != "strict":
                best_category = "custom"

            if profile.prefs.get("privacy.trackingprotection.socialtracking.enabled") is True:
                social_tp = True

        if best_category == "strict":
            findings.append(
                Finding(
                    title="Firefox Enhanced Tracking Protection: Strict",
                    description=(
                        "ETP Strict blocks all known trackers, cross-site cookies, "
                        "fingerprinters, and cryptominers. Social media trackers from "
                        "Facebook, Twitter, and LinkedIn are blocked."
                    ),
                    threat_level=ThreatLevel.INFO,
                    remediation="No action needed.",
                )
            )
        elif social_tp:
            findings.append(
                Finding(
                    title="Firefox social tracking protection enabled",
                    description=(
                        "Social tracking protection is enabled, but ETP is not set to "
                        "Strict. Strict mode provides stronger overall protection."
                    ),
                    threat_level=ThreatLevel.LOW,
                    remediation=(
                        "Set Enhanced Tracking Protection to Strict: "
                        "Settings > Privacy & Security > Strict."
                    ),
                )
            )
            score_delta -= 5
        else:
            findings.append(
                Finding(
                    title="Firefox tracking protection not set to Strict",
                    description=(
                        "Enhanced Tracking Protection is not on Strict mode and social "
                        "tracking protection is not explicitly enabled. Social media "
                        "trackers from Meta, Twitter, and LinkedIn may load on websites."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        "Set ETP to Strict: Settings > Privacy & Security > Strict. "
                        "Or enable privacy.trackingprotection.socialtracking.enabled "
                        "in about:config."
                    ),
                )
            )
            score_delta -= 20

    # Chrome/Brave tracking protection
    if chrome_profiles:
        any_blocks_third_party = False

        for profile in chrome_profiles:
            prefs = _safe_read_json(profile.profile_path / "Preferences")
            if prefs is None:
                continue

            # Check third-party cookie blocking
            content_settings = prefs.get("profile", {})
            if isinstance(content_settings, dict):
                block_tp = content_settings.get("block_third_party_cookies", False)
                cookie_behavior = content_settings.get("default_content_setting_values", {})
                if isinstance(cookie_behavior, dict):
                    # 1 = allow, 2 = block all, 4 = block third-party
                    cookies_val = cookie_behavior.get("cookies", 1)
                    if cookies_val in (2, 4) or block_tp:
                        any_blocks_third_party = True
                elif block_tp:
                    any_blocks_third_party = True

        if any_blocks_third_party:
            findings.append(
                Finding(
                    title="Chrome/Brave blocks third-party cookies",
                    description=(
                        "Third-party cookie blocking prevents social media trackers "
                        "from reading their cookies on unrelated websites."
                    ),
                    threat_level=ThreatLevel.INFO,
                    remediation="No action needed.",
                )
            )
        else:
            findings.append(
                Finding(
                    title="Chrome/Brave allows third-party cookies",
                    description=(
                        "Third-party cookies are not blocked. Social media platforms "
                        "can read their tracking cookies on every website that has "
                        "their pixel or SDK installed."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        "Chrome: Settings > Privacy and security > Third-party cookies "
                        "> Block third-party cookies. "
                        "Brave: Settings > Shields > Block cookies > Only cross-site."
                    ),
                )
            )
            score_delta -= 15

    return findings, score_delta


def _check_anti_tracker_extensions(
    profiles: list[BrowserProfile],
) -> tuple[list[Finding], int]:
    """Check for content-blocking browser extensions."""
    findings: list[Finding] = []
    score_delta = 0

    found_extensions: set[str] = set()

    for profile in profiles:
        if profile.browser == "firefox":
            data = _safe_read_json(profile.profile_path / "extensions.json")
            if data is None:
                continue
            for addon in data.get("addons", []):
                if not isinstance(addon, dict):
                    continue
                ext_id = addon.get("id", "")
                if ext_id in ANTI_TRACKER_EXTENSIONS:
                    found_extensions.add(ANTI_TRACKER_EXTENSIONS[ext_id])
                    continue
                name = ""
                default_locale = addon.get("defaultLocale")
                if isinstance(default_locale, dict):
                    name = default_locale.get("name", "")
                if name and any(pat in name.lower() for pat in ANTI_TRACKER_NAME_PATTERNS):
                    found_extensions.add(name)

        elif profile.browser in ("chrome", "brave"):
            data = _safe_read_json(profile.profile_path / "Preferences")
            if data is None:
                continue
            settings = data.get("extensions", {}).get("settings", {})
            if not isinstance(settings, dict):
                continue
            for ext_id, ext_data in settings.items():
                if ext_id in ANTI_TRACKER_EXTENSIONS:
                    found_extensions.add(ANTI_TRACKER_EXTENSIONS[ext_id])
                    continue
                if not isinstance(ext_data, dict):
                    continue
                manifest = ext_data.get("manifest", {})
                if isinstance(manifest, dict):
                    name = manifest.get("name", "")
                    if name and any(pat in name.lower() for pat in ANTI_TRACKER_NAME_PATTERNS):
                        found_extensions.add(name)

    if found_extensions:
        ext_list = ", ".join(sorted(found_extensions))
        findings.append(
            Finding(
                title=f"Anti-tracker extensions found: {ext_list}",
                description=(
                    f"Detected {len(found_extensions)} content-blocking extension(s). "
                    "These block social media trackers, pixels, and tracking scripts."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed — keep extensions updated.",
            )
        )
    elif profiles:
        findings.append(
            Finding(
                title="No anti-tracker extensions detected",
                description=(
                    "No content-blocking extensions (uBlock Origin, Privacy Badger, "
                    "Ghostery, etc.) were found. Without these, social media trackers "
                    "load freely on every website you visit."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Install uBlock Origin (best open-source blocker) or Privacy Badger. "
                    "Both are available for Firefox, Chrome, and Brave."
                ),
            )
        )
        score_delta -= 15

    return findings, score_delta


def _find_cookie_databases() -> list[tuple[Path, str]]:
    """Auto-detect Chrome and Firefox cookie database paths.

    Returns list of (path, browser_name) tuples.
    """
    databases: list[tuple[Path, str]] = []
    home = Path.home()
    system = platform.system()

    search_paths: list[tuple[Path, str, str]] = []

    if system == "Darwin":
        search_paths = [
            (home / "Library" / "Application Support" / "Google" / "Chrome", "chrome", "Cookies"),
            (
                home / "Library" / "Application Support" / "Firefox" / "Profiles",
                "firefox",
                "cookies.sqlite",
            ),
        ]
    elif system == "Linux":
        search_paths = [
            (home / ".config" / "google-chrome", "chrome", "Cookies"),
            (home / ".mozilla" / "firefox", "firefox", "cookies.sqlite"),
        ]

    for base_path, browser, db_name in search_paths:
        if not base_path.exists() or base_path.is_symlink():
            continue
        for profile_dir in base_path.iterdir():
            if not profile_dir.is_dir() or profile_dir.is_symlink():
                continue
            cookie_db = profile_dir / db_name
            if cookie_db.is_file() and not cookie_db.is_symlink():
                databases.append((cookie_db, browser))

    return databases


def _read_cookie_hosts(db_path: Path, browser: str) -> list[str]:
    """Read distinct cookie hostnames from a browser database.

    Copies to temp to avoid WAL lock conflicts. Returns list of hostnames.
    """
    try:
        if db_path.stat().st_size > MAX_DB_SIZE:
            return []
    except OSError:
        return []

    tmp_dir = tempfile.mkdtemp()
    tmp_db = Path(tmp_dir) / db_path.name
    try:
        shutil.copy2(db_path, tmp_db)
        for suffix in ("-wal", "-shm"):
            wal = db_path.parent / (db_path.name + suffix)
            if wal.exists() and not wal.is_symlink():
                shutil.copy2(wal, Path(tmp_dir) / (db_path.name + suffix))

        conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True)
        try:
            cursor = conn.cursor()
            if browser == "chrome":
                cursor.execute("SELECT DISTINCT host_key FROM cookies")
            else:
                cursor.execute("SELECT DISTINCT host FROM moz_cookies")
            return [row[0] for row in cursor.fetchall()]
        finally:
            conn.close()
    except (OSError, sqlite3.Error):
        return []
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _check_social_cookies() -> tuple[list[Finding], int, dict[str, Any]]:
    """Check browser cookie databases for social tracker cookies."""
    findings: list[Finding] = []
    score_delta = 0
    raw: dict[str, Any] = {}

    databases = _find_cookie_databases()
    platform_cookies: dict[str, set[str]] = {}  # platform -> set of matched domains

    for db_path, browser in databases:
        hosts = _read_cookie_hosts(db_path, browser)
        for host in hosts:
            is_social, matched, plat = is_social_tracker(host)
            if is_social:
                platform_cookies.setdefault(plat, set()).add(matched)

    raw["platforms_with_cookies"] = sorted(platform_cookies.keys())
    raw["social_cookie_domains"] = {
        plat: sorted(domains) for plat, domains in platform_cookies.items()
    }

    if platform_cookies:
        for plat, domains in sorted(platform_cookies.items()):
            domain_list = ", ".join(sorted(domains))
            findings.append(
                Finding(
                    title=f"{plat} tracking cookies found",
                    description=(
                        f"Cookies from {plat} tracker domains ({domain_list}) are present "
                        "in your browser. These allow cross-site tracking even when you're "
                        "not visiting the platform directly."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        f"Delete {plat} cookies with 'dtm protect social --apply'. "
                        "Block third-party cookies in browser settings to prevent them "
                        "from being set again."
                    ),
                )
            )

        # Cap at -40
        score_delta = max(-40, -5 * len(platform_cookies))
    else:
        findings.append(
            Finding(
                title="No social tracker cookies found",
                description="No cookies from known social media tracker domains were detected.",
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )

    return findings, score_delta, raw


def _read_hosts_file() -> set[str]:
    """Read blocked domains from /etc/hosts. Returns set of blocked hostnames."""
    blocked: set[str] = set()
    try:
        with open("/etc/hosts") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    for host in parts[1:]:
                        if host.startswith("#"):
                            break
                        blocked.add(host.lower())
    except OSError:
        pass
    return blocked


def _check_hosts_file() -> tuple[list[Finding], int]:
    """Check if /etc/hosts blocks social tracker domains."""
    findings: list[Finding] = []
    score_delta = 0

    blocked = _read_hosts_file()
    blocklist_set = {d.lower() for d in SOCIAL_HOSTS_BLOCKLIST}
    matched = blocked & blocklist_set
    ratio = len(matched) / len(blocklist_set) if blocklist_set else 0

    if ratio > 0.5:
        findings.append(
            Finding(
                title=f"Hosts file blocks {len(matched)}/{len(blocklist_set)} social tracker domains",
                description=(
                    "Your /etc/hosts file blocks most known social media tracker "
                    "pixel and SDK domains at the system level."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )
    elif matched:
        findings.append(
            Finding(
                title=f"Hosts file blocks {len(matched)}/{len(blocklist_set)} social tracker domains",
                description=(
                    "Some social tracker domains are blocked in /etc/hosts, but many "
                    "pixel and SDK domains remain accessible."
                ),
                threat_level=ThreatLevel.LOW,
                remediation=(
                    "Add more social tracker domains to /etc/hosts. "
                    "Use 'dtm protect social' to see the recommended blocklist."
                ),
            )
        )
        score_delta -= 5
    else:
        findings.append(
            Finding(
                title="No social tracker domains blocked in /etc/hosts",
                description=(
                    "/etc/hosts does not block any known social media tracker domains. "
                    "Hosts-level blocking prevents tracker requests before the browser "
                    "even makes them."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Add social tracker domains to /etc/hosts (requires root). "
                    "Or use a tracker-blocking DNS like NextDNS or AdGuard DNS."
                ),
            )
        )
        score_delta -= 10

    return findings, score_delta


def _get_system_dns_servers() -> list[str]:
    """Get currently configured DNS servers from the system."""
    servers: list[str] = []

    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("nameserver["):
                        match = re.search(r":\s*(\S+)", line)
                        if match:
                            servers.append(match.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not servers:
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except FileNotFoundError:
            pass

    return list(dict.fromkeys(servers))


def _check_dns_blocking() -> tuple[list[Finding], int]:
    """Check if the system uses a tracker-blocking DNS resolver."""
    findings: list[Finding] = []
    score_delta = 0

    servers = _get_system_dns_servers()
    blocking_dns: list[str] = []
    local_dns = False

    for server in servers:
        if server in TRACKER_BLOCKING_DNS:
            blocking_dns.append(f"{TRACKER_BLOCKING_DNS[server]} ({server})")
        elif server in ("127.0.0.1", "::1") or server.startswith("192.168."):
            local_dns = True

    if blocking_dns:
        dns_list = ", ".join(blocking_dns)
        findings.append(
            Finding(
                title=f"Tracker-blocking DNS detected: {dns_list}",
                description=(
                    "Your DNS resolver blocks known tracker and ad domains at the "
                    "network level, preventing social media trackers from resolving."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )
    elif local_dns:
        findings.append(
            Finding(
                title="Local DNS resolver detected (possible Pi-hole or AdGuard Home)",
                description=(
                    "Your DNS points to a local address, which may indicate a "
                    "Pi-hole or AdGuard Home setup. If configured with blocklists, "
                    "this blocks social media trackers at the network level."
                ),
                threat_level=ThreatLevel.INFO,
                remediation=(
                    "Ensure your local DNS has tracker blocklists enabled. "
                    "Popular lists: AdGuard DNS filter, EasyList, Peter Lowe's ad list."
                ),
            )
        )
    else:
        findings.append(
            Finding(
                title="No tracker-blocking DNS detected",
                description=(
                    "Your DNS resolver does not appear to block tracker domains. "
                    "DNS-level blocking prevents social media trackers from resolving "
                    "across all applications, not just the browser."
                ),
                threat_level=ThreatLevel.LOW,
                remediation=(
                    "Switch to a tracker-blocking DNS: NextDNS (45.90.28.0), "
                    "AdGuard DNS (94.140.14.14), or Mullvad DNS (194.242.2.4). "
                    "Or set up a Pi-hole for whole-network blocking."
                ),
            )
        )
        score_delta -= 10

    return findings, score_delta


async def audit_social(**kwargs: Any) -> AuditResult:
    """Audit social media tracker exposure and browser defenses."""
    findings: list[Finding] = []
    score = 100

    profiles = find_browser_profiles()

    if not profiles:
        findings.append(
            Finding(
                title="No browser profiles found",
                description=(
                    "Could not locate Firefox, Chrome, or Brave profiles. "
                    "Without browser data, social tracker exposure cannot be "
                    "fully assessed."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="Ensure a supported browser is installed.",
            )
        )
        score -= 10

    # Check 1: Browser tracking protection
    tp_findings, tp_delta = _check_tracking_protection(profiles)
    findings.extend(tp_findings)
    score += tp_delta

    # Check 2: Anti-tracker extensions
    ext_findings, ext_delta = _check_anti_tracker_extensions(profiles)
    findings.extend(ext_findings)
    score += ext_delta

    # Check 3: Social tracker cookies
    cookie_findings, cookie_delta, cookie_raw = _check_social_cookies()
    findings.extend(cookie_findings)
    score += cookie_delta

    # Check 4: Hosts-file blocking
    hosts_findings, hosts_delta = _check_hosts_file()
    findings.extend(hosts_findings)
    score += hosts_delta

    # Check 5: DNS-level blocking
    dns_findings, dns_delta = _check_dns_blocking()
    findings.extend(dns_findings)
    score += dns_delta

    score = max(0, min(100, score))

    return AuditResult(
        module_name="social",
        score=score,
        findings=findings,
        raw_data={
            "browsers_found": sorted({p.browser for p in profiles}),
            "profiles_scanned": len(profiles),
            **cookie_raw,
        },
    )
