"""Advertising data ecosystem audit — IDFA, browser privacy, data broker exposure."""

from __future__ import annotations

import platform
import plistlib
import subprocess
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.modules.ad_tracking.brokers import load_brokers
from dont_track_me.modules.fingerprint.browsers import (
    BrowserProfile,
    _safe_read_json,
    find_browser_profiles,
)

# ---------------------------------------------------------------------------
# Phase 1: macOS Advertising ID settings
# ---------------------------------------------------------------------------

_ADLIB_DOMAIN = "com.apple.AdLib"


def _defaults_read(domain: str, key: str) -> str | None:
    """Read a single key from a macOS defaults domain.

    Returns the stripped stdout on success, or None on failure.
    """
    try:
        result = subprocess.run(
            ["defaults", "read", domain, key],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    return result.stdout.strip()


def _audit_advertising_id() -> tuple[list[Finding], int, dict[str, Any]]:
    """Audit macOS advertising ID and personalized ads settings."""
    findings: list[Finding] = []
    deduction = 0
    raw: dict[str, Any] = {}

    if platform.system() != "Darwin":
        return findings, 0, raw

    # Check 1: Advertising identifier exposure (IDFA)
    idfa_val = _defaults_read(_ADLIB_DOMAIN, "allowIdentifierForAdvertising")
    raw["allowIdentifierForAdvertising"] = idfa_val

    if idfa_val is None:
        findings.append(
            Finding(
                title="Cannot read advertising ID settings",
                description=(
                    "Unable to read com.apple.AdLib preferences. The advertising "
                    "identifier status could not be determined."
                ),
                threat_level=ThreatLevel.INFO,
                remediation=(
                    "Check manually: System Settings > Privacy & Security > "
                    "Apple Advertising > Personalized Ads"
                ),
            )
        )
    elif idfa_val == "1":
        findings.append(
            Finding(
                title="Advertising identifier (IDFA) is enabled",
                description=(
                    "Your device exposes a persistent Advertising Identifier (IDFA) "
                    "to all apps. This is the primary mechanism that allows data "
                    "brokers to track your movements across apps and build a detailed "
                    "profile of your behavior, location history, and interests. "
                    "In 2024, Le Monde journalists used a dataset of 16 million "
                    "advertising IDs to identify and locate French intelligence agents."
                ),
                threat_level=ThreatLevel.CRITICAL,
                remediation=(
                    "Disable personalized ads:\n"
                    "System Settings > Privacy & Security > Apple Advertising > "
                    "Personalized Ads > off\n"
                    "Or run: dtm protect ad_tracking --apply"
                ),
            )
        )
        deduction += 25
    else:
        findings.append(
            Finding(
                title="Advertising identifier (IDFA) is limited",
                description=(
                    "Personalized ads are disabled. Apps receive a zeroed-out "
                    "advertising identifier, preventing cross-app tracking via IDFA."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )

    # Check 2: Apple personalized advertising
    personalized_val = _defaults_read(_ADLIB_DOMAIN, "allowApplePersonalizedAdvertising")
    raw["allowApplePersonalizedAdvertising"] = personalized_val

    if personalized_val == "1":
        findings.append(
            Finding(
                title="Apple personalized advertising is enabled",
                description=(
                    "Apple uses your data to deliver targeted ads in the App Store, "
                    "Apple News, and Stocks. While Apple's tracking is more limited "
                    "than third-party ad networks, it still builds an interest profile "
                    "from your app usage, purchases, and reading habits."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Disable Apple personalized ads:\n"
                    "System Settings > Privacy & Security > Apple Advertising > "
                    "Personalized Ads > off\n"
                    "Or run: dtm protect ad_tracking --apply"
                ),
            )
        )
        deduction += 15
    elif personalized_val is not None:
        findings.append(
            Finding(
                title="Apple personalized advertising is disabled",
                description=(
                    "Apple's own ad personalization is turned off. Apple will not "
                    "use your data to target ads in App Store, News, or Stocks."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )

    return findings, deduction, raw


# ---------------------------------------------------------------------------
# Phase 2: Safari privacy settings (macOS only)
# ---------------------------------------------------------------------------

_SAFARI_PLIST_PATH = (
    Path.home()
    / "Library"
    / "Containers"
    / "com.apple.Safari"
    / "Data"
    / "Library"
    / "Preferences"
    / "com.apple.Safari.plist"
)


def _get_safari_plist_path() -> Path:
    """Return the path to Safari's sandboxed preferences plist."""
    return _SAFARI_PLIST_PATH


def _read_safari_prefs() -> dict[str, Any] | None:
    """Read Safari's sandboxed preferences plist.

    Returns the parsed dict, or None if the file cannot be read
    (requires Full Disk Access).
    """
    plist_path = _get_safari_plist_path()
    if not plist_path.exists():
        return None

    try:
        with plist_path.open("rb") as f:
            return plistlib.load(f)
    except (PermissionError, OSError, plistlib.InvalidFileException):
        return None


def _audit_safari_privacy() -> tuple[list[Finding], int, dict[str, Any]]:
    """Audit Safari privacy and tracking prevention settings."""
    findings: list[Finding] = []
    deduction = 0
    raw: dict[str, Any] = {}

    if platform.system() != "Darwin":
        return findings, 0, raw

    prefs = _read_safari_prefs()
    raw["safari_prefs_readable"] = prefs is not None

    if prefs is None:
        # Safari not installed or plist not readable (needs FDA)
        plist_path = _get_safari_plist_path()
        if plist_path.parent.exists():
            # Safari is installed but we can't read prefs
            findings.append(
                Finding(
                    title="Cannot read Safari privacy settings",
                    description=(
                        "Safari's preferences are sandboxed and require Full Disk "
                        "Access to read. Grant FDA to your terminal to enable this check."
                    ),
                    threat_level=ThreatLevel.INFO,
                    remediation=(
                        "Grant Full Disk Access to your terminal:\n"
                        "System Settings > Privacy & Security > Full Disk Access"
                    ),
                )
            )
        return findings, 0, raw

    # Check 1: Do Not Track header
    dnt = prefs.get("SendDoNotTrackHTTPHeader", False)
    raw["safari_dnt"] = dnt

    if not dnt:
        findings.append(
            Finding(
                title="Safari Do Not Track header is disabled",
                description=(
                    "Safari is not sending the Do Not Track (DNT) HTTP header. "
                    "While many sites ignore DNT, some privacy-respecting services "
                    "honor it. Enabling it signals your tracking preference."
                ),
                threat_level=ThreatLevel.LOW,
                remediation=(
                    "Enable DNT in Safari:\n"
                    "Safari > Settings > Privacy > "
                    "Prevent cross-site tracking (includes DNT signal)"
                ),
            )
        )
        deduction += 5
    else:
        findings.append(
            Finding(
                title="Safari Do Not Track header is enabled",
                description="Safari sends the DNT header with requests.",
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )

    # Check 2: Third-party cookie blocking
    # BlockStoragePolicy: 2 = block all, 1 = block from third parties, 0 = allow all
    block_policy = prefs.get("BlockStoragePolicy", 2)
    raw["safari_block_storage_policy"] = block_policy

    if block_policy == 0:
        findings.append(
            Finding(
                title="Safari allows all cookies",
                description=(
                    "Safari is configured to allow all cookies including third-party "
                    "tracking cookies. Ad networks and data brokers use these cookies "
                    "to track you across websites."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Block third-party cookies in Safari:\n"
                    "Safari > Settings > Privacy > Block all cookies (or enable "
                    "Prevent cross-site tracking)"
                ),
            )
        )
        deduction += 10
    elif block_policy == 2:
        findings.append(
            Finding(
                title="Safari blocks all cookies",
                description=(
                    "Safari blocks all cookies. This provides maximum protection "
                    "against cookie-based tracking but may break some websites."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )

    # Check 3: Hide IP address from trackers
    # WBSPrivacyProxyAvailabilityTraffic:
    #   262144 = trackers only, 262145 = trackers and websites, 0 = off
    hide_ip = prefs.get("WBSPrivacyProxyAvailabilityTraffic", 0)
    raw["safari_hide_ip"] = hide_ip

    if hide_ip == 0:
        findings.append(
            Finding(
                title="Safari does not hide IP from trackers",
                description=(
                    "Safari's 'Hide IP Address' feature is disabled. Known trackers "
                    "embedded on websites can see your real IP address, which reveals "
                    "your approximate location and ISP."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Enable IP hiding in Safari:\n"
                    "Safari > Settings > Privacy > Hide IP Address > "
                    "From Trackers (or From Trackers and Websites)"
                ),
            )
        )
        deduction += 10

    return findings, deduction, raw


# ---------------------------------------------------------------------------
# Phase 3: Browser ad-tracking settings (cross-platform)
# ---------------------------------------------------------------------------


def _audit_browser_ad_tracking(
    profiles: list[BrowserProfile],
) -> tuple[list[Finding], int, dict[str, Any]]:
    """Audit browser-level ad-tracking protection settings.

    Checks Firefox, Chrome, and Brave for ad-specific privacy settings
    that are not covered by the social module (which focuses on social
    tracker blocking).
    """
    findings: list[Finding] = []
    deduction = 0
    raw: dict[str, Any] = {}

    firefox_profiles = [p for p in profiles if p.browser == "firefox"]
    chrome_profiles = [p for p in profiles if p.browser == "chrome"]
    brave_profiles = [p for p in profiles if p.browser == "brave"]

    raw["browsers_found"] = sorted({p.browser for p in profiles})

    # --- Firefox: DNT header and cookie behavior ---
    if firefox_profiles:
        # Use the best (most private) settings across all profiles
        any_dnt = any(
            p.prefs.get("privacy.donottrackheader.enabled", False) for p in firefox_profiles
        )
        raw["firefox_dnt"] = any_dnt

        if not any_dnt:
            findings.append(
                Finding(
                    title="Firefox Do Not Track header is disabled",
                    description=(
                        "Firefox is not sending the Do Not Track (DNT) header. "
                        "While many ad networks ignore DNT, enabling it is a "
                        "low-cost signal of your tracking preference."
                    ),
                    threat_level=ThreatLevel.LOW,
                    remediation=(
                        "Enable DNT in Firefox:\n"
                        "Settings > Privacy & Security > "
                        "Send websites a 'Do Not Track' request"
                    ),
                )
            )
            deduction += 5

        # Cookie behavior: 0=allow all, 1=block 3P, 4=block 3P trackers, 5=block all
        best_cookie = max(
            (p.prefs.get("network.cookie.cookieBehavior", 0) for p in firefox_profiles),
            default=0,
        )
        raw["firefox_cookie_behavior"] = best_cookie

        if best_cookie == 0:
            findings.append(
                Finding(
                    title="Firefox allows all cookies",
                    description=(
                        "Firefox is set to accept all cookies including third-party "
                        "ad tracking cookies. Ad networks like DoubleClick, Criteo, "
                        "and AppNexus use these cookies to build cross-site profiles."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation=(
                        "Set Enhanced Tracking Protection to Strict:\n"
                        "Settings > Privacy & Security > Enhanced Tracking Protection > Strict"
                    ),
                )
            )
            deduction += 10

    # --- Chrome: DNT, Topics API, Privacy Sandbox ---
    if chrome_profiles:
        any_chrome_dnt = False
        any_topics_enabled = False
        any_fledge_enabled = False

        for profile in chrome_profiles:
            prefs = _safe_read_json(profile.profile_path / "Preferences")
            if prefs is None:
                continue

            # Do Not Track
            if prefs.get("enable_do_not_track", False):
                any_chrome_dnt = True

            # Privacy Sandbox / Topics API (Google's cookie replacement)
            privacy_sandbox = prefs.get("privacy_sandbox", {})
            if isinstance(privacy_sandbox, dict):
                m1 = privacy_sandbox.get("m1", {})
                if isinstance(m1, dict):
                    if m1.get("topics_enabled", True):
                        any_topics_enabled = True
                    if m1.get("fledge_enabled", True):
                        any_fledge_enabled = True

        raw["chrome_dnt"] = any_chrome_dnt
        raw["chrome_topics_enabled"] = any_topics_enabled
        raw["chrome_fledge_enabled"] = any_fledge_enabled

        if not any_chrome_dnt:
            findings.append(
                Finding(
                    title="Chrome Do Not Track header is disabled",
                    description=("Chrome is not sending the Do Not Track header to websites."),
                    threat_level=ThreatLevel.LOW,
                    remediation=(
                        "Enable DNT in Chrome:\n"
                        "Settings > Privacy and security > "
                        'Send a "Do Not Track" request'
                    ),
                )
            )
            deduction += 5

        if any_topics_enabled:
            findings.append(
                Finding(
                    title="Chrome Topics API is enabled",
                    description=(
                        "Google's Topics API (part of Privacy Sandbox) is active. "
                        "It categorizes your browsing into interest topics and shares "
                        "them with advertisers. While designed as a less invasive "
                        "replacement for third-party cookies, it still enables "
                        "interest-based ad targeting."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation=(
                        "Disable Topics API:\n"
                        "Settings > Privacy and security > Ad privacy > "
                        "Ad topics > turn off"
                    ),
                )
            )
            deduction += 10

        if any_fledge_enabled:
            findings.append(
                Finding(
                    title="Chrome Protected Audiences (FLEDGE) is enabled",
                    description=(
                        "Chrome's Protected Audiences API (formerly FLEDGE) allows "
                        "advertisers to run on-device ad auctions based on interest "
                        "groups you have been added to while browsing. Sites can "
                        "place you in audience segments for later retargeting."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation=(
                        "Disable Protected Audiences:\n"
                        "Settings > Privacy and security > Ad privacy > "
                        "Site-suggested ads > turn off"
                    ),
                )
            )
            deduction += 10

    # --- Brave: positive signal ---
    if brave_profiles:
        raw["brave_detected"] = True
        findings.append(
            Finding(
                title="Brave browser detected (built-in ad blocking)",
                description=(
                    "Brave blocks ads and trackers by default via its Shields feature, "
                    "including ad network requests, cross-site cookies, and fingerprinting. "
                    "This provides strong baseline protection against the advertising "
                    "data ecosystem."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed — keep Shields enabled.",
            )
        )

    if not profiles:
        raw["no_browsers"] = True

    return findings, deduction, raw


# ---------------------------------------------------------------------------
# Phase 4: Data broker exposure (cross-platform)
# ---------------------------------------------------------------------------


def _audit_data_broker_exposure(
    country: str,
) -> tuple[list[Finding], int, dict[str, Any]]:
    """Assess data broker exposure and provide opt-out guidance."""
    findings: list[Finding] = []
    deduction = 0
    raw: dict[str, Any] = {}

    brokers = load_brokers(country)
    raw["country"] = country
    raw["broker_count"] = len(brokers)
    raw["brokers"] = brokers

    broker_names = [b["name"] for b in brokers]
    opt_out_urls = [f"  - {b['name']}: {b['opt_out_url']}" for b in brokers if b.get("opt_out_url")]

    findings.append(
        Finding(
            title=f"Data broker exposure: {len(brokers)} brokers identified",
            description=(
                "Your advertising data is likely held by multiple data brokers who "
                "purchase it from ad exchanges and RTB bidstream. These brokers "
                "aggregate your advertising ID, location history, app usage, and "
                "browsing behavior into profiles that are sold to advertisers, "
                "law enforcement, and intelligence companies.\n\n"
                f"Known brokers ({country.upper()}): "
                + ", ".join(broker_names[:10])
                + (f" and {len(broker_names) - 10} more" if len(broker_names) > 10 else "")
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Request data deletion from each broker:\n"
                + "\n".join(opt_out_urls[:10])
                + (f"\n  ... and {len(opt_out_urls) - 10} more" if len(opt_out_urls) > 10 else "")
                + "\n\nThis is time-consuming but is your legal right under "
                "GDPR (EU) and CCPA (California). Consider using a data removal "
                "service like Incogni or DeleteMe to automate the process."
            ),
        )
    )
    deduction += 15

    return findings, deduction, raw


# ---------------------------------------------------------------------------
# Main audit function
# ---------------------------------------------------------------------------


async def audit_ad_tracking(**kwargs: Any) -> AuditResult:
    """Audit advertising data ecosystem exposure."""
    findings: list[Finding] = []
    total_deduction = 0
    raw_data: dict[str, Any] = {"platform": platform.system()}

    country = kwargs.get("country", "us")

    # Phase 1: macOS Advertising ID settings
    ad_findings, ad_deduction, ad_raw = _audit_advertising_id()
    findings.extend(ad_findings)
    total_deduction += ad_deduction
    raw_data.update(ad_raw)

    # Phase 2: Safari privacy settings (macOS only)
    safari_findings, safari_deduction, safari_raw = _audit_safari_privacy()
    findings.extend(safari_findings)
    total_deduction += safari_deduction
    raw_data.update(safari_raw)

    # Phase 3: Browser ad-tracking settings (Firefox, Chrome, Brave)
    profiles = find_browser_profiles()
    browser_findings, browser_deduction, browser_raw = _audit_browser_ad_tracking(profiles)
    findings.extend(browser_findings)
    total_deduction += browser_deduction
    raw_data.update(browser_raw)

    # Phase 4: Data broker exposure
    broker_findings, broker_deduction, broker_raw = _audit_data_broker_exposure(country)
    findings.extend(broker_findings)
    total_deduction += broker_deduction
    raw_data.update(broker_raw)

    score = max(0, min(100, 100 - total_deduction))

    return AuditResult(
        module_name="ad_tracking",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
