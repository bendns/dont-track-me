"""Tests for the advertising data ecosystem audit module."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from dont_track_me.modules.ad_tracking.auditor import audit_ad_tracking
from dont_track_me.modules.ad_tracking.brokers import load_brokers
from dont_track_me.modules.ad_tracking.module import AdTrackingModule
from dont_track_me.modules.ad_tracking.protector import protect_ad_tracking
from dont_track_me.modules.fingerprint.browsers import BrowserProfile

_MODULE_PATH = "dont_track_me.modules.ad_tracking.auditor"
_PROTECTOR_PATH = "dont_track_me.modules.ad_tracking.protector"


def _mock_defaults_read(values: dict[str, str | None]):
    """Create a side_effect for subprocess.run that returns defaults values.

    `values` maps 'key' -> 'stdout value' (or None for failure).
    """

    def side_effect(cmd, **kwargs):
        if cmd[0] == "defaults" and cmd[1] == "read" and len(cmd) >= 4:
            key = cmd[3]
            val = values.get(key)
            if val is not None:
                return subprocess.CompletedProcess(cmd, 0, stdout=f"{val}\n", stderr="")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return side_effect


# ---------------------------------------------------------------------------
# Module-level tests
# ---------------------------------------------------------------------------


def test_module_attributes():
    """Module has correct name, display_name, and description."""
    module = AdTrackingModule()
    assert module.name == "ad_tracking"
    assert module.display_name == "Advertising Data Ecosystem Audit"
    assert "advertising" in module.description.lower()


def test_module_educational_content():
    """Educational content is substantial and mentions advertising."""
    module = AdTrackingModule()
    content = module.get_educational_content()
    assert len(content) > 500
    assert "advertising" in content.lower()
    assert "IDFA" in content


# ---------------------------------------------------------------------------
# Broker data tests
# ---------------------------------------------------------------------------


def test_load_brokers_us():
    """US broker data loads with expected entries."""
    brokers = load_brokers("us")
    assert len(brokers) > 10
    names = {b["name"] for b in brokers}
    assert any("LiveRamp" in n for n in names)
    assert any("Fog" in n for n in names)


def test_load_brokers_fr():
    """French broker data loads with expected entries."""
    brokers = load_brokers("fr")
    assert len(brokers) > 5
    names = {b["name"] for b in brokers}
    assert any("Criteo" in n for n in names)
    assert any("CNIL" in n for n in names)


def test_load_brokers_fallback():
    """Unknown country falls back to US brokers."""
    brokers = load_brokers("zz")
    us_brokers = load_brokers("us")
    assert len(brokers) == len(us_brokers)


# ---------------------------------------------------------------------------
# Phase 1: Advertising ID tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_idfa_enabled():
    """IDFA enabled triggers a CRITICAL finding."""
    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Darwin"),
        patch(
            f"{_MODULE_PATH}.subprocess.run",
            side_effect=_mock_defaults_read(
                {
                    "allowIdentifierForAdvertising": "1",
                    "allowApplePersonalizedAdvertising": "0",
                }
            ),
        ),
        patch(f"{_MODULE_PATH}._read_safari_prefs", return_value=None),
        patch(f"{_MODULE_PATH}._get_safari_plist_path") as mock_path,
    ):
        mock_path.return_value.parent.exists.return_value = False
        result = await audit_ad_tracking()

    idfa_findings = [f for f in result.findings if "IDFA" in f.title]
    assert len(idfa_findings) == 1
    assert idfa_findings[0].threat_level == "critical"
    assert result.score < 100


@pytest.mark.asyncio
async def test_idfa_disabled():
    """IDFA disabled produces INFO finding, no penalty."""
    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Darwin"),
        patch(
            f"{_MODULE_PATH}.subprocess.run",
            side_effect=_mock_defaults_read(
                {
                    "allowIdentifierForAdvertising": "0",
                    "allowApplePersonalizedAdvertising": "0",
                }
            ),
        ),
        patch(f"{_MODULE_PATH}._read_safari_prefs", return_value=None),
        patch(f"{_MODULE_PATH}._get_safari_plist_path") as mock_path,
    ):
        mock_path.return_value.parent.exists.return_value = False
        result = await audit_ad_tracking()

    idfa_findings = [f for f in result.findings if "IDFA" in f.title]
    assert len(idfa_findings) == 1
    assert idfa_findings[0].threat_level == "info"


@pytest.mark.asyncio
async def test_personalized_ads_enabled():
    """Apple personalized ads enabled triggers a HIGH finding."""
    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Darwin"),
        patch(
            f"{_MODULE_PATH}.subprocess.run",
            side_effect=_mock_defaults_read(
                {
                    "allowIdentifierForAdvertising": "0",
                    "allowApplePersonalizedAdvertising": "1",
                }
            ),
        ),
        patch(f"{_MODULE_PATH}._read_safari_prefs", return_value=None),
        patch(f"{_MODULE_PATH}._get_safari_plist_path") as mock_path,
    ):
        mock_path.return_value.parent.exists.return_value = False
        result = await audit_ad_tracking()

    ads_findings = [f for f in result.findings if "personalized" in f.title.lower()]
    assert len(ads_findings) == 1
    assert ads_findings[0].threat_level == "high"
    assert result.score < 100


@pytest.mark.asyncio
async def test_adlib_not_readable():
    """Subprocess failure produces INFO finding with no penalty."""
    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Darwin"),
        patch(
            f"{_MODULE_PATH}.subprocess.run",
            side_effect=FileNotFoundError("defaults not found"),
        ),
        patch(f"{_MODULE_PATH}._read_safari_prefs", return_value=None),
        patch(f"{_MODULE_PATH}._get_safari_plist_path") as mock_path,
    ):
        mock_path.return_value.parent.exists.return_value = False
        result = await audit_ad_tracking()

    info_findings = [
        f for f in result.findings if "Cannot read" in f.title and "advertising" in f.title.lower()
    ]
    assert len(info_findings) == 1
    assert info_findings[0].threat_level == "info"


@pytest.mark.asyncio
async def test_non_macos_skips_adlib():
    """Advertising ID checks are skipped on non-macOS platforms."""
    with patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"):
        result = await audit_ad_tracking()

    ad_findings = [
        f for f in result.findings if "advertising" in f.title.lower() or "IDFA" in f.title
    ]
    assert len(ad_findings) == 0


# ---------------------------------------------------------------------------
# Phase 2: Safari tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safari_dnt_disabled():
    """Safari DNT disabled triggers a LOW finding."""
    safari_prefs = {
        "SendDoNotTrackHTTPHeader": False,
        "BlockStoragePolicy": 2,
        "WBSPrivacyProxyAvailabilityTraffic": 262144,
    }

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Darwin"),
        patch(
            f"{_MODULE_PATH}.subprocess.run",
            side_effect=_mock_defaults_read(
                {
                    "allowIdentifierForAdvertising": "0",
                    "allowApplePersonalizedAdvertising": "0",
                }
            ),
        ),
        patch(f"{_MODULE_PATH}._read_safari_prefs", return_value=safari_prefs),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=[]),
    ):
        result = await audit_ad_tracking()

    dnt_findings = [f for f in result.findings if "Safari" in f.title and "Do Not Track" in f.title]
    assert len(dnt_findings) == 1
    assert dnt_findings[0].threat_level == "low"


@pytest.mark.asyncio
async def test_safari_cookies_allowed():
    """Safari allowing all cookies triggers a MEDIUM finding."""
    safari_prefs = {
        "SendDoNotTrackHTTPHeader": True,
        "BlockStoragePolicy": 0,
        "WBSPrivacyProxyAvailabilityTraffic": 262144,
    }

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Darwin"),
        patch(
            f"{_MODULE_PATH}.subprocess.run",
            side_effect=_mock_defaults_read(
                {
                    "allowIdentifierForAdvertising": "0",
                    "allowApplePersonalizedAdvertising": "0",
                }
            ),
        ),
        patch(f"{_MODULE_PATH}._read_safari_prefs", return_value=safari_prefs),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=[]),
    ):
        result = await audit_ad_tracking()

    cookie_findings = [
        f for f in result.findings if "Safari" in f.title and "cookies" in f.title.lower()
    ]
    assert len(cookie_findings) == 1
    assert cookie_findings[0].threat_level == "medium"


@pytest.mark.asyncio
async def test_safari_not_readable():
    """Safari prefs unreadable produces INFO finding, no penalty."""
    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Darwin"),
        patch(
            f"{_MODULE_PATH}.subprocess.run",
            side_effect=_mock_defaults_read(
                {
                    "allowIdentifierForAdvertising": "0",
                    "allowApplePersonalizedAdvertising": "0",
                }
            ),
        ),
        patch(f"{_MODULE_PATH}._read_safari_prefs", return_value=None),
        patch(f"{_MODULE_PATH}._get_safari_plist_path") as mock_path,
    ):
        mock_path.return_value.parent.exists.return_value = True
        result = await audit_ad_tracking()

    safari_findings = [f for f in result.findings if "Safari" in f.title]
    assert len(safari_findings) == 1
    assert safari_findings[0].threat_level == "info"


@pytest.mark.asyncio
async def test_non_macos_skips_safari():
    """Safari checks are skipped on non-macOS platforms."""
    with patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"):
        result = await audit_ad_tracking()

    safari_findings = [f for f in result.findings if "Safari" in f.title]
    assert len(safari_findings) == 0


# ---------------------------------------------------------------------------
# Phase 3: Browser ad-tracking tests
# ---------------------------------------------------------------------------


def _make_firefox_profile(prefs: dict) -> BrowserProfile:
    """Create a mock Firefox BrowserProfile with given prefs."""
    return BrowserProfile(
        browser="firefox",
        profile_path=Path("/fake/firefox/profile"),
        prefs=prefs,
    )


def _make_chrome_profile() -> BrowserProfile:
    """Create a mock Chrome BrowserProfile."""
    return BrowserProfile(
        browser="chrome",
        profile_path=Path("/fake/chrome/profile"),
    )


def _make_brave_profile() -> BrowserProfile:
    """Create a mock Brave BrowserProfile."""
    return BrowserProfile(
        browser="brave",
        profile_path=Path("/fake/brave/profile"),
    )


@pytest.mark.asyncio
async def test_firefox_dnt_disabled():
    """Firefox with DNT disabled triggers a LOW finding."""
    profiles = [_make_firefox_profile({"privacy.donottrackheader.enabled": False})]

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=profiles),
    ):
        result = await audit_ad_tracking()

    dnt = [f for f in result.findings if "Firefox" in f.title and "Do Not Track" in f.title]
    assert len(dnt) == 1
    assert dnt[0].threat_level == "low"


@pytest.mark.asyncio
async def test_firefox_cookies_allow_all():
    """Firefox allowing all cookies triggers a MEDIUM finding."""
    profiles = [
        _make_firefox_profile(
            {
                "privacy.donottrackheader.enabled": True,
                "network.cookie.cookieBehavior": 0,
            }
        )
    ]

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=profiles),
    ):
        result = await audit_ad_tracking()

    cookie = [f for f in result.findings if "Firefox allows all cookies" in f.title]
    assert len(cookie) == 1
    assert cookie[0].threat_level == "medium"


@pytest.mark.asyncio
async def test_firefox_strict_no_findings():
    """Firefox with strict settings produces no negative findings."""
    profiles = [
        _make_firefox_profile(
            {
                "privacy.donottrackheader.enabled": True,
                "network.cookie.cookieBehavior": 5,
            }
        )
    ]

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=profiles),
    ):
        result = await audit_ad_tracking()

    firefox_issues = [
        f for f in result.findings if "Firefox" in f.title and f.threat_level != "info"
    ]
    assert len(firefox_issues) == 0


@pytest.mark.asyncio
async def test_chrome_topics_enabled():
    """Chrome with Topics API enabled triggers a MEDIUM finding."""
    profiles = [_make_chrome_profile()]
    chrome_prefs = {
        "enable_do_not_track": True,
        "privacy_sandbox": {"m1": {"topics_enabled": True, "fledge_enabled": False}},
    }

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=profiles),
        patch(f"{_MODULE_PATH}._safe_read_json", return_value=chrome_prefs),
    ):
        result = await audit_ad_tracking()

    topics = [f for f in result.findings if "Topics" in f.title]
    assert len(topics) == 1
    assert topics[0].threat_level == "medium"


@pytest.mark.asyncio
async def test_chrome_fledge_enabled():
    """Chrome with FLEDGE/Protected Audiences triggers a MEDIUM finding."""
    profiles = [_make_chrome_profile()]
    chrome_prefs = {
        "enable_do_not_track": True,
        "privacy_sandbox": {"m1": {"topics_enabled": False, "fledge_enabled": True}},
    }

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=profiles),
        patch(f"{_MODULE_PATH}._safe_read_json", return_value=chrome_prefs),
    ):
        result = await audit_ad_tracking()

    fledge = [f for f in result.findings if "Protected Audiences" in f.title]
    assert len(fledge) == 1
    assert fledge[0].threat_level == "medium"


@pytest.mark.asyncio
async def test_chrome_dnt_disabled():
    """Chrome with DNT disabled triggers a LOW finding."""
    profiles = [_make_chrome_profile()]
    chrome_prefs = {
        "enable_do_not_track": False,
        "privacy_sandbox": {"m1": {"topics_enabled": False, "fledge_enabled": False}},
    }

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=profiles),
        patch(f"{_MODULE_PATH}._safe_read_json", return_value=chrome_prefs),
    ):
        result = await audit_ad_tracking()

    dnt = [f for f in result.findings if "Chrome" in f.title and "Do Not Track" in f.title]
    assert len(dnt) == 1
    assert dnt[0].threat_level == "low"


@pytest.mark.asyncio
async def test_brave_positive_signal():
    """Brave browser detected produces an INFO finding."""
    profiles = [_make_brave_profile()]

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=profiles),
    ):
        result = await audit_ad_tracking()

    brave = [f for f in result.findings if "Brave" in f.title]
    assert len(brave) == 1
    assert brave[0].threat_level == "info"


@pytest.mark.asyncio
async def test_no_browsers_no_browser_findings():
    """No browser profiles produces no browser findings."""
    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_MODULE_PATH}.find_browser_profiles", return_value=[]),
    ):
        result = await audit_ad_tracking()

    browser_findings = [
        f
        for f in result.findings
        if any(
            b in f.title for b in ("Firefox", "Chrome", "Brave", "Topics", "FLEDGE", "Protected")
        )
    ]
    assert len(browser_findings) == 0


# ---------------------------------------------------------------------------
# Phase 4: Data broker tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broker_exposure_finding():
    """Data broker exposure always produces a HIGH finding."""
    with patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"):
        result = await audit_ad_tracking()

    broker_findings = [f for f in result.findings if "broker" in f.title.lower()]
    assert len(broker_findings) == 1
    assert broker_findings[0].threat_level == "high"


@pytest.mark.asyncio
async def test_broker_country_kwarg():
    """Country kwarg is passed through to broker loading."""
    with patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"):
        result = await audit_ad_tracking(country="fr")

    assert result.raw_data["country"] == "fr"
    assert result.raw_data["broker_count"] > 0


# ---------------------------------------------------------------------------
# Protector tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_protect_dry_run():
    """Protect with dry_run=True takes no actions."""
    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_PROTECTOR_PATH}.platform.system", return_value="Linux"),
    ):
        result = await protect_ad_tracking(dry_run=True)

    assert result.module_name == "ad_tracking"
    assert result.dry_run is True
    assert len(result.actions_taken) == 0
    assert len(result.actions_available) > 0


@pytest.mark.asyncio
async def test_protect_apply_disables_idfa():
    """Protect with --apply calls defaults write to disable IDFA."""
    # Auditor subprocess calls (defaults read)
    auditor_side_effect = _mock_defaults_read(
        {
            "allowIdentifierForAdvertising": "1",
            "allowApplePersonalizedAdvertising": "1",
        }
    )

    # Protector subprocess calls (defaults write) - always succeed
    def combined_side_effect(cmd, **kwargs):
        if cmd[0] == "defaults" and cmd[1] == "write":
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return auditor_side_effect(cmd, **kwargs)

    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Darwin"),
        patch(f"{_MODULE_PATH}.subprocess.run", side_effect=auditor_side_effect),
        patch(f"{_MODULE_PATH}._read_safari_prefs", return_value=None),
        patch(f"{_MODULE_PATH}._get_safari_plist_path") as mock_path,
        patch(f"{_PROTECTOR_PATH}.platform.system", return_value="Darwin"),
        patch(f"{_PROTECTOR_PATH}.subprocess.run", side_effect=combined_side_effect),
    ):
        mock_path.return_value.parent.exists.return_value = False
        result = await protect_ad_tracking(dry_run=False)

    assert len(result.actions_taken) == 2
    assert any("allowIdentifierForAdvertising" in a for a in result.actions_taken)
    assert any("allowApplePersonalizedAdvertising" in a for a in result.actions_taken)


@pytest.mark.asyncio
async def test_protect_recommendations_include_brokers():
    """Protect always includes broker opt-out URLs in recommendations."""
    with (
        patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"),
        patch(f"{_PROTECTOR_PATH}.platform.system", return_value="Linux"),
    ):
        result = await protect_ad_tracking(dry_run=True)

    broker_actions = [a for a in result.actions_available if "data deletion" in a.lower()]
    assert len(broker_actions) > 0


@pytest.mark.asyncio
async def test_audit_score_range():
    """Score is always clamped between 0 and 100."""
    with patch(f"{_MODULE_PATH}.platform.system", return_value="Linux"):
        result = await audit_ad_tracking()

    assert 0 <= result.score <= 100
