"""Tests for the social media tracker detection module."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from dont_track_me.modules.fingerprint.browsers import BrowserProfile
from dont_track_me.modules.social.auditor import (
    _check_anti_tracker_extensions,
    _check_dns_blocking,
    _check_hosts_file,
    _check_social_cookies,
    _check_tracking_protection,
    audit_social,
)
from dont_track_me.modules.social.protector import protect_social
from dont_track_me.modules.social.trackers import (
    SOCIAL_HOSTS_BLOCKLIST,
    SOCIAL_TRACKER_DOMAINS,
    is_social_tracker,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _firefox_profile(
    tmp_path: Path,
    prefs: dict[str, Any] | None = None,
    extensions: dict[str, str] | None = None,
) -> BrowserProfile:
    """Create a fake Firefox BrowserProfile with optional prefs.js and extensions.json."""
    import json

    profile_dir = tmp_path / "firefox-test"
    profile_dir.mkdir(exist_ok=True)

    # Write prefs.js
    if prefs:
        lines = []
        for key, value in prefs.items():
            if isinstance(value, bool):
                lines.append(f'user_pref("{key}", {"true" if value else "false"});')
            elif isinstance(value, int):
                lines.append(f'user_pref("{key}", {value});')
            else:
                lines.append(f'user_pref("{key}", "{value}");')
        (profile_dir / "prefs.js").write_text("\n".join(lines))
    else:
        (profile_dir / "prefs.js").write_text("")

    # Write extensions.json
    if extensions:
        addons = []
        for ext_id, name in extensions.items():
            addons.append(
                {
                    "id": ext_id,
                    "defaultLocale": {"name": name},
                }
            )
        (profile_dir / "extensions.json").write_text(json.dumps({"addons": addons}))

    return BrowserProfile(
        browser="firefox",
        profile_path=profile_dir,
        prefs=prefs or {},
        extensions=[],
    )


def _chrome_profile(
    tmp_path: Path,
    prefs_data: dict[str, Any] | None = None,
    extensions: dict[str, dict[str, Any]] | None = None,
) -> BrowserProfile:
    """Create a fake Chrome BrowserProfile with Preferences JSON."""
    import json

    profile_dir = tmp_path / "chrome-test"
    profile_dir.mkdir(exist_ok=True)

    data: dict[str, Any] = prefs_data or {}
    if extensions:
        data.setdefault("extensions", {})["settings"] = extensions
    (profile_dir / "Preferences").write_text(json.dumps(data))

    return BrowserProfile(
        browser="chrome",
        profile_path=profile_dir,
        prefs={},
        extensions=[],
    )


def _create_chrome_db(db_path: Path, hosts: list[str]) -> None:
    """Create a mock Chrome Cookies DB with given hosts."""
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE cookies ("
        "  host_key TEXT NOT NULL,"
        "  name TEXT NOT NULL,"
        "  is_secure INTEGER NOT NULL DEFAULT 0,"
        "  is_httponly INTEGER NOT NULL DEFAULT 0,"
        "  samesite INTEGER NOT NULL DEFAULT -1,"
        "  has_expires INTEGER NOT NULL DEFAULT 0,"
        "  expires_utc INTEGER NOT NULL DEFAULT 0"
        ")"
    )
    for host in hosts:
        conn.execute(
            "INSERT INTO cookies (host_key, name) VALUES (?, ?)",
            (host, "test_cookie"),
        )
    conn.commit()
    conn.close()


def _create_firefox_db(db_path: Path, hosts: list[str]) -> None:
    """Create a mock Firefox cookies.sqlite DB with given hosts."""
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE moz_cookies ("
        "  host TEXT NOT NULL,"
        "  name TEXT NOT NULL,"
        "  isSecure INTEGER NOT NULL DEFAULT 0,"
        "  isHttpOnly INTEGER NOT NULL DEFAULT 0,"
        "  sameSite INTEGER NOT NULL DEFAULT 0,"
        "  expiry INTEGER NOT NULL DEFAULT 0"
        ")"
    )
    for host in hosts:
        conn.execute(
            "INSERT INTO moz_cookies (host, name) VALUES (?, ?)",
            (host, "test_cookie"),
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# TestSocialTrackers
# ---------------------------------------------------------------------------


class TestSocialTrackers:
    def test_exact_match(self):
        is_social, domain, plat = is_social_tracker("facebook.com")
        assert is_social is True
        assert domain == "facebook.com"
        assert "Meta" in plat

    def test_subdomain_match(self):
        is_social, domain, _plat = is_social_tracker("pixel.facebook.com")
        assert is_social is True
        assert domain == "facebook.com"

    def test_leading_dot(self):
        is_social, _domain, _plat = is_social_tracker(".facebook.com")
        assert is_social is True

    def test_non_social_domain(self):
        is_social, domain, plat = is_social_tracker("example.com")
        assert is_social is False
        assert domain == ""
        assert plat == ""

    def test_all_platforms_have_domains(self):
        for plat, domains in SOCIAL_TRACKER_DOMAINS.items():
            assert len(domains) > 0, f"Platform {plat} has no domains"

    def test_blocklist_entries_match_social_domains(self):
        for host in SOCIAL_HOSTS_BLOCKLIST:
            is_social, _domain, _plat = is_social_tracker(host)
            assert is_social, f"Blocklist entry {host} not in social domains"

    def test_case_insensitive(self):
        is_social, _domain, _plat = is_social_tracker("Facebook.COM")
        assert is_social is True


# ---------------------------------------------------------------------------
# TestCheckTrackingProtection
# ---------------------------------------------------------------------------


class TestCheckTrackingProtection:
    def test_firefox_etp_strict(self, tmp_path: Path):
        profile = _firefox_profile(
            tmp_path,
            prefs={
                "browser.contentblocking.category": "strict",
            },
        )
        findings, delta = _check_tracking_protection([profile])
        assert delta == 0
        assert any("Strict" in f.title for f in findings)

    def test_firefox_etp_standard_with_social(self, tmp_path: Path):
        profile = _firefox_profile(
            tmp_path,
            prefs={
                "browser.contentblocking.category": "standard",
                "privacy.trackingprotection.socialtracking.enabled": True,
            },
        )
        findings, delta = _check_tracking_protection([profile])
        assert delta == -5
        assert any(f.threat_level.name == "LOW" for f in findings)

    def test_firefox_no_protection(self, tmp_path: Path):
        profile = _firefox_profile(tmp_path, prefs={})
        findings, delta = _check_tracking_protection([profile])
        assert delta == -20
        assert any(f.threat_level.name == "HIGH" for f in findings)

    def test_chrome_blocks_third_party(self, tmp_path: Path):
        profile = _chrome_profile(
            tmp_path,
            prefs_data={
                "profile": {"block_third_party_cookies": True},
            },
        )
        _findings, delta = _check_tracking_protection([profile])
        assert delta == 0

    def test_chrome_allows_third_party(self, tmp_path: Path):
        profile = _chrome_profile(
            tmp_path,
            prefs_data={
                "profile": {"block_third_party_cookies": False},
            },
        )
        _findings, delta = _check_tracking_protection([profile])
        assert delta == -15

    def test_no_browsers(self):
        findings, delta = _check_tracking_protection([])
        assert delta == 0
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# TestCheckAntiTrackerExtensions
# ---------------------------------------------------------------------------


class TestCheckAntiTrackerExtensions:
    def test_ublock_firefox(self, tmp_path: Path):
        profile = _firefox_profile(
            tmp_path,
            extensions={
                "uBlock0@AK": "uBlock Origin",
            },
        )
        findings, delta = _check_anti_tracker_extensions([profile])
        assert delta == 0
        assert any("uBlock Origin" in f.title for f in findings)

    def test_ghostery_chrome(self, tmp_path: Path):
        profile = _chrome_profile(
            tmp_path,
            extensions={
                "mlomiejdfkolichcflejclcbmpeaniij": {
                    "manifest": {"name": "Ghostery"},
                },
            },
        )
        findings, delta = _check_anti_tracker_extensions([profile])
        assert delta == 0
        assert any("Ghostery" in f.title for f in findings)

    def test_no_extensions(self, tmp_path: Path):
        profile = _firefox_profile(tmp_path)
        findings, delta = _check_anti_tracker_extensions([profile])
        assert delta == -15
        assert any(f.threat_level.name == "MEDIUM" for f in findings)

    def test_no_profiles(self):
        findings, delta = _check_anti_tracker_extensions([])
        assert delta == 0
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# TestCheckSocialCookies
# ---------------------------------------------------------------------------


class TestCheckSocialCookies:
    def test_facebook_cookies_found(self, tmp_path: Path):
        db = tmp_path / "Cookies"
        _create_chrome_db(db, [".facebook.com", ".example.com"])
        with patch(
            "dont_track_me.modules.social.auditor._find_cookie_databases",
            return_value=[(db, "chrome")],
        ):
            findings, delta, raw = _check_social_cookies()
        assert delta < 0
        assert any("Meta" in f.title for f in findings)
        assert "Meta (Facebook/Instagram)" in raw["platforms_with_cookies"]

    def test_multiple_platforms(self, tmp_path: Path):
        db = tmp_path / "Cookies"
        _create_chrome_db(db, [".facebook.com", ".google-analytics.com", ".twitter.com"])
        with patch(
            "dont_track_me.modules.social.auditor._find_cookie_databases",
            return_value=[(db, "chrome")],
        ):
            _findings, delta, raw = _check_social_cookies()
        assert len(raw["platforms_with_cookies"]) == 3
        assert delta == -15  # -5 * 3

    def test_no_social_cookies(self, tmp_path: Path):
        db = tmp_path / "Cookies"
        _create_chrome_db(db, [".example.com", ".mysite.org"])
        with patch(
            "dont_track_me.modules.social.auditor._find_cookie_databases",
            return_value=[(db, "chrome")],
        ):
            findings, delta, _raw = _check_social_cookies()
        assert delta == 0
        assert any("No social tracker" in f.title for f in findings)

    def test_no_databases(self):
        with patch(
            "dont_track_me.modules.social.auditor._find_cookie_databases",
            return_value=[],
        ):
            _findings, delta, _raw = _check_social_cookies()
        assert delta == 0

    def test_score_capped_at_minus_40(self, tmp_path: Path):
        db = tmp_path / "Cookies"
        # All 8 platforms
        hosts = [
            ".facebook.com",
            ".google-analytics.com",
            ".twitter.com",
            ".tiktok.com",
            ".linkedin.com",
            ".pinterest.com",
            ".snap.com",
            ".reddit.com",
            ".example.com",
        ]
        _create_chrome_db(db, hosts)
        with patch(
            "dont_track_me.modules.social.auditor._find_cookie_databases",
            return_value=[(db, "chrome")],
        ):
            _findings, delta, _raw = _check_social_cookies()
        assert delta == -40


# ---------------------------------------------------------------------------
# TestCheckHostsFile
# ---------------------------------------------------------------------------


class TestCheckHostsFile:
    def test_blocks_social_trackers(self):
        hosts_content = "\n".join(f"0.0.0.0 {d}" for d in SOCIAL_HOSTS_BLOCKLIST)
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__ = lambda s: iter(hosts_content.splitlines())
            mock_open.return_value.__exit__ = lambda *a: None
            findings, delta = _check_hosts_file()
        assert delta == 0
        assert any(f.threat_level.name == "INFO" for f in findings)

    def test_no_blocks(self):
        with patch(
            "dont_track_me.modules.social.auditor._read_hosts_file",
            return_value=set(),
        ):
            findings, delta = _check_hosts_file()
        assert delta == -10
        assert any(f.threat_level.name == "MEDIUM" for f in findings)

    def test_partial_blocks(self):
        # Block just a few
        partial = {SOCIAL_HOSTS_BLOCKLIST[0].lower(), SOCIAL_HOSTS_BLOCKLIST[1].lower()}
        with patch(
            "dont_track_me.modules.social.auditor._read_hosts_file",
            return_value=partial,
        ):
            findings, delta = _check_hosts_file()
        assert delta == -5
        assert any(f.threat_level.name == "LOW" for f in findings)


# ---------------------------------------------------------------------------
# TestCheckDnsBlocking
# ---------------------------------------------------------------------------


class TestCheckDnsBlocking:
    def test_adguard_dns(self):
        with patch(
            "dont_track_me.modules.social.auditor._get_system_dns_servers",
            return_value=["94.140.14.14"],
        ):
            findings, delta = _check_dns_blocking()
        assert delta == 0
        assert any("AdGuard" in f.title for f in findings)

    def test_nextdns(self):
        with patch(
            "dont_track_me.modules.social.auditor._get_system_dns_servers",
            return_value=["45.90.28.0"],
        ):
            findings, delta = _check_dns_blocking()
        assert delta == 0
        assert any("NextDNS" in f.title for f in findings)

    def test_no_blocking_dns(self):
        with patch(
            "dont_track_me.modules.social.auditor._get_system_dns_servers",
            return_value=["8.8.8.8"],
        ):
            findings, delta = _check_dns_blocking()
        assert delta == -10
        assert any(f.threat_level.name == "LOW" for f in findings)

    def test_local_dns(self):
        with patch(
            "dont_track_me.modules.social.auditor._get_system_dns_servers",
            return_value=["127.0.0.1"],
        ):
            findings, delta = _check_dns_blocking()
        assert delta == 0
        assert any("Local DNS" in f.title or "Pi-hole" in f.title for f in findings)


# ---------------------------------------------------------------------------
# TestAuditSocial
# ---------------------------------------------------------------------------


class TestAuditSocial:
    @pytest.mark.asyncio
    async def test_returns_valid_result(self, tmp_path: Path):
        profile = _firefox_profile(
            tmp_path,
            prefs={
                "browser.contentblocking.category": "strict",
            },
        )
        with (
            patch(
                "dont_track_me.modules.social.auditor.find_browser_profiles",
                return_value=[profile],
            ),
            patch(
                "dont_track_me.modules.social.auditor._find_cookie_databases",
                return_value=[],
            ),
            patch(
                "dont_track_me.modules.social.auditor._read_hosts_file",
                return_value=set(),
            ),
            patch(
                "dont_track_me.modules.social.auditor._get_system_dns_servers",
                return_value=["94.140.14.14"],
            ),
        ):
            result = await audit_social()
        assert result.module_name == "social"
        assert 0 <= result.score <= 100
        assert isinstance(result.findings, list)
        assert "browsers_found" in result.raw_data

    @pytest.mark.asyncio
    async def test_no_browsers(self):
        with (
            patch(
                "dont_track_me.modules.social.auditor.find_browser_profiles",
                return_value=[],
            ),
            patch(
                "dont_track_me.modules.social.auditor._find_cookie_databases",
                return_value=[],
            ),
            patch(
                "dont_track_me.modules.social.auditor._read_hosts_file",
                return_value=set(),
            ),
            patch(
                "dont_track_me.modules.social.auditor._get_system_dns_servers",
                return_value=["8.8.8.8"],
            ),
        ):
            result = await audit_social()
        assert result.score < 100


# ---------------------------------------------------------------------------
# TestProtectSocial
# ---------------------------------------------------------------------------


class TestProtectSocial:
    @pytest.mark.asyncio
    async def test_dry_run_lists_actions(self, tmp_path: Path):
        db = tmp_path / "Cookies"
        _create_chrome_db(db, [".facebook.com"])
        with (
            patch(
                "dont_track_me.modules.social.protector._find_cookie_databases",
                return_value=[(db, "chrome")],
            ),
            patch(
                "dont_track_me.modules.social.protector._get_unblocked_hosts",
                return_value=["connect.facebook.net"],
            ),
        ):
            result = await protect_social(dry_run=True)
        assert result.dry_run is True
        assert len(result.actions_available) > 0
        assert len(result.actions_taken) == 0

    @pytest.mark.asyncio
    async def test_apply_deletes_social_cookies_chrome(self, tmp_path: Path):
        db = tmp_path / "Cookies"
        _create_chrome_db(db, [".facebook.com", ".example.com"])
        with (
            patch(
                "dont_track_me.modules.social.protector._find_cookie_databases",
                return_value=[(db, "chrome")],
            ),
            patch(
                "dont_track_me.modules.social.protector._get_unblocked_hosts",
                return_value=[],
            ),
        ):
            result = await protect_social(dry_run=False)
        assert any("Deleted" in a for a in result.actions_taken)
        # Verify facebook cookie is gone but example.com remains
        conn = sqlite3.connect(str(db))
        hosts = [r[0] for r in conn.execute("SELECT DISTINCT host_key FROM cookies")]
        conn.close()
        assert ".facebook.com" not in hosts
        assert ".example.com" in hosts

    @pytest.mark.asyncio
    async def test_apply_deletes_social_cookies_firefox(self, tmp_path: Path):
        db = tmp_path / "cookies.sqlite"
        _create_firefox_db(db, [".twitter.com", ".mysite.org"])
        with (
            patch(
                "dont_track_me.modules.social.protector._find_cookie_databases",
                return_value=[(db, "firefox")],
            ),
            patch(
                "dont_track_me.modules.social.protector._get_unblocked_hosts",
                return_value=[],
            ),
        ):
            result = await protect_social(dry_run=False)
        assert any("Deleted" in a for a in result.actions_taken)
        conn = sqlite3.connect(str(db))
        hosts = [r[0] for r in conn.execute("SELECT DISTINCT host FROM moz_cookies")]
        conn.close()
        assert ".twitter.com" not in hosts
        assert ".mysite.org" in hosts

    @pytest.mark.asyncio
    async def test_dry_run_includes_recommendations(self):
        with (
            patch(
                "dont_track_me.modules.social.protector._find_cookie_databases",
                return_value=[],
            ),
            patch(
                "dont_track_me.modules.social.protector._get_unblocked_hosts",
                return_value=[],
            ),
        ):
            result = await protect_social(dry_run=True)
        assert any("uBlock Origin" in a for a in result.actions_available)
        assert any("Firefox" in a for a in result.actions_available)
