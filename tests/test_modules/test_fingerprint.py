"""Tests for the browser fingerprint detection module."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from dont_track_me.modules.fingerprint.auditor import (
    _check_anti_fingerprint_extensions,
    _check_canvas_protection,
    _check_font_exposure,
    _check_resist_fingerprinting,
    _check_system_fingerprint,
    _check_webgl_exposure,
    audit_fingerprint,
)
from dont_track_me.modules.fingerprint.browsers import (
    BrowserProfile,
    _parse_chrome_extensions,
    _parse_firefox_extensions,
    _parse_firefox_prefs,
    find_browser_profiles,
)
from dont_track_me.modules.fingerprint.protector import (
    _MARKER,
    _write_user_js,
    protect_fingerprint,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_firefox_profile(
    tmp_path: Path,
    *,
    resist_fp: bool = False,
    webgl_disabled: bool = False,
    extensions: list[dict[str, str]] | None = None,
) -> Path:
    """Create a fake Firefox profile directory with prefs.js and extensions.json."""
    profile_dir = tmp_path / "abc123.default"
    profile_dir.mkdir(parents=True, exist_ok=True)

    # prefs.js
    lines = []
    lines.append(
        f'user_pref("privacy.resistFingerprinting", {"true" if resist_fp else "false"});\n'
    )
    lines.append(f'user_pref("webgl.disabled", {"true" if webgl_disabled else "false"});\n')
    lines.append('user_pref("browser.startup.homepage", "https://example.com");\n')
    (profile_dir / "prefs.js").write_text("".join(lines))

    # extensions.json
    addons = []
    if extensions:
        for ext in extensions:
            addons.append(
                {
                    "id": ext.get("id", "unknown@ext"),
                    "defaultLocale": {"name": ext.get("name", "Unknown Extension")},
                }
            )
    (profile_dir / "extensions.json").write_text(json.dumps({"addons": addons}))

    return profile_dir


def _make_chrome_profile(
    tmp_path: Path,
    *,
    extensions: dict[str, dict[str, str]] | None = None,
) -> Path:
    """Create a fake Chrome profile directory with Preferences JSON."""
    profile_dir = tmp_path / "Default"
    profile_dir.mkdir(parents=True, exist_ok=True)

    settings: dict[str, Any] = {}
    if extensions:
        for ext_id, ext_data in extensions.items():
            settings[ext_id] = {"manifest": {"name": ext_data.get("name", "")}}

    prefs = {"extensions": {"settings": settings}}
    (profile_dir / "Preferences").write_text(json.dumps(prefs))

    return profile_dir


# ---------------------------------------------------------------------------
# Browser profile discovery tests
# ---------------------------------------------------------------------------


class TestFindBrowserProfiles:
    def test_finds_firefox_macos(self, tmp_path: Path) -> None:
        profiles_dir = tmp_path / "Library" / "Application Support" / "Firefox" / "Profiles"
        _make_firefox_profile(profiles_dir)

        with (
            patch("dont_track_me.modules.fingerprint.browsers.Path.home", return_value=tmp_path),
            patch(
                "dont_track_me.modules.fingerprint.browsers.platform.system", return_value="Darwin"
            ),
        ):
            profiles = find_browser_profiles()

        assert len(profiles) == 1
        assert profiles[0].browser == "firefox"

    def test_finds_chrome_macos(self, tmp_path: Path) -> None:
        chrome_dir = tmp_path / "Library" / "Application Support" / "Google" / "Chrome"
        _make_chrome_profile(chrome_dir)

        with (
            patch("dont_track_me.modules.fingerprint.browsers.Path.home", return_value=tmp_path),
            patch(
                "dont_track_me.modules.fingerprint.browsers.platform.system", return_value="Darwin"
            ),
        ):
            profiles = find_browser_profiles()

        assert len(profiles) == 1
        assert profiles[0].browser == "chrome"

    def test_finds_brave_linux(self, tmp_path: Path) -> None:
        brave_dir = tmp_path / ".config" / "BraveSoftware" / "Brave-Browser"
        _make_chrome_profile(brave_dir)

        with (
            patch("dont_track_me.modules.fingerprint.browsers.Path.home", return_value=tmp_path),
            patch(
                "dont_track_me.modules.fingerprint.browsers.platform.system", return_value="Linux"
            ),
        ):
            profiles = find_browser_profiles()

        assert len(profiles) == 1
        assert profiles[0].browser == "brave"

    def test_skips_symlinks(self, tmp_path: Path) -> None:
        profiles_dir = tmp_path / "Library" / "Application Support" / "Firefox" / "Profiles"
        profiles_dir.mkdir(parents=True)
        real_dir = tmp_path / "real_profile"
        real_dir.mkdir()
        (real_dir / "prefs.js").write_text("")
        (profiles_dir / "symlinked.default").symlink_to(real_dir)

        with (
            patch("dont_track_me.modules.fingerprint.browsers.Path.home", return_value=tmp_path),
            patch(
                "dont_track_me.modules.fingerprint.browsers.platform.system", return_value="Darwin"
            ),
        ):
            profiles = find_browser_profiles()

        assert len(profiles) == 0

    def test_no_browsers(self, tmp_path: Path) -> None:
        with (
            patch("dont_track_me.modules.fingerprint.browsers.Path.home", return_value=tmp_path),
            patch(
                "dont_track_me.modules.fingerprint.browsers.platform.system", return_value="Darwin"
            ),
        ):
            profiles = find_browser_profiles()

        assert len(profiles) == 0


# ---------------------------------------------------------------------------
# Firefox prefs parsing tests
# ---------------------------------------------------------------------------


class TestFirefoxPrefs:
    def test_parses_resist_fingerprinting_true(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        (profile / "prefs.js").write_text('user_pref("privacy.resistFingerprinting", true);\n')
        prefs = _parse_firefox_prefs(profile)
        assert prefs["privacy.resistFingerprinting"] is True

    def test_parses_resist_fingerprinting_false(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        (profile / "prefs.js").write_text('user_pref("privacy.resistFingerprinting", false);\n')
        prefs = _parse_firefox_prefs(profile)
        assert prefs["privacy.resistFingerprinting"] is False

    def test_parses_webgl_disabled(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        (profile / "prefs.js").write_text('user_pref("webgl.disabled", true);\n')
        prefs = _parse_firefox_prefs(profile)
        assert prefs["webgl.disabled"] is True

    def test_parses_integer_prefs(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        (profile / "prefs.js").write_text('user_pref("layout.css.font-visibility.level", 1);\n')
        prefs = _parse_firefox_prefs(profile)
        assert prefs["layout.css.font-visibility.level"] == 1

    def test_parses_string_prefs(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        (profile / "prefs.js").write_text(
            'user_pref("browser.startup.homepage", "https://example.com");\n'
        )
        prefs = _parse_firefox_prefs(profile)
        assert prefs["browser.startup.homepage"] == "https://example.com"

    def test_handles_malformed_prefs(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        (profile / "prefs.js").write_text("this is not valid prefs.js content\n{garbage}")
        prefs = _parse_firefox_prefs(profile)
        assert prefs == {}

    def test_handles_missing_prefs_js(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        prefs = _parse_firefox_prefs(profile)
        assert prefs == {}

    def test_parses_firefox_extensions(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        data = {
            "addons": [
                {"id": "uBlock0@AK", "defaultLocale": {"name": "uBlock Origin"}},
                {"id": "some-other@ext", "defaultLocale": {"name": "Some Other Extension"}},
            ]
        }
        (profile / "extensions.json").write_text(json.dumps(data))
        extensions = _parse_firefox_extensions(profile)
        assert "uBlock Origin" in extensions
        assert len(extensions) == 1  # Only the known anti-FP extension

    def test_parses_extensions_by_name(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        data = {
            "addons": [
                {"id": "unknown@ext", "defaultLocale": {"name": "Canvas Fingerprint Defender"}},
            ]
        }
        (profile / "extensions.json").write_text(json.dumps(data))
        extensions = _parse_firefox_extensions(profile)
        assert len(extensions) == 1
        assert extensions[0] == "Canvas Fingerprint Defender"

    def test_handles_missing_extensions_json(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        extensions = _parse_firefox_extensions(profile)
        assert extensions == []


# ---------------------------------------------------------------------------
# Chrome prefs parsing tests
# ---------------------------------------------------------------------------


class TestChromePrefs:
    def test_parses_extensions_by_id(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        prefs = {
            "extensions": {
                "settings": {
                    "cjpalhdlnbpafiamejdnhcphjbkeiagm": {"manifest": {"name": "uBlock Origin"}},
                    "other-ext-id": {"manifest": {"name": "Some Extension"}},
                }
            }
        }
        (profile / "Preferences").write_text(json.dumps(prefs))
        extensions = _parse_chrome_extensions(profile)
        assert "uBlock Origin" in extensions
        assert len(extensions) == 1

    def test_parses_extensions_by_name(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        prefs = {
            "extensions": {
                "settings": {
                    "unknown-id": {"manifest": {"name": "CanvasBlocker Extension"}},
                }
            }
        }
        (profile / "Preferences").write_text(json.dumps(prefs))
        extensions = _parse_chrome_extensions(profile)
        assert len(extensions) == 1

    def test_handles_empty_preferences(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        (profile / "Preferences").write_text("{}")
        extensions = _parse_chrome_extensions(profile)
        assert extensions == []

    def test_handles_missing_preferences(self, tmp_path: Path) -> None:
        profile = tmp_path / "profile"
        profile.mkdir()
        extensions = _parse_chrome_extensions(profile)
        assert extensions == []


# ---------------------------------------------------------------------------
# Auditor check tests
# ---------------------------------------------------------------------------


class TestAuditorChecks:
    def test_resist_fingerprinting_enabled(self) -> None:
        profiles = [
            BrowserProfile("firefox", Path("/fake"), {"privacy.resistFingerprinting": True}, [])
        ]
        findings, delta = _check_resist_fingerprinting(profiles)
        assert len(findings) == 1
        assert findings[0].threat_level.name == "INFO"
        assert delta == 0

    def test_resist_fingerprinting_disabled(self) -> None:
        profiles = [
            BrowserProfile("firefox", Path("/fake"), {"privacy.resistFingerprinting": False}, [])
        ]
        findings, delta = _check_resist_fingerprinting(profiles)
        assert len(findings) == 1
        assert findings[0].threat_level.name == "HIGH"
        assert delta == -25

    def test_resist_fingerprinting_no_firefox(self) -> None:
        profiles = [BrowserProfile("chrome", Path("/fake"), {}, [])]
        findings, delta = _check_resist_fingerprinting(profiles)
        assert len(findings) == 0
        assert delta == 0

    def test_webgl_exposed(self) -> None:
        profiles = [BrowserProfile("firefox", Path("/fake"), {}, [])]
        findings, delta = _check_webgl_exposure(profiles)
        assert len(findings) == 1
        assert findings[0].threat_level.name == "MEDIUM"
        assert delta == -10

    def test_webgl_disabled(self) -> None:
        profiles = [BrowserProfile("firefox", Path("/fake"), {"webgl.disabled": True}, [])]
        findings, delta = _check_webgl_exposure(profiles)
        assert len(findings) == 0
        assert delta == 0

    def test_webgl_skipped_when_rfp_enabled(self) -> None:
        profiles = [
            BrowserProfile("firefox", Path("/fake"), {"privacy.resistFingerprinting": True}, [])
        ]
        findings, _delta = _check_webgl_exposure(profiles)
        assert len(findings) == 0  # RFP covers WebGL

    def test_extensions_found(self) -> None:
        profiles = [
            BrowserProfile("firefox", Path("/fake"), {}, ["uBlock Origin", "CanvasBlocker"])
        ]
        findings, delta = _check_anti_fingerprint_extensions(profiles)
        assert len(findings) == 1
        assert findings[0].threat_level.name == "INFO"
        assert delta == 0

    def test_no_extensions(self) -> None:
        profiles = [BrowserProfile("chrome", Path("/fake"), {}, [])]
        findings, delta = _check_anti_fingerprint_extensions(profiles)
        assert len(findings) == 1
        assert findings[0].threat_level.name == "MEDIUM"
        assert delta == -15

    def test_canvas_unprotected(self) -> None:
        profiles = [BrowserProfile("chrome", Path("/fake"), {}, [])]
        findings, delta = _check_canvas_protection(profiles)
        assert len(findings) == 1
        assert findings[0].threat_level.name == "HIGH"
        assert delta == -15

    def test_canvas_protected_by_rfp(self) -> None:
        profiles = [
            BrowserProfile("firefox", Path("/fake"), {"privacy.resistFingerprinting": True}, [])
        ]
        findings, _delta = _check_canvas_protection(profiles)
        assert len(findings) == 0

    def test_canvas_protected_by_extension(self) -> None:
        profiles = [BrowserProfile("chrome", Path("/fake"), {}, ["CanvasBlocker"])]
        findings, _delta = _check_canvas_protection(profiles)
        assert len(findings) == 0

    def test_font_exposure_high(self) -> None:
        findings, delta = _check_font_exposure(250)
        assert len(findings) == 1
        assert findings[0].threat_level.name == "MEDIUM"
        assert delta == -5

    def test_font_exposure_moderate(self) -> None:
        findings, delta = _check_font_exposure(150)
        assert len(findings) == 1
        assert findings[0].threat_level.name == "LOW"
        assert delta == -2

    def test_font_exposure_low(self) -> None:
        findings, delta = _check_font_exposure(50)
        assert len(findings) == 0
        assert delta == 0

    def test_system_fingerprint_reports_cpu_and_timezone(self) -> None:
        with (
            patch("dont_track_me.modules.fingerprint.auditor.os.cpu_count", return_value=10),
            patch("dont_track_me.modules.fingerprint.auditor.time.tzname", ("EST", "EDT")),
        ):
            findings, _delta, raw = _check_system_fingerprint()
        assert raw["cpu_count"] == 10
        assert raw["timezone"] == "EST"
        assert any("10 CPU cores" in f.title for f in findings)
        assert any("EST" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Full audit tests
# ---------------------------------------------------------------------------


class TestAuditFingerprint:
    @pytest.mark.asyncio()
    async def test_audit_no_browsers(self) -> None:
        with (
            patch(
                "dont_track_me.modules.fingerprint.auditor.find_browser_profiles", return_value=[]
            ),
            patch("dont_track_me.modules.fingerprint.auditor.find_spec", return_value=None),
            patch(
                "dont_track_me.modules.fingerprint.auditor._count_system_fonts", return_value=100
            ),
        ):
            result = await audit_fingerprint()
        assert result.module_name == "fingerprint"
        assert result.score < 100
        assert any("No browser profiles found" in f.title for f in result.findings)
        assert result.raw_data["playwright_available"] is False

    @pytest.mark.asyncio()
    async def test_audit_hardened_firefox(self) -> None:
        profile = BrowserProfile(
            "firefox",
            Path("/fake"),
            {"privacy.resistFingerprinting": True, "webgl.disabled": True},
            ["CanvasBlocker"],
        )
        with (
            patch(
                "dont_track_me.modules.fingerprint.auditor.find_browser_profiles",
                return_value=[profile],
            ),
            patch("dont_track_me.modules.fingerprint.auditor.find_spec", return_value=None),
            patch(
                "dont_track_me.modules.fingerprint.auditor._count_system_fonts", return_value=100
            ),
        ):
            result = await audit_fingerprint()
        assert result.score >= 80
        assert result.raw_data["resist_fingerprinting"] is True

    @pytest.mark.asyncio()
    async def test_audit_default_firefox(self) -> None:
        profile = BrowserProfile("firefox", Path("/fake"), {}, [])
        with (
            patch(
                "dont_track_me.modules.fingerprint.auditor.find_browser_profiles",
                return_value=[profile],
            ),
            patch("dont_track_me.modules.fingerprint.auditor.find_spec", return_value=None),
            patch(
                "dont_track_me.modules.fingerprint.auditor._count_system_fonts", return_value=100
            ),
        ):
            result = await audit_fingerprint()
        assert result.score < 50  # No protections at all

    @pytest.mark.asyncio()
    async def test_audit_chrome_with_extensions(self) -> None:
        profile = BrowserProfile("chrome", Path("/fake"), {}, ["uBlock Origin"])
        with (
            patch(
                "dont_track_me.modules.fingerprint.auditor.find_browser_profiles",
                return_value=[profile],
            ),
            patch("dont_track_me.modules.fingerprint.auditor.find_spec", return_value=None),
            patch(
                "dont_track_me.modules.fingerprint.auditor._count_system_fonts", return_value=100
            ),
        ):
            result = await audit_fingerprint()
        assert "uBlock Origin" in result.raw_data["extensions_found"]

    @pytest.mark.asyncio()
    async def test_audit_raw_data_has_system_info(self) -> None:
        with (
            patch(
                "dont_track_me.modules.fingerprint.auditor.find_browser_profiles", return_value=[]
            ),
            patch("dont_track_me.modules.fingerprint.auditor.find_spec", return_value=None),
            patch(
                "dont_track_me.modules.fingerprint.auditor._count_system_fonts", return_value=150
            ),
        ):
            result = await audit_fingerprint()
        assert "cpu_count" in result.raw_data
        assert "timezone" in result.raw_data
        assert result.raw_data["font_count"] == 150


# ---------------------------------------------------------------------------
# Protector tests
# ---------------------------------------------------------------------------


class TestProtectFingerprint:
    @pytest.mark.asyncio()
    async def test_dry_run_recommendations(self) -> None:
        with patch(
            "dont_track_me.modules.fingerprint.protector.find_browser_profiles", return_value=[]
        ):
            result = await protect_fingerprint(dry_run=True)
        assert result.module_name == "fingerprint"
        assert result.dry_run is True
        assert len(result.actions_taken) == 0
        combined = " ".join(result.actions_available)
        assert "resistFingerprinting" in combined
        assert "Tor Browser" in combined

    @pytest.mark.asyncio()
    async def test_recommendations_include_all_browsers(self) -> None:
        with patch(
            "dont_track_me.modules.fingerprint.protector.find_browser_profiles", return_value=[]
        ):
            result = await protect_fingerprint(dry_run=True)
        combined = " ".join(result.actions_available)
        assert "Firefox" in combined
        assert "Chrome" in combined or "Brave" in combined
        assert "Tor Browser" in combined

    @pytest.mark.asyncio()
    async def test_apply_writes_user_js(self, tmp_path: Path) -> None:
        profile_dir = tmp_path / "test.default"
        profile_dir.mkdir()
        (profile_dir / "prefs.js").write_text("")
        (profile_dir / "extensions.json").write_text('{"addons": []}')

        profile = BrowserProfile("firefox", profile_dir, {}, [])
        with patch(
            "dont_track_me.modules.fingerprint.protector.find_browser_profiles",
            return_value=[profile],
        ):
            result = await protect_fingerprint(dry_run=False)

        assert len(result.actions_taken) > 0
        user_js = profile_dir / "user.js"
        assert user_js.exists()
        content = user_js.read_text()
        assert "privacy.resistFingerprinting" in content
        assert "webgl.disabled" in content
        assert _MARKER in content

    @pytest.mark.asyncio()
    async def test_apply_appends_to_existing_user_js(self, tmp_path: Path) -> None:
        profile_dir = tmp_path / "test.default"
        profile_dir.mkdir()
        (profile_dir / "prefs.js").write_text("")
        (profile_dir / "extensions.json").write_text('{"addons": []}')
        existing = 'user_pref("some.existing.pref", true);\n'
        (profile_dir / "user.js").write_text(existing)

        profile = BrowserProfile("firefox", profile_dir, {}, [])
        with patch(
            "dont_track_me.modules.fingerprint.protector.find_browser_profiles",
            return_value=[profile],
        ):
            await protect_fingerprint(dry_run=False)

        content = (profile_dir / "user.js").read_text()
        assert existing in content  # Existing content preserved
        assert "privacy.resistFingerprinting" in content

    @pytest.mark.asyncio()
    async def test_apply_skips_already_hardened(self, tmp_path: Path) -> None:
        profile_dir = tmp_path / "test.default"
        profile_dir.mkdir()
        (profile_dir / "prefs.js").write_text("")
        (profile_dir / "extensions.json").write_text('{"addons": []}')
        (profile_dir / "user.js").write_text(f"existing\n{_MARKER}\nmore prefs\n")

        profile = BrowserProfile("firefox", profile_dir, {}, [])
        with patch(
            "dont_track_me.modules.fingerprint.protector.find_browser_profiles",
            return_value=[profile],
        ):
            result = await protect_fingerprint(dry_run=False)

        assert len(result.actions_taken) == 0


class TestWriteUserJs:
    def test_creates_new_user_js(self, tmp_path: Path) -> None:
        result = _write_user_js(tmp_path)
        assert result is not None
        content = (tmp_path / "user.js").read_text()
        assert _MARKER in content
        assert "privacy.resistFingerprinting" in content

    def test_appends_to_existing(self, tmp_path: Path) -> None:
        existing = 'user_pref("my.pref", 42);\n'
        (tmp_path / "user.js").write_text(existing)
        result = _write_user_js(tmp_path)
        assert result is not None
        content = (tmp_path / "user.js").read_text()
        assert content.startswith(existing)
        assert _MARKER in content

    def test_skips_if_already_applied(self, tmp_path: Path) -> None:
        (tmp_path / "user.js").write_text(f"stuff\n{_MARKER}\nmore stuff\n")
        result = _write_user_js(tmp_path)
        assert result is None

    def test_skips_symlinked_user_js(self, tmp_path: Path) -> None:
        real_file = tmp_path / "real_user.js"
        real_file.write_text("content")
        symlink = tmp_path / "user.js"
        symlink.symlink_to(real_file)
        result = _write_user_js(tmp_path)
        # Should still create user.js (symlink is read, but write replaces it)
        assert result is not None
