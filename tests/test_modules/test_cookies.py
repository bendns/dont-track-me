"""Tests for the browser cookie analysis module."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from dont_track_me.modules.cookies.auditor import (
    CookieInfo,
    _analyze_domains,
    _find_cookie_databases,
    _read_cookie_db,
    audit_cookies,
)
from dont_track_me.modules.cookies.protector import (
    _delete_tracker_cookies_chrome,
    _delete_tracker_cookies_firefox,
    protect_cookies,
)
from dont_track_me.modules.cookies.trackers import is_tracker_domain

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_chrome_db(
    db_path: Path, cookies: list[tuple[str, str, int, int, int, int, int]]
) -> None:
    """Create a mock Chrome Cookies SQLite database.

    Each cookie tuple: (host_key, name, is_secure, is_httponly, samesite, has_expires, expires_utc)
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE cookies ("
        "  host_key TEXT NOT NULL,"
        "  name TEXT NOT NULL,"
        "  is_secure INTEGER NOT NULL DEFAULT 0,"
        "  is_httponly INTEGER NOT NULL DEFAULT 0,"
        "  samesite INTEGER NOT NULL DEFAULT -1,"
        "  has_expires INTEGER NOT NULL DEFAULT 1,"
        "  expires_utc INTEGER NOT NULL DEFAULT 0"
        ")"
    )
    conn.executemany(
        "INSERT INTO cookies (host_key, name, is_secure, is_httponly, samesite, has_expires, expires_utc) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        cookies,
    )
    conn.commit()
    conn.close()


def _create_firefox_db(db_path: Path, cookies: list[tuple[str, str, int, int, int, int]]) -> None:
    """Create a mock Firefox cookies.sqlite database.

    Each cookie tuple: (host, name, isSecure, isHttpOnly, sameSite, expiry)
    """
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
    conn.executemany(
        "INSERT INTO moz_cookies (host, name, isSecure, isHttpOnly, sameSite, expiry) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        cookies,
    )
    conn.commit()
    conn.close()


# Chrome epoch: microseconds since 1601-01-01
# To get a far-future Chrome timestamp: (unix_timestamp + 11644473600) * 1_000_000
_FAR_FUTURE_CHROME = (2000000000 + 11644473600) * 1_000_000  # ~year 2033
_FAR_FUTURE_UNIX = 2000000000  # ~year 2033


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def chrome_db(tmp_path: Path) -> Path:
    """Chrome Cookies DB with a mix of first-party, third-party, and tracker cookies."""
    db_path = tmp_path / "Cookies"
    _create_chrome_db(
        db_path,
        [
            # First-party cookies
            ("example.com", "session_id", 1, 1, 2, 1, _FAR_FUTURE_CHROME),
            ("example.com", "prefs", 1, 0, 1, 1, _FAR_FUTURE_CHROME),
            # Known tracker cookies
            (".doubleclick.net", "id", 0, 0, -1, 1, _FAR_FUTURE_CHROME),
            (".doubleclick.net", "IDE", 0, 0, -1, 1, _FAR_FUTURE_CHROME),
            (".facebook.com", "fr", 0, 0, -1, 1, _FAR_FUTURE_CHROME),
            (".criteo.com", "uid", 0, 0, -1, 1, _FAR_FUTURE_CHROME),
            (".google-analytics.com", "_ga", 0, 0, -1, 1, _FAR_FUTURE_CHROME),
            # Third-party with weak security (SameSite=None=-1, no HttpOnly)
            (".unknown-ad.com", "track", 0, 0, -1, 1, _FAR_FUTURE_CHROME),
        ],
    )
    return db_path


@pytest.fixture()
def firefox_db(tmp_path: Path) -> Path:
    """Firefox cookies.sqlite with tracker and clean cookies."""
    db_path = tmp_path / "cookies.sqlite"
    _create_firefox_db(
        db_path,
        [
            # First-party
            ("example.com", "session", 1, 1, 2, _FAR_FUTURE_UNIX),
            # Trackers
            (".doubleclick.net", "id", 0, 0, 0, _FAR_FUTURE_UNIX),
            (".facebook.net", "fbp", 0, 0, 0, _FAR_FUTURE_UNIX),
            (".hotjar.com", "_hj", 0, 0, 0, _FAR_FUTURE_UNIX),
        ],
    )
    return db_path


@pytest.fixture()
def clean_db(tmp_path: Path) -> Path:
    """Chrome Cookies DB with only well-configured first-party cookies."""
    db_path = tmp_path / "Cookies"
    _create_chrome_db(
        db_path,
        [
            # Secure, HttpOnly, SameSite=Strict, session cookies (no long expiry)
            ("example.com", "session_id", 1, 1, 2, 0, 0),
            ("mysite.org", "prefs", 1, 1, 2, 0, 0),
        ],
    )
    return db_path


# ---------------------------------------------------------------------------
# Tracker domain tests
# ---------------------------------------------------------------------------


class TestTrackerDomain:
    def test_known_tracker_exact(self) -> None:
        is_tracker, match = is_tracker_domain("doubleclick.net")
        assert is_tracker is True
        assert match == "doubleclick.net"

    def test_known_tracker_with_leading_dot(self) -> None:
        is_tracker, match = is_tracker_domain(".facebook.com")
        assert is_tracker is True
        assert match == "facebook.com"

    def test_known_tracker_subdomain(self) -> None:
        is_tracker, match = is_tracker_domain("ads.doubleclick.net")
        assert is_tracker is True
        assert match == "doubleclick.net"

    def test_unknown_domain(self) -> None:
        is_tracker, match = is_tracker_domain("example.com")
        assert is_tracker is False
        assert match == ""

    def test_unknown_domain_with_dot(self) -> None:
        is_tracker, match = is_tracker_domain(".mysite.org")
        assert is_tracker is False
        assert match == ""


# ---------------------------------------------------------------------------
# Database discovery tests
# ---------------------------------------------------------------------------


class TestFindDatabases:
    def test_finds_chrome_macos(self, tmp_path: Path) -> None:
        chrome_dir = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
        chrome_dir.mkdir(parents=True)
        cookie_db = chrome_dir / "Cookies"
        cookie_db.write_bytes(b"")

        with (
            patch("dont_track_me.modules.cookies.auditor.Path.home", return_value=tmp_path),
            patch("dont_track_me.modules.cookies.auditor.platform.system", return_value="Darwin"),
        ):
            dbs = _find_cookie_databases()

        assert len(dbs) == 1
        assert dbs[0][0] == cookie_db
        assert dbs[0][1] == "chrome"

    def test_finds_firefox_macos(self, tmp_path: Path) -> None:
        ff_dir = (
            tmp_path / "Library" / "Application Support" / "Firefox" / "Profiles" / "abc123.default"
        )
        ff_dir.mkdir(parents=True)
        cookie_db = ff_dir / "cookies.sqlite"
        cookie_db.write_bytes(b"")

        with (
            patch("dont_track_me.modules.cookies.auditor.Path.home", return_value=tmp_path),
            patch("dont_track_me.modules.cookies.auditor.platform.system", return_value="Darwin"),
        ):
            dbs = _find_cookie_databases()

        assert len(dbs) == 1
        assert dbs[0][0] == cookie_db
        assert dbs[0][1] == "firefox"

    def test_finds_chrome_linux(self, tmp_path: Path) -> None:
        chrome_dir = tmp_path / ".config" / "google-chrome" / "Default"
        chrome_dir.mkdir(parents=True)
        cookie_db = chrome_dir / "Cookies"
        cookie_db.write_bytes(b"")

        with (
            patch("dont_track_me.modules.cookies.auditor.Path.home", return_value=tmp_path),
            patch("dont_track_me.modules.cookies.auditor.platform.system", return_value="Linux"),
        ):
            dbs = _find_cookie_databases()

        assert len(dbs) == 1
        assert dbs[0][0] == cookie_db
        assert dbs[0][1] == "chrome"

    def test_skips_symlinks(self, tmp_path: Path) -> None:
        chrome_dir = tmp_path / "Library" / "Application Support" / "Google" / "Chrome" / "Default"
        chrome_dir.mkdir(parents=True)
        real_db = tmp_path / "real_cookies"
        real_db.write_bytes(b"")
        symlink = chrome_dir / "Cookies"
        symlink.symlink_to(real_db)

        with (
            patch("dont_track_me.modules.cookies.auditor.Path.home", return_value=tmp_path),
            patch("dont_track_me.modules.cookies.auditor.platform.system", return_value="Darwin"),
        ):
            dbs = _find_cookie_databases()

        assert len(dbs) == 0

    def test_no_browsers_installed(self, tmp_path: Path) -> None:
        with (
            patch("dont_track_me.modules.cookies.auditor.Path.home", return_value=tmp_path),
            patch("dont_track_me.modules.cookies.auditor.platform.system", return_value="Darwin"),
        ):
            dbs = _find_cookie_databases()

        assert len(dbs) == 0


# ---------------------------------------------------------------------------
# Database reading tests
# ---------------------------------------------------------------------------


class TestReadCookieDb:
    def test_read_chrome_cookies(self, chrome_db: Path) -> None:
        result = _read_cookie_db(chrome_db, "chrome")
        assert result.error is None
        assert len(result.cookies) == 8
        assert result.browser == "chrome"

        # Check a tracker cookie
        tracker = [c for c in result.cookies if c.host == ".doubleclick.net"]
        assert len(tracker) == 2

    def test_read_firefox_cookies(self, firefox_db: Path) -> None:
        result = _read_cookie_db(firefox_db, "firefox")
        assert result.error is None
        assert len(result.cookies) == 4
        assert result.browser == "firefox"

    def test_read_nonexistent_db(self, tmp_path: Path) -> None:
        result = _read_cookie_db(tmp_path / "nonexistent", "chrome")
        assert result.error is not None

    def test_read_oversized_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "Cookies"
        db_path.write_bytes(b"x")  # 1 byte file

        with patch("dont_track_me.modules.cookies.auditor.MAX_FILE_SIZE", 0):
            result = _read_cookie_db(db_path, "chrome")

        assert result.error == "Database too large"

    def test_read_invalid_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "Cookies"
        db_path.write_text("not a sqlite database")
        result = _read_cookie_db(db_path, "chrome")
        assert result.error is not None


# ---------------------------------------------------------------------------
# Domain analysis tests
# ---------------------------------------------------------------------------


class TestAnalyzeDomains:
    def test_groups_by_domain(self) -> None:
        cookies = [
            CookieInfo(".example.com", "a", True, True, 2, _FAR_FUTURE_UNIX, "chrome"),
            CookieInfo(".example.com", "b", True, True, 1, _FAR_FUTURE_UNIX, "chrome"),
            CookieInfo(".other.com", "c", True, True, 2, _FAR_FUTURE_UNIX, "chrome"),
        ]
        stats = _analyze_domains(cookies)
        assert len(stats) == 2
        assert stats["example.com"].cookie_count == 2
        assert stats["other.com"].cookie_count == 1

    def test_detects_tracker(self) -> None:
        cookies = [
            CookieInfo(".doubleclick.net", "id", False, False, -1, _FAR_FUTURE_UNIX, "chrome"),
        ]
        stats = _analyze_domains(cookies)
        assert stats["doubleclick.net"].is_tracker is True

    def test_detects_samesite_none_chrome(self) -> None:
        cookies = [
            CookieInfo(".example.com", "a", True, True, -1, _FAR_FUTURE_UNIX, "chrome"),
        ]
        stats = _analyze_domains(cookies)
        assert stats["example.com"].has_samesite_none is True

    def test_detects_samesite_none_firefox(self) -> None:
        cookies = [
            CookieInfo(".example.com", "a", True, True, 0, _FAR_FUTURE_UNIX, "firefox"),
        ]
        stats = _analyze_domains(cookies)
        assert stats["example.com"].has_samesite_none is True

    def test_detects_no_httponly(self) -> None:
        cookies = [
            CookieInfo(".example.com", "a", True, False, 2, _FAR_FUTURE_UNIX, "chrome"),
        ]
        stats = _analyze_domains(cookies)
        assert stats["example.com"].has_no_httponly is True

    def test_detects_long_expiry(self) -> None:
        cookies = [
            CookieInfo(".example.com", "a", True, True, 2, _FAR_FUTURE_UNIX, "chrome"),
        ]
        stats = _analyze_domains(cookies)
        assert stats["example.com"].has_long_expiry is True


# ---------------------------------------------------------------------------
# Audit tests
# ---------------------------------------------------------------------------


class TestAuditCookies:
    @pytest.mark.asyncio()
    async def test_audit_chrome_db(self, chrome_db: Path) -> None:
        result = await audit_cookies(path=str(chrome_db))
        assert result.module_name == "cookies"
        assert result.score < 100  # Has tracker cookies
        assert any(f.title.startswith("Tracking cookies: doubleclick.net") for f in result.findings)
        assert result.raw_data["total_cookies"] == 8
        assert "doubleclick.net" in result.raw_data["tracker_domains"]

    @pytest.mark.asyncio()
    async def test_audit_firefox_db(self, firefox_db: Path) -> None:
        result = await audit_cookies(path=str(firefox_db))
        assert result.module_name == "cookies"
        assert result.score < 100
        assert any("doubleclick.net" in f.title for f in result.findings)

    @pytest.mark.asyncio()
    async def test_audit_clean_db(self, clean_db: Path) -> None:
        result = await audit_cookies(path=str(clean_db))
        assert result.score == 100
        assert not any(f.threat_level.name == "HIGH" for f in result.findings)

    @pytest.mark.asyncio()
    async def test_audit_no_databases(self, tmp_path: Path) -> None:
        result = await audit_cookies(path=str(tmp_path / "nonexistent"))
        assert result.score == 100
        assert any("No browser cookie databases found" in f.title for f in result.findings)

    @pytest.mark.asyncio()
    async def test_audit_empty_db(self, tmp_path: Path) -> None:
        db_path = tmp_path / "Cookies"
        _create_chrome_db(db_path, [])
        result = await audit_cookies(path=str(db_path))
        assert result.score == 100
        assert any("No cookies found" in f.title for f in result.findings)

    @pytest.mark.asyncio()
    async def test_audit_auto_detect(self) -> None:
        with patch("dont_track_me.modules.cookies.auditor._find_cookie_databases", return_value=[]):
            result = await audit_cookies()
        assert result.score == 100
        assert any("No browser cookie databases found" in f.title for f in result.findings)


# ---------------------------------------------------------------------------
# Protector tests
# ---------------------------------------------------------------------------


class TestProtectCookies:
    @pytest.mark.asyncio()
    async def test_dry_run_lists_tracker_cookies(self, chrome_db: Path) -> None:
        result = await protect_cookies(dry_run=True, path=str(chrome_db))
        assert result.dry_run is True
        assert len(result.actions_taken) == 0
        # Should list tracker domains to delete
        assert any("doubleclick.net" in a for a in result.actions_available)
        assert any("facebook.com" in a for a in result.actions_available)

        # DB should be unmodified — tracker cookies still present
        from dont_track_me.modules.cookies.auditor import _read_cookie_db

        db_result = _read_cookie_db(chrome_db, "chrome")
        tracker_cookies = [c for c in db_result.cookies if c.host == ".doubleclick.net"]
        assert len(tracker_cookies) == 2

    @pytest.mark.asyncio()
    async def test_apply_deletes_tracker_cookies_chrome(self, chrome_db: Path) -> None:
        result = await protect_cookies(dry_run=False, path=str(chrome_db))
        assert result.dry_run is False
        assert len(result.actions_taken) > 0
        assert any("doubleclick.net" in a for a in result.actions_taken)

        # Verify tracker cookies are gone
        from dont_track_me.modules.cookies.auditor import _read_cookie_db

        db_result = _read_cookie_db(chrome_db, "chrome")
        tracker_cookies = [c for c in db_result.cookies if c.host == ".doubleclick.net"]
        assert len(tracker_cookies) == 0

        # First-party cookies should still be there
        first_party = [c for c in db_result.cookies if c.host == "example.com"]
        assert len(first_party) == 2

    @pytest.mark.asyncio()
    async def test_apply_deletes_tracker_cookies_firefox(self, firefox_db: Path) -> None:
        result = await protect_cookies(dry_run=False, path=str(firefox_db))
        assert result.dry_run is False
        assert len(result.actions_taken) > 0

        # Verify tracker cookies are gone
        from dont_track_me.modules.cookies.auditor import _read_cookie_db

        db_result = _read_cookie_db(firefox_db, "firefox")
        tracker_cookies = [c for c in db_result.cookies if c.host == ".doubleclick.net"]
        assert len(tracker_cookies) == 0

        # First-party should remain
        first_party = [c for c in db_result.cookies if c.host == "example.com"]
        assert len(first_party) == 1

    @pytest.mark.asyncio()
    async def test_protect_clean_db_no_actions(self, clean_db: Path) -> None:
        result = await protect_cookies(dry_run=False, path=str(clean_db))
        assert len(result.actions_taken) == 0
        # Should still have hardening recommendations
        assert any("Block third-party cookies" in a for a in result.actions_available)

    @pytest.mark.asyncio()
    async def test_protect_always_includes_recommendations(self, chrome_db: Path) -> None:
        result = await protect_cookies(dry_run=True, path=str(chrome_db))
        assert any("Block third-party cookies in Chrome" in a for a in result.actions_available)
        assert any("Block third-party cookies in Firefox" in a for a in result.actions_available)
        assert any("privacy-focused browser" in a for a in result.actions_available)

    @pytest.mark.asyncio()
    async def test_protect_nonexistent_path(self, tmp_path: Path) -> None:
        result = await protect_cookies(dry_run=True, path=str(tmp_path / "nonexistent"))
        # Should still return recommendations even with no DBs
        assert any("Block third-party cookies" in a for a in result.actions_available)


class TestDeleteTrackerCookies:
    def test_delete_chrome_tracker_cookies(self, chrome_db: Path) -> None:
        deleted = _delete_tracker_cookies_chrome(chrome_db)
        assert len(deleted) > 0
        assert any("doubleclick.net" in d for d in deleted)

        # Verify in DB
        conn = sqlite3.connect(str(chrome_db))
        count = conn.execute(
            "SELECT COUNT(*) FROM cookies WHERE host_key = '.doubleclick.net'"
        ).fetchone()[0]
        conn.close()
        assert count == 0

    def test_delete_firefox_tracker_cookies(self, firefox_db: Path) -> None:
        deleted = _delete_tracker_cookies_firefox(firefox_db)
        assert len(deleted) > 0
        assert any("doubleclick.net" in d for d in deleted)

        # Verify in DB
        conn = sqlite3.connect(str(firefox_db))
        count = conn.execute(
            "SELECT COUNT(*) FROM moz_cookies WHERE host = '.doubleclick.net'"
        ).fetchone()[0]
        conn.close()
        assert count == 0

    def test_delete_preserves_first_party(self, chrome_db: Path) -> None:
        _delete_tracker_cookies_chrome(chrome_db)

        conn = sqlite3.connect(str(chrome_db))
        first_party = conn.execute(
            "SELECT COUNT(*) FROM cookies WHERE host_key = 'example.com'"
        ).fetchone()[0]
        conn.close()
        assert first_party == 2

    def test_delete_clean_db_no_changes(self, clean_db: Path) -> None:
        deleted = _delete_tracker_cookies_chrome(clean_db)
        assert len(deleted) == 0
