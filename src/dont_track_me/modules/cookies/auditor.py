"""Browser cookie analysis — detect third-party tracking cookies."""

from __future__ import annotations

import platform
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.modules.cookies.trackers import is_tracker_domain

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB (cookie DBs can be large)

# Chrome stores timestamps as microseconds since 1601-01-01
_CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601 and 1970
_ONE_YEAR_SECONDS = 365 * 24 * 60 * 60


@dataclass
class CookieInfo:
    """Metadata about a single cookie (no value stored)."""

    host: str
    name: str
    is_secure: bool
    is_httponly: bool
    samesite: int  # 0=unset, 1=Lax, 2=Strict, -1=None (Chrome), None=unset (Firefox)
    expires_epoch: int | None  # Unix timestamp, None for session cookies
    browser: str  # "chrome" or "firefox"


@dataclass
class DomainStats:
    """Aggregated cookie stats for a domain."""

    domain: str
    cookie_count: int = 0
    is_tracker: bool = False
    tracker_match: str = ""
    has_samesite_none: bool = False
    has_no_httponly: bool = False
    has_long_expiry: bool = False


@dataclass
class DatabaseResult:
    """Result of scanning a single cookie database."""

    path: Path
    browser: str
    cookies: list[CookieInfo] = field(default_factory=list)
    error: str | None = None


def _find_cookie_databases() -> list[tuple[Path, str]]:
    """Auto-detect Chrome and Firefox cookie database paths.

    Returns list of (path, browser_name) tuples.
    """
    databases: list[tuple[Path, str]] = []
    home = Path.home()
    system = platform.system()

    if system == "Darwin":
        # Chrome on macOS
        chrome_base = home / "Library" / "Application Support" / "Google" / "Chrome"
        if chrome_base.exists():
            for profile_dir in chrome_base.iterdir():
                cookie_db = profile_dir / "Cookies"
                if cookie_db.is_file() and not cookie_db.is_symlink():
                    databases.append((cookie_db, "chrome"))

        # Firefox on macOS
        firefox_base = home / "Library" / "Application Support" / "Firefox" / "Profiles"
        if firefox_base.exists():
            for profile_dir in firefox_base.iterdir():
                cookie_db = profile_dir / "cookies.sqlite"
                if cookie_db.is_file() and not cookie_db.is_symlink():
                    databases.append((cookie_db, "firefox"))

    elif system == "Linux":
        # Chrome on Linux
        chrome_base = home / ".config" / "google-chrome"
        if chrome_base.exists():
            for profile_dir in chrome_base.iterdir():
                cookie_db = profile_dir / "Cookies"
                if cookie_db.is_file() and not cookie_db.is_symlink():
                    databases.append((cookie_db, "chrome"))

        # Firefox on Linux
        firefox_base = home / ".mozilla" / "firefox"
        if firefox_base.exists():
            for profile_dir in firefox_base.iterdir():
                cookie_db = profile_dir / "cookies.sqlite"
                if cookie_db.is_file() and not cookie_db.is_symlink():
                    databases.append((cookie_db, "firefox"))

    return databases


def _read_cookie_db(db_path: Path, browser: str) -> DatabaseResult:
    """Read cookie metadata from a browser SQLite database.

    Copies the database to a temp file first to avoid WAL lock conflicts.
    Never reads the value column.
    """
    result = DatabaseResult(path=db_path, browser=browser)

    try:
        if db_path.stat().st_size > MAX_FILE_SIZE:
            result.error = "Database too large"
            return result
    except OSError:
        result.error = "Cannot stat database"
        return result

    # Copy to temp to avoid WAL lock conflicts with the browser
    tmp_dir = tempfile.mkdtemp()
    tmp_db = Path(tmp_dir) / db_path.name
    try:
        shutil.copy2(db_path, tmp_db)
        # Also copy WAL/SHM files if present (needed for consistent reads), skip symlinks
        for suffix in ("-wal", "-shm"):
            wal = db_path.parent / (db_path.name + suffix)
            if wal.exists() and not wal.is_symlink():
                shutil.copy2(wal, Path(tmp_dir) / (db_path.name + suffix))

        conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if browser == "chrome":
                result.cookies = _read_chrome_cookies(cursor)
            elif browser == "firefox":
                result.cookies = _read_firefox_cookies(cursor)
        finally:
            conn.close()

    except (OSError, sqlite3.Error) as e:
        result.error = str(e)
    finally:
        # Clean up temp files
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return result


def _read_chrome_cookies(cursor: sqlite3.Cursor) -> list[CookieInfo]:
    """Read cookie metadata from a Chrome cookies database."""
    cookies: list[CookieInfo] = []
    try:
        cursor.execute(
            "SELECT host_key, name, is_secure, is_httponly, samesite, "
            "has_expires, expires_utc FROM cookies"
        )
    except sqlite3.OperationalError:
        return cookies

    now = time.time()
    for row in cursor.fetchall():
        expires_epoch = None
        if row["has_expires"] and row["expires_utc"]:
            # Chrome stores microseconds since 1601-01-01
            expires_epoch = int(row["expires_utc"] / 1_000_000 - _CHROME_EPOCH_OFFSET)

        cookies.append(
            CookieInfo(
                host=row["host_key"],
                name=row["name"],
                is_secure=bool(row["is_secure"]),
                is_httponly=bool(row["is_httponly"]),
                samesite=row["samesite"],
                expires_epoch=expires_epoch if expires_epoch and expires_epoch > now else None,
                browser="chrome",
            )
        )
    return cookies


def _read_firefox_cookies(cursor: sqlite3.Cursor) -> list[CookieInfo]:
    """Read cookie metadata from a Firefox cookies database."""
    cookies: list[CookieInfo] = []
    try:
        cursor.execute("SELECT host, name, isSecure, isHttpOnly, sameSite, expiry FROM moz_cookies")
    except sqlite3.OperationalError:
        return cookies

    now = time.time()
    for row in cursor.fetchall():
        expiry = row["expiry"]
        expires_epoch = expiry if expiry and expiry > now else None

        cookies.append(
            CookieInfo(
                host=row["host"],
                name=row["name"],
                is_secure=bool(row["isSecure"]),
                is_httponly=bool(row["isHttpOnly"]),
                samesite=row["sameSite"],
                expires_epoch=expires_epoch,
                browser="firefox",
            )
        )
    return cookies


def _analyze_domains(cookies: list[CookieInfo]) -> dict[str, DomainStats]:
    """Group cookies by domain and compute per-domain statistics."""
    domains: dict[str, DomainStats] = {}
    now = time.time()

    for cookie in cookies:
        host = cookie.host.lstrip(".")
        if host not in domains:
            is_tracker, match = is_tracker_domain(cookie.host)
            domains[host] = DomainStats(
                domain=host,
                is_tracker=is_tracker,
                tracker_match=match,
            )

        stats = domains[host]
        stats.cookie_count += 1

        # SameSite=None in Chrome is -1, in Firefox it's 0
        if cookie.samesite == -1 or (cookie.browser == "firefox" and cookie.samesite == 0):
            stats.has_samesite_none = True

        if not cookie.is_httponly:
            stats.has_no_httponly = True

        if cookie.expires_epoch and (cookie.expires_epoch - now) > _ONE_YEAR_SECONDS:
            stats.has_long_expiry = True

    return domains


async def audit_cookies(path: str | None = None, **kwargs: Any) -> AuditResult:
    """Analyze browser cookies for third-party tracking."""
    findings: list[Finding] = []
    score = 100

    # Find cookie databases
    if path:
        # User-specified path (for testing or manual scan)
        db_path = Path(path)
        if db_path.is_file() and not db_path.is_symlink():
            # Guess browser from filename
            browser = "firefox" if "cookies.sqlite" in db_path.name else "chrome"
            db_list = [(db_path, browser)]
        else:
            db_list = []
    else:
        db_list = _find_cookie_databases()

    if not db_list:
        findings.append(
            Finding(
                title="No browser cookie databases found",
                description=(
                    "Could not locate Chrome or Firefox cookie databases. "
                    "This may mean no supported browser is installed, or the "
                    "profile directories are in non-standard locations."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="Specify a path manually with --path, or check browser installation.",
            )
        )
        return AuditResult(
            module_name="cookies",
            score=100,
            findings=findings,
            raw_data={"browsers_found": [], "databases_scanned": 0},
        )

    # Read all databases
    all_cookies: list[CookieInfo] = []
    databases_scanned = 0
    browsers_found: set[str] = set()

    for db_path, browser in db_list:
        result = _read_cookie_db(db_path, browser)
        if result.error:
            findings.append(
                Finding(
                    title=f"Could not read {browser} cookie database",
                    description=f"Error reading {db_path.name}: {result.error}",
                    threat_level=ThreatLevel.INFO,
                    remediation="Close the browser and try again, or check file permissions.",
                )
            )
            continue
        databases_scanned += 1
        browsers_found.add(browser)
        all_cookies.extend(result.cookies)

    if not all_cookies:
        findings.append(
            Finding(
                title="No cookies found",
                description="Browser cookie databases were found but contain no cookies.",
                threat_level=ThreatLevel.INFO,
                remediation="No action needed.",
            )
        )
        return AuditResult(
            module_name="cookies",
            score=100,
            findings=findings,
            raw_data={
                "browsers_found": sorted(browsers_found),
                "databases_scanned": databases_scanned,
                "total_cookies": 0,
            },
        )

    # Analyze cookies by domain
    domain_stats = _analyze_domains(all_cookies)
    tracker_domains = [d for d in domain_stats.values() if d.is_tracker]
    third_party_domains = [d for d in domain_stats.values() if not d.is_tracker]

    # Report known tracker domains
    for stats in sorted(tracker_domains, key=lambda d: d.cookie_count, reverse=True):
        findings.append(
            Finding(
                title=f"Tracking cookies: {stats.domain} ({stats.cookie_count} cookies)",
                description=(
                    f"Known tracking domain '{stats.tracker_match}' has {stats.cookie_count} "
                    "cookies in your browser. This domain tracks you across websites."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Delete these cookies and block third-party cookies in your browser settings. "
                    "Use 'dtm protect cookies --apply' to remove tracker cookies."
                ),
            )
        )
        score -= 5

    # Report suspicious third-party domains with weak security
    for stats in sorted(third_party_domains, key=lambda d: d.cookie_count, reverse=True)[:20]:
        issues: list[str] = []
        if stats.has_samesite_none:
            issues.append("SameSite=None (cross-site tracking)")
        if stats.has_no_httponly:
            issues.append("no HttpOnly (JS-accessible)")
        if stats.has_long_expiry:
            issues.append("long expiry (>1 year)")

        if issues:
            findings.append(
                Finding(
                    title=f"Third-party cookies: {stats.domain} ({stats.cookie_count} cookies)",
                    description=(
                        f"Domain '{stats.domain}' has {stats.cookie_count} cookies with "
                        f"weak security: {', '.join(issues)}."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation="Review this domain and consider blocking it.",
                )
            )
            score -= 2

    score = max(0, min(100, score))

    return AuditResult(
        module_name="cookies",
        score=score,
        findings=findings,
        raw_data={
            "browsers_found": sorted(browsers_found),
            "databases_scanned": databases_scanned,
            "total_cookies": len(all_cookies),
            "tracker_domains": [d.domain for d in tracker_domains],
            "third_party_count": len(third_party_domains),
        },
    )
