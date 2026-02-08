"""Browser cookie protection — delete tracker cookies and harden settings."""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.cookies.auditor import (
    MAX_FILE_SIZE,
    _find_cookie_databases,
    _read_cookie_db,
)
from dont_track_me.modules.cookies.trackers import is_tracker_domain


def _delete_tracker_cookies_chrome(db_path: Path) -> list[str]:
    """Delete known tracker cookies from a Chrome cookie database.

    Uses copy-modify-replace to avoid corrupting the live database.
    Returns list of deleted domain descriptions.
    """
    pending: list[str] = []

    tmp_dir = tempfile.mkdtemp()
    tmp_db = Path(tmp_dir) / db_path.name
    try:
        shutil.copy2(db_path, tmp_db)
        # Copy WAL/SHM for consistency, skip symlinks
        for suffix in ("-wal", "-shm"):
            wal = db_path.parent / (db_path.name + suffix)
            if wal.exists() and not wal.is_symlink():
                shutil.copy2(wal, Path(tmp_dir) / (db_path.name + suffix))

        conn = sqlite3.connect(str(tmp_db))
        try:
            cursor = conn.cursor()
            # Find all unique host_keys
            cursor.execute("SELECT DISTINCT host_key FROM cookies")
            hosts = [row[0] for row in cursor.fetchall()]

            for host in hosts:
                is_tracker, match = is_tracker_domain(host)
                if is_tracker:
                    cursor.execute("DELETE FROM cookies WHERE host_key = ?", (host,))
                    if cursor.rowcount > 0:
                        pending.append(f"{host} ({cursor.rowcount} cookies, tracker: {match})")

            if pending:
                conn.commit()
        finally:
            conn.close()

        if pending:
            # Atomic replace — move modified DB back
            os.replace(str(tmp_db), str(db_path))
            # Remove WAL/SHM from original location (they'll be invalid after replace)
            for suffix in ("-wal", "-shm"):
                wal = db_path.parent / (db_path.name + suffix)
                wal.unlink(missing_ok=True)
            # Only report as deleted after successful replace
            return pending
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return []


def _delete_tracker_cookies_firefox(db_path: Path) -> list[str]:
    """Delete known tracker cookies from a Firefox cookie database.

    Uses copy-modify-replace to avoid corrupting the live database.
    Returns list of deleted domain descriptions.
    """
    pending: list[str] = []

    tmp_dir = tempfile.mkdtemp()
    tmp_db = Path(tmp_dir) / db_path.name
    try:
        shutil.copy2(db_path, tmp_db)
        # Copy WAL/SHM for consistency, skip symlinks
        for suffix in ("-wal", "-shm"):
            wal = db_path.parent / (db_path.name + suffix)
            if wal.exists() and not wal.is_symlink():
                shutil.copy2(wal, Path(tmp_dir) / (db_path.name + suffix))

        conn = sqlite3.connect(str(tmp_db))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT host FROM moz_cookies")
            hosts = [row[0] for row in cursor.fetchall()]

            for host in hosts:
                is_tracker, match = is_tracker_domain(host)
                if is_tracker:
                    cursor.execute("DELETE FROM moz_cookies WHERE host = ?", (host,))
                    if cursor.rowcount > 0:
                        pending.append(f"{host} ({cursor.rowcount} cookies, tracker: {match})")

            if pending:
                conn.commit()
        finally:
            conn.close()

        if pending:
            os.replace(str(tmp_db), str(db_path))
            for suffix in ("-wal", "-shm"):
                wal = db_path.parent / (db_path.name + suffix)
                wal.unlink(missing_ok=True)
            return pending
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return []


async def protect_cookies(
    dry_run: bool = True,
    path: str | None = None,
    **kwargs: Any,
) -> ProtectionResult:
    """Delete tracker cookies and provide browser hardening guidance."""
    actions_available: list[str] = []
    actions_taken: list[str] = []

    # Find databases
    if path:
        db_path = Path(path)
        if db_path.is_file() and not db_path.is_symlink():
            browser = "firefox" if "cookies.sqlite" in db_path.name else "chrome"
            db_list = [(db_path, browser)]
        else:
            db_list = []
    else:
        db_list = _find_cookie_databases()

    for db_path, browser in db_list:
        try:
            if db_path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        # Read to identify tracker cookies for dry-run listing
        result = _read_cookie_db(db_path, browser)
        if result.error:
            continue

        # Count tracker cookies per domain
        tracker_hosts: dict[str, int] = {}
        for cookie in result.cookies:
            is_tracker, _match = is_tracker_domain(cookie.host)
            if is_tracker:
                domain = cookie.host.lstrip(".")
                tracker_hosts[domain] = tracker_hosts.get(domain, 0) + 1

        if not tracker_hosts:
            continue

        for domain, count in sorted(tracker_hosts.items(), key=lambda x: x[1], reverse=True):
            actions_available.append(f"Delete {count} tracking cookies from {browser}: {domain}")

        if not dry_run:
            try:
                if browser == "chrome":
                    deleted = _delete_tracker_cookies_chrome(db_path)
                else:
                    deleted = _delete_tracker_cookies_firefox(db_path)

                for desc in deleted:
                    actions_taken.append(f"Deleted {browser} cookies: {desc}")
            except (OSError, sqlite3.Error):
                actions_taken.append(f"Failed to modify {browser} cookie database at {db_path}")

    # Browser hardening recommendations (always included)
    actions_available.extend(
        [
            "Block third-party cookies in Chrome: "
            "Settings → Privacy and security → Third-party cookies → Block third-party cookies",
            "Block third-party cookies in Firefox: "
            "Settings → Privacy & Security → Enhanced Tracking Protection → Strict",
            "Use a cookie management extension (Cookie AutoDelete, uBlock Origin)",
            "Use a privacy-focused browser (Brave, LibreWolf, Firefox with strict mode)",
        ]
    )

    return ProtectionResult(
        module_name="cookies",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
