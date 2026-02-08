"""Social media tracker protection — delete cookies and harden defenses."""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.social.auditor import (
    _find_cookie_databases,
    _read_cookie_hosts,
    _read_hosts_file,
)
from dont_track_me.modules.social.trackers import (
    SOCIAL_HOSTS_BLOCKLIST,
    is_social_tracker,
)

_HOSTS_MARKER = "# dont-track-me social tracker blocking"


def _delete_social_cookies_chrome(db_path: Path) -> list[str]:
    """Delete social tracker cookies from a Chrome cookie database.

    Uses copy-modify-replace to avoid corrupting the live database.
    Returns list of deleted domain descriptions.
    """
    pending: list[str] = []

    tmp_dir = tempfile.mkdtemp()
    tmp_db = Path(tmp_dir) / db_path.name
    try:
        shutil.copy2(db_path, tmp_db)
        for suffix in ("-wal", "-shm"):
            wal = db_path.parent / (db_path.name + suffix)
            if wal.exists() and not wal.is_symlink():
                shutil.copy2(wal, Path(tmp_dir) / (db_path.name + suffix))

        conn = sqlite3.connect(str(tmp_db))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT host_key FROM cookies")
            hosts = [row[0] for row in cursor.fetchall()]

            for host in hosts:
                is_social, _matched, plat = is_social_tracker(host)
                if is_social:
                    cursor.execute("DELETE FROM cookies WHERE host_key = ?", (host,))
                    if cursor.rowcount > 0:
                        pending.append(f"{host} ({cursor.rowcount} cookies, {plat})")

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


def _delete_social_cookies_firefox(db_path: Path) -> list[str]:
    """Delete social tracker cookies from a Firefox cookie database.

    Uses copy-modify-replace to avoid corrupting the live database.
    Returns list of deleted domain descriptions.
    """
    pending: list[str] = []

    tmp_dir = tempfile.mkdtemp()
    tmp_db = Path(tmp_dir) / db_path.name
    try:
        shutil.copy2(db_path, tmp_db)
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
                is_social, _matched, plat = is_social_tracker(host)
                if is_social:
                    cursor.execute("DELETE FROM moz_cookies WHERE host = ?", (host,))
                    if cursor.rowcount > 0:
                        pending.append(f"{host} ({cursor.rowcount} cookies, {plat})")

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


def _get_unblocked_hosts() -> list[str]:
    """Return SOCIAL_HOSTS_BLOCKLIST entries not already in /etc/hosts."""
    blocked = _read_hosts_file()
    return [d for d in SOCIAL_HOSTS_BLOCKLIST if d.lower() not in blocked]


async def protect_social(
    dry_run: bool = True,
    **kwargs: Any,
) -> ProtectionResult:
    """Delete social tracker cookies and provide hardening guidance."""
    actions_available: list[str] = []
    actions_taken: list[str] = []

    # Action 1: Social tracker cookie deletion
    databases = _find_cookie_databases()
    for db_path, browser in databases:
        hosts = _read_cookie_hosts(db_path, browser)
        social_hosts: dict[str, str] = {}  # host -> platform
        for host in hosts:
            is_social, _matched, plat = is_social_tracker(host)
            if is_social:
                social_hosts[host] = plat

        if social_hosts:
            for host, plat in sorted(social_hosts.items()):
                actions_available.append(f"Delete {plat} cookies from {browser}: {host}")

            if not dry_run:
                try:
                    if browser == "chrome":
                        deleted = _delete_social_cookies_chrome(db_path)
                    else:
                        deleted = _delete_social_cookies_firefox(db_path)
                    for desc in deleted:
                        actions_taken.append(f"Deleted {browser} cookies: {desc}")
                except (OSError, sqlite3.Error):
                    actions_taken.append(f"Failed to modify {browser} cookie database at {db_path}")

    # Action 2: Hosts file blocking
    unblocked = _get_unblocked_hosts()
    if unblocked:
        actions_available.append(
            f"Block {len(unblocked)} social tracker domains in /etc/hosts "
            f"(requires root): {', '.join(unblocked[:5])}"
            + (f" and {len(unblocked) - 5} more" if len(unblocked) > 5 else "")
        )

        if not dry_run:
            try:
                lines = [f"\n{_HOSTS_MARKER}\n"]
                for domain in unblocked:
                    lines.append(f"0.0.0.0 {domain}\n")
                with open("/etc/hosts", "a") as f:
                    f.writelines(lines)
                actions_taken.append(f"Added {len(unblocked)} social tracker domains to /etc/hosts")
            except PermissionError:
                actions_taken.append(
                    "Cannot write to /etc/hosts — run with sudo for hosts-level blocking"
                )
            except OSError as e:
                actions_taken.append(f"Failed to update /etc/hosts: {e}")

    # Action 3: Browser hardening recommendations (always included)
    actions_available.extend(
        [
            "Firefox: set Enhanced Tracking Protection to Strict "
            "(Settings > Privacy & Security > Strict)",
            "Firefox: enable privacy.trackingprotection.socialtracking.enabled in about:config",
            "Chrome: block third-party cookies "
            "(Settings > Privacy and security > Third-party cookies > Block)",
            "Brave: set Shields to Aggressive for trackers & ads",
            "Install uBlock Origin, Privacy Badger, or Ghostery for "
            "cross-browser social tracker blocking",
        ]
    )

    # Action 4: Export blocklist recommendation
    actions_available.append(
        "Export social tracker blocklist in hosts format "
        "(use with Pi-hole, AdGuard Home, or /etc/hosts)"
    )

    return ProtectionResult(
        module_name="social",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
