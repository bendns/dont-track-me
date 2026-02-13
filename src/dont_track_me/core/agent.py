"""Interface with the dtm-agent Rust daemon's event database."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


def get_agent_db() -> Path | None:
    """Find the dtm-agent event database."""
    db_path = Path.home() / ".local" / "share" / "dtm" / "events.db"
    return db_path if db_path.exists() else None


def get_app_scan_results(db: Path) -> list[dict[str, Any]]:
    """Read app scan results from the agent database."""
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.execute(
            "SELECT app_name, bundle_id, app_path, tracking_sdks, "
            "ats_exceptions, binary_size, scanned_at FROM app_scans "
            "ORDER BY app_name"
        )
        results = []
        for row in cursor:
            results.append(
                {
                    "app_name": row["app_name"],
                    "bundle_id": row["bundle_id"],
                    "app_path": row["app_path"],
                    "tracking_sdks": _safe_json_loads(row["tracking_sdks"]),
                    "ats_exceptions": _safe_json_loads(row["ats_exceptions"]),
                    "binary_size": row["binary_size"],
                    "scanned_at": row["scanned_at"],
                }
            )
        return results
    except (sqlite3.OperationalError, json.JSONDecodeError, TypeError):
        return []
    finally:
        conn.close()


def _safe_json_loads(value: str | None) -> list[Any]:
    """Parse a JSON string, returning [] on NULL or malformed data."""
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []


def get_dns_events(
    db: Path,
    since: datetime | None = None,
    tracker_only: bool = False,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Read DNS events from the agent database."""
    limit = max(1, min(limit, 10000))
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        query = "SELECT timestamp, domain, query_type, is_tracker, tracker_category, process_name, process_pid FROM dns_events"
        conditions = []
        params: list[Any] = []

        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        if tracker_only:
            conditions.append("is_tracker = 1")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
