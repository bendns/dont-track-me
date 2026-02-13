use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::models::{AppScanResult, DnsEvent};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS app_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    app_name TEXT NOT NULL,
    bundle_id TEXT,
    app_path TEXT NOT NULL,
    tracking_sdks TEXT NOT NULL,
    ats_exceptions TEXT,
    binary_size INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    domain TEXT NOT NULL,
    query_type TEXT NOT NULL,
    is_tracker INTEGER NOT NULL,
    tracker_category TEXT,
    process_name TEXT,
    process_pid INTEGER
);

CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_events(domain);
CREATE INDEX IF NOT EXISTS idx_dns_is_tracker ON dns_events(is_tracker);
CREATE INDEX IF NOT EXISTS idx_app_scans_app_name ON app_scans(app_name);
";

/// Get the default database path: ~/.local/share/dtm/events.db
pub fn default_db_path() -> PathBuf {
    let data_dir = dirs_fallback();
    data_dir.join("events.db")
}

/// Fallback for data dir without pulling in the `dirs` crate.
fn dirs_fallback() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local").join("share").join("dtm")
    } else {
        log::warn!(
            "HOME not set — using /tmp/dtm for database. \
             Set --db explicitly for a secure location."
        );
        PathBuf::from("/tmp/dtm")
    }
}

/// Open (or create) the event database and apply schema migrations.
pub fn open_db(path: &Path) -> rusqlite::Result<Connection> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Insert an app scan result into the database.
pub fn insert_app_scan(conn: &Connection, result: &AppScanResult) -> rusqlite::Result<()> {
    let sdks_json =
        serde_json::to_string(&result.tracking_sdks).unwrap_or_else(|_| "[]".to_string());
    let ats_json =
        serde_json::to_string(&result.ats_exceptions).unwrap_or_else(|_| "[]".to_string());

    conn.execute(
        "INSERT INTO app_scans (scanned_at, app_name, bundle_id, app_path, tracking_sdks, ats_exceptions, binary_size)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            result.scanned_at.to_rfc3339(),
            result.app_name,
            result.bundle_id,
            result.app_path,
            sdks_json,
            ats_json,
            result.binary_size,
        ],
    )?;
    Ok(())
}

/// Insert a DNS event into the database.
pub fn insert_dns_event(conn: &Connection, event: &DnsEvent) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO dns_events (timestamp, domain, query_type, is_tracker, tracker_category, process_name, process_pid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event.timestamp.to_rfc3339(),
            event.domain,
            event.query_type,
            event.is_tracker as i32,
            event.tracker_category,
            event.process_name,
            event.process_pid,
        ],
    )?;
    Ok(())
}

/// Clear all app scan results (used before a fresh scan).
pub fn clear_app_scans(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM app_scans", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_open_db_in_memory() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
    }

    #[test]
    fn test_insert_and_query_app_scan() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let result = AppScanResult {
            app_name: "TestApp".to_string(),
            bundle_id: Some("com.test.app".to_string()),
            app_path: "/Applications/TestApp.app".to_string(),
            tracking_sdks: vec![],
            ats_exceptions: vec![],
            binary_size: 1024,
            scanned_at: Utc::now(),
        };

        insert_app_scan(&conn, &result).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM app_scans", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_and_query_dns_event() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let event = DnsEvent {
            timestamp: Utc::now(),
            domain: "doubleclick.net".to_string(),
            query_type: "A".to_string(),
            is_tracker: true,
            tracker_category: Some("advertising".to_string()),
            process_name: Some("chrome".to_string()),
            process_pid: Some(1234),
        };

        insert_dns_event(&conn, &event).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM dns_events WHERE is_tracker = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
