use std::path::{Path, PathBuf};

use rusqlite::Connection;

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
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("dtm")
            .join("events.db")
    } else if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(appdata).join("dtm").join("events.db")
    } else {
        log::warn!(
            "HOME not set — using temp dir for database. \
             Set --db explicitly for a secure location."
        );
        std::env::temp_dir().join("dtm").join("events.db")
    }
}

/// Open (or create) the event database and apply schema migrations.
pub fn open_db(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Read app scan results from the database.
pub fn get_app_scan_results(conn: &Connection) -> rusqlite::Result<Vec<AppScanRow>> {
    let mut stmt = conn.prepare(
        "SELECT app_name, bundle_id, app_path, tracking_sdks, ats_exceptions, scanned_at
         FROM app_scans ORDER BY app_name",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(AppScanRow {
            app_name: row.get(0)?,
            bundle_id: row.get(1)?,
            app_path: row.get(2)?,
            tracking_sdks_json: row.get(3)?,
            ats_exceptions_json: row.get(4)?,
            scanned_at: row.get(5)?,
        })
    })?;

    rows.collect()
}

/// Read DNS events from the database.
pub fn get_dns_events(
    conn: &Connection,
    tracker_only: bool,
    limit: u32,
) -> rusqlite::Result<Vec<DnsEventRow>> {
    let limit = limit.clamp(1, 10000);
    let sql = if tracker_only {
        format!(
            "SELECT timestamp, domain, query_type, is_tracker, tracker_category, process_name, process_pid
             FROM dns_events WHERE is_tracker = 1 ORDER BY timestamp DESC LIMIT {limit}"
        )
    } else {
        format!(
            "SELECT timestamp, domain, query_type, is_tracker, tracker_category, process_name, process_pid
             FROM dns_events ORDER BY timestamp DESC LIMIT {limit}"
        )
    };

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| {
        Ok(DnsEventRow {
            timestamp: row.get(0)?,
            domain: row.get(1)?,
            query_type: row.get(2)?,
            is_tracker: row.get::<_, i32>(3)? != 0,
            tracker_category: row.get(4)?,
            process_name: row.get(5)?,
            process_pid: row.get(6)?,
        })
    })?;

    rows.collect()
}

/// Row from the app_scans table.
#[derive(Debug, Clone)]
pub struct AppScanRow {
    pub app_name: String,
    pub bundle_id: Option<String>,
    pub app_path: String,
    pub tracking_sdks_json: String,
    pub ats_exceptions_json: Option<String>,
    pub scanned_at: String,
}

/// Row from the dns_events table.
#[derive(Debug, Clone)]
pub struct DnsEventRow {
    pub timestamp: String,
    pub domain: String,
    pub query_type: String,
    pub is_tracker: bool,
    pub tracker_category: Option<String>,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
}

/// Insert an app scan result into the database.
pub fn insert_app_scan(conn: &Connection, result: &AppScanInput) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO app_scans (scanned_at, app_name, bundle_id, app_path, tracking_sdks, ats_exceptions, binary_size)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            result.scanned_at,
            result.app_name,
            result.bundle_id,
            result.app_path,
            result.tracking_sdks_json,
            result.ats_exceptions_json,
            result.binary_size,
        ],
    )?;
    Ok(())
}

/// Insert a DNS event into the database.
pub fn insert_dns_event(conn: &Connection, event: &DnsEventInput) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO dns_events (timestamp, domain, query_type, is_tracker, tracker_category, process_name, process_pid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            event.timestamp,
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

/// Clear all app scan results (before a fresh scan).
pub fn clear_app_scans(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM app_scans", [])?;
    Ok(())
}

/// Input for inserting an app scan result.
#[derive(Debug, Clone)]
pub struct AppScanInput {
    pub scanned_at: String,
    pub app_name: String,
    pub bundle_id: Option<String>,
    pub app_path: String,
    pub tracking_sdks_json: String,
    pub ats_exceptions_json: String,
    pub binary_size: u64,
}

/// Input for inserting a DNS event.
#[derive(Debug, Clone)]
pub struct DnsEventInput {
    pub timestamp: String,
    pub domain: String,
    pub query_type: String,
    pub is_tracker: bool,
    pub tracker_category: Option<String>,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_db_in_memory() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
    }

    #[test]
    fn test_get_empty_results() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let apps = get_app_scan_results(&conn).unwrap();
        assert!(apps.is_empty());

        let events = get_dns_events(&conn, false, 100).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_insert_and_read_app_scan() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let input = AppScanInput {
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
            app_name: "TestApp".to_string(),
            bundle_id: Some("com.test.app".to_string()),
            app_path: "/Applications/TestApp.app".to_string(),
            tracking_sdks_json:
                r#"[{"name":"Facebook SDK","category":"social","matched_dylib":"FBSDKCoreKit"}]"#
                    .to_string(),
            ats_exceptions_json: "[]".to_string(),
            binary_size: 1024,
        };

        insert_app_scan(&conn, &input).unwrap();

        let rows = get_app_scan_results(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].app_name, "TestApp");
        assert!(rows[0].tracking_sdks_json.contains("Facebook SDK"));
    }

    #[test]
    fn test_insert_and_read_dns_event() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let input = DnsEventInput {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            domain: "doubleclick.net".to_string(),
            query_type: "A".to_string(),
            is_tracker: true,
            tracker_category: Some("advertising".to_string()),
            process_name: Some("chrome".to_string()),
            process_pid: Some(1234),
        };

        insert_dns_event(&conn, &input).unwrap();

        let rows = get_dns_events(&conn, true, 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].domain, "doubleclick.net");
        assert!(rows[0].is_tracker);

        // Non-tracker filter should also include it
        let all = get_dns_events(&conn, false, 100).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_clear_app_scans() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let input = AppScanInput {
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
            app_name: "App".to_string(),
            bundle_id: None,
            app_path: "/path".to_string(),
            tracking_sdks_json: "[]".to_string(),
            ats_exceptions_json: "[]".to_string(),
            binary_size: 0,
        };

        insert_app_scan(&conn, &input).unwrap();
        assert_eq!(get_app_scan_results(&conn).unwrap().len(), 1);

        clear_app_scans(&conn).unwrap();
        assert!(get_app_scan_results(&conn).unwrap().is_empty());
    }

    #[test]
    fn test_multiple_app_scans() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        for i in 0..5 {
            let input = AppScanInput {
                scanned_at: format!("2024-01-0{i}T00:00:00Z"),
                app_name: format!("App{i}"),
                bundle_id: Some(format!("com.test.app{i}")),
                app_path: format!("/Applications/App{i}.app"),
                tracking_sdks_json: "[]".to_string(),
                ats_exceptions_json: "[]".to_string(),
                binary_size: 1024 * (i as u64 + 1),
            };
            insert_app_scan(&conn, &input).unwrap();
        }

        let rows = get_app_scan_results(&conn).unwrap();
        assert_eq!(rows.len(), 5);
        // Results are ordered by app_name
        assert_eq!(rows[0].app_name, "App0");
        assert_eq!(rows[4].app_name, "App4");
    }

    #[test]
    fn test_dns_events_tracker_filter() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        // Insert a tracker event
        insert_dns_event(
            &conn,
            &DnsEventInput {
                timestamp: "2024-01-01T00:00:01Z".to_string(),
                domain: "doubleclick.net".to_string(),
                query_type: "A".to_string(),
                is_tracker: true,
                tracker_category: Some("advertising".to_string()),
                process_name: Some("chrome".to_string()),
                process_pid: Some(100),
            },
        )
        .unwrap();

        // Insert a non-tracker event
        insert_dns_event(
            &conn,
            &DnsEventInput {
                timestamp: "2024-01-01T00:00:02Z".to_string(),
                domain: "example.com".to_string(),
                query_type: "A".to_string(),
                is_tracker: false,
                tracker_category: None,
                process_name: Some("curl".to_string()),
                process_pid: Some(200),
            },
        )
        .unwrap();

        // tracker_only=true should return only 1
        let tracker_only = get_dns_events(&conn, true, 100).unwrap();
        assert_eq!(tracker_only.len(), 1);
        assert_eq!(tracker_only[0].domain, "doubleclick.net");

        // tracker_only=false should return both
        let all = get_dns_events(&conn, false, 100).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_dns_events_limit() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        for i in 0..10 {
            insert_dns_event(
                &conn,
                &DnsEventInput {
                    timestamp: format!("2024-01-01T00:00:{i:02}Z"),
                    domain: format!("domain{i}.com"),
                    query_type: "A".to_string(),
                    is_tracker: false,
                    tracker_category: None,
                    process_name: None,
                    process_pid: None,
                },
            )
            .unwrap();
        }

        // Limit to 3
        let limited = get_dns_events(&conn, false, 3).unwrap();
        assert_eq!(limited.len(), 3);

        // Limit to 100 should return all 10
        let all = get_dns_events(&conn, false, 100).unwrap();
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_app_scan_with_tracking_sdks() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let sdks_json = r#"[{"name":"Facebook SDK","category":"social","matched_dylib":"FBSDKCoreKit"},{"name":"Firebase Analytics","category":"analytics","matched_dylib":"FirebaseAnalytics"}]"#;
        let input = AppScanInput {
            scanned_at: "2024-06-15T12:00:00Z".to_string(),
            app_name: "SocialApp".to_string(),
            bundle_id: Some("com.social.app".to_string()),
            app_path: "/Applications/SocialApp.app".to_string(),
            tracking_sdks_json: sdks_json.to_string(),
            ats_exceptions_json: "[]".to_string(),
            binary_size: 50_000_000,
        };

        insert_app_scan(&conn, &input).unwrap();

        let rows = get_app_scan_results(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].tracking_sdks_json.contains("Facebook SDK"));
        assert!(rows[0].tracking_sdks_json.contains("Firebase Analytics"));
        assert_eq!(rows[0].bundle_id.as_deref(), Some("com.social.app"));
    }

    #[test]
    fn test_dns_event_with_category() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();

        let input = DnsEventInput {
            timestamp: "2024-03-15T10:30:00Z".to_string(),
            domain: "analytics.google.com".to_string(),
            query_type: "AAAA".to_string(),
            is_tracker: true,
            tracker_category: Some("analytics".to_string()),
            process_name: Some("Safari".to_string()),
            process_pid: Some(5678),
        };

        insert_dns_event(&conn, &input).unwrap();

        let rows = get_dns_events(&conn, false, 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].domain, "analytics.google.com");
        assert_eq!(rows[0].query_type, "AAAA");
        assert!(rows[0].is_tracker);
        assert_eq!(rows[0].tracker_category.as_deref(), Some("analytics"));
        assert_eq!(rows[0].process_name.as_deref(), Some("Safari"));
        assert_eq!(rows[0].process_pid, Some(5678));
    }
}
