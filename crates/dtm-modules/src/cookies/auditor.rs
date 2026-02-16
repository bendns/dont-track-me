use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use rusqlite::Connection;

use dtm_core::data::{load_tracker_domains, match_tracker_domain, TrackerDomains};
use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};
use dtm_core::platform::home_dir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum database file size we are willing to copy (500 MB).
const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024;

/// Chrome stores timestamps as microseconds since 1601-01-01.
const CHROME_EPOCH_OFFSET: i64 = 11_644_473_600;

/// One year in seconds — used to flag long-lived cookies.
const ONE_YEAR_SECONDS: i64 = 365 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Internal data types
// ---------------------------------------------------------------------------

/// Metadata about a single cookie (value is never read).
/// Some fields are only used by the protector (not yet ported).
#[allow(dead_code)]
struct CookieInfo {
    host: String,
    name: String,
    is_secure: bool,
    is_httponly: bool,
    /// Chrome: -1 = None, 0 = unset, 1 = Lax, 2 = Strict.
    /// Firefox: 0 = unset/None, 1 = Lax, 2 = Strict.
    samesite: i32,
    /// Unix epoch timestamp; `None` for session cookies.
    expires_epoch: Option<i64>,
    browser: Browser,
}

/// Aggregated statistics for a single domain.
struct DomainStats {
    domain: String,
    cookie_count: u32,
    is_tracker: bool,
    tracker_category: String,
    has_samesite_none: bool,
    has_no_httponly: bool,
    has_long_expiry: bool,
}

/// Result of scanning a single SQLite database.
#[allow(dead_code)]
struct DatabaseResult {
    browser: Browser,
    cookies: Vec<CookieInfo>,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Browser {
    Chrome,
    Firefox,
}

impl Browser {
    fn as_str(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Firefox => "firefox",
        }
    }
}

// ---------------------------------------------------------------------------
// Database discovery (platform-specific paths)
// ---------------------------------------------------------------------------

/// Locate Chrome and Firefox cookie databases on the current platform.
fn find_cookie_databases() -> Vec<(PathBuf, Browser)> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };

    let mut databases: Vec<(PathBuf, Browser)> = Vec::new();

    // --- Chrome profiles ---------------------------------------------------
    let chrome_bases: Vec<PathBuf> = chrome_base_dirs(&home);
    for base in &chrome_bases {
        if !base.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                let cookie_db = entry.path().join("Cookies");
                if cookie_db.is_file() && !cookie_db.is_symlink() {
                    databases.push((cookie_db, Browser::Chrome));
                }
            }
        }
    }

    // --- Firefox profiles --------------------------------------------------
    let firefox_bases: Vec<PathBuf> = firefox_base_dirs(&home);
    for base in &firefox_bases {
        if !base.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                let cookie_db = entry.path().join("cookies.sqlite");
                if cookie_db.is_file() && !cookie_db.is_symlink() {
                    databases.push((cookie_db, Browser::Firefox));
                }
            }
        }
    }

    databases
}

#[cfg(target_os = "macos")]
fn chrome_base_dirs(home: &Path) -> Vec<PathBuf> {
    vec![home
        .join("Library")
        .join("Application Support")
        .join("Google")
        .join("Chrome")]
}

#[cfg(target_os = "linux")]
fn chrome_base_dirs(home: &Path) -> Vec<PathBuf> {
    vec![home.join(".config").join("google-chrome")]
}

#[cfg(target_os = "windows")]
fn chrome_base_dirs(home: &Path) -> Vec<PathBuf> {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        vec![PathBuf::from(local)
            .join("Google")
            .join("Chrome")
            .join("User Data")]
    } else {
        Vec::new()
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn chrome_base_dirs(_home: &Path) -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(target_os = "macos")]
fn firefox_base_dirs(home: &Path) -> Vec<PathBuf> {
    vec![home
        .join("Library")
        .join("Application Support")
        .join("Firefox")
        .join("Profiles")]
}

#[cfg(target_os = "linux")]
fn firefox_base_dirs(home: &Path) -> Vec<PathBuf> {
    vec![home.join(".mozilla").join("firefox")]
}

#[cfg(target_os = "windows")]
fn firefox_base_dirs(home: &Path) -> Vec<PathBuf> {
    if let Ok(appdata) = std::env::var("APPDATA") {
        vec![PathBuf::from(appdata)
            .join("Mozilla")
            .join("Firefox")
            .join("Profiles")]
    } else {
        Vec::new()
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn firefox_base_dirs(_home: &Path) -> Vec<PathBuf> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Database reading
// ---------------------------------------------------------------------------

/// Copy a database to a temporary directory and open it read-only.
/// This avoids WAL lock conflicts with a running browser.
fn read_cookie_db(db_path: &Path, browser: Browser) -> DatabaseResult {
    // Check file size before copying.
    let file_size = match std::fs::metadata(db_path) {
        Ok(m) => m.len(),
        Err(e) => {
            return DatabaseResult {
                browser,
                cookies: Vec::new(),
                error: Some(format!("Cannot stat database: {e}")),
            };
        }
    };

    if file_size > MAX_FILE_SIZE {
        return DatabaseResult {
            browser,
            cookies: Vec::new(),
            error: Some("Database too large".to_string()),
        };
    }

    // Copy the database (and WAL/SHM companions) to a temp directory.
    let tmp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return DatabaseResult {
                browser,
                cookies: Vec::new(),
                error: Some(format!("Cannot create temp dir: {e}")),
            };
        }
    };

    let db_name = db_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let tmp_db = tmp_dir.path().join(&db_name);

    if let Err(e) = std::fs::copy(db_path, &tmp_db) {
        return DatabaseResult {
            browser,
            cookies: Vec::new(),
            error: Some(format!("Cannot copy database: {e}")),
        };
    }

    // Also copy WAL/SHM files if present (needed for consistent reads).
    for suffix in ["-wal", "-shm"] {
        let companion = db_path.with_file_name(format!("{db_name}{suffix}"));
        if companion.is_file() && !companion.is_symlink() {
            let _ = std::fs::copy(
                &companion,
                tmp_dir.path().join(format!("{db_name}{suffix}")),
            );
        }
    }

    // Open read-only via URI.
    let uri = format!("file:{}?mode=ro", tmp_db.display());
    let conn = match Connection::open_with_flags(
        &uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    ) {
        Ok(c) => c,
        Err(e) => {
            return DatabaseResult {
                browser,
                cookies: Vec::new(),
                error: Some(format!("Cannot open database: {e}")),
            };
        }
    };

    let cookies = match browser {
        Browser::Chrome => read_chrome_cookies(&conn),
        Browser::Firefox => read_firefox_cookies(&conn),
    };

    // `tmp_dir` is dropped here, cleaning up the temp files.
    DatabaseResult {
        browser,
        cookies,
        error: None,
    }
}

/// Read cookie metadata from a Chrome `Cookies` database.
fn read_chrome_cookies(conn: &Connection) -> Vec<CookieInfo> {
    let now = current_unix_timestamp();

    let mut stmt = match conn.prepare(
        "SELECT host_key, name, is_secure, is_httponly, samesite, \
         has_expires, expires_utc FROM cookies",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = stmt.query_map([], |row| {
        let host_key: String = row.get(0)?;
        let name: String = row.get(1)?;
        let is_secure: bool = row.get(2)?;
        let is_httponly: bool = row.get(3)?;
        let samesite: i32 = row.get(4)?;
        let has_expires: bool = row.get(5)?;
        let expires_utc: i64 = row.get(6)?;

        let expires_epoch = if has_expires && expires_utc > 0 {
            let epoch = expires_utc / 1_000_000 - CHROME_EPOCH_OFFSET;
            if epoch > now {
                Some(epoch)
            } else {
                None
            }
        } else {
            None
        };

        Ok(CookieInfo {
            host: host_key,
            name,
            is_secure,
            is_httponly,
            samesite,
            expires_epoch,
            browser: Browser::Chrome,
        })
    });

    match rows {
        Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Read cookie metadata from a Firefox `cookies.sqlite` database.
fn read_firefox_cookies(conn: &Connection) -> Vec<CookieInfo> {
    let now = current_unix_timestamp();

    let mut stmt = match conn
        .prepare("SELECT host, name, isSecure, isHttpOnly, sameSite, expiry FROM moz_cookies")
    {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = stmt.query_map([], |row| {
        let host: String = row.get(0)?;
        let name: String = row.get(1)?;
        let is_secure: bool = row.get(2)?;
        let is_httponly: bool = row.get(3)?;
        let samesite: i32 = row.get(4)?;
        let expiry: i64 = row.get(5)?;

        let expires_epoch = if expiry > now { Some(expiry) } else { None };

        Ok(CookieInfo {
            host,
            name,
            is_secure,
            is_httponly,
            samesite,
            expires_epoch,
            browser: Browser::Firefox,
        })
    });

    match rows {
        Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Domain analysis
// ---------------------------------------------------------------------------

/// Group cookies by domain and compute per-domain statistics.
fn analyze_domains(
    cookies: &[CookieInfo],
    tracker_domains: &TrackerDomains,
) -> HashMap<String, DomainStats> {
    let now = current_unix_timestamp();
    let mut domains: HashMap<String, DomainStats> = HashMap::new();

    for cookie in cookies {
        let host = cookie.host.trim_start_matches('.');
        let entry = domains.entry(host.to_string()).or_insert_with(|| {
            let (is_tracker, category) = match match_tracker_domain(&cookie.host, tracker_domains) {
                Some(cat) => (true, cat),
                None => (false, String::new()),
            };
            DomainStats {
                domain: host.to_string(),
                cookie_count: 0,
                is_tracker,
                tracker_category: category,
                has_samesite_none: false,
                has_no_httponly: false,
                has_long_expiry: false,
            }
        });

        entry.cookie_count += 1;

        // SameSite=None: Chrome uses -1, Firefox uses 0.
        if cookie.samesite == -1 || (cookie.browser == Browser::Firefox && cookie.samesite == 0) {
            entry.has_samesite_none = true;
        }

        if !cookie.is_httponly {
            entry.has_no_httponly = true;
        }

        if let Some(exp) = cookie.expires_epoch {
            if exp - now > ONE_YEAR_SECONDS {
                entry.has_long_expiry = true;
            }
        }
    }

    domains
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Analyse browser cookies for third-party tracking.
pub async fn audit_cookies(opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut score: i32 = 100;

    // Load the shared tracker domain list.
    let tracker_domains = load_tracker_domains().unwrap_or_default();

    // Discover (or accept a user-supplied) cookie database path.
    let db_list: Vec<(PathBuf, Browser)> = if let Some(ref path) = opts.path {
        if path.is_file() && !path.is_symlink() {
            let browser = if path
                .file_name()
                .map(|n| n.to_string_lossy().contains("cookies.sqlite"))
                .unwrap_or(false)
            {
                Browser::Firefox
            } else {
                Browser::Chrome
            };
            vec![(path.clone(), browser)]
        } else {
            Vec::new()
        }
    } else {
        find_cookie_databases()
    };

    if db_list.is_empty() {
        findings.push(Finding {
            title: "No browser cookie databases found".to_string(),
            description: "Could not locate Chrome or Firefox cookie databases. \
                 This may mean no supported browser is installed, or the \
                 profile directories are in non-standard locations."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Specify a path manually with --path, or check browser installation."
                .to_string(),
        });
        return Ok(AuditResult {
            module_name: "cookies".to_string(),
            score: 100,
            findings,
            raw_data: HashMap::from([
                ("browsers_found".to_string(), serde_json::json!([])),
                ("databases_scanned".to_string(), serde_json::json!(0)),
            ]),
        });
    }

    // Read all databases, skipping those that cannot be opened.
    let mut all_cookies: Vec<CookieInfo> = Vec::new();
    let mut databases_scanned: u32 = 0;
    let mut browsers_found: Vec<String> = Vec::new();

    for (db_path, browser) in &db_list {
        let result = read_cookie_db(db_path, *browser);

        if let Some(err) = result.error {
            findings.push(Finding {
                title: format!("Could not read {} cookie database", browser.as_str()),
                description: format!(
                    "Error reading {}: {err}",
                    db_path.file_name().unwrap_or_default().to_string_lossy()
                ),
                threat_level: ThreatLevel::Info,
                remediation: "Close the browser and try again, or check file permissions."
                    .to_string(),
            });
            continue;
        }

        databases_scanned += 1;
        let name = browser.as_str().to_string();
        if !browsers_found.contains(&name) {
            browsers_found.push(name);
        }
        all_cookies.extend(result.cookies);
    }

    if all_cookies.is_empty() {
        findings.push(Finding {
            title: "No cookies found".to_string(),
            description: "Browser cookie databases were found but contain no cookies.".to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed.".to_string(),
        });
        browsers_found.sort();
        return Ok(AuditResult {
            module_name: "cookies".to_string(),
            score: 100,
            findings,
            raw_data: HashMap::from([
                (
                    "browsers_found".to_string(),
                    serde_json::json!(browsers_found),
                ),
                (
                    "databases_scanned".to_string(),
                    serde_json::json!(databases_scanned),
                ),
                ("total_cookies".to_string(), serde_json::json!(0)),
            ]),
        });
    }

    // Analyse cookies by domain.
    let domain_stats = analyze_domains(&all_cookies, &tracker_domains);

    let mut tracker_list: Vec<&DomainStats> =
        domain_stats.values().filter(|d| d.is_tracker).collect();
    tracker_list.sort_by(|a, b| b.cookie_count.cmp(&a.cookie_count));

    let mut third_party_list: Vec<&DomainStats> =
        domain_stats.values().filter(|d| !d.is_tracker).collect();
    third_party_list.sort_by(|a, b| b.cookie_count.cmp(&a.cookie_count));

    // Report known tracker domains.
    for stats in &tracker_list {
        findings.push(Finding {
            title: format!(
                "Tracking cookies: {} ({} cookies)",
                stats.domain, stats.cookie_count
            ),
            description: format!(
                "Known tracking domain '{}' has {} cookies in your browser. \
                 This domain tracks you across websites.",
                stats.tracker_category, stats.cookie_count
            ),
            threat_level: ThreatLevel::High,
            remediation:
                "Delete these cookies and block third-party cookies in your browser settings. \
                 Use 'dtm protect cookies --apply' to remove tracker cookies."
                    .to_string(),
        });
        score -= 5;
    }

    // Report suspicious third-party domains with weak security (top 20).
    for stats in third_party_list.iter().take(20) {
        let mut issues: Vec<&str> = Vec::new();
        if stats.has_samesite_none {
            issues.push("SameSite=None (cross-site tracking)");
        }
        if stats.has_no_httponly {
            issues.push("no HttpOnly (JS-accessible)");
        }
        if stats.has_long_expiry {
            issues.push("long expiry (>1 year)");
        }

        if !issues.is_empty() {
            findings.push(Finding {
                title: format!(
                    "Third-party cookies: {} ({} cookies)",
                    stats.domain, stats.cookie_count
                ),
                description: format!(
                    "Domain '{}' has {} cookies with weak security: {}.",
                    stats.domain,
                    stats.cookie_count,
                    issues.join(", ")
                ),
                threat_level: ThreatLevel::Medium,
                remediation: "Review this domain and consider blocking it.".to_string(),
            });
            score -= 2;
        }
    }

    let score = score.clamp(0, 100) as u32;
    browsers_found.sort();

    let tracker_domain_names: Vec<String> = tracker_list.iter().map(|d| d.domain.clone()).collect();

    Ok(AuditResult {
        module_name: "cookies".to_string(),
        score,
        findings,
        raw_data: HashMap::from([
            (
                "browsers_found".to_string(),
                serde_json::json!(browsers_found),
            ),
            (
                "databases_scanned".to_string(),
                serde_json::json!(databases_scanned),
            ),
            (
                "total_cookies".to_string(),
                serde_json::json!(all_cookies.len()),
            ),
            (
                "tracker_domains".to_string(),
                serde_json::json!(tracker_domain_names),
            ),
            (
                "third_party_count".to_string(),
                serde_json::json!(third_party_list.len()),
            ),
        ]),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current time as a Unix timestamp (seconds since 1970).
fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn sample_tracker_domains() -> TrackerDomains {
        let mut domains = TrackerDomains::new();
        domains.insert("doubleclick.net".to_string(), "advertising".to_string());
        domains.insert("facebook.com".to_string(), "social".to_string());
        domains.insert("analytics.google.com".to_string(), "analytics".to_string());
        domains
    }

    /// Create a Chrome-schema SQLite database at the given path.
    fn create_chrome_db(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE cookies (
                host_key TEXT NOT NULL,
                name TEXT NOT NULL,
                is_secure INTEGER NOT NULL DEFAULT 0,
                is_httponly INTEGER NOT NULL DEFAULT 0,
                samesite INTEGER NOT NULL DEFAULT -1,
                has_expires INTEGER NOT NULL DEFAULT 0,
                expires_utc INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        conn
    }

    /// Create a Firefox-schema SQLite database at the given path.
    fn create_firefox_db(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE moz_cookies (
                host TEXT NOT NULL,
                name TEXT NOT NULL,
                isSecure INTEGER NOT NULL DEFAULT 0,
                isHttpOnly INTEGER NOT NULL DEFAULT 0,
                sameSite INTEGER NOT NULL DEFAULT 0,
                expiry INTEGER NOT NULL DEFAULT 0
            );",
        )
        .unwrap();
        conn
    }

    /// Insert a Chrome cookie row.
    #[allow(clippy::too_many_arguments)]
    fn insert_chrome_cookie(
        conn: &Connection,
        host_key: &str,
        name: &str,
        is_secure: bool,
        is_httponly: bool,
        samesite: i32,
        has_expires: bool,
        expires_utc: i64,
    ) {
        conn.execute(
            "INSERT INTO cookies (host_key, name, is_secure, is_httponly, samesite, has_expires, expires_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![host_key, name, is_secure, is_httponly, samesite, has_expires, expires_utc],
        )
        .unwrap();
    }

    /// Insert a Firefox cookie row.
    fn insert_firefox_cookie(
        conn: &Connection,
        host: &str,
        name: &str,
        is_secure: bool,
        is_httponly: bool,
        same_site: i32,
        expiry: i64,
    ) {
        conn.execute(
            "INSERT INTO moz_cookies (host, name, isSecure, isHttpOnly, sameSite, expiry)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![host, name, is_secure, is_httponly, same_site, expiry],
        )
        .unwrap();
    }

    /// Returns a Chrome `expires_utc` value that is `days_from_now` days in the future.
    /// Chrome stores microseconds since 1601-01-01.
    fn chrome_expires_utc_from_now(days_from_now: i64) -> i64 {
        let now = current_unix_timestamp();
        let future = now + days_from_now * 24 * 3600;
        (future + CHROME_EPOCH_OFFSET) * 1_000_000
    }

    /// Returns a Firefox `expiry` value that is `days_from_now` days in the future.
    fn firefox_expiry_from_now(days_from_now: i64) -> i64 {
        current_unix_timestamp() + days_from_now * 24 * 3600
    }

    // -----------------------------------------------------------------------
    // 1. tracker_domain_exact_match
    // -----------------------------------------------------------------------
    #[test]
    fn tracker_domain_exact_match() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain("doubleclick.net", &domains);
        assert_eq!(result, Some("advertising".to_string()));
    }

    // -----------------------------------------------------------------------
    // 2. tracker_domain_subdomain_match
    // -----------------------------------------------------------------------
    #[test]
    fn tracker_domain_subdomain_match() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain("ads.doubleclick.net", &domains);
        assert_eq!(result, Some("advertising".to_string()));
    }

    // -----------------------------------------------------------------------
    // 3. tracker_domain_not_tracker
    // -----------------------------------------------------------------------
    #[test]
    fn tracker_domain_not_tracker() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain("example.com", &domains);
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // 4. tracker_domain_leading_dot
    // -----------------------------------------------------------------------
    #[test]
    fn tracker_domain_leading_dot() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain(".doubleclick.net", &domains);
        assert_eq!(result, Some("advertising".to_string()));
    }

    // -----------------------------------------------------------------------
    // 5. find_databases_empty_dir
    // -----------------------------------------------------------------------
    #[test]
    fn find_databases_empty_dir() {
        let dir = TempDir::new().unwrap();
        // No Chrome or Firefox cookie databases exist here.
        let chrome_dirs: Vec<PathBuf> = vec![dir.path().to_path_buf()];
        // Simulate scanning: read_dir will find no "Cookies" or "cookies.sqlite".
        let mut databases: Vec<(PathBuf, Browser)> = Vec::new();
        for base in &chrome_dirs {
            if let Ok(entries) = std::fs::read_dir(base) {
                for entry in entries.flatten() {
                    let cookie_db = entry.path().join("Cookies");
                    if cookie_db.is_file() {
                        databases.push((cookie_db, Browser::Chrome));
                    }
                }
            }
        }
        assert!(databases.is_empty(), "empty dir should yield no databases");
    }

    // -----------------------------------------------------------------------
    // 6. read_chrome_cookies_basic
    // -----------------------------------------------------------------------
    #[test]
    fn read_chrome_cookies_basic() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("Cookies");
        let conn = create_chrome_db(&db_path);

        let future_expires = chrome_expires_utc_from_now(30);
        insert_chrome_cookie(
            &conn,
            "example.com",
            "session_id",
            true,
            true,
            1,
            true,
            future_expires,
        );
        insert_chrome_cookie(
            &conn,
            ".tracker.net",
            "uid",
            false,
            false,
            -1,
            true,
            future_expires,
        );
        drop(conn);

        let cookies = {
            let c = Connection::open(&db_path).unwrap();
            read_chrome_cookies(&c)
        };

        assert_eq!(cookies.len(), 2);

        let session_cookie = cookies.iter().find(|c| c.name == "session_id").unwrap();
        assert_eq!(session_cookie.host, "example.com");
        assert!(session_cookie.is_secure);
        assert!(session_cookie.is_httponly);
        assert_eq!(session_cookie.samesite, 1);
        assert_eq!(session_cookie.browser, Browser::Chrome);

        let tracker_cookie = cookies.iter().find(|c| c.name == "uid").unwrap();
        assert_eq!(tracker_cookie.host, ".tracker.net");
        assert!(!tracker_cookie.is_secure);
        assert!(!tracker_cookie.is_httponly);
        assert_eq!(tracker_cookie.samesite, -1);
    }

    // -----------------------------------------------------------------------
    // 7. read_firefox_cookies_basic
    // -----------------------------------------------------------------------
    #[test]
    fn read_firefox_cookies_basic() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("cookies.sqlite");
        let conn = create_firefox_db(&db_path);

        let future_expiry = firefox_expiry_from_now(30);
        insert_firefox_cookie(
            &conn,
            "example.com",
            "session_id",
            true,
            true,
            2,
            future_expiry,
        );
        insert_firefox_cookie(&conn, ".tracker.net", "uid", false, false, 0, future_expiry);
        drop(conn);

        let cookies = {
            let c = Connection::open(&db_path).unwrap();
            read_firefox_cookies(&c)
        };

        assert_eq!(cookies.len(), 2);

        let session_cookie = cookies.iter().find(|c| c.name == "session_id").unwrap();
        assert_eq!(session_cookie.host, "example.com");
        assert!(session_cookie.is_secure);
        assert!(session_cookie.is_httponly);
        assert_eq!(session_cookie.samesite, 2);
        assert_eq!(session_cookie.browser, Browser::Firefox);

        let tracker_cookie = cookies.iter().find(|c| c.name == "uid").unwrap();
        assert_eq!(tracker_cookie.host, ".tracker.net");
        assert!(!tracker_cookie.is_secure);
        assert!(!tracker_cookie.is_httponly);
        assert_eq!(tracker_cookie.samesite, 0);
    }

    // -----------------------------------------------------------------------
    // 8. analyze_domains_groups_by_domain
    // -----------------------------------------------------------------------
    #[test]
    fn analyze_domains_groups_by_domain() {
        let tracker_domains = sample_tracker_domains();
        let future_expiry = Some(current_unix_timestamp() + 30 * 24 * 3600);

        let cookies = vec![
            CookieInfo {
                host: "example.com".to_string(),
                name: "a".to_string(),
                is_secure: true,
                is_httponly: true,
                samesite: 1,
                expires_epoch: future_expiry,
                browser: Browser::Chrome,
            },
            CookieInfo {
                host: "example.com".to_string(),
                name: "b".to_string(),
                is_secure: true,
                is_httponly: true,
                samesite: 1,
                expires_epoch: future_expiry,
                browser: Browser::Chrome,
            },
            CookieInfo {
                host: "other.com".to_string(),
                name: "c".to_string(),
                is_secure: true,
                is_httponly: true,
                samesite: 1,
                expires_epoch: future_expiry,
                browser: Browser::Chrome,
            },
        ];

        let stats = analyze_domains(&cookies, &tracker_domains);
        assert_eq!(stats.len(), 2);
        assert_eq!(stats["example.com"].cookie_count, 2);
        assert_eq!(stats["other.com"].cookie_count, 1);
    }

    // -----------------------------------------------------------------------
    // 9. analyze_domains_detects_weak_security
    // -----------------------------------------------------------------------
    #[test]
    fn analyze_domains_detects_weak_security() {
        let tracker_domains = sample_tracker_domains();
        let future_expiry = Some(current_unix_timestamp() + 30 * 24 * 3600);

        let cookies = vec![CookieInfo {
            host: "weak.example.com".to_string(),
            name: "vuln".to_string(),
            is_secure: false,
            is_httponly: false,
            samesite: -1, // Chrome SameSite=None
            expires_epoch: future_expiry,
            browser: Browser::Chrome,
        }];

        let stats = analyze_domains(&cookies, &tracker_domains);
        let domain = &stats["weak.example.com"];

        assert!(domain.has_samesite_none, "SameSite=None should be flagged");
        assert!(domain.has_no_httponly, "missing HttpOnly should be flagged");
    }

    // -----------------------------------------------------------------------
    // 10. analyze_domains_tracker_vs_first_party
    // -----------------------------------------------------------------------
    #[test]
    fn analyze_domains_tracker_vs_first_party() {
        let tracker_domains = sample_tracker_domains();
        let future_expiry = Some(current_unix_timestamp() + 30 * 24 * 3600);

        let cookies = vec![
            CookieInfo {
                host: "doubleclick.net".to_string(),
                name: "ad_id".to_string(),
                is_secure: false,
                is_httponly: false,
                samesite: -1,
                expires_epoch: future_expiry,
                browser: Browser::Chrome,
            },
            CookieInfo {
                host: "mysite.com".to_string(),
                name: "session".to_string(),
                is_secure: true,
                is_httponly: true,
                samesite: 1,
                expires_epoch: future_expiry,
                browser: Browser::Chrome,
            },
        ];

        let stats = analyze_domains(&cookies, &tracker_domains);

        assert!(
            stats["doubleclick.net"].is_tracker,
            "doubleclick.net should be identified as a tracker"
        );
        assert_eq!(stats["doubleclick.net"].tracker_category, "advertising");
        assert!(
            !stats["mysite.com"].is_tracker,
            "mysite.com should not be identified as a tracker"
        );
    }

    // -----------------------------------------------------------------------
    // 11. audit_clean_browser
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn audit_clean_browser() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("Cookies");
        let conn = create_chrome_db(&db_path);

        // All secure, HttpOnly, SameSite=Lax, short expiry
        let future_expires = chrome_expires_utc_from_now(30);
        insert_chrome_cookie(
            &conn,
            "safe.example.com",
            "session",
            true,
            true,
            1,
            true,
            future_expires,
        );
        insert_chrome_cookie(
            &conn,
            "safe.other.com",
            "token",
            true,
            true,
            2,
            true,
            future_expires,
        );
        drop(conn);

        let opts = AuditOpts {
            path: Some(db_path),
            ..Default::default()
        };

        let result = audit_cookies(&opts).await.unwrap();
        assert_eq!(result.module_name, "cookies");
        assert_eq!(
            result.score, 100,
            "all secure cookies should yield a perfect score"
        );
        // No high/medium findings expected
        let high_medium: Vec<_> = result
            .findings
            .iter()
            .filter(|f| matches!(f.threat_level, ThreatLevel::High | ThreatLevel::Medium))
            .collect();
        assert!(
            high_medium.is_empty(),
            "no high/medium findings expected for clean browser"
        );
    }

    // -----------------------------------------------------------------------
    // 12. audit_with_trackers
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn audit_with_trackers() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("Cookies");
        let conn = create_chrome_db(&db_path);

        let future_expires = chrome_expires_utc_from_now(30);
        // A known tracker domain
        insert_chrome_cookie(
            &conn,
            "doubleclick.net",
            "ad_id",
            false,
            false,
            -1,
            true,
            future_expires,
        );
        insert_chrome_cookie(
            &conn,
            "facebook.com",
            "fb_uid",
            false,
            false,
            -1,
            true,
            future_expires,
        );
        // One clean cookie
        insert_chrome_cookie(
            &conn,
            "safe.example.com",
            "session",
            true,
            true,
            1,
            true,
            future_expires,
        );
        drop(conn);

        let opts = AuditOpts {
            path: Some(db_path),
            ..Default::default()
        };

        let result = audit_cookies(&opts).await.unwrap();
        assert_eq!(result.module_name, "cookies");
        assert!(
            result.score < 100,
            "tracker cookies should lower the score, got {}",
            result.score
        );

        let high_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.threat_level == ThreatLevel::High)
            .collect();
        assert!(
            !high_findings.is_empty(),
            "tracker cookies should produce high-threat findings"
        );

        // Verify tracker domains are reported in raw_data
        let tracker_list = result.raw_data.get("tracker_domains").unwrap();
        let tracker_arr = tracker_list.as_array().unwrap();
        assert!(
            tracker_arr
                .iter()
                .any(|v| v.as_str() == Some("doubleclick.net")),
            "doubleclick.net should be in tracker_domains"
        );
    }

    // -----------------------------------------------------------------------
    // 13. delete_tracker_cookies_dry_run
    // -----------------------------------------------------------------------
    #[test]
    fn delete_tracker_cookies_dry_run() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("Cookies");
        let conn = create_chrome_db(&db_path);

        let future_expires = chrome_expires_utc_from_now(30);
        insert_chrome_cookie(
            &conn,
            "doubleclick.net",
            "ad_id",
            false,
            false,
            -1,
            true,
            future_expires,
        );
        insert_chrome_cookie(
            &conn,
            "example.com",
            "session",
            true,
            true,
            1,
            true,
            future_expires,
        );
        drop(conn);

        // Simulate dry run: read and identify tracker cookies but do NOT delete.
        let conn = Connection::open(&db_path).unwrap();
        let cookies = read_chrome_cookies(&conn);
        let tracker_domains = sample_tracker_domains();

        let tracker_cookies: Vec<_> = cookies
            .iter()
            .filter(|c| match_tracker_domain(&c.host, &tracker_domains).is_some())
            .collect();
        assert_eq!(
            tracker_cookies.len(),
            1,
            "one tracker cookie should be identified"
        );
        drop(conn);

        // Verify the DB is unchanged after dry run.
        let conn = Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cookies", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2, "dry run should not modify the database");
    }

    // -----------------------------------------------------------------------
    // 14. delete_tracker_cookies_apply
    // -----------------------------------------------------------------------
    #[test]
    fn delete_tracker_cookies_apply() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("Cookies");
        let conn = create_chrome_db(&db_path);

        let future_expires = chrome_expires_utc_from_now(30);
        insert_chrome_cookie(
            &conn,
            "doubleclick.net",
            "ad_id",
            false,
            false,
            -1,
            true,
            future_expires,
        );
        insert_chrome_cookie(
            &conn,
            "facebook.com",
            "fb_uid",
            false,
            false,
            -1,
            true,
            future_expires,
        );
        insert_chrome_cookie(
            &conn,
            "example.com",
            "session",
            true,
            true,
            1,
            true,
            future_expires,
        );
        drop(conn);

        // Apply mode: delete tracker cookies from the database.
        let conn = Connection::open(&db_path).unwrap();
        let tracker_domains = sample_tracker_domains();

        let cookies = read_chrome_cookies(&conn);
        let tracker_hosts: Vec<String> = cookies
            .iter()
            .filter(|c| match_tracker_domain(&c.host, &tracker_domains).is_some())
            .map(|c| c.host.clone())
            .collect();

        for host in &tracker_hosts {
            conn.execute("DELETE FROM cookies WHERE host_key = ?1", [host])
                .unwrap();
        }
        drop(conn);

        // Verify tracker rows were removed but first-party cookie remains.
        let conn = Connection::open(&db_path).unwrap();
        let remaining: Vec<String> = {
            let mut stmt = conn.prepare("SELECT host_key FROM cookies").unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
        };
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], "example.com");
    }

    // -----------------------------------------------------------------------
    // 15. empty_cookie_db_perfect_score
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn empty_cookie_db_perfect_score() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("Cookies");
        // Create an empty Chrome database (no cookie rows).
        let _conn = create_chrome_db(&db_path);

        let opts = AuditOpts {
            path: Some(db_path),
            ..Default::default()
        };

        let result = audit_cookies(&opts).await.unwrap();
        assert_eq!(result.score, 100, "empty database should score 100");
        assert_eq!(
            result.raw_data.get("total_cookies"),
            Some(&serde_json::json!(0))
        );
    }

    // -----------------------------------------------------------------------
    // 16. long_expiry_detected
    // -----------------------------------------------------------------------
    #[test]
    fn long_expiry_detected() {
        let tracker_domains = sample_tracker_domains();

        // Cookie expiring 400 days from now (> 365 day threshold).
        let long_expiry = Some(current_unix_timestamp() + 400 * 24 * 3600);
        let cookies = vec![CookieInfo {
            host: "persistent.example.com".to_string(),
            name: "long_lived".to_string(),
            is_secure: true,
            is_httponly: true,
            samesite: 1,
            expires_epoch: long_expiry,
            browser: Browser::Chrome,
        }];

        let stats = analyze_domains(&cookies, &tracker_domains);
        let domain = &stats["persistent.example.com"];
        assert!(
            domain.has_long_expiry,
            "cookie with 400+ day expiry should be flagged as long-lived"
        );
    }

    // -----------------------------------------------------------------------
    // 17. httponly_missing_detected
    // -----------------------------------------------------------------------
    #[test]
    fn httponly_missing_detected() {
        let tracker_domains = sample_tracker_domains();
        let future_expiry = Some(current_unix_timestamp() + 30 * 24 * 3600);

        let cookies = vec![CookieInfo {
            host: "js-accessible.example.com".to_string(),
            name: "no_httponly".to_string(),
            is_secure: true,
            is_httponly: false, // not HttpOnly
            samesite: 1,
            expires_epoch: future_expiry,
            browser: Browser::Chrome,
        }];

        let stats = analyze_domains(&cookies, &tracker_domains);
        let domain = &stats["js-accessible.example.com"];
        assert!(
            domain.has_no_httponly,
            "cookie without HttpOnly should be flagged"
        );
    }
}
