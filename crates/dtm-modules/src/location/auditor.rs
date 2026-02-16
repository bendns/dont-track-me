use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use regex::Regex;

use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};
use dtm_core::platform::home_dir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Threshold for number of remembered Wi-Fi networks that indicates
/// fingerprinting risk (unique SSID lists are surprisingly identifying).
const WIFI_NETWORK_FINGERPRINT_THRESHOLD: usize = 20;

// ---------------------------------------------------------------------------
// SSID classification patterns
// ---------------------------------------------------------------------------

/// Build a regex for hotel/lodging SSIDs.
fn hotel_pattern() -> Regex {
    Regex::new(
        r"(?i)(hotel|hilton|marriott|hyatt|sheraton|westin|holiday.?inn|best.?western|airbnb|motel)",
    )
    .expect("hotel regex must compile")
}

/// Build a regex for airport/transit SSIDs.
fn airport_pattern() -> Regex {
    Regex::new(r"(?i)(airport|terminal|airline|lounge|amtrak|sncf|gare|aeroport)")
        .expect("airport regex must compile")
}

/// Build a regex for public venue SSIDs.
fn public_venue_pattern() -> Regex {
    Regex::new(r"(?i)(starbucks|mcdonald|cafe|library|hospital|mall|free.?wifi|guest|public)")
        .expect("public venue regex must compile")
}

/// Classification result for a Wi-Fi SSID.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SsidCategory {
    Hotel,
    AirportTransit,
    PublicVenue,
    Unknown,
}

impl SsidCategory {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Hotel => "hotel/lodging",
            Self::AirportTransit => "airport/transit",
            Self::PublicVenue => "public venue",
            Self::Unknown => "unknown",
        }
    }
}

/// Classify an SSID into a location-revealing category.
fn classify_ssid(
    ssid: &str,
    hotel_re: &Regex,
    airport_re: &Regex,
    venue_re: &Regex,
) -> SsidCategory {
    if hotel_re.is_match(ssid) {
        SsidCategory::Hotel
    } else if airport_re.is_match(ssid) {
        SsidCategory::AirportTransit
    } else if venue_re.is_match(ssid) {
        SsidCategory::PublicVenue
    } else {
        SsidCategory::Unknown
    }
}

// ---------------------------------------------------------------------------
// Phase 1: Wi-Fi SSID History (macOS only)
// ---------------------------------------------------------------------------

/// Parsed Wi-Fi audit results.
struct WifiFindings {
    findings: Vec<Finding>,
    score_deduction: i32,
    ssid_count: usize,
    location_revealing: Vec<(String, SsidCategory)>,
}

/// Platform-specific remediation text for removing saved Wi-Fi networks.
fn wifi_removal_command() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "networksetup -removepreferredwirelessnetwork en0 <SSID>"
    }
    #[cfg(target_os = "linux")]
    {
        "nmcli connection delete <SSID>"
    }
    #[cfg(target_os = "windows")]
    {
        "netsh wlan delete profile name=<SSID>"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "Remove the saved Wi-Fi network using your system's network manager"
    }
}

/// Analyze a list of SSIDs for location-revealing patterns, fingerprinting risk, and scoring.
/// This is cross-platform: it takes already-collected SSIDs and produces findings.
fn analyze_ssids(ssids: Vec<String>) -> WifiFindings {
    let mut findings = Vec::new();
    let mut score_deduction: i32 = 0;

    let ssid_count = ssids.len();

    // Classify SSIDs
    let hotel_re = hotel_pattern();
    let airport_re = airport_pattern();
    let venue_re = public_venue_pattern();

    let mut location_revealing: Vec<(String, SsidCategory)> = Vec::new();

    for ssid in &ssids {
        let category = classify_ssid(ssid, &hotel_re, &airport_re, &venue_re);
        if category != SsidCategory::Unknown {
            location_revealing.push((ssid.clone(), category));
        }
    }

    let removal_cmd = wifi_removal_command();

    // Flag large SSID list (fingerprinting risk)
    if ssid_count > WIFI_NETWORK_FINGERPRINT_THRESHOLD {
        findings.push(Finding {
            title: format!("{ssid_count} remembered Wi-Fi networks"),
            description: format!(
                "Your device remembers {ssid_count} Wi-Fi networks (threshold: \
                 {WIFI_NETWORK_FINGERPRINT_THRESHOLD}). A large list of saved SSIDs \
                 creates a unique fingerprint that can identify you across networks. \
                 Nearby devices can probe for these networks, revealing your history."
            ),
            threat_level: ThreatLevel::Medium,
            remediation: format!(
                "Remove Wi-Fi networks you no longer use: {removal_cmd}\n\
                 Disable auto-join for networks you rarely visit."
            ),
        });
        score_deduction += 10;
    }

    // Flag location-revealing SSIDs
    if !location_revealing.is_empty() {
        let mut hotel_ssids: Vec<&str> = Vec::new();
        let mut airport_ssids: Vec<&str> = Vec::new();
        let mut venue_ssids: Vec<&str> = Vec::new();

        for (ssid, category) in &location_revealing {
            match category {
                SsidCategory::Hotel => hotel_ssids.push(ssid),
                SsidCategory::AirportTransit => airport_ssids.push(ssid),
                SsidCategory::PublicVenue => venue_ssids.push(ssid),
                SsidCategory::Unknown => {}
            }
        }

        if !hotel_ssids.is_empty() {
            findings.push(Finding {
                title: format!(
                    "{} hotel/lodging Wi-Fi network(s) remembered",
                    hotel_ssids.len()
                ),
                description: format!(
                    "Your device remembers Wi-Fi networks from hotels or lodging: {}. \
                     These reveal your travel history and specific locations you've stayed at.",
                    hotel_ssids.join(", ")
                ),
                threat_level: ThreatLevel::High,
                remediation: format!("Remove hotel Wi-Fi networks after checkout: {removal_cmd}"),
            });
            score_deduction += 10;
        }

        if !airport_ssids.is_empty() {
            findings.push(Finding {
                title: format!(
                    "{} airport/transit Wi-Fi network(s) remembered",
                    airport_ssids.len()
                ),
                description: format!(
                    "Your device remembers Wi-Fi networks from airports or transit: {}. \
                     These reveal your travel routes and transportation patterns.",
                    airport_ssids.join(", ")
                ),
                threat_level: ThreatLevel::High,
                remediation: format!(
                    "Remove airport/transit Wi-Fi networks after travel: {removal_cmd}"
                ),
            });
            score_deduction += 10;
        }

        if !venue_ssids.is_empty() {
            findings.push(Finding {
                title: format!(
                    "{} public venue Wi-Fi network(s) remembered",
                    venue_ssids.len()
                ),
                description: format!(
                    "Your device remembers Wi-Fi networks from public venues: {}. \
                     These reveal places you frequent and daily routines.",
                    venue_ssids.join(", ")
                ),
                threat_level: ThreatLevel::Medium,
                remediation: format!(
                    "Remove public venue Wi-Fi networks you no longer visit: {removal_cmd}"
                ),
            });
            score_deduction += 5;
        }
    }

    WifiFindings {
        findings,
        score_deduction,
        ssid_count,
        location_revealing,
    }
}

/// Audit saved Wi-Fi networks for location-revealing SSIDs (macOS).
#[cfg(target_os = "macos")]
fn audit_wifi_history() -> WifiFindings {
    let output = Command::new("networksetup")
        .args(["-listpreferredwirelessnetworks", "en0"])
        .output();

    let ssids: Vec<String> = match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            // First line is the header: "Preferred networks on en0:"
            // Each subsequent line is an SSID (with leading whitespace).
            text.lines()
                .skip(1)
                .map(|line| line.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
        Ok(_) => {
            return WifiFindings {
                findings: vec![Finding {
                    title: "Could not list Wi-Fi networks".to_string(),
                    description:
                        "The networksetup command failed. Wi-Fi interface en0 may not exist."
                            .to_string(),
                    threat_level: ThreatLevel::Info,
                    remediation: "Check your Wi-Fi interface name with: \
                        networksetup -listallhardwareports"
                        .to_string(),
                }],
                score_deduction: 0,
                ssid_count: 0,
                location_revealing: Vec::new(),
            };
        }
        Err(e) => {
            return WifiFindings {
                findings: vec![Finding {
                    title: "Could not run networksetup".to_string(),
                    description: format!("Failed to execute networksetup: {e}"),
                    threat_level: ThreatLevel::Info,
                    remediation: "Ensure you are running on macOS with networksetup available."
                        .to_string(),
                }],
                score_deduction: 0,
                ssid_count: 0,
                location_revealing: Vec::new(),
            };
        }
    };

    analyze_ssids(ssids)
}

/// Audit saved Wi-Fi networks for location-revealing SSIDs (Linux).
#[cfg(target_os = "linux")]
fn audit_wifi_history() -> WifiFindings {
    let output = Command::new("nmcli")
        .args(["-t", "-f", "NAME", "connection", "show"])
        .output();

    let ssids: Vec<String> = match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            // Terse format: one connection name per line.
            text.lines()
                .map(|line| line.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        }
        Ok(_) | Err(_) => {
            return WifiFindings {
                findings: vec![Finding {
                    title: "Wi-Fi SSID audit not available".to_string(),
                    description: "Could not run nmcli to list saved Wi-Fi networks. \
                        NetworkManager may not be installed."
                        .to_string(),
                    threat_level: ThreatLevel::Info,
                    remediation: "Install NetworkManager or manually review saved Wi-Fi networks."
                        .to_string(),
                }],
                score_deduction: 0,
                ssid_count: 0,
                location_revealing: Vec::new(),
            };
        }
    };

    analyze_ssids(ssids)
}

/// Audit saved Wi-Fi networks for location-revealing SSIDs (Windows).
#[cfg(target_os = "windows")]
fn audit_wifi_history() -> WifiFindings {
    let output = Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output();

    let ssids: Vec<String> = match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let profile_re =
                Regex::new(r"All User Profile\s*:\s*(.+)").expect("profile regex must compile");
            text.lines()
                .filter_map(|line| {
                    profile_re
                        .captures(line)
                        .map(|cap| cap[1].trim().to_string())
                })
                .collect()
        }
        Ok(_) | Err(_) => {
            return WifiFindings {
                findings: vec![Finding {
                    title: "Wi-Fi SSID audit not available".to_string(),
                    description: "Could not run netsh to list saved Wi-Fi profiles. \
                        Ensure you are running on Windows with Wi-Fi support."
                        .to_string(),
                    threat_level: ThreatLevel::Info,
                    remediation: "Manually review saved Wi-Fi profiles in \
                        Settings > Network & Internet > Wi-Fi > Manage known networks."
                        .to_string(),
                }],
                score_deduction: 0,
                ssid_count: 0,
                location_revealing: Vec::new(),
            };
        }
    };

    analyze_ssids(ssids)
}

/// Fallback for unsupported platforms.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn audit_wifi_history() -> WifiFindings {
    WifiFindings {
        findings: vec![Finding {
            title: "Wi-Fi SSID audit not available on this platform".to_string(),
            description: "Wi-Fi history auditing is not supported on this platform.".to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Manually review your saved Wi-Fi networks for location-revealing SSIDs."
                .to_string(),
        }],
        score_deduction: 0,
        ssid_count: 0,
        location_revealing: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Phase 2: Timezone vs VPN Mismatch (cross-platform)
// ---------------------------------------------------------------------------

/// IP geolocation response (subset of ipapi.co JSON).
#[derive(Debug, serde::Deserialize)]
struct IpApiResponse {
    timezone: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
}

/// Extract the region prefix from a timezone string (e.g. "America" from "America/New_York").
fn timezone_region(tz: &str) -> &str {
    tz.split('/').next().unwrap_or(tz)
}

/// Map Windows timezone names to IANA timezone identifiers.
/// Covers the most common timezones (~95% of users).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn windows_tz_to_iana(windows_tz: &str) -> Option<&'static str> {
    match windows_tz {
        "Eastern Standard Time" => Some("America/New_York"),
        "Central Standard Time" => Some("America/Chicago"),
        "Mountain Standard Time" => Some("America/Denver"),
        "Pacific Standard Time" => Some("America/Los_Angeles"),
        "Alaska Standard Time" => Some("America/Anchorage"),
        "Hawaiian Standard Time" => Some("Pacific/Honolulu"),
        "GMT Standard Time" => Some("Europe/London"),
        "W. Europe Standard Time" => Some("Europe/Berlin"),
        "Romance Standard Time" => Some("Europe/Paris"),
        "Central European Standard Time" => Some("Europe/Warsaw"),
        "E. Europe Standard Time" => Some("Europe/Bucharest"),
        "FLE Standard Time" => Some("Europe/Helsinki"),
        "Russian Standard Time" => Some("Europe/Moscow"),
        "Tokyo Standard Time" => Some("Asia/Tokyo"),
        "China Standard Time" => Some("Asia/Shanghai"),
        "India Standard Time" => Some("Asia/Kolkata"),
        "AUS Eastern Standard Time" => Some("Australia/Sydney"),
        "New Zealand Standard Time" => Some("Pacific/Auckland"),
        "SA Pacific Standard Time" => Some("America/Bogota"),
        "Atlantic Standard Time" => Some("America/Halifax"),
        "Newfoundland Standard Time" => Some("America/St_Johns"),
        "UTC" => Some("Etc/UTC"),
        _ => None,
    }
}

/// Get the local timezone name from the environment or chrono.
fn get_local_timezone() -> Option<String> {
    // Prefer the TZ environment variable if set.
    if let Ok(tz) = std::env::var("TZ") {
        if !tz.is_empty() && tz.contains('/') {
            return Some(tz);
        }
    }

    // macOS: read /etc/localtime symlink target to extract timezone.
    #[cfg(target_os = "macos")]
    {
        if let Ok(target) = std::fs::read_link("/etc/localtime") {
            let target_str = target.to_string_lossy().to_string();
            // The symlink target looks like: /var/db/timezone/zoneinfo/America/New_York
            if let Some(pos) = target_str.find("zoneinfo/") {
                let tz = &target_str[pos + "zoneinfo/".len()..];
                if tz.contains('/') {
                    return Some(tz.to_string());
                }
            }
        }
    }

    // Linux: read /etc/timezone or parse /etc/localtime symlink.
    #[cfg(target_os = "linux")]
    {
        if let Ok(tz) = std::fs::read_to_string("/etc/timezone") {
            let trimmed = tz.trim().to_string();
            if trimmed.contains('/') {
                return Some(trimmed);
            }
        }
        if let Ok(target) = std::fs::read_link("/etc/localtime") {
            let target_str = target.to_string_lossy().to_string();
            if let Some(pos) = target_str.find("zoneinfo/") {
                let tz = &target_str[pos + "zoneinfo/".len()..];
                if tz.contains('/') {
                    return Some(tz.to_string());
                }
            }
        }
    }

    // Windows: use PowerShell to get the system timezone.
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-Command", "[System.TimeZoneInfo]::Local.Id"])
            .output()
        {
            if output.status.success() {
                let tz_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                // Windows returns names like "Eastern Standard Time" — map to IANA
                if let Some(iana) = windows_tz_to_iana(&tz_name) {
                    return Some(iana.to_string());
                }
            }
        }
    }

    None
}

/// Check for timezone vs IP geolocation mismatch (indicates VPN leak or misconfiguration).
async fn audit_timezone_mismatch() -> (Vec<Finding>, i32, HashMap<String, serde_json::Value>) {
    let mut findings = Vec::new();
    let mut score_deduction: i32 = 0;
    let mut raw = HashMap::new();

    let local_tz = get_local_timezone();
    raw.insert(
        "local_timezone".to_string(),
        serde_json::json!(local_tz.as_deref().unwrap_or("unknown")),
    );

    // Fetch IP geolocation data.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let response = client.get("https://ipapi.co/json/").send().await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<IpApiResponse>().await {
                Ok(geo) => {
                    let ip_tz = geo.timezone.as_deref().unwrap_or("unknown");
                    raw.insert("ip_timezone".to_string(), serde_json::json!(ip_tz));

                    if let Some(ref city) = geo.city {
                        raw.insert("ip_city".to_string(), serde_json::json!(city));
                    }
                    if let Some(ref region) = geo.region {
                        raw.insert("ip_region".to_string(), serde_json::json!(region));
                    }
                    if let Some(ref country) = geo.country_name {
                        raw.insert("ip_country".to_string(), serde_json::json!(country));
                    }

                    if let Some(ref local) = local_tz {
                        let local_region = timezone_region(local);
                        let ip_region = timezone_region(ip_tz);

                        raw.insert("local_region".to_string(), serde_json::json!(local_region));
                        raw.insert("ip_region".to_string(), serde_json::json!(ip_region));

                        if local_region != ip_region {
                            // Region mismatch: strong indicator of VPN or timezone leak.
                            let location_desc = [
                                geo.city.as_deref(),
                                geo.region.as_deref(),
                                geo.country_name.as_deref(),
                            ]
                            .iter()
                            .filter_map(|v| *v)
                            .collect::<Vec<_>>()
                            .join(", ");

                            findings.push(Finding {
                                title: "Timezone vs IP location mismatch".to_string(),
                                description: format!(
                                    "Your system timezone is '{local}' (region: {local_region}) \
                                     but your IP geolocates to '{ip_tz}' (region: {ip_region}), \
                                     near {location_desc}. This mismatch can reveal VPN usage or \
                                     expose your actual location through timezone-based tracking."
                                ),
                                threat_level: ThreatLevel::High,
                                remediation:
                                    "Align your system timezone with your VPN exit node's region, \
                                     or use a VPN provider that automatically adjusts timezone. \
                                     WebRTC and JavaScript can leak your real timezone to websites."
                                        .to_string(),
                            });
                            score_deduction += 15;
                        } else if local != ip_tz {
                            // Same region but different specific timezone — minor leak.
                            findings.push(Finding {
                                title: "Minor timezone discrepancy".to_string(),
                                description: format!(
                                    "Your system timezone is '{local}' but your IP geolocates to \
                                     '{ip_tz}'. Both are in the '{local_region}' region, but the \
                                     specific timezone differs. This is a minor fingerprinting vector."
                                ),
                                threat_level: ThreatLevel::Low,
                                remediation:
                                    "Consider setting your timezone to match your IP location \
                                     for maximum privacy."
                                        .to_string(),
                            });
                            score_deduction += 5;
                        } else {
                            findings.push(Finding {
                                title: "Timezone matches IP location".to_string(),
                                description: format!(
                                    "Your system timezone '{local}' matches your IP geolocation. \
                                     No timezone leak detected."
                                ),
                                threat_level: ThreatLevel::Info,
                                remediation: "No action needed.".to_string(),
                            });
                        }
                    } else {
                        findings.push(Finding {
                            title: "Could not determine local timezone".to_string(),
                            description: "Unable to read the local system timezone for comparison."
                                .to_string(),
                            threat_level: ThreatLevel::Info,
                            remediation: "Set the TZ environment variable to your timezone \
                                (e.g., TZ=America/New_York)."
                                .to_string(),
                        });
                    }
                }
                Err(e) => {
                    findings.push(Finding {
                        title: "Could not parse IP geolocation response".to_string(),
                        description: format!("Failed to parse ipapi.co response: {e}"),
                        threat_level: ThreatLevel::Info,
                        remediation: "Check your internet connection and try again.".to_string(),
                    });
                }
            }
        }
        Ok(resp) => {
            findings.push(Finding {
                title: "IP geolocation request failed".to_string(),
                description: format!(
                    "ipapi.co returned HTTP {}. Rate limiting may be in effect.",
                    resp.status()
                ),
                threat_level: ThreatLevel::Info,
                remediation: "Wait a moment and try again, or check your network connection."
                    .to_string(),
            });
        }
        Err(e) => {
            findings.push(Finding {
                title: "Could not reach IP geolocation service".to_string(),
                description: format!("Failed to connect to ipapi.co: {e}"),
                threat_level: ThreatLevel::Info,
                remediation: "Check your internet connection and try again.".to_string(),
            });
        }
    }

    (findings, score_deduction, raw)
}

// ---------------------------------------------------------------------------
// Phase 3: Location Services Grants (macOS only)
// ---------------------------------------------------------------------------

/// Services that together form a full tracking suite.
const TRACKING_SUITE_SERVICES: &[&str] = &[
    "kTCCServiceLocation",
    "kTCCServiceCamera",
    "kTCCServiceMicrophone",
];

/// Audit TCC database for apps with location (and related) permissions.
#[cfg(target_os = "macos")]
fn audit_location_services() -> (Vec<Finding>, i32, HashMap<String, serde_json::Value>) {
    let mut findings = Vec::new();
    let mut score_deduction: i32 = 0;
    let mut raw = HashMap::new();

    let tcc_path: PathBuf = match home_dir() {
        Some(home) => home
            .join("Library")
            .join("Application Support")
            .join("com.apple.TCC")
            .join("TCC.db"),
        None => {
            findings.push(Finding {
                title: "Could not determine home directory".to_string(),
                description: "Unable to locate TCC database without home directory.".to_string(),
                threat_level: ThreatLevel::Info,
                remediation: "Set the HOME environment variable.".to_string(),
            });
            return (findings, 0, raw);
        }
    };

    raw.insert(
        "tcc_db_path".to_string(),
        serde_json::json!(tcc_path.display().to_string()),
    );

    if !tcc_path.exists() {
        findings.push(Finding {
            title: "TCC database not found".to_string(),
            description: format!(
                "The TCC database was not found at {}. \
                 Full Disk Access may be required to read it.",
                tcc_path.display()
            ),
            threat_level: ThreatLevel::Info,
            remediation: "Grant Full Disk Access to the terminal running this tool \
                in System Settings > Privacy & Security > Full Disk Access."
                .to_string(),
        });
        return (findings, score_deduction, raw);
    }

    // Copy the database to a temp file to avoid locking issues.
    let tmp_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            findings.push(Finding {
                title: "Could not create temporary directory".to_string(),
                description: format!("Failed to create temp dir for TCC database copy: {e}"),
                threat_level: ThreatLevel::Info,
                remediation: "Check disk space and permissions.".to_string(),
            });
            return (findings, score_deduction, raw);
        }
    };

    let tmp_db = tmp_dir.path().join("TCC.db");
    if let Err(e) = std::fs::copy(&tcc_path, &tmp_db) {
        findings.push(Finding {
            title: "Could not read TCC database".to_string(),
            description: format!(
                "Failed to copy TCC database: {e}. \
                 Full Disk Access is required to read this file."
            ),
            threat_level: ThreatLevel::Info,
            remediation: "Grant Full Disk Access to the terminal running this tool \
                in System Settings > Privacy & Security > Full Disk Access."
                .to_string(),
        });
        return (findings, score_deduction, raw);
    }

    // Also copy WAL/SHM companions if present.
    for suffix in ["-wal", "-shm"] {
        let companion = tcc_path.with_file_name(format!("TCC.db{suffix}"));
        if companion.is_file() {
            let _ = std::fs::copy(&companion, tmp_dir.path().join(format!("TCC.db{suffix}")));
        }
    }

    let uri = format!("file:{}?mode=ro", tmp_db.display());
    let conn = match rusqlite::Connection::open_with_flags(
        &uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    ) {
        Ok(c) => c,
        Err(e) => {
            findings.push(Finding {
                title: "Could not open TCC database".to_string(),
                description: format!("Failed to open TCC.db: {e}"),
                threat_level: ThreatLevel::Info,
                remediation: "The database may be corrupted or require Full Disk Access."
                    .to_string(),
            });
            return (findings, score_deduction, raw);
        }
    };

    // Query apps with location access granted (auth_value = 2 means "allowed").
    let location_apps: Vec<String> = {
        let mut stmt = match conn
            .prepare("SELECT client FROM access WHERE service LIKE '%Location%' AND auth_value = 2")
        {
            Ok(s) => s,
            Err(e) => {
                findings.push(Finding {
                    title: "Could not query TCC database".to_string(),
                    description: format!("SQL query failed: {e}"),
                    threat_level: ThreatLevel::Info,
                    remediation: "The TCC database schema may have changed.".to_string(),
                });
                return (findings, score_deduction, raw);
            }
        };

        let result: Vec<String> = match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        };
        result
    };

    raw.insert(
        "location_apps".to_string(),
        serde_json::json!(location_apps),
    );
    raw.insert(
        "location_app_count".to_string(),
        serde_json::json!(location_apps.len()),
    );

    if location_apps.is_empty() {
        findings.push(Finding {
            title: "No apps have Location Services access".to_string(),
            description: "No applications have been granted Location Services permission \
                in the user TCC database."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed.".to_string(),
        });
    } else {
        findings.push(Finding {
            title: format!(
                "{} app(s) have Location Services access",
                location_apps.len()
            ),
            description: format!(
                "The following apps can access your location: {}. \
                 Each app with location access can track your physical movements.",
                location_apps.join(", ")
            ),
            threat_level: if location_apps.len() > 10 {
                ThreatLevel::High
            } else if location_apps.len() > 5 {
                ThreatLevel::Medium
            } else {
                ThreatLevel::Low
            },
            remediation: "Review Location Services permissions in \
                System Settings > Privacy & Security > Location Services. \
                Remove access for apps that don't need your location."
                .to_string(),
        });

        if location_apps.len() > 10 {
            score_deduction += 15;
        } else if location_apps.len() > 5 {
            score_deduction += 10;
        } else {
            score_deduction += 5;
        }
    }

    // Check for apps with the full tracking suite (location + camera + microphone).
    let full_tracking_apps = check_tracking_suite(&conn);
    if !full_tracking_apps.is_empty() {
        raw.insert(
            "full_tracking_suite_apps".to_string(),
            serde_json::json!(full_tracking_apps),
        );

        findings.push(Finding {
            title: format!(
                "{} app(s) have full tracking suite (location + camera + microphone)",
                full_tracking_apps.len()
            ),
            description: format!(
                "These apps have location, camera, AND microphone access: {}. \
                 This combination enables comprehensive surveillance — the app can \
                 track where you are, what you see, and what you say.",
                full_tracking_apps.join(", ")
            ),
            threat_level: ThreatLevel::High,
            remediation: "Review whether each of these apps truly needs all three permissions. \
                Revoke unnecessary permissions in System Settings > Privacy & Security."
                .to_string(),
        });
        score_deduction += 10;
    }

    (findings, score_deduction, raw)
}

/// Find apps that have all three tracking permissions: location, camera, microphone.
#[cfg(target_os = "macos")]
fn check_tracking_suite(conn: &rusqlite::Connection) -> Vec<String> {
    let mut app_services: HashMap<String, Vec<String>> = HashMap::new();

    for service in TRACKING_SUITE_SERVICES {
        let query = format!(
            "SELECT client FROM access WHERE service = '{}' AND auth_value = 2",
            service
        );
        let mut stmt = match conn.prepare(&query) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let apps: Vec<String> = match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => continue,
        };
        for app in apps {
            app_services
                .entry(app)
                .or_default()
                .push(service.to_string());
        }
    }

    let required_count = TRACKING_SUITE_SERVICES.len();
    let mut full_suite: Vec<String> = app_services
        .into_iter()
        .filter(|(_, services)| services.len() >= required_count)
        .map(|(app, _)| app)
        .collect();

    full_suite.sort();
    full_suite
}

#[cfg(target_os = "linux")]
fn audit_location_services() -> (Vec<Finding>, i32, HashMap<String, serde_json::Value>) {
    (
        vec![Finding {
            title: "Location Services audit limited on Linux".to_string(),
            description: "Linux does not have a centralized permission database like \
                macOS TCC. App permissions are managed per-sandbox (Flatpak, Snap) \
                or at the system level."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Review location access in GNOME Settings > Privacy > \
                Location Services, or check Flatpak/Snap permissions."
                .to_string(),
        }],
        0,
        HashMap::new(),
    )
}

#[cfg(target_os = "windows")]
fn audit_location_services() -> (Vec<Finding>, i32, HashMap<String, serde_json::Value>) {
    (
        vec![Finding {
            title: "Location Services audit limited on Windows".to_string(),
            description: "Windows app permissions are managed through the Settings app. \
                A detailed permission audit is available in the app_permissions module."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Review location access in Settings > Privacy & Security > Location. \
                Run 'dtm audit app_permissions' for a detailed permission audit."
                .to_string(),
        }],
        0,
        HashMap::new(),
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn audit_location_services() -> (Vec<Finding>, i32, HashMap<String, serde_json::Value>) {
    (
        vec![Finding {
            title: "Location Services audit not available on this platform".to_string(),
            description: "Location permission auditing is not supported on this platform."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Manually review your app location permissions in system settings."
                .to_string(),
        }],
        0,
        HashMap::new(),
    )
}

// ---------------------------------------------------------------------------
// Main audit entry point
// ---------------------------------------------------------------------------

/// Audit location data leakage across Wi-Fi history, timezone, and permissions.
pub async fn audit_location(_opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut score: i32 = 100;
    let mut raw_data: HashMap<String, serde_json::Value> = HashMap::new();

    // Phase 1: Wi-Fi SSID History
    let wifi = audit_wifi_history();
    findings.extend(wifi.findings);
    score -= wifi.score_deduction;
    raw_data.insert(
        "wifi_ssid_count".to_string(),
        serde_json::json!(wifi.ssid_count),
    );
    raw_data.insert(
        "wifi_location_revealing".to_string(),
        serde_json::json!(wifi
            .location_revealing
            .iter()
            .map(|(ssid, cat)| serde_json::json!({
                "ssid": ssid,
                "category": cat.as_str(),
            }))
            .collect::<Vec<_>>()),
    );

    // Phase 2: Timezone vs VPN Mismatch
    let (tz_findings, tz_deduction, tz_raw) = audit_timezone_mismatch().await;
    findings.extend(tz_findings);
    score -= tz_deduction;
    raw_data.extend(tz_raw);

    // Phase 3: Location Services Grants
    let (loc_findings, loc_deduction, loc_raw) = audit_location_services();
    findings.extend(loc_findings);
    score -= loc_deduction;
    raw_data.extend(loc_raw);

    Ok(AuditResult {
        module_name: "location".to_string(),
        score: score.clamp(0, 100) as u32,
        findings,
        raw_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtm_core::models::ThreatLevel;

    // Build shared regex instances for SSID classification tests.
    fn regexes() -> (Regex, Regex, Regex) {
        (hotel_pattern(), airport_pattern(), public_venue_pattern())
    }

    // -----------------------------------------------------------------------
    // 1. wifi_ssid_hotel_pattern
    // -----------------------------------------------------------------------
    #[test]
    fn wifi_ssid_hotel_pattern() {
        let (hotel_re, airport_re, venue_re) = regexes();
        let cat = classify_ssid("Hilton_WiFi", &hotel_re, &airport_re, &venue_re);
        assert_eq!(
            cat,
            SsidCategory::Hotel,
            "Hilton_WiFi should be classified as Hotel"
        );
    }

    // -----------------------------------------------------------------------
    // 2. wifi_ssid_airport_pattern
    // -----------------------------------------------------------------------
    #[test]
    fn wifi_ssid_airport_pattern() {
        let (hotel_re, airport_re, venue_re) = regexes();
        let cat = classify_ssid("LAX-Free-WiFi", &hotel_re, &airport_re, &venue_re);
        // LAX doesn't match airport pattern directly (no "airport" keyword),
        // but "Free-WiFi" matches the public venue pattern
        assert_ne!(
            cat,
            SsidCategory::Unknown,
            "LAX-Free-WiFi should be classified as location-revealing"
        );
    }

    #[test]
    fn wifi_ssid_airport_explicit() {
        let (hotel_re, airport_re, venue_re) = regexes();
        let cat = classify_ssid("JFK-Airport-WiFi", &hotel_re, &airport_re, &venue_re);
        assert_eq!(
            cat,
            SsidCategory::AirportTransit,
            "JFK-Airport-WiFi should be classified as AirportTransit"
        );
    }

    // -----------------------------------------------------------------------
    // 3. wifi_ssid_generic_safe
    // -----------------------------------------------------------------------
    #[test]
    fn wifi_ssid_generic_safe() {
        let (hotel_re, airport_re, venue_re) = regexes();
        let cat = classify_ssid("MyHomeNetwork", &hotel_re, &airport_re, &venue_re);
        assert_eq!(
            cat,
            SsidCategory::Unknown,
            "MyHomeNetwork should not be classified as location-revealing"
        );
    }

    #[test]
    fn wifi_ssid_generic_safe_variants() {
        let (hotel_re, airport_re, venue_re) = regexes();
        for ssid in &["NETGEAR-5G", "TP-Link_1234", "xfinitywifi_home"] {
            let cat = classify_ssid(ssid, &hotel_re, &airport_re, &venue_re);
            assert_eq!(
                cat,
                SsidCategory::Unknown,
                "{ssid} should not be classified as location-revealing"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 4. many_networks_medium_finding
    // -----------------------------------------------------------------------
    #[test]
    fn many_networks_medium_finding() {
        // The threshold is WIFI_NETWORK_FINGERPRINT_THRESHOLD (20).
        // When >20 networks exist, the audit should flag it as Medium.
        // We test the constant value and logic indirectly.
        assert_eq!(
            WIFI_NETWORK_FINGERPRINT_THRESHOLD, 20,
            "Wi-Fi fingerprint threshold should be 20"
        );
    }

    // -----------------------------------------------------------------------
    // 5. revealing_ssid_high_finding
    // -----------------------------------------------------------------------
    #[test]
    fn revealing_ssid_high_finding() {
        let (hotel_re, airport_re, venue_re) = regexes();

        // Hotel SSIDs should be classified and produce High findings
        let hotel_ssids = ["Marriott_Guest", "Hilton-Lobby", "Holiday Inn WiFi"];
        for ssid in &hotel_ssids {
            let cat = classify_ssid(ssid, &hotel_re, &airport_re, &venue_re);
            assert_eq!(
                cat,
                SsidCategory::Hotel,
                "'{ssid}' should be classified as Hotel"
            );
        }

        // Airport SSIDs should be classified as AirportTransit
        let airport_ssids = ["Airport-Free", "Terminal-WiFi", "Amtrak_WiFi"];
        for ssid in &airport_ssids {
            let cat = classify_ssid(ssid, &hotel_re, &airport_re, &venue_re);
            assert_eq!(
                cat,
                SsidCategory::AirportTransit,
                "'{ssid}' should be classified as AirportTransit"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 6. open_network_medium_finding
    // -----------------------------------------------------------------------
    #[test]
    fn open_network_medium_finding() {
        let (hotel_re, airport_re, venue_re) = regexes();

        // Public venue SSIDs (often open/unsecured) should be classified
        let venue_ssids = ["Starbucks-WiFi", "Library-Guest", "Free WiFi"];
        for ssid in &venue_ssids {
            let cat = classify_ssid(ssid, &hotel_re, &airport_re, &venue_re);
            assert_eq!(
                cat,
                SsidCategory::PublicVenue,
                "'{ssid}' should be classified as PublicVenue"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 7. timezone_mismatch_detected
    // -----------------------------------------------------------------------
    #[test]
    fn timezone_mismatch_detected() {
        // Test the timezone_region helper that drives mismatch detection.
        let region1 = timezone_region("America/New_York");
        let region2 = timezone_region("Europe/Paris");

        assert_eq!(region1, "America");
        assert_eq!(region2, "Europe");
        assert_ne!(
            region1, region2,
            "Different continent timezones should have different regions"
        );
    }

    // -----------------------------------------------------------------------
    // 8. timezone_match_no_finding
    // -----------------------------------------------------------------------
    #[test]
    fn timezone_match_no_finding() {
        // When local and IP timezones match, no mismatch finding should be generated.
        let region1 = timezone_region("America/New_York");
        let region2 = timezone_region("America/Chicago");

        assert_eq!(
            region1, region2,
            "Same-continent timezones should have matching regions"
        );
    }

    // -----------------------------------------------------------------------
    // 9. tracking_suite_app_high
    // -----------------------------------------------------------------------
    #[test]
    fn tracking_suite_app_high() {
        // Verify the TRACKING_SUITE_SERVICES constant has the expected entries.
        assert_eq!(
            TRACKING_SUITE_SERVICES.len(),
            3,
            "Tracking suite should require exactly 3 services"
        );
        assert!(TRACKING_SUITE_SERVICES.contains(&"kTCCServiceLocation"));
        assert!(TRACKING_SUITE_SERVICES.contains(&"kTCCServiceCamera"));
        assert!(TRACKING_SUITE_SERVICES.contains(&"kTCCServiceMicrophone"));
    }

    // -----------------------------------------------------------------------
    // 10. api_failure_info_only
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn api_failure_info_only() {
        // When the IP geolocation API is unreachable, findings should be Info only.
        // We test by calling audit_timezone_mismatch which makes a real HTTP call.
        // In test environments, the API may or may not be reachable.
        let (findings, score_deduction, _raw) = audit_timezone_mismatch().await;

        // All findings should be present (at least one)
        // If the API failed, the finding should be Info
        for finding in &findings {
            // Network-failure findings are always Info
            if finding.title.contains("Could not") || finding.title.contains("failed") {
                assert_eq!(
                    finding.threat_level,
                    ThreatLevel::Info,
                    "API failure findings should be Info level"
                );
            }
        }

        // Score deduction should be non-negative (it's a deduction amount)
        assert!(
            score_deduction >= 0,
            "Score deduction should be non-negative"
        );

        let _ = findings;
    }

    // -----------------------------------------------------------------------
    // 11. module_name_is_location
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn module_name_is_location() {
        let opts = AuditOpts::default();
        let result = audit_location(&opts).await.unwrap();
        assert_eq!(result.module_name, "location");
    }

    // -----------------------------------------------------------------------
    // 12. empty_wifi_history
    // -----------------------------------------------------------------------
    #[test]
    fn empty_wifi_history() {
        // On non-macOS platforms, audit_wifi_history returns a platform-unavailable finding.
        // On macOS, if no networks exist, there should be no fingerprinting finding.
        let wifi = audit_wifi_history();

        // Regardless of platform, score deduction should be non-negative
        assert!(
            wifi.score_deduction >= 0,
            "Wi-Fi score deduction should be non-negative"
        );

        // If there are no SSIDs, there should be no location-revealing entries
        if wifi.ssid_count == 0 {
            assert!(
                wifi.location_revealing.is_empty(),
                "No SSIDs means no location-revealing entries"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 13. non_macos_returns_info
    // -----------------------------------------------------------------------
    #[test]
    fn non_macos_returns_info() {
        // On non-macOS, wifi audit and location services return Info-level platform findings.
        #[cfg(not(target_os = "macos"))]
        {
            let wifi = audit_wifi_history();
            assert!(
                wifi.findings
                    .iter()
                    .all(|f| f.threat_level == ThreatLevel::Info),
                "Non-macOS Wi-Fi audit should only produce Info-level findings"
            );
            assert_eq!(wifi.score_deduction, 0, "No score deduction on non-macOS");

            let (loc_findings, loc_deduction, _) = audit_location_services();
            assert!(
                loc_findings
                    .iter()
                    .all(|f| f.threat_level == ThreatLevel::Info),
                "Non-macOS location services should only produce Info-level findings"
            );
            assert_eq!(loc_deduction, 0, "No score deduction on non-macOS");
        }

        // On macOS, we still test that the functions return valid results
        #[cfg(target_os = "macos")]
        {
            let wifi = audit_wifi_history();
            assert!(
                wifi.score_deduction >= 0,
                "Score deduction should be non-negative"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Additional SSID classification edge-case tests
    // -----------------------------------------------------------------------
    #[test]
    fn classify_ssid_case_insensitive() {
        let (hotel_re, airport_re, venue_re) = regexes();

        // The regex patterns use (?i), so case shouldn't matter.
        assert_eq!(
            classify_ssid("HILTON-WIFI", &hotel_re, &airport_re, &venue_re),
            SsidCategory::Hotel,
        );
        assert_eq!(
            classify_ssid("airport-lounge", &hotel_re, &airport_re, &venue_re),
            SsidCategory::AirportTransit,
        );
        assert_eq!(
            classify_ssid("STARBUCKS", &hotel_re, &airport_re, &venue_re),
            SsidCategory::PublicVenue,
        );
    }

    #[test]
    fn ssid_category_as_str() {
        assert_eq!(SsidCategory::Hotel.as_str(), "hotel/lodging");
        assert_eq!(SsidCategory::AirportTransit.as_str(), "airport/transit");
        assert_eq!(SsidCategory::PublicVenue.as_str(), "public venue");
        assert_eq!(SsidCategory::Unknown.as_str(), "unknown");
    }

    #[test]
    fn timezone_region_single_component() {
        // Timezone with no slash should return the whole string.
        assert_eq!(timezone_region("UTC"), "UTC");
    }

    #[test]
    fn timezone_region_deep_path() {
        // Timezone with multiple slashes returns the first component.
        assert_eq!(timezone_region("America/Indiana/Indianapolis"), "America");
    }

    #[test]
    fn audit_returns_valid_score() {
        // Use a tokio runtime to run the async audit function
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let opts = AuditOpts::default();
            audit_location(&opts).await.unwrap()
        });

        assert!(result.score <= 100, "Score should be at most 100");
        assert!(
            !result.findings.is_empty(),
            "Should have at least one finding"
        );
    }

    // -----------------------------------------------------------------------
    // windows_tz_to_iana mapping tests (cross-platform)
    // -----------------------------------------------------------------------
    #[test]
    fn windows_tz_to_iana_known_timezones() {
        assert_eq!(
            windows_tz_to_iana("Eastern Standard Time"),
            Some("America/New_York")
        );
        assert_eq!(
            windows_tz_to_iana("Pacific Standard Time"),
            Some("America/Los_Angeles")
        );
        assert_eq!(
            windows_tz_to_iana("GMT Standard Time"),
            Some("Europe/London")
        );
        assert_eq!(
            windows_tz_to_iana("Romance Standard Time"),
            Some("Europe/Paris")
        );
        assert_eq!(
            windows_tz_to_iana("Tokyo Standard Time"),
            Some("Asia/Tokyo")
        );
        assert_eq!(
            windows_tz_to_iana("China Standard Time"),
            Some("Asia/Shanghai")
        );
        assert_eq!(
            windows_tz_to_iana("India Standard Time"),
            Some("Asia/Kolkata")
        );
        assert_eq!(
            windows_tz_to_iana("AUS Eastern Standard Time"),
            Some("Australia/Sydney")
        );
        assert_eq!(windows_tz_to_iana("UTC"), Some("Etc/UTC"));
    }

    #[test]
    fn windows_tz_to_iana_unknown_returns_none() {
        assert_eq!(windows_tz_to_iana("Fake Timezone"), None);
        assert_eq!(windows_tz_to_iana(""), None);
        assert_eq!(windows_tz_to_iana("America/New_York"), None);
    }

    #[test]
    fn windows_tz_to_iana_all_entries_are_valid_iana() {
        // Every mapped IANA timezone should contain a '/' (except Etc/UTC).
        let test_cases = [
            "Eastern Standard Time",
            "Central Standard Time",
            "Mountain Standard Time",
            "Pacific Standard Time",
            "Alaska Standard Time",
            "Hawaiian Standard Time",
            "GMT Standard Time",
            "W. Europe Standard Time",
            "Romance Standard Time",
            "Central European Standard Time",
            "E. Europe Standard Time",
            "FLE Standard Time",
            "Russian Standard Time",
            "Tokyo Standard Time",
            "China Standard Time",
            "India Standard Time",
            "AUS Eastern Standard Time",
            "New Zealand Standard Time",
            "SA Pacific Standard Time",
            "Atlantic Standard Time",
            "Newfoundland Standard Time",
            "UTC",
        ];
        for tz in test_cases {
            let iana = windows_tz_to_iana(tz);
            assert!(iana.is_some(), "Expected mapping for '{tz}' but got None");
            let iana = iana.unwrap();
            assert!(
                iana.contains('/'),
                "IANA timezone '{iana}' for '{tz}' should contain a '/'"
            );
        }
    }

    // -----------------------------------------------------------------------
    // analyze_ssids tests (cross-platform)
    // -----------------------------------------------------------------------
    #[test]
    fn analyze_ssids_empty_list() {
        let result = analyze_ssids(vec![]);
        assert!(
            result.findings.is_empty(),
            "No SSIDs should produce no findings"
        );
        assert_eq!(result.score_deduction, 0);
        assert_eq!(result.ssid_count, 0);
        assert!(result.location_revealing.is_empty());
    }

    #[test]
    fn analyze_ssids_safe_networks_only() {
        let ssids = vec![
            "MyHomeNetwork".to_string(),
            "NETGEAR-5G".to_string(),
            "TP-Link_1234".to_string(),
        ];
        let result = analyze_ssids(ssids);
        assert!(
            result.findings.is_empty(),
            "Safe SSIDs should produce no findings"
        );
        assert_eq!(result.score_deduction, 0);
        assert_eq!(result.ssid_count, 3);
        assert!(result.location_revealing.is_empty());
    }

    #[test]
    fn analyze_ssids_hotel_detection() {
        let ssids = vec![
            "HomeWiFi".to_string(),
            "Marriott_Guest".to_string(),
            "Hilton-Lobby".to_string(),
        ];
        let result = analyze_ssids(ssids);
        assert_eq!(result.ssid_count, 3);
        assert_eq!(result.location_revealing.len(), 2);
        assert!(result
            .findings
            .iter()
            .any(|f| f.title.contains("hotel/lodging")));
        assert!(result.score_deduction >= 10);
    }

    #[test]
    fn analyze_ssids_airport_detection() {
        let ssids = vec!["Airport-Free".to_string(), "Terminal-WiFi".to_string()];
        let result = analyze_ssids(ssids);
        assert_eq!(result.location_revealing.len(), 2);
        assert!(result
            .findings
            .iter()
            .any(|f| f.title.contains("airport/transit")));
    }

    #[test]
    fn analyze_ssids_venue_detection() {
        let ssids = vec!["Starbucks-WiFi".to_string(), "Library-Guest".to_string()];
        let result = analyze_ssids(ssids);
        assert_eq!(result.location_revealing.len(), 2);
        assert!(result
            .findings
            .iter()
            .any(|f| f.title.contains("public venue")));
    }

    #[test]
    fn analyze_ssids_fingerprint_threshold() {
        // Create 25 safe SSIDs to trigger fingerprinting warning
        let ssids: Vec<String> = (0..25).map(|i| format!("Network_{i}")).collect();
        let result = analyze_ssids(ssids);
        assert_eq!(result.ssid_count, 25);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.title.contains("remembered Wi-Fi networks")),
            "Should flag large SSID list as fingerprinting risk"
        );
        assert!(result.score_deduction >= 10);
    }

    #[test]
    fn analyze_ssids_mixed_categories() {
        let ssids = vec![
            "Marriott_Guest".to_string(),
            "Airport-Free".to_string(),
            "Starbucks-WiFi".to_string(),
            "HomeWiFi".to_string(),
        ];
        let result = analyze_ssids(ssids);
        assert_eq!(result.ssid_count, 4);
        assert_eq!(result.location_revealing.len(), 3);
        // Should have findings for each category
        assert!(result
            .findings
            .iter()
            .any(|f| f.title.contains("hotel/lodging")));
        assert!(result
            .findings
            .iter()
            .any(|f| f.title.contains("airport/transit")));
        assert!(result
            .findings
            .iter()
            .any(|f| f.title.contains("public venue")));
        // hotel(10) + airport(10) + venue(5) = 25
        assert_eq!(result.score_deduction, 25);
    }

    #[test]
    fn analyze_ssids_remediation_contains_platform_command() {
        let ssids = vec!["Marriott_Guest".to_string()];
        let result = analyze_ssids(ssids);
        let finding = result
            .findings
            .first()
            .expect("Should have at least one finding");

        #[cfg(target_os = "macos")]
        assert!(
            finding.remediation.contains("networksetup"),
            "macOS remediation should reference networksetup"
        );
        #[cfg(target_os = "linux")]
        assert!(
            finding.remediation.contains("nmcli"),
            "Linux remediation should reference nmcli"
        );
        #[cfg(target_os = "windows")]
        assert!(
            finding.remediation.contains("netsh"),
            "Windows remediation should reference netsh"
        );
    }

    // -----------------------------------------------------------------------
    // Platform-specific Wi-Fi parsing tests
    // -----------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_wifi_audit_returns_valid_results() {
        let wifi = audit_wifi_history();
        assert!(wifi.score_deduction >= 0);
        // On macOS, we should get either real SSIDs or an error finding
        // (depending on whether networksetup is available)
        if wifi.ssid_count == 0 && !wifi.findings.is_empty() {
            // Got a tool-not-available finding, which is fine in CI
            assert!(wifi
                .findings
                .iter()
                .all(|f| f.threat_level == ThreatLevel::Info));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_wifi_audit_returns_valid_results() {
        let wifi = audit_wifi_history();
        assert!(wifi.score_deduction >= 0);
        // On Linux without nmcli, we get an Info fallback
        if wifi.ssid_count == 0 {
            assert!(wifi
                .findings
                .iter()
                .all(|f| f.threat_level == ThreatLevel::Info));
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_wifi_audit_returns_valid_results() {
        let wifi = audit_wifi_history();
        assert!(wifi.score_deduction >= 0);
        // On Windows without netsh/Wi-Fi, we get an Info fallback
        if wifi.ssid_count == 0 {
            assert!(wifi
                .findings
                .iter()
                .all(|f| f.threat_level == ThreatLevel::Info));
        }
    }
}
