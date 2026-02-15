//! App permission audit — cross-platform.
//!
//! - **macOS**: Reads the user-level TCC database to discover which apps have
//!   been granted sensitive permissions (camera, microphone, screen recording,
//!   etc.) and flags over-permissioned apps.
//! - **Linux**: Inspects Flatpak and Snap sandbox permissions.
//! - **Windows**: Checks capability access (camera, microphone, location, etc.)
//!   via the registry.

use anyhow::Result;

use dtm_core::models::{AuditOpts, AuditResult};

// ===========================================================================
// Public entry point — platform dispatch
// ===========================================================================

/// Audit app permissions for privacy and security issues.
pub async fn audit_app_permissions(opts: &AuditOpts) -> Result<AuditResult> {
    #[cfg(target_os = "macos")]
    {
        audit_macos_permissions(opts).await
    }

    #[cfg(target_os = "linux")]
    {
        audit_linux_permissions().await
    }

    #[cfg(target_os = "windows")]
    {
        audit_windows_permissions().await
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        use dtm_core::models::{Finding, ThreatLevel};
        use std::collections::HashMap;

        let _ = opts;
        Ok(AuditResult {
            module_name: "app_permissions".to_string(),
            score: 50,
            findings: vec![Finding {
                title: "App permission audit not available on this platform".to_string(),
                description: "App permission auditing is not supported on this platform."
                    .to_string(),
                threat_level: ThreatLevel::Info,
                remediation: "Manually review your app permissions in system settings.".to_string(),
            }],
            raw_data: HashMap::new(),
        })
    }
}

// ===========================================================================
// macOS — TCC (Transparency, Consent, and Control) permission audit
// ===========================================================================

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use anyhow::Result;
    use rusqlite::Connection;

    use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};
    use dtm_core::platform::home_dir;

    // -----------------------------------------------------------------------
    // TCC service mapping
    // -----------------------------------------------------------------------

    /// A TCC service with its friendly name and associated threat level.
    pub(super) struct ServiceInfo {
        pub friendly_name: &'static str,
        pub threat_level: ThreatLevel,
        /// Whether this service is considered "high-risk" for the
        /// over-permissioned app detection heuristic.
        pub high_risk: bool,
    }

    /// Map a TCC service identifier to its friendly name and threat level.
    pub(super) fn classify_service(service: &str) -> Option<ServiceInfo> {
        match service {
            "kTCCServiceCamera" => Some(ServiceInfo {
                friendly_name: "Camera",
                threat_level: ThreatLevel::High,
                high_risk: true,
            }),
            "kTCCServiceMicrophone" => Some(ServiceInfo {
                friendly_name: "Microphone",
                threat_level: ThreatLevel::High,
                high_risk: true,
            }),
            "kTCCServiceScreenCapture" => Some(ServiceInfo {
                friendly_name: "Screen Recording",
                threat_level: ThreatLevel::High,
                high_risk: true,
            }),
            "kTCCServiceAccessibility" => Some(ServiceInfo {
                friendly_name: "Accessibility",
                threat_level: ThreatLevel::High,
                high_risk: true,
            }),
            "kTCCServiceSystemPolicyAllFiles" => Some(ServiceInfo {
                friendly_name: "Full Disk Access",
                threat_level: ThreatLevel::Critical,
                high_risk: true,
            }),
            s if s.starts_with("kTCCServiceLocation") => Some(ServiceInfo {
                friendly_name: "Location Services",
                threat_level: ThreatLevel::High,
                high_risk: true,
            }),
            "kTCCServiceAddressBook" => Some(ServiceInfo {
                friendly_name: "Contacts",
                threat_level: ThreatLevel::Medium,
                high_risk: false,
            }),
            "kTCCServiceCalendar" => Some(ServiceInfo {
                friendly_name: "Calendar",
                threat_level: ThreatLevel::Medium,
                high_risk: false,
            }),
            "kTCCServiceReminders" => Some(ServiceInfo {
                friendly_name: "Reminders",
                threat_level: ThreatLevel::Low,
                high_risk: false,
            }),
            s if s.starts_with("kTCCServicePhotos") => Some(ServiceInfo {
                friendly_name: "Photos",
                threat_level: ThreatLevel::Medium,
                high_risk: false,
            }),
            "kTCCServiceBluetoothAlways" => Some(ServiceInfo {
                friendly_name: "Bluetooth",
                threat_level: ThreatLevel::Medium,
                high_risk: false,
            }),
            "kTCCServiceInputMonitoring" => Some(ServiceInfo {
                friendly_name: "Input Monitoring",
                threat_level: ThreatLevel::Critical,
                high_risk: true,
            }),
            _ => None,
        }
    }

    /// Score deduction for each threat level.
    fn threat_deduction(level: ThreatLevel) -> i32 {
        match level {
            ThreatLevel::Critical => 15,
            ThreatLevel::High => 10,
            ThreatLevel::Medium => 5,
            ThreatLevel::Low => 2,
            ThreatLevel::Info => 0,
        }
    }

    // -----------------------------------------------------------------------
    // TCC record
    // -----------------------------------------------------------------------

    /// A single allowed permission from the TCC database.
    #[derive(Debug)]
    struct TccRecord {
        service: String,
        client: String,
        friendly_name: String,
        threat_level: ThreatLevel,
        high_risk: bool,
    }

    // -----------------------------------------------------------------------
    // Database reading
    // -----------------------------------------------------------------------

    /// Read allowed TCC records from the user-level TCC database.
    ///
    /// The `db_path` parameter allows overriding the default location for testing.
    fn read_tcc_database(db_path: &PathBuf) -> Result<Vec<TccRecord>> {
        let conn =
            Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;

        let mut stmt =
            conn.prepare("SELECT service, client, auth_value FROM access WHERE auth_value = 2")?;

        let records = stmt
            .query_map([], |row| {
                let service: String = row.get(0)?;
                let client: String = row.get(1)?;
                Ok((service, client))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(service, client)| {
                let info = classify_service(&service)?;
                Some(TccRecord {
                    service,
                    client,
                    friendly_name: info.friendly_name.to_string(),
                    threat_level: info.threat_level,
                    high_risk: info.high_risk,
                })
            })
            .collect();

        Ok(records)
    }

    // -----------------------------------------------------------------------
    // Analysis helpers
    // -----------------------------------------------------------------------

    /// Build a map of service -> list of clients that have that permission.
    fn permissions_by_service(records: &[TccRecord]) -> HashMap<&str, Vec<&str>> {
        let mut map: HashMap<&str, Vec<&str>> = HashMap::new();
        for record in records {
            map.entry(&record.friendly_name)
                .or_default()
                .push(&record.client);
        }
        map
    }

    /// Build a map of client -> list of permissions granted.
    fn permissions_by_client(records: &[TccRecord]) -> HashMap<&str, Vec<&TccRecord>> {
        let mut map: HashMap<&str, Vec<&TccRecord>> = HashMap::new();
        for record in records {
            map.entry(&record.client).or_default().push(record);
        }
        map
    }

    /// Extract the short app name from a bundle identifier.
    ///
    /// e.g. "com.example.MyApp" -> "MyApp"
    pub(super) fn short_app_name(bundle_id: &str) -> &str {
        bundle_id.rsplit('.').next().unwrap_or(bundle_id)
    }

    // -----------------------------------------------------------------------
    // Finding generators
    // -----------------------------------------------------------------------

    /// Generate per-service findings showing which apps have each sensitive permission.
    fn findings_per_service(records: &[TccRecord]) -> Vec<(Finding, ThreatLevel)> {
        let by_service = permissions_by_service(records);

        // Collect unique services with their threat level (use the highest if duplicated).
        let mut service_threat: HashMap<&str, ThreatLevel> = HashMap::new();
        for record in records {
            let entry = service_threat
                .entry(&record.friendly_name)
                .or_insert(record.threat_level);
            // Keep the higher threat level.
            if (record.threat_level as u8) < (*entry as u8) {
                *entry = record.threat_level;
            }
        }

        let mut findings = Vec::new();

        // Sort services by threat level (critical first) then alphabetically.
        let mut services: Vec<(&str, ThreatLevel)> = service_threat.into_iter().collect();
        services.sort_by(|a, b| (a.1 as u8).cmp(&(b.1 as u8)).then(a.0.cmp(b.0)));

        for (service_name, threat_level) in &services {
            if let Some(clients) = by_service.get(service_name) {
                // Only generate findings for Medium or above.
                if matches!(threat_level, ThreatLevel::Low | ThreatLevel::Info) {
                    continue;
                }

                let count = clients.len();
                let app_list: Vec<String> = clients
                    .iter()
                    .map(|c| short_app_name(c).to_string())
                    .collect();
                let app_names = app_list.join(", ");

                findings.push((
                    Finding {
                        title: format!("{count} app(s) with {service_name} access"),
                        description: format!(
                            "{count} application(s) have been granted {service_name} permission: \
                             {app_names}. Each app with this permission can access this resource \
                             at any time while running."
                        ),
                        threat_level: *threat_level,
                        remediation: format!(
                            "Review {service_name} permissions in System Settings > \
                             Privacy & Security > {service_name}. Revoke access for any \
                             apps that do not need it."
                        ),
                    },
                    *threat_level,
                ));
            }
        }

        findings
    }

    /// Detect apps that have both Camera and Microphone access.
    fn find_camera_mic_combo(records: &[TccRecord]) -> Vec<(Finding, ThreatLevel)> {
        let by_client = permissions_by_client(records);
        let mut findings = Vec::new();

        let mut combo_apps: Vec<&str> = Vec::new();
        for (client, perms) in &by_client {
            let has_camera = perms.iter().any(|r| r.friendly_name == "Camera");
            let has_mic = perms.iter().any(|r| r.friendly_name == "Microphone");
            if has_camera && has_mic {
                combo_apps.push(client);
            }
        }

        if !combo_apps.is_empty() {
            combo_apps.sort();
            let app_names: Vec<String> = combo_apps
                .iter()
                .map(|c| short_app_name(c).to_string())
                .collect();
            let count = combo_apps.len();

            findings.push((
                Finding {
                    title: format!("{count} app(s) with both Camera and Microphone access"),
                    description: format!(
                        "The following app(s) have access to both the camera and microphone, \
                         which means they can record audio and video simultaneously: {}. \
                         This combination significantly increases surveillance risk.",
                        app_names.join(", ")
                    ),
                    threat_level: ThreatLevel::High,
                    remediation: "Review whether each app truly needs both Camera and Microphone \
                        access. Revoke one or both permissions for apps that do not require \
                        audio/video capture as a core function."
                        .to_string(),
                },
                ThreatLevel::High,
            ));
        }

        findings
    }

    /// Detect over-permissioned apps (3+ high-risk permissions).
    fn find_over_permissioned(records: &[TccRecord]) -> Vec<(Finding, ThreatLevel)> {
        let by_client = permissions_by_client(records);
        let mut findings = Vec::new();

        let mut flagged_apps: Vec<(&str, Vec<&str>)> = Vec::new();
        for (client, perms) in &by_client {
            let high_risk_perms: Vec<&str> = perms
                .iter()
                .filter(|r| r.high_risk)
                .map(|r| r.friendly_name.as_str())
                .collect();

            if high_risk_perms.len() >= 3 {
                flagged_apps.push((client, high_risk_perms));
            }
        }

        flagged_apps.sort_by_key(|(client, _)| *client);

        for (client, perms) in &flagged_apps {
            let app_name = short_app_name(client);
            let perm_list = perms.join(", ");
            let perm_count = perms.len();

            findings.push((
                Finding {
                    title: format!(
                        "Over-permissioned app: {app_name} ({perm_count} high-risk permissions)"
                    ),
                    description: format!(
                        "{app_name} ({client}) has {perm_count} high-risk permissions: \
                         {perm_list}. Apps with extensive system access pose a greater \
                         privacy risk if compromised or if they contain tracking SDKs."
                    ),
                    threat_level: ThreatLevel::High,
                    remediation: format!(
                        "Audit whether {app_name} genuinely requires all of these permissions. \
                         Revoke any that are not essential for the app's core functionality \
                         in System Settings > Privacy & Security."
                    ),
                },
                ThreatLevel::High,
            ));
        }

        findings
    }

    // -----------------------------------------------------------------------
    // macOS entry point
    // -----------------------------------------------------------------------

    /// Audit macOS TCC permissions for privacy and security issues.
    pub(super) async fn audit_macos_permissions(opts: &AuditOpts) -> Result<AuditResult> {
        let mut findings: Vec<Finding> = Vec::new();
        let mut score: i32 = 100;
        let mut raw_data = HashMap::new();

        // Determine TCC database path.
        let db_path = opts.path.clone().unwrap_or_else(|| {
            home_dir()
                .unwrap_or_else(|| PathBuf::from("/"))
                .join("Library/Application Support/com.apple.TCC/TCC.db")
        });

        raw_data.insert(
            "tcc_db_path".to_string(),
            serde_json::Value::String(db_path.display().to_string()),
        );

        if !db_path.exists() {
            findings.push(Finding {
                title: "TCC database not found".to_string(),
                description: format!(
                    "Could not find the TCC database at {}. This may indicate \
                     the file is protected by Full Disk Access restrictions, or that \
                     this is not a macOS system.",
                    db_path.display()
                ),
                threat_level: ThreatLevel::Info,
                remediation: "Grant Full Disk Access to the terminal application running \
                    this tool, or run with appropriate privileges."
                    .to_string(),
            });

            return Ok(AuditResult {
                module_name: "app_permissions".to_string(),
                score: 100,
                findings,
                raw_data,
            });
        }

        // Read the TCC database.
        let records = match read_tcc_database(&db_path) {
            Ok(r) => r,
            Err(e) => {
                findings.push(Finding {
                    title: "Cannot read TCC database".to_string(),
                    description: format!(
                        "Failed to read the TCC database at {}: {e}. \
                         The database may be locked or the terminal may lack \
                         Full Disk Access permission.",
                        db_path.display()
                    ),
                    threat_level: ThreatLevel::Medium,
                    remediation: "Grant Full Disk Access to the terminal application in \
                        System Settings > Privacy & Security > Full Disk Access."
                        .to_string(),
                });

                return Ok(AuditResult {
                    module_name: "app_permissions".to_string(),
                    score: 80,
                    findings,
                    raw_data,
                });
            }
        };

        let total_permissions = records.len();
        raw_data.insert(
            "total_permissions".to_string(),
            serde_json::json!(total_permissions),
        );

        if records.is_empty() {
            findings.push(Finding {
                title: "No TCC permissions found".to_string(),
                description: "No granted permissions were found in the TCC database. \
                    Either no apps have been granted sensitive permissions, or the \
                    database could not be fully read."
                    .to_string(),
                threat_level: ThreatLevel::Info,
                remediation: "No action needed if this is expected.".to_string(),
            });

            return Ok(AuditResult {
                module_name: "app_permissions".to_string(),
                score: 100,
                findings,
                raw_data,
            });
        }

        // Collect summary statistics for raw_data.
        let by_service = permissions_by_service(&records);
        let mut service_counts: HashMap<String, usize> = HashMap::new();
        for (service, clients) in &by_service {
            service_counts.insert(service.to_string(), clients.len());
        }
        raw_data.insert(
            "permissions_by_service".to_string(),
            serde_json::json!(service_counts),
        );

        let by_client = permissions_by_client(&records);
        let mut client_counts: HashMap<String, usize> = HashMap::new();
        for (client, perms) in &by_client {
            client_counts.insert(client.to_string(), perms.len());
        }
        raw_data.insert(
            "permissions_by_app".to_string(),
            serde_json::json!(client_counts),
        );

        // Include raw TCC service identifiers for debugging/advanced use.
        let raw_services: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "service": r.service,
                    "client": r.client,
                    "friendly_name": r.friendly_name,
                })
            })
            .collect();
        raw_data.insert(
            "raw_tcc_records".to_string(),
            serde_json::json!(raw_services),
        );

        // Phase 1: Per-service findings.
        let service_findings = findings_per_service(&records);
        for (finding, threat_level) in service_findings {
            score -= threat_deduction(threat_level);
            findings.push(finding);
        }

        // Phase 2: Camera + Microphone combo detection.
        let combo_findings = find_camera_mic_combo(&records);
        for (finding, threat_level) in combo_findings {
            score -= threat_deduction(threat_level);
            findings.push(finding);
        }

        // Phase 3: Over-permissioned app detection.
        let over_perm_findings = find_over_permissioned(&records);
        for (finding, threat_level) in over_perm_findings {
            score -= threat_deduction(threat_level);
            findings.push(finding);
        }

        let score = score.clamp(0, 100) as u32;

        Ok(AuditResult {
            module_name: "app_permissions".to_string(),
            score,
            findings,
            raw_data,
        })
    }
}

#[cfg(target_os = "macos")]
use macos::audit_macos_permissions;

// ===========================================================================
// Linux — Flatpak and Snap permission audit
// ===========================================================================

#[cfg(target_os = "linux")]
async fn audit_linux_permissions() -> Result<AuditResult> {
    use std::process::Command;

    let mut findings = Vec::new();
    let mut score: i32 = 100;
    let mut raw_data = HashMap::new();

    // Check Flatpak permissions
    let flatpak_findings = audit_flatpak_permissions();
    for (delta, finding) in &flatpak_findings {
        score += delta;
        findings.push(finding.clone());
    }
    raw_data.insert("flatpak_checked".to_string(), serde_json::json!(true));

    // Check Snap permissions
    let snap_findings = audit_snap_permissions();
    for (delta, finding) in &snap_findings {
        score += delta;
        findings.push(finding.clone());
    }
    raw_data.insert("snap_checked".to_string(), serde_json::json!(true));

    if findings.is_empty() {
        findings.push(Finding {
            title: "No Flatpak or Snap apps found".to_string(),
            description: "No sandboxed applications were detected. Permissions for \
                native packages are managed at the system level."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed.".to_string(),
        });
    }

    score = score.clamp(0, 100);

    Ok(AuditResult {
        module_name: "app_permissions".to_string(),
        score: score as u32,
        findings,
        raw_data,
    })
}

#[cfg(target_os = "linux")]
fn audit_flatpak_permissions() -> Vec<(i32, Finding)> {
    use std::process::Command;

    let mut results = Vec::new();

    // Check if flatpak is installed
    let output = match Command::new("flatpak")
        .args(["list", "--app", "--columns=application"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return results,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let apps: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.is_empty() && *l != "Application")
        .collect();

    if apps.is_empty() {
        return results;
    }

    let mut over_permissioned = Vec::new();

    for app_id in &apps {
        let perms_output = match Command::new("flatpak")
            .args(["info", "--show-permissions", app_id])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };

        let perms = String::from_utf8_lossy(&perms_output.stdout);
        let mut risky_perms = Vec::new();

        // Check for broad permissions
        if perms.contains("devices=all") {
            risky_perms.push("all devices (camera, microphone)");
        }
        if perms.contains("filesystems=host") || perms.contains("filesystems=home") {
            risky_perms.push("filesystem access");
        }
        if perms.contains("sockets=x11") {
            risky_perms.push("X11 (can capture keystrokes/screen)");
        }
        if perms.contains("sockets=pulseaudio") {
            risky_perms.push("audio access");
        }

        if risky_perms.len() >= 3 {
            over_permissioned.push(app_id.to_string());
        }

        if !risky_perms.is_empty() {
            let short_name = app_id.rsplit('.').next().unwrap_or(app_id);
            results.push((
                -5,
                Finding {
                    title: format!("{}: {} risky permissions", short_name, risky_perms.len()),
                    description: format!("Flatpak app {} has: {}", app_id, risky_perms.join(", ")),
                    threat_level: if risky_perms.len() >= 3 {
                        ThreatLevel::High
                    } else {
                        ThreatLevel::Medium
                    },
                    remediation: format!("Review with: flatpak override --show {app_id}"),
                },
            ));
        }
    }

    if !over_permissioned.is_empty() {
        results.push((
            -10,
            Finding {
                title: format!(
                    "{} Flatpak apps are over-permissioned",
                    over_permissioned.len()
                ),
                description: format!(
                    "These Flatpak apps have 3+ risky permissions: {}",
                    over_permissioned.join(", ")
                ),
                threat_level: ThreatLevel::High,
                remediation: "Restrict permissions with: flatpak override --nodevice=all <app>"
                    .to_string(),
            },
        ));
    }

    results
}

#[cfg(target_os = "linux")]
fn audit_snap_permissions() -> Vec<(i32, Finding)> {
    use std::process::Command;

    let mut results = Vec::new();

    let output = match Command::new("snap").args(["list"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return results,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let snaps: Vec<&str> = stdout
        .lines()
        .skip(1) // header
        .filter_map(|l| l.split_whitespace().next())
        .filter(|name| {
            ![
                "core",
                "core18",
                "core20",
                "core22",
                "snapd",
                "bare",
                "gnome-42-2204",
            ]
            .contains(name)
        })
        .collect();

    for snap_name in &snaps {
        let conn_output = match Command::new("snap")
            .args(["connections", snap_name])
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };

        let conns = String::from_utf8_lossy(&conn_output.stdout);
        let mut risky_interfaces = Vec::new();

        for line in conns.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let interface = parts[0];
                let connected = parts.get(2).unwrap_or(&"-");
                if *connected != "-" {
                    match interface {
                        i if i.contains("camera") => risky_interfaces.push("camera"),
                        i if i.contains("audio-record") => risky_interfaces.push("microphone"),
                        i if i.contains("home") => risky_interfaces.push("home directory"),
                        i if i.contains("removable-media") => {
                            risky_interfaces.push("removable media");
                        }
                        i if i.contains("screen-inhibit-control") => {
                            risky_interfaces.push("screen control");
                        }
                        _ => {}
                    }
                }
            }
        }

        if !risky_interfaces.is_empty() {
            results.push((
                -3,
                Finding {
                    title: format!(
                        "{}: {} connected interfaces",
                        snap_name,
                        risky_interfaces.len()
                    ),
                    description: format!(
                        "Snap '{}' has access to: {}",
                        snap_name,
                        risky_interfaces.join(", ")
                    ),
                    threat_level: if risky_interfaces.len() >= 3 {
                        ThreatLevel::High
                    } else {
                        ThreatLevel::Medium
                    },
                    remediation: format!("Review with: snap connections {snap_name}"),
                },
            ));
        }
    }

    results
}

// ===========================================================================
// Windows — capability access audit via the registry
// ===========================================================================

#[cfg(target_os = "windows")]
async fn audit_windows_permissions() -> Result<AuditResult> {
    let mut findings = Vec::new();
    let mut score: i32 = 100;
    let mut raw_data = HashMap::new();

    let capabilities = [
        ("webcam", "Camera", ThreatLevel::High),
        ("microphone", "Microphone", ThreatLevel::High),
        ("location", "Location", ThreatLevel::High),
        ("contacts", "Contacts", ThreatLevel::Medium),
        (
            "broadFileSystemAccess",
            "Broad File System Access",
            ThreatLevel::High,
        ),
        ("appDiagnostics", "App Diagnostics", ThreatLevel::Low),
    ];

    let mut allowed_capabilities: Vec<String> = Vec::new();

    for (cap_key, friendly_name, threat_level) in &capabilities {
        match check_windows_capability(cap_key) {
            Some(true) => {
                findings.push(Finding {
                    title: format!("{} access is enabled for apps", friendly_name),
                    description: format!(
                        "Applications are allowed to access your {}. \
                        Review which apps have been granted this permission.",
                        friendly_name.to_lowercase()
                    ),
                    threat_level: *threat_level,
                    remediation: format!(
                        "Review in Settings > Privacy & Security > {}.",
                        friendly_name
                    ),
                });
                allowed_capabilities.push(friendly_name.to_string());
                match threat_level {
                    ThreatLevel::High => score -= 10,
                    ThreatLevel::Medium => score -= 5,
                    _ => score -= 2,
                }
            }
            Some(false) => {
                // Capability disabled — good
            }
            None => {
                // Could not read — skip silently
            }
        }
    }

    raw_data.insert(
        "allowed_capabilities".to_string(),
        serde_json::json!(allowed_capabilities),
    );

    // Check for camera + microphone combo (surveillance risk)
    if allowed_capabilities.contains(&"Camera".to_string())
        && allowed_capabilities.contains(&"Microphone".to_string())
    {
        findings.push(Finding {
            title: "Camera and microphone both enabled for apps".to_string(),
            description: "Applications can access both your camera and microphone, \
                creating a potential surveillance vector."
                .to_string(),
            threat_level: ThreatLevel::High,
            remediation: "Disable camera and microphone access for apps that don't need them \
                in Settings > Privacy & Security."
                .to_string(),
        });
        score -= 10;
    }

    if findings.is_empty() {
        findings.push(Finding {
            title: "No risky app permissions detected".to_string(),
            description: "Windows app capability access appears to be properly restricted."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed.".to_string(),
        });
    }

    score = score.clamp(0, 100);

    Ok(AuditResult {
        module_name: "app_permissions".to_string(),
        score: score as u32,
        findings,
        raw_data,
    })
}

#[cfg(target_os = "windows")]
fn check_windows_capability(capability: &str) -> Option<bool> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = format!(
        "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{}",
        capability
    );
    let key = hkcu.open_subkey(&path).ok()?;
    let value: String = key.get_value("Value").ok()?;
    Some(value == "Allow")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use dtm_core::models::{ProtectOpts, ThreatLevel};

    // -----------------------------------------------------------------------
    // Cross-platform tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn module_name_is_app_permissions() {
        let opts = AuditOpts::default();
        let result = audit_app_permissions(&opts).await.unwrap();
        assert_eq!(result.module_name, "app_permissions");
        assert!(result.score <= 100);
    }

    #[test]
    fn test_module_name() {
        let module = super::super::AppPermissionsModule;
        use dtm_core::module_trait::Module;
        assert_eq!(module.name(), "app_permissions");
        assert!(!module.display_name().is_empty());
        assert!(!module.description().is_empty());
    }

    #[tokio::test]
    async fn test_protect_dry_run() {
        let module = super::super::AppPermissionsModule;
        use dtm_core::module_trait::Module;
        let opts = ProtectOpts {
            apply: false,
            ..Default::default()
        };
        let result = module.protect(&opts).await.unwrap();
        assert_eq!(result.module_name, "app_permissions");
        assert!(result.dry_run);
        assert!(result.actions_taken.is_empty());
        assert!(
            !result.actions_available.is_empty(),
            "Should have available actions"
        );
    }

    // -----------------------------------------------------------------------
    // macOS-specific tests
    // -----------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    mod macos_tests {
        use super::super::macos::*;
        use super::*;
        use rusqlite::Connection;
        use tempfile::tempdir;

        /// Create a minimal TCC database with the required schema and insert
        /// sample records.
        fn create_tcc_db(path: &std::path::Path, records: &[(&str, &str, i32)]) {
            let conn = Connection::open(path).unwrap();
            conn.execute_batch(
                "CREATE TABLE access (
                    service  TEXT NOT NULL,
                    client   TEXT NOT NULL,
                    auth_value INTEGER NOT NULL
                );",
            )
            .unwrap();
            for &(service, client, auth_value) in records {
                conn.execute(
                    "INSERT INTO access (service, client, auth_value) VALUES (?1, ?2, ?3)",
                    rusqlite::params![service, client, auth_value],
                )
                .unwrap();
            }
        }

        #[tokio::test]
        async fn camera_permission_produces_finding() {
            let dir = tempdir().unwrap();
            let db_path = dir.path().join("TCC.db");
            create_tcc_db(&db_path, &[("kTCCServiceCamera", "com.example.SpyApp", 2)]);

            let opts = AuditOpts {
                path: Some(db_path),
                ..Default::default()
            };
            let result = audit_app_permissions(&opts).await.unwrap();

            let cam_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.title.contains("Camera"))
                .collect();
            assert!(
                !cam_findings.is_empty(),
                "Expected Camera finding, got: {:#?}",
                result.findings
            );
        }

        #[tokio::test]
        async fn camera_and_mic_combo_detected() {
            let dir = tempdir().unwrap();
            let db_path = dir.path().join("TCC.db");
            create_tcc_db(
                &db_path,
                &[
                    ("kTCCServiceCamera", "com.example.VideoApp", 2),
                    ("kTCCServiceMicrophone", "com.example.VideoApp", 2),
                ],
            );

            let opts = AuditOpts {
                path: Some(db_path),
                ..Default::default()
            };
            let result = audit_app_permissions(&opts).await.unwrap();

            let combo_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.title.contains("Camera and Microphone"))
                .collect();
            assert!(
                !combo_findings.is_empty(),
                "Expected Camera+Mic combo finding, got: {:#?}",
                result.findings
            );
        }

        #[tokio::test]
        async fn over_permissioned_app_detected() {
            let dir = tempdir().unwrap();
            let db_path = dir.path().join("TCC.db");
            // Give one app 3+ high-risk permissions.
            create_tcc_db(
                &db_path,
                &[
                    ("kTCCServiceCamera", "com.example.OverApp", 2),
                    ("kTCCServiceMicrophone", "com.example.OverApp", 2),
                    ("kTCCServiceScreenCapture", "com.example.OverApp", 2),
                    ("kTCCServiceAccessibility", "com.example.OverApp", 2),
                ],
            );

            let opts = AuditOpts {
                path: Some(db_path),
                ..Default::default()
            };
            let result = audit_app_permissions(&opts).await.unwrap();

            let over_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.title.contains("Over-permissioned"))
                .collect();
            assert!(
                !over_findings.is_empty(),
                "Expected over-permissioned finding, got: {:#?}",
                result.findings
            );
        }

        #[tokio::test]
        async fn denied_permissions_not_reported() {
            let dir = tempdir().unwrap();
            let db_path = dir.path().join("TCC.db");
            // auth_value = 0 means denied.
            create_tcc_db(
                &db_path,
                &[("kTCCServiceCamera", "com.example.DeniedApp", 0)],
            );

            let opts = AuditOpts {
                path: Some(db_path),
                ..Default::default()
            };
            let result = audit_app_permissions(&opts).await.unwrap();

            // The "No TCC permissions found" finding should appear since no
            // records have auth_value = 2.
            let no_perms: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.title.contains("No TCC permissions found"))
                .collect();
            assert!(
                !no_perms.is_empty(),
                "Expected 'No TCC permissions' finding for denied-only records, got: {:#?}",
                result.findings
            );
            assert_eq!(result.score, 100);
        }

        #[tokio::test]
        async fn empty_db_produces_no_permissions_finding() {
            let dir = tempdir().unwrap();
            let db_path = dir.path().join("TCC.db");
            create_tcc_db(&db_path, &[]);

            let opts = AuditOpts {
                path: Some(db_path),
                ..Default::default()
            };
            let result = audit_app_permissions(&opts).await.unwrap();

            let no_perms: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.title.contains("No TCC permissions found"))
                .collect();
            assert!(
                !no_perms.is_empty(),
                "Expected 'No TCC permissions' finding for empty DB"
            );
            assert_eq!(result.score, 100);
        }

        #[tokio::test]
        async fn missing_db_produces_not_found_finding() {
            let dir = tempdir().unwrap();
            let db_path = dir.path().join("nonexistent.db");

            let opts = AuditOpts {
                path: Some(db_path),
                ..Default::default()
            };
            let result = audit_app_permissions(&opts).await.unwrap();

            let not_found: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.title.contains("TCC database not found"))
                .collect();
            assert!(
                !not_found.is_empty(),
                "Expected 'TCC database not found' finding"
            );
        }

        #[test]
        fn classify_service_known_services() {
            assert!(classify_service("kTCCServiceCamera").is_some());
            assert!(classify_service("kTCCServiceMicrophone").is_some());
            assert!(classify_service("kTCCServiceScreenCapture").is_some());
            assert!(classify_service("kTCCServiceSystemPolicyAllFiles").is_some());
            assert!(classify_service("kTCCServiceInputMonitoring").is_some());
        }

        #[test]
        fn classify_service_unknown_returns_none() {
            assert!(classify_service("kTCCServiceSomethingNew").is_none());
        }

        #[test]
        fn short_app_name_extracts_last_component() {
            assert_eq!(short_app_name("com.apple.Safari"), "Safari");
            assert_eq!(short_app_name("com.google.Chrome"), "Chrome");
            assert_eq!(short_app_name("standalone"), "standalone");
        }

        #[tokio::test]
        async fn test_screen_recording_produces_finding() {
            let dir = tempdir().unwrap();
            let db_path = dir.path().join("TCC.db");
            create_tcc_db(
                &db_path,
                &[("kTCCServiceScreenCapture", "com.example.RecorderApp", 2)],
            );

            let opts = AuditOpts {
                path: Some(db_path),
                ..Default::default()
            };
            let result = audit_app_permissions(&opts).await.unwrap();

            let screen_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.title.contains("Screen Recording"))
                .collect();
            assert!(
                !screen_findings.is_empty(),
                "Expected Screen Recording finding, got: {:#?}",
                result.findings
            );
            assert_eq!(screen_findings[0].threat_level, ThreatLevel::High);
        }

        #[tokio::test]
        async fn test_accessibility_critical_finding() {
            let dir = tempdir().unwrap();
            let db_path = dir.path().join("TCC.db");
            // Full Disk Access is Critical, Accessibility is High
            // Use SystemPolicyAllFiles to test Critical level
            create_tcc_db(
                &db_path,
                &[(
                    "kTCCServiceSystemPolicyAllFiles",
                    "com.example.FullDiskApp",
                    2,
                )],
            );

            let opts = AuditOpts {
                path: Some(db_path),
                ..Default::default()
            };
            let result = audit_app_permissions(&opts).await.unwrap();

            let fda_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.title.contains("Full Disk Access"))
                .collect();
            assert!(
                !fda_findings.is_empty(),
                "Expected Full Disk Access finding, got: {:#?}",
                result.findings
            );
            assert_eq!(fda_findings[0].threat_level, ThreatLevel::Critical);
        }
    }
}
