use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use goblin::mach::Mach;
use log::{debug, info, warn};
use walkdir::WalkDir;

use crate::models::{AppScanResult, TrackingSdk};
use crate::tracker_domains::TRACKING_SDKS;

/// Scan /Applications and ~/Applications (plus any extra dirs) for app bundles.
pub fn scan_apps(extra_dirs: &[PathBuf]) -> Vec<AppScanResult> {
    let mut search_dirs: Vec<PathBuf> = vec![PathBuf::from("/Applications")];
    if let Ok(home) = std::env::var("HOME") {
        let user_apps = PathBuf::from(&home).join("Applications");
        if user_apps.is_dir() {
            search_dirs.push(user_apps);
        }
    }
    search_dirs.extend_from_slice(extra_dirs);
    scan_dirs(&search_dirs)
}

/// Scan only the specified directories for app bundles and detect tracking SDKs.
pub fn scan_dirs(search_dirs: &[PathBuf]) -> Vec<AppScanResult> {
    let mut results = Vec::new();

    for dir in search_dirs {
        if !dir.is_dir() {
            debug!("Skipping non-existent directory: {}", dir.display());
            continue;
        }
        info!("Scanning {}", dir.display());
        for entry in WalkDir::new(dir).min_depth(1).max_depth(1) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    debug!("Error reading directory entry: {e}");
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("app") {
                match scan_app_bundle(path) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        debug!("Error scanning {}: {e}", path.display());
                    }
                }
            }
        }
    }

    info!("Scanned {} applications", results.len());
    results
}

/// Scan a single .app bundle for tracking SDKs.
fn scan_app_bundle(app_path: &Path) -> Result<AppScanResult, Box<dyn std::error::Error>> {
    let app_name = app_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown")
        .to_string();

    let info_plist_path = app_path.join("Contents").join("Info.plist");

    // Parse Info.plist
    let (bundle_id, executable_name, ats_exceptions) = if info_plist_path.exists() {
        parse_info_plist(&info_plist_path)
    } else {
        (None, None, vec![])
    };

    // Find the main executable
    let exec_name = executable_name.unwrap_or_else(|| app_name.clone());
    let exec_path = app_path.join("Contents").join("MacOS").join(&exec_name);

    let mut tracking_sdks = Vec::new();
    let mut binary_size: u64 = 0;

    if exec_path.is_file() {
        binary_size = fs::metadata(&exec_path).map(|m| m.len()).unwrap_or(0);
        tracking_sdks = scan_macho_binary(&exec_path);
    } else {
        // Try to find any executable in Contents/MacOS
        let macos_dir = app_path.join("Contents").join("MacOS");
        if macos_dir.is_dir() {
            if let Some(first_exec) = find_first_executable(&macos_dir) {
                binary_size = fs::metadata(&first_exec).map(|m| m.len()).unwrap_or(0);
                tracking_sdks = scan_macho_binary(&first_exec);
            }
        }
    }

    // Also scan Frameworks directory for tracking SDK frameworks
    let frameworks_dir = app_path.join("Contents").join("Frameworks");
    if frameworks_dir.is_dir() {
        tracking_sdks.extend(scan_frameworks_dir(&frameworks_dir));
    }

    // Deduplicate by SDK name
    tracking_sdks.sort_by(|a, b| a.name.cmp(&b.name));
    tracking_sdks.dedup_by(|a, b| a.name == b.name);

    Ok(AppScanResult {
        app_name,
        bundle_id,
        app_path: app_path.to_string_lossy().to_string(),
        tracking_sdks,
        ats_exceptions,
        binary_size,
        scanned_at: Utc::now(),
    })
}

/// Parse Info.plist to extract bundle ID, executable name, and ATS exceptions.
fn parse_info_plist(path: &Path) -> (Option<String>, Option<String>, Vec<String>) {
    let plist_value = match plist::Value::from_file(path) {
        Ok(v) => v,
        Err(e) => {
            debug!("Failed to parse Info.plist at {}: {e}", path.display());
            return (None, None, vec![]);
        }
    };

    let dict = match plist_value.as_dictionary() {
        Some(d) => d,
        None => return (None, None, vec![]),
    };

    let bundle_id = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .map(String::from);

    let executable = dict
        .get("CFBundleExecutable")
        .and_then(|v| v.as_string())
        .map(String::from);

    let ats_exceptions = extract_ats_exceptions(dict);

    (bundle_id, executable, ats_exceptions)
}

/// Extract App Transport Security exception domains from Info.plist.
fn extract_ats_exceptions(dict: &plist::Dictionary) -> Vec<String> {
    let mut exceptions = Vec::new();

    let ats = match dict.get("NSAppTransportSecurity") {
        Some(v) => v,
        None => return exceptions,
    };

    let ats_dict = match ats.as_dictionary() {
        Some(d) => d,
        None => return exceptions,
    };

    // Check for NSAllowsArbitraryLoads (disables ATS entirely)
    if let Some(allows_arbitrary) = ats_dict.get("NSAllowsArbitraryLoads") {
        if allows_arbitrary.as_boolean() == Some(true) {
            exceptions.push("NSAllowsArbitraryLoads=true (all HTTP allowed)".to_string());
        }
    }

    // Check for per-domain exceptions
    if let Some(domains) = ats_dict.get("NSExceptionDomains") {
        if let Some(domains_dict) = domains.as_dictionary() {
            for (domain, config) in domains_dict {
                let mut issues = Vec::new();
                if let Some(config_dict) = config.as_dictionary() {
                    if config_dict
                        .get("NSExceptionAllowsInsecureHTTPLoads")
                        .and_then(|v| v.as_boolean())
                        == Some(true)
                    {
                        issues.push("allows HTTP");
                    }
                    if config_dict
                        .get("NSTemporaryExceptionAllowsInsecureHTTPLoads")
                        .and_then(|v| v.as_boolean())
                        == Some(true)
                    {
                        issues.push("allows HTTP (temporary)");
                    }
                    if config_dict
                        .get("NSExceptionRequiresForwardSecrecy")
                        .and_then(|v| v.as_boolean())
                        == Some(false)
                    {
                        issues.push("no forward secrecy");
                    }
                }
                if !issues.is_empty() {
                    exceptions.push(format!("{domain}: {}", issues.join(", ")));
                }
            }
        }
    }

    exceptions
}

/// Parse a Mach-O binary and look for tracking SDK dylibs in LC_LOAD_DYLIB commands.
fn scan_macho_binary(path: &Path) -> Vec<TrackingSdk> {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            debug!("Failed to read binary {}: {e}", path.display());
            return vec![];
        }
    };

    let mut found_sdks = Vec::new();

    match goblin::Object::parse(&data) {
        Ok(goblin::Object::Mach(mach)) => match mach {
            Mach::Binary(macho) => {
                found_sdks.extend(extract_sdks_from_libs(&macho.libs));
            }
            Mach::Fat(fat) => {
                // Parse first architecture from fat binary
                for i in 0..fat.narches {
                    if let Ok(macho) = fat.get(i) {
                        if let goblin::mach::SingleArch::MachO(m) = macho {
                            found_sdks.extend(extract_sdks_from_libs(&m.libs));
                            break; // SDKs are the same across architectures
                        }
                    }
                }
            }
        },
        Ok(_) => {
            debug!("Not a Mach-O binary: {}", path.display());
        }
        Err(e) => {
            debug!("Failed to parse binary {}: {e}", path.display());
        }
    }

    found_sdks
}

/// Check loaded dylib paths against known tracking SDK patterns.
fn extract_sdks_from_libs(libs: &[&str]) -> Vec<TrackingSdk> {
    let mut found = Vec::new();

    for &lib in libs {
        for &(pattern, sdk_name, category) in TRACKING_SDKS {
            if lib.contains(pattern) {
                found.push(TrackingSdk {
                    name: sdk_name.to_string(),
                    category: category.to_string(),
                    matched_dylib: lib.to_string(),
                });
                break; // One match per dylib is enough
            }
        }
    }

    found
}

/// Scan the Frameworks directory for known tracking SDK framework bundles.
fn scan_frameworks_dir(frameworks_dir: &Path) -> Vec<TrackingSdk> {
    let mut found = Vec::new();

    let entries = match fs::read_dir(frameworks_dir) {
        Ok(e) => e,
        Err(_) => return found,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Framework bundles end with .framework
        if !name_str.ends_with(".framework") {
            continue;
        }

        let framework_name = name_str.trim_end_matches(".framework");

        for &(pattern, sdk_name, category) in TRACKING_SDKS {
            if framework_name.contains(pattern) {
                found.push(TrackingSdk {
                    name: sdk_name.to_string(),
                    category: category.to_string(),
                    matched_dylib: format!("Frameworks/{name_str}"),
                });
                break;
            }
        }
    }

    found
}

/// Find the first executable file in a directory.
fn find_first_executable(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            // On macOS, check if file is executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(&path) {
                    if meta.permissions().mode() & 0o111 != 0 {
                        return Some(path);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return Some(path);
            }
        }
    }
    None
}

/// Print scan results as JSON to stdout.
pub fn print_results_json(results: &[AppScanResult]) {
    // Filter to only apps with findings
    let with_findings: Vec<&AppScanResult> = results
        .iter()
        .filter(|r| !r.tracking_sdks.is_empty() || !r.ats_exceptions.is_empty())
        .collect();

    match serde_json::to_string_pretty(&with_findings) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            warn!("Failed to serialize results: {e}");
        }
    }
}

/// Print a human-readable summary of scan results.
pub fn print_results_summary(results: &[AppScanResult]) {
    let total = results.len();
    let with_trackers: Vec<&AppScanResult> = results
        .iter()
        .filter(|r| !r.tracking_sdks.is_empty())
        .collect();
    let with_ats: Vec<&AppScanResult> = results
        .iter()
        .filter(|r| !r.ats_exceptions.is_empty())
        .collect();

    println!("\n=== App Tracking SDK Scan ===\n");
    println!("Applications scanned: {total}");
    println!(
        "With tracking SDKs:   {} ({:.0}%)",
        with_trackers.len(),
        if total > 0 {
            with_trackers.len() as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    );
    println!("With ATS exceptions:  {}", with_ats.len());

    if !with_trackers.is_empty() {
        println!("\n--- Apps with Tracking SDKs ---\n");
        for app in &with_trackers {
            let sdk_names: Vec<&str> = app.tracking_sdks.iter().map(|s| s.name.as_str()).collect();
            println!(
                "  {} ({}):",
                app.app_name,
                app.bundle_id.as_deref().unwrap_or("unknown")
            );
            for sdk in &sdk_names {
                println!("    - {sdk}");
            }
        }
    }

    if !with_ats.is_empty() {
        println!("\n--- Apps with ATS Exceptions ---\n");
        for app in &with_ats {
            println!(
                "  {} ({}):",
                app.app_name,
                app.bundle_id.as_deref().unwrap_or("unknown")
            );
            for exc in &app.ats_exceptions {
                println!("    - {exc}");
            }
        }
    }

    if with_trackers.is_empty() && with_ats.is_empty() {
        println!("\nNo tracking SDKs or ATS exceptions found.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_extract_sdks_from_libs() {
        let libs = vec![
            "/usr/lib/libSystem.B.dylib",
            "@rpath/FBSDKCoreKit.framework/FBSDKCoreKit",
            "@rpath/FirebaseAnalytics.framework/FirebaseAnalytics",
            "/usr/lib/libobjc.A.dylib",
        ];
        let sdks = extract_sdks_from_libs(&libs);
        assert_eq!(sdks.len(), 2);
        assert_eq!(sdks[0].name, "Facebook SDK");
        assert_eq!(sdks[1].name, "Firebase Analytics");
    }

    #[test]
    fn test_extract_sdks_no_match() {
        let libs = vec!["/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.A.dylib"];
        let sdks = extract_sdks_from_libs(&libs);
        assert!(sdks.is_empty());
    }

    #[test]
    fn test_scan_empty_directory() {
        let tmp = TempDir::new().unwrap();
        let results = scan_dirs(&[tmp.path().to_path_buf()]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_info_plist_missing() {
        let tmp = TempDir::new().unwrap();
        let fake_plist = tmp.path().join("Info.plist");
        // Non-existent file
        let (bid, exec, ats) = parse_info_plist(&fake_plist);
        assert!(bid.is_none());
        assert!(exec.is_none());
        assert!(ats.is_empty());
    }

    #[test]
    fn test_scan_frameworks_dir_empty() {
        let tmp = TempDir::new().unwrap();
        let sdks = scan_frameworks_dir(tmp.path());
        assert!(sdks.is_empty());
    }

    #[test]
    fn test_scan_frameworks_dir_with_tracker() {
        let tmp = TempDir::new().unwrap();
        let fb_framework = tmp.path().join("FBSDKCoreKit.framework");
        fs::create_dir(&fb_framework).unwrap();
        let sdks = scan_frameworks_dir(tmp.path());
        assert_eq!(sdks.len(), 1);
        assert_eq!(sdks[0].name, "Facebook SDK");
    }
}
