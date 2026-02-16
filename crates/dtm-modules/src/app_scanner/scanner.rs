//! Application scanner — scan installed applications for tracking SDKs.
//!
//! Cross-platform: scans .app bundles (macOS), .desktop entries and ELF binaries
//! (Linux), and .exe files (Windows). Uses goblin for binary parsing on all platforms.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use dtm_core::tracker_domains::TRACKING_SDKS;

/// Result of scanning a single application bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppScanResult {
    pub app_name: String,
    pub bundle_id: Option<String>,
    pub app_path: String,
    pub tracking_sdks: Vec<TrackingSdk>,
    pub ats_exceptions: Vec<String>,
    pub binary_size: u64,
    pub scanned_at: String,
}

/// A tracking SDK detected in an application binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingSdk {
    pub name: String,
    pub category: String,
    pub matched_dylib: String,
}

/// Scan default application directories (plus any extra dirs) for applications.
pub fn scan_apps(extra_dirs: &[PathBuf]) -> Vec<AppScanResult> {
    let mut search_dirs = default_app_dirs();
    search_dirs.extend_from_slice(extra_dirs);
    scan_dirs(&search_dirs)
}

/// Return the default application directories for the current platform.
pub fn default_app_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    #[cfg(target_os = "macos")]
    {
        dirs.push(PathBuf::from("/Applications"));
        if let Ok(home) = std::env::var("HOME") {
            let user_apps = PathBuf::from(&home).join("Applications");
            if user_apps.is_dir() {
                dirs.push(user_apps);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Scan standard application directories
        dirs.push(PathBuf::from("/usr/share/applications"));
        dirs.push(PathBuf::from("/usr/local/share/applications"));
        if let Ok(home) = std::env::var("HOME") {
            let local_apps = PathBuf::from(&home).join(".local/share/applications");
            if local_apps.is_dir() {
                dirs.push(local_apps);
            }
        }
        // Snap applications
        if PathBuf::from("/snap").is_dir() {
            dirs.push(PathBuf::from("/snap"));
        }
        // Flatpak applications
        let flatpak_dir = PathBuf::from("/var/lib/flatpak/app");
        if flatpak_dir.is_dir() {
            dirs.push(flatpak_dir);
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(pf) = std::env::var_os("ProgramFiles") {
            dirs.push(PathBuf::from(pf));
        }
        if let Some(pf86) = std::env::var_os("ProgramFiles(x86)") {
            dirs.push(PathBuf::from(pf86));
        }
        if let Some(localappdata) = std::env::var_os("LOCALAPPDATA") {
            let programs = PathBuf::from(localappdata).join("Programs");
            if programs.is_dir() {
                dirs.push(programs);
            }
        }
    }

    dirs
}

/// Scan only the specified directories for applications and detect tracking SDKs.
pub fn scan_dirs(search_dirs: &[PathBuf]) -> Vec<AppScanResult> {
    let mut results = Vec::new();

    for dir in search_dirs {
        if !dir.is_dir() {
            debug!("Skipping non-existent directory: {}", dir.display());
            continue;
        }
        info!("Scanning {}", dir.display());

        #[cfg(target_os = "macos")]
        {
            // Scan .app bundles
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
                        Err(e) => debug!("Error scanning {}: {e}", path.display()),
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            scan_linux_apps(dir, &mut results);
        }

        #[cfg(target_os = "windows")]
        {
            scan_windows_apps(dir, &mut results);
        }
    }

    info!("Scanned {} applications", results.len());
    results
}

/// Scan a single .app bundle for tracking SDKs.
#[cfg(target_os = "macos")]
fn scan_app_bundle(app_path: &Path) -> anyhow::Result<AppScanResult> {
    let app_name = app_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown")
        .to_string();

    let info_plist_path = app_path.join("Contents").join("Info.plist");

    let (bundle_id, executable_name, ats_exceptions) = if info_plist_path.exists() {
        parse_info_plist(&info_plist_path)
    } else {
        (None, None, vec![])
    };

    let exec_name = executable_name.unwrap_or_else(|| app_name.clone());
    let exec_path = app_path.join("Contents").join("MacOS").join(&exec_name);

    let mut tracking_sdks = Vec::new();
    let mut binary_size: u64 = 0;

    if exec_path.is_file() {
        binary_size = fs::metadata(&exec_path).map(|m| m.len()).unwrap_or(0);
        tracking_sdks = scan_binary(&exec_path);
    } else {
        let macos_dir = app_path.join("Contents").join("MacOS");
        if macos_dir.is_dir() {
            if let Some(first_exec) = find_first_executable(&macos_dir) {
                binary_size = fs::metadata(&first_exec).map(|m| m.len()).unwrap_or(0);
                tracking_sdks = scan_binary(&first_exec);
            }
        }
    }

    // Also scan Frameworks directory
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
        scanned_at: Utc::now().to_rfc3339(),
    })
}

/// Parse Info.plist to extract bundle ID, executable name, and ATS exceptions.
#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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

    if let Some(allows_arbitrary) = ats_dict.get("NSAllowsArbitraryLoads") {
        if allows_arbitrary.as_boolean() == Some(true) {
            exceptions.push("NSAllowsArbitraryLoads=true (all HTTP allowed)".to_string());
        }
    }

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

/// Scan any binary file (Mach-O, ELF, or PE) for tracking SDKs.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn scan_binary_file(path: &Path) -> anyhow::Result<AppScanResult> {
    let app_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Unknown")
        .to_string();

    let binary_size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let tracking_sdks = scan_binary(path);

    Ok(AppScanResult {
        app_name,
        bundle_id: None,
        app_path: path.to_string_lossy().to_string(),
        tracking_sdks,
        ats_exceptions: vec![], // ATS is macOS-only
        binary_size,
        scanned_at: Utc::now().to_rfc3339(),
    })
}

/// Scan a binary for tracking SDKs using goblin (supports Mach-O, ELF, PE).
#[cfg(feature = "macho-scan")]
fn scan_binary(path: &Path) -> Vec<TrackingSdk> {
    use goblin::Object;

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            debug!("Failed to read binary {}: {e}", path.display());
            return vec![];
        }
    };

    match Object::parse(&data) {
        Ok(Object::Mach(mach)) => scan_macho_libs(&mach),
        Ok(Object::Elf(elf)) => scan_elf_libs(&elf),
        Ok(Object::PE(pe)) => scan_pe_imports(&pe),
        Ok(_) => {
            debug!("Unsupported binary format: {}", path.display());
            vec![]
        }
        Err(e) => {
            debug!("Failed to parse binary {}: {e}", path.display());
            vec![]
        }
    }
}

#[cfg(not(feature = "macho-scan"))]
fn scan_binary(_path: &Path) -> Vec<TrackingSdk> {
    vec![]
}

#[cfg(feature = "macho-scan")]
fn scan_macho_libs(mach: &goblin::mach::Mach) -> Vec<TrackingSdk> {
    use goblin::mach::Mach;
    match mach {
        Mach::Binary(macho) => extract_sdks_from_libs(&macho.libs),
        Mach::Fat(fat) => {
            for i in 0..fat.narches {
                if let Ok(goblin::mach::SingleArch::MachO(m)) = fat.get(i) {
                    return extract_sdks_from_libs(&m.libs);
                }
            }
            vec![]
        }
    }
}

#[cfg(feature = "macho-scan")]
fn scan_elf_libs(elf: &goblin::elf::Elf) -> Vec<TrackingSdk> {
    // Extract shared library dependencies (DT_NEEDED entries)
    let libs: Vec<&str> = elf.libraries.to_vec();
    extract_sdks_from_libs(&libs)
}

#[cfg(feature = "macho-scan")]
fn scan_pe_imports(pe: &goblin::pe::PE) -> Vec<TrackingSdk> {
    // Extract imported DLLs
    let libs: Vec<&str> = pe.libraries.to_vec();
    extract_sdks_from_libs(&libs)
}

// ---------------------------------------------------------------------------
// Linux app scanning
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn scan_linux_apps(dir: &Path, results: &mut Vec<AppScanResult>) {
    // If this is a .desktop files directory
    if dir.to_string_lossy().contains("applications") {
        for entry in WalkDir::new(dir).min_depth(1).max_depth(1) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("desktop") {
                if let Some(result) = scan_desktop_file(path) {
                    results.push(result);
                }
            }
        }
    } else {
        // For snap/flatpak dirs, scan binaries directly
        for entry in WalkDir::new(dir).min_depth(1).max_depth(3) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.is_file() && is_elf_binary(path) {
                if let Ok(result) = scan_binary_file(path) {
                    results.push(result);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn scan_desktop_file(desktop_path: &Path) -> Option<AppScanResult> {
    use std::process::Command;

    let content = std::fs::read_to_string(desktop_path).ok()?;

    let _app_name = desktop_path.file_stem()?.to_string_lossy().to_string();

    // Parse Exec= line to find binary path
    let exec_line = content.lines().find(|l| l.starts_with("Exec="))?;
    let exec_cmd = exec_line.strip_prefix("Exec=")?;
    // Take the first token (before any %u, %f args)
    let binary_path_str = exec_cmd.split_whitespace().next()?;
    let binary_path = PathBuf::from(binary_path_str);

    if !binary_path.is_file() {
        // Try to find it in PATH
        let which_output = Command::new("which").arg(binary_path_str).output().ok()?;
        if !which_output.status.success() {
            return None;
        }
        let resolved = String::from_utf8_lossy(&which_output.stdout)
            .trim()
            .to_string();
        let binary_path = PathBuf::from(&resolved);
        if !binary_path.is_file() {
            return None;
        }
        return scan_binary_file(&binary_path).ok();
    }

    scan_binary_file(&binary_path).ok()
}

#[cfg(target_os = "linux")]
fn is_elf_binary(path: &Path) -> bool {
    // Check for ELF magic bytes
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    use std::io::Read;
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    magic == [0x7f, b'E', b'L', b'F']
}

// ---------------------------------------------------------------------------
// Windows app scanning
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn scan_windows_apps(dir: &Path, results: &mut Vec<AppScanResult>) {
    // Scan for .exe files in program directories (max depth 3 to avoid recursion)
    for entry in WalkDir::new(dir).min_depth(1).max_depth(3) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("exe") {
            if let Ok(result) = scan_binary_file(path) {
                results.push(result);
            }
        }
    }
}

/// Check loaded dylib paths against known tracking SDK patterns.
pub fn extract_sdks_from_libs(libs: &[&str]) -> Vec<TrackingSdk> {
    let mut found = Vec::new();

    for &lib in libs {
        for &(pattern, sdk_name, category) in TRACKING_SDKS {
            if lib.contains(pattern) {
                found.push(TrackingSdk {
                    name: sdk_name.to_string(),
                    category: category.to_string(),
                    matched_dylib: lib.to_string(),
                });
                break;
            }
        }
    }

    found
}

/// Scan the Frameworks directory for known tracking SDK framework bundles.
#[cfg(target_os = "macos")]
fn scan_frameworks_dir(frameworks_dir: &Path) -> Vec<TrackingSdk> {
    let mut found = Vec::new();

    let entries = match fs::read_dir(frameworks_dir) {
        Ok(e) => e,
        Err(_) => return found,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

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
#[cfg(target_os = "macos")]
fn find_first_executable(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
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

/// Convert scan results to DB input format and store them.
pub fn store_results(results: &[AppScanResult]) -> anyhow::Result<()> {
    let db_path = dtm_core::db::default_db_path();
    let conn = dtm_core::db::open_db(&db_path)?;

    dtm_core::db::clear_app_scans(&conn)?;

    for result in results {
        let input = dtm_core::db::AppScanInput {
            scanned_at: result.scanned_at.clone(),
            app_name: result.app_name.clone(),
            bundle_id: result.bundle_id.clone(),
            app_path: result.app_path.clone(),
            tracking_sdks_json: serde_json::to_string(&result.tracking_sdks)
                .unwrap_or_else(|_| "[]".to_string()),
            ats_exceptions_json: serde_json::to_string(&result.ats_exceptions)
                .unwrap_or_else(|_| "[]".to_string()),
            binary_size: result.binary_size,
        };
        dtm_core::db::insert_app_scan(&conn, &input)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn extract_sdks_from_known_libs() {
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
    fn extract_sdks_no_match() {
        let libs = vec!["/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.A.dylib"];
        let sdks = extract_sdks_from_libs(&libs);
        assert!(sdks.is_empty());
    }

    #[test]
    fn scan_empty_directory() {
        let tmp = TempDir::new().unwrap();
        let results = scan_dirs(&[tmp.path().to_path_buf()]);
        assert!(results.is_empty());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn parse_info_plist_missing() {
        let tmp = TempDir::new().unwrap();
        let fake_plist = tmp.path().join("Info.plist");
        let (bid, exec, ats) = parse_info_plist(&fake_plist);
        assert!(bid.is_none());
        assert!(exec.is_none());
        assert!(ats.is_empty());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn scan_frameworks_dir_empty() {
        let tmp = TempDir::new().unwrap();
        let sdks = scan_frameworks_dir(tmp.path());
        assert!(sdks.is_empty());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn scan_frameworks_dir_with_tracker() {
        let tmp = TempDir::new().unwrap();
        let fb_framework = tmp.path().join("FBSDKCoreKit.framework");
        fs::create_dir(&fb_framework).unwrap();
        let sdks = scan_frameworks_dir(tmp.path());
        assert_eq!(sdks.len(), 1);
        assert_eq!(sdks[0].name, "Facebook SDK");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_ats_exceptions_parsing() {
        // Create a mock Info.plist with ATS exceptions using plist crate
        let tmp = TempDir::new().unwrap();
        let plist_path = tmp.path().join("Info.plist");

        let mut ats_exceptions = plist::Dictionary::new();
        ats_exceptions.insert(
            "NSAllowsArbitraryLoads".to_string(),
            plist::Value::Boolean(true),
        );

        let mut exception_domain_config = plist::Dictionary::new();
        exception_domain_config.insert(
            "NSExceptionAllowsInsecureHTTPLoads".to_string(),
            plist::Value::Boolean(true),
        );

        let mut exception_domains = plist::Dictionary::new();
        exception_domains.insert(
            "example.com".to_string(),
            plist::Value::Dictionary(exception_domain_config),
        );
        ats_exceptions.insert(
            "NSExceptionDomains".to_string(),
            plist::Value::Dictionary(exception_domains),
        );

        let mut dict = plist::Dictionary::new();
        dict.insert(
            "CFBundleIdentifier".to_string(),
            plist::Value::String("com.test.ats".to_string()),
        );
        dict.insert(
            "CFBundleExecutable".to_string(),
            plist::Value::String("TestATS".to_string()),
        );
        dict.insert(
            "NSAppTransportSecurity".to_string(),
            plist::Value::Dictionary(ats_exceptions),
        );

        let value = plist::Value::Dictionary(dict);
        value.to_file_xml(&plist_path).unwrap();

        let (bundle_id, exec, ats) = parse_info_plist(&plist_path);
        assert_eq!(bundle_id.as_deref(), Some("com.test.ats"));
        assert_eq!(exec.as_deref(), Some("TestATS"));
        assert!(!ats.is_empty(), "Expected ATS exceptions, got none");
        // Should contain the arbitrary loads exception
        assert!(
            ats.iter().any(|e| e.contains("NSAllowsArbitraryLoads")),
            "Expected NSAllowsArbitraryLoads exception, got: {ats:?}"
        );
        // Should contain the domain exception
        assert!(
            ats.iter().any(|e| e.contains("example.com")),
            "Expected example.com exception, got: {ats:?}"
        );
    }

    #[test]
    fn test_scan_result_struct() {
        // Verify AppScanResult fields are populated correctly
        let result = AppScanResult {
            app_name: "TestApp".to_string(),
            bundle_id: Some("com.test.app".to_string()),
            app_path: "/Applications/TestApp.app".to_string(),
            tracking_sdks: vec![TrackingSdk {
                name: "Facebook SDK".to_string(),
                category: "social".to_string(),
                matched_dylib: "FBSDKCoreKit".to_string(),
            }],
            ats_exceptions: vec!["NSAllowsArbitraryLoads=true (all HTTP allowed)".to_string()],
            binary_size: 1024 * 1024,
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
        };

        assert_eq!(result.app_name, "TestApp");
        assert_eq!(result.bundle_id.as_deref(), Some("com.test.app"));
        assert_eq!(result.tracking_sdks.len(), 1);
        assert_eq!(result.tracking_sdks[0].name, "Facebook SDK");
        assert_eq!(result.tracking_sdks[0].category, "social");
        assert_eq!(result.ats_exceptions.len(), 1);
        assert_eq!(result.binary_size, 1024 * 1024);

        // Verify JSON serialization round-trip
        let json = serde_json::to_string(&result).expect("serialize");
        let deserialized: AppScanResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.app_name, "TestApp");
        assert_eq!(deserialized.tracking_sdks.len(), 1);
    }

    #[test]
    fn scan_binary_file_constructs_result() {
        let tmp = TempDir::new().unwrap();
        let fake_binary = tmp.path().join("test_app");
        fs::write(&fake_binary, b"not a real binary").unwrap();
        let result = scan_binary_file(&fake_binary).unwrap();
        assert_eq!(result.app_name, "test_app");
        assert!(result.tracking_sdks.is_empty());
        assert!(result.ats_exceptions.is_empty());
    }

    #[test]
    fn default_app_dirs_returns_entries() {
        let dirs = default_app_dirs();
        // On any platform, we should get at least one directory
        assert!(!dirs.is_empty(), "Should have at least one app directory");
    }
}
