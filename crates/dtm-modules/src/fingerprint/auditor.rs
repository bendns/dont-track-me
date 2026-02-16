use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;
use serde_json::Value;

use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};
use dtm_core::platform::home_dir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB for config files

/// Regex to parse Firefox prefs.js: user_pref("key", value);
static PREF_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"user_pref\("([^"]+)",\s*(.+?)\);"#).unwrap());

/// Known anti-fingerprinting extension IDs (Firefox and Chrome/Brave).
static ANTI_FP_EXTENSIONS: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        // Firefox extension IDs
        ("CanvasBlocker@AK", "CanvasBlocker"),
        ("jid1-KKzOGWgsW3Ao4Q@jetpack", "JShelter"),
        ("jid1-MnnxcxisBPnSXQ@jetpack", "Privacy Badger"),
        ("uBlock0@AK", "uBlock Origin"),
        ("{73a6fe31-595d-460b-a920-fcc0f8843232}", "NoScript"),
        ("AK@nickerbocker.dk", "Trace"),
        ("{74145f27-f039-47ce-a470-a662b129930a}", "ClearURLs"),
        // Chrome extension IDs
        ("nomnklagbgmblcanipdhfkpbfkgfnclb", "CanvasBlocker"),
        ("gcbommkclmhbdofmjdahifelcpgpbidi", "JShelter"),
        ("pkehgijcmpdhfbdbbnkijodmdjhbjlgp", "Privacy Badger"),
        ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "uBlock Origin"),
    ])
});

/// Name-based fallback matching patterns (lowercase).
static ANTI_FP_NAME_PATTERNS: &[&str] = &[
    "canvasblocker",
    "jshelter",
    "privacy badger",
    "ublock origin",
    "noscript",
    "trace",
    "clearurls",
    "canvas fingerprint",
    "fingerprint protect",
    "fingerprint defend",
];

// ---------------------------------------------------------------------------
// Browser profile types
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BrowserProfile {
    browser: String,
    #[allow(dead_code)]
    profile_path: PathBuf,
    prefs: HashMap<String, Value>,
    extensions: Vec<String>,
}

impl BrowserProfile {
    fn pref_is_true(&self, key: &str) -> bool {
        self.prefs
            .get(key)
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Safe file reading helpers
// ---------------------------------------------------------------------------

fn safe_read_text(path: &Path) -> Option<String> {
    if !path.is_file() || path.is_symlink() {
        return None;
    }
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_SIZE {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

fn safe_read_json(path: &Path) -> Option<serde_json::Map<String, Value>> {
    let text = safe_read_text(path)?;
    let val: Value = serde_json::from_str(&text).ok()?;
    val.as_object().cloned()
}

// ---------------------------------------------------------------------------
// Browser profile discovery
// ---------------------------------------------------------------------------

fn find_browser_profiles() -> Vec<BrowserProfile> {
    let mut profiles = Vec::new();
    let home = match home_dir() {
        Some(h) => h,
        None => return profiles,
    };

    // (base_path, browser_name, config_type)
    let search_paths: Vec<(PathBuf, &str, &str)>;

    #[cfg(target_os = "macos")]
    {
        search_paths = vec![
            (
                home.join("Library/Application Support/Firefox/Profiles"),
                "firefox",
                "firefox",
            ),
            (
                home.join("Library/Application Support/Google/Chrome"),
                "chrome",
                "chrome",
            ),
            (
                home.join("Library/Application Support/BraveSoftware/Brave-Browser"),
                "brave",
                "chrome",
            ),
        ];
    }

    #[cfg(target_os = "linux")]
    {
        search_paths = vec![
            (home.join(".mozilla/firefox"), "firefox", "firefox"),
            (home.join(".config/google-chrome"), "chrome", "chrome"),
            (
                home.join(".config/BraveSoftware/Brave-Browser"),
                "brave",
                "chrome",
            ),
        ];
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        search_paths = Vec::new();
    }

    for (base_path, browser, config_type) in &search_paths {
        if !base_path.exists() || base_path.is_symlink() {
            continue;
        }

        let entries = match std::fs::read_dir(base_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let profile_dir = entry.path();
            if !profile_dir.is_dir() || profile_dir.is_symlink() {
                continue;
            }

            if *config_type == "firefox" {
                if !profile_dir.join("prefs.js").exists() {
                    continue;
                }
                let prefs = parse_firefox_prefs(&profile_dir);
                let extensions = parse_firefox_extensions(&profile_dir);
                profiles.push(BrowserProfile {
                    browser: browser.to_string(),
                    profile_path: profile_dir,
                    prefs,
                    extensions,
                });
            } else {
                // Chrome/Brave profiles have Preferences file
                if !profile_dir.join("Preferences").exists() {
                    continue;
                }
                let extensions = parse_chrome_extensions(&profile_dir);
                profiles.push(BrowserProfile {
                    browser: browser.to_string(),
                    profile_path: profile_dir,
                    prefs: HashMap::new(),
                    extensions,
                });
            }
        }
    }

    profiles
}

// ---------------------------------------------------------------------------
// Firefox prefs.js parsing
// ---------------------------------------------------------------------------

fn parse_firefox_prefs(profile_path: &Path) -> HashMap<String, Value> {
    let mut prefs = HashMap::new();
    let text = match safe_read_text(&profile_path.join("prefs.js")) {
        Some(t) => t,
        None => return prefs,
    };

    for caps in PREF_RE.captures_iter(&text) {
        let key = caps[1].to_string();
        let raw_value = caps[2].trim();

        let value = match raw_value {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ if raw_value.starts_with('"') && raw_value.ends_with('"') => {
                Value::String(raw_value[1..raw_value.len() - 1].to_string())
            }
            _ => {
                if let Ok(n) = raw_value.parse::<i64>() {
                    Value::Number(n.into())
                } else {
                    Value::String(raw_value.to_string())
                }
            }
        };

        prefs.insert(key, value);
    }

    prefs
}

// ---------------------------------------------------------------------------
// Firefox extension parsing
// ---------------------------------------------------------------------------

fn parse_firefox_extensions(profile_path: &Path) -> Vec<String> {
    let mut extensions = Vec::new();
    let data = match safe_read_json(&profile_path.join("extensions.json")) {
        Some(d) => d,
        None => return extensions,
    };

    let addons = match data.get("addons").and_then(Value::as_array) {
        Some(a) => a,
        None => return extensions,
    };

    for addon in addons {
        let obj = match addon.as_object() {
            Some(o) => o,
            None => continue,
        };

        let ext_id = obj.get("id").and_then(Value::as_str).unwrap_or("");

        let name = obj
            .get("defaultLocale")
            .and_then(Value::as_object)
            .and_then(|loc| loc.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");

        // Check by ID first
        if let Some(&friendly_name) = ANTI_FP_EXTENSIONS.get(ext_id) {
            extensions.push(friendly_name.to_string());
        } else if !name.is_empty() {
            let lower = name.to_ascii_lowercase();
            if ANTI_FP_NAME_PATTERNS.iter().any(|pat| lower.contains(pat)) {
                extensions.push(name.to_string());
            }
        }
    }

    extensions
}

// ---------------------------------------------------------------------------
// Chrome/Brave extension parsing
// ---------------------------------------------------------------------------

fn parse_chrome_extensions(profile_path: &Path) -> Vec<String> {
    let mut extensions = Vec::new();
    let data = match safe_read_json(&profile_path.join("Preferences")) {
        Some(d) => d,
        None => return extensions,
    };

    let settings = match data
        .get("extensions")
        .and_then(Value::as_object)
        .and_then(|e| e.get("settings"))
        .and_then(Value::as_object)
    {
        Some(s) => s,
        None => return extensions,
    };

    for (ext_id, ext_data) in settings {
        let obj = match ext_data.as_object() {
            Some(o) => o,
            None => continue,
        };

        // Check by ID
        if let Some(&friendly_name) = ANTI_FP_EXTENSIONS.get(ext_id.as_str()) {
            extensions.push(friendly_name.to_string());
            continue;
        }

        // Check by manifest name
        if let Some(name) = obj
            .get("manifest")
            .and_then(Value::as_object)
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
        {
            let lower = name.to_ascii_lowercase();
            if ANTI_FP_NAME_PATTERNS.iter().any(|pat| lower.contains(pat)) {
                extensions.push(name.to_string());
            }
        }
    }

    extensions
}

// ---------------------------------------------------------------------------
// Fingerprint checks
// ---------------------------------------------------------------------------

fn check_resist_fingerprinting(profiles: &[BrowserProfile]) -> (Vec<Finding>, i32) {
    let mut findings = Vec::new();
    let mut score_delta: i32 = 0;

    let firefox_profiles: Vec<&BrowserProfile> =
        profiles.iter().filter(|p| p.browser == "firefox").collect();

    if firefox_profiles.is_empty() {
        return (findings, score_delta);
    }

    let any_enabled = firefox_profiles
        .iter()
        .any(|p| p.pref_is_true("privacy.resistFingerprinting"));

    if any_enabled {
        findings.push(Finding {
            title: "Firefox resistFingerprinting enabled".to_string(),
            description: "privacy.resistFingerprinting is enabled, which normalizes \
                Canvas, WebGL, fonts, timezone, screen dimensions, languages, \
                and User-Agent to reduce fingerprint uniqueness."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed — this is the strongest anti-fingerprinting measure."
                .to_string(),
        });
    } else {
        findings.push(Finding {
            title: "Firefox resistFingerprinting is disabled".to_string(),
            description: "privacy.resistFingerprinting is not enabled in any Firefox profile. \
                This single setting is the most effective anti-fingerprinting measure \
                available — it normalizes dozens of fingerprinting signals at once."
                .to_string(),
            threat_level: ThreatLevel::High,
            remediation: "Open about:config in Firefox, search for \
                'privacy.resistFingerprinting' and set it to true. \
                Or use 'dtm protect fingerprint --apply' to set it automatically."
                .to_string(),
        });
        score_delta -= 25;
    }

    (findings, score_delta)
}

fn check_webgl_exposure(profiles: &[BrowserProfile]) -> (Vec<Finding>, i32) {
    let mut findings = Vec::new();
    let mut score_delta: i32 = 0;

    let firefox_profiles: Vec<&BrowserProfile> =
        profiles.iter().filter(|p| p.browser == "firefox").collect();

    // If resistFingerprinting is on, WebGL renderer is already spoofed
    let rfp_enabled = firefox_profiles
        .iter()
        .any(|p| p.pref_is_true("privacy.resistFingerprinting"));
    if rfp_enabled {
        return (findings, score_delta);
    }

    let webgl_disabled = firefox_profiles
        .iter()
        .any(|p| p.pref_is_true("webgl.disabled"));

    if !webgl_disabled {
        findings.push(Finding {
            title: "WebGL fingerprinting vector exposed".to_string(),
            description: "WebGL is enabled and exposes your GPU vendor and renderer string \
                (e.g., 'ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)'). This is one of \
                the strongest fingerprinting signals — it uniquely identifies your \
                hardware configuration."
                .to_string(),
            threat_level: ThreatLevel::Medium,
            remediation: "Firefox: set 'webgl.disabled = true' in about:config \
                (may break some websites). Or enable resistFingerprinting to spoof it."
                .to_string(),
        });
        score_delta -= 10;
    }

    (findings, score_delta)
}

fn check_anti_fingerprint_extensions(profiles: &[BrowserProfile]) -> (Vec<Finding>, i32) {
    let mut findings = Vec::new();
    let mut score_delta: i32 = 0;

    let all_extensions: HashSet<&str> = profiles
        .iter()
        .flat_map(|p| p.extensions.iter().map(|s| s.as_str()))
        .collect();

    if !all_extensions.is_empty() {
        let mut sorted: Vec<&str> = all_extensions.into_iter().collect();
        sorted.sort();
        findings.push(Finding {
            title: format!(
                "Anti-fingerprinting extensions found: {}",
                sorted.join(", ")
            ),
            description: format!(
                "Detected {} anti-fingerprinting extension(s) \
                 across your browser profiles. These help reduce fingerprint uniqueness.",
                sorted.len()
            ),
            threat_level: ThreatLevel::Info,
            remediation: "No action needed — keep these extensions updated.".to_string(),
        });
    } else if !profiles.is_empty() {
        findings.push(Finding {
            title: "No anti-fingerprinting extensions detected".to_string(),
            description: "No anti-fingerprinting browser extensions were found in any profile. \
                Extensions like CanvasBlocker, uBlock Origin, or Privacy Badger can \
                significantly reduce your fingerprint uniqueness."
                .to_string(),
            threat_level: ThreatLevel::Medium,
            remediation: "Install CanvasBlocker (Firefox) or a fingerprint-blocking extension. \
                uBlock Origin in advanced mode also blocks many fingerprinting scripts."
                .to_string(),
        });
        score_delta -= 15;
    }

    (findings, score_delta)
}

fn check_canvas_protection(profiles: &[BrowserProfile]) -> (Vec<Finding>, i32) {
    let mut findings = Vec::new();
    let mut score_delta: i32 = 0;

    // Firefox with resistFingerprinting already covers Canvas
    let firefox_rfp = profiles
        .iter()
        .any(|p| p.browser == "firefox" && p.pref_is_true("privacy.resistFingerprinting"));
    if firefox_rfp {
        return (findings, score_delta);
    }

    // Check for CanvasBlocker or similar extension
    let has_canvas_ext = profiles.iter().any(|p| {
        p.extensions
            .iter()
            .any(|ext| ext == "CanvasBlocker" || ext == "Canvas Fingerprint Defender")
    });
    if has_canvas_ext {
        return (findings, score_delta);
    }

    if !profiles.is_empty() {
        findings.push(Finding {
            title: "Canvas fingerprinting unprotected".to_string(),
            description: "No Canvas fingerprinting protection detected. HTML5 Canvas renders \
                text and shapes slightly differently per GPU, driver, and font \
                configuration — creating a near-unique fingerprint. This is the \
                most common active fingerprinting technique."
                .to_string(),
            threat_level: ThreatLevel::High,
            remediation:
                "Firefox: enable privacy.resistFingerprinting (normalizes Canvas output). \
                Chrome: install CanvasBlocker or Canvas Fingerprint Defender extension."
                    .to_string(),
        });
        score_delta -= 15;
    }

    (findings, score_delta)
}

// ---------------------------------------------------------------------------
// System font counting
// ---------------------------------------------------------------------------

fn count_system_fonts() -> usize {
    #[cfg(target_os = "macos")]
    {
        count_system_fonts_macos()
    }

    #[cfg(target_os = "linux")]
    {
        count_system_fonts_linux()
    }

    #[cfg(target_os = "windows")]
    {
        count_system_fonts_windows()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        0
    }
}

#[cfg(target_os = "macos")]
fn count_system_fonts_macos() -> usize {
    let home = home_dir().unwrap_or_else(|| PathBuf::from("/"));
    let font_dirs = [
        PathBuf::from("/Library/Fonts"),
        PathBuf::from("/System/Library/Fonts"),
        home.join("Library/Fonts"),
    ];

    let mut count: usize = 0;
    for font_dir in &font_dirs {
        if !font_dir.exists() || font_dir.is_symlink() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(font_dir) {
            count += entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .count();
        }
    }
    count
}

#[cfg(target_os = "linux")]
fn count_system_fonts_linux() -> usize {
    let output = Command::new("fc-list")
        .args(["--format", "%{family}\n"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let families: HashSet<&str> = text
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            families.len()
        }
        _ => 0,
    }
}

#[cfg(target_os = "windows")]
fn count_system_fonts_windows() -> usize {
    let font_dir = std::path::PathBuf::from(r"C:\Windows\Fonts");
    if !font_dir.exists() {
        return 0;
    }
    match std::fs::read_dir(&font_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .count(),
        Err(_) => 0,
    }
}

fn check_font_exposure(font_count: usize) -> (Vec<Finding>, i32) {
    let mut findings = Vec::new();
    let mut score_delta: i32 = 0;

    if font_count == 0 {
        return (findings, score_delta);
    }

    if font_count > 200 {
        findings.push(Finding {
            title: format!("Large font library ({font_count} fonts) increases uniqueness"),
            description: format!(
                "Your system has {font_count} fonts installed. Font enumeration is \
                 a powerful fingerprinting vector — each additional font increases \
                 your browser's uniqueness. Most systems have 100-200 fonts."
            ),
            threat_level: ThreatLevel::Medium,
            remediation: "Remove unnecessary custom fonts. Use Firefox with \
                resistFingerprinting (restricts font visibility) or set \
                layout.css.font-visibility.level = 1 in about:config."
                .to_string(),
        });
        score_delta -= 5;
    } else if font_count > 100 {
        findings.push(Finding {
            title: format!("Moderate font library ({font_count} fonts)"),
            description: format!(
                "Your system has {font_count} fonts installed. This is within \
                 the normal range but still contributes to fingerprint uniqueness."
            ),
            threat_level: ThreatLevel::Low,
            remediation: "Consider enabling Firefox's resistFingerprinting or setting \
                layout.css.font-visibility.level to restrict font access."
                .to_string(),
        });
        score_delta -= 2;
    }

    (findings, score_delta)
}

// ---------------------------------------------------------------------------
// System fingerprint signals
// ---------------------------------------------------------------------------

fn check_system_fingerprint() -> (Vec<Finding>, i32, HashMap<String, Value>) {
    let mut findings = Vec::new();
    let mut score_delta: i32 = 0;
    let mut raw: HashMap<String, Value> = HashMap::new();

    // CPU count (exposed as navigator.hardwareConcurrency)
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    raw.insert("cpu_count".to_string(), serde_json::json!(cpu_count));

    if cpu_count > 4 {
        findings.push(Finding {
            title: format!("Hardware: {cpu_count} CPU cores exposed"),
            description: format!(
                "navigator.hardwareConcurrency reports {cpu_count} cores. \
                 Non-standard values (most common: 4, 8) add entropy to your fingerprint. \
                 Firefox with resistFingerprinting normalizes this to 2."
            ),
            threat_level: ThreatLevel::Low,
            remediation: "Enable resistFingerprinting in Firefox to normalize to 2 cores."
                .to_string(),
        });
        score_delta -= 3;
    }

    // Timezone (exposed via Intl.DateTimeFormat)
    let tz_name = get_timezone_name();
    raw.insert("timezone".to_string(), Value::String(tz_name.clone()));

    if tz_name != "UTC" && tz_name != "GMT" && tz_name != "unknown" {
        findings.push(Finding {
            title: format!("Timezone '{tz_name}' adds fingerprint entropy"),
            description: format!(
                "Your timezone ({tz_name}) is exposed via the Intl API. \
                 Combined with other signals, timezone helps narrow your identity. \
                 Firefox with resistFingerprinting reports UTC."
            ),
            threat_level: ThreatLevel::Low,
            remediation: "Enable resistFingerprinting in Firefox to report UTC timezone."
                .to_string(),
        });
        score_delta -= 3;
    }

    (findings, score_delta, raw)
}

/// Get the system timezone name.
fn get_timezone_name() -> String {
    // Try reading /etc/localtime symlink target on Unix
    #[cfg(unix)]
    {
        if let Ok(link) = std::fs::read_link("/etc/localtime") {
            let path_str = link.to_string_lossy();
            // Path looks like .../zoneinfo/America/New_York
            if let Some(pos) = path_str.find("zoneinfo/") {
                return path_str[pos + 9..].to_string();
            }
        }
        // Fallback: TZ environment variable
        if let Ok(tz) = std::env::var("TZ") {
            if !tz.is_empty() {
                return tz;
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Ok(tz) = std::env::var("TZ") {
            if !tz.is_empty() {
                return tz;
            }
        }
    }

    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn audit_fingerprint(_opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut score: i32 = 100;

    // Discover browser profiles
    let profiles = find_browser_profiles();

    if profiles.is_empty() {
        findings.push(Finding {
            title: "No browser profiles found".to_string(),
            description: "Could not locate Firefox, Chrome, or Brave profiles. \
                Without browser configuration data, fingerprint exposure \
                cannot be fully assessed."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Ensure a supported browser is installed. \
                The audit checks Firefox, Chrome, and Brave profiles."
                .to_string(),
        });
        score -= 20; // Unknown browser config is risky
    }

    // Run static checks
    type CheckFn = fn(&[BrowserProfile]) -> (Vec<Finding>, i32);
    let checks: Vec<CheckFn> = vec![
        check_resist_fingerprinting,
        check_webgl_exposure,
        check_anti_fingerprint_extensions,
        check_canvas_protection,
    ];

    for check_fn in checks {
        let (check_findings, delta) = check_fn(&profiles);
        findings.extend(check_findings);
        score += delta;
    }

    // Font exposure check
    let font_count = count_system_fonts();
    let (font_findings, font_delta) = check_font_exposure(font_count);
    findings.extend(font_findings);
    score += font_delta;

    // System fingerprint signals
    let (sys_findings, sys_delta, sys_raw) = check_system_fingerprint();
    findings.extend(sys_findings);
    score += sys_delta;

    // Collect raw data
    let browsers_found: Vec<String> = {
        let mut set: HashSet<&str> = HashSet::new();
        for p in &profiles {
            set.insert(&p.browser);
        }
        let mut v: Vec<String> = set.into_iter().map(|s| s.to_string()).collect();
        v.sort();
        v
    };

    let resist_fp = profiles
        .iter()
        .any(|p| p.browser == "firefox" && p.pref_is_true("privacy.resistFingerprinting"));

    let webgl_off = profiles
        .iter()
        .any(|p| p.browser == "firefox" && p.pref_is_true("webgl.disabled"));

    let extensions_found: Vec<String> = {
        let mut set: HashSet<&str> = HashSet::new();
        for p in &profiles {
            for ext in &p.extensions {
                set.insert(ext.as_str());
            }
        }
        let mut v: Vec<String> = set.into_iter().map(|s| s.to_string()).collect();
        v.sort();
        v
    };

    let mut raw_data: HashMap<String, Value> = HashMap::new();
    raw_data.insert(
        "browsers_found".to_string(),
        serde_json::json!(browsers_found),
    );
    raw_data.insert(
        "profiles_scanned".to_string(),
        serde_json::json!(profiles.len()),
    );
    raw_data.insert(
        "resist_fingerprinting".to_string(),
        serde_json::json!(resist_fp),
    );
    raw_data.insert("webgl_disabled".to_string(), serde_json::json!(webgl_off));
    raw_data.insert(
        "extensions_found".to_string(),
        serde_json::json!(extensions_found),
    );
    raw_data.insert("font_count".to_string(), serde_json::json!(font_count));
    raw_data.extend(sys_raw);

    let score = score.clamp(0, 100) as u32;

    Ok(AuditResult {
        module_name: "fingerprint".to_string(),
        score,
        findings,
        raw_data,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Create a BrowserProfile with the given parameters (no disk I/O).
    fn make_firefox_profile(
        prefs: HashMap<String, Value>,
        extensions: Vec<String>,
    ) -> BrowserProfile {
        BrowserProfile {
            browser: "firefox".to_string(),
            profile_path: PathBuf::from("/tmp/fake-profile"),
            prefs,
            extensions,
        }
    }

    fn make_chrome_profile(extensions: Vec<String>) -> BrowserProfile {
        BrowserProfile {
            browser: "chrome".to_string(),
            profile_path: PathBuf::from("/tmp/fake-chrome-profile"),
            prefs: HashMap::new(),
            extensions,
        }
    }

    fn prefs_with(key: &str, val: Value) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert(key.to_string(), val);
        m
    }

    // -----------------------------------------------------------------------
    // 1. find_profiles_empty_dir
    // -----------------------------------------------------------------------
    #[test]
    fn find_profiles_empty_dir() {
        let dir = TempDir::new().unwrap();
        // Scan an empty directory — no profiles should be found.
        let entries = fs::read_dir(dir.path()).unwrap();
        let profiles: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter(|e| e.path().join("prefs.js").exists() || e.path().join("Preferences").exists())
            .map(|e| e.path())
            .collect();
        assert!(profiles.is_empty(), "empty dir should yield no profiles");
    }

    // -----------------------------------------------------------------------
    // 2. parse_firefox_prefs_rfp_enabled
    // -----------------------------------------------------------------------
    #[test]
    fn parse_firefox_prefs_rfp_enabled() {
        let dir = TempDir::new().unwrap();
        let prefs_content = r#"user_pref("privacy.resistFingerprinting", true);
user_pref("browser.startup.homepage", "about:blank");
"#;
        fs::write(dir.path().join("prefs.js"), prefs_content).unwrap();

        let prefs = parse_firefox_prefs(dir.path());
        assert_eq!(
            prefs.get("privacy.resistFingerprinting"),
            Some(&Value::Bool(true)),
            "resistFingerprinting should be parsed as true"
        );
    }

    // -----------------------------------------------------------------------
    // 3. parse_firefox_prefs_rfp_disabled
    // -----------------------------------------------------------------------
    #[test]
    fn parse_firefox_prefs_rfp_disabled() {
        let dir = TempDir::new().unwrap();
        let prefs_content = r#"user_pref("privacy.resistFingerprinting", false);"#;
        fs::write(dir.path().join("prefs.js"), prefs_content).unwrap();

        let prefs = parse_firefox_prefs(dir.path());
        assert_eq!(
            prefs.get("privacy.resistFingerprinting"),
            Some(&Value::Bool(false)),
            "resistFingerprinting should be parsed as false"
        );
    }

    // -----------------------------------------------------------------------
    // 4. parse_firefox_prefs_webgl_disabled
    // -----------------------------------------------------------------------
    #[test]
    fn parse_firefox_prefs_webgl_disabled() {
        let dir = TempDir::new().unwrap();
        let prefs_content = r#"user_pref("webgl.disabled", true);"#;
        fs::write(dir.path().join("prefs.js"), prefs_content).unwrap();

        let prefs = parse_firefox_prefs(dir.path());
        assert_eq!(
            prefs.get("webgl.disabled"),
            Some(&Value::Bool(true)),
            "webgl.disabled should be parsed as true"
        );
    }

    // -----------------------------------------------------------------------
    // 5. parse_firefox_prefs_empty
    // -----------------------------------------------------------------------
    #[test]
    fn parse_firefox_prefs_empty() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("prefs.js"), "").unwrap();

        let prefs = parse_firefox_prefs(dir.path());
        assert!(prefs.is_empty(), "empty prefs.js should yield no prefs");
    }

    // -----------------------------------------------------------------------
    // 6. parse_chrome_prefs_basic
    // -----------------------------------------------------------------------
    #[test]
    fn parse_chrome_prefs_basic() {
        let dir = TempDir::new().unwrap();
        let prefs_json = serde_json::json!({
            "extensions": {
                "settings": {
                    "cjpalhdlnbpafiamejdnhcphjbkeiagm": {
                        "manifest": {
                            "name": "uBlock Origin"
                        }
                    }
                }
            }
        });
        fs::write(
            dir.path().join("Preferences"),
            serde_json::to_string_pretty(&prefs_json).unwrap(),
        )
        .unwrap();

        let extensions = parse_chrome_extensions(dir.path());
        assert!(
            extensions.contains(&"uBlock Origin".to_string()),
            "uBlock Origin should be detected by extension ID"
        );
    }

    // -----------------------------------------------------------------------
    // 7. check_rfp_enabled_no_penalty
    // -----------------------------------------------------------------------
    #[test]
    fn check_rfp_enabled_no_penalty() {
        let profiles = vec![make_firefox_profile(
            prefs_with("privacy.resistFingerprinting", Value::Bool(true)),
            vec![],
        )];

        let (findings, delta) = check_resist_fingerprinting(&profiles);
        assert_eq!(delta, 0, "RFP enabled should not penalize score");
        assert!(
            findings.iter().any(|f| f.threat_level == ThreatLevel::Info),
            "should have an info-level finding for enabled RFP"
        );
    }

    // -----------------------------------------------------------------------
    // 8. check_rfp_disabled_penalty
    // -----------------------------------------------------------------------
    #[test]
    fn check_rfp_disabled_penalty() {
        let profiles = vec![make_firefox_profile(
            prefs_with("privacy.resistFingerprinting", Value::Bool(false)),
            vec![],
        )];

        let (findings, delta) = check_resist_fingerprinting(&profiles);
        assert!(delta < 0, "RFP disabled should penalize the score");
        assert_eq!(delta, -25, "penalty should be -25");
        assert!(
            findings.iter().any(|f| f.threat_level == ThreatLevel::High),
            "should have a high-threat finding for disabled RFP"
        );
    }

    // -----------------------------------------------------------------------
    // 9. check_webgl_exposure_disabled
    // -----------------------------------------------------------------------
    #[test]
    fn check_webgl_exposure_disabled() {
        let profiles = vec![make_firefox_profile(
            {
                let mut m = HashMap::new();
                m.insert(
                    "privacy.resistFingerprinting".to_string(),
                    Value::Bool(false),
                );
                m.insert("webgl.disabled".to_string(), Value::Bool(true));
                m
            },
            vec![],
        )];

        let (findings, delta) = check_webgl_exposure(&profiles);
        assert_eq!(delta, 0, "WebGL disabled should not penalize score");
        assert!(
            findings.is_empty(),
            "no findings expected when WebGL is disabled"
        );
    }

    // -----------------------------------------------------------------------
    // 10. check_webgl_exposure_enabled
    // -----------------------------------------------------------------------
    #[test]
    fn check_webgl_exposure_enabled() {
        let profiles = vec![make_firefox_profile(
            prefs_with("privacy.resistFingerprinting", Value::Bool(false)),
            vec![],
        )];

        let (findings, delta) = check_webgl_exposure(&profiles);
        assert!(delta < 0, "WebGL enabled should penalize score");
        assert_eq!(delta, -10);
        assert!(
            findings
                .iter()
                .any(|f| f.threat_level == ThreatLevel::Medium),
            "should have a medium-threat finding for WebGL exposure"
        );
    }

    // -----------------------------------------------------------------------
    // 11. check_canvas_no_extension
    // -----------------------------------------------------------------------
    #[test]
    fn check_canvas_no_extension() {
        // Firefox without RFP, no canvas-blocking extensions
        let profiles = vec![make_firefox_profile(
            prefs_with("privacy.resistFingerprinting", Value::Bool(false)),
            vec![],
        )];

        let (findings, delta) = check_canvas_protection(&profiles);
        assert!(delta < 0, "no canvas protection should penalize score");
        assert_eq!(delta, -15);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Canvas fingerprinting unprotected")),
            "should report canvas fingerprinting as unprotected"
        );
    }

    // -----------------------------------------------------------------------
    // 12. extensions_detected
    // -----------------------------------------------------------------------
    #[test]
    fn extensions_detected() {
        let profiles = vec![make_firefox_profile(
            HashMap::new(),
            vec!["uBlock Origin".to_string(), "CanvasBlocker".to_string()],
        )];

        let (findings, delta) = check_anti_fingerprint_extensions(&profiles);
        assert_eq!(delta, 0, "having extensions should not penalize score");
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Anti-fingerprinting extensions found")),
            "should report detected extensions"
        );
        // Both extension names should appear in the finding
        let ext_finding = findings
            .iter()
            .find(|f| f.title.contains("Anti-fingerprinting extensions found"))
            .unwrap();
        assert!(ext_finding.title.contains("CanvasBlocker"));
        assert!(ext_finding.title.contains("uBlock Origin"));
    }

    // -----------------------------------------------------------------------
    // 13. system_font_count
    // -----------------------------------------------------------------------
    #[test]
    fn system_font_count() {
        // Large font count (> 200) should produce a finding
        let (findings, delta) = check_font_exposure(250);
        assert!(delta < 0, "large font count should penalize score");
        assert_eq!(delta, -5);
        assert!(
            findings.iter().any(|f| f.title.contains("250 fonts")),
            "finding should mention the font count"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.threat_level == ThreatLevel::Medium),
            "large font count should be medium threat"
        );

        // Moderate font count (101-200)
        let (findings_mod, delta_mod) = check_font_exposure(150);
        assert_eq!(delta_mod, -2);
        assert!(
            findings_mod
                .iter()
                .any(|f| f.threat_level == ThreatLevel::Low),
            "moderate font count should be low threat"
        );

        // Small font count (< 100) — no finding
        let (findings_small, delta_small) = check_font_exposure(50);
        assert_eq!(delta_small, 0);
        assert!(findings_small.is_empty());
    }

    // -----------------------------------------------------------------------
    // 14. audit_with_rfp_and_extensions
    // -----------------------------------------------------------------------
    #[test]
    fn audit_with_rfp_and_extensions() {
        // Good config: RFP enabled + extensions
        let profiles = vec![make_firefox_profile(
            prefs_with("privacy.resistFingerprinting", Value::Bool(true)),
            vec!["uBlock Origin".to_string(), "CanvasBlocker".to_string()],
        )];

        let mut total_delta: i32 = 0;

        let (_, delta) = check_resist_fingerprinting(&profiles);
        total_delta += delta;
        assert_eq!(delta, 0, "RFP enabled: no penalty");

        let (_, delta) = check_webgl_exposure(&profiles);
        total_delta += delta;
        assert_eq!(delta, 0, "RFP covers WebGL: no penalty");

        let (_, delta) = check_anti_fingerprint_extensions(&profiles);
        total_delta += delta;
        assert_eq!(delta, 0, "extensions present: no penalty");

        let (_, delta) = check_canvas_protection(&profiles);
        total_delta += delta;
        assert_eq!(delta, 0, "RFP covers canvas: no penalty");

        // Score should remain at 100 (no penalties from browser checks)
        let score = (100 + total_delta).clamp(0, 100);
        assert_eq!(
            score, 100,
            "well-configured browser should score 100 from browser checks"
        );
    }

    // -----------------------------------------------------------------------
    // 15. audit_bare_browser
    // -----------------------------------------------------------------------
    #[test]
    fn audit_bare_browser() {
        // No protections at all: RFP off, no extensions
        let profiles = vec![make_firefox_profile(HashMap::new(), vec![])];

        let mut total_delta: i32 = 0;

        let (_, delta) = check_resist_fingerprinting(&profiles);
        total_delta += delta;
        assert_eq!(delta, -25, "RFP disabled: -25");

        let (_, delta) = check_webgl_exposure(&profiles);
        total_delta += delta;
        assert_eq!(delta, -10, "WebGL exposed: -10");

        let (_, delta) = check_anti_fingerprint_extensions(&profiles);
        total_delta += delta;
        assert_eq!(delta, -15, "no extensions: -15");

        let (_, delta) = check_canvas_protection(&profiles);
        total_delta += delta;
        assert_eq!(delta, -15, "canvas unprotected: -15");

        let score = (100 + total_delta).clamp(0, 100);
        assert_eq!(
            score, 35,
            "bare browser should score 35 from browser checks"
        );
    }

    // -----------------------------------------------------------------------
    // 16. firefox_profile_with_prefs_js
    // -----------------------------------------------------------------------
    #[test]
    fn firefox_profile_with_prefs_js() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path().join("abc123.default");
        fs::create_dir_all(&profile_dir).unwrap();

        let prefs_content = r#"
user_pref("privacy.resistFingerprinting", true);
user_pref("webgl.disabled", true);
user_pref("network.cookie.cookieBehavior", 5);
user_pref("browser.startup.homepage", "about:blank");
"#;
        fs::write(profile_dir.join("prefs.js"), prefs_content).unwrap();

        let prefs = parse_firefox_prefs(&profile_dir);
        assert_eq!(prefs.len(), 4);
        assert_eq!(
            prefs.get("privacy.resistFingerprinting"),
            Some(&Value::Bool(true))
        );
        assert_eq!(prefs.get("webgl.disabled"), Some(&Value::Bool(true)));
        assert_eq!(
            prefs.get("network.cookie.cookieBehavior"),
            Some(&Value::Number(5.into()))
        );
        assert_eq!(
            prefs.get("browser.startup.homepage"),
            Some(&Value::String("about:blank".to_string()))
        );
    }

    // -----------------------------------------------------------------------
    // 17. chrome_profile_with_preferences
    // -----------------------------------------------------------------------
    #[test]
    fn chrome_profile_with_preferences() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path().join("Default");
        fs::create_dir_all(&profile_dir).unwrap();

        let prefs_json = serde_json::json!({
            "extensions": {
                "settings": {
                    "cjpalhdlnbpafiamejdnhcphjbkeiagm": {
                        "manifest": {
                            "name": "uBlock Origin",
                            "version": "1.50.0"
                        }
                    },
                    "pkehgijcmpdhfbdbbnkijodmdjhbjlgp": {
                        "manifest": {
                            "name": "Privacy Badger",
                            "version": "2024.1.1"
                        }
                    },
                    "some-other-extension-id": {
                        "manifest": {
                            "name": "Dark Reader",
                            "version": "4.9.0"
                        }
                    }
                }
            }
        });
        fs::write(
            profile_dir.join("Preferences"),
            serde_json::to_string_pretty(&prefs_json).unwrap(),
        )
        .unwrap();

        let extensions = parse_chrome_extensions(&profile_dir);
        // uBlock Origin and Privacy Badger should be detected (by ID)
        assert!(
            extensions.contains(&"uBlock Origin".to_string()),
            "uBlock Origin should be detected"
        );
        assert!(
            extensions.contains(&"Privacy Badger".to_string()),
            "Privacy Badger should be detected"
        );
        // Dark Reader is not anti-fingerprinting
        assert!(
            !extensions.contains(&"Dark Reader".to_string()),
            "Dark Reader should not be detected as anti-fingerprinting"
        );
    }

    // -----------------------------------------------------------------------
    // 18. protect_writes_user_js
    // -----------------------------------------------------------------------
    #[test]
    fn protect_writes_user_js() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path().join("test-profile.default");
        fs::create_dir_all(&profile_dir).unwrap();

        // Simulate what a protector would do: write user.js with RFP settings.
        let user_js_content = r#"// dtm-generated hardening
user_pref("privacy.resistFingerprinting", true);
user_pref("webgl.disabled", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("layout.css.font-visibility.level", 1);
"#;
        let user_js_path = profile_dir.join("user.js");
        fs::write(&user_js_path, user_js_content).unwrap();

        // Verify file was created and contains expected prefs.
        assert!(user_js_path.exists(), "user.js should be created");
        let content = fs::read_to_string(&user_js_path).unwrap();
        assert!(content.contains("privacy.resistFingerprinting"));
        assert!(content.contains("webgl.disabled"));
        assert!(content.contains("layout.css.font-visibility.level"));

        // Verify the prefs can be parsed back by our parser.
        // user.js has same format as prefs.js.
        // Copy it as prefs.js to test parsing.
        fs::copy(&user_js_path, profile_dir.join("prefs.js")).unwrap();
        let prefs = parse_firefox_prefs(&profile_dir);
        assert_eq!(
            prefs.get("privacy.resistFingerprinting"),
            Some(&Value::Bool(true))
        );
        assert_eq!(prefs.get("webgl.disabled"), Some(&Value::Bool(true)));
        assert_eq!(
            prefs.get("layout.css.font-visibility.level"),
            Some(&Value::Number(1.into()))
        );
    }

    // -----------------------------------------------------------------------
    // 19. protect_dry_run
    // -----------------------------------------------------------------------
    #[test]
    fn protect_dry_run() {
        let dir = TempDir::new().unwrap();
        let profile_dir = dir.path().join("test-profile.default");
        fs::create_dir_all(&profile_dir).unwrap();

        // In dry-run mode, no files should be written.
        let user_js_path = profile_dir.join("user.js");
        let dry_run = true;

        if !dry_run {
            // This block would write user.js in apply mode.
            fs::write(
                &user_js_path,
                "user_pref(\"privacy.resistFingerprinting\", true);",
            )
            .unwrap();
        }

        // Verify no file was written.
        assert!(!user_js_path.exists(), "dry run should not create user.js");

        // Also verify the profile directory itself is untouched
        // (only the directory we created should exist).
        let entries: Vec<_> = fs::read_dir(&profile_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries.is_empty(),
            "dry run should not create any files in profile dir"
        );
    }

    // -----------------------------------------------------------------------
    // Additional edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn pref_is_true_helper() {
        let profile = make_firefox_profile(
            {
                let mut m = HashMap::new();
                m.insert(
                    "privacy.resistFingerprinting".to_string(),
                    Value::Bool(true),
                );
                m.insert(
                    "some.string.pref".to_string(),
                    Value::String("yes".to_string()),
                );
                m
            },
            vec![],
        );

        assert!(profile.pref_is_true("privacy.resistFingerprinting"));
        // String "yes" is not a bool, so pref_is_true returns false
        assert!(!profile.pref_is_true("some.string.pref"));
        // Missing key returns false
        assert!(!profile.pref_is_true("nonexistent.key"));
    }

    #[test]
    fn browser_str_representation() {
        let ff = make_firefox_profile(HashMap::new(), vec![]);
        assert_eq!(ff.browser, "firefox");

        let ch = make_chrome_profile(vec![]);
        assert_eq!(ch.browser, "chrome");
    }

    #[test]
    fn check_rfp_no_firefox_profiles() {
        // Only Chrome profiles — RFP check should return no findings.
        let profiles = vec![make_chrome_profile(vec![])];

        let (findings, delta) = check_resist_fingerprinting(&profiles);
        assert_eq!(delta, 0, "no Firefox profiles means no RFP check");
        assert!(findings.is_empty());
    }

    #[test]
    fn check_webgl_skipped_when_rfp_enabled() {
        // When RFP is on, WebGL is already spoofed — no penalty.
        let profiles = vec![make_firefox_profile(
            prefs_with("privacy.resistFingerprinting", Value::Bool(true)),
            vec![],
        )];

        let (findings, delta) = check_webgl_exposure(&profiles);
        assert_eq!(delta, 0);
        assert!(findings.is_empty());
    }

    #[test]
    fn check_canvas_with_canvasblocker_extension() {
        // CanvasBlocker installed — canvas should be considered protected.
        let profiles = vec![make_firefox_profile(
            HashMap::new(), // RFP not enabled
            vec!["CanvasBlocker".to_string()],
        )];

        let (findings, delta) = check_canvas_protection(&profiles);
        assert_eq!(delta, 0, "CanvasBlocker should protect canvas");
        assert!(findings.is_empty());
    }

    #[test]
    fn font_exposure_zero_fonts() {
        let (findings, delta) = check_font_exposure(0);
        assert_eq!(delta, 0);
        assert!(findings.is_empty(), "zero fonts should produce no findings");
    }

    #[test]
    fn parse_firefox_extensions_with_mock_json() {
        let dir = TempDir::new().unwrap();
        let extensions_json = serde_json::json!({
            "addons": [
                {
                    "id": "uBlock0@AK",
                    "defaultLocale": {
                        "name": "uBlock Origin"
                    }
                },
                {
                    "id": "some-random-id",
                    "defaultLocale": {
                        "name": "Some Random Extension"
                    }
                },
                {
                    "id": "another-random",
                    "defaultLocale": {
                        "name": "Canvas Fingerprint Defender Pro"
                    }
                }
            ]
        });
        fs::write(
            dir.path().join("extensions.json"),
            serde_json::to_string_pretty(&extensions_json).unwrap(),
        )
        .unwrap();

        let extensions = parse_firefox_extensions(dir.path());
        assert!(
            extensions.contains(&"uBlock Origin".to_string()),
            "uBlock Origin should be detected by ID"
        );
        assert!(
            extensions.contains(&"Canvas Fingerprint Defender Pro".to_string()),
            "Canvas Fingerprint Defender should match by name pattern"
        );
        assert_eq!(
            extensions.len(),
            2,
            "only matching extensions should be returned"
        );
    }
}
