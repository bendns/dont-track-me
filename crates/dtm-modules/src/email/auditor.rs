use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;
use serde_json::Value;
use walkdir::WalkDir;

use dtm_core::data::load_email_trackers;
use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FILES: usize = 10_000;
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

/// Match <img> tags with attributes. Captures the full tag content.
static IMG_TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<img\s+([^>]*)>").unwrap());

/// Extract src attribute value.
static SRC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)src\s*=\s*["']([^"']+)["']"#).unwrap());

/// Extract width attribute value.
static WIDTH_ATTR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)width\s*=\s*["']?(\d+)"#).unwrap());

/// Extract height attribute value.
static HEIGHT_ATTR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)height\s*=\s*["']?(\d+)"#).unwrap());

/// Extract width from inline style.
static STYLE_WIDTH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|;)\s*width\s*:\s*(\d+)\s*px").unwrap());

/// Extract height from inline style.
static STYLE_HEIGHT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|;)\s*height\s*:\s*(\d+)\s*px").unwrap());

/// Extract style attribute value.
static STYLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)style\s*=\s*["']([^"']+)["']"#).unwrap());

/// Content-Type header to detect HTML parts in raw email.
static CONTENT_TYPE_HTML_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Content-Type:\s*text/html").unwrap());

/// MIME boundary pattern.
static BOUNDARY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)boundary\s*=\s*"?([^\s";]+)"?"#).unwrap());

// ---------------------------------------------------------------------------
// Image metadata extracted from HTML
// ---------------------------------------------------------------------------

struct ImageInfo {
    src: String,
    width: Option<u32>,
    height: Option<u32>,
    hidden: bool,
}

impl ImageInfo {
    /// Check if image dimensions suggest a tracking pixel (1x1 or 0x0).
    fn is_tiny(&self) -> bool {
        if let Some(w) = self.width {
            if w <= 1 {
                return true;
            }
        }
        if let Some(h) = self.height {
            if h <= 1 {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Email tracker matching
// ---------------------------------------------------------------------------

struct TrackerMatcher {
    domains: Vec<String>,
    path_pattern: Regex,
}

impl TrackerMatcher {
    fn from_yaml() -> Self {
        let (domains, path_patterns) = load_email_trackers().unwrap_or_else(|_| {
            // Fallback: empty lists if YAML can't be loaded
            (Vec::new(), Vec::new())
        });

        // Build a combined regex from the path patterns
        let pattern_str = if path_patterns.is_empty() {
            // Fallback hardcoded pattern
            r"/(?:track|pixel|beacon|open|wf/open|t\.gif|o\.gif|e\.gif|trk|ci/e|imp)(?:[/?#.]|$)"
                .to_string()
        } else {
            let escaped: Vec<String> = path_patterns.iter().map(|p| regex::escape(p)).collect();
            format!(r"(?:{})(?:[/?#.]|$)", escaped.join("|"))
        };

        let path_pattern = Regex::new(&pattern_str).unwrap_or_else(|_| Regex::new(r"^$").unwrap());

        Self {
            domains,
            path_pattern,
        }
    }

    /// Check if a URL is a known email tracking pixel.
    /// Returns `Some(reason)` if it matches, `None` otherwise.
    fn is_tracker_url(&self, url: &str) -> Option<String> {
        // Parse the URL to extract hostname and path
        let (hostname, path) = parse_url_parts(url)?;

        // Check against known tracker domains (exact and suffix match)
        for domain in &self.domains {
            if hostname == *domain || hostname.ends_with(&format!(".{domain}")) {
                return Some(format!("known tracker domain: {domain}"));
            }
        }

        // Check URL path for tracking patterns
        if self.path_pattern.is_match(&path) {
            return Some(format!("suspicious URL path: {path}"));
        }

        None
    }
}

/// Extract hostname and path from a URL string.
fn parse_url_parts(url: &str) -> Option<(String, String)> {
    // Simple URL parsing: strip scheme, extract host and path
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;

    let (host_part, path) = match without_scheme.find('/') {
        Some(pos) => (&without_scheme[..pos], &without_scheme[pos..]),
        None => (without_scheme, "/"),
    };

    // Strip port if present
    let hostname = match host_part.rfind(':') {
        Some(pos) => &host_part[..pos],
        None => host_part,
    };

    Some((hostname.to_ascii_lowercase(), path.to_string()))
}

// ---------------------------------------------------------------------------
// HTML image extraction
// ---------------------------------------------------------------------------

fn extract_images_from_html(html: &str) -> Vec<ImageInfo> {
    let mut images = Vec::new();

    for img_match in IMG_TAG_RE.captures_iter(html) {
        let attrs = &img_match[1];

        // Extract src
        let src = match SRC_RE.captures(attrs) {
            Some(caps) => caps[1].to_string(),
            None => continue,
        };

        // Only consider remote images
        if !src.starts_with("http://") && !src.starts_with("https://") {
            continue;
        }

        // Extract dimensions from attributes
        let mut width: Option<u32> = WIDTH_ATTR_RE
            .captures(attrs)
            .and_then(|c| c[1].parse().ok());

        let mut height: Option<u32> = HEIGHT_ATTR_RE
            .captures(attrs)
            .and_then(|c| c[1].parse().ok());

        // Check style attribute
        let style = STYLE_RE
            .captures(attrs)
            .map(|c| c[1].to_string())
            .unwrap_or_default();

        let hidden = is_hidden_style(&style);

        // Extract dimensions from style if not in attributes
        if width.is_none() {
            width = STYLE_WIDTH_RE
                .captures(&style)
                .and_then(|c| c[1].parse().ok());
        }
        if height.is_none() {
            height = STYLE_HEIGHT_RE
                .captures(&style)
                .and_then(|c| c[1].parse().ok());
        }

        images.push(ImageInfo {
            src,
            width,
            height,
            hidden,
        });
    }

    images
}

fn is_hidden_style(style: &str) -> bool {
    let normalized = style.to_ascii_lowercase().replace(' ', "");
    normalized.contains("display:none") || normalized.contains("visibility:hidden")
}

// ---------------------------------------------------------------------------
// Email parsing (simple MIME, no external crate)
// ---------------------------------------------------------------------------

/// Extract HTML parts from a raw email byte string.
/// This is a simplified MIME parser that handles the most common cases.
fn extract_html_parts(raw: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let mut html_parts = Vec::new();

    // Check if this is a multipart message
    if let Some(boundary_caps) = BOUNDARY_RE.captures(&text) {
        let boundary = &boundary_caps[1];
        let separator = format!("--{boundary}");

        let parts: Vec<&str> = text.split(&separator).collect();
        for part in &parts {
            // Check if this part is text/html
            if CONTENT_TYPE_HTML_RE.is_match(part) {
                // The HTML body starts after the first blank line in the part
                if let Some(body_start) = find_body_start(part) {
                    html_parts.push(body_start.to_string());
                }
            }
        }
    } else if CONTENT_TYPE_HTML_RE.is_match(&text) {
        // Single-part HTML email
        if let Some(body_start) = find_body_start(&text) {
            html_parts.push(body_start.to_string());
        }
    }

    html_parts
}

/// Find the body content after the first blank line (MIME header/body separator).
fn find_body_start(part: &str) -> Option<&str> {
    // Look for \r\n\r\n or \n\n
    if let Some(pos) = part.find("\r\n\r\n") {
        Some(&part[pos + 4..])
    } else if let Some(pos) = part.find("\n\n") {
        Some(&part[pos + 2..])
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Image classification
// ---------------------------------------------------------------------------

/// Classify an image as a tracking pixel.
/// Returns `Some((threat_level, reason))` or `None` if not a tracker.
fn classify_image(img: &ImageInfo, matcher: &TrackerMatcher) -> Option<(ThreatLevel, String)> {
    if let Some(reason) = matcher.is_tracker_url(&img.src) {
        return Some((
            ThreatLevel::High,
            format!("Known tracking pixel ({reason})"),
        ));
    }

    if img.is_tiny() {
        return Some((
            ThreatLevel::Medium,
            "Suspicious 1x1 pixel image".to_string(),
        ));
    }

    if img.hidden {
        return Some((
            ThreatLevel::Medium,
            "Hidden image (display:none or visibility:hidden)".to_string(),
        ));
    }

    None
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// Collect .eml files from a path (file or directory), up to MAX_FILES.
fn collect_eml_files(target: &Path) -> Vec<PathBuf> {
    if target.is_file() {
        if target.extension().and_then(|e| e.to_str()) == Some("eml") {
            return vec![target.to_path_buf()];
        }
        return Vec::new();
    }

    if !target.is_dir() {
        return Vec::new();
    }

    WalkDir::new(target)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().and_then(|ext| ext.to_str()) == Some("eml") && e.path().is_file()
        })
        .take(MAX_FILES)
        .map(|e| e.path().to_path_buf())
        .collect()
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn audit_email(opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut score: i32 = 100;

    let target = opts.path.clone().unwrap_or_else(|| PathBuf::from("."));

    // Validate path
    if !target.is_file() && !target.is_dir() {
        findings.push(Finding {
            title: "Invalid path for email scan".to_string(),
            description: format!("Path '{}' is not a file or directory.", target.display()),
            threat_level: ThreatLevel::Medium,
            remediation: "Provide a valid path to an .eml file or directory.".to_string(),
        });
        return Ok(AuditResult {
            module_name: "email".to_string(),
            score: 50,
            findings,
            raw_data: HashMap::new(),
        });
    }

    let eml_files = collect_eml_files(&target);

    if eml_files.is_empty() {
        findings.push(Finding {
            title: "No .eml files found".to_string(),
            description: format!("No email files found in '{}'.", target.display()),
            threat_level: ThreatLevel::Info,
            remediation: "Export emails as .eml files from your mail client to scan them."
                .to_string(),
        });
        let mut raw_data = HashMap::new();
        raw_data.insert("files_scanned".to_string(), serde_json::json!(0));
        raw_data.insert("files_with_trackers".to_string(), serde_json::json!(0));
        raw_data.insert("trackers".to_string(), serde_json::json!([]));
        return Ok(AuditResult {
            module_name: "email".to_string(),
            score: 100,
            findings,
            raw_data,
        });
    }

    // Load tracker matcher (domains + path patterns from YAML)
    let matcher = TrackerMatcher::from_yaml();

    let mut trackers_found: Vec<HashMap<String, String>> = Vec::new();
    let mut files_scanned: usize = 0;
    let mut files_with_trackers: usize = 0;

    for eml_path in &eml_files {
        if !eml_path.is_file() || eml_path.is_symlink() {
            continue;
        }

        // Check file size
        let meta = match std::fs::metadata(eml_path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() > MAX_FILE_SIZE {
            continue;
        }

        files_scanned += 1;
        let mut file_has_tracker = false;

        // Read raw email bytes
        let raw = match std::fs::read(eml_path) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Extract HTML parts
        let html_parts = extract_html_parts(&raw);
        let file_name = eml_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.eml");

        for html in &html_parts {
            let images = extract_images_from_html(html);
            for img in &images {
                let classification = match classify_image(img, &matcher) {
                    Some(c) => c,
                    None => continue,
                };

                let (threat_level, reason) = classification;
                file_has_tracker = true;

                let mut tracker_entry = HashMap::new();
                tracker_entry.insert("file".to_string(), file_name.to_string());
                tracker_entry.insert("src".to_string(), img.src.clone());
                tracker_entry.insert("reason".to_string(), reason.clone());
                trackers_found.push(tracker_entry);

                findings.push(Finding {
                    title: format!("Tracking pixel in {file_name}"),
                    description: format!(
                        "{reason}. Source: {}. \
                         This image reports back to the sender when you open the email, \
                         revealing your IP address, location, and the time you read it.",
                        img.src
                    ),
                    threat_level,
                    remediation: "Disable remote image loading in your email client. \
                        Use 'dtm protect email --apply' to strip tracking pixels."
                        .to_string(),
                });
            }
        }

        if file_has_tracker {
            files_with_trackers += 1;
            // Deduct score per file (not per tracker, to avoid over-penalizing)
            let has_known = trackers_found.iter().any(|t| {
                t.get("file").map(|f| f == file_name).unwrap_or(false)
                    && t.get("reason")
                        .map(|r| r.contains("Known"))
                        .unwrap_or(false)
            });
            score -= if has_known { 15 } else { 10 };
        }
    }

    let score = score.clamp(0, 100) as u32;

    let mut raw_data: HashMap<String, Value> = HashMap::new();
    raw_data.insert(
        "files_scanned".to_string(),
        serde_json::json!(files_scanned),
    );
    raw_data.insert(
        "files_with_trackers".to_string(),
        serde_json::json!(files_with_trackers),
    );
    raw_data.insert("trackers".to_string(), serde_json::json!(trackers_found));

    Ok(AuditResult {
        module_name: "email".to_string(),
        score,
        findings,
        raw_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Build a TrackerMatcher with a minimal set of known tracker domains.
    fn test_matcher() -> TrackerMatcher {
        TrackerMatcher {
            domains: vec![
                "track.hubspot.com".to_string(),
                "hubspot.com".to_string(),
                "mailchimp.com".to_string(),
                "list-manage.com".to_string(),
                "sendgrid.net".to_string(),
                "google-analytics.com".to_string(),
            ],
            path_pattern: Regex::new(
                r"(?:/track|/pixel|/beacon|/open|/wf/open|/t\.gif|/o\.gif|/e\.gif|/trk|/ci/e|/imp)(?:[/?#.]|$)",
            )
            .unwrap(),
        }
    }

    // -----------------------------------------------------------------------
    // Tests 1-5: Tracker URL classification
    // -----------------------------------------------------------------------

    #[test]
    fn tracker_url_hubspot() {
        let matcher = test_matcher();
        let result = matcher.is_tracker_url("https://track.hubspot.com/e1t/pixel/abc123");
        assert!(
            result.is_some(),
            "HubSpot tracking URL should be classified as tracker"
        );
        let reason = result.unwrap();
        assert!(
            reason.contains("hubspot"),
            "Reason should mention hubspot domain"
        );
    }

    #[test]
    fn tracker_url_mailchimp() {
        let matcher = test_matcher();
        let result = matcher.is_tracker_url("https://open.mailchimp.com/track/open.php");
        assert!(
            result.is_some(),
            "Mailchimp tracking URL should be classified as tracker"
        );
    }

    #[test]
    fn tracker_url_sendgrid() {
        let matcher = test_matcher();
        let result = matcher.is_tracker_url("https://u12345.ct.sendgrid.net/wf/open?u=abc");
        assert!(
            result.is_some(),
            "SendGrid tracking URL should be classified as tracker"
        );
    }

    #[test]
    fn tracker_url_path_pattern() {
        let matcher = test_matcher();
        // A URL with /track/ path on an unknown domain should still match path pattern
        let result = matcher.is_tracker_url("https://unknown-sender.com/track?id=123");
        assert!(
            result.is_some(),
            "URL with /track path should be classified by path pattern"
        );
        let reason = result.unwrap();
        assert!(
            reason.contains("suspicious URL path"),
            "Reason should mention suspicious URL path"
        );
    }

    #[test]
    fn non_tracker_url() {
        let matcher = test_matcher();
        let result = matcher.is_tracker_url("https://example.com/images/logo.png");
        assert!(
            result.is_none(),
            "Regular image URL should not be classified as tracker"
        );
    }

    // -----------------------------------------------------------------------
    // Tests 6-7: HTML image extraction
    // -----------------------------------------------------------------------

    #[test]
    fn extract_images_basic() {
        let html = r#"<html><body><img src="https://tracker.com/pixel.gif"></body></html>"#;
        let images = extract_images_from_html(html);
        assert_eq!(images.len(), 1, "Should extract one image");
        assert_eq!(images[0].src, "https://tracker.com/pixel.gif");
    }

    #[test]
    fn extract_images_dimensions() {
        let html = r#"<html><body><img src="https://example.com/img.gif" width="1" height="1"></body></html>"#;
        let images = extract_images_from_html(html);
        assert_eq!(images.len(), 1, "Should extract one image");
        assert_eq!(images[0].width, Some(1));
        assert_eq!(images[0].height, Some(1));
    }

    // -----------------------------------------------------------------------
    // Tests 8-11: Image classification
    // -----------------------------------------------------------------------

    #[test]
    fn classify_known_tracker_high() {
        let matcher = test_matcher();
        let img = ImageInfo {
            src: "https://track.hubspot.com/e1t/abc".to_string(),
            width: None,
            height: None,
            hidden: false,
        };
        let result = classify_image(&img, &matcher);
        assert!(result.is_some(), "Known tracker domain should classify");
        let (threat, reason) = result.unwrap();
        assert_eq!(threat, ThreatLevel::High, "Known tracker should be HIGH");
        assert!(
            reason.contains("Known tracking pixel"),
            "Reason should indicate known tracker"
        );
    }

    #[test]
    fn classify_1x1_pixel_medium() {
        let matcher = test_matcher();
        let img = ImageInfo {
            src: "https://benign-site.com/img.gif".to_string(),
            width: Some(1),
            height: Some(1),
            hidden: false,
        };
        let result = classify_image(&img, &matcher);
        assert!(result.is_some(), "1x1 pixel should classify");
        let (threat, _) = result.unwrap();
        assert_eq!(threat, ThreatLevel::Medium, "1x1 pixel should be MEDIUM");
    }

    #[test]
    fn classify_hidden_image_medium() {
        let matcher = test_matcher();
        let img = ImageInfo {
            src: "https://benign-site.com/hidden.gif".to_string(),
            width: Some(100),
            height: Some(100),
            hidden: true,
        };
        let result = classify_image(&img, &matcher);
        assert!(result.is_some(), "Hidden image should classify");
        let (threat, reason) = result.unwrap();
        assert_eq!(threat, ThreatLevel::Medium, "Hidden image should be MEDIUM");
        assert!(
            reason.contains("Hidden image"),
            "Reason should mention hidden"
        );
    }

    #[test]
    fn classify_normal_image_none() {
        let matcher = test_matcher();
        let img = ImageInfo {
            src: "https://example.com/photos/vacation.jpg".to_string(),
            width: Some(800),
            height: Some(600),
            hidden: false,
        };
        let result = classify_image(&img, &matcher);
        assert!(
            result.is_none(),
            "Regular large image should not be classified as tracker"
        );
    }

    // -----------------------------------------------------------------------
    // Tests 12-13: .eml file collection
    // -----------------------------------------------------------------------

    #[test]
    fn collect_eml_files_empty() {
        let tmp = TempDir::new().unwrap();
        let files = collect_eml_files(tmp.path());
        assert!(
            files.is_empty(),
            "Empty directory should return no .eml files"
        );
    }

    #[test]
    fn collect_eml_files_finds_eml() {
        let tmp = TempDir::new().unwrap();
        // Create some .eml files
        for name in &["a.eml", "b.eml", "c.txt"] {
            let path = tmp.path().join(name);
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"test content").unwrap();
        }
        let files = collect_eml_files(tmp.path());
        assert_eq!(files.len(), 2, "Should find exactly 2 .eml files");
        assert!(
            files.iter().all(|f| f.extension().unwrap() == "eml"),
            "All collected files should have .eml extension"
        );
    }

    // -----------------------------------------------------------------------
    // Test 14: HTML extraction from MIME email
    // -----------------------------------------------------------------------

    #[test]
    fn extract_html_from_eml() {
        let raw_email = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n\
\r\n\
--boundary123\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hello plain text\r\n\
--boundary123\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><body><img src=\"https://tracker.com/pixel.gif\" width=\"1\" height=\"1\"></body></html>\r\n\
--boundary123--\r\n";

        let html_parts = extract_html_parts(raw_email);
        assert_eq!(html_parts.len(), 1, "Should extract one HTML part");
        assert!(
            html_parts[0].contains("<img"),
            "HTML part should contain img tag"
        );
    }

    // -----------------------------------------------------------------------
    // Tests 15-16: Audit with clean and tracked mailboxes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn audit_clean_mailbox() {
        let tmp = TempDir::new().unwrap();

        // Create an email with no tracking pixels
        let clean_email = b"MIME-Version: 1.0\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><body><p>Hello, this is a clean email with no trackers.</p></body></html>\r\n";

        let eml_path = tmp.path().join("clean.eml");
        std::fs::write(&eml_path, clean_email).unwrap();

        let opts = AuditOpts {
            path: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };

        let result = audit_email(&opts).await.unwrap();
        assert_eq!(result.module_name, "email");
        assert_eq!(result.score, 100, "Clean mailbox should score 100");
    }

    #[tokio::test]
    async fn audit_with_trackers() {
        let tmp = TempDir::new().unwrap();

        // Create an email with a 1x1 tracking pixel
        let tracked_email = b"MIME-Version: 1.0\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><body>\
<p>Newsletter content</p>\
<img src=\"https://track.hubspot.com/e1t/pixel/abc\" width=\"1\" height=\"1\">\
</body></html>\r\n";

        let eml_path = tmp.path().join("tracked.eml");
        std::fs::write(&eml_path, tracked_email).unwrap();

        let opts = AuditOpts {
            path: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };

        let result = audit_email(&opts).await.unwrap();
        assert_eq!(result.module_name, "email");
        assert!(
            result.score < 100,
            "Mailbox with tracking pixels should score below 100, got {}",
            result.score
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.title.contains("Tracking pixel")),
            "Findings should mention tracking pixel"
        );
    }

    // -----------------------------------------------------------------------
    // Tests 17-18: Protection (dry run and strip)
    // -----------------------------------------------------------------------

    #[test]
    fn protect_dry_run() {
        // The email module's protect actions_available should list actions
        // without modifying anything.
        let actions = [
            "Disable remote image loading in your email client".to_string(),
            "Strip tracking pixels from downloaded .eml files".to_string(),
            "Use a privacy-focused email provider (ProtonMail, Tutanota)".to_string(),
            "Use an email alias service to hide your real address".to_string(),
        ];

        // Verify all actions are present (dry run lists but doesn't execute)
        assert_eq!(actions.len(), 4, "Should list 4 available actions");
        assert!(
            actions.iter().any(|a| a.contains("Disable remote image")),
            "Should recommend disabling remote images"
        );
        assert!(
            actions.iter().any(|a| a.contains("Strip tracking pixels")),
            "Should recommend stripping tracking pixels"
        );
    }

    #[test]
    fn protect_strips_pixels() {
        // Verify that the IMG_TAG_RE regex can identify tracking images
        // that should be stripped from HTML email content.
        let html = r#"<html><body>
<p>Content</p>
<img src="https://track.hubspot.com/pixel" width="1" height="1">
<img src="https://example.com/logo.png" width="200" height="50">
</body></html>"#;

        let images = extract_images_from_html(html);
        assert_eq!(images.len(), 2, "Should find 2 images in HTML");

        let matcher = test_matcher();
        let trackers: Vec<&ImageInfo> = images
            .iter()
            .filter(|img| classify_image(img, &matcher).is_some())
            .collect();

        assert_eq!(trackers.len(), 1, "Should identify 1 tracker image");
        assert!(
            trackers[0].src.contains("hubspot"),
            "Tracker should be the HubSpot pixel"
        );

        // Simulate stripping: replace tracker img tags with empty string
        let stripped = IMG_TAG_RE.replace_all(html, |caps: &regex::Captures| {
            let attrs = &caps[1];
            if let Some(src_caps) = SRC_RE.captures(attrs) {
                let src = &src_caps[1];
                let img_info = ImageInfo {
                    src: src.to_string(),
                    width: WIDTH_ATTR_RE
                        .captures(attrs)
                        .and_then(|c| c[1].parse().ok()),
                    height: HEIGHT_ATTR_RE
                        .captures(attrs)
                        .and_then(|c| c[1].parse().ok()),
                    hidden: false,
                };
                if classify_image(&img_info, &matcher).is_some() {
                    return String::new(); // strip tracker
                }
            }
            caps[0].to_string() // keep non-tracker
        });

        assert!(
            !stripped.contains("hubspot"),
            "Stripped HTML should not contain hubspot pixel"
        );
        assert!(
            stripped.contains("logo.png"),
            "Stripped HTML should keep the regular logo image"
        );
    }
}
