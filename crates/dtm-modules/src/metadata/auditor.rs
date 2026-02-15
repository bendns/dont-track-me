use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FILES: usize = 10_000;

/// EXIF tags that reveal personal/identifying information.
const SENSITIVE_EXIF_TAGS: &[&str] = &[
    "GPSInfo",
    "GPSLatitude",
    "GPSLongitude",
    "GPSLatitudeRef",
    "GPSLongitudeRef",
    "Make",
    "Model",
    "Software",
    "DateTime",
    "DateTimeOriginal",
    "DateTimeDigitized",
    "Artist",
    "Copyright",
    "CameraOwnerName",
    "BodySerialNumber",
    "LensSerialNumber",
    "ImageUniqueID",
];

/// GPS-specific EXIF tags (subset of SENSITIVE_EXIF_TAGS).
const GPS_TAGS: &[&str] = &["GPSInfo", "GPSLatitude", "GPSLongitude"];

/// PDF metadata keys that reveal authorship and tool information.
const SENSITIVE_PDF_KEYS: &[&str] = &[
    "Author",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
    "Title",
    "Subject",
    "Keywords",
];

// ---------------------------------------------------------------------------
// EXIF scanning (gated behind metadata-parse feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "metadata-parse")]
fn scan_image_exif(file_path: &Path) -> Option<HashMap<String, String>> {
    use exif::{In, Reader, Tag};
    use std::fs::File;
    use std::io::BufReader;

    let file = File::open(file_path).ok()?;
    let mut reader = BufReader::new(file);
    let exif_data = Reader::new().read_from_container(&mut reader).ok()?;

    let mut metadata = HashMap::new();

    // Well-known tags to check
    let tags_to_check: &[(Tag, &str)] = &[
        (Tag::Make, "Make"),
        (Tag::Model, "Model"),
        (Tag::Software, "Software"),
        (Tag::DateTime, "DateTime"),
        (Tag::DateTimeOriginal, "DateTimeOriginal"),
        (Tag::DateTimeDigitized, "DateTimeDigitized"),
        (Tag::Artist, "Artist"),
        (Tag::Copyright, "Copyright"),
        (Tag::ImageUniqueID, "ImageUniqueID"),
        (Tag::GPSLatitudeRef, "GPSLatitudeRef"),
        (Tag::GPSLatitude, "GPSLatitude"),
        (Tag::GPSLongitudeRef, "GPSLongitudeRef"),
        (Tag::GPSLongitude, "GPSLongitude"),
        (Tag::BodySerialNumber, "BodySerialNumber"),
        (Tag::LensSerialNumber, "LensSerialNumber"),
        (Tag::CameraOwnerName, "CameraOwnerName"),
    ];

    for &(tag, name) in tags_to_check {
        if let Some(field) = exif_data.get_field(tag, In::PRIMARY) {
            metadata.insert(name.to_string(), field.display_value().to_string());
        }
    }

    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

#[cfg(not(feature = "metadata-parse"))]
fn scan_image_exif(_file_path: &Path) -> Option<HashMap<String, String>> {
    None
}

// ---------------------------------------------------------------------------
// PDF scanning (gated behind metadata-parse feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "metadata-parse")]
fn scan_pdf_metadata(file_path: &Path) -> Option<HashMap<String, String>> {
    use lopdf::Document;

    let doc = Document::load(file_path).ok()?;
    let mut metadata = HashMap::new();

    // lopdf exposes trailer dict with /Info reference
    if let Ok(info_ref) = doc.trailer.get(b"Info") {
        if let Ok(info_ref) = info_ref.as_reference() {
            if let Ok(info_dict) = doc.get_dictionary(info_ref) {
                for &key in SENSITIVE_PDF_KEYS {
                    if let Ok(value) = info_dict.get(key.as_bytes()) {
                        let val_str = match value {
                            lopdf::Object::String(bytes, _) => {
                                String::from_utf8_lossy(bytes).to_string()
                            }
                            other => format!("{other:?}"),
                        };
                        if !val_str.is_empty() {
                            metadata.insert(format!("/{key}"), val_str);
                        }
                    }
                }
            }
        }
    }

    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

#[cfg(not(feature = "metadata-parse"))]
fn scan_pdf_metadata(_file_path: &Path) -> Option<HashMap<String, String>> {
    None
}

// ---------------------------------------------------------------------------
// File type detection
// ---------------------------------------------------------------------------

/// Check if a file extension indicates a JPEG image.
fn is_jpeg(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            let lower = ext.to_ascii_lowercase();
            lower == "jpg" || lower == "jpeg"
        })
}

/// Check if a file extension indicates a supported image format.
fn is_image(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            let lower = ext.to_ascii_lowercase();
            matches!(
                lower.as_str(),
                "jpg" | "jpeg" | "png" | "tiff" | "tif" | "webp" | "heic"
            )
        })
}

/// Check if a file extension indicates a PDF document.
fn is_pdf(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pdf"))
}

// ---------------------------------------------------------------------------
// File enumeration
// ---------------------------------------------------------------------------

/// Collect files to scan, respecting MAX_FILES limit.
fn collect_files(target: &Path) -> Vec<PathBuf> {
    if target.is_file() {
        return vec![target.to_path_buf()];
    }

    let mut files = Vec::new();

    if !target.is_dir() {
        return files;
    }

    // Use walkdir for recursive traversal with bounded results
    for entry in walkdir::WalkDir::new(target)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .take(MAX_FILES)
    {
        files.push(entry.into_path());
    }

    files
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn audit_metadata(opts: &AuditOpts) -> Result<AuditResult> {
    let target = opts.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let target = Path::new(&target);

    if !target.exists() {
        let path_str = target.display().to_string();
        return Ok(AuditResult {
            module_name: "metadata".to_string(),
            score: 50,
            findings: vec![Finding {
                title: "Invalid path".to_string(),
                description: format!("Path '{path_str}' does not exist."),
                threat_level: ThreatLevel::Info,
                remediation: "Provide a valid file or directory path.".to_string(),
            }],
            raw_data: HashMap::new(),
        });
    }

    let mut findings: Vec<Finding> = Vec::new();
    let mut raw_data: Vec<serde_json::Value> = Vec::new();
    let mut files_scanned: usize = 0;
    let mut files_with_metadata: usize = 0;

    let files = collect_files(target);

    for file_path in &files {
        if is_image(file_path) || is_jpeg(file_path) {
            files_scanned += 1;

            if let Some(meta) = scan_image_exif(file_path) {
                let file_name = file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                raw_data.push(serde_json::json!({
                    "file": file_path.display().to_string(),
                    "type": "exif",
                    "metadata": meta,
                }));

                // Check for GPS data (critical)
                let has_gps = GPS_TAGS.iter().any(|tag| meta.contains_key(*tag));
                if has_gps {
                    files_with_metadata += 1;
                    findings.push(Finding {
                        title: format!("GPS location in {file_name}"),
                        description: format!(
                            "Image '{}' contains GPS coordinates. \
                             This reveals the exact location where the photo was taken.",
                            file_path.display()
                        ),
                        threat_level: ThreatLevel::Critical,
                        remediation:
                            "Strip EXIF data before sharing: dtm protect metadata --apply --path ."
                                .to_string(),
                    });
                } else {
                    // Check for other sensitive tags
                    let leaked_tags: Vec<&str> = SENSITIVE_EXIF_TAGS
                        .iter()
                        .filter(|tag| meta.contains_key(**tag))
                        .copied()
                        .collect();

                    if !leaked_tags.is_empty() {
                        files_with_metadata += 1;
                        findings.push(Finding {
                            title: format!("Device metadata in {file_name}"),
                            description: format!(
                                "Image '{}' contains identifying metadata: {}. \
                                 This can identify your camera, software, and when the photo was taken.",
                                file_path.display(),
                                leaked_tags.join(", ")
                            ),
                            threat_level: ThreatLevel::High,
                            remediation:
                                "Strip EXIF data before sharing: dtm protect metadata --apply --path ."
                                    .to_string(),
                        });
                    }
                }
            }
        } else if is_pdf(file_path) {
            files_scanned += 1;

            if let Some(meta) = scan_pdf_metadata(file_path) {
                let file_name = file_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                raw_data.push(serde_json::json!({
                    "file": file_path.display().to_string(),
                    "type": "pdf",
                    "metadata": meta,
                }));

                let leaked: Vec<String> = SENSITIVE_PDF_KEYS
                    .iter()
                    .map(|k| format!("/{k}"))
                    .filter(|k| meta.contains_key(k))
                    .collect();

                if !leaked.is_empty() {
                    files_with_metadata += 1;
                    findings.push(Finding {
                        title: format!("Author/tool metadata in {file_name}"),
                        description: format!(
                            "PDF '{}' contains: {}. \
                             This reveals who created the document and what software was used.",
                            file_path.display(),
                            leaked.join(", ")
                        ),
                        threat_level: ThreatLevel::Medium,
                        remediation: "Strip PDF metadata: dtm protect metadata --apply --path ."
                            .to_string(),
                    });
                }
            }
        }
    }

    // Scoring: more files with metadata = lower score
    let score = if files_scanned == 0 {
        findings.push(Finding {
            title: "No scannable files found".to_string(),
            description: format!("No image or PDF files found in '{}'.", target.display()),
            threat_level: ThreatLevel::Info,
            remediation: "Point to a directory with images or PDFs to scan.".to_string(),
        });
        100
    } else if files_with_metadata == 0 {
        100
    } else {
        let ratio = files_with_metadata as f64 / files_scanned as f64;
        (100.0 * (1.0 - ratio)).max(0.0) as u32
    };

    let mut result_raw = HashMap::new();
    result_raw.insert(
        "files_scanned".to_string(),
        serde_json::json!(files_scanned),
    );
    result_raw.insert(
        "files_with_metadata".to_string(),
        serde_json::json!(files_with_metadata),
    );
    result_raw.insert("details".to_string(), serde_json::json!(raw_data));

    Ok(AuditResult {
        module_name: "metadata".to_string(),
        score,
        findings,
        raw_data: result_raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // Scoring
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn empty_directory_perfect_score() {
        let tmp = TempDir::new().expect("create temp dir");
        let opts = AuditOpts {
            path: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };

        let result = audit_metadata(&opts).await.expect("audit empty dir");
        assert_eq!(result.module_name, "metadata");
        assert_eq!(
            result.score, 100,
            "empty directory (no scannable files) should yield score 100"
        );
    }

    // -----------------------------------------------------------------------
    // File collection
    // -----------------------------------------------------------------------

    #[test]
    fn collect_files_empty_dir() {
        let tmp = TempDir::new().expect("create temp dir");
        let files = collect_files(tmp.path());
        assert!(files.is_empty(), "empty directory should return no files");
    }

    #[test]
    fn collect_files_finds_images() {
        let tmp = TempDir::new().expect("create temp dir");

        // Create some .jpg files
        fs::write(tmp.path().join("photo1.jpg"), b"fake jpeg data").expect("write jpg");
        fs::write(tmp.path().join("photo2.jpeg"), b"fake jpeg data").expect("write jpeg");
        fs::write(tmp.path().join("image.png"), b"fake png data").expect("write png");

        let files = collect_files(tmp.path());
        assert!(
            files.len() >= 3,
            "should find at least 3 files, got {}",
            files.len()
        );

        // Verify image files are present
        let extensions: Vec<String> = files
            .iter()
            .filter_map(|f| {
                f.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_lowercase())
            })
            .collect();
        assert!(extensions.contains(&"jpg".to_string()));
        assert!(extensions.contains(&"jpeg".to_string()));
        assert!(extensions.contains(&"png".to_string()));
    }

    #[test]
    fn collect_files_finds_pdfs() {
        let tmp = TempDir::new().expect("create temp dir");

        // Create some .pdf files
        fs::write(tmp.path().join("doc1.pdf"), b"fake pdf data").expect("write pdf 1");
        fs::write(tmp.path().join("doc2.pdf"), b"fake pdf data").expect("write pdf 2");

        let files = collect_files(tmp.path());
        assert!(
            files.len() >= 2,
            "should find at least 2 files, got {}",
            files.len()
        );

        let pdf_count = files.iter().filter(|f| is_pdf(f)).count();
        assert_eq!(pdf_count, 2, "should find exactly 2 PDF files");
    }

    #[test]
    fn collect_files_respects_limit() {
        let tmp = TempDir::new().expect("create temp dir");

        // Create more than MAX_FILES files is impractical, but verify the
        // function caps at MAX_FILES by checking the constant is reasonable
        const {
            assert!(MAX_FILES > 0 && MAX_FILES <= 100_000);
        }

        // Create a few files and verify they are all collected (under the limit)
        for i in 0..5 {
            fs::write(tmp.path().join(format!("file{i}.txt")), b"data").expect("write file");
        }

        let files = collect_files(tmp.path());
        assert_eq!(
            files.len(),
            5,
            "should collect all 5 files when under MAX_FILES limit"
        );
        assert!(
            files.len() <= MAX_FILES,
            "collected files should not exceed MAX_FILES"
        );
    }

    // -----------------------------------------------------------------------
    // File type detection helpers
    // -----------------------------------------------------------------------

    #[test]
    fn is_jpeg_detects_jpg_extensions() {
        assert!(is_jpeg(Path::new("photo.jpg")));
        assert!(is_jpeg(Path::new("photo.jpeg")));
        assert!(is_jpeg(Path::new("photo.JPG")));
        assert!(is_jpeg(Path::new("photo.JPEG")));
        assert!(!is_jpeg(Path::new("photo.png")));
        assert!(!is_jpeg(Path::new("photo.pdf")));
    }

    #[test]
    fn is_image_detects_image_extensions() {
        assert!(is_image(Path::new("photo.jpg")));
        assert!(is_image(Path::new("photo.jpeg")));
        assert!(is_image(Path::new("photo.png")));
        assert!(is_image(Path::new("photo.tiff")));
        assert!(is_image(Path::new("photo.webp")));
        assert!(is_image(Path::new("photo.heic")));
        assert!(!is_image(Path::new("doc.pdf")));
        assert!(!is_image(Path::new("file.txt")));
    }

    #[test]
    fn is_pdf_detects_pdf_extension() {
        assert!(is_pdf(Path::new("doc.pdf")));
        assert!(is_pdf(Path::new("doc.PDF")));
        assert!(!is_pdf(Path::new("photo.jpg")));
        assert!(!is_pdf(Path::new("file.txt")));
    }

    // -----------------------------------------------------------------------
    // Audit on clean directory
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn audit_clean_directory() {
        let tmp = TempDir::new().expect("create temp dir");

        // Create image files without real EXIF metadata (just raw bytes)
        fs::write(tmp.path().join("clean.jpg"), b"not a real jpeg").expect("write clean jpg");
        fs::write(tmp.path().join("clean.pdf"), b"not a real pdf").expect("write clean pdf");

        let opts = AuditOpts {
            path: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };

        let result = audit_metadata(&opts).await.expect("audit clean dir");
        assert_eq!(result.module_name, "metadata");

        // Without the metadata-parse feature (or with fake files that have no
        // parseable metadata), the score should be high (100 = no metadata found)
        assert!(
            result.score >= 100,
            "directory with no parseable metadata should have a high score, got {}",
            result.score
        );
    }
}
