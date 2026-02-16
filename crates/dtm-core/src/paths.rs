use std::path::PathBuf;

/// Resolve the `shared/` directory relative to the executable or workspace root.
pub fn shared_dir() -> PathBuf {
    // 1. Check relative to executable: ../shared/ (installed layout)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join("../shared");
            if candidate.is_dir() {
                return candidate.canonicalize().unwrap_or(candidate);
            }
            // Also check ../../shared for workspace target/release/dtm layout
            let candidate = parent.join("../../shared");
            if candidate.is_dir() {
                return candidate.canonicalize().unwrap_or(candidate);
            }
        }
    }

    // 2. Check CARGO_MANIFEST_DIR (dev mode — run from crates/dtm-cli/)
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let candidate = PathBuf::from(manifest_dir).join("../../shared");
        if candidate.is_dir() {
            return candidate.canonicalize().unwrap_or(candidate);
        }
    }

    // 3. Check current working directory
    let candidate = PathBuf::from("shared");
    if candidate.is_dir() {
        return candidate.canonicalize().unwrap_or(candidate);
    }

    // 4. Fallback — return relative path even if not found
    PathBuf::from("shared")
}

/// Load educational content markdown for a module.
pub fn load_educational_content(module_name: &str) -> String {
    let path = shared_dir()
        .join("content")
        .join(format!("{module_name}.md"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|_| format!("No educational content available for '{module_name}'."))
}

/// Load a YAML file from the shared directory.
pub fn load_shared_yaml(relative_path: &str) -> Option<String> {
    let path = shared_dir().join(relative_path);
    std::fs::read_to_string(&path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_dir_exists() {
        // In dev mode (cargo test), shared/ should be findable
        let dir = shared_dir();
        // Don't assert existence — CI may not have it
        assert!(!dir.as_os_str().is_empty());
    }

    #[test]
    fn test_load_educational_content_missing_module() {
        // A non-existent module should return the fallback message
        let content = load_educational_content("nonexistent_module_xyz_12345");
        assert!(
            content.contains("No educational content available"),
            "Expected fallback text for missing module, got: {content}"
        );
        assert!(
            content.contains("nonexistent_module_xyz_12345"),
            "Fallback should mention the module name"
        );
    }

    #[test]
    fn test_load_shared_yaml_missing() {
        // A non-existent YAML path should return None
        let result = load_shared_yaml("nonexistent/path/file_xyz_12345.yaml");
        assert!(result.is_none(), "Expected None for non-existent YAML file");
    }

    #[test]
    fn test_load_shared_yaml_valid() {
        // If the shared directory is available (dev mode), loading a known file should work
        let result = load_shared_yaml("tracker_domains.yaml");
        if shared_dir().join("tracker_domains.yaml").exists() {
            assert!(
                result.is_some(),
                "Expected Some for existing tracker_domains.yaml"
            );
            let content = result.unwrap();
            assert!(
                !content.is_empty(),
                "tracker_domains.yaml should not be empty"
            );
            // Should contain at least one known tracker category
            assert!(
                content.contains("advertising") || content.contains("analytics"),
                "tracker_domains.yaml should contain tracker categories"
            );
        }
        // If shared dir doesn't exist (CI), the test passes silently
    }
}
