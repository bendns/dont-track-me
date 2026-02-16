use std::path::PathBuf;

/// Which OS we're running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOS,
    Linux,
    Windows,
    Other,
}

/// Detect the current platform at runtime.
pub fn current_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Other
    }
}

/// Get the user's home directory.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .ok()
}

/// Get the user's config directory.
pub fn config_dir() -> Option<PathBuf> {
    match current_platform() {
        Platform::MacOS | Platform::Linux => home_dir().map(|h| h.join(".config")),
        Platform::Windows => std::env::var("APPDATA").map(PathBuf::from).ok(),
        Platform::Other => home_dir().map(|h| h.join(".config")),
    }
}

/// Get the user's data directory (for caches, databases, etc.).
pub fn data_dir() -> Option<PathBuf> {
    match current_platform() {
        Platform::MacOS | Platform::Linux => home_dir().map(|h| h.join(".local").join("share")),
        Platform::Windows => std::env::var("LOCALAPPDATA").map(PathBuf::from).ok(),
        Platform::Other => home_dir().map(|h| h.join(".local").join("share")),
    }
}

/// Check if a command is available in PATH.
pub fn command_exists(name: &str) -> bool {
    let cmd = if cfg!(target_os = "windows") {
        "where"
    } else {
        "which"
    };
    std::process::Command::new(cmd)
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_platform_returns_macos_on_macos() {
        // This test is compiled on macOS, so it should return MacOS
        #[cfg(target_os = "macos")]
        assert_eq!(current_platform(), Platform::MacOS);

        #[cfg(target_os = "linux")]
        assert_eq!(current_platform(), Platform::Linux);

        #[cfg(target_os = "windows")]
        assert_eq!(current_platform(), Platform::Windows);
    }

    #[test]
    fn home_dir_returns_some() {
        // On typical systems HOME (unix) or USERPROFILE (windows) is set
        let home = home_dir();
        assert!(
            home.is_some(),
            "home_dir() should return Some on typical systems"
        );
        let path = home.unwrap();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn config_dir_returns_some() {
        let dir = config_dir();
        assert!(
            dir.is_some(),
            "config_dir() should return Some on typical systems"
        );
    }

    #[test]
    fn data_dir_returns_some() {
        let dir = data_dir();
        assert!(
            dir.is_some(),
            "data_dir() should return Some on typical systems"
        );
    }

    #[test]
    fn command_exists_returns_true_for_ls() {
        // "ls" should exist on macOS and Linux
        #[cfg(not(target_os = "windows"))]
        assert!(command_exists("ls"), "ls should exist on unix systems");

        // "cmd" should exist on Windows
        #[cfg(target_os = "windows")]
        assert!(command_exists("cmd"), "cmd should exist on windows");
    }

    #[test]
    fn command_exists_returns_false_for_nonexistent() {
        assert!(
            !command_exists("nonexistent_command_xyz_12345"),
            "nonexistent command should not be found"
        );
    }

    #[test]
    fn test_current_platform_is_supported() {
        let platform = current_platform();
        // Should be one of the known variants (not Other on our supported targets)
        assert!(
            matches!(
                platform,
                Platform::MacOS | Platform::Linux | Platform::Windows
            ),
            "Expected a known platform, got: {platform:?}"
        );
    }

    #[test]
    fn test_home_dir_is_absolute() {
        let home = home_dir();
        assert!(home.is_some(), "home_dir should return Some");
        let path = home.unwrap();
        assert!(
            path.is_absolute(),
            "home_dir should return an absolute path, got: {}",
            path.display()
        );
    }

    #[test]
    fn test_run_command_success() {
        // Running "echo hello" should succeed
        let output = std::process::Command::new("echo")
            .arg("hello")
            .output()
            .expect("echo should execute");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.trim() == "hello", "Expected 'hello', got: {stdout}");
    }

    #[test]
    fn test_run_command_failure() {
        // Running a non-existent command should fail gracefully
        let result = std::process::Command::new("nonexistent_binary_xyz_12345").output();
        assert!(
            result.is_err(),
            "Non-existent command should return an error"
        );
    }
}
