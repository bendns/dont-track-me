use std::path::PathBuf;

use serde::Deserialize;

/// Application configuration loaded from ~/.config/dont-track-me/config.toml.
#[derive(Debug, Default, Deserialize)]
pub struct AppConfig {
    /// Default country code (e.g., "us", "fr").
    pub country: Option<String>,

    /// Per-platform OAuth settings.
    #[serde(default)]
    pub reddit: OAuthConfig,

    #[serde(default)]
    pub youtube: OAuthConfig,
}

/// OAuth configuration for a platform.
#[derive(Debug, Default, Deserialize)]
pub struct OAuthConfig {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Get the config file path.
pub fn config_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".config")
            .join("dont-track-me")
            .join("config.toml")
    } else if let Ok(appdata) = std::env::var("APPDATA") {
        PathBuf::from(appdata)
            .join("dont-track-me")
            .join("config.toml")
    } else {
        PathBuf::from("config.toml")
    }
}

/// Load the application config from the default path.
pub fn load_config() -> AppConfig {
    let path = config_path();
    if !path.exists() {
        return AppConfig::default();
    }

    match std::fs::read_to_string(&path) {
        Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
            log::warn!("Failed to parse config at {}: {e}", path.display());
            AppConfig::default()
        }),
        Err(e) => {
            log::warn!("Failed to read config at {}: {e}", path.display());
            AppConfig::default()
        }
    }
}

/// Detect the default country from locale or environment.
pub fn detect_country() -> String {
    // Check env var first
    if let Ok(country) = std::env::var("DTM_COUNTRY") {
        return country.to_lowercase();
    }

    // Check LANG env var (e.g., "en_US.UTF-8")
    if let Ok(lang) = std::env::var("LANG") {
        if let Some(country) = lang.split('_').nth(1) {
            let code = country.split('.').next().unwrap_or(country);
            if code.len() == 2 {
                return code.to_lowercase();
            }
        }
    }

    // Default to US
    "us".to_string()
}

/// Get OAuth client_id for a platform from config or environment.
pub fn get_client_id(platform: &str, config: &AppConfig) -> Option<String> {
    // Check env var first
    let env_key = format!("DTM_{}_CLIENT_ID", platform.to_uppercase());
    if let Ok(val) = std::env::var(&env_key) {
        return Some(val);
    }

    // Check config file
    match platform {
        "reddit" => config.reddit.client_id.clone(),
        "youtube" => config.youtube.client_id.clone(),
        _ => None,
    }
}

/// Get OAuth client_secret for a platform from config or environment.
pub fn get_client_secret(platform: &str, config: &AppConfig) -> Option<String> {
    let env_key = format!("DTM_{}_CLIENT_SECRET", platform.to_uppercase());
    if let Ok(val) = std::env::var(&env_key) {
        return Some(val);
    }

    match platform {
        "reddit" => config.reddit.client_secret.clone(),
        "youtube" => config.youtube.client_secret.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_path_returns_non_empty_path() {
        let path = config_path();
        assert!(!path.as_os_str().is_empty());
        // Should end with config.toml regardless of platform
        assert!(path.ends_with("config.toml"));
    }

    #[test]
    fn detect_country_returns_a_string() {
        let country = detect_country();
        assert!(!country.is_empty());
        // Should be lowercase
        assert_eq!(country, country.to_lowercase());
    }

    #[test]
    fn app_config_default_works() {
        let config = AppConfig::default();
        assert!(config.country.is_none());
        assert!(config.reddit.client_id.is_none());
        assert!(config.reddit.client_secret.is_none());
        assert!(config.youtube.client_id.is_none());
        assert!(config.youtube.client_secret.is_none());
    }

    #[test]
    fn get_client_id_returns_none_when_not_configured() {
        let config = AppConfig::default();
        // Use a platform name that won't have env vars set
        assert_eq!(get_client_id("nonexistent_platform_xyz", &config), None);
        // Default config has no reddit client_id
        // (only passes if DTM_REDDIT_CLIENT_ID env var is not set)
        if std::env::var("DTM_REDDIT_CLIENT_ID").is_err() {
            assert_eq!(get_client_id("reddit", &config), None);
        }
    }

    #[test]
    fn get_client_secret_returns_none_when_not_configured() {
        let config = AppConfig::default();
        assert_eq!(get_client_secret("nonexistent_platform_xyz", &config), None);
        if std::env::var("DTM_REDDIT_CLIENT_SECRET").is_err() {
            assert_eq!(get_client_secret("reddit", &config), None);
        }
    }

    #[test]
    fn load_config_returns_default_when_no_file() {
        // load_config should gracefully return defaults if config file doesn't exist
        let config = load_config();
        // We can't assert specific values since a real config might exist,
        // but it should not panic
        let _ = config.country;
    }

    #[test]
    fn app_config_deserializes_from_toml() {
        let toml_str = r#"
country = "fr"

[reddit]
client_id = "my_reddit_id"
client_secret = "my_reddit_secret"

[youtube]
client_id = "my_yt_id"
"#;

        let config: AppConfig = toml::from_str(toml_str).expect("parse toml");
        assert_eq!(config.country.as_deref(), Some("fr"));
        assert_eq!(config.reddit.client_id.as_deref(), Some("my_reddit_id"));
        assert_eq!(
            config.reddit.client_secret.as_deref(),
            Some("my_reddit_secret")
        );
        assert_eq!(config.youtube.client_id.as_deref(), Some("my_yt_id"));
        assert!(config.youtube.client_secret.is_none());
    }

    #[test]
    fn test_country_env_var_override() {
        // Save and set DTM_COUNTRY
        let prev = std::env::var("DTM_COUNTRY").ok();
        std::env::set_var("DTM_COUNTRY", "DE");

        let country = detect_country();
        assert_eq!(
            country, "de",
            "DTM_COUNTRY env var should override detection and be lowercased"
        );

        // Restore
        match prev {
            Some(val) => std::env::set_var("DTM_COUNTRY", val),
            None => std::env::remove_var("DTM_COUNTRY"),
        }
    }

    #[test]
    fn test_config_merge_defaults() {
        // A TOML with only country set should default the OAuth sections
        let toml_str = r#"
country = "jp"
"#;
        let config: AppConfig = toml::from_str(toml_str).expect("parse toml");
        assert_eq!(config.country.as_deref(), Some("jp"));
        // OAuth sections should use defaults (all None)
        assert!(config.reddit.client_id.is_none());
        assert!(config.reddit.client_secret.is_none());
        assert!(config.youtube.client_id.is_none());
        assert!(config.youtube.client_secret.is_none());
    }

    #[test]
    fn test_empty_config_file() {
        // An empty TOML string should parse successfully and return defaults
        let config: AppConfig = toml::from_str("").expect("empty toml should parse");
        assert!(config.country.is_none());
        assert!(config.reddit.client_id.is_none());
        assert!(config.youtube.client_id.is_none());
    }

    #[test]
    fn test_get_client_id_from_config() {
        let config = AppConfig {
            country: None,
            reddit: OAuthConfig {
                client_id: Some("reddit_id_123".to_string()),
                client_secret: None,
            },
            youtube: OAuthConfig {
                client_id: Some("yt_id_456".to_string()),
                client_secret: Some("yt_secret_789".to_string()),
            },
        };

        // Only test if env vars aren't set (to avoid interference)
        if std::env::var("DTM_REDDIT_CLIENT_ID").is_err() {
            assert_eq!(
                get_client_id("reddit", &config),
                Some("reddit_id_123".to_string())
            );
        }
        if std::env::var("DTM_YOUTUBE_CLIENT_ID").is_err() {
            assert_eq!(
                get_client_id("youtube", &config),
                Some("yt_id_456".to_string())
            );
        }
        if std::env::var("DTM_YOUTUBE_CLIENT_SECRET").is_err() {
            assert_eq!(
                get_client_secret("youtube", &config),
                Some("yt_secret_789".to_string())
            );
        }
    }

    #[test]
    fn test_config_path_ends_with_expected_components() {
        let path = config_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains("dont-track-me"),
            "Config path should contain 'dont-track-me': {path_str}"
        );
        assert!(
            path_str.ends_with("config.toml"),
            "Config path should end with config.toml: {path_str}"
        );
    }
}
