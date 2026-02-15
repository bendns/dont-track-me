use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::paths;

/// Tracker domain entry: domain -> category.
pub type TrackerDomains = HashMap<String, String>;

/// Load tracker domains from shared/tracker_domains.yaml.
/// Returns a flat map of domain -> category.
pub fn load_tracker_domains() -> Result<TrackerDomains> {
    let yaml = paths::load_shared_yaml("tracker_domains.yaml")
        .context("Failed to load shared/tracker_domains.yaml")?;

    let categories: HashMap<String, Vec<String>> =
        serde_yaml::from_str(&yaml).context("Failed to parse tracker_domains.yaml")?;

    let mut domains = TrackerDomains::new();
    for (category, domain_list) in categories {
        for domain in domain_list {
            domains.insert(domain, category.clone());
        }
    }
    Ok(domains)
}

/// A tracking SDK pattern for Mach-O binary analysis.
#[derive(Debug, Clone, Deserialize)]
pub struct TrackingSdkPattern {
    pub pattern: String,
    pub name: String,
    pub category: String,
}

/// Load tracking SDK patterns from shared/tracker_sdks.yaml.
pub fn load_tracking_sdks() -> Result<Vec<TrackingSdkPattern>> {
    let yaml = paths::load_shared_yaml("tracker_sdks.yaml")
        .context("Failed to load shared/tracker_sdks.yaml")?;

    #[derive(Deserialize)]
    struct SdkFile {
        sdks: Vec<TrackingSdkPattern>,
    }

    let file: SdkFile = serde_yaml::from_str(&yaml).context("Failed to parse tracker_sdks.yaml")?;
    Ok(file.sdks)
}

/// Load email tracker domains from shared/email_trackers.yaml.
pub fn load_email_trackers() -> Result<(Vec<String>, Vec<String>)> {
    let yaml = paths::load_shared_yaml("email_trackers.yaml")
        .context("Failed to load shared/email_trackers.yaml")?;

    #[derive(Deserialize)]
    struct EmailTrackerFile {
        domains: Vec<String>,
        tracking_path_patterns: Vec<String>,
    }

    let file: EmailTrackerFile =
        serde_yaml::from_str(&yaml).context("Failed to parse email_trackers.yaml")?;
    Ok((file.domains, file.tracking_path_patterns))
}

/// Social tracker domains organized by platform.
pub type SocialTrackerPlatforms = HashMap<String, Vec<String>>;

/// Load social tracker data from shared/social_trackers.yaml.
pub fn load_social_trackers() -> Result<SocialTrackerPlatforms> {
    let yaml = paths::load_shared_yaml("social_trackers.yaml")
        .context("Failed to load shared/social_trackers.yaml")?;

    #[derive(Deserialize)]
    struct SocialTrackerFile {
        platforms: SocialTrackerPlatforms,
    }

    let file: SocialTrackerFile =
        serde_yaml::from_str(&yaml).context("Failed to parse social_trackers.yaml")?;
    Ok(file.platforms)
}

/// Check if a domain matches any tracker domain (exact or suffix match).
pub fn match_tracker_domain(domain: &str, tracker_domains: &TrackerDomains) -> Option<String> {
    let domain = domain.trim_start_matches('.').to_ascii_lowercase();

    // Exact match
    if let Some(category) = tracker_domains.get(&domain) {
        return Some(category.clone());
    }

    // Suffix match: "ads.doubleclick.net" matches "doubleclick.net"
    for (tracker, category) in tracker_domains {
        if domain.len() > tracker.len() {
            let offset = domain.len() - tracker.len();
            if domain.as_bytes()[offset - 1] == b'.'
                && domain[offset..].eq_ignore_ascii_case(tracker)
            {
                return Some(category.clone());
            }
        }
    }

    None
}

/// Load a per-country YAML data file from shared/data/<module>/<country>.yaml.
pub fn load_country_data<T: serde::de::DeserializeOwned>(module: &str, country: &str) -> Result<T> {
    let relative = format!("data/{module}/{country}.yaml");
    let yaml =
        paths::load_shared_yaml(&relative).context(format!("Failed to load shared/{relative}"))?;
    serde_yaml::from_str(&yaml).context(format!("Failed to parse {relative}"))
}

/// Load a checklist YAML file from shared/checklists/<name>.yaml.
///
/// The YAML file is expected to have a top-level `checks:` key wrapping the array.
pub fn load_checklist(name: &str) -> Result<Vec<crate::models::PrivacyCheck>> {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ChecklistFile {
        checks: Vec<crate::models::PrivacyCheck>,
    }

    let relative = format!("checklists/{name}.yaml");
    let yaml =
        paths::load_shared_yaml(&relative).context(format!("Failed to load shared/{relative}"))?;

    // Try the wrapped format first (checks: [...]), fall back to bare array.
    if let Ok(file) = serde_yaml::from_str::<ChecklistFile>(&yaml) {
        return Ok(file.checks);
    }
    serde_yaml::from_str(&yaml).context(format!("Failed to parse {relative}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tracker_domains() -> TrackerDomains {
        let mut domains = TrackerDomains::new();
        domains.insert("doubleclick.net".to_string(), "advertising".to_string());
        domains.insert("facebook.com".to_string(), "social".to_string());
        domains.insert("analytics.google.com".to_string(), "analytics".to_string());
        domains
    }

    #[test]
    fn match_tracker_domain_exact_match() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain("doubleclick.net", &domains);
        assert_eq!(result, Some("advertising".to_string()));
    }

    #[test]
    fn match_tracker_domain_suffix_match() {
        let domains = sample_tracker_domains();
        // "ads.doubleclick.net" should match "doubleclick.net" via suffix
        let result = match_tracker_domain("ads.doubleclick.net", &domains);
        assert_eq!(result, Some("advertising".to_string()));
    }

    #[test]
    fn match_tracker_domain_deep_suffix_match() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain("pixel.tracking.facebook.com", &domains);
        assert_eq!(result, Some("social".to_string()));
    }

    #[test]
    fn match_tracker_domain_no_match() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain("example.com", &domains);
        assert_eq!(result, None);
    }

    #[test]
    fn match_tracker_domain_no_partial_match() {
        let domains = sample_tracker_domains();
        // "notdoubleclick.net" should NOT match "doubleclick.net"
        // because offset - 1 byte is not '.'
        let result = match_tracker_domain("notdoubleclick.net", &domains);
        assert_eq!(result, None);
    }

    #[test]
    fn match_tracker_domain_case_insensitive() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain("DOUBLECLICK.NET", &domains);
        assert_eq!(result, Some("advertising".to_string()));
    }

    #[test]
    fn match_tracker_domain_case_insensitive_suffix() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain("Ads.DoubleClick.Net", &domains);
        assert_eq!(result, Some("advertising".to_string()));
    }

    #[test]
    fn match_tracker_domain_strips_leading_dot() {
        let domains = sample_tracker_domains();
        let result = match_tracker_domain(".doubleclick.net", &domains);
        assert_eq!(result, Some("advertising".to_string()));
    }

    #[test]
    fn test_load_tracker_domains() {
        // Only run if shared/ directory is available (dev mode)
        if crate::paths::shared_dir()
            .join("tracker_domains.yaml")
            .exists()
        {
            let domains = load_tracker_domains().expect("load tracker domains");
            assert!(
                !domains.is_empty(),
                "tracker_domains should contain entries"
            );
            // Should contain well-known tracker domains
            let has_known = domains.keys().any(|d| {
                d.contains("doubleclick") || d.contains("facebook") || d.contains("google")
            });
            assert!(
                has_known,
                "Should contain at least one known tracker domain"
            );
        }
    }

    #[test]
    fn test_load_social_trackers() {
        if crate::paths::shared_dir()
            .join("social_trackers.yaml")
            .exists()
        {
            let platforms = load_social_trackers().expect("load social trackers");
            assert!(
                !platforms.is_empty(),
                "social_trackers should contain platform entries"
            );
            // Should have at least one known platform
            let has_platform = platforms.keys().any(|p| {
                let lower = p.to_lowercase();
                lower.contains("facebook")
                    || lower.contains("meta")
                    || lower.contains("google")
                    || lower.contains("twitter")
                    || lower.contains("tiktok")
            });
            assert!(
                has_platform,
                "Should contain at least one known social platform, got keys: {:?}",
                platforms.keys().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn test_load_tracker_cookies() {
        // Verify the tracker_cookies.yaml is loadable if present
        if crate::paths::shared_dir()
            .join("tracker_cookies.yaml")
            .exists()
        {
            let yaml = crate::paths::load_shared_yaml("tracker_cookies.yaml")
                .expect("load tracker_cookies.yaml");
            assert!(!yaml.is_empty(), "tracker_cookies.yaml should not be empty");
            // Should parse as valid YAML
            let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&yaml);
            assert!(parsed.is_ok(), "tracker_cookies.yaml should be valid YAML");
        }
    }

    #[test]
    fn test_load_email_trackers() {
        if crate::paths::shared_dir()
            .join("email_trackers.yaml")
            .exists()
        {
            let (domains, patterns) = load_email_trackers().expect("load email trackers");
            assert!(
                !domains.is_empty(),
                "email tracker domains should not be empty"
            );
            assert!(
                !patterns.is_empty(),
                "email tracker path patterns should not be empty"
            );
        }
    }
}
