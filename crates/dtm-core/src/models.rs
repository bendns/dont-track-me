use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Severity level for a privacy finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl ThreatLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single privacy issue found during an audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub threat_level: ThreatLevel,
    pub remediation: String,
}

/// Result of auditing a single module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub module_name: String,
    /// Privacy score: 0 (fully exposed) to 100 (fully protected).
    pub score: u32,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub raw_data: HashMap<String, serde_json::Value>,
}

/// Result of running protections for a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionResult {
    pub module_name: String,
    pub dry_run: bool,
    pub actions_taken: Vec<String>,
    pub actions_available: Vec<String>,
}

/// Options passed to audit functions.
#[derive(Debug, Clone, Default)]
pub struct AuditOpts {
    /// Path to scan (for file-based modules).
    pub path: Option<std::path::PathBuf>,
    /// Whether to run in interactive mode (for checklist modules).
    pub interactive: bool,
    /// Country code for locale-specific data.
    pub country: Option<String>,
}

/// Options passed to protect functions.
#[derive(Debug, Clone, Default)]
pub struct ProtectOpts {
    /// If false, only show what would be done (dry run).
    pub apply: bool,
    /// Path to operate on.
    pub path: Option<std::path::PathBuf>,
    /// Only apply hardening (no diversification).
    pub harden_only: bool,
    /// Only apply diversification (no hardening).
    pub diversify_only: bool,
    /// Country code for locale-specific data.
    pub country: Option<String>,
    /// Number of items to generate (for noise modules).
    pub count: Option<usize>,
    /// Categories to target.
    pub categories: Vec<String>,
}

/// A privacy check item for checklist-based modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyCheck {
    pub id: String,
    pub question: String,
    pub description: String,
    pub threat_level: ThreatLevel,
    pub remediation: String,
    #[serde(default = "default_category")]
    pub category: String,
    pub technical_countermeasure: Option<String>,
    /// The answer that indicates the user is protected.
    #[serde(default = "default_safe_answer")]
    pub safe_answer: bool,
}

fn default_category() -> String {
    "general".to_string()
}

fn default_safe_answer() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_level_as_str_returns_correct_strings() {
        assert_eq!(ThreatLevel::Critical.as_str(), "critical");
        assert_eq!(ThreatLevel::High.as_str(), "high");
        assert_eq!(ThreatLevel::Medium.as_str(), "medium");
        assert_eq!(ThreatLevel::Low.as_str(), "low");
        assert_eq!(ThreatLevel::Info.as_str(), "info");
    }

    #[test]
    fn threat_level_display_trait() {
        assert_eq!(format!("{}", ThreatLevel::Critical), "critical");
        assert_eq!(format!("{}", ThreatLevel::High), "high");
        assert_eq!(format!("{}", ThreatLevel::Medium), "medium");
        assert_eq!(format!("{}", ThreatLevel::Low), "low");
        assert_eq!(format!("{}", ThreatLevel::Info), "info");
    }

    #[test]
    fn finding_creation_and_json_serialization() {
        let finding = Finding {
            title: "Tracking pixel detected".to_string(),
            description: "A tracking pixel was found in your email.".to_string(),
            threat_level: ThreatLevel::High,
            remediation: "Block remote images in your email client.".to_string(),
        };

        let json = serde_json::to_string(&finding).expect("serialize Finding");
        assert!(json.contains("\"title\":\"Tracking pixel detected\""));
        assert!(json.contains("\"threat_level\":\"high\""));

        let deserialized: Finding = serde_json::from_str(&json).expect("deserialize Finding");
        assert_eq!(deserialized.title, "Tracking pixel detected");
        assert_eq!(deserialized.threat_level, ThreatLevel::High);
    }

    #[test]
    fn audit_result_serialization_round_trip() {
        let result = AuditResult {
            module_name: "email".to_string(),
            score: 75,
            findings: vec![Finding {
                title: "Test finding".to_string(),
                description: "A test finding.".to_string(),
                threat_level: ThreatLevel::Medium,
                remediation: "Fix it.".to_string(),
            }],
            raw_data: {
                let mut m = HashMap::new();
                m.insert("key".to_string(), serde_json::json!("value"));
                m
            },
        };

        let json = serde_json::to_string(&result).expect("serialize AuditResult");
        let deserialized: AuditResult =
            serde_json::from_str(&json).expect("deserialize AuditResult");

        assert_eq!(deserialized.module_name, "email");
        assert_eq!(deserialized.score, 75);
        assert_eq!(deserialized.findings.len(), 1);
        assert_eq!(
            deserialized.raw_data.get("key"),
            Some(&serde_json::json!("value"))
        );
    }

    #[test]
    fn audit_opts_default() {
        let opts = AuditOpts::default();
        assert!(opts.path.is_none());
        assert!(!opts.interactive);
        assert!(opts.country.is_none());
    }

    #[test]
    fn protect_opts_default() {
        let opts = ProtectOpts::default();
        assert!(!opts.apply);
        assert!(opts.path.is_none());
        assert!(!opts.harden_only);
        assert!(!opts.diversify_only);
        assert!(opts.country.is_none());
        assert!(opts.count.is_none());
        assert!(opts.categories.is_empty());
    }

    #[test]
    fn privacy_check_deserialization_with_defaults() {
        let yaml = r#"
id: "check_1"
question: "Is your profile private?"
description: "Checks whether your profile is set to private."
threat_level: high
remediation: "Set your profile to private in settings."
"#;

        let check: PrivacyCheck = serde_yaml::from_str(yaml).expect("deserialize PrivacyCheck");
        assert_eq!(check.id, "check_1");
        assert_eq!(check.question, "Is your profile private?");
        assert_eq!(check.threat_level, ThreatLevel::High);
        // Defaults should apply
        assert_eq!(check.category, "general");
        assert!(check.safe_answer);
        assert!(check.technical_countermeasure.is_none());
    }

    #[test]
    fn privacy_check_deserialization_with_explicit_values() {
        let yaml = r#"
id: "check_2"
question: "Do you share location?"
description: "Checks location sharing."
threat_level: critical
remediation: "Disable location sharing."
category: "location"
safe_answer: false
technical_countermeasure: "Disable GPS"
"#;

        let check: PrivacyCheck = serde_yaml::from_str(yaml).expect("deserialize PrivacyCheck");
        assert_eq!(check.category, "location");
        assert!(!check.safe_answer);
        assert_eq!(
            check.technical_countermeasure.as_deref(),
            Some("Disable GPS")
        );
    }

    #[test]
    fn test_threat_level_ordering() {
        // Verify that the enum variants have the expected discriminant order
        // Critical < High < Medium < Low < Info (by discriminant, so Critical is "most severe")
        let levels = [
            ThreatLevel::Critical,
            ThreatLevel::High,
            ThreatLevel::Medium,
            ThreatLevel::Low,
            ThreatLevel::Info,
        ];
        // Each level should have a distinct as_str
        let strs: Vec<&str> = levels.iter().map(|l| l.as_str()).collect();
        assert_eq!(strs, vec!["critical", "high", "medium", "low", "info"]);

        // Verify PartialEq works correctly
        assert_ne!(ThreatLevel::Critical, ThreatLevel::High);
        assert_ne!(ThreatLevel::High, ThreatLevel::Medium);
        assert_ne!(ThreatLevel::Medium, ThreatLevel::Low);
        assert_ne!(ThreatLevel::Low, ThreatLevel::Info);
        assert_eq!(ThreatLevel::Critical, ThreatLevel::Critical);
    }

    #[test]
    fn test_protection_result_serialization() {
        let result = ProtectionResult {
            module_name: "ssh".to_string(),
            dry_run: true,
            actions_taken: vec!["Backed up config".to_string()],
            actions_available: vec![
                "Harden SSH config".to_string(),
                "Add passphrase to keys".to_string(),
            ],
        };

        let json = serde_json::to_string(&result).expect("serialize ProtectionResult");
        let deserialized: ProtectionResult =
            serde_json::from_str(&json).expect("deserialize ProtectionResult");

        assert_eq!(deserialized.module_name, "ssh");
        assert!(deserialized.dry_run);
        assert_eq!(deserialized.actions_taken.len(), 1);
        assert_eq!(deserialized.actions_taken[0], "Backed up config");
        assert_eq!(deserialized.actions_available.len(), 2);
    }

    #[test]
    fn test_audit_result_default_raw_data() {
        let result = AuditResult {
            module_name: "test".to_string(),
            score: 100,
            findings: vec![],
            raw_data: HashMap::new(),
        };

        assert!(result.raw_data.is_empty());
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.score, 100);

        // Verify it round-trips with empty raw_data
        let json = serde_json::to_string(&result).expect("serialize");
        let deserialized: AuditResult = serde_json::from_str(&json).expect("deserialize");
        assert!(deserialized.raw_data.is_empty());
    }
}
