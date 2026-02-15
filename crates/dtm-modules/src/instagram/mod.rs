use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::checklist;
use dtm_core::models::{
    AuditOpts, AuditResult, Finding, PrivacyCheck, ProtectOpts, ProtectionResult, ThreatLevel,
};
use dtm_core::module_trait::Module;

pub struct InstagramModule;

impl InstagramModule {
    fn load_checks(&self) -> Vec<PrivacyCheck> {
        checklist::load_checks("instagram").unwrap_or_default()
    }
}

#[async_trait]
impl Module for InstagramModule {
    fn name(&self) -> &str {
        "instagram"
    }

    fn display_name(&self) -> &str {
        "Instagram Privacy"
    }

    fn description(&self) -> &str {
        "Interactive privacy checklist for Instagram settings"
    }

    async fn audit(&self, _opts: &AuditOpts) -> Result<AuditResult> {
        let checks = self.load_checks();
        if checks.is_empty() {
            return Ok(AuditResult {
                module_name: self.name().to_string(),
                score: 0,
                findings: vec![Finding {
                    title: "Checklist data not found".to_string(),
                    description: "Could not load Instagram privacy checks from shared/checklists/instagram.yaml".to_string(),
                    threat_level: ThreatLevel::Info,
                    remediation: "Ensure the shared/ directory is available.".to_string(),
                }],
                raw_data: HashMap::new(),
            });
        }

        // TODO: interactive prompting will be added in CLI phase
        let responses = HashMap::new();
        Ok(checklist::audit_checklist(self.name(), &checks, &responses))
    }

    async fn protect(&self, _opts: &ProtectOpts) -> Result<ProtectionResult> {
        let checks = self.load_checks();
        Ok(checklist::protect_checklist_module(
            self.name(),
            self.display_name(),
            &checks,
            None,
        ))
    }

    fn checklist(&self) -> Option<Vec<PrivacyCheck>> {
        Some(self.load_checks())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtm_core::module_trait::Module;
    use std::collections::HashSet;

    fn module() -> InstagramModule {
        InstagramModule
    }

    // -----------------------------------------------------------------------
    // 1. module_name
    // -----------------------------------------------------------------------
    #[test]
    fn module_name() {
        assert_eq!(module().name(), "instagram");
    }

    // -----------------------------------------------------------------------
    // 2. module_display_name
    // -----------------------------------------------------------------------
    #[test]
    fn module_display_name() {
        assert_eq!(module().display_name(), "Instagram Privacy");
    }

    // -----------------------------------------------------------------------
    // 3. checklist_loads
    // -----------------------------------------------------------------------
    #[test]
    fn checklist_loads() {
        let m = module();
        let checks = m.checklist();
        assert!(checks.is_some(), "Instagram checklist() should return Some");
    }

    // -----------------------------------------------------------------------
    // 4. checklist_has_checks
    // -----------------------------------------------------------------------
    #[test]
    fn checklist_has_checks() {
        let m = module();
        let checks = m.checklist().unwrap();
        assert!(
            checks.len() >= 10,
            "Instagram checklist should have at least 10 checks, got {}",
            checks.len()
        );
    }

    // -----------------------------------------------------------------------
    // 5. checks_have_unique_ids
    // -----------------------------------------------------------------------
    #[test]
    fn checks_have_unique_ids() {
        let m = module();
        let checks = m.checklist().unwrap();
        let ids: HashSet<&str> = checks.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids.len(),
            checks.len(),
            "All check IDs should be unique; found {} unique out of {}",
            ids.len(),
            checks.len()
        );
    }

    // -----------------------------------------------------------------------
    // 6. checks_cover_categories
    // -----------------------------------------------------------------------
    #[test]
    fn checks_cover_categories() {
        let m = module();
        let checks = m.checklist().unwrap();
        let categories: HashSet<&str> = checks.iter().map(|c| c.category.as_str()).collect();

        assert!(
            categories.contains("visibility"),
            "Should have 'visibility' category"
        );
        assert!(
            categories.contains("data_sharing"),
            "Should have 'data_sharing' category"
        );
        assert!(
            categories.contains("security"),
            "Should have 'security' category"
        );
    }

    // -----------------------------------------------------------------------
    // 7. educational_content_not_empty
    // -----------------------------------------------------------------------
    #[test]
    fn educational_content_not_empty() {
        let m = module();
        let content = m.educational_content();
        assert!(
            content.len() > 50,
            "Educational content should have substance, got {} bytes",
            content.len()
        );
        // Should not be the fallback "No educational content available" message
        assert!(
            !content.contains("No educational content available"),
            "Should load actual educational content, not fallback"
        );
    }

    // -----------------------------------------------------------------------
    // 8. audit_non_interactive_returns_result
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn audit_non_interactive_returns_result() {
        let m = module();
        let opts = AuditOpts {
            interactive: false,
            ..Default::default()
        };
        let result = m.audit(&opts).await.unwrap();
        assert_eq!(result.module_name, "instagram");
        // Non-interactive with no responses: all checks assumed unsafe
        assert!(!result.findings.is_empty());
        assert!(result.score <= 100);
    }

    // -----------------------------------------------------------------------
    // 9. all_checks_have_remediation
    // -----------------------------------------------------------------------
    #[test]
    fn all_checks_have_remediation() {
        let m = module();
        let checks = m.checklist().unwrap();
        for check in &checks {
            assert!(
                !check.remediation.is_empty(),
                "Check '{}' should have non-empty remediation",
                check.id
            );
        }
    }

    // -----------------------------------------------------------------------
    // 10. all_checks_have_valid_threat_level
    // -----------------------------------------------------------------------
    #[test]
    fn all_checks_have_valid_threat_level() {
        let m = module();
        let checks = m.checklist().unwrap();
        for check in &checks {
            // Verify threat_level is a valid variant by pattern matching
            match check.threat_level {
                ThreatLevel::Critical
                | ThreatLevel::High
                | ThreatLevel::Medium
                | ThreatLevel::Low
                | ThreatLevel::Info => {} // all valid
            }
        }
    }
}
