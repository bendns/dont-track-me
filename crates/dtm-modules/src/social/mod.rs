mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct SocialModule;

#[async_trait]
impl Module for SocialModule {
    fn name(&self) -> &str {
        "social"
    }

    fn display_name(&self) -> &str {
        "Social Media Tracker Detection"
    }

    fn description(&self) -> &str {
        "Detect social media tracking pixels, cookies, and browser protection gaps"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_social(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Delete social tracker cookies from browser databases".to_string(),
                "Add social tracker domains to /etc/hosts blocklist".to_string(),
                "Switch to a tracker-blocking DNS resolver".to_string(),
                "Install uBlock Origin or Privacy Badger browser extension".to_string(),
            ],
        })
    }
}
