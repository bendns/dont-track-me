mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct EmailModule;

#[async_trait]
impl Module for EmailModule {
    fn name(&self) -> &str {
        "email"
    }

    fn display_name(&self) -> &str {
        "Email Tracking Pixel Detection"
    }

    fn description(&self) -> &str {
        "Detect and strip email tracking pixels in .eml files"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_email(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Disable remote image loading in your email client".to_string(),
                "Strip tracking pixels from downloaded .eml files".to_string(),
                "Use a privacy-focused email provider (ProtonMail, Tutanota)".to_string(),
                "Use an email alias service to hide your real address".to_string(),
            ],
        })
    }
}
