mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct CookiesModule;

#[async_trait]
impl Module for CookiesModule {
    fn name(&self) -> &str {
        "cookies"
    }

    fn display_name(&self) -> &str {
        "Browser Cookies"
    }

    fn description(&self) -> &str {
        "Analyzes browser cookie databases for tracking cookies"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_cookies(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Delete all known tracker cookies from browser databases".to_string(),
                "Block third-party cookies in browser settings".to_string(),
                "Enable Total Cookie Protection (Firefox) or similar partitioning".to_string(),
                "Install a cookie auto-delete extension".to_string(),
            ],
        })
    }
}
