mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct HeadersModule;

#[async_trait]
impl Module for HeadersModule {
    fn name(&self) -> &str {
        "headers"
    }

    fn display_name(&self) -> &str {
        "HTTP Headers"
    }

    fn description(&self) -> &str {
        "Analyzes HTTP request headers for privacy-revealing information"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_headers(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Use a privacy-focused browser (Firefox, Brave, Tor Browser)".to_string(),
                "Install a User-Agent spoofing extension".to_string(),
                "Disable JavaScript to reduce fingerprinting surface".to_string(),
                "Use a VPN to mask your IP address".to_string(),
            ],
        })
    }
}
