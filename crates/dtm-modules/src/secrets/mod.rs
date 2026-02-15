mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct SecretsModule;

#[async_trait]
impl Module for SecretsModule {
    fn name(&self) -> &str {
        "secrets"
    }

    fn display_name(&self) -> &str {
        "Secret Scanning"
    }

    fn description(&self) -> &str {
        "Scans for exposed secrets, API keys, and credentials in files"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_secrets(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Review and rotate exposed credentials".to_string(),
                "Add secrets to .gitignore".to_string(),
                "Use environment variables instead of hardcoded secrets".to_string(),
                "Set up a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager)".to_string(),
            ],
        })
    }
}
