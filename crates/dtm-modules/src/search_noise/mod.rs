mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct SearchNoiseModule;

#[async_trait]
impl Module for SearchNoiseModule {
    fn name(&self) -> &str {
        "search_noise"
    }

    fn display_name(&self) -> &str {
        "Search Query Obfuscation"
    }

    fn description(&self) -> &str {
        "Generate balanced search noise to prevent ideological profiling"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_search_noise(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        auditor::protect_search_noise(opts).await
    }
}
