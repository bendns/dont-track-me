mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct SocialNoiseModule;

#[async_trait]
impl Module for SocialNoiseModule {
    fn name(&self) -> &str {
        "social_noise"
    }

    fn display_name(&self) -> &str {
        "Social Media Profile Obfuscation"
    }

    fn description(&self) -> &str {
        "Generate balanced follow lists to prevent social media profiling"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_social_noise(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        auditor::protect_social_noise(opts).await
    }
}
