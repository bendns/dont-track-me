//! Reddit module — audit and harden Reddit privacy settings.

pub mod auditor;
pub mod client;
pub mod protector;
pub mod subreddits;

use anyhow::Result;
use async_trait::async_trait;

use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct RedditModule;

#[async_trait]
impl Module for RedditModule {
    fn name(&self) -> &str {
        "reddit"
    }

    fn display_name(&self) -> &str {
        "Reddit Privacy Hardening"
    }

    fn description(&self) -> &str {
        "Audit and harden Reddit privacy settings, diversify subscriptions"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_reddit(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        protector::protect_reddit(opts).await
    }

    fn is_available(&self) -> bool {
        cfg!(feature = "oauth")
    }
}
