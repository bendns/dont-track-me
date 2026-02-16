//! YouTube module — audit and diversify YouTube subscriptions.

pub mod auditor;
pub mod channels;
pub mod client;
pub mod protector;

use anyhow::Result;
use async_trait::async_trait;

use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct YoutubeModule;

#[async_trait]
impl Module for YoutubeModule {
    fn name(&self) -> &str {
        "youtube"
    }

    fn display_name(&self) -> &str {
        "YouTube Subscription Diversification"
    }

    fn description(&self) -> &str {
        "Audit subscription bias and diversify YouTube profile"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_youtube(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        protector::protect_youtube(opts).await
    }

    fn is_available(&self) -> bool {
        cfg!(feature = "oauth")
    }
}
