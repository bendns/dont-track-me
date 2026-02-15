use anyhow::Result;
use async_trait::async_trait;

use crate::models::{AuditOpts, AuditResult, PrivacyCheck, ProtectOpts, ProtectionResult};

/// Trait that all privacy audit modules must implement.
#[async_trait]
pub trait Module: Send + Sync {
    /// Internal name (e.g., "cookies", "dns").
    fn name(&self) -> &str;

    /// Human-readable display name (e.g., "Browser Cookies").
    fn display_name(&self) -> &str;

    /// Short description of what this module audits.
    fn description(&self) -> &str;

    /// Run a privacy audit and return findings with a score.
    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult>;

    /// Apply privacy protections (or show what would be done in dry-run mode).
    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult>;

    /// Load educational content from shared/content/<name>.md.
    fn educational_content(&self) -> String {
        crate::paths::load_educational_content(self.name())
    }

    /// Return interactive checklist items, if this is a checklist module.
    fn checklist(&self) -> Option<Vec<PrivacyCheck>> {
        None
    }

    /// Whether this module is available on the current platform.
    fn is_available(&self) -> bool {
        true
    }
}
