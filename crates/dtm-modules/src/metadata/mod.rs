mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct MetadataModule;

#[async_trait]
impl Module for MetadataModule {
    fn name(&self) -> &str {
        "metadata"
    }

    fn display_name(&self) -> &str {
        "File Metadata Scanner"
    }

    fn description(&self) -> &str {
        "Detect and strip privacy-leaking metadata from images and documents"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_metadata(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Strip EXIF data (GPS, camera model, timestamps) from images".to_string(),
                "Strip PDF metadata (author, creator, timestamps)".to_string(),
                "Configure camera app to disable GPS tagging".to_string(),
                "Use metadata-stripping tools before sharing files".to_string(),
            ],
        })
    }
}
