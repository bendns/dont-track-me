mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct FingerprintModule;

#[async_trait]
impl Module for FingerprintModule {
    fn name(&self) -> &str {
        "fingerprint"
    }

    fn display_name(&self) -> &str {
        "Browser Fingerprint Detection"
    }

    fn description(&self) -> &str {
        "Detect browser fingerprinting exposure and anti-fingerprinting protections"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_fingerprint(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Enable privacy.resistFingerprinting in Firefox about:config".to_string(),
                "Disable WebGL (webgl.disabled = true) in Firefox about:config".to_string(),
                "Install anti-fingerprinting extensions (CanvasBlocker, uBlock Origin)".to_string(),
                "Restrict font visibility (layout.css.font-visibility.level = 1)".to_string(),
            ],
        })
    }
}
