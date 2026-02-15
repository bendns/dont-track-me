mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct CertificatesModule;

#[async_trait]
impl Module for CertificatesModule {
    fn name(&self) -> &str {
        "certificates"
    }

    fn display_name(&self) -> &str {
        "TLS Certificate Trust Audit"
    }

    fn description(&self) -> &str {
        "Audit system certificate trust stores for expired, weak, or suspicious CAs"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_certificates(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Enforce TLS 1.2+ minimum: disable TLS 1.0/1.1 in browser and OS settings"
                    .to_string(),
                "Remove suspicious/distrusted CAs from system trust store".to_string(),
                "Enable Certificate Transparency monitoring for your domains (e.g., crt.sh)"
                    .to_string(),
                "Use a browser with built-in CT enforcement (Chrome, Firefox)".to_string(),
                "Pin certificates for critical services using HPKP alternatives or local config"
                    .to_string(),
                "Regularly audit trust store for newly added or unexpected CAs".to_string(),
            ],
        })
    }
}
