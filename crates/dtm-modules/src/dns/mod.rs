mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct DnsModule;

#[async_trait]
impl Module for DnsModule {
    fn name(&self) -> &str {
        "dns"
    }

    fn display_name(&self) -> &str {
        "DNS Privacy"
    }

    fn description(&self) -> &str {
        "Audits DNS configuration for privacy leaks and tracking exposure"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_dns(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Switch to a privacy-focused DNS resolver (e.g., NextDNS, AdGuard DNS)".to_string(),
                "Enable DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)".to_string(),
                "Disable mDNS/Bonjour if not needed".to_string(),
                "Use a VPN with built-in DNS leak protection".to_string(),
            ],
        })
    }
}
