mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct WebrtcModule;

#[async_trait]
impl Module for WebrtcModule {
    fn name(&self) -> &str {
        "webrtc"
    }

    fn display_name(&self) -> &str {
        "WebRTC IP Leak Detection"
    }

    fn description(&self) -> &str {
        "Detect WebRTC-based IP address leaks that bypass VPNs"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_webrtc(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Disable WebRTC in Firefox: about:config > media.peerconnection.enabled = false"
                    .to_string(),
                "Install 'WebRTC Leak Prevent' extension in Chrome".to_string(),
                "Brave: Settings > Privacy > WebRTC IP Handling Policy > Disable non-proxied UDP"
                    .to_string(),
                "Block UDP port 3478/19302 in firewall to prevent STUN queries".to_string(),
            ],
        })
    }
}
