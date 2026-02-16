mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct LocationModule;

#[async_trait]
impl Module for LocationModule {
    fn name(&self) -> &str {
        "location"
    }

    fn display_name(&self) -> &str {
        "Location Data Leakage Audit"
    }

    fn description(&self) -> &str {
        "Audit Wi-Fi history, location permissions, and timezone/VPN mismatches"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_location(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        let mut actions_available = Vec::new();

        // Platform-specific Wi-Fi and location actions
        #[cfg(target_os = "macos")]
        {
            actions_available.push(
                "Remove saved Wi-Fi networks that reveal locations: \
                 networksetup -removepreferredwirelessnetwork en0 <SSID>"
                    .to_string(),
            );
            actions_available
                .push("Disable Wi-Fi auto-join for public networks in System Settings".to_string());
            actions_available.push(
                "Review and revoke unnecessary Location Services permissions \
                 in System Settings > Privacy & Security > Location Services"
                    .to_string(),
            );
            actions_available.push(
                "Disable Significant Locations: Settings > Privacy > Location Services > \
                 System Services > Significant Locations"
                    .to_string(),
            );
        }

        #[cfg(target_os = "linux")]
        {
            actions_available
                .push("Remove saved Wi-Fi: nmcli connection delete <SSID>".to_string());
            actions_available.push(
                "Review location access in GNOME Settings > Privacy > Location Services"
                    .to_string(),
            );
        }

        #[cfg(target_os = "windows")]
        {
            actions_available
                .push("Remove saved Wi-Fi: netsh wlan delete profile name=<SSID>".to_string());
            actions_available.push(
                "Review location access in Settings > Privacy & Security > Location".to_string(),
            );
        }

        // Cross-platform actions
        actions_available
            .push("Set your timezone manually instead of using automatic detection".to_string());
        actions_available
            .push("Use a VPN that forces timezone alignment with exit node region".to_string());

        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available,
        })
    }
}
