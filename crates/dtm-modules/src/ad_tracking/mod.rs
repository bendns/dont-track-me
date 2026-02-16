mod auditor;
pub mod brokers;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct AdTrackingModule;

#[async_trait]
impl Module for AdTrackingModule {
    fn name(&self) -> &str {
        "ad_tracking"
    }

    fn display_name(&self) -> &str {
        "Advertising Data Ecosystem Audit"
    }

    fn description(&self) -> &str {
        "Audit advertising ID exposure, browser ad-tracking settings, and data broker risks"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_ad_tracking(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        let country = opts.country.as_deref().unwrap_or("us");
        let broker_list = brokers::load_brokers(country);

        let mut actions_taken = Vec::new();
        let mut actions_available = Vec::new();

        #[cfg(target_os = "macos")]
        {
            actions_available.extend([
                "Disable IDFA: System Settings > Privacy & Security > Apple Advertising > \
                    turn off 'Personalised Ads'"
                    .to_string(),
                "Or run: defaults write com.apple.AdLib allowIdentifierForAdvertising -bool false"
                    .to_string(),
                "Disable Apple personalized ads: defaults write com.apple.AdLib \
                    allowApplePersonalizedAdvertising -bool false"
                    .to_string(),
                "Safari: Enable 'Prevent cross-site tracking' in Safari > Settings > Privacy"
                    .to_string(),
                "Safari: Enable 'Ask websites not to track me' (Do Not Track header)".to_string(),
                "Safari: Enable iCloud Private Relay (requires iCloud+ subscription)".to_string(),
            ]);
        }

        #[cfg(target_os = "windows")]
        {
            actions_available.push(
                "Disable Windows Advertising ID: Settings > Privacy & Security > General > \
                    turn off 'Let apps show me personalized ads'"
                    .to_string(),
            );
        }

        actions_available.extend([
            "Firefox: Set Enhanced Tracking Protection to 'Strict' mode".to_string(),
            "Firefox: Enable Do Not Track in Privacy & Security settings".to_string(),
            "Chrome: Disable Topics API in Settings > Privacy > Ad privacy > Ad topics".to_string(),
            "Chrome: Disable Site-suggested ads (FLEDGE) in Ad privacy settings".to_string(),
        ]);

        // Add broker opt-out URLs
        let opt_out_brokers: Vec<&brokers::Broker> = broker_list
            .iter()
            .filter(|b| b.opt_out_url.as_deref().is_some_and(|url| !url.is_empty()))
            .collect();

        for broker in &opt_out_brokers {
            if let Some(url) = &broker.opt_out_url {
                actions_available.push(format!("Opt out of {}: {}", broker.name, url));
            }
        }

        if opts.apply {
            // Open all opt-out URLs in the default browser
            for broker in &opt_out_brokers {
                if let Some(url) = &broker.opt_out_url {
                    if open::that(url).is_ok() {
                        actions_taken
                            .push(format!("Opened opt-out page for {}: {}", broker.name, url));
                    }
                }
            }

            if actions_taken.is_empty() {
                actions_taken.push(
                    "No automated actions available. Review recommendations above.".to_string(),
                );
            }
        }

        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken,
            actions_available,
        })
    }
}
