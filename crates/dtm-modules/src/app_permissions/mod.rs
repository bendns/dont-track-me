mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct AppPermissionsModule;

#[async_trait]
impl Module for AppPermissionsModule {
    fn name(&self) -> &str {
        "app_permissions"
    }

    fn display_name(&self) -> &str {
        "App Permission Audit"
    }

    fn description(&self) -> &str {
        "Audit app permissions for over-permissioned applications"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_app_permissions(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        let actions_available = platform_protect_actions();

        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available,
        })
    }
}

#[cfg(target_os = "macos")]
fn platform_protect_actions() -> Vec<String> {
    vec![
        "Review and revoke unnecessary Camera permissions in System Settings > Privacy & Security > Camera".to_string(),
        "Review and revoke unnecessary Microphone permissions in System Settings > Privacy & Security > Microphone".to_string(),
        "Review and revoke Screen Recording permissions in System Settings > Privacy & Security > Screen Recording".to_string(),
        "Review and revoke Full Disk Access permissions in System Settings > Privacy & Security > Full Disk Access".to_string(),
        "Review and revoke Accessibility permissions in System Settings > Privacy & Security > Accessibility".to_string(),
        "Review and revoke Input Monitoring permissions in System Settings > Privacy & Security > Input Monitoring".to_string(),
        "Run: tccutil reset <service> to reset all permissions for a given service".to_string(),
    ]
}

#[cfg(target_os = "linux")]
fn platform_protect_actions() -> Vec<String> {
    vec![
        "Review Flatpak permissions: flatpak override --show <app>".to_string(),
        "Review Snap connections: snap connections <snap>".to_string(),
        "Revoke camera/mic access for specific Flatpak apps: flatpak override --nodevice=all <app>"
            .to_string(),
    ]
}

#[cfg(target_os = "windows")]
fn platform_protect_actions() -> Vec<String> {
    vec![
        "Review app permissions in Settings > Privacy & Security".to_string(),
        "Disable camera access: Settings > Privacy & Security > Camera".to_string(),
        "Disable microphone access: Settings > Privacy & Security > Microphone".to_string(),
        "Disable location access: Settings > Privacy & Security > Location".to_string(),
    ]
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_protect_actions() -> Vec<String> {
    vec!["Manually review your app permissions in system settings.".to_string()]
}
