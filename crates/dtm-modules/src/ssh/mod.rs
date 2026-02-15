mod auditor;

use anyhow::Result;
use async_trait::async_trait;
use dtm_core::models::{AuditOpts, AuditResult, ProtectOpts, ProtectionResult};
use dtm_core::module_trait::Module;

pub struct SshModule;

#[async_trait]
impl Module for SshModule {
    fn name(&self) -> &str {
        "ssh"
    }

    fn display_name(&self) -> &str {
        "SSH Security"
    }

    fn description(&self) -> &str {
        "Audits SSH key hygiene, configuration security, and known_hosts privacy"
    }

    async fn audit(&self, opts: &AuditOpts) -> Result<AuditResult> {
        auditor::audit_ssh(opts).await
    }

    async fn protect(&self, opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: self.name().to_string(),
            dry_run: !opts.apply,
            actions_taken: vec![],
            actions_available: vec![
                "Hash known_hosts: ssh-keygen -H".to_string(),
                "Add passphrase to unencrypted keys: ssh-keygen -p -f <key>".to_string(),
                "Generate Ed25519 key: ssh-keygen -t ed25519".to_string(),
                "Restrict authorized_keys permissions: chmod 600 ~/.ssh/authorized_keys"
                    .to_string(),
            ],
        })
    }
}
