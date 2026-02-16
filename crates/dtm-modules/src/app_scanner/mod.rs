//! App scanner module — scan installed applications for tracking SDKs.
//!
//! Merged from the standalone agent/src/app_scanner.rs into the unified binary.
//! This module wraps the scanner as a proper dtm Module.

pub mod scanner;

use anyhow::Result;
use async_trait::async_trait;

use dtm_core::models::{
    AuditOpts, AuditResult, Finding, ProtectOpts, ProtectionResult, ThreatLevel,
};
use dtm_core::module_trait::Module;

pub struct AppScannerModule;

#[async_trait]
impl Module for AppScannerModule {
    fn name(&self) -> &str {
        "app_scanner"
    }

    fn display_name(&self) -> &str {
        "Application Tracking SDK Scanner"
    }

    fn description(&self) -> &str {
        "Scan installed applications for embedded tracking SDKs and ATS exceptions"
    }

    async fn audit(&self, _opts: &AuditOpts) -> Result<AuditResult> {
        let results = scanner::scan_apps(&[]);

        // Store results in DB for `dtm apps` to read
        if let Err(e) = scanner::store_results(&results) {
            log::warn!("Failed to store app scan results in DB: {e}");
        }

        let mut findings = Vec::new();
        let mut score: i32 = 100;
        let mut raw_data = std::collections::HashMap::new();

        let total = results.len();
        let with_trackers: Vec<_> = results
            .iter()
            .filter(|r| !r.tracking_sdks.is_empty())
            .collect();
        let with_ats: Vec<_> = results
            .iter()
            .filter(|r| !r.ats_exceptions.is_empty())
            .collect();

        raw_data.insert("total_apps".to_string(), serde_json::json!(total));
        raw_data.insert(
            "apps_with_trackers".to_string(),
            serde_json::json!(with_trackers.len()),
        );
        raw_data.insert(
            "apps_with_ats_exceptions".to_string(),
            serde_json::json!(with_ats.len()),
        );

        if total == 0 {
            let description = if cfg!(target_os = "macos") {
                "No .app bundles were found in /Applications."
            } else {
                "No applications were found to scan."
            };
            findings.push(Finding {
                title: "No applications found to scan".to_string(),
                description: description.to_string(),
                threat_level: ThreatLevel::Info,
                remediation: "Ensure applications are installed in standard locations.".to_string(),
            });
            return Ok(AuditResult {
                module_name: "app_scanner".to_string(),
                score: 50,
                findings,
                raw_data,
            });
        }

        let tracker_ratio = with_trackers.len() as f64 / total as f64;
        if tracker_ratio > 0.5 {
            findings.push(Finding {
                title: format!(
                    "{} of {} apps contain tracking SDKs ({:.0}%)",
                    with_trackers.len(),
                    total,
                    tracker_ratio * 100.0
                ),
                description: "A majority of your installed applications embed tracking SDKs \
                    that report your usage patterns to third parties."
                    .to_string(),
                threat_level: ThreatLevel::High,
                remediation: "Consider alternatives without embedded trackers. \
                    Use Little Snitch or LuLu to block tracker connections."
                    .to_string(),
            });
            score -= 20;
        } else if !with_trackers.is_empty() {
            findings.push(Finding {
                title: format!(
                    "{} of {} apps contain tracking SDKs",
                    with_trackers.len(),
                    total
                ),
                description: "Some installed applications embed tracking SDKs.".to_string(),
                threat_level: ThreatLevel::Medium,
                remediation: "Review apps with trackers: dtm apps".to_string(),
            });
            score -= 10;
        }

        // Report top offenders (apps with most SDKs)
        let mut sorted = with_trackers.clone();
        sorted.sort_by(|a, b| b.tracking_sdks.len().cmp(&a.tracking_sdks.len()));
        for app in sorted.iter().take(5) {
            let sdk_names: Vec<&str> = app.tracking_sdks.iter().map(|s| s.name.as_str()).collect();
            findings.push(Finding {
                title: format!(
                    "{}: {} tracking SDKs",
                    app.app_name,
                    app.tracking_sdks.len()
                ),
                description: format!("SDKs: {}", sdk_names.join(", ")),
                threat_level: ThreatLevel::Medium,
                remediation: format!(
                    "Consider alternatives to {} or block its network access.",
                    app.app_name
                ),
            });
            score -= 3;
        }

        if !with_ats.is_empty() {
            findings.push(Finding {
                title: format!(
                    "{} apps have App Transport Security exceptions",
                    with_ats.len()
                ),
                description: "These apps are allowed to make insecure HTTP connections, \
                    which could expose data in transit."
                    .to_string(),
                threat_level: ThreatLevel::Low,
                remediation: "Review ATS exceptions: dtm apps --format json".to_string(),
            });
            score -= 5;
        }

        if with_trackers.is_empty() && with_ats.is_empty() {
            findings.push(Finding {
                title: "No tracking SDKs or ATS exceptions found".to_string(),
                description: "Your installed applications appear clean of known tracking SDKs."
                    .to_string(),
                threat_level: ThreatLevel::Info,
                remediation: "No action needed.".to_string(),
            });
        }

        score = score.clamp(0, 100);

        Ok(AuditResult {
            module_name: "app_scanner".to_string(),
            score: score as u32,
            findings,
            raw_data,
        })
    }

    async fn protect(&self, _opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: "app_scanner".to_string(),
            dry_run: true,
            actions_taken: vec![],
            actions_available: vec![
                "Use Little Snitch or LuLu to block tracker SDK connections".to_string(),
                "Review and replace apps with privacy-respecting alternatives".to_string(),
            ],
        })
    }
}
