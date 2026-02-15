//! DNS monitor module — capture DNS queries and detect tracker domains.
//!
//! Merged from the standalone agent/src/dns_monitor.rs into the unified binary.
//! This module wraps the capture logic as a proper dtm Module.
//!
//! The audit function reads stored DNS events from the database.
//! Live monitoring is done via `capture::monitor_dns()` called from the CLI.

pub mod capture;

use anyhow::Result;
use async_trait::async_trait;

use dtm_core::models::{
    AuditOpts, AuditResult, Finding, ProtectOpts, ProtectionResult, ThreatLevel,
};
use dtm_core::module_trait::Module;

pub struct DnsMonitorModule;

#[async_trait]
impl Module for DnsMonitorModule {
    fn name(&self) -> &str {
        "dns_monitor"
    }

    fn display_name(&self) -> &str {
        "DNS Tracker Monitor"
    }

    fn description(&self) -> &str {
        "Monitor DNS queries for known tracker domains (requires elevated privileges)"
    }

    async fn audit(&self, _opts: &AuditOpts) -> Result<AuditResult> {
        // Read stored events from the database
        let db_path = dtm_core::db::default_db_path();
        if !db_path.exists() {
            return Ok(AuditResult {
                module_name: "dns_monitor".to_string(),
                score: 50,
                findings: vec![Finding {
                    title: "No DNS monitoring data available".to_string(),
                    description: "Run 'sudo dtm monitor' first to capture DNS queries.".to_string(),
                    threat_level: ThreatLevel::Info,
                    remediation: "sudo dtm monitor".to_string(),
                }],
                raw_data: std::collections::HashMap::new(),
            });
        }

        let conn = dtm_core::db::open_db(&db_path)?;
        let events = dtm_core::db::get_dns_events(&conn, false, 1000)?;

        let mut findings = Vec::new();
        let mut score: i32 = 100;
        let mut raw_data = std::collections::HashMap::new();

        let total = events.len();
        let tracker_events: Vec<_> = events.iter().filter(|e| e.is_tracker).collect();

        raw_data.insert("total_queries".to_string(), serde_json::json!(total));
        raw_data.insert(
            "tracker_queries".to_string(),
            serde_json::json!(tracker_events.len()),
        );

        if total == 0 {
            findings.push(Finding {
                title: "No DNS events recorded".to_string(),
                description: "The DNS monitor has not captured any queries yet.".to_string(),
                threat_level: ThreatLevel::Info,
                remediation: "Run 'sudo dtm monitor' to start capturing.".to_string(),
            });
            return Ok(AuditResult {
                module_name: "dns_monitor".to_string(),
                score: 50,
                findings,
                raw_data,
            });
        }

        if tracker_events.is_empty() {
            findings.push(Finding {
                title: "No tracker DNS queries detected".to_string(),
                description: format!(
                    "Out of {total} captured DNS queries, none matched known tracker domains."
                ),
                threat_level: ThreatLevel::Info,
                remediation: "No action needed.".to_string(),
            });
        } else {
            let ratio = tracker_events.len() as f64 / total as f64;

            // Count by category
            let mut categories: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for event in &tracker_events {
                let cat = event.tracker_category.as_deref().unwrap_or("unknown");
                *categories.entry(cat.to_string()).or_insert(0) += 1;
            }

            raw_data.insert(
                "category_breakdown".to_string(),
                serde_json::to_value(&categories).unwrap_or_default(),
            );

            findings.push(Finding {
                title: format!(
                    "{} of {} DNS queries went to tracker domains ({:.1}%)",
                    tracker_events.len(),
                    total,
                    ratio * 100.0
                ),
                description: "Your system is making DNS queries to known tracking domains."
                    .to_string(),
                threat_level: if ratio > 0.3 {
                    ThreatLevel::High
                } else if ratio > 0.1 {
                    ThreatLevel::Medium
                } else {
                    ThreatLevel::Low
                },
                remediation: "Use a tracker-blocking DNS resolver (NextDNS, Pi-hole, AdGuard)."
                    .to_string(),
            });

            if ratio > 0.3 {
                score -= 30;
            } else if ratio > 0.1 {
                score -= 15;
            } else {
                score -= 5;
            }

            // Report top categories
            let mut sorted_cats: Vec<_> = categories.into_iter().collect();
            sorted_cats.sort_by(|a, b| b.1.cmp(&a.1));
            for (cat, count) in sorted_cats.iter().take(5) {
                findings.push(Finding {
                    title: format!("{cat}: {count} tracker queries"),
                    description: format!(
                        "{count} DNS queries to {cat} tracking domains were captured."
                    ),
                    threat_level: ThreatLevel::Medium,
                    remediation: format!("Block {cat} trackers at DNS level."),
                });
                score -= 3;
            }

            // Report top processes making tracker queries
            let mut processes: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for event in &tracker_events {
                let proc = event.process_name.as_deref().unwrap_or("unknown");
                *processes.entry(proc.to_string()).or_insert(0) += 1;
            }

            let mut sorted_procs: Vec<_> = processes.into_iter().collect();
            sorted_procs.sort_by(|a, b| b.1.cmp(&a.1));
            for (proc, count) in sorted_procs.iter().take(3) {
                findings.push(Finding {
                    title: format!("Process '{proc}' made {count} tracker queries"),
                    description: format!(
                        "The process '{proc}' is actively contacting tracker domains."
                    ),
                    threat_level: ThreatLevel::Medium,
                    remediation: format!(
                        "Block '{proc}' from contacting trackers using a firewall."
                    ),
                });
            }
        }

        score = score.clamp(0, 100);

        Ok(AuditResult {
            module_name: "dns_monitor".to_string(),
            score: score as u32,
            findings,
            raw_data,
        })
    }

    async fn protect(&self, _opts: &ProtectOpts) -> Result<ProtectionResult> {
        Ok(ProtectionResult {
            module_name: "dns_monitor".to_string(),
            dry_run: true,
            actions_taken: vec![],
            actions_available: vec![
                "Configure a tracker-blocking DNS resolver (NextDNS, Pi-hole, AdGuard)".to_string(),
                "Use a firewall to block tracker connections per-app (Little Snitch on macOS, simplewall on Windows, OpenSnitch on Linux)".to_string(),
                "Enable your browser's built-in tracking protection".to_string(),
            ],
        })
    }

    fn is_available(&self) -> bool {
        // The pcap-capture feature gate already handles compilation
        true
    }
}
