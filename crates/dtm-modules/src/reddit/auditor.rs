//! Reddit auditor — audit privacy settings and subreddit bias.

use std::collections::HashMap;

use anyhow::Result;

use dtm_core::auth::ensure_authenticated;
use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};

use super::client::{RedditClient, TOKEN_URL};
use super::subreddits::classify_subreddit;
use crate::reddit::client::tracking_prefs;

pub async fn audit_reddit(_opts: &AuditOpts) -> Result<AuditResult> {
    let token = ensure_authenticated("reddit", TOKEN_URL).await?;
    let client = RedditClient::new(token);

    let mut findings = Vec::new();
    let mut score: i32 = 100;
    let mut raw_data = HashMap::new();

    // Phase 1: Privacy settings audit
    match client.get_prefs().await {
        Ok(prefs) => {
            let prefs_snapshot: HashMap<String, serde_json::Value> = tracking_prefs()
                .iter()
                .filter_map(|(name, _)| prefs.get(*name).map(|v| (name.to_string(), v.clone())))
                .collect();
            raw_data.insert(
                "prefs".to_string(),
                serde_json::to_value(&prefs_snapshot).unwrap_or_default(),
            );

            let mut hostile_count = 0;
            for (pref_name, pref_info) in tracking_prefs() {
                let current = prefs.get(pref_name).and_then(|v| v.as_bool());
                if current != Some(pref_info.safe_value) {
                    hostile_count += 1;
                    findings.push(Finding {
                        title: format!("Tracking enabled: {pref_name}"),
                        description: pref_info.description.to_string(),
                        threat_level: ThreatLevel::High,
                        remediation: "Run: dtm protect reddit --apply --harden-only".to_string(),
                    });
                    score -= 8;
                }
            }

            if hostile_count == 0 {
                findings.push(Finding {
                    title: "All privacy settings are hardened".to_string(),
                    description: "All 7 Reddit tracking preferences are set to their safe values."
                        .to_string(),
                    threat_level: ThreatLevel::Info,
                    remediation: "No action needed.".to_string(),
                });
            }
        }
        Err(e) => {
            findings.push(Finding {
                title: "Failed to read Reddit preferences".to_string(),
                description: format!("Could not fetch privacy settings: {e}"),
                threat_level: ThreatLevel::Medium,
                remediation: "Check your authentication: dtm auth reddit".to_string(),
            });
            score -= 20;
        }
    }

    // Phase 2: Subscription bias analysis
    match client.get_subscribed_subreddits().await {
        Ok(subreddits) => {
            raw_data.insert(
                "subreddit_count".to_string(),
                serde_json::json!(subreddits.len()),
            );

            let mut category_counts: HashMap<String, HashMap<String, usize>> = HashMap::new();
            let mut classified = 0;

            for sub in &subreddits {
                if let Some((cat, perspective)) = classify_subreddit(sub) {
                    classified += 1;
                    *category_counts
                        .entry(cat.to_string())
                        .or_default()
                        .entry(perspective.to_string())
                        .or_insert(0) += 1;
                }
            }

            raw_data.insert("classified".to_string(), serde_json::json!(classified));
            raw_data.insert(
                "category_breakdown".to_string(),
                serde_json::to_value(&category_counts).unwrap_or_default(),
            );

            for (cat, perspectives) in &category_counts {
                let total: usize = perspectives.values().sum();
                if total < 2 {
                    continue;
                }

                for (perspective, &count) in perspectives {
                    let ratio = count as f64 / total as f64;
                    if ratio > 0.7 && total >= 3 {
                        findings.push(Finding {
                            title: format!("Strong {cat} bias: {perspective} ({count}/{total})"),
                            description: format!(
                                "In the '{cat}' category, {:.0}% of your subscriptions \
                                 lean '{perspective}'. This creates a clear profiling signal.",
                                ratio * 100.0
                            ),
                            threat_level: ThreatLevel::High,
                            remediation: "Run: dtm protect reddit --apply --diversify-only"
                                .to_string(),
                        });
                        score -= 10;
                    }
                }
            }
        }
        Err(e) => {
            findings.push(Finding {
                title: "Failed to read Reddit subscriptions".to_string(),
                description: format!("Could not fetch subreddit list: {e}"),
                threat_level: ThreatLevel::Medium,
                remediation: "Check your authentication: dtm auth reddit".to_string(),
            });
        }
    }

    score = score.clamp(0, 100);

    Ok(AuditResult {
        module_name: "reddit".to_string(),
        score: score as u32,
        findings,
        raw_data,
    })
}
