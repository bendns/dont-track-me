//! YouTube auditor — analyze subscription bias.

use std::collections::HashMap;

use anyhow::Result;

use dtm_core::auth::ensure_authenticated;
use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};

use super::channels::classify_channel;
use super::client::{YoutubeClient, TOKEN_URL};

pub async fn audit_youtube(_opts: &AuditOpts) -> Result<AuditResult> {
    let token = ensure_authenticated("youtube", TOKEN_URL).await?;
    let client = YoutubeClient::new(token);

    let mut findings = Vec::new();
    let mut score: i32 = 100;
    let mut raw_data = HashMap::new();

    match client.get_subscriptions().await {
        Ok(subs) => {
            raw_data.insert(
                "subscription_count".to_string(),
                serde_json::json!(subs.len()),
            );

            // Classify subscriptions
            let mut category_counts: HashMap<String, HashMap<String, usize>> = HashMap::new();
            let mut classified = 0;
            let mut unclassified = Vec::new();

            for (channel_id, title) in &subs {
                if let Some((cat, perspective, _name)) = classify_channel(channel_id) {
                    classified += 1;
                    *category_counts
                        .entry(cat.to_string())
                        .or_default()
                        .entry(perspective.to_string())
                        .or_insert(0) += 1;
                } else {
                    unclassified.push(title.clone());
                }
            }

            raw_data.insert("classified".to_string(), serde_json::json!(classified));
            raw_data.insert(
                "unclassified_count".to_string(),
                serde_json::json!(unclassified.len()),
            );
            raw_data.insert(
                "category_breakdown".to_string(),
                serde_json::to_value(&category_counts).unwrap_or_default(),
            );

            if subs.is_empty() {
                findings.push(Finding {
                    title: "No YouTube subscriptions found".to_string(),
                    description: "Your account has no subscriptions to analyze.".to_string(),
                    threat_level: ThreatLevel::Info,
                    remediation: "Subscribe to diverse channels to build a balanced profile."
                        .to_string(),
                });
                return Ok(AuditResult {
                    module_name: "youtube".to_string(),
                    score: 50,
                    findings,
                    raw_data,
                });
            }

            // Detect bias in each category
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
                                "In '{cat}', {:.0}% of your subscriptions lean \
                                 '{perspective}'. YouTube's algorithm amplifies this bias, \
                                 and the pattern is visible to anyone analyzing your account.",
                                ratio * 100.0
                            ),
                            threat_level: ThreatLevel::High,
                            remediation: "Run: dtm protect youtube --apply".to_string(),
                        });
                        score -= 12;
                    } else if ratio > 0.5 && total >= 3 {
                        findings.push(Finding {
                            title: format!("Moderate {cat} bias: {perspective} ({count}/{total})"),
                            description: format!(
                                "In '{cat}', {:.0}% of your subscriptions lean \
                                 '{perspective}'. This creates a detectable pattern.",
                                ratio * 100.0
                            ),
                            threat_level: ThreatLevel::Medium,
                            remediation:
                                "Consider subscribing to channels from other perspectives."
                                    .to_string(),
                        });
                        score -= 6;
                    }
                }
            }

            // General YouTube tracking warning
            findings.push(Finding {
                title: "YouTube shares subscription data with Google's ad network".to_string(),
                description: "Your YouTube subscriptions feed into Google's advertising profile. \
                     This data determines ad targeting across all Google services \
                     (Search, Gmail, Maps, Android) and the 2M+ websites in Google's ad network."
                    .to_string(),
                threat_level: ThreatLevel::Medium,
                remediation: "Diversify subscriptions with dtm protect youtube --apply. \
                     Periodically pause YouTube watch history in Google My Activity."
                    .to_string(),
            });
            score -= 5;
        }
        Err(e) => {
            findings.push(Finding {
                title: "Failed to fetch YouTube subscriptions".to_string(),
                description: format!("Error: {e}"),
                threat_level: ThreatLevel::Medium,
                remediation: "Check authentication: dtm auth youtube".to_string(),
            });
            score = 50;
        }
    }

    score = score.clamp(0, 100);

    Ok(AuditResult {
        module_name: "youtube".to_string(),
        score: score as u32,
        findings,
        raw_data,
    })
}
