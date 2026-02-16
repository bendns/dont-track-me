use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::models::{AuditResult, Finding, PrivacyCheck, ProtectionResult, ThreatLevel};
use crate::paths;

/// Threat weight penalties loaded from shared/schema/threat_weights.yaml.
fn load_threat_weights() -> HashMap<ThreatLevel, u32> {
    let yaml = paths::load_shared_yaml("schema/threat_weights.yaml");
    if let Some(yaml) = yaml {
        #[derive(Deserialize)]
        struct WeightsFile {
            threat_weights: HashMap<String, u32>,
        }
        if let Ok(file) = serde_yaml::from_str::<WeightsFile>(&yaml) {
            let mut weights = HashMap::new();
            for (level, penalty) in file.threat_weights {
                let tl = match level.as_str() {
                    "critical" => ThreatLevel::Critical,
                    "high" => ThreatLevel::High,
                    "medium" => ThreatLevel::Medium,
                    "low" => ThreatLevel::Low,
                    "info" => ThreatLevel::Info,
                    _ => continue,
                };
                weights.insert(tl, penalty);
            }
            return weights;
        }
    }

    // Fallback defaults
    HashMap::from([
        (ThreatLevel::Critical, 15),
        (ThreatLevel::High, 10),
        (ThreatLevel::Medium, 6),
        (ThreatLevel::Low, 3),
        (ThreatLevel::Info, 0),
    ])
}

/// Get the penalty for a threat level.
pub fn threat_penalty(level: ThreatLevel) -> u32 {
    let weights = load_threat_weights();
    weights.get(&level).copied().unwrap_or(5)
}

/// Score a checklist based on user responses.
///
/// Unanswered questions are assumed unsafe.
/// Returns (score 0-100, list of findings).
pub fn compute_checklist_score(
    checks: &[PrivacyCheck],
    responses: &HashMap<String, bool>,
) -> (u32, Vec<Finding>) {
    let weights = load_threat_weights();
    let mut score: i32 = 100;
    let mut findings = Vec::new();

    for check in checks {
        let answer = responses.get(&check.id);
        let is_safe = answer.is_some_and(|&a| a == check.safe_answer);

        if is_safe {
            findings.push(Finding {
                title: format!("OK: {}", check.question),
                description: check.description.clone(),
                threat_level: ThreatLevel::Info,
                remediation: "No action needed.".to_string(),
            });
        } else {
            let penalty = weights.get(&check.threat_level).copied().unwrap_or(5) as i32;
            score -= penalty;
            findings.push(Finding {
                title: check.question.clone(),
                description: check.description.clone(),
                threat_level: check.threat_level,
                remediation: check.remediation.clone(),
            });
        }
    }

    (score.clamp(0, 100) as u32, findings)
}

/// Generate a protection result for a checklist-based module.
///
/// With responses: returns only remediation steps for unsafe settings.
/// Without: returns the full hardening guide.
pub fn protect_checklist_module(
    module_name: &str,
    display_name: &str,
    checks: &[PrivacyCheck],
    responses: Option<&HashMap<String, bool>>,
) -> ProtectionResult {
    let mut actions = Vec::new();

    if let Some(responses) = responses {
        for check in checks {
            let answer = responses.get(&check.id);
            let is_safe = answer.is_some_and(|&a| a == check.safe_answer);
            if !is_safe {
                actions.push(format!(
                    "[{}] {}",
                    check.threat_level.as_str().to_uppercase(),
                    check.remediation,
                ));
                if let Some(tc) = &check.technical_countermeasure {
                    actions.push(format!("  >> {tc}"));
                }
            }
        }
    } else {
        actions.push(format!("--- {display_name} Privacy Hardening Guide ---"));
        for check in checks {
            actions.push(format!(
                "[{}] {}",
                check.threat_level.as_str().to_uppercase(),
                check.question,
            ));
            actions.push(format!("  {}", check.remediation));
            if let Some(tc) = &check.technical_countermeasure {
                actions.push(format!("  >> {tc}"));
            }
        }
    }

    if actions.is_empty() {
        actions.push(format!(
            "All {display_name} privacy settings are properly configured."
        ));
    }

    ProtectionResult {
        module_name: module_name.to_string(),
        dry_run: true, // Always dry-run for checklists
        actions_taken: Vec::new(),
        actions_available: actions,
    }
}

/// Load checklist checks from shared/checklists/<name>.yaml and return an audit result.
pub fn audit_checklist(
    module_name: &str,
    checks: &[PrivacyCheck],
    responses: &HashMap<String, bool>,
) -> AuditResult {
    let (score, findings) = compute_checklist_score(checks, responses);
    AuditResult {
        module_name: module_name.to_string(),
        score,
        findings,
        raw_data: HashMap::new(),
    }
}

/// Load checks from YAML for a checklist module.
pub fn load_checks(name: &str) -> Result<Vec<PrivacyCheck>> {
    crate::data::load_checklist(name).context(format!("Failed to load checklist for '{name}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_checks() -> Vec<PrivacyCheck> {
        vec![
            PrivacyCheck {
                id: "private_account".to_string(),
                question: "Is your account private?".to_string(),
                description: "A private account limits who can see your posts.".to_string(),
                threat_level: ThreatLevel::High,
                remediation: "Set your account to private in settings.".to_string(),
                category: "visibility".to_string(),
                technical_countermeasure: None,
                safe_answer: true,
            },
            PrivacyCheck {
                id: "two_factor".to_string(),
                question: "Is two-factor auth enabled?".to_string(),
                description: "2FA protects against unauthorized access.".to_string(),
                threat_level: ThreatLevel::Critical,
                remediation: "Enable 2FA in security settings.".to_string(),
                category: "security".to_string(),
                technical_countermeasure: Some("Use TOTP app, not SMS.".to_string()),
                safe_answer: true,
            },
        ]
    }

    #[test]
    fn test_all_safe() {
        let checks = sample_checks();
        let responses = HashMap::from([
            ("private_account".to_string(), true),
            ("two_factor".to_string(), true),
        ]);
        let (score, findings) = compute_checklist_score(&checks, &responses);
        assert_eq!(score, 100);
        assert!(findings.iter().all(|f| f.threat_level == ThreatLevel::Info));
    }

    #[test]
    fn test_all_unsafe() {
        let checks = sample_checks();
        let responses = HashMap::from([
            ("private_account".to_string(), false),
            ("two_factor".to_string(), false),
        ]);
        let (score, findings) = compute_checklist_score(&checks, &responses);
        // 100 - 10 (high) - 15 (critical) = 75
        assert_eq!(score, 75);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.threat_level != ThreatLevel::Info)
                .count(),
            2
        );
    }

    #[test]
    fn test_unanswered_assumed_unsafe() {
        let checks = sample_checks();
        let responses = HashMap::new();
        let (score, _) = compute_checklist_score(&checks, &responses);
        assert_eq!(score, 75);
    }

    // --- Ported from Python test_checklist.py ---

    #[test]
    fn score_clamps_at_zero() {
        // Many high-severity unsafe checks should not produce a negative score
        let checks: Vec<PrivacyCheck> = (0..20)
            .map(|i| PrivacyCheck {
                id: format!("check_{i}"),
                question: format!("Question {i}?"),
                description: "Desc".to_string(),
                threat_level: ThreatLevel::Critical,
                remediation: "Fix it".to_string(),
                category: "security".to_string(),
                technical_countermeasure: None,
                safe_answer: true,
            })
            .collect();
        // All answered unsafe
        let responses: HashMap<String, bool> =
            (0..20).map(|i| (format!("check_{i}"), false)).collect();
        let (score, _) = compute_checklist_score(&checks, &responses);
        // 100 - 20*15 = -200, clamped to 0
        assert_eq!(score, 0);
    }

    #[test]
    fn mixed_safe_and_unsafe() {
        let checks = sample_checks();
        // private_account safe, two_factor unsafe
        let responses = HashMap::from([
            ("private_account".to_string(), true),
            ("two_factor".to_string(), false),
        ]);
        let (score, findings) = compute_checklist_score(&checks, &responses);
        // 100 - 15 (critical penalty for two_factor) = 85
        assert_eq!(score, 85);
        // One info finding (safe) + one non-info finding (unsafe)
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.threat_level == ThreatLevel::Info)
                .count(),
            1
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.threat_level != ThreatLevel::Info)
                .count(),
            1
        );
    }

    #[test]
    fn optional_technical_countermeasure() {
        // Verify that a check with technical_countermeasure is handled in protect
        let checks = vec![PrivacyCheck {
            id: "tc_check".to_string(),
            question: "Has MFA?".to_string(),
            description: "MFA protects.".to_string(),
            threat_level: ThreatLevel::High,
            remediation: "Enable MFA.".to_string(),
            category: "security".to_string(),
            technical_countermeasure: Some("Use hardware key.".to_string()),
            safe_answer: true,
        }];
        let responses = HashMap::from([("tc_check".to_string(), false)]);
        let result = protect_checklist_module("test", "Test", &checks, Some(&responses));
        // Should contain remediation action and the technical countermeasure
        assert!(result
            .actions_available
            .iter()
            .any(|a| a.contains("Enable MFA.")));
        assert!(result
            .actions_available
            .iter()
            .any(|a| a.contains("Use hardware key.")));
    }

    #[test]
    fn inverted_safe_answer() {
        // Check with safe_answer=false — answering false is the safe answer
        let checks = vec![PrivacyCheck {
            id: "share_location".to_string(),
            question: "Do you share location?".to_string(),
            description: "Location sharing exposes you.".to_string(),
            threat_level: ThreatLevel::High,
            remediation: "Disable location sharing.".to_string(),
            category: "location".to_string(),
            technical_countermeasure: None,
            safe_answer: false,
        }];
        // User answers false (matching safe_answer) -> safe
        let responses_safe = HashMap::from([("share_location".to_string(), false)]);
        let (score_safe, findings_safe) = compute_checklist_score(&checks, &responses_safe);
        assert_eq!(score_safe, 100);
        assert!(findings_safe
            .iter()
            .all(|f| f.threat_level == ThreatLevel::Info));

        // User answers true (not matching safe_answer) -> unsafe
        let responses_unsafe = HashMap::from([("share_location".to_string(), true)]);
        let (score_unsafe, _) = compute_checklist_score(&checks, &responses_unsafe);
        // 100 - 10 (high penalty) = 90
        assert_eq!(score_unsafe, 90);
    }

    #[test]
    fn single_critical_check() {
        // One critical check, all unsafe -> score = 100 - 15 = 85
        let checks = vec![PrivacyCheck {
            id: "single".to_string(),
            question: "Is 2FA enabled?".to_string(),
            description: "2FA protects access.".to_string(),
            threat_level: ThreatLevel::Critical,
            remediation: "Enable 2FA.".to_string(),
            category: "security".to_string(),
            technical_countermeasure: None,
            safe_answer: true,
        }];
        let responses = HashMap::from([("single".to_string(), false)]);
        let (score, findings) = compute_checklist_score(&checks, &responses);
        assert_eq!(score, 85);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_level, ThreatLevel::Critical);
    }
}
