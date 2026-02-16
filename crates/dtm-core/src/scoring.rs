use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::models::AuditResult;
use crate::paths;

/// Score tier labels and colors.
#[derive(Debug, Clone)]
pub struct ScoreTier {
    pub label: &'static str,
    pub color: &'static str,
}

/// Get the tier for a given score.
pub fn get_score_tier(score: u32) -> ScoreTier {
    match score {
        90..=100 => ScoreTier {
            label: "Excellent",
            color: "green",
        },
        70..=89 => ScoreTier {
            label: "Good",
            color: "blue",
        },
        50..=69 => ScoreTier {
            label: "Moderate",
            color: "yellow",
        },
        30..=49 => ScoreTier {
            label: "Poor",
            color: "dark_orange",
        },
        _ => ScoreTier {
            label: "Critical",
            color: "red",
        },
    }
}

/// Scoring configuration loaded from shared/schema/scoring.yaml.
#[derive(Debug, Deserialize)]
pub struct ScoringConfig {
    #[serde(default = "default_weights")]
    pub module_weights: HashMap<String, f64>,
    #[serde(default = "default_weight")]
    pub default_weight: f64,
}

fn default_weights() -> HashMap<String, f64> {
    HashMap::new()
}

fn default_weight() -> f64 {
    5.0
}

/// Load scoring configuration from shared/schema/scoring.yaml.
pub fn load_scoring_config() -> Result<ScoringConfig> {
    let yaml = paths::load_shared_yaml("schema/scoring.yaml")
        .context("Failed to load shared/schema/scoring.yaml")?;
    serde_yaml::from_str(&yaml).context("Failed to parse scoring.yaml")
}

/// Compute the overall weighted privacy score from individual module results.
pub fn compute_overall_score(results: &[AuditResult], config: &ScoringConfig) -> f64 {
    if results.is_empty() {
        return 0.0;
    }

    let mut weighted_sum = 0.0;
    let mut total_weight = 0.0;

    for result in results {
        let weight = config
            .module_weights
            .get(&result.module_name)
            .copied()
            .unwrap_or(config.default_weight);

        weighted_sum += result.score as f64 * weight;
        total_weight += weight;
    }

    if total_weight == 0.0 {
        return 0.0;
    }

    (weighted_sum / total_weight * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_tiers() {
        assert_eq!(get_score_tier(95).label, "Excellent");
        assert_eq!(get_score_tier(75).label, "Good");
        assert_eq!(get_score_tier(55).label, "Moderate");
        assert_eq!(get_score_tier(35).label, "Poor");
        assert_eq!(get_score_tier(15).label, "Critical");
    }

    #[test]
    fn test_compute_overall_score_empty() {
        let config = ScoringConfig {
            module_weights: HashMap::new(),
            default_weight: 5.0,
        };
        assert_eq!(compute_overall_score(&[], &config), 0.0);
    }

    #[test]
    fn test_compute_overall_score_weighted() {
        let mut weights = HashMap::new();
        weights.insert("cookies".to_string(), 15.0);
        weights.insert("dns".to_string(), 12.0);

        let config = ScoringConfig {
            module_weights: weights,
            default_weight: 5.0,
        };

        let results = vec![
            AuditResult {
                module_name: "cookies".to_string(),
                score: 80,
                findings: vec![],
                raw_data: HashMap::new(),
            },
            AuditResult {
                module_name: "dns".to_string(),
                score: 60,
                findings: vec![],
                raw_data: HashMap::new(),
            },
        ];

        let score = compute_overall_score(&results, &config);
        // (80*15 + 60*12) / (15+12) = (1200+720)/27 = 71.1
        assert!((score - 71.1).abs() < 0.1);
    }

    #[test]
    fn test_score_tier_boundaries() {
        // Exact boundary values for each tier
        assert_eq!(get_score_tier(0).label, "Critical");
        assert_eq!(get_score_tier(29).label, "Critical");
        assert_eq!(get_score_tier(30).label, "Poor");
        assert_eq!(get_score_tier(49).label, "Poor");
        assert_eq!(get_score_tier(50).label, "Moderate");
        assert_eq!(get_score_tier(69).label, "Moderate");
        assert_eq!(get_score_tier(70).label, "Good");
        assert_eq!(get_score_tier(89).label, "Good");
        assert_eq!(get_score_tier(90).label, "Excellent");
        assert_eq!(get_score_tier(100).label, "Excellent");
    }

    #[test]
    fn test_score_tier_colors() {
        assert_eq!(get_score_tier(95).color, "green");
        assert_eq!(get_score_tier(75).color, "blue");
        assert_eq!(get_score_tier(55).color, "yellow");
        assert_eq!(get_score_tier(35).color, "dark_orange");
        assert_eq!(get_score_tier(15).color, "red");
    }

    #[test]
    fn test_weighted_score_single_module() {
        let mut weights = HashMap::new();
        weights.insert("ssh".to_string(), 20.0);

        let config = ScoringConfig {
            module_weights: weights,
            default_weight: 5.0,
        };

        let results = vec![AuditResult {
            module_name: "ssh".to_string(),
            score: 85,
            findings: vec![],
            raw_data: HashMap::new(),
        }];

        let score = compute_overall_score(&results, &config);
        // Single module: 85 * 20 / 20 = 85.0
        assert!((score - 85.0).abs() < 0.1);
    }

    #[test]
    fn test_equal_weights_are_average() {
        let config = ScoringConfig {
            module_weights: HashMap::new(),
            default_weight: 10.0,
        };

        let results = vec![
            AuditResult {
                module_name: "a".to_string(),
                score: 80,
                findings: vec![],
                raw_data: HashMap::new(),
            },
            AuditResult {
                module_name: "b".to_string(),
                score: 60,
                findings: vec![],
                raw_data: HashMap::new(),
            },
            AuditResult {
                module_name: "c".to_string(),
                score: 40,
                findings: vec![],
                raw_data: HashMap::new(),
            },
        ];

        let score = compute_overall_score(&results, &config);
        // (80 + 60 + 40) / 3 = 60.0
        assert!((score - 60.0).abs() < 0.1);
    }

    #[test]
    fn test_zero_weight_module_excluded() {
        let mut weights = HashMap::new();
        weights.insert("important".to_string(), 10.0);
        weights.insert("ignored".to_string(), 0.0);

        let config = ScoringConfig {
            module_weights: weights,
            default_weight: 5.0,
        };

        let results = vec![
            AuditResult {
                module_name: "important".to_string(),
                score: 90,
                findings: vec![],
                raw_data: HashMap::new(),
            },
            AuditResult {
                module_name: "ignored".to_string(),
                score: 10,
                findings: vec![],
                raw_data: HashMap::new(),
            },
        ];

        let score = compute_overall_score(&results, &config);
        // Weight 0 means: 90*10 + 10*0 / (10+0) = 900/10 = 90.0
        assert!((score - 90.0).abs() < 0.1);
    }

    #[test]
    fn test_default_weight_used_for_unknown_module() {
        let config = ScoringConfig {
            module_weights: HashMap::new(),
            default_weight: 7.0,
        };

        let results = vec![AuditResult {
            module_name: "unknown_module".to_string(),
            score: 50,
            findings: vec![],
            raw_data: HashMap::new(),
        }];

        let score = compute_overall_score(&results, &config);
        // Single module at default weight: 50 * 7 / 7 = 50.0
        assert!((score - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_all_zero_weights_returns_zero() {
        let mut weights = HashMap::new();
        weights.insert("a".to_string(), 0.0);
        weights.insert("b".to_string(), 0.0);

        let config = ScoringConfig {
            module_weights: weights,
            default_weight: 0.0,
        };

        let results = vec![
            AuditResult {
                module_name: "a".to_string(),
                score: 100,
                findings: vec![],
                raw_data: HashMap::new(),
            },
            AuditResult {
                module_name: "b".to_string(),
                score: 100,
                findings: vec![],
                raw_data: HashMap::new(),
            },
        ];

        let score = compute_overall_score(&results, &config);
        assert_eq!(score, 0.0, "All-zero weights should return 0.0");
    }

    #[test]
    fn test_scoring_config_deserializes_defaults() {
        let yaml = "{}";
        let config: ScoringConfig = serde_yaml::from_str(yaml).expect("parse empty yaml");
        assert!(config.module_weights.is_empty());
        assert!((config.default_weight - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_score_rounding() {
        // Ensure score is rounded to 1 decimal place
        let mut weights = HashMap::new();
        weights.insert("a".to_string(), 3.0);
        weights.insert("b".to_string(), 7.0);

        let config = ScoringConfig {
            module_weights: weights,
            default_weight: 5.0,
        };

        let results = vec![
            AuditResult {
                module_name: "a".to_string(),
                score: 33,
                findings: vec![],
                raw_data: HashMap::new(),
            },
            AuditResult {
                module_name: "b".to_string(),
                score: 77,
                findings: vec![],
                raw_data: HashMap::new(),
            },
        ];

        let score = compute_overall_score(&results, &config);
        // (33*3 + 77*7) / (3+7) = (99+539)/10 = 63.8
        assert!((score - 63.8).abs() < 0.1);
        // Verify it has at most 1 decimal place
        let formatted = format!("{score}");
        if let Some(dot_pos) = formatted.find('.') {
            let decimals = formatted.len() - dot_pos - 1;
            assert!(
                decimals <= 1,
                "Score should have at most 1 decimal: {score}"
            );
        }
    }
}
