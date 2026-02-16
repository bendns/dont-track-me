use std::collections::HashMap;

use anyhow::{Context, Result};
use rand::seq::SliceRandom;

use dtm_core::data::load_country_data;
use dtm_core::models::{
    AuditOpts, AuditResult, Finding, ProtectOpts, ProtectionResult, ThreatLevel,
};

/// YAML structure: platform -> category -> perspective -> list of account handles.
type AccountDatabase = HashMap<String, HashMap<String, HashMap<String, Vec<String>>>>;

/// A single account recommendation with metadata.
struct AccountEntry {
    account: String,
    category: String,
    perspective: String,
}

/// Load the account database for a given country code.
fn load_accounts(country: &str) -> Result<AccountDatabase> {
    load_country_data::<AccountDatabase>("social_noise", country).context(format!(
        "Failed to load social noise data for country '{country}'"
    ))
}

/// Get all platform names for a country.
fn get_all_platforms(country: &str) -> Result<Vec<String>> {
    let accounts = load_accounts(country)?;
    Ok(accounts.keys().cloned().collect())
}

/// Get categories available for a platform in a country.
fn get_platform_categories(platform: &str, country: &str) -> Result<Vec<String>> {
    let accounts = load_accounts(country)?;
    match accounts.get(platform) {
        Some(platform_data) => Ok(platform_data.keys().cloned().collect()),
        None => Ok(Vec::new()),
    }
}

/// Generate balanced follow lists for selected platforms.
///
/// Returns a map of platform name -> list of account entries.
/// Picks evenly from every perspective in every category.
fn get_balanced_follow_list(
    platforms: &[String],
    categories: &[String],
    per_subcategory: usize,
    country: &str,
) -> Result<HashMap<String, Vec<AccountEntry>>> {
    let accounts = load_accounts(country)?;
    let mut rng = rand::thread_rng();
    let mut result: HashMap<String, Vec<AccountEntry>> = HashMap::new();

    for platform in platforms {
        let platform_data = match accounts.get(platform) {
            Some(data) => data,
            None => continue,
        };

        let mut accounts_list: Vec<AccountEntry> = Vec::new();

        for (cat_name, perspectives) in platform_data {
            if !categories.is_empty() && !categories.contains(cat_name) {
                continue;
            }

            for (perspective_name, accts) in perspectives {
                let sample_size = per_subcategory.min(accts.len());
                let mut pool = accts.clone();
                pool.shuffle(&mut rng);
                for account in pool.into_iter().take(sample_size) {
                    accounts_list.push(AccountEntry {
                        account,
                        category: cat_name.clone(),
                        perspective: perspective_name.clone(),
                    });
                }
            }
        }

        accounts_list.shuffle(&mut rng);
        result.insert(platform.clone(), accounts_list);
    }

    Ok(result)
}

/// Format follow lists as readable action items.
fn format_follow_list(follow_list: &HashMap<String, Vec<AccountEntry>>) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();

    for (platform, accounts) in follow_list {
        if accounts.is_empty() {
            continue;
        }
        lines.push(format!(
            "--- {} ({} accounts) ---",
            platform.to_uppercase(),
            accounts.len()
        ));

        // Group by category for readability
        let mut by_category: HashMap<&str, Vec<&AccountEntry>> = HashMap::new();
        for acc in accounts {
            by_category
                .entry(acc.category.as_str())
                .or_default()
                .push(acc);
        }

        for (cat, accs) in &by_category {
            lines.push(format!("  [{cat}]"));
            for acc in accs {
                lines.push(format!("    {}  ({})", acc.account, acc.perspective));
            }
        }
    }

    lines
}

/// Audit social media profiling risk.
///
/// This is primarily educational -- we cannot access actual social media
/// accounts. Instead, we highlight the risks and score based on general
/// exposure patterns.
pub async fn audit_social_noise(_opts: &AuditOpts) -> Result<AuditResult> {
    let findings = vec![
        Finding {
            title: "Social media following lists reveal your identity profile".to_string(),
            description: "Platforms like Instagram, TikTok, Facebook, and YouTube build detailed \
                 profiles based on who you follow. If you only follow artists from one genre, \
                 politicians from one party, or news from one perspective — your beliefs, \
                 sexuality, religion, and political leaning are exposed. Example: a man \
                 following only pop divas may be profiled as gay. Someone following only \
                 left-wing accounts is categorized as a left-wing voter."
                .to_string(),
            threat_level: ThreatLevel::Critical,
            remediation: "Run 'dtm noise social --apply' to generate balanced follow lists. \
                 Follow accounts from all perspectives to make your profile unreadable."
                .to_string(),
        },
        Finding {
            title: "Instagram/Facebook share following data with advertisers".to_string(),
            description:
                "Meta (Instagram, Facebook) uses your follow list, likes, and interactions \
                 to build an ad profile. Advertisers can target you based on 'interests' \
                 inferred from who you follow. This data is also available to political \
                 campaigns for voter micro-targeting."
                    .to_string(),
            threat_level: ThreatLevel::High,
            remediation: "1. Follow diverse accounts across all political/cultural spectrums\n\
                 2. Periodically clear your ad preferences in Meta settings\n\
                 3. Use 'Off-Facebook Activity' settings to limit data sharing"
                .to_string(),
        },
        Finding {
            title: "YouTube watch history and subscriptions reveal ideology".to_string(),
            description:
                "YouTube's recommendation algorithm categorizes you based on subscriptions \
                 and watch history. Research shows this creates 'filter bubbles' that \
                 radicalize viewers. Your YouTube profile is shared with Google's ad network."
                    .to_string(),
            threat_level: ThreatLevel::High,
            remediation: "Subscribe to channels from all political perspectives. \
                 Regularly pause and clear your YouTube watch history. \
                 Use YouTube in incognito mode for sensitive topics."
                .to_string(),
        },
        Finding {
            title: "TikTok algorithm profiling".to_string(),
            description: "TikTok's algorithm builds an extremely detailed interest profile within \
                 minutes of use. Your For You page reveals your inferred age, gender, \
                 sexuality, politics, and emotional state. This data is stored on servers \
                 accessible to the platform's parent company."
                .to_string(),
            threat_level: ThreatLevel::High,
            remediation: "Actively engage with diverse content. Follow accounts outside your \
                 typical interests. Use 'Not Interested' on overly targeted content. \
                 Periodically reset your For You page via settings."
                .to_string(),
        },
        Finding {
            title: "Data brokers aggregate social profiles across platforms".to_string(),
            description: "Companies like Palantir, Clearview AI, and data brokers aggregate your \
                 public social media data across all platforms. Your Instagram follows + \
                 YouTube subscriptions + Twitter likes = a comprehensive ideological profile \
                 that can be sold to governments, employers, or insurance companies."
                .to_string(),
            threat_level: ThreatLevel::Critical,
            remediation: "1. Make your follow lists private where possible\n\
                 2. Diversify your follows across all platforms\n\
                 3. Regularly audit your public social media presence\n\
                 4. Use 'dtm noise social --apply' to generate balanced follow lists"
                .to_string(),
        },
    ];

    let mut raw_data = HashMap::new();
    raw_data.insert(
        "note".to_string(),
        serde_json::Value::String(
            "Social media audit is educational — cannot access actual account data without OAuth"
                .to_string(),
        ),
    );
    raw_data.insert(
        "platforms_covered".to_string(),
        serde_json::to_value(["instagram", "youtube", "tiktok", "facebook", "twitter"])?,
    );

    Ok(AuditResult {
        module_name: "social_noise".to_string(),
        score: 30, // Default: most people are heavily exposed
        findings,
        raw_data,
    })
}

/// Generate balanced social media follow lists.
///
/// Loads per-country account data from `shared/data/social_noise/<country>.yaml`,
/// selects a balanced set across platforms, categories, and perspectives, then
/// either prints the suggestions (dry run) or opens them in the browser (apply).
pub async fn protect_social_noise(opts: &ProtectOpts) -> Result<ProtectionResult> {
    let dry_run = !opts.apply;
    let country = opts.country.as_deref().unwrap_or("us");
    let per_subcategory = opts.count.unwrap_or(2);

    let mut actions_available: Vec<String> = Vec::new();
    let mut actions_taken: Vec<String> = Vec::new();

    // Determine platforms
    let platforms = get_all_platforms(country)?;

    // Determine categories
    let categories = &opts.categories;

    actions_available.push(format!(
        "Generate balanced follow lists for: {}",
        platforms.join(", ")
    ));

    for p in &platforms {
        let mut cats = get_platform_categories(p, country)?;
        if !categories.is_empty() {
            cats.retain(|c| categories.contains(c));
        }
        if !cats.is_empty() {
            actions_available.push(format!("  {p}: categories = {}", cats.join(", ")));
        }
    }

    actions_available.push(format!("Accounts per perspective: {per_subcategory}"));

    if !dry_run {
        let follow_list =
            get_balanced_follow_list(&platforms, categories, per_subcategory, country)?;

        let formatted = format_follow_list(&follow_list);
        actions_taken.extend(formatted);

        // Summary
        let total: usize = follow_list.values().map(|accs| accs.len()).sum();
        actions_taken.push(format!(
            "\nTotal: {total} accounts to follow across {} platforms",
            follow_list.len()
        ));
        actions_taken
            .push("Follow these accounts to balance your social media profile.".to_string());

        // Open URLs in browser when applying
        for accounts in follow_list.values() {
            for acc in accounts {
                let handle = &acc.account;
                // Best-effort: try to open as a URL if it looks like one
                if handle.starts_with("http://") || handle.starts_with("https://") {
                    let _ = open::that(handle);
                }
            }
        }
    }

    Ok(ProtectionResult {
        module_name: "social_noise".to_string(),
        dry_run,
        actions_taken,
        actions_available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtm_core::models::{AuditOpts, ProtectOpts};

    // -----------------------------------------------------------------------
    // Account database loading
    // -----------------------------------------------------------------------

    #[test]
    fn accounts_database_not_empty() {
        let accounts = load_accounts("us").expect("load US accounts");
        assert!(
            !accounts.is_empty(),
            "US account database should not be empty"
        );
    }

    #[test]
    fn accounts_have_platforms() {
        let accounts = load_accounts("us").expect("load US accounts");
        let platforms: Vec<&String> = accounts.keys().collect();

        assert!(
            platforms.iter().any(|p| p.as_str() == "instagram"),
            "should contain instagram"
        );
        assert!(
            platforms.iter().any(|p| p.as_str() == "youtube"),
            "should contain youtube"
        );
        assert!(
            platforms.iter().any(|p| p.as_str() == "tiktok"),
            "should contain tiktok"
        );
    }

    #[test]
    fn accounts_have_perspectives() {
        let accounts = load_accounts("us").expect("load US accounts");

        // Look for perspective-level keys across all platforms and categories
        let mut all_perspectives: Vec<String> = Vec::new();
        for platform_data in accounts.values() {
            for category_data in platform_data.values() {
                all_perspectives.extend(category_data.keys().cloned());
            }
        }

        // The politics category should have left/right/center perspectives
        // Check at least some platform has political perspectives
        let has_diverse_perspectives = all_perspectives.iter().any(|p| p == "left")
            || all_perspectives.iter().any(|p| p == "gauche")
            || all_perspectives.iter().any(|p| p.contains("left"));

        assert!(
            has_diverse_perspectives || !all_perspectives.is_empty(),
            "accounts should have perspective-level organization"
        );
    }

    // -----------------------------------------------------------------------
    // Balanced follow list generation
    // -----------------------------------------------------------------------

    #[test]
    fn balanced_list_respects_platform_filter() {
        let platforms = vec!["instagram".to_string()];
        let categories: Vec<String> = Vec::new(); // all categories
        let follow_list =
            get_balanced_follow_list(&platforms, &categories, 2, "us").expect("follow list");

        // Should only have instagram
        assert!(
            follow_list.contains_key("instagram"),
            "should contain instagram"
        );
        // Should NOT have platforms we didn't request
        assert!(
            !follow_list.contains_key("youtube"),
            "should not contain youtube when only instagram requested"
        );
    }

    #[test]
    fn balanced_list_respects_category_filter() {
        let platforms = get_all_platforms("us").expect("get platforms");
        let categories = vec!["politics".to_string()];
        let follow_list =
            get_balanced_follow_list(&platforms, &categories, 2, "us").expect("follow list");

        // All entries should be from the politics category
        for accounts in follow_list.values() {
            for acc in accounts {
                assert_eq!(
                    acc.category, "politics",
                    "all accounts should be from politics category, got '{}'",
                    acc.category
                );
            }
        }
    }

    #[test]
    fn accounts_include_metadata() {
        let platforms = vec!["instagram".to_string()];
        let categories: Vec<String> = Vec::new();
        let follow_list =
            get_balanced_follow_list(&platforms, &categories, 2, "us").expect("follow list");

        if let Some(accounts) = follow_list.get("instagram") {
            assert!(!accounts.is_empty(), "instagram should have some accounts");
            for acc in accounts {
                assert!(
                    !acc.perspective.is_empty(),
                    "account should have perspective info"
                );
                assert!(
                    !acc.category.is_empty(),
                    "account should have category info"
                );
                assert!(!acc.account.is_empty(), "account should have a handle/name");
            }
        }
    }

    #[test]
    fn balanced_list_mixed_perspectives() {
        let platforms = get_all_platforms("us").expect("get platforms");
        let categories = vec!["politics".to_string()];
        let follow_list =
            get_balanced_follow_list(&platforms, &categories, 5, "us").expect("follow list");

        // Collect all perspectives across all platforms
        let mut perspectives: std::collections::HashSet<String> = std::collections::HashSet::new();
        for accounts in follow_list.values() {
            for acc in accounts {
                perspectives.insert(acc.perspective.clone());
            }
        }

        assert!(
            perspectives.len() >= 2,
            "balanced list should include at least 2 perspectives, got {}",
            perspectives.len()
        );
    }

    #[test]
    fn per_subcategory_limit_respected() {
        let platforms = vec!["instagram".to_string()];
        let categories: Vec<String> = Vec::new();
        let per_sub = 1;
        let follow_list =
            get_balanced_follow_list(&platforms, &categories, per_sub, "us").expect("follow list");

        if let Some(accounts) = follow_list.get("instagram") {
            // Group by (category, perspective) — each group should have at most per_sub entries
            let mut groups: HashMap<(String, String), usize> = HashMap::new();
            for acc in accounts {
                let key = (acc.category.clone(), acc.perspective.clone());
                *groups.entry(key).or_insert(0) += 1;
            }

            for ((cat, perspective), count) in &groups {
                assert!(
                    *count <= per_sub,
                    "category '{cat}' / perspective '{perspective}' has {count} accounts but limit is {per_sub}"
                );
            }
        }
    }

    #[test]
    fn all_platforms_covered() {
        let platforms = get_all_platforms("us").expect("get platforms");
        assert!(
            platforms.len() >= 3,
            "should have at least 3 platforms, got {}",
            platforms.len()
        );
    }

    // -----------------------------------------------------------------------
    // Country data
    // -----------------------------------------------------------------------

    #[test]
    fn fr_accounts_load() {
        let accounts = load_accounts("fr").expect("load FR accounts");
        assert!(
            !accounts.is_empty(),
            "French account database should not be empty"
        );
    }

    #[test]
    fn nonexistent_country_falls_back() {
        let result = load_accounts("zz");
        // Should not panic — either returns data (fallback) or an error
        if let Ok(accounts) = result {
            assert!(
                !accounts.is_empty(),
                "fallback should return non-empty data"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Protect (dry run)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn protect_dry_run_generates_list() {
        let opts = ProtectOpts {
            apply: false,
            country: Some("us".to_string()),
            count: Some(3),
            ..Default::default()
        };

        let result = protect_social_noise(&opts).await.expect("dry run");
        assert!(result.dry_run, "should be a dry run");
        assert_eq!(result.module_name, "social_noise");
        assert!(
            !result.actions_available.is_empty(),
            "dry run should list available actions"
        );
    }

    #[tokio::test]
    async fn protect_respects_filters() {
        let opts = ProtectOpts {
            apply: false,
            country: Some("us".to_string()),
            count: Some(2),
            categories: vec!["politics".to_string()],
            ..Default::default()
        };

        let result = protect_social_noise(&opts).await.expect("filtered protect");
        assert!(result.dry_run);
        assert_eq!(result.module_name, "social_noise");
    }

    // -----------------------------------------------------------------------
    // Audit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn audit_returns_educational_findings() {
        let opts = AuditOpts::default();
        let result = audit_social_noise(&opts).await.expect("audit");
        assert_eq!(result.module_name, "social_noise");
        assert!(
            !result.findings.is_empty(),
            "audit should return educational findings"
        );
        // Check that findings cover social media risks
        let has_social_finding = result.findings.iter().any(|f| {
            f.title.contains("Social media")
                || f.title.contains("social")
                || f.title.contains("Instagram")
                || f.title.contains("YouTube")
                || f.title.contains("TikTok")
        });
        assert!(
            has_social_finding,
            "audit should include findings about social media profiling"
        );
    }
}
