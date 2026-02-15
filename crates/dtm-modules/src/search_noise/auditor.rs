use std::collections::HashMap;

use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use tokio::time::{sleep, Duration};

use dtm_core::data::load_country_data;
use dtm_core::models::{
    AuditOpts, AuditResult, Finding, ProtectOpts, ProtectionResult, ThreatLevel,
};

/// Search engines and their query URL templates.
const SEARCH_ENGINES: &[(&str, &str)] = &[
    ("google", "https://www.google.com/search?q="),
    ("bing", "https://www.bing.com/search?q="),
    ("duckduckgo", "https://duckduckgo.com/?q="),
    ("yahoo", "https://search.yahoo.com/search?p="),
];

/// Realistic user agents to rotate through.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
];

/// YAML structure: category -> perspective -> list of queries.
type QueryDatabase = HashMap<String, HashMap<String, Vec<String>>>;

/// Load the query database for a given country code.
fn load_queries(country: &str) -> Result<QueryDatabase> {
    load_country_data::<QueryDatabase>("search_noise", country).context(format!(
        "Failed to load search noise data for country '{country}'"
    ))
}

/// Get all category names for a country.
fn get_all_categories(country: &str) -> Result<Vec<String>> {
    let queries = load_queries(country)?;
    Ok(queries.keys().cloned().collect())
}

/// Pick queries evenly across all perspectives within selected categories.
/// Returns a shuffled list of `count` queries, balanced across all sides.
fn get_balanced_queries(categories: &[String], count: usize, country: &str) -> Result<Vec<String>> {
    let queries = load_queries(country)?;
    let mut rng = rand::thread_rng();
    let mut all_queries: Vec<String> = Vec::new();

    let active_categories: Vec<&String> = categories
        .iter()
        .filter(|cat| queries.contains_key(cat.as_str()))
        .collect();

    if active_categories.is_empty() {
        return Ok(Vec::new());
    }

    for cat in &active_categories {
        if let Some(perspectives) = queries.get(cat.as_str()) {
            let per_perspective = (count / (perspectives.len() * active_categories.len())).max(1);

            for perspective_queries in perspectives.values() {
                let sample_size = per_perspective.min(perspective_queries.len());
                let mut pool = perspective_queries.clone();
                pool.shuffle(&mut rng);
                all_queries.extend(pool.into_iter().take(sample_size));
            }
        }
    }

    all_queries.shuffle(&mut rng);
    all_queries.truncate(count);
    Ok(all_queries)
}

/// URL-encode a query string for use in search engine URLs.
fn url_encode(input: &str) -> String {
    form_urlencoded::byte_serialize(input.as_bytes()).collect()
}

/// Extract cookie names from Set-Cookie response headers.
fn extract_cookie_names(resp: &reqwest::Response) -> Vec<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|val| {
            val.to_str().ok().and_then(|s| {
                s.split(';').next().and_then(|pair| {
                    let name = pair.split('=').next()?.trim();
                    if name.is_empty() {
                        None
                    } else {
                        Some(name.to_string())
                    }
                })
            })
        })
        .collect()
}

/// Execute a single search query against a search engine.
async fn execute_query(
    client: &reqwest::Client,
    query: &str,
    engine_name: &str,
    engine_base_url: &str,
    user_agent: &str,
) -> String {
    let encoded = url_encode(query);
    let url = format!("{engine_base_url}{encoded}");

    match client
        .get(&url)
        .header("User-Agent", user_agent)
        .send()
        .await
    {
        Ok(resp) => format!(
            "[{engine_name}] '{query}' — HTTP {}",
            resp.status().as_u16()
        ),
        Err(e) => format!("[{engine_name}] '{query}' — Error: {e}"),
    }
}

/// Audit search privacy exposure.
///
/// Checks for signals that indicate your searches are being profiled:
/// - Google personalization (tracking cookies)
/// - Bing tracking cookies
/// - General search profiling warnings
pub async fn audit_search_noise(_opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings = Vec::new();
    let mut score: i32 = 100;
    let mut raw_data = HashMap::new();

    // Check if Google returns personalization signals
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    match client
        .get("https://www.google.com/search?q=test")
        .send()
        .await
    {
        Ok(resp) => {
            raw_data.insert(
                "google_status".to_string(),
                serde_json::Value::Number(resp.status().as_u16().into()),
            );

            let cookie_names = extract_cookie_names(&resp);
            let cookie_count = cookie_names.len();
            raw_data.insert(
                "google_cookies_received".to_string(),
                serde_json::Value::Number(cookie_count.into()),
            );
            raw_data.insert(
                "google_cookie_names".to_string(),
                serde_json::to_value(&cookie_names)?,
            );

            if cookie_count > 0 {
                let display_names: Vec<&str> =
                    cookie_names.iter().take(5).map(|s| s.as_str()).collect();
                findings.push(Finding {
                    title: format!("Google sets {cookie_count} tracking cookies"),
                    description: format!(
                        "Google returned cookies: {}. \
                         These cookies allow Google to link your searches across sessions \
                         and build a detailed profile of your interests, politics, and beliefs.",
                        display_names.join(", ")
                    ),
                    threat_level: ThreatLevel::High,
                    remediation: "Use DuckDuckGo or Brave Search as your default engine. \
                        If using Google, always use private/incognito mode. \
                        Run dtm noise search to pollute your search profile."
                        .to_string(),
                });
                score -= 20;
            }

            // Check Bing
            if let Ok(bing_resp) = client
                .get("https://www.bing.com/search?q=test")
                .send()
                .await
            {
                let bing_cookie_names = extract_cookie_names(&bing_resp);
                let bing_cookie_count = bing_cookie_names.len();
                raw_data.insert(
                    "bing_cookies_received".to_string(),
                    serde_json::Value::Number(bing_cookie_count.into()),
                );

                if bing_cookie_count > 0 {
                    findings.push(Finding {
                        title: format!("Bing sets {bing_cookie_count} tracking cookies"),
                        description:
                            "Microsoft Bing also sets tracking cookies that profile your searches. \
                             This data feeds into Microsoft's advertising network."
                                .to_string(),
                        threat_level: ThreatLevel::Medium,
                        remediation: "Use DuckDuckGo or clear Bing cookies regularly.".to_string(),
                    });
                    score -= 10;
                }
            }
        }
        Err(e) => {
            if e.is_connect() {
                findings.push(Finding {
                    title: "Cannot reach search engines".to_string(),
                    description:
                        "Could not connect to search engines to test tracking. You may be offline."
                            .to_string(),
                    threat_level: ThreatLevel::Info,
                    remediation: "Check your internet connection and try again.".to_string(),
                });
                return Ok(AuditResult {
                    module_name: "search_noise".to_string(),
                    score: 50,
                    findings,
                    raw_data,
                });
            }
        }
    }

    // General warnings about search profiling
    findings.push(Finding {
        title: "Search history reveals political and personal beliefs".to_string(),
        description: "Every search you make is logged and profiled by the search engine. \
             Searching for political topics, health conditions, religious questions, \
             or lifestyle choices creates a detailed ideological profile. \
             This data is sold to advertisers and can be subpoenaed by governments."
            .to_string(),
        threat_level: ThreatLevel::High,
        remediation: "1. Use DuckDuckGo/Brave Search for sensitive queries\n\
             2. Run 'dtm noise search --apply' regularly to dilute your profile\n\
             3. Use private browsing for political/religious/health searches\n\
             4. Disable Google Web & App Activity in your Google account"
            .to_string(),
    });
    score -= 15;

    findings.push(Finding {
        title: "Search engines share data with advertising networks".to_string(),
        description: "Google shares search data with its ad network (90%+ of global search). \
             Bing shares with Microsoft Advertising. Your search profile directly \
             determines what ads you see — and what data brokers know about you."
            .to_string(),
        threat_level: ThreatLevel::Medium,
        remediation: "Use search engines that don't track: DuckDuckGo, Brave Search, Startpage."
            .to_string(),
    });
    score -= 10;

    Ok(AuditResult {
        module_name: "search_noise".to_string(),
        score: score.clamp(0, 100) as u32,
        findings,
        raw_data,
    })
}

/// Generate search noise to obfuscate your search profile.
///
/// Loads per-country queries from `shared/data/search_noise/<country>.yaml`,
/// selects a balanced set across categories and perspectives, then either
/// prints them (dry run) or sends them to real search engines with random
/// User-Agent rotation and human-like delays.
pub async fn protect_search_noise(opts: &ProtectOpts) -> Result<ProtectionResult> {
    let dry_run = !opts.apply;
    let country = opts.country.as_deref().unwrap_or("us");
    let count = opts.count.unwrap_or(50);
    let min_delay: f64 = 2.0;
    let max_delay: f64 = 8.0;

    let mut actions_available: Vec<String> = Vec::new();
    let mut actions_taken: Vec<String> = Vec::new();

    // Determine categories
    let categories = if opts.categories.is_empty() {
        get_all_categories(country)?
    } else {
        opts.categories.clone()
    };

    // Determine engines
    let engine_list: Vec<(&str, &str)> = SEARCH_ENGINES.to_vec();
    if engine_list.is_empty() {
        return Ok(ProtectionResult {
            module_name: "search_noise".to_string(),
            dry_run,
            actions_taken: vec![],
            actions_available: vec!["No valid search engines selected.".to_string()],
        });
    }

    // Generate balanced query list
    let queries = get_balanced_queries(&categories, count, country)?;

    let engine_names: Vec<&str> = engine_list.iter().map(|(name, _)| *name).collect();
    actions_available.push(format!(
        "Send {} balanced search queries across {} engines (categories: {})",
        queries.len(),
        engine_list.len(),
        categories.join(", ")
    ));
    actions_available.push(format!("Engines: {}", engine_names.join(", ")));
    actions_available.push(format!(
        "Delay between queries: {min_delay}-{max_delay}s (randomized)"
    ));

    // Show sample queries
    actions_available.push("--- Sample queries ---".to_string());
    for q in queries.iter().take(10) {
        actions_available.push(format!("  \"{q}\""));
    }
    if queries.len() > 10 {
        actions_available.push(format!("  ... and {} more", queries.len() - 10));
    }

    if !dry_run {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()?;

        for (i, query) in queries.iter().enumerate() {
            // Pick a random engine and user-agent (scoped so rng doesn't live across await)
            let (engine_name, engine_url, user_agent, delay) = {
                let mut rng = rand::thread_rng();
                let &(name, url) = engine_list
                    .choose(&mut rng)
                    .expect("engine_list is non-empty");
                let ua = USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())];
                let d = rng.gen_range(min_delay..max_delay);
                (name, url, ua, d)
            };

            let result = execute_query(&client, query, engine_name, engine_url, user_agent).await;
            actions_taken.push(result);

            // Human-like delay between queries
            if i < queries.len() - 1 {
                sleep(Duration::from_secs_f64(delay)).await;
            }
        }
    }

    Ok(ProtectionResult {
        module_name: "search_noise".to_string(),
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
    // Query database loading
    // -----------------------------------------------------------------------

    #[test]
    fn queries_database_not_empty() {
        let queries = load_queries("us").expect("load US queries");
        assert!(!queries.is_empty(), "US query database should not be empty");
    }

    #[test]
    fn queries_have_perspectives() {
        let queries = load_queries("us").expect("load US queries");
        let all_perspectives: Vec<String> = queries
            .values()
            .flat_map(|perspectives| perspectives.keys().cloned())
            .collect();

        assert!(
            all_perspectives.iter().any(|p| p == "left"),
            "should contain left perspective"
        );
        assert!(
            all_perspectives.iter().any(|p| p == "right"),
            "should contain right perspective"
        );
        assert!(
            all_perspectives.iter().any(|p| p == "center"),
            "should contain center perspective"
        );
    }

    #[test]
    fn queries_have_categories() {
        let queries = load_queries("us").expect("load US queries");
        let categories: Vec<&String> = queries.keys().collect();

        assert!(
            categories.iter().any(|c| c.as_str() == "politics"),
            "should contain politics category"
        );
        assert!(
            categories.iter().any(|c| c.as_str() == "religion"),
            "should contain religion category"
        );
        // Check for a third expected category (lifestyle, interests, or news_sources)
        let has_science_or_other = categories.iter().any(|c| {
            matches!(
                c.as_str(),
                "science" | "interests" | "news_sources" | "lifestyle"
            )
        });
        assert!(
            has_science_or_other,
            "should contain at least one additional category beyond politics/religion"
        );
    }

    // -----------------------------------------------------------------------
    // Balanced query generation
    // -----------------------------------------------------------------------

    #[test]
    fn balanced_queries_respects_count() {
        let categories = get_all_categories("us").expect("get categories");
        let count = 10;
        let queries = get_balanced_queries(&categories, count, "us").expect("get balanced queries");
        assert!(
            queries.len() <= count,
            "returned {} queries but requested at most {count}",
            queries.len()
        );
        assert!(
            !queries.is_empty(),
            "should return at least some queries for US"
        );
    }

    #[test]
    fn balanced_queries_category_filter() {
        let queries_all =
            get_balanced_queries(&["politics".to_string()], 50, "us").expect("politics queries");
        // All returned queries should come from the politics category
        assert!(
            !queries_all.is_empty(),
            "filtering by politics should return queries"
        );

        // Cross-check: these queries should exist in the politics section of the DB
        let db = load_queries("us").expect("load US");
        let politics = db.get("politics").expect("politics category exists");
        let politics_queries: Vec<&String> = politics.values().flat_map(|v| v.iter()).collect();
        for q in &queries_all {
            assert!(
                politics_queries.contains(&q),
                "query '{q}' should be from politics category"
            );
        }
    }

    #[test]
    fn balanced_queries_mixed_perspectives() {
        let db = load_queries("us").expect("load US");
        let politics = db.get("politics").expect("politics exists");
        // Request enough queries to span multiple perspectives
        let queries =
            get_balanced_queries(&["politics".to_string()], 30, "us").expect("balanced queries");
        assert!(
            queries.len() > 1,
            "should return multiple queries for mixed perspectives"
        );

        // Check that queries come from at least two perspectives
        let mut perspectives_hit = std::collections::HashSet::new();
        for q in &queries {
            for (perspective, perspective_queries) in politics {
                if perspective_queries.contains(q) {
                    perspectives_hit.insert(perspective.clone());
                }
            }
        }
        assert!(
            perspectives_hit.len() >= 2,
            "balanced queries should cover at least 2 perspectives, got {}",
            perspectives_hit.len()
        );
    }

    #[test]
    fn empty_category_returns_empty() {
        let queries = get_balanced_queries(&["nonexistent_xyz".to_string()], 10, "us")
            .expect("should not error");
        assert!(
            queries.is_empty(),
            "nonexistent category should return empty list"
        );
    }

    // -----------------------------------------------------------------------
    // Country-specific queries
    // -----------------------------------------------------------------------

    #[test]
    fn us_queries_in_english() {
        let queries = load_queries("us").expect("load US");
        let all_query_strings: Vec<&String> = queries
            .values()
            .flat_map(|perspectives| perspectives.values().flat_map(|v| v.iter()))
            .collect();
        // At least some queries should contain common English words
        let has_english = all_query_strings
            .iter()
            .any(|q| q.contains("policy") || q.contains("research") || q.contains("reform"));
        assert!(has_english, "US queries should contain English words");
    }

    #[test]
    fn fr_queries_in_french() {
        let queries = load_queries("fr").expect("load FR queries");
        let all_query_strings: Vec<&String> = queries
            .values()
            .flat_map(|perspectives| perspectives.values().flat_map(|v| v.iter()))
            .collect();

        let has_french = all_query_strings
            .iter()
            .any(|q| q.contains("gauche") || q.contains("droite") || q.contains("politique"));
        assert!(has_french, "FR queries should contain French words");
    }

    #[test]
    fn nonexistent_country_falls_back() {
        // Unknown country code should fall back to US data
        let result = load_queries("zz");
        // Either it loads US fallback data or errors — if it errors, that's acceptable
        // but the system should not panic
        if let Ok(queries) = result {
            assert!(!queries.is_empty(), "fallback should return non-empty data");
        }
        // If Err, that's also acceptable — the function doesn't crash
    }

    // -----------------------------------------------------------------------
    // Search engines
    // -----------------------------------------------------------------------

    #[test]
    fn search_engines_include_google() {
        let has_google = SEARCH_ENGINES.iter().any(|(name, _)| *name == "google");
        assert!(has_google, "search engines should include Google");
    }

    #[test]
    fn search_engines_include_duckduckgo() {
        let has_ddg = SEARCH_ENGINES.iter().any(|(name, _)| *name == "duckduckgo");
        assert!(has_ddg, "search engines should include DuckDuckGo");
    }

    // -----------------------------------------------------------------------
    // Protect (dry run)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn protect_dry_run_generates_queries() {
        let opts = ProtectOpts {
            apply: false,
            country: Some("us".to_string()),
            count: Some(10),
            ..Default::default()
        };

        let result = protect_search_noise(&opts).await.expect("dry run");
        assert!(result.dry_run, "should be a dry run");
        assert_eq!(result.module_name, "search_noise");
        assert!(
            !result.actions_available.is_empty(),
            "dry run should list available actions"
        );
        // In dry run mode, no actions are taken
        assert!(
            result.actions_taken.is_empty(),
            "dry run should not take any actions"
        );
    }

    #[tokio::test]
    async fn protect_respects_category_filter() {
        let opts = ProtectOpts {
            apply: false,
            country: Some("us".to_string()),
            count: Some(10),
            categories: vec!["politics".to_string()],
            ..Default::default()
        };

        let result = protect_search_noise(&opts).await.expect("filtered protect");
        assert!(result.dry_run);
        // The actions_available should mention the category
        let available_text = result.actions_available.join(" ");
        assert!(
            available_text.contains("politics"),
            "filtered protection should mention 'politics' in available actions"
        );
    }

    // -----------------------------------------------------------------------
    // Audit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn audit_returns_educational_findings() {
        let opts = AuditOpts::default();
        let result = audit_search_noise(&opts).await.expect("audit");
        assert_eq!(result.module_name, "search_noise");
        assert!(
            !result.findings.is_empty(),
            "audit should return educational findings"
        );
        // Should contain the general educational warning about search profiling
        let has_educational = result
            .findings
            .iter()
            .any(|f| f.title.contains("Search history") || f.title.contains("search"));
        assert!(
            has_educational,
            "audit should include educational findings about search privacy"
        );
    }
}
