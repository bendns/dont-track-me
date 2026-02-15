//! Subreddit classification database for bias analysis and diversification.

use std::collections::HashMap;

use rand::seq::SliceRandom;

/// All subreddits organized by category and perspective.
pub fn subreddit_db() -> HashMap<&'static str, HashMap<&'static str, Vec<&'static str>>> {
    let mut db = HashMap::new();

    // Politics
    let mut politics = HashMap::new();
    politics.insert(
        "left",
        vec![
            "progressive",
            "SandersForPresident",
            "DemocraticSocialism",
            "socialism",
            "LateStageCapitalism",
            "antiwork",
            "GreenParty",
            "WayOfTheBern",
            "Political_Revolution",
        ],
    );
    politics.insert(
        "right",
        vec![
            "Conservative",
            "Republican",
            "Libertarian",
            "Anarcho_Capitalism",
            "walkaway",
            "LouderWithCrowder",
            "JordanPeterson",
            "benshapiro",
            "TimPool",
        ],
    );
    politics.insert(
        "center",
        vec![
            "moderatepolitics",
            "centrist",
            "NeutralPolitics",
            "PoliticalDiscussion",
            "neoliberal",
            "tuesday",
            "Ask_Politics",
            "PoliticalPhilosophy",
        ],
    );
    politics.insert(
        "international",
        vec![
            "worldpolitics",
            "geopolitics",
            "europe",
            "ukpolitics",
            "CanadaPolitics",
            "AustralianPolitics",
            "IndianPolitics",
            "france",
            "de",
        ],
    );
    db.insert("politics", politics);

    // News
    let mut news = HashMap::new();
    news.insert(
        "mainstream",
        vec![
            "news",
            "worldnews",
            "UpliftingNews",
            "nottheonion",
            "inthenews",
        ],
    );
    news.insert(
        "investigative",
        vec![
            "journalism",
            "media_criticism",
            "Documentaries",
            "longform",
            "TrueReddit",
        ],
    );
    news.insert(
        "local",
        vec![
            "nyc",
            "LosAngeles",
            "chicago",
            "bayarea",
            "london",
            "toronto",
        ],
    );
    db.insert("news", news);

    // Religion
    let mut religion = HashMap::new();
    religion.insert(
        "christianity",
        vec![
            "Christianity",
            "Catholicism",
            "OrthodoxChristianity",
            "Reformed",
            "OpenChristian",
        ],
    );
    religion.insert(
        "islam",
        vec![
            "islam",
            "progressive_islam",
            "MuslimLounge",
            "converts",
            "Sufism",
        ],
    );
    religion.insert("judaism", vec!["Judaism", "Jewish", "jewishguns"]);
    religion.insert(
        "buddhism",
        vec!["Buddhism", "zenbuddhism", "theravada", "Meditation"],
    );
    religion.insert("hinduism", vec!["hinduism", "yoga", "Vedanta"]);
    religion.insert(
        "atheism",
        vec![
            "atheism",
            "TrueAtheism",
            "DebateAnAtheist",
            "humanism",
            "secularism",
        ],
    );
    db.insert("religion", religion);

    // Science & Tech
    let mut science_tech = HashMap::new();
    science_tech.insert(
        "science",
        vec![
            "science",
            "askscience",
            "EverythingScience",
            "space",
            "physics",
            "biology",
        ],
    );
    science_tech.insert(
        "technology",
        vec![
            "technology",
            "programming",
            "linux",
            "opensource",
            "netsec",
            "privacy",
        ],
    );
    science_tech.insert(
        "ai",
        vec![
            "MachineLearning",
            "artificial",
            "ChatGPT",
            "LocalLLaMA",
            "singularity",
        ],
    );
    db.insert("science_tech", science_tech);

    // Culture
    let mut culture = HashMap::new();
    culture.insert(
        "music",
        vec![
            "Music",
            "hiphopheads",
            "Metal",
            "classicalmusic",
            "Jazz",
            "kpop",
            "country",
            "indieheads",
            "EDM",
        ],
    );
    culture.insert(
        "art",
        vec![
            "Art",
            "museum",
            "ArtHistory",
            "StreetArt",
            "photography",
            "cinema",
        ],
    );
    culture.insert(
        "books",
        vec![
            "books",
            "literature",
            "suggestmeabook",
            "philosophy",
            "history",
        ],
    );
    culture.insert(
        "sports",
        vec![
            "sports", "soccer", "nba", "nfl", "formula1", "Cricket", "tennis", "MMA", "running",
        ],
    );
    db.insert("culture", culture);

    // Lifestyle
    let mut lifestyle = HashMap::new();
    lifestyle.insert(
        "cooking",
        vec![
            "Cooking",
            "food",
            "MealPrepSunday",
            "AskCulinary",
            "veganrecipes",
            "BBQ",
        ],
    );
    lifestyle.insert(
        "outdoors",
        vec![
            "hiking",
            "camping",
            "fishing",
            "gardening",
            "Bushcraft",
            "birdwatching",
        ],
    );
    lifestyle.insert(
        "fitness",
        vec![
            "Fitness",
            "bodyweightfitness",
            "running",
            "yoga",
            "CrossFit",
            "Swimming",
        ],
    );
    lifestyle.insert(
        "gaming",
        vec![
            "gaming",
            "pcgaming",
            "PS5",
            "NintendoSwitch",
            "patientgamers",
            "boardgames",
        ],
    );
    db.insert("lifestyle", lifestyle);

    db
}

/// Get all category names.
pub fn get_all_categories() -> Vec<&'static str> {
    vec![
        "politics",
        "news",
        "religion",
        "science_tech",
        "culture",
        "lifestyle",
    ]
}

/// Classify a subreddit by category and perspective.
/// Returns `(category, perspective)` or `None` if unknown.
pub fn classify_subreddit(name: &str) -> Option<(&'static str, &'static str)> {
    let name_lower = name.to_lowercase();
    let db = subreddit_db();

    for (category, perspectives) in &db {
        for (perspective, subs) in perspectives {
            if subs.iter().any(|s| s.to_lowercase() == name_lower) {
                return Some((category, perspective));
            }
        }
    }
    None
}

/// Pick subreddits evenly across all perspectives.
/// Returns list of `(subreddit, category, perspective)`.
pub fn get_balanced_subreddits(
    categories: Option<&[String]>,
    per_perspective: usize,
) -> Vec<(String, String, String)> {
    let db = subreddit_db();
    let all_cats = get_all_categories();
    let cat_list: Vec<&str> = match categories {
        Some(cats) => cats.iter().map(|c| c.as_str()).collect(),
        None => all_cats,
    };

    let mut rng = rand::thread_rng();
    let mut result = Vec::new();

    for cat in &cat_list {
        if let Some(perspectives) = db.get(cat) {
            for (perspective, subs) in perspectives {
                let sample_size = per_perspective.min(subs.len());
                let mut shuffled = subs.clone();
                shuffled.shuffle(&mut rng);
                for sub in shuffled.into_iter().take(sample_size) {
                    result.push((sub.to_string(), cat.to_string(), perspective.to_string()));
                }
            }
        }
    }

    result.shuffle(&mut rng);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_subreddit() {
        let result = classify_subreddit("Conservative");
        assert_eq!(result, Some(("politics", "right")));
    }

    #[test]
    fn classify_case_insensitive() {
        let result = classify_subreddit("conservative");
        assert_eq!(result, Some(("politics", "right")));
    }

    #[test]
    fn classify_unknown_subreddit() {
        assert!(classify_subreddit("some_random_sub_xyz").is_none());
    }

    #[test]
    fn get_balanced_returns_entries() {
        let result = get_balanced_subreddits(None, 1);
        assert!(!result.is_empty());
        // Each entry should have non-empty fields
        for (sub, cat, perspective) in &result {
            assert!(!sub.is_empty());
            assert!(!cat.is_empty());
            assert!(!perspective.is_empty());
        }
    }

    #[test]
    fn get_balanced_respects_categories_filter() {
        let cats = vec!["politics".to_string()];
        let result = get_balanced_subreddits(Some(&cats), 1);
        assert!(!result.is_empty());
        for (_, cat, _) in &result {
            assert_eq!(cat, "politics");
        }
    }

    #[test]
    fn all_categories_contains_expected() {
        let cats = get_all_categories();
        assert!(cats.contains(&"politics"));
        assert!(cats.contains(&"news"));
        assert!(cats.contains(&"religion"));
        assert!(cats.contains(&"science_tech"));
        assert!(cats.contains(&"culture"));
        assert!(cats.contains(&"lifestyle"));
    }
}
