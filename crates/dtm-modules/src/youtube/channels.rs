//! YouTube channel classification database for bias analysis and diversification.
//!
//! Channel IDs are the stable identifier (handles/names can change).

use std::collections::HashMap;

use rand::seq::SliceRandom;

/// A YouTube channel with its stable ID and display name.
#[derive(Debug, Clone)]
pub struct Channel {
    pub id: &'static str,
    pub name: &'static str,
}

/// All channels organized by category and perspective.
pub fn channel_db() -> HashMap<&'static str, HashMap<&'static str, Vec<Channel>>> {
    let mut db = HashMap::new();

    // Politics
    let mut politics = HashMap::new();
    politics.insert(
        "left",
        vec![
            Channel {
                id: "UC1yBKRuGpC1tSM73A0ZjYjQ",
                name: "The Young Turks",
            },
            Channel {
                id: "UCtoaZpBnrd0lhycxYJ0QWIA",
                name: "HasanAbi",
            },
            Channel {
                id: "UCNvsIonJdJ5E4EXMa65VYpA",
                name: "ContraPoints",
            },
            Channel {
                id: "UC2PA-AKmVpU6NKCGtZq_rKQ",
                name: "Philosophy Tube",
            },
            Channel {
                id: "UCvlj0IzjSnNoIn1fwY3Kngg",
                name: "Some More News",
            },
        ],
    );
    politics.insert(
        "right",
        vec![
            Channel {
                id: "UCnQC_G5Xsjhp9fEJKuIcrSw",
                name: "Ben Shapiro",
            },
            Channel {
                id: "UCJdKr0Bgd_5saZYqLCa9mng",
                name: "PragerU",
            },
            Channel {
                id: "UCL_f53ZEJxp8TtlOkHwMV9Q",
                name: "Jordan B Peterson",
            },
            Channel {
                id: "UCIveFvW-ARp_B_RckhKnM5A",
                name: "Steven Crowder",
            },
            Channel {
                id: "UCnQFq8M1ceN3saFRfOaHBqw",
                name: "Matt Walsh",
            },
        ],
    );
    politics.insert(
        "center",
        vec![
            Channel {
                id: "UCuMo0RRtnNDuMB8DV5stEag",
                name: "Breaking Points",
            },
            Channel {
                id: "UCPQXVp2WiKm-8DKD0lN_zYQ",
                name: "The Hill",
            },
            Channel {
                id: "UCe02lGcO-ahAURWuxAJnjdA",
                name: "Tim Pool",
            },
            Channel {
                id: "UCsXVk37bltHxD1rDPwtNM8Q",
                name: "Kurzgesagt",
            },
        ],
    );
    politics.insert(
        "international",
        vec![
            Channel {
                id: "UCknLrEdhRCp1aegoMqRaCZg",
                name: "DW News",
            },
            Channel {
                id: "UCQfwfsi5VrQ8yKZ-UWmAEFg",
                name: "France 24 English",
            },
            Channel {
                id: "UCNye-wNBqNL5ZzHSJj3l8Bg",
                name: "Al Jazeera English",
            },
            Channel {
                id: "UCHDkGM1Gp9ZGl7IQ1NO6gBw",
                name: "WION",
            },
            Channel {
                id: "UC7fWeaHhqgM4Lba7jedRkVw",
                name: "TRT World",
            },
        ],
    );
    db.insert("politics", politics);

    // Education
    let mut education = HashMap::new();
    education.insert(
        "science",
        vec![
            Channel {
                id: "UCHnyfMqiRRG1u-2MsSQLbXA",
                name: "Veritasium",
            },
            Channel {
                id: "UCsXVk37bltHxD1rDPwtNM8Q",
                name: "Kurzgesagt",
            },
            Channel {
                id: "UC6107grRI4m0o2-emgoDnAA",
                name: "SmarterEveryDay",
            },
            Channel {
                id: "UCo8bcnLyZH8tBIH9V1mLgqQ",
                name: "PBS Space Time",
            },
            Channel {
                id: "UCYO_jab_esuFRV4b17AJtAw",
                name: "3Blue1Brown",
            },
        ],
    );
    education.insert(
        "history",
        vec![
            Channel {
                id: "UCNIuvl7V8cR6x3N1OGYAi0w",
                name: "Oversimplified",
            },
            Channel {
                id: "UC22BdTgxefuvUivrMic_GkQ",
                name: "History Matters",
            },
            Channel {
                id: "UCMmaBzfCCwZ2KqaBJjkj0fw",
                name: "Kings and Generals",
            },
            Channel {
                id: "UCCODtTcd5M1JavPCOr_Uydg",
                name: "Extra History",
            },
        ],
    );
    education.insert(
        "philosophy",
        vec![
            Channel {
                id: "UCiRiQGCHGjDLT9FQXFW0I3A",
                name: "Academy of Ideas",
            },
            Channel {
                id: "UCVBQ399Z65GkMPoOpTOkaHg",
                name: "Einzelgänger",
            },
            Channel {
                id: "UCgNg3vwj3xt7QOrcIDaHdFg",
                name: "Then & Now",
            },
            Channel {
                id: "UC9yt3wz-6j19RwD5m5f6HSg",
                name: "Pursuit of Wonder",
            },
        ],
    );
    education.insert(
        "technology",
        vec![
            Channel {
                id: "UCXuqSBlHAE6Xw-yeJA0Tunw",
                name: "Linus Tech Tips",
            },
            Channel {
                id: "UCBJycsmduvYEL83R_U4JriQ",
                name: "MKBHD",
            },
            Channel {
                id: "UCsBjURrPoezykLs9EqgamOA",
                name: "Fireship",
            },
            Channel {
                id: "UCVls1GmFKf6WlTraIb_IaJg",
                name: "NetworkChuck",
            },
        ],
    );
    db.insert("education", education);

    // Entertainment
    let mut entertainment = HashMap::new();
    entertainment.insert(
        "gaming",
        vec![
            Channel {
                id: "UC-lHJZR3Gqxm24_Vd_AJ5Yw",
                name: "PewDiePie",
            },
            Channel {
                id: "UC7_YxT-KID8kRbqZo7MyscQ",
                name: "Markiplier",
            },
            Channel {
                id: "UCYzPXprvl5Y-Sf0g4vX-m6g",
                name: "jacksepticeye",
            },
            Channel {
                id: "UCX6OQ3DkcsbYNE6H8uQQuVA",
                name: "MrBeast",
            },
        ],
    );
    entertainment.insert(
        "music",
        vec![
            Channel {
                id: "UC2Qw1dzXDBAZPwS7zm37g8g",
                name: "COLORS",
            },
            Channel {
                id: "UC4eYXhJI4-7wSWc8UNRwD4A",
                name: "NPR Tiny Desk",
            },
        ],
    );
    entertainment.insert(
        "comedy",
        vec![
            Channel {
                id: "UCx-KWLTKlB83hDI6UKECtJQ",
                name: "Key & Peele",
            },
            Channel {
                id: "UCqFzWxSCi39LnW1JKFR3oGQ",
                name: "Saturday Night Live",
            },
            Channel {
                id: "UCwWhs_6x42TyRM4Wstoq8HA",
                name: "The Daily Show",
            },
            Channel {
                id: "UCPDis9pjXuqyI7RYLJ-TTSA",
                name: "Russell Howard",
            },
        ],
    );
    entertainment.insert(
        "cooking",
        vec![
            Channel {
                id: "UCJHA_jMfCvEnv-3kRjTCQXw",
                name: "Binging with Babish",
            },
            Channel {
                id: "UCcjhYlDx7SRyCP6LVlad2hQ",
                name: "Joshua Weissman",
            },
            Channel {
                id: "UC8gFadPgK2r1ndqLI04Xvvw",
                name: "Maangchi",
            },
        ],
    );
    db.insert("entertainment", entertainment);

    // Sports
    let mut sports = HashMap::new();
    sports.insert(
        "football",
        vec![
            Channel {
                id: "UCGlUhRSdRSGm3P7FwJ9YNtQ",
                name: "Copa90",
            },
            Channel {
                id: "UCqZQlzSHbVJrwrn5XvzrG0g",
                name: "GOAL",
            },
        ],
    );
    sports.insert(
        "fitness",
        vec![
            Channel {
                id: "UCe0TLA0EsQbE-MjuHXevj2A",
                name: "ATHLEAN-X",
            },
            Channel {
                id: "UCERm5yFZ1SptUEU4wZ2vJvw",
                name: "Jeff Nippard",
            },
            Channel {
                id: "UCFKE7WVJfvaHW5q283SxchA",
                name: "Yoga With Adriene",
            },
        ],
    );
    db.insert("sports", sports);

    db
}

/// Get all category names.
pub fn get_all_categories() -> Vec<&'static str> {
    vec!["politics", "education", "entertainment", "sports"]
}

/// Classify a channel by its ID.
/// Returns `(category, perspective, name)` or `None` if unknown.
pub fn classify_channel(channel_id: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let db = channel_db();
    for (category, perspectives) in &db {
        for (perspective, channels) in perspectives {
            for ch in channels {
                if ch.id == channel_id {
                    return Some((category, perspective, ch.name));
                }
            }
        }
    }
    None
}

/// Pick channels evenly across all perspectives.
/// Returns list of `(channel_id, name, category, perspective)`.
pub fn get_balanced_channels(
    categories: Option<&[String]>,
    per_perspective: usize,
) -> Vec<(String, String, String, String)> {
    let db = channel_db();
    let all_cats = get_all_categories();
    let cat_list: Vec<&str> = match categories {
        Some(cats) => cats.iter().map(|c| c.as_str()).collect(),
        None => all_cats,
    };

    let mut rng = rand::thread_rng();
    let mut result = Vec::new();

    for cat in &cat_list {
        if let Some(perspectives) = db.get(cat) {
            for (perspective, channels) in perspectives {
                let sample_size = per_perspective.min(channels.len());
                let mut shuffled = channels.clone();
                shuffled.shuffle(&mut rng);
                for ch in shuffled.into_iter().take(sample_size) {
                    result.push((
                        ch.id.to_string(),
                        ch.name.to_string(),
                        cat.to_string(),
                        perspective.to_string(),
                    ));
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
    fn classify_known_channel() {
        let result = classify_channel("UCnQC_G5Xsjhp9fEJKuIcrSw");
        assert!(result.is_some());
        let (cat, perspective, name) = result.unwrap();
        assert_eq!(cat, "politics");
        assert_eq!(perspective, "right");
        assert_eq!(name, "Ben Shapiro");
    }

    #[test]
    fn classify_unknown_channel() {
        assert!(classify_channel("UC_NONEXISTENT_123").is_none());
    }

    #[test]
    fn get_balanced_returns_entries() {
        let result = get_balanced_channels(None, 1);
        assert!(!result.is_empty());
        for (id, name, cat, perspective) in &result {
            assert!(!id.is_empty());
            assert!(!name.is_empty());
            assert!(!cat.is_empty());
            assert!(!perspective.is_empty());
        }
    }

    #[test]
    fn get_balanced_respects_categories_filter() {
        let cats = vec!["sports".to_string()];
        let result = get_balanced_channels(Some(&cats), 1);
        assert!(!result.is_empty());
        for (_, _, cat, _) in &result {
            assert_eq!(cat, "sports");
        }
    }

    #[test]
    fn all_categories_contains_expected() {
        let cats = get_all_categories();
        assert!(cats.contains(&"politics"));
        assert!(cats.contains(&"education"));
        assert!(cats.contains(&"entertainment"));
        assert!(cats.contains(&"sports"));
    }
}
