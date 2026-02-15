//! Reddit protector — harden privacy settings and diversify subscriptions.

use std::collections::HashMap;

use anyhow::Result;

use dtm_core::auth::ensure_authenticated;
use dtm_core::models::{ProtectOpts, ProtectionResult};

use super::client::{RedditClient, TOKEN_URL};
use super::subreddits::get_balanced_subreddits;
use crate::reddit::client::tracking_prefs;

pub async fn protect_reddit(opts: &ProtectOpts) -> Result<ProtectionResult> {
    let token = ensure_authenticated("reddit", TOKEN_URL).await?;
    let client = RedditClient::new(token);

    let mut actions_available = Vec::new();
    let mut actions_taken = Vec::new();

    // Phase 1: Harden privacy settings
    if !opts.diversify_only {
        match client.get_prefs().await {
            Ok(prefs) => {
                let mut safe_prefs = HashMap::new();

                for (pref_name, pref_info) in tracking_prefs() {
                    let current = prefs.get(pref_name).and_then(|v| v.as_bool());
                    if current != Some(pref_info.safe_value) {
                        safe_prefs.insert(
                            pref_name.to_string(),
                            serde_json::json!(pref_info.safe_value),
                        );
                        actions_available
                            .push(format!("Disable {pref_name}: {}", pref_info.description));
                    }
                }

                if safe_prefs.is_empty() {
                    actions_available.push("All privacy settings already hardened".to_string());
                } else if opts.apply {
                    client.update_prefs(&safe_prefs).await?;
                    for pref_name in safe_prefs.keys() {
                        actions_taken.push(format!("Disabled {pref_name}"));
                    }
                }
            }
            Err(e) => {
                actions_available.push(format!("Failed to read preferences: {e}"));
            }
        }
    }

    // Phase 2: Diversify subscriptions
    if !opts.harden_only {
        let cat_filter = if opts.categories.is_empty() {
            None
        } else {
            Some(opts.categories.as_slice())
        };

        let new_subs = get_balanced_subreddits(cat_filter, 2);

        // Check which we're already subscribed to
        let existing_lower: std::collections::HashSet<String> =
            match client.get_subscribed_subreddits().await {
                Ok(subs) => subs.into_iter().map(|s| s.to_lowercase()).collect(),
                Err(_) => std::collections::HashSet::new(),
            };

        let to_subscribe: Vec<_> = new_subs
            .into_iter()
            .filter(|(sub, _, _)| !existing_lower.contains(&sub.to_lowercase()))
            .collect();

        if to_subscribe.is_empty() {
            actions_available.push("Subscription list already well diversified".to_string());
        } else {
            actions_available.push(format!(
                "Subscribe to {} diverse subreddits",
                to_subscribe.len()
            ));
            for (sub, cat, perspective) in to_subscribe.iter().take(10) {
                actions_available.push(format!("  r/{sub} ({cat}/{perspective})"));
            }
            if to_subscribe.len() > 10 {
                actions_available.push(format!("  ... and {} more", to_subscribe.len() - 10));
            }

            if opts.apply {
                for (sub, cat, perspective) in &to_subscribe {
                    match client.subscribe(sub).await {
                        Ok(true) => {
                            actions_taken
                                .push(format!("Subscribed to r/{sub} ({cat}/{perspective})"));
                        }
                        _ => {
                            actions_taken.push(format!("Failed to subscribe to r/{sub}"));
                        }
                    }
                    // Rate limiting — Reddit allows 60 req/min
                    tokio::time::sleep(std::time::Duration::from_millis(
                        rand::random::<u64>() % 1000 + 1000,
                    ))
                    .await;
                }
            }
        }
    }

    Ok(ProtectionResult {
        module_name: "reddit".to_string(),
        dry_run: !opts.apply,
        actions_taken,
        actions_available,
    })
}
