//! YouTube protector — diversify subscriptions to obfuscate profile.

use std::collections::HashSet;

use anyhow::Result;

use dtm_core::auth::ensure_authenticated;
use dtm_core::models::{ProtectOpts, ProtectionResult};

use super::channels::get_balanced_channels;
use super::client::{YoutubeClient, TOKEN_URL};

pub async fn protect_youtube(opts: &ProtectOpts) -> Result<ProtectionResult> {
    let token = ensure_authenticated("youtube", TOKEN_URL).await?;
    let client = YoutubeClient::new(token);

    let mut actions_available = Vec::new();
    let mut actions_taken = Vec::new();

    let cat_filter = if opts.categories.is_empty() {
        None
    } else {
        Some(opts.categories.as_slice())
    };

    let new_channels = get_balanced_channels(cat_filter, 2);

    // Check which we're already subscribed to
    let existing_ids: HashSet<String> = match client.get_subscriptions().await {
        Ok(subs) => subs.into_iter().map(|(id, _)| id).collect(),
        Err(_) => HashSet::new(),
    };

    let to_subscribe: Vec<_> = new_channels
        .into_iter()
        .filter(|(id, _, _, _)| !existing_ids.contains(id))
        .collect();

    if to_subscribe.is_empty() {
        actions_available.push("Subscription list already well diversified".to_string());
    } else {
        actions_available.push(format!(
            "Subscribe to {} diverse channels",
            to_subscribe.len()
        ));
        for (_, name, cat, perspective) in to_subscribe.iter().take(10) {
            actions_available.push(format!("  {name} ({cat}/{perspective})"));
        }
        if to_subscribe.len() > 10 {
            actions_available.push(format!("  ... and {} more", to_subscribe.len() - 10));
        }

        // Quota estimate: ~50 units per subscribe, 10K daily quota
        let quota_cost = to_subscribe.len() * 50;
        actions_available.push(format!(
            "Estimated quota cost: {quota_cost} units (daily limit: 10,000)"
        ));

        if opts.apply {
            for (id, name, cat, perspective) in &to_subscribe {
                match client.subscribe(id).await {
                    Ok(true) => {
                        actions_taken.push(format!("Subscribed to {name} ({cat}/{perspective})"));
                    }
                    _ => {
                        actions_taken.push(format!("Failed to subscribe to {name}"));
                    }
                }
                // Respect rate limits — random delay between subscribes
                tokio::time::sleep(std::time::Duration::from_millis(
                    rand::random::<u64>() % 3000 + 1000,
                ))
                .await;
            }
        }
    }

    Ok(ProtectionResult {
        module_name: "youtube".to_string(),
        dry_run: !opts.apply,
        actions_taken,
        actions_available,
    })
}
