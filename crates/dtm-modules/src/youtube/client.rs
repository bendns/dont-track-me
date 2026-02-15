//! YouTube Data API v3 client — async reqwest wrapper.

use anyhow::Result;
use serde_json::Value;

use dtm_core::auth::TokenData;

const BASE_URL: &str = "https://www.googleapis.com/youtube/v3";

/// YouTube OAuth endpoints.
pub const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const SCOPES: &[&str] = &["https://www.googleapis.com/auth/youtube"];

/// Async client for YouTube Data API v3.
pub struct YoutubeClient {
    token: TokenData,
}

impl YoutubeClient {
    pub fn new(token: TokenData) -> Self {
        Self { token }
    }

    fn client(&self) -> Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?)
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token.access_token)
    }

    /// Get all user subscriptions.
    /// Returns list of `(channel_id, channel_title)`.
    /// Costs 1 quota unit per page (50 results).
    pub async fn get_subscriptions(&self) -> Result<Vec<(String, String)>> {
        let client = self.client()?;
        let mut subscriptions = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut params = vec![
                ("part", "snippet".to_string()),
                ("mine", "true".to_string()),
                ("maxResults", "50".to_string()),
            ];
            if let Some(ref pt) = page_token {
                params.push(("pageToken", pt.clone()));
            }

            let resp = client
                .get(format!("{BASE_URL}/subscriptions"))
                .header("Authorization", self.auth_header())
                .query(&params)
                .send()
                .await?
                .error_for_status()?;

            let data: Value = resp.json().await?;

            if let Some(items) = data["items"].as_array() {
                for item in items {
                    let channel_id = item["snippet"]["resourceId"]["channelId"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let title = item["snippet"]["title"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    subscriptions.push((channel_id, title));
                }
            }

            match data["nextPageToken"].as_str() {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => break,
            }
        }

        Ok(subscriptions)
    }

    /// Subscribe to a channel.
    /// Costs ~50 quota units. With 10K daily quota, that's ~200 subscribes/day.
    pub async fn subscribe(&self, channel_id: &str) -> Result<bool> {
        let client = self.client()?;
        let body = serde_json::json!({
            "snippet": {
                "resourceId": {
                    "kind": "youtube#channel",
                    "channelId": channel_id,
                }
            }
        });

        let resp = client
            .post(format!("{BASE_URL}/subscriptions"))
            .header("Authorization", self.auth_header())
            .query(&[("part", "snippet")])
            .json(&body)
            .send()
            .await?;

        Ok(resp.status().is_success())
    }
}
