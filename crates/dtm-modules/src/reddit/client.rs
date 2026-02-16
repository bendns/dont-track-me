//! Reddit API client — async reqwest wrapper for OAuth-authenticated Reddit API calls.

use std::collections::HashMap;

use anyhow::Result;
use serde_json::Value;

use dtm_core::auth::TokenData;

const BASE_URL: &str = "https://oauth.reddit.com";
const USER_AGENT: &str = "dont-track-me:v0.1.0 (privacy research toolkit)";

/// Reddit OAuth endpoints.
pub const AUTHORIZE_URL: &str = "https://www.reddit.com/api/v1/authorize";
pub const TOKEN_URL: &str = "https://www.reddit.com/api/v1/access_token";
pub const SCOPES: &[&str] = &["identity", "mysubreddits", "read", "account", "edit"];

/// Privacy-hostile Reddit settings and their safe values.
pub struct TrackingPref {
    pub safe_value: bool,
    pub description: &'static str,
}

/// All tracking preferences that can be hardened.
pub fn tracking_prefs() -> Vec<(&'static str, TrackingPref)> {
    vec![
        (
            "activity_relevant_ads",
            TrackingPref {
                safe_value: false,
                description: "Reddit uses your activity to personalize ads",
            },
        ),
        (
            "third_party_data_personalized_ads",
            TrackingPref {
                safe_value: false,
                description: "Third-party data is used to personalize ads shown to you",
            },
        ),
        (
            "third_party_site_data_personalized_ads",
            TrackingPref {
                safe_value: false,
                description: "Your activity on other sites is used for Reddit ad targeting",
            },
        ),
        (
            "third_party_site_data_personalized_content",
            TrackingPref {
                safe_value: false,
                description: "Your activity on other sites personalizes Reddit content",
            },
        ),
        (
            "allow_clicktracking",
            TrackingPref {
                safe_value: false,
                description: "Reddit tracks your link clicks",
            },
        ),
        (
            "public_votes",
            TrackingPref {
                safe_value: false,
                description: "Your upvotes and downvotes are publicly visible",
            },
        ),
        (
            "show_presence",
            TrackingPref {
                safe_value: false,
                description: "Your online status is visible to others",
            },
        ),
    ]
}

/// Async client for Reddit's OAuth API.
pub struct RedditClient {
    token: TokenData,
}

impl RedditClient {
    pub fn new(token: TokenData) -> Self {
        Self { token }
    }

    fn client(&self) -> Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent(USER_AGENT)
            .build()?)
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token.access_token)
    }

    /// Get user preferences including privacy settings.
    pub async fn get_prefs(&self) -> Result<HashMap<String, Value>> {
        let client = self.client()?;
        let resp = client
            .get(format!("{BASE_URL}/api/v1/me/prefs"))
            .header("Authorization", self.auth_header())
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// Update user preferences.
    pub async fn update_prefs(&self, prefs: &HashMap<String, Value>) -> Result<Value> {
        let client = self.client()?;
        let resp = client
            .patch(format!("{BASE_URL}/api/v1/me/prefs"))
            .header("Authorization", self.auth_header())
            .json(prefs)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// Get list of subscribed subreddit names.
    pub async fn get_subscribed_subreddits(&self) -> Result<Vec<String>> {
        let client = self.client()?;
        let mut subreddits = Vec::new();
        let mut after: Option<String> = None;

        loop {
            let mut params = vec![("limit", "100".to_string())];
            if let Some(ref a) = after {
                params.push(("after", a.clone()));
            }

            let resp = client
                .get(format!("{BASE_URL}/subreddits/mine/subscriber"))
                .header("Authorization", self.auth_header())
                .query(&params)
                .send()
                .await?
                .error_for_status()?;

            let data: Value = resp.json().await?;

            if let Some(children) = data["data"]["children"].as_array() {
                for child in children {
                    if let Some(name) = child["data"]["display_name"].as_str() {
                        if !name.is_empty() {
                            subreddits.push(name.to_string());
                        }
                    }
                }
            }

            match data["data"]["after"].as_str() {
                Some(a) if !a.is_empty() => after = Some(a.to_string()),
                _ => break,
            }
        }

        Ok(subreddits)
    }

    /// Subscribe to a subreddit. Returns true on success.
    pub async fn subscribe(&self, subreddit: &str) -> Result<bool> {
        let client = self.client()?;
        let resp = client
            .post(format!("{BASE_URL}/api/subscribe"))
            .header("Authorization", self.auth_header())
            .form(&[("action", "sub"), ("sr_name", subreddit)])
            .send()
            .await?;
        Ok(resp.status().is_success())
    }
}
