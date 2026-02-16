//! OAuth infrastructure — token storage, OAuth flow, and credential helpers.
//!
//! Feature-gated behind `oauth` in dtm-modules; dtm-core exposes the data types
//! unconditionally so other crates can reference them without the feature.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{get_client_id, get_client_secret, load_config};

/// Prefix used when storing tokens in the system keyring.
pub const KEYRING_SERVICE_PREFIX: &str = "dont-track-me";

/// Local redirect port for OAuth callback.
pub const REDIRECT_PORT: u16 = 8914;

/// Local redirect URI for OAuth callback.
pub const REDIRECT_URI: &str = "http://localhost:8914/callback";

/// Raised when a module requires authentication but no token is available.
#[derive(Debug, thiserror::Error)]
#[error("Not authenticated. Run: dtm auth {platform}")]
pub struct AuthenticationRequired {
    pub platform: String,
}

/// Stored OAuth token data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix timestamp when token expires.
    pub expires_at: Option<f64>,
    #[serde(default = "default_token_type")]
    pub token_type: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub platform: String,
}

fn default_token_type() -> String {
    "Bearer".to_string()
}

impl TokenData {
    /// Whether the token has expired (with a 60-second buffer).
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();
                now > expires_at - 60.0
            }
            None => false,
        }
    }
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Store and retrieve OAuth tokens via the system keyring.
pub struct TokenStore;

impl TokenStore {
    fn service_name(platform: &str) -> String {
        format!("{KEYRING_SERVICE_PREFIX}:{platform}")
    }

    /// Save a token to the system keyring.
    #[cfg(feature = "oauth")]
    pub fn save(platform: &str, token: &TokenData) -> anyhow::Result<()> {
        let mut token = token.clone();
        token.platform = platform.to_string();
        let json = serde_json::to_string(&token)?;

        let entry = keyring::Entry::new(&Self::service_name(platform), "oauth_token")?;
        entry.set_password(&json)?;
        Ok(())
    }

    /// Load a token from the system keyring. Returns `None` if not found.
    #[cfg(feature = "oauth")]
    pub fn load(platform: &str) -> Option<TokenData> {
        let entry = keyring::Entry::new(&Self::service_name(platform), "oauth_token").ok()?;
        let json = entry.get_password().ok()?;
        serde_json::from_str(&json).ok()
    }

    /// Delete stored token.
    #[cfg(feature = "oauth")]
    pub fn delete(platform: &str) {
        if let Ok(entry) = keyring::Entry::new(&Self::service_name(platform), "oauth_token") {
            let _ = entry.delete_credential();
        }
    }

    /// Check if a valid (non-expired) token exists.
    #[cfg(feature = "oauth")]
    pub fn is_authenticated(platform: &str) -> bool {
        Self::load(platform).is_some_and(|t| !t.is_expired())
    }

    // Stub implementations when oauth feature is disabled
    #[cfg(not(feature = "oauth"))]
    pub fn save(_platform: &str, _token: &TokenData) -> anyhow::Result<()> {
        anyhow::bail!("OAuth support not compiled (enable the `oauth` feature)")
    }

    #[cfg(not(feature = "oauth"))]
    pub fn load(_platform: &str) -> Option<TokenData> {
        None
    }

    #[cfg(not(feature = "oauth"))]
    pub fn delete(_platform: &str) {}

    #[cfg(not(feature = "oauth"))]
    pub fn is_authenticated(_platform: &str) -> bool {
        false
    }
}

/// Execute an OAuth 2.0 authorization code flow with a local redirect server.
pub struct OAuthFlow {
    pub authorize_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub extra_params: Vec<(String, String)>,
}

impl OAuthFlow {
    /// Run the full OAuth flow: open browser -> capture code -> exchange for token.
    #[cfg(feature = "oauth")]
    pub fn run(&self) -> anyhow::Result<TokenData> {
        // Generate state for CSRF protection
        let state: String = (0..32)
            .map(|_| {
                let idx = rand::random::<u8>() % 62;
                let c = match idx {
                    0..=25 => b'a' + idx,
                    26..=51 => b'A' + (idx - 26),
                    _ => b'0' + (idx - 52),
                };
                c as char
            })
            .collect();

        // Build authorization URL
        let mut params: Vec<(&str, &str)> = vec![
            ("client_id", &self.client_id),
            ("redirect_uri", REDIRECT_URI),
            ("response_type", "code"),
            ("state", &state),
        ];

        let scope = self.scopes.join(" ");
        params.push(("scope", &scope));

        let extra_refs: Vec<(&str, &str)> = self
            .extra_params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        params.extend_from_slice(&extra_refs);

        let query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(params)
            .finish();
        let auth_url = format!("{}?{}", self.authorize_url, query);

        // Start local HTTP server to receive the callback
        let server = tiny_http::Server::http(format!("127.0.0.1:{REDIRECT_PORT}"))
            .map_err(|e| anyhow::anyhow!("Failed to start local OAuth server: {e}"))?;

        // Open browser
        if let Err(e) = open::that(&auth_url) {
            log::warn!("Failed to open browser: {e}");
            println!("Open this URL in your browser:\n{auth_url}");
        }

        // Wait for the callback (120s timeout)
        let request = server
            .recv_timeout(std::time::Duration::from_secs(120))
            .map_err(|e| anyhow::anyhow!("Error receiving OAuth callback: {e}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("OAuth flow timed out — no authorization code received.")
            })?;

        // Parse the callback URL
        let url = request.url().to_string();
        let query_start = url.find('?').unwrap_or(url.len());
        let query_str = &url[query_start..].trim_start_matches('?');
        let params: std::collections::HashMap<String, String> =
            form_urlencoded::parse(query_str.as_bytes())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

        // Send response to browser
        let (status, body) = if params.contains_key("error") {
            (
                400,
                "<h1>Authentication failed</h1><p>You can close this tab.</p>",
            )
        } else {
            (200, "<h1>Authentication successful!</h1><p>You can close this tab and return to the terminal.</p>")
        };

        let response = tiny_http::Response::from_string(body)
            .with_status_code(status)
            .with_header(tiny_http::Header::from_bytes(b"Content-Type", b"text/html").unwrap());
        let _ = request.respond(response);

        // Check for errors
        if let Some(err) = params.get("error") {
            anyhow::bail!("OAuth error: {err}");
        }

        let code = params
            .get("code")
            .ok_or_else(|| anyhow::anyhow!("No authorization code in callback"))?;

        let received_state = params.get("state").map(|s| s.as_str()).unwrap_or("");
        if received_state != state {
            anyhow::bail!("OAuth state mismatch — possible CSRF attack.");
        }

        // Exchange code for token
        self.exchange_code(code)
    }

    #[cfg(not(feature = "oauth"))]
    pub fn run(&self) -> anyhow::Result<TokenData> {
        anyhow::bail!("OAuth support not compiled (enable the `oauth` feature)")
    }

    /// Exchange an authorization code for access/refresh tokens.
    fn exchange_code(&self, code: &str) -> anyhow::Result<TokenData> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        let resp = client
            .post(&self.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .send()?
            .error_for_status()?;

        let data: serde_json::Value = resp.json()?;

        let expires_at = data
            .get("expires_in")
            .and_then(|v| v.as_f64())
            .map(|secs| now_unix() + secs);

        Ok(TokenData {
            access_token: data["access_token"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            refresh_token: data
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(String::from),
            expires_at,
            token_type: data
                .get("token_type")
                .and_then(|v| v.as_str())
                .unwrap_or("Bearer")
                .to_string(),
            scope: data
                .get("scope")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            platform: String::new(),
        })
    }
}

/// Refresh an expired OAuth token.
pub async fn refresh_token(
    token: &TokenData,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
) -> anyhow::Result<TokenData> {
    let refresh = token
        .refresh_token
        .as_deref()
        .ok_or_else(|| AuthenticationRequired {
            platform: token.platform.clone(),
        })?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let resp = client
        .post(token_url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await?
        .error_for_status()?;

    let data: serde_json::Value = resp.json().await?;

    let expires_at = data
        .get("expires_in")
        .and_then(|v| v.as_f64())
        .map(|secs| now_unix() + secs);

    Ok(TokenData {
        access_token: data["access_token"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        refresh_token: data
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| token.refresh_token.clone()),
        expires_at,
        token_type: data
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or("Bearer")
            .to_string(),
        scope: data
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or(&token.scope)
            .to_string(),
        platform: token.platform.clone(),
    })
}

/// Get OAuth client credentials for a platform from env vars or config.
pub fn get_platform_credentials(platform: &str) -> anyhow::Result<(String, String)> {
    let config = load_config();
    let client_id = get_client_id(platform, &config);
    let client_secret = get_client_secret(platform, &config);

    match (client_id, client_secret) {
        (Some(id), Some(secret)) => Ok((id, secret)),
        _ => anyhow::bail!(
            "No credentials for {platform}. Set DTM_{}_CLIENT_ID and \
             DTM_{}_CLIENT_SECRET env vars, or add them to \
             ~/.config/dont-track-me/config.toml under [{platform}].",
            platform.to_uppercase(),
            platform.to_uppercase(),
        ),
    }
}

/// Ensure we have a valid token for a platform, refreshing if necessary.
pub async fn ensure_authenticated(platform: &str, token_url: &str) -> anyhow::Result<TokenData> {
    let token = TokenStore::load(platform).ok_or_else(|| AuthenticationRequired {
        platform: platform.to_string(),
    })?;

    if !token.is_expired() {
        return Ok(token);
    }

    // Try to refresh
    if token.refresh_token.is_some() {
        let (client_id, client_secret) = get_platform_credentials(platform)?;
        let new_token = refresh_token(&token, token_url, &client_id, &client_secret).await?;
        TokenStore::save(platform, &new_token)?;
        return Ok(new_token);
    }

    Err(AuthenticationRequired {
        platform: platform.to_string(),
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_data_not_expired_when_no_expiry() {
        let token = TokenData {
            access_token: "test".into(),
            refresh_token: None,
            expires_at: None,
            token_type: "Bearer".into(),
            scope: String::new(),
            platform: String::new(),
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn token_data_expired_when_in_past() {
        let token = TokenData {
            access_token: "test".into(),
            refresh_token: None,
            expires_at: Some(1000.0), // way in the past
            token_type: "Bearer".into(),
            scope: String::new(),
            platform: String::new(),
        };
        assert!(token.is_expired());
    }

    #[test]
    fn token_data_not_expired_when_far_future() {
        let token = TokenData {
            access_token: "test".into(),
            refresh_token: None,
            expires_at: Some(now_unix() + 3600.0),
            token_type: "Bearer".into(),
            scope: String::new(),
            platform: String::new(),
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn token_data_serialization_round_trip() {
        let token = TokenData {
            access_token: "abc123".into(),
            refresh_token: Some("refresh456".into()),
            expires_at: Some(1700000000.0),
            token_type: "Bearer".into(),
            scope: "read write".into(),
            platform: "reddit".into(),
        };
        let json = serde_json::to_string(&token).unwrap();
        let parsed: TokenData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.access_token, "abc123");
        assert_eq!(parsed.refresh_token.as_deref(), Some("refresh456"));
        assert_eq!(parsed.platform, "reddit");
    }

    #[test]
    fn keyring_service_name_format() {
        assert_eq!(TokenStore::service_name("reddit"), "dont-track-me:reddit");
        assert_eq!(TokenStore::service_name("youtube"), "dont-track-me:youtube");
    }

    #[test]
    fn authentication_required_error_message() {
        let err = AuthenticationRequired {
            platform: "reddit".into(),
        };
        assert_eq!(err.to_string(), "Not authenticated. Run: dtm auth reddit");
    }

    #[test]
    fn get_platform_credentials_fails_without_config() {
        // Use a platform name that won't have env vars set
        let result = get_platform_credentials("nonexistent_test_platform_xyz");
        assert!(result.is_err());
    }
}
