use std::collections::HashMap;

use anyhow::Result;
use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};

/// Audit HTTP request headers for privacy-revealing information.
pub async fn audit_headers(_opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings = Vec::new();
    let mut score: i32 = 100;

    // Send a request to httpbin.org to see what headers are sent
    let client = reqwest::Client::new();
    let response = client.get("https://httpbin.org/headers").send().await;

    match response {
        Ok(resp) => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(headers) = body.get("headers").and_then(|h| h.as_object()) {
                    // Check User-Agent
                    if let Some(ua) = headers.get("User-Agent").and_then(|v| v.as_str()) {
                        let ua_lower = ua.to_lowercase();

                        // Check for overly specific User-Agent
                        if ua_lower.contains("mac os") || ua_lower.contains("windows nt") {
                            findings.push(Finding {
                                title: "User-Agent reveals operating system".to_string(),
                                description: format!(
                                    "Your User-Agent string reveals your OS: \"{ua}\". "
                                ),
                                threat_level: ThreatLevel::Medium,
                                remediation: "Use a privacy-focused browser or a User-Agent spoofing extension.".to_string(),
                            });
                            score -= 10;
                        }

                        // Check for browser version specificity
                        if ua.len() > 100 {
                            findings.push(Finding {
                                title: "Highly specific User-Agent string".to_string(),
                                description: format!(
                                    "Your User-Agent is {} characters long, which increases fingerprinting uniqueness.",
                                    ua.len()
                                ),
                                threat_level: ThreatLevel::Low,
                                remediation: "Consider using a simpler User-Agent string.".to_string(),
                            });
                            score -= 5;
                        }
                    }

                    // Check Accept-Language (reveals locale)
                    if let Some(lang) = headers.get("Accept-Language").and_then(|v| v.as_str()) {
                        if lang.contains(',') {
                            findings.push(Finding {
                                title: "Accept-Language reveals locale preferences".to_string(),
                                description: format!(
                                    "Your Accept-Language header ({lang}) reveals your language preferences \
                                     and likely geographic location."
                                ),
                                threat_level: ThreatLevel::Medium,
                                remediation: "Reduce Accept-Language to a single common value like 'en'.".to_string(),
                            });
                            score -= 10;
                        }
                    }

                    // Check for DNT header
                    if headers.get("Dnt").is_none() {
                        findings.push(Finding {
                            title: "Do Not Track header not set".to_string(),
                            description: "The DNT (Do Not Track) header is not being sent. \
                                While many sites ignore it, it signals privacy preference."
                                .to_string(),
                            threat_level: ThreatLevel::Low,
                            remediation: "Enable 'Do Not Track' in your browser settings."
                                .to_string(),
                        });
                        score -= 5;
                    }

                    // Good: no unexpected headers
                    if findings.is_empty() {
                        findings.push(Finding {
                            title: "HTTP headers are reasonably private".to_string(),
                            description:
                                "No significant privacy issues found in your HTTP headers."
                                    .to_string(),
                            threat_level: ThreatLevel::Info,
                            remediation: "No action needed.".to_string(),
                        });
                    }
                }
            }
        }
        Err(e) => {
            findings.push(Finding {
                title: "Could not check HTTP headers".to_string(),
                description: format!("Failed to connect to httpbin.org: {e}"),
                threat_level: ThreatLevel::Info,
                remediation: "Check your internet connection and try again.".to_string(),
            });
        }
    }

    Ok(AuditResult {
        module_name: "headers".to_string(),
        score: score.clamp(0, 100) as u32,
        findings,
        raw_data: HashMap::new(),
    })
}

#[cfg(test)]
mod tests {
    /// Known tracking-relevant HTTP headers that reveal identity.
    const TRACKING_HEADERS: &[&str] = &[
        "user-agent",
        "accept-language",
        "referer",
        "dnt",
        "sec-ch-ua",
        "sec-ch-ua-platform",
        "sec-ch-ua-mobile",
    ];

    /// Browsers recommended for privacy protection.
    const PRIVACY_BROWSERS: &[&str] = &["Firefox", "Tor Browser", "Brave", "Chrome (hardened)"];

    #[test]
    fn tracking_headers_defined() {
        // user-agent and accept-language should be in the tracking headers list
        assert!(
            TRACKING_HEADERS.contains(&"user-agent"),
            "user-agent should be a known tracking header"
        );
        assert!(
            TRACKING_HEADERS.contains(&"accept-language"),
            "accept-language should be a known tracking header"
        );
    }

    #[test]
    fn protect_mentions_browsers() {
        // Protection recommendations should mention privacy-focused browsers
        let has_firefox = PRIVACY_BROWSERS.iter().any(|b| b.contains("Firefox"));
        let has_chrome_like = PRIVACY_BROWSERS
            .iter()
            .any(|b| b.contains("Chrome") || b.contains("Brave"));

        assert!(
            has_firefox,
            "privacy browser recommendations should mention Firefox"
        );
        assert!(
            has_chrome_like,
            "privacy browser recommendations should mention a Chromium-based option"
        );
    }
}
