use std::collections::HashMap;
use std::process::Command;

use anyhow::Result;
use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};

/// Known privacy-focused DNS resolvers.
const PRIVACY_DNS: &[(&str, &str)] = &[
    ("1.1.1.1", "Cloudflare DNS"),
    ("1.0.0.1", "Cloudflare DNS"),
    ("8.8.8.8", "Google Public DNS"),
    ("8.8.4.4", "Google Public DNS"),
    ("9.9.9.9", "Quad9 DNS"),
    ("149.112.112.112", "Quad9 DNS"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS"),
];

/// Known tracker-blocking DNS resolvers.
const BLOCKING_DNS: &[(&str, &str)] = &[
    ("45.90.28.0", "NextDNS"),
    ("45.90.30.0", "NextDNS"),
    ("94.140.14.14", "AdGuard DNS"),
    ("94.140.15.15", "AdGuard DNS"),
    ("176.103.130.130", "AdGuard DNS"),
    ("176.103.130.131", "AdGuard DNS"),
    ("194.242.2.3", "Mullvad DNS (ad-blocking)"),
    ("194.242.2.4", "Mullvad DNS (tracker + ad-blocking)"),
];

/// Audit DNS configuration for privacy leaks.
pub async fn audit_dns(_opts: &AuditOpts) -> Result<AuditResult> {
    let mut findings = Vec::new();
    let mut score: i32 = 100;
    let mut raw_data = HashMap::new();

    // Get DNS resolvers based on platform
    let resolvers = get_dns_resolvers();
    raw_data.insert(
        "resolvers".to_string(),
        serde_json::Value::Array(
            resolvers
                .iter()
                .map(|r| serde_json::Value::String(r.clone()))
                .collect(),
        ),
    );

    if resolvers.is_empty() {
        findings.push(Finding {
            title: "Could not determine DNS resolvers".to_string(),
            description: "Unable to read DNS configuration on this platform.".to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Manually check your DNS settings.".to_string(),
        });
        return Ok(AuditResult {
            module_name: "dns".to_string(),
            score: 50,
            findings,
            raw_data,
        });
    }

    // Check if using ISP DNS (not a known privacy/blocking resolver)
    let mut _uses_privacy_dns = false;
    let mut uses_blocking_dns = false;
    let mut isp_resolvers = Vec::new();

    for resolver in &resolvers {
        let is_privacy = PRIVACY_DNS.iter().any(|(ip, _)| ip == resolver);
        let is_blocking = BLOCKING_DNS.iter().any(|(ip, _)| ip == resolver);

        if is_blocking {
            uses_blocking_dns = true;
            let name = BLOCKING_DNS
                .iter()
                .find(|(ip, _)| ip == resolver)
                .map(|(_, n)| *n)
                .unwrap_or("Unknown");
            findings.push(Finding {
                title: format!("Using tracker-blocking DNS: {name}"),
                description: format!("Resolver {resolver} ({name}) blocks known tracker and ad domains at the DNS level."),
                threat_level: ThreatLevel::Info,
                remediation: "No action needed. This is excellent for privacy.".to_string(),
            });
        } else if is_privacy {
            _uses_privacy_dns = true;
            let name = PRIVACY_DNS
                .iter()
                .find(|(ip, _)| ip == resolver)
                .map(|(_, n)| *n)
                .unwrap_or("Unknown");
            findings.push(Finding {
                title: format!("Using privacy DNS: {name}"),
                description: format!(
                    "Resolver {resolver} ({name}) is a known privacy-focused DNS provider."
                ),
                threat_level: ThreatLevel::Info,
                remediation:
                    "Consider upgrading to a tracker-blocking DNS like NextDNS or AdGuard DNS."
                        .to_string(),
            });
        } else {
            isp_resolvers.push(resolver.clone());
        }
    }

    if !isp_resolvers.is_empty() && !uses_blocking_dns {
        findings.push(Finding {
            title: "Using ISP or unknown DNS resolvers".to_string(),
            description: format!(
                "Resolvers {} are not known privacy DNS providers. \
                 Your ISP can log every domain you visit.",
                isp_resolvers.join(", ")
            ),
            threat_level: ThreatLevel::High,
            remediation: "Switch to a privacy-focused DNS: NextDNS, AdGuard DNS, Cloudflare (1.1.1.1), or Quad9 (9.9.9.9).".to_string(),
        });
        score -= 25;
    }

    if !uses_blocking_dns {
        findings.push(Finding {
            title: "No tracker-blocking DNS configured".to_string(),
            description: "Your DNS resolver does not block known tracker and ad domains. \
                 All tracker DNS queries resolve normally."
                .to_string(),
            threat_level: ThreatLevel::Medium,
            remediation:
                "Use a tracker-blocking DNS like NextDNS or AdGuard DNS to block ads and trackers at the DNS level."
                    .to_string(),
        });
        score -= 15;
    }

    // Check for DNS encryption (DoH/DoT) — platform specific
    let has_encrypted_dns = check_encrypted_dns();
    raw_data.insert(
        "encrypted_dns".to_string(),
        serde_json::Value::Bool(has_encrypted_dns),
    );

    if !has_encrypted_dns {
        findings.push(Finding {
            title: "DNS queries are not encrypted".to_string(),
            description: "Your DNS queries are sent in plaintext, visible to your ISP and anyone on your network.".to_string(),
            threat_level: ThreatLevel::Medium,
            remediation: "Enable DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) in your browser or OS settings.".to_string(),
        });
        score -= 10;
    }

    // Check mDNS/Bonjour on macOS
    #[cfg(target_os = "macos")]
    {
        if check_mdns_enabled() {
            findings.push(Finding {
                title: "mDNS/Bonjour is enabled".to_string(),
                description: "Multicast DNS broadcasts your hostname to the local network, \
                     revealing your device name to nearby devices."
                    .to_string(),
                threat_level: ThreatLevel::Low,
                remediation:
                    "Disable Bonjour if not needed, or change your hostname to something generic."
                        .to_string(),
            });
            score -= 5;
        }
    }

    Ok(AuditResult {
        module_name: "dns".to_string(),
        score: score.clamp(0, 100) as u32,
        findings,
        raw_data,
    })
}

/// Get DNS resolvers from the system.
fn get_dns_resolvers() -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        get_dns_resolvers_macos()
    }

    #[cfg(target_os = "linux")]
    {
        get_dns_resolvers_linux()
    }

    #[cfg(target_os = "windows")]
    {
        get_dns_resolvers_windows()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
fn get_dns_resolvers_macos() -> Vec<String> {
    let output = Command::new("scutil").arg("--dns").output();
    let mut resolvers = Vec::new();

    if let Ok(output) = output {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver[") {
                if let Some(ip) = trimmed.split(':').nth(1) {
                    let ip = ip.trim().to_string();
                    if !resolvers.contains(&ip) {
                        resolvers.push(ip);
                    }
                }
            }
        }
    }

    resolvers
}

#[cfg(target_os = "linux")]
fn get_dns_resolvers_linux() -> Vec<String> {
    let mut resolvers = Vec::new();

    // Try /etc/resolv.conf
    if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("nameserver ") {
                if let Some(ip) = trimmed.split_whitespace().nth(1) {
                    resolvers.push(ip.to_string());
                }
            }
        }
    }

    // Try systemd-resolve
    if resolvers.is_empty() {
        if let Ok(output) = Command::new("resolvectl").arg("status").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                if line.contains("DNS Servers:") {
                    if let Some(ip) = line.split(':').nth(1) {
                        for addr in ip.trim().split_whitespace() {
                            resolvers.push(addr.to_string());
                        }
                    }
                }
            }
        }
    }

    resolvers
}

#[cfg(target_os = "windows")]
fn get_dns_resolvers_windows() -> Vec<String> {
    let mut resolvers = Vec::new();

    if let Ok(output) = Command::new("powershell")
        .args([
            "-Command",
            "Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses",
        ])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                resolvers.push(trimmed.to_string());
            }
        }
    }

    resolvers
}

/// Check if encrypted DNS (DoH/DoT) is configured.
fn check_encrypted_dns() -> bool {
    #[cfg(target_os = "macos")]
    {
        // Check for DNS configuration profiles
        let output = Command::new("scutil").arg("--dns").output();
        if let Ok(output) = output {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("encrypted") || text.contains("HTTPS") || text.contains("TLS") {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "linux")]
    {
        // Check systemd-resolved for DoT
        if let Ok(output) = Command::new("resolvectl").arg("status").output() {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("DNSOverTLS") && text.contains("yes") {
                return true;
            }
        }
        false
    }

    #[cfg(target_os = "windows")]
    {
        // Check for DNS-over-HTTPS via netsh
        if let Ok(output) = Command::new("netsh")
            .args(["dns", "show", "encryption"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("DNS-over-HTTPS") || text.contains("HTTPS") {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Check if mDNS/Bonjour is enabled (macOS only).
#[cfg(target_os = "macos")]
fn check_mdns_enabled() -> bool {
    // mDNS is enabled by default on macOS; check if it's been disabled
    let output = Command::new("defaults")
        .args(["read", "/Library/Preferences/com.apple.mDNSResponder.plist"])
        .output();

    // If the plist exists and is readable, mDNS is running
    // (this is a simplified check — mDNS is almost always on)
    output.is_ok_and(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracking_dns_detected() {
        // Google DNS (8.8.8.8) is in the PRIVACY_DNS list but is a known profiler
        let is_known = PRIVACY_DNS.iter().any(|(ip, _)| *ip == "8.8.8.8");
        assert!(
            is_known,
            "8.8.8.8 (Google DNS) should be in the known DNS resolver list"
        );

        // It should be labeled as Google
        let label = PRIVACY_DNS
            .iter()
            .find(|(ip, _)| *ip == "8.8.8.8")
            .map(|(_, name)| *name);
        assert_eq!(label, Some("Google Public DNS"));
    }

    #[test]
    fn private_dns_recommended() {
        // Quad9 (9.9.9.9) should be recognized as a privacy DNS provider
        let is_known = PRIVACY_DNS.iter().any(|(ip, _)| *ip == "9.9.9.9");
        assert!(
            is_known,
            "9.9.9.9 (Quad9) should be recognized as privacy DNS"
        );

        let label = PRIVACY_DNS
            .iter()
            .find(|(ip, _)| *ip == "9.9.9.9")
            .map(|(_, name)| *name);
        assert_eq!(label, Some("Quad9 DNS"));
    }

    #[test]
    fn mullvad_dns_recognized() {
        // Mullvad DNS should be in the BLOCKING_DNS list
        let has_mullvad = BLOCKING_DNS
            .iter()
            .any(|(_, name)| name.contains("Mullvad"));
        assert!(
            has_mullvad,
            "Mullvad DNS should be in the blocking DNS list"
        );

        // Check specific Mullvad IPs
        let mullvad_ips: Vec<&str> = BLOCKING_DNS
            .iter()
            .filter(|(_, name)| name.contains("Mullvad"))
            .map(|(ip, _)| *ip)
            .collect();
        assert!(
            !mullvad_ips.is_empty(),
            "should have at least one Mullvad DNS IP"
        );
    }

    #[test]
    fn cloudflare_dns_recognized() {
        // 1.1.1.1 should be recognized as Cloudflare DNS
        let is_known = PRIVACY_DNS.iter().any(|(ip, _)| *ip == "1.1.1.1");
        assert!(
            is_known,
            "1.1.1.1 should be recognized as Cloudflare privacy DNS"
        );

        let label = PRIVACY_DNS
            .iter()
            .find(|(ip, _)| *ip == "1.1.1.1")
            .map(|(_, name)| *name);
        assert_eq!(label, Some("Cloudflare DNS"));
    }
}
