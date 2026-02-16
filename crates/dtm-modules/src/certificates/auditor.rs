//! TLS certificate trust store audit.

use std::collections::HashMap;

use anyhow::Result;
use dtm_core::models::{AuditOpts, AuditResult, Finding, ThreatLevel};

/// Known suspicious or distrusted certificate authorities.
const SUSPICIOUS_CAS: &[(&str, &str)] = &[
    (
        "CNNIC",
        "China Internet Network Information Center -- distrusted by Google and Mozilla \
         after issuing unauthorized certificates via an intermediate CA.",
    ),
    (
        "WoSign",
        "Chinese CA that issued fraudulent certificates (including for GitHub) and \
         backdated SHA-1 certs. Distrusted by all major browsers since 2016.",
    ),
    (
        "StartCom",
        "Israeli CA secretly acquired by WoSign. Distrusted by all major browsers \
         after the acquisition and shared infrastructure were revealed.",
    ),
    (
        "TurkTrust",
        "Turkish CA that accidentally issued intermediate CA certificates to \
         organizations which were then used to create fraudulent Google certificates.",
    ),
    (
        "ANSSI",
        "French government CA that issued unauthorized certificates for Google \
         domains in 2013.",
    ),
    (
        "DarkMatter",
        "UAE-based security firm linked to Project Raven surveillance operations. \
         Applied to become a trusted root CA despite documented involvement in \
         offensive cyber operations.",
    ),
];

/// OID for MD5 with RSA (1.2.840.113549.1.1.4).
#[cfg(feature = "certificates")]
const OID_MD5_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 4];

/// OID for SHA-1 with RSA (1.2.840.113549.1.1.5).
#[cfg(feature = "certificates")]
const OID_SHA1_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 5];

/// OID for MD2 with RSA (1.2.840.113549.1.1.2).
#[cfg(feature = "certificates")]
const OID_MD2_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 2];

/// Check if a name matches any suspicious CA (case-insensitive contains).
fn check_suspicious_ca(name: &str) -> Option<(&'static str, &'static str)> {
    let lower = name.to_lowercase();
    for &(ca_name, description) in SUSPICIOUS_CAS {
        if lower.contains(&ca_name.to_lowercase()) {
            return Some((ca_name, description));
        }
    }
    None
}

/// Audit certificates with the `certificates` feature enabled.
#[cfg(feature = "certificates")]
pub async fn audit_certificates(_opts: &AuditOpts) -> Result<AuditResult> {
    use x509_parser::prelude::*;

    let mut findings = Vec::new();
    let mut score: i32 = 100;
    let mut raw_data = HashMap::new();

    // --- Load system certificates ---
    let native_certs = rustls_native_certs::load_native_certs();
    let certs = native_certs.certs;

    if certs.is_empty() {
        findings.push(Finding {
            title: "Could not load system certificate store".to_string(),
            description: "Unable to read the system's trusted CA certificate store. \
                This may indicate a misconfigured SSL installation."
                .to_string(),
            threat_level: ThreatLevel::Medium,
            remediation: "Verify your system certificate store configuration.".to_string(),
        });
        return Ok(AuditResult {
            module_name: "certificates".to_string(),
            score: 50,
            findings,
            raw_data: HashMap::from([(
                "error".to_string(),
                serde_json::json!("could_not_load_certs"),
            )]),
        });
    }

    raw_data.insert("total_ca_count".to_string(), serde_json::json!(certs.len()));

    let mut expired_certs: Vec<String> = Vec::new();
    let mut suspicious_found: HashMap<&str, Vec<String>> = HashMap::new();
    let mut weak_sig_certs: Vec<String> = Vec::new();
    let now = ::time::OffsetDateTime::now_utc();

    // --- Check 1: Trust store size ---
    if certs.len() > 200 {
        findings.push(Finding {
            title: format!("Large certificate trust store ({} CAs)", certs.len()),
            description: format!(
                "Your system trusts {} certificate authorities. A larger trust \
                 store increases your attack surface -- each trusted CA can issue \
                 certificates for any domain.",
                certs.len()
            ),
            threat_level: ThreatLevel::Medium,
            remediation: "Review your trusted CAs and remove any that you do not need.".to_string(),
        });
        score -= 5;
    }

    // --- Per-certificate checks ---
    for cert_der in &certs {
        let parsed = match X509Certificate::from_der(cert_der.as_ref()) {
            Ok((_, cert)) => cert,
            Err(_) => continue,
        };

        let issuer = parsed.issuer().to_string();
        let subject = parsed.subject().to_string();
        let cert_label = if issuer == subject {
            subject.clone()
        } else {
            format!("{subject} (issued by {issuer})")
        };

        // Check for expired certificates
        let not_after = parsed.validity().not_after.to_datetime();
        if not_after < now {
            expired_certs.push(cert_label.clone());
        }

        // Check for suspicious CAs
        let combined = format!("{subject} {issuer}");
        if let Some((ca_name, _desc)) = check_suspicious_ca(&combined) {
            suspicious_found
                .entry(ca_name)
                .or_default()
                .push(cert_label.clone());
        }

        // Check for weak signature algorithms
        let sig_oid = parsed.signature_algorithm.algorithm.iter().unwrap();
        let sig_components: Vec<u64> = sig_oid.collect();

        let weak_algo = if sig_components == OID_MD5_RSA {
            Some("MD5")
        } else if sig_components == OID_SHA1_RSA {
            Some("SHA-1")
        } else if sig_components == OID_MD2_RSA {
            Some("MD2")
        } else {
            None
        };

        if let Some(algo) = weak_algo {
            weak_sig_certs.push(format!("{cert_label} (uses {algo})"));
        }
    }

    // --- Report expired certificates ---
    if !expired_certs.is_empty() {
        let count = expired_certs.len();
        let listed: String = expired_certs
            .iter()
            .take(10)
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n");
        let more = if count > 10 {
            format!("\n  ... and {} more", count - 10)
        } else {
            String::new()
        };

        findings.push(Finding {
            title: format!("Expired CA certificates found ({count})"),
            description: format!(
                "The following trusted CA certificates have expired and should \
                 have been removed from your trust store:\n{listed}{more}"
            ),
            threat_level: ThreatLevel::High,
            remediation: "Remove expired CA certificates from your trust store. On macOS, \
                use Keychain Access. On Linux, update your ca-certificates package."
                .to_string(),
        });
        score -= (count as i32 * 10).min(40);
    }

    // --- Report suspicious CAs ---
    for (ca_name, cert_labels) in &suspicious_found {
        let description = SUSPICIOUS_CAS
            .iter()
            .find(|(name, _)| name == ca_name)
            .map(|(_, desc)| *desc)
            .unwrap_or("Suspicious CA");

        let listed: String = cert_labels
            .iter()
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n");

        findings.push(Finding {
            title: format!("Suspicious CA in trust store: {ca_name}"),
            description: format!("{description}\n\nFound in your trust store:\n{listed}"),
            threat_level: ThreatLevel::Critical,
            remediation: format!(
                "Remove {ca_name} certificates from your trust store. These CAs \
                 have been distrusted by major browsers due to security incidents \
                 or ties to surveillance operations."
            ),
        });
        score -= 20;
    }

    // --- Report weak signature algorithms ---
    if !weak_sig_certs.is_empty() {
        let count = weak_sig_certs.len();
        let listed: String = weak_sig_certs
            .iter()
            .take(10)
            .map(|c| format!("  - {c}"))
            .collect::<Vec<_>>()
            .join("\n");
        let more = if count > 10 {
            format!("\n  ... and {} more", count - 10)
        } else {
            String::new()
        };

        findings.push(Finding {
            title: format!("Weak signature algorithms detected ({count} certs)"),
            description: format!(
                "The following CA certificates use deprecated signature algorithms \
                 vulnerable to collision attacks:\n{listed}{more}"
            ),
            threat_level: ThreatLevel::High,
            remediation: "SHA-1 and MD5 signatures are broken. An attacker with \
                sufficient resources can forge certificates signed with these \
                algorithms. Remove or replace these certificates."
                .to_string(),
        });
        score -= 10;
    }

    raw_data.insert(
        "expired_count".to_string(),
        serde_json::json!(expired_certs.len()),
    );
    raw_data.insert(
        "suspicious_cas".to_string(),
        serde_json::json!(suspicious_found.keys().collect::<Vec<_>>()),
    );
    raw_data.insert(
        "weak_sig_count".to_string(),
        serde_json::json!(weak_sig_certs.len()),
    );

    // --- Certificate Transparency (educational) ---
    findings.push(Finding {
        title: "Certificate Transparency monitoring".to_string(),
        description: "Certificate Transparency (CT) is a public logging framework that \
            records all issued TLS certificates. By monitoring CT logs, you can detect \
            if a CA issues an unauthorized certificate for your domains. Major browsers \
            now require CT compliance for trusted certificates.\n\n\
            Monitor CT logs at https://crt.sh or Google's CT search."
            .to_string(),
        threat_level: ThreatLevel::Info,
        remediation: "Enable Certificate Transparency checking in your browser. Chrome \
            enables this by default. For domain owners, set up CT log monitoring."
            .to_string(),
    });

    let score = score.clamp(0, 100) as u32;

    Ok(AuditResult {
        module_name: "certificates".to_string(),
        score,
        findings,
        raw_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_suspicious_ca_detects_cnnic() {
        let result = check_suspicious_ca("CN=CNNIC ROOT");
        assert!(result.is_some(), "Expected CNNIC to be flagged");
        let (name, _desc) = result.unwrap();
        assert_eq!(name, "CNNIC");
    }

    #[test]
    fn check_suspicious_ca_detects_wosign() {
        let result = check_suspicious_ca("CN=WoSign CA Free SSL Certificate G2");
        assert!(result.is_some(), "Expected WoSign to be flagged");
        let (name, _desc) = result.unwrap();
        assert_eq!(name, "WoSign");
    }

    #[test]
    fn check_suspicious_ca_detects_startcom() {
        let result = check_suspicious_ca("O=StartCom Ltd.");
        assert!(result.is_some(), "Expected StartCom to be flagged");
        let (name, _desc) = result.unwrap();
        assert_eq!(name, "StartCom");
    }

    #[test]
    fn check_suspicious_ca_detects_turktrust() {
        let result = check_suspicious_ca("CN=TURKTRUST Certificate Services");
        assert!(result.is_some(), "Expected TurkTrust to be flagged");
        let (name, _desc) = result.unwrap();
        assert_eq!(name, "TurkTrust");
    }

    #[test]
    fn check_suspicious_ca_detects_anssi() {
        let result = check_suspicious_ca("O=ANSSI, CN=IGC/A");
        assert!(result.is_some(), "Expected ANSSI to be flagged");
        let (name, _desc) = result.unwrap();
        assert_eq!(name, "ANSSI");
    }

    #[test]
    fn check_suspicious_ca_detects_darkmatter() {
        let result = check_suspicious_ca("CN=DarkMatter Assured CA");
        assert!(result.is_some(), "Expected DarkMatter to be flagged");
        let (name, _desc) = result.unwrap();
        assert_eq!(name, "DarkMatter");
    }

    #[test]
    fn check_suspicious_ca_safe_names_return_none() {
        assert!(check_suspicious_ca("CN=DigiCert Global Root G2").is_none());
        assert!(check_suspicious_ca("CN=Let's Encrypt Authority X3").is_none());
        assert!(check_suspicious_ca("CN=Baltimore CyberTrust Root").is_none());
        assert!(check_suspicious_ca("CN=Amazon Root CA 1").is_none());
        assert!(check_suspicious_ca("CN=GlobalSign Root CA").is_none());
        assert!(check_suspicious_ca("").is_none());
    }

    #[test]
    fn check_suspicious_ca_case_insensitive() {
        // The function lowercases both sides, so mixed case should still match.
        assert!(check_suspicious_ca("cn=cnnic root").is_some());
        assert!(check_suspicious_ca("CN=WOSIGN CA").is_some());
        assert!(check_suspicious_ca("o=darkmatter").is_some());
    }

    #[test]
    fn test_safe_ca_no_finding() {
        // Well-known trusted CAs should NOT trigger any suspicious finding
        let safe_cas = [
            "CN=DigiCert Global Root G2",
            "CN=DigiCert High Assurance EV Root CA",
            "CN=Let's Encrypt Authority X3",
            "CN=ISRG Root X1",
            "CN=Baltimore CyberTrust Root",
            "CN=Amazon Root CA 1",
            "CN=GlobalSign Root CA",
            "CN=Comodo RSA Certification Authority",
            "CN=GeoTrust Global CA",
            "CN=VeriSign Class 3 Public Primary Certification Authority",
        ];
        for ca in safe_cas {
            assert!(
                check_suspicious_ca(ca).is_none(),
                "Expected {ca} to NOT be flagged as suspicious"
            );
        }
    }
}

/// Fallback when the `certificates` feature is not enabled.
#[cfg(not(feature = "certificates"))]
pub async fn audit_certificates(_opts: &AuditOpts) -> Result<AuditResult> {
    Ok(AuditResult {
        module_name: "certificates".to_string(),
        score: 0,
        findings: vec![Finding {
            title: "Certificate audit not available".to_string(),
            description: "The certificate audit requires the 'certificates' feature \
                to be enabled at compile time (x509-parser, rustls-native-certs)."
                .to_string(),
            threat_level: ThreatLevel::Info,
            remediation: "Rebuild with: cargo build --features certificates".to_string(),
        }],
        raw_data: HashMap::new(),
    })
}
