"""TLS/SSL certificate trust store audit."""

from __future__ import annotations

import contextlib
import ssl
import time
from datetime import UTC, datetime
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel

# Certificate authorities that have been compromised, distrusted, or are state-controlled.
# Presence in a system trust store represents a security and privacy risk.
SUSPICIOUS_CAS: dict[str, str] = {
    "CNNIC": (
        "China Internet Network Information Center -- distrusted by Google and Mozilla "
        "after issuing unauthorized certificates via an intermediate CA."
    ),
    "WoSign": (
        "Chinese CA that issued fraudulent certificates (including for GitHub) and "
        "backdated SHA-1 certs. Distrusted by all major browsers since 2016."
    ),
    "StartCom": (
        "Israeli CA secretly acquired by WoSign. Distrusted by all major browsers "
        "after the acquisition and shared infrastructure were revealed."
    ),
    "TurkTrust": (
        "Turkish CA that accidentally issued intermediate CA certificates to "
        "organizations which were then used to create fraudulent Google certificates."
    ),
    "ANSSI": (
        "French government CA (Agence nationale de la securite des systemes d'information) "
        "that issued unauthorized certificates for Google domains in 2013."
    ),
    "Trustwave": (
        "US-based CA that issued a subordinate CA certificate to a private company "
        "for the explicit purpose of DPI/MITM traffic interception."
    ),
    "DarkMatter": (
        "UAE-based security firm linked to Project Raven surveillance operations. "
        "Applied to become a trusted root CA despite documented involvement in "
        "offensive cyber operations."
    ),
}

# Weak signature algorithms that are vulnerable to collision attacks
WEAK_ALGORITHMS: set[str] = {"md5", "sha1", "md2", "md4"}


def _parse_cert_time(time_str: str) -> float:
    """Parse a certificate time string to a Unix timestamp.

    Uses ssl.cert_time_to_seconds when available, falls back to strptime.
    """
    with contextlib.suppress(AttributeError, ValueError):
        return ssl.cert_time_to_seconds(time_str)

    # Fallback: parse manually. Format is typically "Mon DD HH:MM:SS YYYY GMT"
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        with contextlib.suppress(ValueError):
            dt = datetime.strptime(time_str, fmt)
            return dt.replace(tzinfo=UTC).timestamp()

    # If all parsing fails, return 0 (will not be flagged as expired)
    return 0.0


def _get_org_name(cert: dict[str, Any]) -> str:
    """Extract the organization name from a certificate subject or issuer."""
    for field in cert.get("subject", ()):
        for key, value in field:
            if key == "organizationName":
                return value
    for field in cert.get("issuer", ()):
        for key, value in field:
            if key == "organizationName":
                return value
    # Fall back to commonName
    for field in cert.get("subject", ()):
        for key, value in field:
            if key == "commonName":
                return value
    return "Unknown"


def _get_common_name(cert: dict[str, Any]) -> str:
    """Extract the common name from a certificate subject."""
    for field in cert.get("subject", ()):
        for key, value in field:
            if key == "commonName":
                return value
    return "Unknown"


def _check_suspicious_ca(org_name: str, common_name: str) -> str | None:
    """Check if a certificate belongs to a known suspicious CA.

    Returns the suspicious CA key if matched, None otherwise.
    """
    combined = f"{org_name} {common_name}".lower()
    for ca_name in SUSPICIOUS_CAS:
        if ca_name.lower() in combined:
            return ca_name
    return None


def _check_weak_signature(cert: dict[str, Any]) -> str | None:
    """Check if a certificate uses a weak signature algorithm.

    The cert dict from ssl may not always include the signature algorithm directly.
    We check common fields that might indicate weak signatures.
    """
    # The Python ssl cert dict doesn't reliably expose the signature algorithm.
    # We check the serialNumber length as a heuristic: very short serial numbers
    # combined with certain issuers may indicate old/weak certs. However, the most
    # reliable check is via the 'crlDistributionPoints' or other fields.
    #
    # For the stdlib ssl module, we inspect available fields.
    # The OCSP and CRL fields sometimes hint at the algorithm, but the most
    # direct approach with stdlib is limited.
    #
    # We return None here and rely on the TLS version check and other heuristics
    # for weak algorithm detection. If future Python versions expose the
    # signatureAlgorithm field, this function can be updated.
    #
    # For now, check if any text fields mention sha1 or md5
    for field_name in ("crlDistributionPoints", "OCSP", "caIssuers"):
        field_val = cert.get(field_name, "")
        if isinstance(field_val, str):
            lower_val = field_val.lower()
            for algo in WEAK_ALGORITHMS:
                if algo in lower_val:
                    return algo
    return None


def _check_tls_versions() -> tuple[list[Finding], bool]:
    """Check which TLS versions the system supports."""
    findings: list[Finding] = []

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # Check minimum TLS version
    min_version = ctx.minimum_version

    # ssl.TLSVersion was added in Python 3.7
    tls_1_0_enabled = False
    tls_1_1_enabled = False

    with contextlib.suppress(AttributeError):
        if min_version <= ssl.TLSVersion.TLSv1:
            tls_1_0_enabled = True
        if min_version <= ssl.TLSVersion.TLSv1_1:
            tls_1_1_enabled = True

    if tls_1_0_enabled:
        findings.append(
            Finding(
                title="TLS 1.0 is enabled",
                description=(
                    "Your system allows TLS 1.0 connections, which has known vulnerabilities "
                    "including BEAST and POODLE attacks. TLS 1.0 was deprecated by RFC 8996 "
                    "in March 2021. All major browsers have disabled it."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Disable TLS 1.0 in your system's SSL configuration. Most applications "
                    "and browsers have already done this, but system-level libraries may "
                    "still allow it."
                ),
            )
        )

    if tls_1_1_enabled:
        findings.append(
            Finding(
                title="TLS 1.1 is enabled",
                description=(
                    "Your system allows TLS 1.1 connections. While less vulnerable than TLS 1.0, "
                    "TLS 1.1 was also deprecated by RFC 8996 and lacks modern cipher suites. "
                    "It does not support AEAD ciphers which are now considered essential."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Disable TLS 1.1 and ensure your system uses TLS 1.2 or TLS 1.3 as the "
                    "minimum version. TLS 1.3 is strongly preferred for its improved security "
                    "and performance."
                ),
            )
        )

    if not tls_1_0_enabled and not tls_1_1_enabled:
        findings.append(
            Finding(
                title="Modern TLS versions enforced",
                description=(
                    "Your system requires TLS 1.2 or higher, which is the current best practice. "
                    "TLS 1.3 provides additional security improvements including encrypted "
                    "handshakes and forward secrecy by default."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed. Consider verifying TLS 1.3 is preferred.",
            )
        )

    return findings, tls_1_0_enabled or tls_1_1_enabled


async def audit_certificates(**kwargs: Any) -> AuditResult:
    """Audit system certificate trust stores for security and privacy issues."""
    findings: list[Finding] = []
    score = 100
    raw_data: dict[str, Any] = {}

    # --- Load system certificates ---
    certs: list[dict[str, Any]] = []
    try:
        ctx = ssl.create_default_context()
        certs = ctx.get_ca_certs(binary_form=False)
    except (ssl.SSLError, OSError):
        findings.append(
            Finding(
                title="Could not load system certificate store",
                description=(
                    "Unable to read the system's trusted CA certificate store. "
                    "This may indicate a misconfigured SSL installation."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation="Verify your Python SSL installation and system certificate store.",
            )
        )
        return AuditResult(
            module_name="certificates",
            score=50,
            findings=findings,
            raw_data={"error": "could_not_load_certs"},
        )

    raw_data["total_ca_count"] = len(certs)
    expired_certs: list[str] = []
    suspicious_found: dict[str, list[str]] = {}
    weak_sig_certs: list[str] = []

    now = time.time()

    # --- Check 1: Trust store size ---
    if len(certs) > 200:
        findings.append(
            Finding(
                title=f"Large certificate trust store ({len(certs)} CAs)",
                description=(
                    f"Your system trusts {len(certs)} certificate authorities. A larger trust "
                    "store increases your attack surface -- each trusted CA can issue certificates "
                    "for any domain. The more CAs you trust, the more entities that could "
                    "potentially intercept your encrypted traffic via a misissued certificate."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Review your trusted CAs and remove any that you do not need. "
                    "Most users only need CAs that sign certificates for the sites they visit."
                ),
            )
        )
        score -= 5

    # --- Check 2 & 3 & 4: Per-certificate checks ---
    for cert in certs:
        org_name = _get_org_name(cert)
        common_name = _get_common_name(cert)
        cert_label = f"{org_name} ({common_name})"

        # Check for expired certificates
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry_ts = _parse_cert_time(not_after)
            if expiry_ts > 0 and expiry_ts < now:
                expired_certs.append(cert_label)

        # Check for suspicious CAs
        suspicious_match = _check_suspicious_ca(org_name, common_name)
        if suspicious_match is not None:
            if suspicious_match not in suspicious_found:
                suspicious_found[suspicious_match] = []
            suspicious_found[suspicious_match].append(cert_label)

        # Check for weak signature algorithms
        weak_algo = _check_weak_signature(cert)
        if weak_algo is not None:
            weak_sig_certs.append(f"{cert_label} (uses {weak_algo})")

    # --- Report expired certificates ---
    if expired_certs:
        findings.append(
            Finding(
                title=f"Expired CA certificates found ({len(expired_certs)})",
                description=(
                    "The following trusted CA certificates have expired and should have been "
                    "removed from your trust store. Expired CAs can indicate a stale or "
                    "poorly maintained certificate store:\n"
                    + "\n".join(f"  - {c}" for c in expired_certs[:10])
                    + (
                        f"\n  ... and {len(expired_certs) - 10} more"
                        if len(expired_certs) > 10
                        else ""
                    )
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Remove expired CA certificates from your trust store. On macOS, use "
                    "Keychain Access to find and remove them. On Linux, update your "
                    "ca-certificates package."
                ),
            )
        )
        score -= min(len(expired_certs) * 10, 40)

    # --- Report suspicious CAs ---
    for ca_name, cert_labels in suspicious_found.items():
        description = SUSPICIOUS_CAS[ca_name]
        findings.append(
            Finding(
                title=f"Suspicious CA in trust store: {ca_name}",
                description=(
                    f"{description}\n\nFound in your trust store:\n"
                    + "\n".join(f"  - {label}" for label in cert_labels)
                ),
                threat_level=ThreatLevel.CRITICAL,
                remediation=(
                    f"Remove {ca_name} certificates from your trust store. "
                    "These CAs have been distrusted by major browsers due to security "
                    "incidents or ties to surveillance operations."
                ),
            )
        )
        score -= 20

    # --- Report weak signature algorithms ---
    if weak_sig_certs:
        findings.append(
            Finding(
                title=f"Weak signature algorithms detected ({len(weak_sig_certs)} certs)",
                description=(
                    "The following CA certificates use deprecated signature algorithms "
                    "vulnerable to collision attacks:\n"
                    + "\n".join(f"  - {c}" for c in weak_sig_certs[:10])
                    + (
                        f"\n  ... and {len(weak_sig_certs) - 10} more"
                        if len(weak_sig_certs) > 10
                        else ""
                    )
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "SHA-1 and MD5 signatures are broken. An attacker with sufficient resources "
                    "can forge certificates signed with these algorithms. Remove or replace "
                    "these certificates."
                ),
            )
        )
        score -= 10

    raw_data["expired_certs"] = expired_certs
    raw_data["suspicious_cas"] = {k: v for k, v in suspicious_found.items()}
    raw_data["weak_sig_certs"] = weak_sig_certs

    # --- Check 5: TLS version support ---
    tls_findings, old_tls_enabled = _check_tls_versions()
    findings.extend(tls_findings)
    if old_tls_enabled:
        score -= 15

    # --- Check 6: Certificate Transparency (educational) ---
    findings.append(
        Finding(
            title="Certificate Transparency monitoring",
            description=(
                "Certificate Transparency (CT) is a public logging framework that records "
                "all issued TLS certificates. By monitoring CT logs, you can detect if a CA "
                "issues an unauthorized certificate for your domains. Major browsers (Chrome, "
                "Safari, Firefox) now require CT compliance for trusted certificates.\n\n"
                "You can monitor CT logs for domains you own at https://crt.sh or through "
                "Google's CT search at https://transparencyreport.google.com/https/certificates"
            ),
            threat_level=ThreatLevel.INFO,
            remediation=(
                "Enable Certificate Transparency checking in your browser. Chrome enables "
                "this by default. For domain owners, set up CT log monitoring to detect "
                "unauthorized certificates issued for your domains."
            ),
        )
    )

    score = max(0, min(100, score))

    return AuditResult(
        module_name="certificates",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
