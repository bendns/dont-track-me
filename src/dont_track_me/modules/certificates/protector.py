"""TLS/SSL certificate trust store protection and hardening recommendations."""

from __future__ import annotations

import contextlib
import platform
import ssl
import time
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.certificates.auditor import (
    SUSPICIOUS_CAS,
    _check_suspicious_ca,
    _get_common_name,
    _get_org_name,
    _parse_cert_time,
)


def _suspicious_ca_removal_instructions(ca_name: str) -> str:
    """Generate platform-specific instructions for removing a suspicious CA."""
    system = platform.system()

    if system == "Darwin":
        return (
            f"macOS: Open Keychain Access > System Roots > find '{ca_name}' > "
            f"Get Info > Trust > set to 'Never Trust'"
        )
    if system == "Linux":
        return (
            f"Linux: Remove the {ca_name} certificate from /etc/ssl/certs/ or "
            f"add it to /etc/ca-certificates/trust-source/blocklist/ and run "
            f"'sudo update-ca-certificates'"
        )
    return (
        f"Windows: Open certmgr.msc > Trusted Root Certification Authorities > "
        f"find '{ca_name}' > right-click > Properties > set to 'Disable all purposes'"
    )


def _tls_version_instructions() -> list[str]:
    """Generate browser-specific instructions for disabling old TLS versions."""
    return [
        (
            "Firefox: Navigate to about:config and set "
            "'security.tls.version.min' to 3 (TLS 1.2) or 4 (TLS 1.3)"
        ),
        (
            "Chrome: TLS 1.0/1.1 are disabled by default since Chrome 84. "
            "Ensure you are running an up-to-date version"
        ),
        (
            "Safari: TLS 1.0/1.1 are disabled by default since Safari 13.1. "
            "Keep macOS updated to maintain this protection"
        ),
        (
            "System-wide (Linux): Edit /etc/ssl/openssl.cnf and set "
            "'MinProtocol = TLSv1.2' in the [system_default_sect] section"
        ),
    ]


def _ct_instructions() -> list[str]:
    """Generate instructions for enabling Certificate Transparency checking."""
    return [
        (
            "Chrome: Certificate Transparency is enforced by default. Ensure "
            "you have not disabled it via enterprise policy"
        ),
        (
            "Firefox: CT enforcement is being rolled out. Check about:config "
            "for 'security.pki.certificate_transparency' settings"
        ),
        (
            "For domain owners: Monitor CT logs at https://crt.sh or use "
            "Facebook's CT monitoring tool at https://developers.facebook.com/tools/ct/"
        ),
    ]


async def protect_certificates(
    dry_run: bool = True,
    **kwargs: Any,
) -> ProtectionResult:
    """Provide protection recommendations for certificate trust store hardening.

    Certificate trust store modifications are inherently dangerous -- removing the
    wrong CA can break HTTPS connectivity. Therefore, all actions are recommendations
    only, even when dry_run=False. No automatic modifications are made.
    """
    actions_available: list[str] = []
    actions_taken: list[str] = []

    # --- Check for suspicious CAs and recommend removal ---
    certs: list[dict[str, Any]] = []
    with contextlib.suppress(ssl.SSLError, OSError):
        ctx = ssl.create_default_context()
        certs = ctx.get_ca_certs(binary_form=False)

    suspicious_found: dict[str, list[str]] = {}
    expired_certs: list[str] = []
    now = time.time()

    for cert in certs:
        org_name = _get_org_name(cert)
        common_name = _get_common_name(cert)
        cert_label = f"{org_name} ({common_name})"

        # Check suspicious
        suspicious_match = _check_suspicious_ca(org_name, common_name)
        if suspicious_match is not None:
            if suspicious_match not in suspicious_found:
                suspicious_found[suspicious_match] = []
            suspicious_found[suspicious_match].append(cert_label)

        # Check expired
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry_ts = _parse_cert_time(not_after)
            if expiry_ts > 0 and expiry_ts < now:
                expired_certs.append(cert_label)

    # Suspicious CA removal recommendations
    for ca_name, _cert_labels in suspicious_found.items():
        reason = SUSPICIOUS_CAS[ca_name]
        instructions = _suspicious_ca_removal_instructions(ca_name)
        action = (
            f"Remove suspicious CA '{ca_name}' from trust store. "
            f"Reason: {reason} "
            f"Instructions: {instructions}"
        )
        actions_available.append(action)

    if not suspicious_found:
        actions_available.append("No known suspicious CAs found in your trust store -- good!")

    # Expired certificate cleanup recommendations
    if expired_certs:
        system = platform.system()
        if system == "Darwin":
            cleanup_instruction = (
                "macOS: Open Keychain Access > search for the expired CA > "
                "right-click > Delete. Or use: "
                "'sudo security delete-certificate -c \"<CA Name>\" /System/Library/Keychains/SystemRootCertificates.keychain'"
            )
        elif system == "Linux":
            cleanup_instruction = (
                "Linux: Remove expired certificates from /etc/ssl/certs/ "
                "and run 'sudo update-ca-certificates --fresh'"
            )
        else:
            cleanup_instruction = (
                "Windows: Open certmgr.msc > find expired CAs > right-click > Delete"
            )

        actions_available.append(
            f"Clean up {len(expired_certs)} expired CA certificate(s): "
            + ", ".join(expired_certs[:5])
            + (f" and {len(expired_certs) - 5} more" if len(expired_certs) > 5 else "")
            + f". {cleanup_instruction}"
        )

    # TLS version recommendations
    tls_actions = _tls_version_instructions()
    actions_available.append("Ensure TLS 1.0 and 1.1 are disabled in all browsers and system-wide")
    for instruction in tls_actions:
        actions_available.append(instruction)

    # Certificate Transparency recommendations
    ct_actions = _ct_instructions()
    actions_available.append("Enable Certificate Transparency monitoring for domains you own")
    for instruction in ct_actions:
        actions_available.append(instruction)

    # Even with --apply, we don't auto-modify the trust store
    if not dry_run:
        actions_taken.append(
            "Certificate trust store modifications require manual action for safety. "
            "Automatically removing CAs could break HTTPS connectivity to legitimate "
            "websites. Please follow the recommendations in actions_available."
        )

    return ProtectionResult(
        module_name="certificates",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
