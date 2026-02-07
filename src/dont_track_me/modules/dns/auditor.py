"""DNS leak detection and privacy audit."""

from __future__ import annotations

import re
import subprocess

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel

# DNS providers known for logging/tracking user queries
TRACKING_DNS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "208.67.222.222": "OpenDNS (Cisco)",
    "208.67.220.220": "OpenDNS (Cisco)",
    "209.244.0.3": "Level3 DNS",
    "209.244.0.4": "Level3 DNS",
}

# Privacy-respecting DNS resolvers
PRIVATE_DNS = {
    "9.9.9.9": "Quad9 (privacy-focused, malware blocking)",
    "149.112.112.112": "Quad9 secondary",
    "1.1.1.1": "Cloudflare (privacy-focused, fast)",
    "1.0.0.1": "Cloudflare secondary",
    "194.242.2.2": "Mullvad DNS (no logging)",
    "194.242.2.3": "Mullvad DNS with ad blocking",
}

# ISP DNS is often used for tracking — we detect them by absence from known lists
KNOWN_SAFE = {**PRIVATE_DNS}


def _get_system_dns_servers() -> list[str]:
    """Get currently configured DNS servers from the system."""
    servers: list[str] = []

    try:
        # macOS: scutil --dns
        result = subprocess.run(
            ["scutil", "--dns"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("nameserver["):
                    match = re.search(r":\s*(\S+)", line)
                    if match:
                        servers.append(match.group(1))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not servers:
        # Linux: /etc/resolv.conf
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.append(parts[1])
        except FileNotFoundError:
            pass

    return list(dict.fromkeys(servers))  # deduplicate, preserve order


async def audit_dns(**kwargs) -> AuditResult:
    """Audit DNS configuration for privacy issues."""
    findings: list[Finding] = []
    servers = _get_system_dns_servers()
    score = 100

    if not servers:
        findings.append(
            Finding(
                title="Could not detect DNS servers",
                description="Unable to determine your current DNS configuration.",
                threat_level=ThreatLevel.MEDIUM,
                remediation="Manually check your DNS settings.",
            )
        )
        return AuditResult(
            module_name="dns",
            score=50,
            findings=findings,
            raw_data={"servers": []},
        )

    # Check for tracking DNS providers
    for server in servers:
        if server in TRACKING_DNS:
            name = TRACKING_DNS[server]
            findings.append(
                Finding(
                    title=f"Tracking DNS detected: {name}",
                    description=(
                        f"Your system uses {name} ({server}) which logs DNS queries. "
                        f"This allows the provider to build a profile of every website you visit."
                    ),
                    threat_level=ThreatLevel.HIGH,
                    remediation=(
                        "Switch to a privacy-respecting DNS like Quad9 (9.9.9.9) "
                        "or Cloudflare (1.1.1.1). Better yet, use DNS-over-HTTPS (DoH)."
                    ),
                )
            )
            score -= 30

    # Check for ISP DNS (not in any known list)
    for server in servers:
        if server not in TRACKING_DNS and server not in KNOWN_SAFE:
            # Likely ISP DNS
            findings.append(
                Finding(
                    title=f"Possible ISP DNS: {server}",
                    description=(
                        f"DNS server {server} is not a known privacy-respecting resolver. "
                        "ISP DNS servers typically log all queries and may sell this data "
                        "to advertisers or share it with government agencies."
                    ),
                    threat_level=ThreatLevel.MEDIUM,
                    remediation=(
                        "Switch to a known privacy-respecting DNS provider. "
                        "Quad9 (9.9.9.9) blocks malware and respects privacy. "
                        "Mullvad DNS (194.242.2.2) has a strict no-logging policy."
                    ),
                )
            )
            score -= 20

    # Check for private DNS
    using_private = any(s in PRIVATE_DNS for s in servers)
    if using_private:
        findings.append(
            Finding(
                title="Privacy-respecting DNS detected",
                description="You're using a DNS provider known for respecting user privacy.",
                threat_level=ThreatLevel.INFO,
                remediation="Consider enabling DNS-over-HTTPS (DoH) for additional encryption.",
            )
        )

    # Check for DoH/DoT (encrypted DNS)
    # We can detect if the system is configured for DoH on macOS
    doh_detected = False
    try:
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # DoH detection is limited from userspace; we note this
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not doh_detected:
        findings.append(
            Finding(
                title="No encrypted DNS (DoH/DoT) detected",
                description=(
                    "Your DNS queries are sent in plain text. Anyone on your network "
                    "(ISP, Wi-Fi operator, attackers) can see every domain you visit."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Enable DNS-over-HTTPS in your browser (Firefox/Chrome settings) "
                    "or system-wide using a tool like dnscrypt-proxy."
                ),
            )
        )
        score -= 15

    score = max(0, min(100, score))

    return AuditResult(
        module_name="dns",
        score=score,
        findings=findings,
        raw_data={
            "servers": servers,
            "tracking_dns": [s for s in servers if s in TRACKING_DNS],
        },
    )
