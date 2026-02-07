"""HTTP header auditor — analyze headers that leak identity information."""

from __future__ import annotations

from typing import Any

import httpx

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel

# Test URL that echoes back request headers
ECHO_URL = "https://httpbin.org/headers"

# Headers that leak identity/tracking info
TRACKING_HEADERS = {
    "user-agent": {
        "threat": ThreatLevel.HIGH,
        "description": (
            "Your User-Agent string identifies your browser, OS, version, and device type. "
            "This is one of the most powerful browser fingerprinting signals."
        ),
        "remediation": (
            "Use a browser extension to randomize or generalize your User-Agent. "
            "Firefox: set privacy.resistFingerprinting=true in about:config."
        ),
    },
    "accept-language": {
        "threat": ThreatLevel.MEDIUM,
        "description": (
            "Your Accept-Language header reveals your preferred languages and locale. "
            "Combined with other signals, this significantly narrows your identity."
        ),
        "remediation": (
            "Set Accept-Language to a common value like 'en-US,en;q=0.9' to blend in. "
            "Firefox: privacy.resistFingerprinting generalizes this automatically."
        ),
    },
    "referer": {
        "threat": ThreatLevel.MEDIUM,
        "description": (
            "The Referer header tells every website which page you came from. "
            "This enables cross-site tracking of your browsing path."
        ),
        "remediation": (
            "Set your browser's referrer policy to 'strict-origin-when-cross-origin' "
            "or 'no-referrer'. Use Firefox's Enhanced Tracking Protection."
        ),
    },
}

# Response headers that indicate tracking/surveillance
SUSPICIOUS_RESPONSE_HEADERS = {
    "x-request-id": "Request tracking identifier — can be used to correlate requests",
    "x-correlation-id": "Request correlation — used to track user sessions server-side",
    "x-amzn-trace-id": "AWS request tracing — tracks requests through Amazon infrastructure",
    "set-cookie": "Cookies being set — primary mechanism for cross-site tracking",
    "x-fb-debug": "Facebook debug header — indicates Facebook tracking infrastructure",
}


async def audit_headers(**kwargs) -> AuditResult:
    """Audit HTTP headers for privacy leaks."""
    findings: list[Finding] = []
    score = 100
    raw_data: dict[str, Any] = {}

    # Check what headers our client sends
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(ECHO_URL)
            data = response.json()
            sent_headers = data.get("headers", {})
            raw_data["sent_headers"] = sent_headers

            # Analyze sent headers
            for header_name, info in TRACKING_HEADERS.items():
                # httpbin returns headers with title case
                for key in sent_headers:
                    if key.lower() == header_name:
                        value = sent_headers[key]
                        findings.append(
                            Finding(
                                title=f"Leaking {header_name}: {value[:80]}",
                                description=info["description"],
                                threat_level=info["threat"],
                                remediation=info["remediation"],
                            )
                        )
                        if info["threat"] == ThreatLevel.HIGH:
                            score -= 20
                        elif info["threat"] == ThreatLevel.MEDIUM:
                            score -= 10

            # Check response headers for tracking infrastructure
            raw_data["response_headers"] = dict(response.headers)
            for header_name, description in SUSPICIOUS_RESPONSE_HEADERS.items():
                if header_name in response.headers:
                    findings.append(
                        Finding(
                            title=f"Tracking header in response: {header_name}",
                            description=description,
                            threat_level=ThreatLevel.LOW,
                            remediation="This is server-side — use a privacy-focused browser or proxy to strip these.",
                        )
                    )
                    score -= 5

    except httpx.ConnectError:
        findings.append(
            Finding(
                title="Cannot reach header echo service",
                description="Could not connect to httpbin.org to test headers. You may be offline.",
                threat_level=ThreatLevel.INFO,
                remediation="Check your internet connection and try again.",
            )
        )
        return AuditResult(
            module_name="headers", score=50, findings=findings, raw_data=raw_data
        )
    except Exception as e:
        findings.append(
            Finding(
                title="Header audit error",
                description=f"Error during header analysis: {e}",
                threat_level=ThreatLevel.INFO,
                remediation="Try again or report this issue.",
            )
        )
        return AuditResult(
            module_name="headers", score=50, findings=findings, raw_data=raw_data
        )

    score = max(0, min(100, score))

    return AuditResult(
        module_name="headers",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
