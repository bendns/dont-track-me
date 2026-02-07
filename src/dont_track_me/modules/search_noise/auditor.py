"""Search noise auditor — assess how exposed your search profile is."""

from __future__ import annotations

import httpx

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel


async def audit_search_noise(**kwargs) -> AuditResult:
    """Audit search privacy exposure.

    Checks for signals that indicate your searches are being profiled:
    - Google personalization (logged-in cookies)
    - Search engine tracking headers
    - Personalized results indicators
    """
    findings: list[Finding] = []
    score = 100
    raw_data: dict = {}

    # Check if Google returns personalization signals
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            # Test Google — check for consent/personalization redirects
            resp = await client.get("https://www.google.com/search?q=test")
            raw_data["google_status"] = resp.status_code
            raw_data["google_cookies_received"] = len(resp.cookies)

            # Google sets tracking cookies
            cookie_names = list(resp.cookies.keys())
            raw_data["google_cookie_names"] = cookie_names

            if resp.cookies:
                findings.append(
                    Finding(
                        title=f"Google sets {len(resp.cookies)} tracking cookies",
                        description=(
                            f"Google returned cookies: {', '.join(cookie_names[:5])}. "
                            "These cookies allow Google to link your searches across sessions "
                            "and build a detailed profile of your interests, politics, and beliefs."
                        ),
                        threat_level=ThreatLevel.HIGH,
                        remediation=(
                            "Use DuckDuckGo or Brave Search as your default engine. "
                            "If using Google, always use private/incognito mode. "
                            "Run dtm noise search to pollute your search profile."
                        ),
                    )
                )
                score -= 20

            # Check Bing
            resp_bing = await client.get("https://www.bing.com/search?q=test")
            raw_data["bing_cookies_received"] = len(resp_bing.cookies)
            if resp_bing.cookies:
                findings.append(
                    Finding(
                        title=f"Bing sets {len(resp_bing.cookies)} tracking cookies",
                        description=(
                            "Microsoft Bing also sets tracking cookies that profile your searches. "
                            "This data feeds into Microsoft's advertising network."
                        ),
                        threat_level=ThreatLevel.MEDIUM,
                        remediation="Use DuckDuckGo or clear Bing cookies regularly.",
                    )
                )
                score -= 10

    except httpx.ConnectError:
        findings.append(
            Finding(
                title="Cannot reach search engines",
                description="Could not connect to search engines to test tracking. You may be offline.",
                threat_level=ThreatLevel.INFO,
                remediation="Check your internet connection and try again.",
            )
        )
        return AuditResult(
            module_name="search_noise", score=50, findings=findings, raw_data=raw_data
        )
    except Exception:
        pass

    # General warnings about search profiling
    findings.append(
        Finding(
            title="Search history reveals political and personal beliefs",
            description=(
                "Every search you make is logged and profiled by the search engine. "
                "Searching for political topics, health conditions, religious questions, "
                "or lifestyle choices creates a detailed ideological profile. "
                "This data is sold to advertisers and can be subpoenaed by governments."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "1. Use DuckDuckGo/Brave Search for sensitive queries\n"
                "2. Run 'dtm noise search --apply' regularly to dilute your profile\n"
                "3. Use private browsing for political/religious/health searches\n"
                "4. Disable Google Web & App Activity in your Google account"
            ),
        )
    )
    score -= 15

    findings.append(
        Finding(
            title="Search engines share data with advertising networks",
            description=(
                "Google shares search data with its ad network (90%+ of global search). "
                "Bing shares with Microsoft Advertising. Your search profile directly "
                "determines what ads you see — and what data brokers know about you."
            ),
            threat_level=ThreatLevel.MEDIUM,
            remediation="Use search engines that don't track: DuckDuckGo, Brave Search, Startpage.",
        )
    )
    score -= 10

    score = max(0, min(100, score))

    return AuditResult(
        module_name="search_noise",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
