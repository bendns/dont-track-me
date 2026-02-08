"""YouTube auditor — analyze subscription bias."""

from __future__ import annotations

from dont_track_me.core.auth import AuthenticationRequired, TokenStore
from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.modules.youtube.channels import classify_channel
from dont_track_me.modules.youtube.client import YouTubeClient


async def audit_youtube(**kwargs) -> AuditResult:
    """Audit YouTube subscription list for ideological bias."""
    token = TokenStore.load("youtube")
    if token is None or token.is_expired:
        raise AuthenticationRequired("youtube")

    client = YouTubeClient(token)
    findings: list[Finding] = []
    score = 100
    raw_data: dict = {}

    try:
        subs = await client.get_subscriptions()
        raw_data["subscription_count"] = len(subs)

        # Classify subscriptions
        category_counts: dict[str, dict[str, int]] = {}
        classified = 0
        unclassified: list[str] = []

        for sub in subs:
            result = classify_channel(sub["channel_id"])
            if result:
                cat, perspective, _name = result
                classified += 1
                category_counts.setdefault(cat, {})
                category_counts[cat][perspective] = (
                    category_counts[cat].get(perspective, 0) + 1
                )
            else:
                unclassified.append(sub["channel_title"])

        raw_data["classified"] = classified
        raw_data["unclassified_count"] = len(unclassified)
        raw_data["category_breakdown"] = category_counts

        if not subs:
            findings.append(
                Finding(
                    title="No YouTube subscriptions found",
                    description="Your account has no subscriptions to analyze.",
                    threat_level=ThreatLevel.INFO,
                    remediation="Subscribe to diverse channels to build a balanced profile.",
                )
            )
            return AuditResult(
                module_name="youtube", score=50, findings=findings, raw_data=raw_data
            )

        # Detect bias in each category
        for cat, perspectives in category_counts.items():
            total = sum(perspectives.values())
            if total < 2:
                continue

            for perspective, count in perspectives.items():
                ratio = count / total
                if ratio > 0.7 and total >= 3:
                    findings.append(
                        Finding(
                            title=f"Strong {cat} bias: {perspective} ({count}/{total})",
                            description=(
                                f"In '{cat}', {ratio:.0%} of your subscriptions lean "
                                f"'{perspective}'. YouTube's algorithm amplifies this bias, "
                                f"and the pattern is visible to anyone analyzing your account."
                            ),
                            threat_level=ThreatLevel.HIGH,
                            remediation="Run: dtm protect youtube --apply",
                        )
                    )
                    score -= 12
                elif ratio > 0.5 and total >= 3:
                    findings.append(
                        Finding(
                            title=f"Moderate {cat} bias: {perspective} ({count}/{total})",
                            description=(
                                f"In '{cat}', {ratio:.0%} of your subscriptions lean "
                                f"'{perspective}'. This creates a detectable pattern."
                            ),
                            threat_level=ThreatLevel.MEDIUM,
                            remediation="Consider subscribing to channels from other perspectives.",
                        )
                    )
                    score -= 6

        # General YouTube tracking warning
        findings.append(
            Finding(
                title="YouTube shares subscription data with Google's ad network",
                description=(
                    "Your YouTube subscriptions feed into Google's advertising profile. "
                    "This data determines ad targeting across all Google services "
                    "(Search, Gmail, Maps, Android) and the 2M+ websites in Google's ad network."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Diversify subscriptions with dtm protect youtube --apply. "
                    "Periodically pause YouTube watch history in Google My Activity."
                ),
            )
        )
        score -= 5

    except AuthenticationRequired:
        raise
    except Exception as e:
        findings.append(
            Finding(
                title="Failed to fetch YouTube subscriptions",
                description=f"Error: {e}",
                threat_level=ThreatLevel.MEDIUM,
                remediation="Check authentication: dtm auth youtube",
            )
        )
        score = 50

    score = max(0, min(100, score))

    return AuditResult(
        module_name="youtube",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
