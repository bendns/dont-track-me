"""Twitter/X auditor — assess Twitter/X privacy exposure."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.core.checklist import compute_checklist_score
from dont_track_me.modules.twitter.checks import PRIVACY_CHECKS


async def audit_twitter(responses: dict[str, bool] | None = None, **kwargs: Any) -> AuditResult:
    """Audit Twitter/X privacy settings.

    If responses are provided (interactive mode), compute a personalized score.
    Otherwise, return educational findings with a default score.
    """
    if responses is not None:
        score, findings = compute_checklist_score(PRIVACY_CHECKS, responses)
        return AuditResult(
            module_name="twitter",
            score=score,
            findings=findings,
            raw_data={"mode": "interactive", "responses": responses},
        )

    # Non-interactive: educational findings
    findings = [
        Finding(
            title="Twitter/X tracks your activity across the web via conversion tracking",
            description=(
                "Twitter's conversion tracking pixel is embedded on over 1 million websites. "
                "When you visit any site with this pixel — news outlets, e-commerce stores, "
                "political campaigns — Twitter records the visit and links it to your profile. "
                "Combined with t.co link wrapping (every outbound link you click is routed "
                "through Twitter's servers), Twitter builds a detailed browsing history that "
                "extends far beyond the platform itself."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "Run 'dtm audit twitter -i' to check your privacy settings interactively."
            ),
        ),
        Finding(
            title="Your ad profile categorizes you by 350+ interest segments",
            description=(
                "Twitter infers your interests, demographics, political leaning, and purchasing "
                "behavior from your tweets, likes, follows, and browsing activity. These "
                "categorizations — which you can view at Settings > Ads preferences > Interests "
                "— are sold to advertisers for micro-targeting. Twitter also uses 'inferred "
                "identity' to link your activity across devices and browsers using fingerprinting "
                "techniques, even when you are logged out."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "Settings > Privacy and safety > Ads preferences > "
                "Personalized ads > toggle OFF. Also disable inferred identity."
            ),
        ),
        Finding(
            title="Discoverability settings expose your identity through email/phone lookup",
            description=(
                "By default, anyone with your email address or phone number can find your "
                "Twitter account. Data brokers that already have your contact information can "
                "cross-reference it to link your pseudonymous Twitter activity to your real "
                "identity. In 2022, a vulnerability in this feature was exploited to scrape "
                "the email-to-account mappings of over 200 million users."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Settings > Privacy and safety > Discoverability and contacts > "
                "disable both email and phone discoverability."
            ),
        ),
        Finding(
            title="Tweet metadata reveals location and behavioral patterns",
            description=(
                "Geotagged tweets reveal your precise location. Even without explicit "
                "geotags, your posting times, language patterns, timezone, and interaction "
                "patterns allow inference of your approximate location, work schedule, and "
                "daily routine. This metadata is indexed by search engines and scraped by "
                "OSINT tools used by investigators, journalists, and threat actors."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Settings > Privacy and safety > Location information > "
                "disable location tagging and delete existing location data."
            ),
        ),
    ]

    return AuditResult(
        module_name="twitter",
        score=30,
        findings=findings,
        raw_data={
            "mode": "educational",
            "note": "Run 'dtm audit twitter -i' for a personalized score based on your settings.",
        },
    )
