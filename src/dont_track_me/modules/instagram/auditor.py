"""Instagram auditor — assess Instagram privacy exposure."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.core.checklist import compute_checklist_score
from dont_track_me.modules.instagram.checks import PRIVACY_CHECKS


async def audit_instagram(
    responses: dict[str, bool] | None = None, **kwargs: Any
) -> AuditResult:
    """Audit Instagram privacy settings.

    If responses are provided (interactive mode), compute a personalized score.
    Otherwise, return educational findings with a default score.
    """
    if responses:
        score, findings = compute_checklist_score(PRIVACY_CHECKS, responses)
        return AuditResult(
            module_name="instagram",
            score=score,
            findings=findings,
            raw_data={"mode": "interactive", "responses": responses},
        )

    # Non-interactive: educational findings
    findings = [
        Finding(
            title="Instagram builds a detailed advertising profile from your activity",
            description=(
                "Every like, follow, story view, and search is used to categorize you by age, "
                "gender, interests, political leaning, and purchasing behavior. This profile is "
                "shared with Meta's advertising network and used for micro-targeting."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation="Run 'dtm audit instagram -i' to check your privacy settings interactively.",
        ),
        Finding(
            title="Off-Instagram Activity tracks you across the web",
            description=(
                "Meta's tracking pixel is embedded on millions of websites. Every time you visit "
                "a site with a Meta pixel, Instagram records it — even when you're not using the app. "
                "This creates a browsing shadow profile linked to your account."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "Settings > Accounts Center > Your information and permissions > "
                "Off-Facebook Activity > Clear and disconnect."
            ),
        ),
        Finding(
            title="Public accounts expose your social graph to data brokers",
            description=(
                "With a public account, your followers, following list, likes, and comments are "
                "scraped by companies like Clearview AI, data brokers, and background check services. "
                "This data is aggregated to build profiles sold to employers, insurers, and governments."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation="Set your account to Private: Settings > Privacy > Account Privacy.",
        ),
        Finding(
            title="Contact syncing maps your entire real-world network",
            description=(
                "When you sync contacts, Meta receives your full address book — names, phone numbers, "
                "and email addresses of everyone you know, including people who don't use Instagram. "
                "This data is used to build social graph models and suggest connections."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation="Disable contact syncing: Settings > Accounts Center > Upload contacts > OFF.",
        ),
    ]

    return AuditResult(
        module_name="instagram",
        score=30,
        findings=findings,
        raw_data={
            "mode": "educational",
            "note": "Run 'dtm audit instagram -i' for a personalized score based on your settings.",
        },
    )
