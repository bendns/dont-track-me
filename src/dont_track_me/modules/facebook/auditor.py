"""Facebook auditor — assess Facebook privacy exposure."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.core.checklist import compute_checklist_score
from dont_track_me.modules.facebook.checks import PRIVACY_CHECKS


async def audit_facebook(responses: dict[str, bool] | None = None, **kwargs: Any) -> AuditResult:
    """Audit Facebook privacy settings.

    With *responses*: compute a personalized score from the interactive checklist.
    Without: return educational findings about Facebook's surveillance practices.
    """
    if responses is not None:
        score, findings = compute_checklist_score(PRIVACY_CHECKS, responses)
        return AuditResult(
            module_name="facebook",
            score=score,
            findings=findings,
            raw_data={"mode": "interactive", "responses": responses},
        )

    # Non-interactive: educational findings about Facebook tracking
    findings: list[Finding] = [
        Finding(
            title="Off-Facebook Activity tracks you across millions of websites",
            description=(
                "Meta's tracking pixel is embedded on over 8.4 million websites. Every time "
                "you visit a site with a Meta pixel — including health portals, banking sites, "
                "and shopping platforms — your browsing activity is sent directly to Facebook "
                "and linked to your profile. This happens even when you are not actively using "
                "Facebook, building a comprehensive shadow browsing history that reveals medical "
                "conditions, financial decisions, political interests, and purchasing behavior."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "Settings > Your Facebook Information > Off-Facebook Activity > "
                "Clear history > Disconnect future activity"
            ),
        ),
        Finding(
            title="Shadow profiles are built for people who never signed up",
            description=(
                "When Facebook users sync their contacts, Facebook receives phone numbers and "
                "email addresses of people who have never created an account. Facebook combines "
                "this with Meta pixel data, IP address correlations, and device fingerprinting "
                "to build detailed 'shadow profiles' of non-users. These profiles contain "
                "inferred demographics, social connections, browsing habits, and location "
                "data — all without consent or any way to opt out."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "Disable contact syncing on all devices: Settings > Your Facebook Information > "
                "Upload contacts > disable. Ask friends and family to do the same."
            ),
        ),
        Finding(
            title="Ad targeting uses 98+ data points including offline purchases",
            description=(
                "Facebook's ad system categorizes users using at least 98 data points spanning "
                "demographics, behaviors, interests, life events, political affiliation, income "
                "bracket, and purchasing power. Data brokers like Acxiom, Experian, and Oracle "
                "Data Cloud feed Facebook your offline purchases, loyalty card activity, and "
                "credit card transactions — linking what you buy in physical stores to your "
                "online profile. This enables predictive modeling that anticipates major life "
                "events like pregnancies, job changes, and relationship status shifts."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Settings > Ads > Ad Settings > Data about your activity from partners > "
                "Not allowed. Also review: Categories used to reach you > remove all."
            ),
        ),
        Finding(
            title="DeepFace identifies you in photos you did not upload",
            description=(
                "Facebook's DeepFace facial recognition system achieves 97.35% accuracy — "
                "approaching human-level performance. When anyone uploads a photo, DeepFace "
                "scans every face and matches it against its database of facial templates. "
                "This means you can be identified and tracked in photos taken without your "
                "knowledge or consent. Your facial geometry is stored as a 128-dimensional "
                "mathematical vector that persists even if you delete your account."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Settings > Face Recognition > toggle OFF. Note: this feature has been "
                "removed in some regions due to legal action (e.g., Illinois BIPA lawsuit "
                "resulting in a $650M settlement)."
            ),
        ),
        Finding(
            title="Contact and call log syncing maps your entire communication network",
            description=(
                "When enabled, Facebook uploads your full address book, call history "
                "(including duration and frequency), and SMS metadata from your phone. This "
                "data reveals who you communicate with, how often, at what times, and for "
                "how long — enabling Facebook to map your complete social and professional "
                "network. This information is used to refine friend suggestions, build "
                "advertising audiences, and construct shadow profiles for non-users."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Settings > Your Facebook Information > Upload contacts > "
                "disable on all devices. Remove previously uploaded contacts."
            ),
        ),
    ]

    return AuditResult(
        module_name="facebook",
        score=30,
        findings=findings,
        raw_data={
            "mode": "educational",
            "note": "Run 'dtm audit facebook -i' for a personalized score.",
        },
    )
