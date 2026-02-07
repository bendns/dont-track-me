"""Social noise auditor — assess social media profiling exposure."""

from __future__ import annotations

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel


async def audit_social_noise(**kwargs) -> AuditResult:
    """Audit social media profiling risk.

    This is primarily educational — we can't access your actual social media
    accounts. Instead, we highlight the risks and score based on general
    exposure patterns.
    """
    findings: list[Finding] = []
    score = 30  # Default: most people are heavily exposed

    findings.append(
        Finding(
            title="Social media following lists reveal your identity profile",
            description=(
                "Platforms like Instagram, TikTok, Facebook, and YouTube build detailed "
                "profiles based on who you follow. If you only follow artists from one genre, "
                "politicians from one party, or news from one perspective — your beliefs, "
                "sexuality, religion, and political leaning are exposed. Example: a man "
                "following only pop divas may be profiled as gay. Someone following only "
                "left-wing accounts is categorized as a left-wing voter."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "Run 'dtm noise social --apply' to generate balanced follow lists. "
                "Follow accounts from all perspectives to make your profile unreadable."
            ),
        )
    )

    findings.append(
        Finding(
            title="Instagram/Facebook share following data with advertisers",
            description=(
                "Meta (Instagram, Facebook) uses your follow list, likes, and interactions "
                "to build an ad profile. Advertisers can target you based on 'interests' "
                "inferred from who you follow. This data is also available to political "
                "campaigns for voter micro-targeting."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "1. Follow diverse accounts across all political/cultural spectrums\n"
                "2. Periodically clear your ad preferences in Meta settings\n"
                "3. Use 'Off-Facebook Activity' settings to limit data sharing"
            ),
        )
    )

    findings.append(
        Finding(
            title="YouTube watch history and subscriptions reveal ideology",
            description=(
                "YouTube's recommendation algorithm categorizes you based on subscriptions "
                "and watch history. Research shows this creates 'filter bubbles' that "
                "radicalize viewers. Your YouTube profile is shared with Google's ad network."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Subscribe to channels from all political perspectives. "
                "Regularly pause and clear your YouTube watch history. "
                "Use YouTube in incognito mode for sensitive topics."
            ),
        )
    )

    findings.append(
        Finding(
            title="TikTok algorithm profiling",
            description=(
                "TikTok's algorithm builds an extremely detailed interest profile within "
                "minutes of use. Your For You page reveals your inferred age, gender, "
                "sexuality, politics, and emotional state. This data is stored on servers "
                "accessible to the platform's parent company."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Actively engage with diverse content. Follow accounts outside your "
                "typical interests. Use 'Not Interested' on overly targeted content. "
                "Periodically reset your For You page via settings."
            ),
        )
    )

    findings.append(
        Finding(
            title="Data brokers aggregate social profiles across platforms",
            description=(
                "Companies like Palantir, Clearview AI, and data brokers aggregate your "
                "public social media data across all platforms. Your Instagram follows + "
                "YouTube subscriptions + Twitter likes = a comprehensive ideological profile "
                "that can be sold to governments, employers, or insurance companies."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "1. Make your follow lists private where possible\n"
                "2. Diversify your follows across all platforms\n"
                "3. Regularly audit your public social media presence\n"
                "4. Use 'dtm noise social --apply' to generate balanced follow lists"
            ),
        )
    )

    return AuditResult(
        module_name="social_noise",
        score=score,
        findings=findings,
        raw_data={
            "note": "Social media audit is educational — cannot access actual account data without OAuth",
            "platforms_covered": [
                "instagram",
                "youtube",
                "tiktok",
                "facebook",
                "twitter",
            ],
        },
    )
