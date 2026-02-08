"""Reddit auditor — audit privacy settings and subreddit bias."""

from __future__ import annotations

from dont_track_me.core.auth import AuthenticationRequired, TokenStore
from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.modules.reddit.client import TRACKING_PREFS, RedditClient
from dont_track_me.modules.reddit.subreddits import classify_subreddit


async def audit_reddit(**kwargs) -> AuditResult:
    """Audit Reddit privacy settings and subscription bias."""
    token = TokenStore.load("reddit")
    if token is None or token.is_expired:
        raise AuthenticationRequired("reddit")

    client = RedditClient(token)
    findings: list[Finding] = []
    score = 100
    raw_data: dict = {}

    # Phase 1: Privacy settings audit
    try:
        prefs = await client.get_prefs()
        raw_data["prefs"] = {k: prefs.get(k) for k in TRACKING_PREFS}

        hostile_count = 0
        for pref_name, pref_info in TRACKING_PREFS.items():
            current_value = prefs.get(pref_name)
            safe_value = pref_info["safe_value"]

            if current_value != safe_value:
                hostile_count += 1
                findings.append(
                    Finding(
                        title=f"Tracking enabled: {pref_name}",
                        description=pref_info["description"],
                        threat_level=ThreatLevel.HIGH,
                        remediation="Run: dtm protect reddit --apply --harden-only",
                    )
                )
                score -= 8  # ~8 per setting, 7 settings = -56 max

        if hostile_count == 0:
            findings.append(
                Finding(
                    title="All privacy settings are hardened",
                    description="All 7 Reddit tracking preferences are set to their safe values.",
                    threat_level=ThreatLevel.INFO,
                    remediation="No action needed.",
                )
            )

    except Exception as e:
        findings.append(
            Finding(
                title="Failed to read Reddit preferences",
                description=f"Could not fetch privacy settings: {e}",
                threat_level=ThreatLevel.MEDIUM,
                remediation="Check your authentication: dtm auth reddit",
            )
        )
        score -= 20

    # Phase 2: Subscription bias analysis
    try:
        subreddits = await client.get_subscribed_subreddits()
        raw_data["subreddit_count"] = len(subreddits)

        # Classify subscriptions
        category_counts: dict[str, dict[str, int]] = {}
        classified = 0
        for sub in subreddits:
            result = classify_subreddit(sub)
            if result:
                cat, perspective = result
                classified += 1
                category_counts.setdefault(cat, {})
                category_counts[cat][perspective] = (
                    category_counts[cat].get(perspective, 0) + 1
                )

        raw_data["classified"] = classified
        raw_data["category_breakdown"] = category_counts

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
                                f"In the '{cat}' category, {ratio:.0%} of your subscriptions "
                                f"lean '{perspective}'. This creates a clear profiling signal."
                            ),
                            threat_level=ThreatLevel.HIGH,
                            remediation="Run: dtm protect reddit --apply --diversify-only",
                        )
                    )
                    score -= 10

    except Exception as e:
        findings.append(
            Finding(
                title="Failed to read Reddit subscriptions",
                description=f"Could not fetch subreddit list: {e}",
                threat_level=ThreatLevel.MEDIUM,
                remediation="Check your authentication: dtm auth reddit",
            )
        )

    score = max(0, min(100, score))

    return AuditResult(
        module_name="reddit",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
