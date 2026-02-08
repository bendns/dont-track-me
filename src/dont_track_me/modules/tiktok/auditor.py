"""TikTok auditor — assess TikTok privacy exposure."""

from __future__ import annotations

from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.core.checklist import compute_checklist_score
from dont_track_me.modules.tiktok.checks import PRIVACY_CHECKS


async def audit_tiktok(
    responses: dict[str, bool] | None = None, **kwargs: Any
) -> AuditResult:
    """Run the TikTok privacy audit.

    With *responses*: score the interactive checklist.
    Without: return educational findings about TikTok's tracking practices.
    """
    if responses:
        score, findings = compute_checklist_score(PRIVACY_CHECKS, responses)
        return AuditResult(
            module_name="tiktok",
            score=score,
            findings=findings,
            raw_data={"mode": "interactive", "responses": responses},
        )

    # Non-interactive: educational findings about TikTok tracking
    findings = [
        Finding(
            title="TikTok's algorithm builds a detailed profile within minutes",
            description=(
                "TikTok's recommendation engine analyzes watch time, pauses, "
                "replays, scroll speed, and hesitation patterns to classify "
                "users into behavioral clusters. Research has shown the algorithm "
                "can accurately infer political orientation, mental health "
                "indicators, and personal vulnerabilities after fewer than "
                "40 minutes of usage. Unlike platforms that rely on explicit "
                "signals (likes, follows), TikTok's For You Page is driven by "
                "implicit behavioral data that users cannot easily control."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "Set your account to private, limit usage time, and avoid "
                "interacting with content you do not want associated with "
                "your profile. Use TikTok's 'Not Interested' feature "
                "aggressively to disrupt profiling."
            ),
        ),
        Finding(
            title="Device fingerprinting and cross-app tracking",
            description=(
                "TikTok collects hardware identifiers (IMEI, Android ID, "
                "MAC address), installed app lists, battery status, audio "
                "settings, screen resolution, and network configuration. "
                "This data creates a unique device fingerprint that persists "
                "across app reinstalls and account changes. The TikTok Pixel "
                "and SDK embedded in third-party apps and websites extend "
                "this tracking beyond the TikTok app itself."
            ),
            threat_level=ThreatLevel.CRITICAL,
            remediation=(
                "Disable ad personalization, revoke unnecessary app "
                "permissions (location, contacts, microphone when not "
                "recording), and use a privacy-focused browser to avoid "
                "TikTok Pixel tracking on websites."
            ),
        ),
        Finding(
            title="Behavioral data collection: keystrokes, clipboard, watch patterns",
            description=(
                "TikTok's in-app browser injects JavaScript that monitors "
                "keystroke timing and input patterns. The app has been "
                "documented reading clipboard contents on launch. Combined "
                "with precise watch-time telemetry (down to millisecond "
                "pause and replay events), TikTok captures a granular "
                "behavioral signature unique to each user."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Avoid using TikTok's in-app browser for any web activity. "
                "Open links in your default browser instead. On iOS, enable "
                "clipboard access notifications. On Android, revoke clipboard "
                "permissions where possible."
            ),
        ),
        Finding(
            title="Data shared with advertising partners and third parties",
            description=(
                "TikTok shares device identifiers, hashed email addresses, "
                "behavioral segments, and engagement data with advertising "
                "partners. The 'Off-TikTok Activity' feature reveals that "
                "data flows bidirectionally: partners send purchase and "
                "browsing data to TikTok, and TikTok shares user segments "
                "back. This enables cross-platform identity resolution and "
                "tracking that persists even if you delete TikTok."
            ),
            threat_level=ThreatLevel.HIGH,
            remediation=(
                "Disable personalized ads, turn off ads from data partners, "
                "clear ad interest categories, and disconnect Off-TikTok "
                "Activity. Review your data download to see exactly what "
                "has been collected."
            ),
        ),
    ]

    return AuditResult(
        module_name="tiktok",
        score=30,
        findings=findings,
        raw_data={
            "mode": "educational",
            "note": "Run 'dtm audit tiktok -i' for a personalized score.",
        },
    )
