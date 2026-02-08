"""TikTok privacy checks — interactive self-assessment for TikTok settings."""

from __future__ import annotations

from dont_track_me.core.base import ThreatLevel
from dont_track_me.core.checklist import PrivacyCheck

PRIVACY_CHECKS: list[PrivacyCheck] = [
    # ── Visibility ──────────────────────────────────────────────────────
    PrivacyCheck(
        id="private_account",
        question="Is your account set to Private?",
        description=(
            "Public accounts let anyone see your videos, likes, and followers. "
            "TikTok's discovery algorithm pushes public content to millions."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation=(
            "Profile > Menu (\u2261) > Settings and Privacy > Privacy > Private Account > toggle ON"
        ),
        category="visibility",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="suggest_account",
        question='Is "Suggest your account to others" disabled?',
        description=(
            "TikTok recommends your profile to strangers based on contacts, "
            "Facebook connections, and behavioral similarities"
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings and Privacy > Privacy > Suggest your account to others > disable all toggles"
        ),
        category="visibility",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="duet_stitch",
        question="Are Duet and Stitch restricted to friends or nobody?",
        description=(
            "Public duets/stitches let strangers remix your content, associate "
            "your identity with any narrative, and amplify your reach without consent"
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            'Settings and Privacy > Privacy > Duet / Stitch > select "Friends" or "No one"'
        ),
        category="visibility",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="direct_messages",
        question="Are direct messages restricted to friends or nobody?",
        description=(
            "Open DMs allow spam, phishing, and unsolicited contact from anyone "
            "who discovers your profile"
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            'Settings and Privacy > Privacy > Direct Messages > select "Friends" or "No one"'
        ),
        category="visibility",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="liked_videos",
        question="Are liked videos set to private?",
        description=(
            "Your liked videos reveal interests, political views, and personal "
            "preferences \u2014 this list is public by default"
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings and Privacy > Privacy > Liked Videos > Only me",
        category="visibility",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="activity_status",
        question="Is activity status disabled?",
        description=(
            "Shows contacts when you were last active, enabling behavioral tracking and stalking"
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=("Settings and Privacy > Privacy > Activity Status > toggle OFF"),
        category="visibility",
        safe_answer=True,
    ),
    # ── Data sharing ────────────────────────────────────────────────────
    PrivacyCheck(
        id="personalized_ads",
        question="Is personalized ads disabled?",
        description=(
            "TikTok uses your watch history, search queries, and device data "
            "to build a detailed ad profile"
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings and Privacy > Privacy > Ads and Data > Personalized Ads > toggle OFF"
        ),
        technical_countermeasure=(
            "Block analytics.tiktok.com via 'dtm protect social --apply'. "
            "Use Pi-hole or NextDNS for network-wide blocking."
        ),
        category="data_sharing",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="ad_interests",
        question="Have you cleared ad interest categories?",
        description=(
            "TikTok assigns interest labels based on your behavior \u2014 clearing "
            "them forces the system to rebuild from scratch"
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            "Settings and Privacy > Privacy > Ads and Data > Ad Interest Categories > remove all"
        ),
        technical_countermeasure=(
            "Run 'dtm protect cookies --apply' to delete TikTok tracking cookies "
            "that store interest profiles."
        ),
        category="data_sharing",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="data_download",
        question="Have you reviewed your data download recently?",
        description=(
            "TikTok collects device fingerprints, keystroke patterns, clipboard "
            "content, and location data \u2014 reviewing shows exactly what they have"
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            "Settings and Privacy > Privacy > Personalization and Data > Download your data"
        ),
        category="data_sharing",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="ads_data_partners",
        question='Is "Ads from data partners" disabled?',
        description=(
            "TikTok receives data about you from third-party partners "
            "(purchases, app usage, website visits) to refine ad targeting"
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings and Privacy > Privacy > Ads and Data > "
            "Ads from TikTok's Advertising Partners > OFF"
        ),
        technical_countermeasure=(
            "Install uBlock Origin to block third-party data broker scripts "
            "that feed TikTok your off-platform activity."
        ),
        category="data_sharing",
        safe_answer=True,
    ),
    PrivacyCheck(
        id="third_party_data",
        question='Is "Share data with third parties" disabled?',
        description=(
            "TikTok shares your behavioral data and device identifiers with "
            "advertising partners for cross-platform tracking"
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings and Privacy > Privacy > Ads and Data > "
            "Off-TikTok Activity > manage and disconnect"
        ),
        technical_countermeasure=(
            "Block TikTok analytics domains at DNS level using "
            "AdGuard DNS (94.140.14.14) or Mullvad DNS (194.242.2.4)."
        ),
        category="data_sharing",
        safe_answer=True,
    ),
    # ── Security ────────────────────────────────────────────────────────
    PrivacyCheck(
        id="two_factor_auth",
        question="Is two-factor authentication enabled?",
        description=(
            "Without 2FA, a compromised password exposes your entire video "
            "history, messages, and behavioral profile"
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=("Settings and Privacy > Security > 2-Step Verification > enable"),
        category="security",
        safe_answer=True,
    ),
]
