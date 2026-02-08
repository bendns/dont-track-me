"""Instagram privacy checks — settings that affect your trackability."""

from dont_track_me.core.base import ThreatLevel
from dont_track_me.core.checklist import PrivacyCheck

PRIVACY_CHECKS: list[PrivacyCheck] = [
    # --- visibility ---
    PrivacyCheck(
        id="private_account",
        question="Is your account set to Private?",
        description=(
            "A public account exposes your posts, followers, and following list to anyone — "
            "including data brokers, employers, and stalkers. Instagram indexes public profiles "
            "in search engines, making them discoverable to background check services and "
            "scraping tools like Clearview AI."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation="Settings > Privacy > Account Privacy > toggle ON",
        category="visibility",
    ),
    PrivacyCheck(
        id="activity_status",
        question="Is Activity Status disabled?",
        description=(
            "Activity Status shows when you were last online or are currently active. This "
            "enables behavioral profiling (when you sleep, when you're free, your timezone) "
            "and can be exploited for stalking. Third-party tools scrape this data to build "
            "activity timelines."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Privacy > Activity Status > toggle OFF",
        category="visibility",
    ),
    PrivacyCheck(
        id="story_sharing",
        question="Is story sharing to other apps disabled?",
        description=(
            "Cross-platform story sharing expands your tracking surface by syndicating your "
            "content to Facebook and other connected platforms. Each platform adds its own "
            "tracking layer, and the shared content may have different privacy defaults on "
            "the destination platform."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation="Settings > Privacy > Story > disable sharing to Facebook/other apps",
        category="visibility",
    ),
    PrivacyCheck(
        id="mentions_restricted",
        question="Are mentions restricted to people you follow?",
        description=(
            "Unrestricted mentions allow strangers to associate your account with any content, "
            "including spam, scams, or objectionable material. This can be used to manipulate "
            "your public image or draw unwanted attention to your profile."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation='Settings > Privacy > Mentions > select "People you follow"',
        category="visibility",
    ),
    PrivacyCheck(
        id="tag_approval",
        question="Do tags require your manual approval?",
        description=(
            "Auto-approved tags let others attach your identity to photos without your consent. "
            "Tagged photos appear on your profile and can reveal your location, companions, and "
            "activities to anyone who views your profile."
        ),
        threat_level=ThreatLevel.LOW,
        remediation='Settings > Privacy > Posts > toggle "Manually approve tags" ON',
        category="visibility",
    ),
    # --- data_sharing ---
    PrivacyCheck(
        id="third_party_apps",
        question="Are third-party app permissions revoked?",
        description=(
            "Connected third-party apps access your profile data, posts, and follower list "
            "continuously — not just at the moment you authorize them. Many apps retain broad "
            "permissions long after you stop using them, creating persistent data leaks to "
            "companies you may no longer trust."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Security > Apps and Websites > remove all unnecessary apps",
        category="data_sharing",
    ),
    PrivacyCheck(
        id="ad_personalization",
        question="Is ad personalization limited?",
        description=(
            "Instagram uses your activity, location, and interests to build a detailed "
            "advertising profile. This profile categorizes you by demographics, purchasing "
            "behavior, political leaning, and hundreds of other attributes — then sells "
            "access to advertisers for micro-targeting."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Accounts Center > Ad Preferences > Ad Settings > limit personalization",
        category="data_sharing",
    ),
    PrivacyCheck(
        id="off_instagram_activity",
        question="Is Off-Instagram Activity paused/cleared?",
        description=(
            "Meta tracks you across the web via tracking pixels embedded on millions of "
            "third-party websites. Every time you visit a site with a Meta pixel, Instagram "
            "records it — even when you're not using the app. This creates a browsing shadow "
            "profile linked to your account that reveals health searches, shopping habits, "
            "and sensitive interests."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation=(
            "Settings > Accounts Center > Your information and permissions > "
            "Off-Facebook Activity > Clear history and disconnect"
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="contact_sync",
        question="Is contact syncing disabled?",
        description=(
            "Uploading your contacts lets Meta map your entire social network, including "
            "people who don't use Instagram. Phone numbers and email addresses of your "
            "contacts are stored permanently and used to build social graph models, suggest "
            "connections, and create shadow profiles for non-users."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Accounts Center > Your information and permissions > "
            "Upload contacts > toggle OFF"
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="search_history",
        question="Have you cleared your search history?",
        description=(
            "Instagram retains your search history indefinitely, revealing interests, people "
            "you've looked up, and topics you've explored. This data is used for ad targeting "
            "and could be exposed in a data breach or legal subpoena, revealing sensitive "
            "searches you assumed were private."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation="Settings > Security > Search history > Clear all",
        category="data_sharing",
    ),
    # --- security ---
    PrivacyCheck(
        id="two_factor_auth",
        question="Is two-factor authentication enabled?",
        description=(
            "Without 2FA, a compromised password gives attackers full access to your profile, "
            "DMs, and personal data. SIM-swap attacks and credential stuffing make password-only "
            "accounts especially vulnerable. An attacker with account access can also download "
            "your complete data archive."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Accounts Center > Password and Security > "
            "Two-factor authentication > enable"
        ),
        category="security",
    ),
    PrivacyCheck(
        id="login_activity",
        question="Have you reviewed login activity recently?",
        description=(
            "Unauthorized sessions can silently monitor your activity, messages, and personal "
            "information without triggering any notification. Regularly reviewing active sessions "
            "helps detect compromised accounts before significant damage occurs."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            "Settings > Accounts Center > Password and Security > "
            "Where you're logged in > review"
        ),
        category="security",
    ),
]
