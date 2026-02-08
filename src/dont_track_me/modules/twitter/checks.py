"""Twitter/X privacy checks — settings that affect your trackability."""

from dont_track_me.core.base import ThreatLevel
from dont_track_me.core.checklist import PrivacyCheck

PRIVACY_CHECKS: list[PrivacyCheck] = [
    # --- visibility ---
    PrivacyCheck(
        id="protected_tweets",
        question="Are your tweets set to Protected?",
        description=(
            "Public tweets are indexed by search engines, scraped by data brokers, archived "
            "by the Wayback Machine, and ingested by AI training datasets. Anyone — employers, "
            "insurers, law enforcement — can read, screenshot, and aggregate your entire public "
            "timeline without your knowledge. Protected tweets are only visible to approved "
            "followers."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation=(
            "Settings > Privacy and safety > Audience and tagging > Protect your Tweets > toggle ON"
        ),
        category="visibility",
    ),
    PrivacyCheck(
        id="location_tagging",
        question="Is location tagging disabled for tweets?",
        description=(
            "When enabled, precise GPS coordinates are attached to your tweets as metadata. "
            "Even without precise location, Twitter infers your city from IP address and "
            "network data. A history of geotagged tweets reveals your home address, workplace, "
            "daily commute, and travel patterns — data used by advertisers and accessible to "
            "anyone viewing your profile."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Privacy and safety > Location information > "
            "Add location information to your posts > toggle OFF. "
            "Also: delete existing location data from previous tweets."
        ),
        category="visibility",
    ),
    PrivacyCheck(
        id="photo_tagging",
        question="Is photo tagging restricted to people you follow?",
        description=(
            "Unrestricted photo tagging allows anyone to associate your account with images "
            "you did not post. Tagged photos appear on your profile and can be used to place "
            "you at specific locations or events, link you to other people, or associate your "
            "identity with content you do not endorse."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            "Settings > Privacy and safety > Audience and tagging > "
            'Photo tagging > select "Only people you follow"'
        ),
        category="visibility",
    ),
    PrivacyCheck(
        id="discoverability_email",
        question="Is discoverability by email address disabled?",
        description=(
            "When enabled, anyone who has your email address can find your Twitter account. "
            "Data brokers and people-search sites that already have your email can cross-reference "
            "it to link your Twitter activity to your real identity — even if you use a pseudonym. "
            "This is a common technique for deanonymizing accounts."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Privacy and safety > Discoverability and contacts > "
            "Let people who have your email address find you > toggle OFF"
        ),
        category="visibility",
    ),
    PrivacyCheck(
        id="discoverability_phone",
        question="Is discoverability by phone number disabled?",
        description=(
            "Phone number lookup is even more dangerous than email — phone numbers are harder "
            "to change and more tightly bound to your real identity. Data brokers, SIM-swap "
            "attackers, and law enforcement can use your phone number to locate your account "
            "and correlate it with other platforms, financial records, and government databases."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Privacy and safety > Discoverability and contacts > "
            "Let people who have your phone number find you > toggle OFF"
        ),
        category="visibility",
    ),
    # --- data_sharing ---
    PrivacyCheck(
        id="personalized_ads",
        question="Is personalized advertising disabled?",
        description=(
            "Twitter builds an advertising profile with 350+ interest categories inferred from "
            "your tweets, likes, follows, and browsing behavior. This profile — which may include "
            "political leaning, health interests, financial status, and relationship indicators — "
            "is sold to advertisers for micro-targeting. Disabling personalized ads does not stop "
            "data collection but prevents it from being used for ad targeting."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation=(
            "Settings > Privacy and safety > Ads preferences > Personalized ads > toggle OFF"
        ),
        technical_countermeasure=(
            "Block analytics.twitter.com and static.ads-twitter.com via "
            "'dtm protect social --apply' or your hosts file."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="inferred_identity",
        question="Is inferred identity disabled?",
        description=(
            "Twitter uses device and browser signals — IP address, installed fonts, screen "
            "resolution, timezone, and language settings — to build an identity graph that links "
            "your Twitter activity to other online accounts and devices. This allows Twitter to "
            "track you even when you are logged out or using a different browser."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Privacy and safety > Ads preferences > Inferred identity > toggle OFF"
        ),
        technical_countermeasure=(
            "Use Firefox Multi-Account Containers to isolate Twitter. "
            "Run 'dtm protect fingerprint --apply' to enable resistFingerprinting."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="off_twitter_activity",
        question="Is off-Twitter activity tracking disabled?",
        description=(
            "Twitter tracks your activity across websites and apps that use Twitter's conversion "
            "tracking pixel, embedded tweets, or share buttons. This off-platform data — which "
            "sites you visit, what you purchase, what apps you use — is linked to your Twitter "
            "profile and used for ad targeting and audience segmentation."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation=(
            "Settings > Privacy and safety > Off-Twitter activity > "
            "Allow use of where you see Twitter content across the web > toggle OFF"
        ),
        technical_countermeasure=(
            "Install uBlock Origin to block Twitter's conversion pixel on third-party sites. "
            "Enable Firefox Enhanced Tracking Protection (Strict mode)."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="data_sharing_partners",
        question="Is data sharing with business partners disabled?",
        description=(
            "Twitter shares data with advertising partners who can then match your Twitter "
            "profile against their own customer databases using hashed email addresses, phone "
            "numbers, or device IDs. This enables cross-platform identity resolution — linking "
            "your Twitter behavior to purchases, subscriptions, and activity on other platforms."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Privacy and safety > Ads preferences > "
            "Data sharing with business partners > toggle OFF"
        ),
        technical_countermeasure=(
            "Block platform.twitter.com via hosts file, Pi-hole, or NextDNS "
            "to prevent partner data matching."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="contact_sync",
        question="Is address book syncing disabled?",
        description=(
            "Syncing your contacts uploads every phone number and email address in your address "
            "book to Twitter. This data is used to map your social network, suggest connections, "
            "and build profiles of people who do not use Twitter. Once uploaded, contact data "
            "is retained even if you later disable syncing."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Privacy and safety > Discoverability and contacts > "
            "Sync address book contacts > toggle OFF. "
            "Also: Manage contacts > delete all uploaded contacts."
        ),
        technical_countermeasure=(
            "Use the web browser instead of the mobile app — "
            "mobile apps can bypass network-level controls for contact upload."
        ),
        category="data_sharing",
    ),
    # --- security ---
    PrivacyCheck(
        id="two_factor_auth",
        question="Is two-factor authentication enabled?",
        description=(
            "Without 2FA, a leaked or guessed password gives full access to your account, "
            "DMs, and personal data. Twitter removed SMS-based 2FA for non-paying users in "
            "2023, but authenticator apps and security keys remain available for all accounts. "
            "A compromised account can be used for impersonation or to access your data archive."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Security and account access > Security > "
            "Two-factor authentication > enable using an authenticator app or security key"
        ),
        category="security",
    ),
    PrivacyCheck(
        id="dm_restricted",
        question="Are DMs restricted to people you follow?",
        description=(
            "Open DMs allow anyone to send you messages, including phishing links, social "
            "engineering attempts, and unsolicited content. Twitter DMs are not end-to-end "
            "encrypted by default, meaning Twitter employees and anyone who gains access to "
            "Twitter's systems can read them. DMs are also subject to legal subpoenas."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            "Settings > Privacy and safety > Direct Messages > "
            "Allow message requests from everyone > toggle OFF"
        ),
        category="security",
    ),
    PrivacyCheck(
        id="connected_apps",
        question="Have you reviewed and removed unnecessary connected apps?",
        description=(
            "Third-party apps authorized via Twitter OAuth retain access to your account data "
            "until you explicitly revoke them. Many apps request broad permissions (read tweets, "
            "read DMs, post on your behalf) and retain this access indefinitely — even apps you "
            "no longer use. Each connected app is a potential data leak or attack vector."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            "Settings > Security and account access > Apps and sessions > "
            "Connected apps > review and remove unnecessary apps"
        ),
        category="security",
    ),
]
