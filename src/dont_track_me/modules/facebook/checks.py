"""Facebook privacy checks — settings that affect your trackability."""

from dont_track_me.core.base import ThreatLevel
from dont_track_me.core.checklist import PrivacyCheck

PRIVACY_CHECKS: list[PrivacyCheck] = [
    # --- visibility ---
    PrivacyCheck(
        id="posts_friends_only",
        question='Are your posts set to "Friends only"?',
        description=(
            "Public posts are indexed by search engines, scraped by data brokers, and "
            "visible to anyone with a browser. Every public post becomes a permanent record "
            "that can be archived by the Wayback Machine, scraped by Clearview AI, or "
            "surfaced in background checks."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation="Settings > Privacy > Who can see your future posts > Friends",
        category="visibility",
    ),
    PrivacyCheck(
        id="default_audience",
        question='Is your default posting audience set to "Friends"?',
        description=(
            "New posts inherit this default — if set to Public, every status update is "
            "exposed until manually changed. Many users unknowingly post publicly for months "
            "because they never checked this setting after account creation."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Privacy > Who can see your future posts > Friends",
        category="visibility",
    ),
    PrivacyCheck(
        id="friend_list_hidden",
        question="Is your friend list hidden from public?",
        description=(
            "A public friend list reveals your social network — employers, governments, and "
            "stalkers use it to map connections. Intelligence agencies and social engineering "
            "attackers use friend lists to identify high-value targets and build trust chains "
            "for phishing attacks."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Privacy > Who can see your friends list > Only me",
        category="visibility",
    ),
    PrivacyCheck(
        id="search_by_contact",
        question="Is profile search by email/phone disabled?",
        description=(
            "Allows anyone with your email or phone number to find your Facebook profile — "
            "used by stalkers and data enrichment services. Phone number enumeration attacks "
            "can systematically link phone numbers to Facebook profiles at scale, enabling "
            "mass de-anonymization."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Privacy > Who can look you up using your email/phone > Friends",
        category="visibility",
    ),
    PrivacyCheck(
        id="search_engine_indexing",
        question="Is search engine indexing disabled?",
        description=(
            "Allows Google to index your Facebook profile, making it permanently cached and "
            "discoverable. Even after you change settings, cached versions persist in search "
            "engine indexes for weeks or months, and may be archived by third-party services "
            "indefinitely."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            "Settings > Privacy > Do you want search engines outside of Facebook "
            "to link to your profile > No"
        ),
        category="visibility",
    ),
    # --- data_sharing ---
    PrivacyCheck(
        id="off_facebook_activity",
        question="Is Off-Facebook Activity cleared and disconnected?",
        description=(
            "Meta's tracking pixel on millions of websites sends your browsing history to "
            "Facebook — purchases, searches, medical sites visited. This creates a comprehensive "
            "shadow browsing profile linked to your account, revealing health conditions, "
            "financial decisions, and sensitive interests you never shared on Facebook."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation=(
            "Settings > Your Facebook Information > Off-Facebook Activity > "
            "Clear history > Disconnect future activity"
        ),
        technical_countermeasure=(
            "Block connect.facebook.net and pixel.facebook.com via "
            "'dtm protect social --apply'. Install uBlock Origin to block Meta pixels on third-party sites."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="ad_personalization",
        question="Is ad personalization disabled?",
        description=(
            "Facebook uses 98+ data points about you for ad targeting — interests, behaviors, "
            "life events, politics, income bracket. This behavioral model predicts your "
            "purchasing decisions, political views, emotional state, and vulnerability to "
            "specific advertising techniques."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Ads > Ad Settings > Data about your activity from partners > Not allowed",
        technical_countermeasure=(
            "Run 'dtm protect social --apply' to delete Meta advertising cookies. "
            "Enable Firefox ETP Strict mode to block cross-site trackers."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="ads_data_partners",
        question='Are "Ads based on data from partners" disabled?',
        description=(
            "Third-party data brokers feed Facebook your offline purchases, loyalty card data, "
            "and credit card transactions. Companies like Acxiom, Experian, and Oracle Data "
            "Cloud supply Facebook with data about what you buy in physical stores, linking "
            "your offline life to your online profile."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Ads > Ad Settings > Categories used to reach you > remove all",
        technical_countermeasure=(
            "Block Facebook tracking domains at DNS level using Pi-hole, NextDNS, or AdGuard DNS."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="ads_activity",
        question='Are "Ads based on your activity" limited?',
        description=(
            "Facebook tracks every click, hover, and reaction to refine its behavioral model "
            "and predict future actions. This includes time spent viewing posts, scroll speed, "
            "and interaction patterns — building a psychological profile that predicts what "
            "you will do next."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Ads > Ad Settings > Audience-based advertising > "
            "review and remove advertisers"
        ),
        technical_countermeasure=(
            "Use Firefox Multi-Account Containers to isolate Facebook, "
            "preventing cross-site behavioral tracking."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="face_recognition",
        question="Is face recognition disabled?",
        description=(
            "Facebook's DeepFace system identifies you in photos with 97.35% accuracy — "
            "even in photos uploaded by others. Your facial template is stored as a mathematical "
            "representation that can be matched against any photo uploaded to the platform, "
            "regardless of who uploaded it or whether you were tagged."
        ),
        threat_level=ThreatLevel.CRITICAL,
        remediation=(
            "Settings > Face Recognition > toggle OFF "
            "(or check if removed in your region due to legal pressure)"
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="location_history",
        question="Is location history disabled?",
        description=(
            "Facebook records your GPS location continuously when enabled — mapping where "
            "you live, work, travel, and who you visit. Location data reveals patterns of "
            "life including medical visits, religious attendance, political gatherings, and "
            "personal relationships that you may not share publicly."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation="Settings > Location > Location History > toggle OFF",
        technical_countermeasure=(
            "Revoke location permission for the Facebook app at OS level "
            "(macOS: System Settings > Privacy & Security > Location Services)."
        ),
        category="data_sharing",
    ),
    PrivacyCheck(
        id="contact_sync",
        question="Is contact/call log syncing disabled?",
        description=(
            "Facebook uploads your full address book, call history, and SMS metadata — "
            "mapping your communications network. This data is used to build shadow profiles "
            "for people who have never created a Facebook account, and to infer relationships "
            "and communication patterns across your entire social circle."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=(
            "Settings > Your Facebook Information > Upload contacts > disable on all devices"
        ),
        category="data_sharing",
    ),
    # --- security ---
    PrivacyCheck(
        id="two_factor_auth",
        question="Is two-factor authentication enabled?",
        description=(
            "A compromised Facebook account exposes years of messages, photos, and personal "
            "information. Without 2FA, a single leaked password from any data breach gives "
            "attackers full access to your account, including the ability to download your "
            "complete data archive."
        ),
        threat_level=ThreatLevel.HIGH,
        remediation=("Settings > Security and Login > Two-Factor Authentication > enable"),
        category="security",
    ),
    PrivacyCheck(
        id="login_alerts",
        question="Are login alerts enabled?",
        description=(
            "Without alerts, unauthorized access goes undetected — attackers can monitor "
            "your account silently. They can read private messages, impersonate you, and "
            "exfiltrate data for days or weeks before you notice anything unusual."
        ),
        threat_level=ThreatLevel.MEDIUM,
        remediation=(
            "Settings > Security and Login > Get alerts about unrecognized logins > enable"
        ),
        category="security",
    ),
]
