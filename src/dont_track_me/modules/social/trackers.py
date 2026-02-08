"""Social media tracker domain registry and lookup helpers."""

from __future__ import annotations

# Platform name -> set of known tracker/pixel domains
SOCIAL_TRACKER_DOMAINS: dict[str, set[str]] = {
    "Meta (Facebook/Instagram)": {
        "facebook.com",
        "facebook.net",
        "fbcdn.net",
        "instagram.com",
        "fbsbx.com",
        "connect.facebook.net",
    },
    "Google": {
        "google-analytics.com",
        "analytics.google.com",
        "googletagmanager.com",
        "googletagservices.com",
        "googlesyndication.com",
        "googleadservices.com",
        "doubleclick.net",
    },
    "Twitter/X": {
        "twitter.com",
        "t.co",
        "ads-twitter.com",
        "analytics.twitter.com",
        "platform.twitter.com",
    },
    "TikTok": {
        "tiktok.com",
        "tiktokcdn.com",
        "analytics.tiktok.com",
    },
    "LinkedIn": {
        "linkedin.com",
        "licdn.com",
        "snap.licdn.com",
    },
    "Pinterest": {
        "pinterest.com",
        "pinimg.com",
        "ct.pinterest.com",
    },
    "Snapchat": {
        "snap.com",
        "snapchat.com",
        "sc-static.net",
        "tr.snapchat.com",
    },
    "Reddit": {
        "reddit.com",
        "redditmedia.com",
        "redditstatic.com",
    },
}

# Flat set of all social tracker domains
ALL_SOCIAL_DOMAINS: set[str] = set()
for _domains in SOCIAL_TRACKER_DOMAINS.values():
    ALL_SOCIAL_DOMAINS.update(_domains)

# Reverse lookup: domain -> platform name
_DOMAIN_TO_PLATFORM: dict[str, str] = {}
for _platform, _domains in SOCIAL_TRACKER_DOMAINS.items():
    for _domain in _domains:
        _DOMAIN_TO_PLATFORM[_domain] = _platform


def is_social_tracker(host: str) -> tuple[bool, str, str]:
    """Check if a host belongs to a known social tracker domain.

    Returns (is_social, matched_domain, platform_name).
    """
    host = host.lstrip(".").lower()

    # Exact match
    if host in ALL_SOCIAL_DOMAINS:
        return True, host, _DOMAIN_TO_PLATFORM[host]

    # Subdomain match: "pixel.facebook.com" matches "facebook.com"
    for domain in ALL_SOCIAL_DOMAINS:
        if host.endswith("." + domain):
            return True, domain, _DOMAIN_TO_PLATFORM[domain]

    return False, "", ""


# Focused pixel/SDK subdomains to recommend blocking in /etc/hosts
SOCIAL_HOSTS_BLOCKLIST: list[str] = [
    # Meta
    "connect.facebook.net",
    "pixel.facebook.com",
    "www.facebook.com",
    # Google Analytics / Tag Manager
    "www.google-analytics.com",
    "ssl.google-analytics.com",
    "www.googletagmanager.com",
    # Twitter/X
    "analytics.twitter.com",
    "static.ads-twitter.com",
    "t.co",
    # TikTok
    "analytics.tiktok.com",
    # LinkedIn
    "snap.licdn.com",
    "px.ads.linkedin.com",
    # Pinterest
    "ct.pinterest.com",
    # Snapchat
    "tr.snapchat.com",
    "sc-static.net",
]

# Anti-tracker browser extensions (content blockers)
ANTI_TRACKER_EXTENSIONS: dict[str, str] = {
    # Firefox extension IDs
    "uBlock0@AK": "uBlock Origin",
    "jid1-MnnxcxisBPnSXQ@jetpack": "Privacy Badger",
    "{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}": "Adblock Plus",
    "jid1-ZAdIEUB7XOzOJw@jetpack": "DuckDuckGo Privacy Essentials",
    "{446900e4-71c2-419f-a6a7-df9c091e268b}": "Disconnect",
    "firefox@ghostery.com": "Ghostery",
    "adguardadblocker@adguard.com": "AdGuard AdBlocker",
    # Chrome extension IDs
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
    "pkehgijcmpdhfbdbbnkijodmdjhbjlgp": "Privacy Badger",
    "bgnkhhnnamicmpeenaelnjfhikgbkllg": "AdGuard AdBlocker",
    "mcgekeccgjgcmhnhbabplanchdogjcnh": "Disconnect",
    "mlomiejdfkolichcflejclcbmpeaniij": "Ghostery",
    "caacbgbklghmpodbdafajbgdnegacfmo": "DuckDuckGo Privacy Essentials",
}

ANTI_TRACKER_NAME_PATTERNS: list[str] = [
    "ublock origin",
    "privacy badger",
    "adblock",
    "ghostery",
    "disconnect",
    "adguard",
    "duckduckgo privacy",
]

# Known tracker-blocking DNS resolvers
TRACKER_BLOCKING_DNS: dict[str, str] = {
    "45.90.28.0": "NextDNS",
    "45.90.30.0": "NextDNS",
    "94.140.14.14": "AdGuard DNS",
    "94.140.15.15": "AdGuard DNS",
    "176.103.130.130": "AdGuard DNS",
    "176.103.130.131": "AdGuard DNS",
    "194.242.2.3": "Mullvad DNS (ad-blocking)",
    "194.242.2.4": "Mullvad DNS (tracker + ad-blocking)",
}
