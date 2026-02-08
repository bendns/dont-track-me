"""Known third-party tracking cookie domains."""

from __future__ import annotations

# Domains known for setting third-party tracking cookies.
# These are ad networks, analytics platforms, social trackers, and data brokers
# that track users across websites via cookies.
TRACKER_COOKIE_DOMAINS: set[str] = {
    # Google ad/tracking network
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googletagservices.com",
    "googlevideo.com",
    "gstatic.com",
    # Facebook / Meta
    "facebook.com",
    "facebook.net",
    "fbcdn.net",
    "instagram.com",
    # Microsoft / Bing
    "bat.bing.com",
    "bing.com",
    "clarity.ms",
    # Ad exchanges and DSPs
    "adsrvr.org",
    "criteo.com",
    "criteo.net",
    "outbrain.com",
    "taboola.com",
    "amazon-adsystem.com",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "indexexchange.com",
    "adnxs.com",
    "bidswitch.net",
    "sharethrough.com",
    "spotxchange.com",
    "smartadserver.com",
    "quantserve.com",
    # Analytics platforms
    "hotjar.com",
    "fullstory.com",
    "mixpanel.com",
    "segment.com",
    "segment.io",
    "amplitude.com",
    "heap.io",
    "newrelic.com",
    "nr-data.net",
    # Social tracking pixels
    "twitter.com",
    "t.co",
    "linkedin.com",
    "licdn.com",
    "pinterest.com",
    "pinimg.com",
    "tiktok.com",
    "snap.com",
    "snapchat.com",
    "sc-static.net",
    "reddit.com",
    # Data brokers / DMPs
    "bluekai.com",  # Oracle
    "demdex.net",  # Adobe
    "krxd.net",  # Salesforce
    "rlcdn.com",  # LiveRamp
    "casalemedia.com",
    "exelator.com",  # Nielsen
    "eyeota.net",
    "lotame.com",
    "addthis.com",
    "sharethis.com",
    # Retargeting / attribution
    "adsymptotic.com",
    "branch.io",
    "appsflyer.com",
    "adjust.com",
    "kochava.com",
    # Other common trackers
    "scorecardresearch.com",
    "chartbeat.com",
    "comscore.com",
    "moatads.com",
    "doubleverify.com",
    "yieldmo.com",
}


def is_tracker_domain(host: str) -> tuple[bool, str]:
    """Check if a cookie host belongs to a known tracking domain.

    Cookie hosts may have a leading dot (e.g., ".doubleclick.net").
    Returns (is_tracker, matched_domain).
    """
    # Strip leading dot (cookie domain convention)
    clean = host.lstrip(".")

    # Exact match
    if clean in TRACKER_COOKIE_DOMAINS:
        return True, clean

    # Subdomain match (e.g., "ads.doubleclick.net" matches "doubleclick.net")
    for domain in TRACKER_COOKIE_DOMAINS:
        if clean.endswith("." + domain):
            return True, domain

    return False, ""
