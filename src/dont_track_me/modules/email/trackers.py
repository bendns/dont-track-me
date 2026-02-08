"""Known email tracking pixel domains and URL pattern detection."""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Known email tracking / marketing automation domains.
# These services embed 1x1 pixel images in emails to track opens.
TRACKER_DOMAINS: set[str] = {
    # Marketing automation platforms
    "list-manage.com",  # Mailchimp
    "mailchimp.com",
    "hubspot.com",
    "track.hubspot.com",
    "track.customer.io",
    "sendgrid.net",
    "mailgun.com",
    "klaviyo.com",
    "braze.com",
    "iterable.com",
    "pardot.com",  # Salesforce
    "mktotracking.com",  # Marketo
    "marketo.com",
    "exacttarget.com",  # Salesforce Marketing Cloud
    "sfmc-content.com",
    "createsend.com",  # Campaign Monitor
    "cmail19.com",
    "cmail20.com",
    "constantcontact.com",
    "emltrk.com",
    "drip.com",
    "convertkit.com",
    "activecampaign.com",
    "aweber.com",
    "getresponse.com",
    "sendinblue.com",
    "brevo.com",  # Sendinblue rebranded
    "intercom.io",
    "intercom-mail.com",
    # Analytics / ad platforms
    "google-analytics.com",
    "bat.bing.com",
    "pixel.quantserve.com",
    "doubleclick.net",
    # Email tracking services (individual tracking)
    "mailtrack.io",
    "yesware.com",
    "streak.com",
    "bananatag.com",
    "getnotify.com",
    "readnotify.com",
    "superhuman.com",
    "cirrusinsight.com",
    "boomeranggmail.com",
    "mixmax.com",
    "saleshandy.com",
    "snov.io",
    "woodpecker.co",
    "lemlist.com",
    "outreach.io",
    "salesloft.com",
    "apollo.io",
    # Other known pixel hosts
    "links.mkt.com",
    "t.signauxfaibles.com",
    "email.hteumeuleu.com",
}

# URL path patterns that suggest tracking pixel behavior
_TRACKING_PATH_PATTERNS = re.compile(
    r"/("
    r"track"
    r"|pixel"
    r"|beacon"
    r"|open"
    r"|wf/open"
    r"|t\.gif"
    r"|o\.gif"
    r"|e\.gif"
    r"|trk"
    r"|ci/e"
    r"|imp"
    r")(?:[/?#.]|$)",
    re.IGNORECASE,
)


def is_tracker_url(url: str) -> tuple[bool, str]:
    """Check if a URL is a known email tracking pixel.

    Returns (is_tracker, reason) where reason describes why it matched.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, ""

    hostname = parsed.hostname or ""

    # Check against known tracker domains (exact match and suffix match)
    for domain in TRACKER_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return True, f"known tracker domain: {domain}"

    # Check URL path for tracking patterns
    path = parsed.path
    if _TRACKING_PATH_PATTERNS.search(path):
        return True, f"suspicious URL path: {path}"

    return False, ""
