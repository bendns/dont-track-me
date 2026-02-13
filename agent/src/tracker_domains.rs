/// Known tracker domains for DNS query matching.
///
/// Consolidated from the Python project's cookies/trackers.py, social/trackers.py,
/// and email/trackers.py modules.

/// Each entry is (domain, category).
pub const TRACKER_DOMAINS: &[(&str, &str)] = &[
    // --- Ad exchanges and DSPs ---
    ("doubleclick.net", "advertising"),
    ("googlesyndication.com", "advertising"),
    ("googleadservices.com", "advertising"),
    ("amazon-adsystem.com", "advertising"),
    ("adsrvr.org", "advertising"),
    ("criteo.com", "advertising"),
    ("criteo.net", "advertising"),
    ("outbrain.com", "advertising"),
    ("taboola.com", "advertising"),
    ("rubiconproject.com", "advertising"),
    ("pubmatic.com", "advertising"),
    ("openx.net", "advertising"),
    ("indexexchange.com", "advertising"),
    ("adnxs.com", "advertising"),
    ("bidswitch.net", "advertising"),
    ("sharethrough.com", "advertising"),
    ("spotxchange.com", "advertising"),
    ("smartadserver.com", "advertising"),
    ("moatads.com", "advertising"),
    ("doubleverify.com", "advertising"),
    ("yieldmo.com", "advertising"),
    ("ads-twitter.com", "advertising"),
    // --- Analytics ---
    ("google-analytics.com", "analytics"),
    ("analytics.google.com", "analytics"),
    ("googletagmanager.com", "analytics"),
    ("googletagservices.com", "analytics"),
    ("hotjar.com", "analytics"),
    ("fullstory.com", "analytics"),
    ("mixpanel.com", "analytics"),
    ("segment.com", "analytics"),
    ("segment.io", "analytics"),
    ("amplitude.com", "analytics"),
    ("heap.io", "analytics"),
    ("newrelic.com", "analytics"),
    ("nr-data.net", "analytics"),
    ("chartbeat.com", "analytics"),
    ("scorecardresearch.com", "analytics"),
    ("comscore.com", "analytics"),
    ("quantserve.com", "analytics"),
    ("clarity.ms", "analytics"),
    // --- Social tracking ---
    ("facebook.com", "social"),
    ("facebook.net", "social"),
    ("fbcdn.net", "social"),
    ("instagram.com", "social"),
    ("fbsbx.com", "social"),
    ("connect.facebook.net", "social"),
    ("twitter.com", "social"),
    ("t.co", "social"),
    ("analytics.twitter.com", "social"),
    ("platform.twitter.com", "social"),
    ("tiktok.com", "social"),
    ("tiktokcdn.com", "social"),
    ("analytics.tiktok.com", "social"),
    ("linkedin.com", "social"),
    ("licdn.com", "social"),
    ("snap.licdn.com", "social"),
    ("pinterest.com", "social"),
    ("pinimg.com", "social"),
    ("ct.pinterest.com", "social"),
    ("snap.com", "social"),
    ("snapchat.com", "social"),
    ("sc-static.net", "social"),
    ("tr.snapchat.com", "social"),
    ("reddit.com", "social"),
    ("redditmedia.com", "social"),
    ("redditstatic.com", "social"),
    // --- Data brokers / DMPs ---
    ("bluekai.com", "data_broker"),
    ("demdex.net", "data_broker"),
    ("krxd.net", "data_broker"),
    ("rlcdn.com", "data_broker"),
    ("casalemedia.com", "data_broker"),
    ("exelator.com", "data_broker"),
    ("eyeota.net", "data_broker"),
    ("lotame.com", "data_broker"),
    ("addthis.com", "data_broker"),
    ("sharethis.com", "data_broker"),
    // --- Attribution / retargeting ---
    ("branch.io", "attribution"),
    ("appsflyer.com", "attribution"),
    ("adjust.com", "attribution"),
    ("kochava.com", "attribution"),
    ("adsymptotic.com", "attribution"),
    // --- Email tracking ---
    ("list-manage.com", "email_tracking"),
    ("mailchimp.com", "email_tracking"),
    ("hubspot.com", "email_tracking"),
    ("track.hubspot.com", "email_tracking"),
    ("track.customer.io", "email_tracking"),
    ("sendgrid.net", "email_tracking"),
    ("mailgun.com", "email_tracking"),
    ("klaviyo.com", "email_tracking"),
    ("braze.com", "email_tracking"),
    ("iterable.com", "email_tracking"),
    ("pardot.com", "email_tracking"),
    ("mktotracking.com", "email_tracking"),
    ("marketo.com", "email_tracking"),
    ("exacttarget.com", "email_tracking"),
    ("sfmc-content.com", "email_tracking"),
    ("createsend.com", "email_tracking"),
    ("constantcontact.com", "email_tracking"),
    ("mailtrack.io", "email_tracking"),
    ("superhuman.com", "email_tracking"),
    // --- Microsoft ---
    ("bat.bing.com", "analytics"),
    ("bing.com", "analytics"),
    // --- Google (other) ---
    ("googlevideo.com", "analytics"),
    ("gstatic.com", "analytics"),
];

/// Known tracking SDK frameworks detectable in Mach-O binaries.
/// Each entry is (dylib_substring, sdk_name, category).
pub const TRACKING_SDKS: &[(&str, &str, &str)] = &[
    // Facebook / Meta
    ("FBSDKCoreKit", "Facebook SDK", "social"),
    ("FBSDKLoginKit", "Facebook Login SDK", "social"),
    ("FBSDKShareKit", "Facebook Share SDK", "social"),
    // Google
    ("GoogleAnalytics", "Google Analytics", "analytics"),
    ("FirebaseAnalytics", "Firebase Analytics", "analytics"),
    ("FirebaseCore", "Firebase Core", "analytics"),
    ("GoogleMobileAds", "Google Mobile Ads", "advertising"),
    ("GoogleTagManager", "Google Tag Manager", "analytics"),
    // Attribution / marketing
    ("Adjust", "Adjust", "attribution"),
    ("AppsFlyerLib", "AppsFlyer", "attribution"),
    ("Amplitude", "Amplitude", "analytics"),
    ("Mixpanel", "Mixpanel", "analytics"),
    ("Segment", "Segment", "analytics"),
    ("Branch", "Branch.io", "attribution"),
    ("Kochava", "Kochava", "attribution"),
    // Push / engagement
    ("Braze", "Braze", "engagement"),
    ("Appboy", "Braze (Appboy)", "engagement"),
    ("OneSignal", "OneSignal", "engagement"),
    // Error tracking (includes device fingerprinting)
    ("Sentry", "Sentry", "error_tracking"),
    ("Crashlytics", "Crashlytics", "error_tracking"),
    ("NewRelic", "New Relic", "monitoring"),
    ("Flurry", "Flurry", "analytics"),
    // Ad mediation
    ("UnityAds", "Unity Ads", "advertising"),
    ("IronSource", "ironSource", "advertising"),
    ("AppLovinSDK", "AppLovin", "advertising"),
    ("MoPub", "MoPub", "advertising"),
    ("Chartboost", "Chartboost", "advertising"),
];

/// Check if a domain matches any known tracker domain (exact or suffix match).
/// Returns the category if matched.
pub fn match_tracker_domain(domain: &str) -> Option<&'static str> {
    let domain = domain.trim_start_matches('.').to_ascii_lowercase();

    for &(tracker, category) in TRACKER_DOMAINS {
        if domain == tracker {
            return Some(category);
        }
        // Suffix match: "ads.doubleclick.net" matches "doubleclick.net"
        if domain.len() > tracker.len() {
            let offset = domain.len() - tracker.len();
            if domain.as_bytes()[offset - 1] == b'.'
                && domain[offset..].eq_ignore_ascii_case(tracker)
            {
                return Some(category);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert_eq!(match_tracker_domain("doubleclick.net"), Some("advertising"));
        assert_eq!(
            match_tracker_domain("google-analytics.com"),
            Some("analytics")
        );
        assert_eq!(match_tracker_domain("facebook.com"), Some("social"));
    }

    #[test]
    fn test_subdomain_match() {
        assert_eq!(
            match_tracker_domain("ads.doubleclick.net"),
            Some("advertising")
        );
        assert_eq!(match_tracker_domain("pixel.facebook.com"), Some("social"));
        assert_eq!(
            match_tracker_domain("www.google-analytics.com"),
            Some("analytics")
        );
    }

    #[test]
    fn test_leading_dot() {
        assert_eq!(
            match_tracker_domain(".doubleclick.net"),
            Some("advertising")
        );
    }

    #[test]
    fn test_no_match() {
        assert_eq!(match_tracker_domain("example.com"), None);
        assert_eq!(match_tracker_domain("rust-lang.org"), None);
    }

    #[test]
    fn test_case_insensitive() {
        assert_eq!(match_tracker_domain("DoubleClick.Net"), Some("advertising"));
    }
}
