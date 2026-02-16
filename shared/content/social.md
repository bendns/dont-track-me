# Social Media Trackers — They Follow You Everywhere

## What are social media trackers?

Social media trackers are invisible scripts and images embedded on websites across the internet. When you visit a news site, online shop, or health portal, these trackers silently report your visit back to social media platforms — even if you never clicked "Share" or "Like."

The most common forms:
- **Tracking pixels** — 1x1 transparent images that load from a social platform's server, sending your IP, browser fingerprint, page URL, and any cookies back to the platform
- **SDK embeds** — "Login with Facebook" buttons, embedded tweets, and YouTube players that load full JavaScript from the platform
- **Conversion tags** — scripts placed by advertisers to tell platforms "this user bought something after seeing our ad"

## How the Meta Pixel works

The Meta Pixel (formerly Facebook Pixel) is the most pervasive social tracker. It is embedded on over 30% of the top 10,000 websites, including:
- Hospital and health insurance portals
- Banking and financial services
- Government and tax filing sites
- Dating and mental health apps

When you visit any of these sites:
1. Your browser loads `connect.facebook.net/en_US/fbevents.js`
2. The script reads your Facebook cookie (if you're logged in or ever were)
3. It sends the page URL, your cookie ID, and the page's custom event data to `facebook.com/tr/`
4. Meta links this visit to your profile — or creates a "shadow profile" if you don't have an account

Meta then uses this data to build an **Off-Facebook Activity** profile: every website you've visited that has the pixel installed.

## Google Analytics and Tag Manager

Google Analytics is installed on over 50% of all websites. While not a social network, Google uses this data to:
- Build advertising profiles across Search, YouTube, Gmail, and Maps
- Sell "audience segments" to advertisers (e.g., "visited health sites," "researching loans")
- Feed its machine learning models for ad targeting

Google Tag Manager (`googletagmanager.com`) acts as a container — a single script that loads dozens of other trackers, making it harder to block individual ones.

## Shadow profiles

Even if you don't have a Facebook, Google, or Twitter account, these platforms build **shadow profiles** about you:
- Your IP address and browser fingerprint are tracked across sites
- If a friend uploads their contacts (which includes your email or phone), Meta links the data
- Over time, the platform knows your browsing habits, interests, and approximate identity — without you ever creating an account

## Why a VPN doesn't help

A VPN changes your IP address, but social trackers identify you by **cookies and browser fingerprint**, not IP:
- If you're logged into Facebook in one tab, every site with a Meta Pixel in another tab knows it's you
- Even without cookies, your canvas fingerprint, installed fonts, and screen resolution create a unique ID
- The tracker request still goes to `facebook.com` — your VPN hides your IP from the site you're visiting, not from the tracker receiving the request

## Browser defenses

Modern browsers have built-in social tracker blocking:

**Firefox Enhanced Tracking Protection (ETP)**
- **Standard** (default): blocks known trackers in private windows and social media trackers
- **Strict**: blocks all cross-site cookies, all known trackers, fingerprinters, and cryptominers
- Social tracker blocking specifically targets Facebook, Twitter, and LinkedIn embeds

**Brave Shields**
- Blocks trackers and ads by default
- Aggressive mode blocks fingerprinting and bouncing trackers

**Chrome**
- Third-party cookie deprecation (in progress)
- No built-in tracker blocklist — relies on extensions

## The scale of the problem

- Meta Pixel: 8.4+ million websites
- Google Analytics: 30+ million websites
- Twitter pixel: 1+ million websites
- LinkedIn Insight Tag: 500,000+ websites
- TikTok Pixel: growing rapidly, now on major e-commerce platforms

Each of these platforms knows a significant portion of your browsing history — and they share data with advertisers, data brokers, and (via legal process) governments.

## What you can do

1. **Enable Firefox Enhanced Tracking Protection — Strict mode** (Settings > Privacy & Security)
2. **Install uBlock Origin** — the most effective open-source content blocker
3. **Block social tracker domains at the DNS level** — use NextDNS, AdGuard DNS, or a Pi-hole
4. **Add tracker domains to /etc/hosts** — blocks them before the browser even makes a request
5. **Regularly clear social media cookies** — `dtm protect social --apply` does this automatically
6. **Use container tabs** (Firefox Multi-Account Containers) to isolate social media from other browsing
7. **Disable "Login with Facebook/Google"** on third-party sites — use email/password instead
