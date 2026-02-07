# HTTP Header Tracking — Your Browser's Business Card

## What are HTTP headers?

Every time your browser requests a web page, it sends a set of HTTP headers — metadata about itself. These headers include your browser name and version, your operating system, your preferred language, which page you came from, and more. Together, they act as a **business card** your browser hands to every website.

## How headers are used to track you

### User-Agent fingerprinting
Your User-Agent string (e.g., `Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 Chrome/120.0.0.0`) reveals your exact browser version, OS, and device. Combined with other signals, this creates a nearly unique fingerprint. The EFF's Panopticlick research found that User-Agent alone identifies ~10 bits of entropy.

### Accept-Language profiling
Your Accept-Language header reveals your language preferences and locale (e.g., `fr-FR,fr;q=0.9,en-US;q=0.8`). For a French speaker in the US, this is highly identifying. Intelligence agencies use language headers to correlate anonymous traffic with known individuals.

### Referer tracking
The Referer header tells each website which page sent you there. Ad networks use this to trace your complete browsing path across the web — even without cookies. For example, if you click a link on Reddit that goes to a news site, the news site (and its ad networks) know you came from Reddit.

### Do Not Track (DNT) — the ironic tracker
The DNT header was designed for privacy, but since only a minority of users enable it, having DNT: 1 actually makes you **more identifiable**. Most websites ignore it entirely.

## Why a VPN doesn't help

A VPN changes your IP address, but your browser still sends the same headers. Your User-Agent, language preferences, and referrer information are transmitted inside the encrypted tunnel — the VPN has no effect on them. You arrive at the website with a different IP but the same business card.

## What to do about it

1. **Firefox's resistFingerprinting**: Set `privacy.resistFingerprinting = true` in `about:config`. This standardizes your User-Agent, language, and timezone to match other Firefox users.
2. **Tor Browser**: All Tor Browser users share identical headers, making you indistinguishable.
3. **Referrer Policy**: Configure your browser to send minimal or no referrer information.
4. **uBlock Origin**: Blocks many tracking requests before headers are even sent.
5. **Avoid unique header combinations**: Each extension or setting that modifies headers can make your fingerprint more unique, not less.

## Severity

**High** — HTTP headers are sent with every single request. They require no JavaScript, no cookies, and no user interaction to collect. They are the most passive and universal tracking mechanism on the web.
