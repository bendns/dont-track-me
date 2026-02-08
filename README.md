# dont-track-me

> **Disclaimer:** This entire codebase was generated using Claude (Anthropic). While we've tested it, use it with caution and review the code before relying on it for your privacy.
>
> **Scope:** This toolkit is an educational starting point, not a complete privacy solution. Real-world digital protection requires a layered approach — Tor/VPN, hardened browsers (Mullvad, LibreWolf), OS-level isolation (Tails, Qubes), hardware security keys, and operational discipline. The checks and countermeasures here cover common tracking vectors but do not address advanced threats like browser fingerprinting, traffic analysis, or state-level surveillance. Use this alongside — not instead of — established privacy tools.

A modular anti-tracking toolkit that audits how trackable you are online and applies countermeasures. Built for privacy researchers, activists, journalists, and anyone who believes their digital profile shouldn't be weaponized against them.

## Why this exists

Using a VPN is not enough.

A VPN hides your IP address. But modern surveillance uses browser fingerprinting, cookies, DNS queries, HTTP headers, file metadata, search history profiling, and social media analysis to build detailed profiles about you — your politics, religion, sexuality, health, and beliefs.

Companies like Palantir aggregate public data across platforms. Data brokers sell "audience segments" like "likely left-wing voter" or "interested in LGBTQ topics." Governments subpoena search histories. Advertisers know more about you than your closest friends.

**dont-track-me** fights back with two strategies:

1. **Defensive** — Detect and block tracking vectors (DNS leaks, metadata, headers)
2. **Offensive** — Poison the data they collect by injecting noise (balanced search queries, diversified social media follows)

## Installation

Requires Python 3.11+.

```bash
# Clone the repository
git clone https://github.com/your-username/dont-track-me.git
cd dont-track-me

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install with all optional dependencies
pip install -e ".[all]"

# Or install with development dependencies (includes test tools)
pip install -e ".[dev]"
```

### Minimal install

If you only need the core modules (dns, headers, search noise, social noise):

```bash
pip install -e .
```

The metadata module requires `Pillow` and `pypdf` — install them via `pip install -e ".[metadata]"` or `pip install -e ".[all]"`.

The fingerprint module's core works without dependencies. For enhanced JS-based fingerprint measurement, install Playwright:

```bash
pip install -e ".[fingerprint]"
playwright install chromium
```

### API modules (Reddit, YouTube)

The Reddit and YouTube modules connect to real APIs to audit your account and apply protections. They require OAuth credentials:

```bash
# Install with API module dependencies
pip install -e ".[social-api]"    # Both Reddit + YouTube
pip install -e ".[reddit]"        # Reddit only
pip install -e ".[youtube]"       # YouTube only
```

#### Setting up Reddit API credentials

1. Go to https://www.reddit.com/prefs/apps
2. Click "create another app..."
3. Select **"script"** type
4. Set redirect URI to `http://localhost:8914/callback`
5. Note the client ID (under the app name) and client secret

#### Setting up YouTube API credentials

1. Go to https://console.cloud.google.com/apis/credentials
2. Create a new project (or use an existing one)
3. Enable the **YouTube Data API v3**
4. Create an **OAuth 2.0 Client ID** (type: Desktop app)
5. Add `http://localhost:8914/callback` as an authorized redirect URI
6. Download or note the client ID and client secret

#### Storing credentials

Set credentials via environment variables:

```bash
export DTM_REDDIT_CLIENT_ID="your-client-id"
export DTM_REDDIT_CLIENT_SECRET="your-client-secret"
export DTM_YOUTUBE_CLIENT_ID="your-client-id"
export DTM_YOUTUBE_CLIENT_SECRET="your-client-secret"
```

Or add them to `~/.config/dont-track-me/config.toml`:

```toml
[reddit]
client_id = "your-client-id"
client_secret = "your-client-secret"

[youtube]
client_id = "your-client-id"
client_secret = "your-client-secret"
```

## Quick start

```bash
# See what modules are available
dtm status

# Run a full privacy audit
dtm audit

# Get your overall privacy score
dtm score

# Learn about a specific threat
dtm info dns
```

## Usage

### Auth — Connect your accounts

Authenticate with API-backed platforms to unlock real account auditing and protection:

```bash
dtm auth reddit              # Open browser → OAuth → store token in system keychain
dtm auth youtube             # Open browser → OAuth → store token in system keychain
dtm auth status              # Show which platforms are connected + token expiry
dtm auth revoke reddit       # Delete stored token
```

Tokens are stored securely in your system's credential store (macOS Keychain, Linux Secret Service, Windows Credential Locker) via `keyring`.

### Audit — How trackable are you?

```bash
dtm audit                        # Run all audits
dtm audit dns                    # Audit a single module
dtm audit --modules dns,headers  # Audit specific modules
dtm audit --format json          # Machine-readable output
```

### Protect — Apply countermeasures

```bash
dtm protect                              # Dry-run (preview changes)
dtm protect --apply                      # Apply all protections
dtm protect dns --apply                  # Apply DNS protections only
dtm protect metadata --apply --path ./   # Strip metadata from files
```

Protect is **dry-run by default** — it never modifies anything without `--apply`.

#### Reddit — Harden privacy settings + diversify subreddits

Reddit is the only major platform where privacy/tracking settings are writable via API. The Reddit module can disable all 7 tracking preferences in a single command:

```bash
dtm audit reddit                             # Audit privacy settings + subreddit bias
dtm protect reddit --apply                   # Harden settings + diversify subreddits
dtm protect reddit --apply --harden-only     # Only disable tracking preferences
dtm protect reddit --apply --diversify-only  # Only diversify subscriptions
```

Settings hardened: `activity_relevant_ads`, `third_party_data_personalized_ads`, `third_party_site_data_personalized_ads`, `third_party_site_data_personalized_content`, `allow_clicktracking`, `public_votes`, `show_presence`.

#### YouTube — Audit and diversify subscriptions

```bash
dtm audit youtube                  # Analyze subscription bias by category/perspective
dtm protect youtube --apply        # Subscribe to diverse channels
```

Rate limited to stay within YouTube's free 10K daily quota (~200 subscribes/day), with randomized delays between calls.

#### Instagram, TikTok, Facebook, Twitter/X — Privacy checklists

These platforms' APIs don't allow reading or modifying privacy settings programmatically. Instead, these modules use interactive checklists — answer questions about your current settings and get a personalized score with step-by-step hardening instructions.

Platforms can't be trusted to honor their own privacy toggles ([Facebook was fined $5B by the FTC](https://www.ftc.gov/news-events/news/press-releases/2019/07/ftc-imposes-5-billion-penalty-sweeping-new-privacy-restrictions-facebook) for deceiving users about privacy controls, [Google settled for $391.5M with 40 states](https://www.njoag.gov/forty-attorneys-general-announce-historic-settlement-with-google-over-location-tracking-practices/) over location tracking that continued after users disabled it). Where applicable, checks include **technical countermeasures** — platform-independent enforcement steps like DNS-level blocking, browser extension recommendations, cookie deletion via `dtm protect social/cookies`, and Firefox hardening via `dtm protect fingerprint`.

```bash
dtm audit instagram                  # Educational findings (default score)
dtm audit instagram -i               # Interactive checklist — personalized score
dtm audit tiktok -i                  # Same for TikTok (12 checks)
dtm audit facebook -i                # Same for Facebook (14 checks)
dtm audit twitter -i                 # Same for Twitter/X (13 checks)
dtm protect instagram                # Step-by-step hardening guide
dtm info instagram                   # How Instagram tracks you
```

### Noise — Poison your profile

This is the offensive strategy. Instead of blocking tracking, you make the collected data useless by injecting noise.

#### Search noise

Generate balanced search queries across multiple engines to drown out your real search history:

```bash
dtm noise search                                          # Preview (safe, no requests sent)
dtm noise search --apply                                  # Send 50 balanced queries
dtm noise search --apply --count 100                      # Send 100 queries
dtm noise search --apply --categories politics,religion   # Target specific categories
dtm noise search --apply --engines google,bing            # Use specific engines
dtm noise search --apply --country fr                     # French-localized queries
```

Query categories: `politics` (left/right/center/libertarian/green), `religion` (christianity/islam/judaism/buddhism/hinduism/atheism), `news_sources`, `interests`, `lifestyle`.

Queries are balanced across all perspectives — equal representation from every side — then shuffled and sent with randomized human-like delays.

#### Social noise

Generate diversified follow lists so your social media profile doesn't reveal a one-dimensional identity:

```bash
dtm noise social --apply                                   # All platforms
dtm noise social --apply --platforms instagram,youtube      # Specific platforms
dtm noise social --apply --categories politics,music        # Specific categories
dtm noise social --apply --format json                      # JSON export
dtm noise social --apply --country fr                      # French accounts
```

Platforms: `instagram`, `youtube`, `tiktok`, `facebook`, `twitter`.

This module generates **recommendation lists** — it does not auto-follow accounts (which would require API tokens and risk account bans). You follow the suggested accounts manually.

#### Country localization

Noise data is stored in per-country YAML files so queries and accounts match your local context. A French user gets queries about Macron and Le Monde, not American politics.

```bash
dtm noise search --country fr                              # Use French queries
dtm noise social --country fr                              # Use French accounts
```

Available countries: `us` (default), `fr`.

The default country is resolved in order:
1. `--country` / `-C` CLI flag
2. `DTM_COUNTRY` environment variable
3. `country` key in `~/.config/dont-track-me/config.toml`
4. Falls back to `us`

```toml
# ~/.config/dont-track-me/config.toml
country = "fr"
```

### Info — Learn about threats

```bash
dtm info dns             # How DNS tracking works
dtm info metadata        # How file metadata leaks your identity
dtm info headers         # How HTTP headers fingerprint you
dtm info search_noise    # How search engines profile your beliefs
dtm info social_noise    # How social media follows define you
dtm info reddit          # How Reddit tracks your preferences
dtm info youtube         # How YouTube profiles your subscriptions
dtm info instagram       # How Instagram tracks you
dtm info tiktok          # How TikTok profiles your behavior
dtm info facebook        # How Facebook builds your shadow profile
dtm info twitter         # How Twitter/X tracks and profiles you
dtm info webrtc          # How WebRTC leaks your real IP behind a VPN
dtm info email           # How email tracking pixels spy on you
dtm info cookies         # How third-party cookies track you across the web
dtm info fingerprint     # How browser fingerprinting identifies you without cookies
dtm info social          # How social media trackers follow you everywhere
```

### Score — Your privacy at a glance

```bash
dtm score
```

Returns a weighted score from 0 (fully exposed) to 100 (fully protected) with a per-module breakdown.

## Modules

### Defensive modules

| Module | What it does | Deep dive |
|---|---|---|
| **dns** | Detects DNS leaks, tracking DNS providers (Google, OpenDNS), and lack of encrypted DNS | [DNS Tracking — Your Browsing History in Plain Text](src/dont_track_me/modules/dns/info.md) |
| **metadata** | Scans images for GPS/EXIF data and PDFs for author metadata; strips them on protect | [Metadata Leakage — Hidden Data in Your Files](src/dont_track_me/modules/metadata/info.md) |
| **headers** | Analyzes HTTP headers (User-Agent, Accept-Language, Referer) for identity leaks | [HTTP Header Tracking — Your Browser's Business Card](src/dont_track_me/modules/headers/info.md) |
| **webrtc** | Detects WebRTC IP leaks via STUN server queries that bypass VPNs | [WebRTC IP Leaks — Your VPN's Blind Spot](src/dont_track_me/modules/webrtc/info.md) |
| **email** | Detects and strips email tracking pixels (1x1 images, known tracker domains) in .eml files | [Email Tracking Pixels — Someone Knows You Read This](src/dont_track_me/modules/email/info.md) |
| **cookies** | Analyzes browser cookie databases (Chrome/Firefox) for third-party tracking cookies; deletes tracker cookies on protect | [Browser Cookies & Third-Party Tracking](src/dont_track_me/modules/cookies/info.md) |
| **fingerprint** | Detects browser fingerprinting exposure (Canvas, WebGL, fonts, extensions); optional Playwright-based JS measurement; hardens Firefox via user.js | [Browser Fingerprinting](src/dont_track_me/modules/fingerprint/info.md) |
| **social** | Detects social media tracker cookies, checks browser tracking protection (ETP/Shields), anti-tracker extensions, hosts-file blocking, and DNS-level blocking | [Social Media Trackers](src/dont_track_me/modules/social/info.md) |

### API modules (authenticated)

| Module | What it does | Deep dive |
|---|---|---|
| **reddit** | Audits 7 privacy/tracking settings + subreddit bias; hardens settings and diversifies subscriptions via API | [Reddit Tracking — Your Preferences Betray You](src/dont_track_me/modules/reddit/info.md) |
| **youtube** | Audits subscription bias by category/perspective; subscribes to diverse channels via API | [YouTube Profiling — Your Subscriptions Define You](src/dont_track_me/modules/youtube/info.md) |

### Checklist modules (interactive)

| Module | What it does | Deep dive |
|---|---|---|
| **instagram** | Interactive privacy checklist (12 checks) covering account visibility, ad tracking, and Off-Instagram Activity | [Instagram Tracking — Your Photos Tell More Than You Think](src/dont_track_me/modules/instagram/info.md) |
| **tiktok** | Interactive privacy checklist (12 checks) covering algorithm profiling, device fingerprinting, and ad data sharing | [TikTok Tracking — The Algorithm Knows You Better Than You Know Yourself](src/dont_track_me/modules/tiktok/info.md) |
| **facebook** | Interactive privacy checklist (14 checks) covering Off-Facebook Activity, face recognition, and shadow profiles | [Facebook Tracking — The Most Complete Surveillance Machine Ever Built](src/dont_track_me/modules/facebook/info.md) |
| **twitter** | Interactive privacy checklist (13 checks) covering protected tweets, ad personalization, and off-Twitter activity tracking | [Twitter/X Tracking — Your Tweets Tell More Than You Type](src/dont_track_me/modules/twitter/info.md) |

### Offensive modules (noise generation)

| Module | What it does | Deep dive |
|---|---|---|
| **search_noise** | Sends balanced search queries across Google/Bing/DuckDuckGo/Yahoo to pollute your search profile | [Search Engine Profiling — They Know What You Think](src/dont_track_me/modules/search_noise/info.md) |
| **social_noise** | Generates diversified follow lists for Instagram/YouTube/TikTok/Facebook/Twitter | [Social Media Profiling — Your Follows Define You](src/dont_track_me/modules/social_noise/info.md) |

## How it works

Every tracking vector is a **module** that implements three operations:

- **audit** — Non-destructive scan. Returns a score (0 = exposed, 100 = protected) and specific findings with remediation steps.
- **protect** — Apply countermeasures. Dry-run by default. For noise modules, this generates and executes noise.
- **educate** — Explain the threat: how it works technically, who exploits it, and why a VPN doesn't help.

Modules are auto-discovered at startup. Adding a new tracking vector is as simple as creating a new directory under `src/dont_track_me/modules/` with a `module.py` that subclasses `BaseModule`.

## Architecture

```
src/dont_track_me/
├── cli/main.py           # CLI entry point (dtm command)
├── core/
│   ├── auth.py           # OAuthModule, TokenStore, OAuthFlow
│   ├── base.py           # BaseModule ABC, AuditResult, Finding, ThreatLevel
│   ├── checklist.py      # PrivacyCheck model & interactive checklist scoring
│   ├── registry.py       # Auto-discovery of modules
│   ├── scoring.py        # Weighted score aggregation
│   └── config.py         # TOML configuration loading
└── modules/
    ├── dns/              # DNS leak detection & secure DNS configuration
    ├── metadata/         # File metadata scanning & stripping
    ├── headers/          # HTTP header analysis & recommendations
    ├── search_noise/     # Search query noise generation
    │   └── data/         #   Per-country query YAML files (us.yaml, fr.yaml)
    ├── social_noise/     # Social media follow list diversification
    │   └── data/         #   Per-country account YAML files (us.yaml, fr.yaml)
    ├── reddit/           # Reddit privacy audit & protection (API)
    ├── youtube/          # YouTube subscription audit & diversification (API)
    ├── webrtc/           # WebRTC IP leak detection via STUN queries
    ├── email/            # Email tracking pixel detection & stripping
    ├── cookies/          # Browser cookie analysis & tracker cookie removal
    ├── fingerprint/      # Browser fingerprint detection & hardening
    ├── social/           # Social media tracker detection & blocking
    ├── instagram/        # Instagram privacy checklist (interactive)
    ├── tiktok/           # TikTok privacy checklist (interactive)
    ├── facebook/         # Facebook privacy checklist (interactive)
    └── twitter/          # Twitter/X privacy checklist (interactive)
```

## Running tests

```bash
pip install -e ".[dev]"
pytest -v
```

## Roadmap

Future modules, ordered by priority:

### Defensive

1. **secrets** — Local secrets exposure audit (leaked credentials in `.env`, `.git/config`, shell history, plaintext API keys, browser saved passwords)
2. **ssh** — SSH key hygiene (key age, algorithm strength, `authorized_keys` audit, agent forwarding, `known_hosts` fingerprinting vector)
3. **certificates** — TLS/SSL certificate audit (system trust store, browser cert stores, expired/weak/untrusted CAs, self-signed certs)
4. **app_permissions** — macOS app permission audit (TCC database: camera, microphone, location, contacts, screen recording — flag over-permissioned apps)
5. **location** — Location data leakage audit (Wi-Fi SSID history, location services permissions, timezone vs VPN mismatch detection)
6. **network** — Local network exposure (mDNS/Bonjour hostname broadcasting, open ports, UPnP, ARP visibility on shared networks)
7. **bluetooth** — Bluetooth trackability (discoverability state, paired device history, BLE beacon exposure used by retail/airports)
8. **clipboard** — Clipboard privacy (clipboard manager plaintext storage, clipboard access permissions, clipboard-sniffing app detection)
9. **prism_exposure** — PRISM surveillance exposure audit (detect email accounts, cloud sync clients, messaging apps, browsers, and password managers linked to PRISM-participating companies — recommend privacy-focused alternatives from [PRISM Break](https://prism-break.org/))
10. **behavior** — Behavioral fingerprinting detection (typing/mouse patterns — research-grade, high effort)

### Offensive

11. **browse_noise** — Browsing history noise injection (open decoy URLs across diverse categories to dilute browsing profiles)
12. **email_noise** — Newsletter subscription noise (subscribe to diverse mailing lists to poison email interest profiles)

### Platform-specific

13. **linkedin** — LinkedIn privacy checklist (visibility settings, activity broadcasts, ad targeting, third-party data sharing)

### Cross-cutting

14. **summary** — Cross-module correlation insights (connect dots across modules: "DNS leaks + unique fingerprint = identifiable even with VPN")
15. **export** — Data portability and trending (structured JSON/CSV export, score diffing over time, periodic re-audit)

### Enhancements to existing modules

- **cookies** — Add localStorage/sessionStorage audit (Firefox `webappsstore.sqlite`, Chrome `Local Storage/leveldb/`) and evercookie detection (cross-reference tracker IDs across cookies, localStorage, IndexedDB)
- **fingerprint** — Add advertising ID check (macOS `defaults read` for ad tracking limit, IDFA exposure)
- **ssh** — Add post-quantum readiness check (flag RSA/ECDSA keys vulnerable to quantum computing, recommend Ed25519 or PQ algorithms)
- **certificates** — Add post-quantum cipher suite audit (flag TLS configs using quantum-vulnerable crypto, check GPG key types)
- **dns** — Flag PRISM-adjacent DNS resolvers (Google DNS 8.8.8.8, OpenDNS 208.67.222.222) and recommend privacy-focused alternatives (dnscrypt-proxy, Mullvad DNS)
- **email** — Flag messages routed through PRISM-participating servers (Gmail, Outlook, Yahoo) based on Received headers
- **metadata** — Flag GPS/location EXIF data as high-risk for aggregation (photo location + timestamp = movement pattern for Palantir-style systems)
- **location** *(planned)* — Add ALPR awareness: educational content about license plate reader networks and physical movement surveillance

### Research references

Sources informing the roadmap — academic papers, government reports, and institutional research:

**Secrets & credentials**
- [GitGuardian — State of Secrets Sprawl 2024](https://www.gitguardian.com/state-of-secrets-sprawl-report-2024) — 12.8M secrets leaked on GitHub in 2023 (+28% YoY); 39M in 2024
- [GitHub Blog — 39M secret leaks in 2024](https://github.blog/security/application-security/next-evolution-github-advanced-security/)

**SSH & cryptography**
- [NIST IR 7966 — Security of Interactive and Automated Access Management Using SSH](https://nvlpubs.nist.gov/nistpubs/ir/2015/nist.ir.7966.pdf)
- [NIST SP 800-57 — Recommendation for Key Management](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf)

**Post-quantum**
- [NIST — First 3 Finalized Post-Quantum Encryption Standards (2024)](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards) — FIPS 203/204/205
- [NIST IR 8547 — Transition to Post-Quantum Cryptography Standards](https://csrc.nist.gov/pubs/ir/8547/ipd)

**Machine identity security**
- [CyberArk — State of Machine Identity Security 2025](https://www.cyberark.com/) — 50% of orgs reported machine identity breaches; 72% had certificate-related outages

**Browser tracking & fingerprinting**
- [Acar et al. — The Web Never Forgets: Persistent Tracking Mechanisms in the Wild (ACM CCS 2014)](https://dl.acm.org/doi/10.1145/2660267.2660347) — first large-scale study of canvas fingerprinting, evercookies, cookie syncing
- [W3C — Mitigating Browser Fingerprinting in Web Specifications](https://w3c.github.io/fingerprinting-guidance/)
- [Kohli et al. — Guarding Digital Privacy: Exploring User Profiling and Security Enhancements (arXiv:2504.07107)](https://arxiv.org/abs/2504.07107) — survey of user profiling techniques, data broker pipelines, PII leakage in mobile apps

**Wi-Fi & location tracking**
- [Matte et al. — Wi-Fi Probe Requests and Location Privacy](https://www.researchgate.net/publication/334890866) — SSIDs in probe requests leak names, locations, travel history
- [Nature Scientific Reports — Compromising Location Privacy Through Wi-Fi RSSI Tracking (2025)](https://www.nature.com/articles/s41598-025-22799-1)

**Clipboard privacy**
- [Mysk — KlipboardSpy: iOS Clipboard Access PoC](https://www.mysk.blog/) — demonstrated 54 iOS apps (including TikTok) reading clipboard without consent
- [Sophos — iOS 14 Flags TikTok and 53 Other Apps Spying on Clipboards](https://news.sophos.com/en-us/2020/06/30/ios-14-flags-tiktok-53-other-apps-spying-on-iphone-clipboards/)

**macOS permissions (TCC)**
- [SentinelOne — Bypassing macOS TCC User Privacy Protections](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [MITRE ATT&CK T1548.006 — TCC Manipulation](https://attack.mitre.org/techniques/T1548/006/)

**Network exposure (mDNS)**
- [Fingerprint.com — Brute-Forcing a macOS User's Real Name via mDNS](https://fingerprint.com/blog/apple-macos-mdns-brute-force/)

**BLE tracking**
- [MDPI — Digital Advertising and Customer Movement Analysis Using BLE Beacon Technology in Retail](https://www.mdpi.com/0718-1876/20/2/55)

**Data brokers**
- [FTC — Data Brokers: A Call for Transparency and Accountability (2014)](https://www.ftc.gov/system/files/documents/reports/data-brokers-call-transparency-accountability-report-federal-trade-commission-may-2014/140527databrokerreport.pdf) — study of 9 major data brokers (Acxiom, Datalogix, Experian, etc.)
- [Duke University Tech Policy — Data Brokers and Sensitive Data on U.S. Individuals](https://techpolicy.sanford.duke.edu/report-data-brokers-and-sensitive-data-on-u-s-individuals/)

**PRISM & mass surveillance**
- [EFF — Upstream vs. PRISM](https://www.eff.org/pages/upstream-prism)
- [ACLU — NSA Dragnet Searches of Communications](https://www.aclu.org/news/national-security/guide-what-we-now-know-about-nsas-dragnet-searches-your)
- [Brookings Institution — Beyond Snowden: Privacy, Mass Surveillance, and the Struggle to Reform the NSA](https://www.brookings.edu/wp-content/uploads/2016/09/chapter-one_-beyond-snowden-9780815730644.pdf)
- [PRISM Break — Opt Out of Global Surveillance Programs](https://prism-break.org/)

**Palantir & aggregation platforms**
- [Parsons — The Seer and the Seen: Surveying Palantir's Surveillance Platform (Information Society, 2022)](https://www.tandfonline.com/doi/full/10.1080/01972243.2022.2100851) — computational analysis of 155 Palantir surveillance patents
- [The Intercept — How Palantir Helped the NSA Spy on the Whole World (2017)](https://theintercept.com/2017/02/22/how-peter-thiels-palantir-helped-the-nsa-spy-on-the-whole-world/)
- [Vice — Palantir's Top-Secret User Manual for Cops (2019)](https://www.vice.com/en/article/revealed-this-is-palantirs-top-secret-user-manual-for-cops/)

**ALPR / license plate surveillance**
- [EFF — Automated License Plate Readers (ALPR)](https://www.eff.org/cases/automated-license-plate-readers)
- [Brennan Center for Justice — ALPR: Legal Status and Policy Recommendations](https://www.brennancenter.org/our-work/research-reports/automatic-license-plate-readers-legal-status-and-policy-recommendations)
- [ACLU — Automatic License Plate Readers](https://www.aclu.org/issues/privacy-technology/location-tracking/automatic-license-plate-readers)

## Contributing

Each module follows the same pattern:

1. Create `src/dont_track_me/modules/<name>/`
2. Add `module.py` with a class that subclasses `BaseModule`
3. Implement `audit()`, `protect()`, and `get_educational_content()`
4. Add `info.md` with educational content
5. Add tests in `tests/test_modules/test_<name>.py`

The module will be auto-discovered — no registration code needed.

## License

All rights reserved. This code is provided for educational purposes only.
