# dont-track-me

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
```

Platforms: `instagram`, `youtube`, `tiktok`, `facebook`, `twitter`.

This module generates **recommendation lists** — it does not auto-follow accounts (which would require API tokens and risk account bans). You follow the suggested accounts manually.

### Info — Learn about threats

```bash
dtm info dns             # How DNS tracking works
dtm info metadata        # How file metadata leaks your identity
dtm info headers         # How HTTP headers fingerprint you
dtm info search_noise    # How search engines profile your beliefs
dtm info social_noise    # How social media follows define you
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
│   ├── base.py           # BaseModule ABC, AuditResult, Finding, ThreatLevel
│   ├── registry.py       # Auto-discovery of modules
│   ├── scoring.py        # Weighted score aggregation
│   └── config.py         # TOML configuration loading
└── modules/
    ├── dns/              # DNS leak detection & secure DNS configuration
    ├── metadata/         # File metadata scanning & stripping
    ├── headers/          # HTTP header analysis & recommendations
    ├── search_noise/     # Search query noise generation
    └── social_noise/     # Social media follow list diversification
```

## Running tests

```bash
pip install -e ".[dev]"
pytest -v
```

## Roadmap

Future modules planned:

- **cookies** — Third-party cookie analysis and cleanup
- **fingerprint** — Browser fingerprint detection and randomization (Playwright-based)
- **social** — Social media tracker/pixel blocking
- **webrtc** — WebRTC IP leak detection
- **email** — Email tracking pixel detection
- **behavior** — Behavioral fingerprinting detection (typing/mouse patterns)

## Contributing

Each module follows the same pattern:

1. Create `src/dont_track_me/modules/<name>/`
2. Add `module.py` with a class that subclasses `BaseModule`
3. Implement `audit()`, `protect()`, and `get_educational_content()`
4. Add `info.md` with educational content
5. Add tests in `tests/test_modules/test_<name>.py`

The module will be auto-discovered — no registration code needed.

## License

MIT
