# DNS Tracking — Your Browsing History in Plain Text

## What is DNS?

Every time you visit a website, your device sends a DNS (Domain Name System) query to translate the domain name (e.g., `example.com`) into an IP address. Think of it as a phone book lookup — and whoever runs the phone book can see every number you look up.

## How DNS is used to track you

### ISP monitoring
Your Internet Service Provider sees every DNS query by default. In many countries, ISPs are legally required to log this data and may be compelled to share it with law enforcement. Some ISPs also sell aggregated browsing data to advertisers.

### Google DNS (8.8.8.8)
Google's public DNS is the most widely used resolver in the world. Every query sent to 8.8.8.8 gives Google another data point about your browsing habits — even if you don't use Google Search or Chrome.

### Corporate surveillance
Companies like Palantir and data brokers can purchase or subpoena DNS logs to build browsing profiles tied to specific households or individuals.

## Why a VPN doesn't fully help

A VPN hides your DNS queries from your ISP — but only if the VPN also handles DNS resolution. Many VPN configurations suffer from **DNS leaks**, where queries still go to your ISP's resolver despite the VPN tunnel. Even with a properly configured VPN, the VPN provider itself can see all your DNS queries.

## What to do about it

1. **Use a privacy-respecting DNS resolver**: Quad9 (9.9.9.9), Cloudflare (1.1.1.1), or Mullvad DNS (194.242.2.2)
2. **Enable DNS-over-HTTPS (DoH)**: Encrypts your DNS queries so network observers can't read them
3. **Enable DNS-over-TLS (DoT)**: Alternative encrypted DNS protocol
4. **Use dnscrypt-proxy**: System-wide encrypted DNS with server validation
5. **Check for DNS leaks**: Use tools like dnsleaktest.com to verify your configuration

## Severity

**High** — DNS queries reveal your complete browsing history. They are trivially observable by ISPs, Wi-Fi operators, and anyone with network access.
