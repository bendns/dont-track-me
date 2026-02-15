# DNS Monitoring — Catching Trackers in Real Time

## What is DNS monitoring?

DNS monitoring captures the Domain Name System queries your computer makes in real time. Every time any application on your system contacts a server — whether it's a website you're visiting or a tracking SDK phoning home — it first resolves the domain name through DNS. By watching these queries, you can see exactly which domains your system is communicating with.

## How tracker detection works

### Known tracker domains
The dont-track-me database contains hundreds of known tracker domains organized by category: advertising (doubleclick.net, adnxs.com), analytics (google-analytics.com, mixpanel.com), social tracking (facebook.com pixel endpoints, twitter analytics), and data brokers (bluekai.com, exelate.com).

### Real-time matching
As DNS queries are captured from the network interface, each domain is checked against the tracker database. Matches are flagged with their category and the process that initiated the query (when available).

### Process attribution
On macOS, DNS monitoring can identify which application made each query. This reveals which of your installed apps are contacting tracker domains — even when running in the background.

## What DNS monitoring reveals

Running DNS monitoring for even a few minutes typically shows:

- **Background tracking** — Apps you're not actively using still contact tracker domains via background refresh
- **System-level telemetry** — macOS itself makes queries to Apple analytics and diagnostics servers
- **Hidden third-party connections** — Apps contact domains you'd never expect, revealing embedded SDKs and data partnerships
- **Advertising infrastructure** — Real-time bidding and programmatic advertising generate dozens of tracker queries per page load

## Limitations

DNS monitoring requires root/sudo access to capture raw network packets. It only sees DNS queries — if an application uses DNS-over-HTTPS (DoH) or hardcoded IP addresses, those connections won't appear. It also can't see the content of communications, only which domains are being contacted.

## What you can do

1. **Monitor regularly** — Run `sudo dtm monitor` to capture DNS queries and identify tracker traffic
2. **Review results** — Run `dtm audit dns_monitor` to analyze captured data for tracker patterns
3. **Block at DNS level** — Use NextDNS, Pi-hole, or AdGuard Home to block tracker domains before they resolve
4. **Block per-app** — Use Little Snitch or LuLu to prevent specific apps from contacting trackers
5. **Check the ratio** — If more than 10-30% of your DNS queries go to trackers, your system has significant tracking exposure

## Severity

**High** — DNS monitoring provides ground truth about tracker communication. Unlike auditing settings or permissions, it shows what is actually happening on your network right now.
