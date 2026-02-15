# Advertising Data Ecosystem

Every time you open an app or visit a website, your device broadcasts an
advertising identifier — a persistent, unique ID that links your activity
across every app, website, and physical location you visit. This identifier
is the backbone of a multi-billion dollar surveillance infrastructure that
reaches far beyond targeted ads.

## What Is an Advertising ID?

Apple devices have the IDFA (Identifier for Advertisers). Android devices
have the GAID (Google Advertising ID). Both serve the same purpose: a
persistent, device-level identifier shared with every app that requests it.

Unlike cookies (which are browser-specific) or IP addresses (which change
with your network), the advertising ID follows you across all apps on your
device. A weather app, a dating app, a news app, and a game all see the
same identifier — allowing data brokers to merge their data into a single
profile.

Until iOS 14.5 (2021), IDFA was enabled by default. Android still enables
GAID by default. Even after Apple introduced App Tracking Transparency
(ATT), many users tap "Allow" without understanding the implications.

## The RTB Pipeline

When an app displays an ad, a real-time bidding (RTB) auction happens in
milliseconds:

1. **Your app** sends your advertising ID, GPS coordinates, device model,
   IP address, and the app name to a **Supply-Side Platform (SSP)**
2. The SSP broadcasts this data to an **ad exchange** (e.g., Google AdX,
   OpenX, PubMatic, Index Exchange)
3. The ad exchange sends a **bid request** containing your data to hundreds
   of **Demand-Side Platforms (DSPs)** and advertisers
4. Each DSP decides whether to bid on showing you an ad

In step 3, your precise location and device profile are broadcast to
hundreds of companies — whether or not they win the auction. This is called
the **bidstream**.

## Bidstream Harvesting

RTB exchanges expect participants to delete bid request data after the
auction. But enforcement is nonexistent. Companies infiltrate the bidstream
by posing as legitimate advertisers, then silently record every bid request
that passes through — billions of data points per day.

This harvested data contains:
- **Advertising ID** (persistent device identifier)
- **GPS coordinates** (3-4 meter precision)
- **Timestamp** (when and how long you were there)
- **App name** (what you were doing)
- **Device model, OS version, carrier**
- **IP address** (network fingerprint)

A single data point is harmless. But aggregated over days and weeks, these
points reveal your home address, workplace, daily routines, doctor visits,
political meetings, religious services, romantic partners, and more.

## The Le Monde Investigation

In 2024, journalists from Le Monde obtained a sample dataset from a data
broker containing **16 million French advertising IDs** with GPS-precise
geolocation. The dataset was a free commercial sample — the broker gave it
away to demonstrate data quality before a purchase.

The journalists cross-referenced GPS pings at sensitive locations:
- **DGSE** (French foreign intelligence): hundreds of phones pinging inside
  headquarters, traceable to home addresses, daily routines, and family
  members of intelligence officers
- **DGSI** (domestic intelligence): an officer traced from DGSI to Gare de
  Lyon to his home — name on the mailbox confirmed the match
- **GIGN** (elite gendarmerie): phones pinging in secret training villages
  south of Paris, linked to home addresses of operators
- **Elysee Palace**: a phone pinging at the presidential residence, the
  Pavillon de la Lanterne (presidential weekend house), the presidential
  airfield, and a Republican Guard barracks — clearly a presidential
  protection officer

The GPS precision (3-4 meters) was sufficient to identify which room in a
house someone was using their phone in.

## Advertising Intelligence

At least 15 companies now package advertising data for government clients:

- **Fog Data Science** ($5-9K/month): provides law enforcement with a
  search interface over harvested location data. Allows tracking any
  advertising ID forward and backward in time
- **Babel Street / Locate X**: used by US Customs and Border Protection,
  ICE, and the Secret Service. 404 Media revealed its use to track women
  visiting abortion clinics in states where abortion was criminalized
- **Anomaly Six**: founded by ex-intelligence officers, embeds its own SDK
  in hundreds of apps to collect location data directly

These companies operate in a legal gray zone — purchasing commercially
available data rather than using traditional surveillance tools, which
would require warrants.

## Weaponized Ads

Spyware companies have discovered that the ad ecosystem is also an attack
vector. Since a displayed ad is executable code running directly on your
device, it is a surface for exploitation:

1. Identify a target's advertising ID (via other surveillance or by
   harvesting bidstream data near a known location)
2. Place a high bid on that specific advertising ID in the RTB auction
3. Win the auction and deliver a malicious ad containing a browser exploit
4. The exploit escapes the browser sandbox and installs spyware

This technique requires no phishing, no clicked links, and no user
interaction — the target simply opens an app that displays ads.

## Data Brokers

Data brokers aggregate advertising data with other sources — public records,
social media scrapes, purchase history, voter rolls — to build comprehensive
profiles tied to real identities. A single broker may hold profiles on
250 million+ people.

The data flows in multiple directions:
- **Advertisers** buy segments ("mothers aged 25-34 interested in organic
  food in Seattle")
- **Insurance companies** can infer health conditions from location data
  (frequent hospital visits, pharmacy trips)
- **Employers** can purchase pre-employment screening data
- **Stalkers** can find a target's home address via people-search sites
  that aggregate broker data

The opt-out process is deliberately painful. Each broker requires a separate
request. Many require identity verification (uploading a photo ID to the
very company you want to stop tracking you). New data continuously flows in,
requiring periodic re-submission.

## What You Can Do

### Disable the advertising ID
- **macOS**: System Settings > Privacy & Security > Apple Advertising >
  Personalized Ads > off
- **iOS**: Settings > Privacy & Security > Apple Advertising >
  Personalized Ads > off (zeroes out the IDFA)
- **Android**: Settings > Privacy > Ads > Delete advertising ID

### Limit app permissions
- Deny location access to apps that don't need it (games, weather apps
  are the most common offenders cited in the Le Monde investigation)
- Use "While Using" instead of "Always" for location when you must grant it
- Review permissions quarterly

### Block at the network level
- Use an ad-blocking DNS like NextDNS, AdGuard DNS, or Pi-hole
- Install uBlock Origin in your browser
- These block ad SDK connections before they send your data

### Request broker deletions
- Exercise your rights under GDPR (EU) or CCPA (California)
- Use data removal services (Incogni, DeleteMe, Optery) to automate
  the process across hundreds of brokers
- Run `dtm protect ad_tracking` for a full list of opt-out URLs

## Why VPN Doesn't Help

A VPN hides your IP address from websites and ad networks. But advertising
IDs are device-level identifiers transmitted directly from apps to ad SDKs
— they never touch the VPN tunnel. Your IDFA is the same whether you are
on Wi-Fi, cellular, or behind a VPN.

The SDK inside the app reads your GPS coordinates directly from the device
(if you granted location permission) and sends them along with your
advertising ID to the ad network. The VPN encrypts the transport, but the
payload — your identity and location — is sent willingly by the app itself.

The only effective defense is to disable the advertising ID and restrict
which apps can access your location.
