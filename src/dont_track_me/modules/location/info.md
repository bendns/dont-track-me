# Location Data Leakage

Your devices continuously generate and store location data — often in ways you
don't expect. Wi-Fi history, timezone settings, and app permissions each create
independent channels through which your physical movements can be tracked.

## Wi-Fi SSID History

Every Wi-Fi network your device remembers is a location marker. Hotel names,
airport codes, workplace SSIDs, and coffee shop networks form a detailed map
of places you have visited.

### Probe Requests

When Wi-Fi is enabled, your device periodically broadcasts *probe requests* —
packets that ask "Is network X nearby?" — for every remembered SSID. Anyone
within radio range can passively capture these probes and reconstruct your
network history. Research by Matte et al. (2020) demonstrated that probe
requests can uniquely fingerprint a device and reveal its owner's movement
patterns.

Retailers, advertisers, and surveillance systems deploy Wi-Fi probe collection
at scale. Even with MAC address randomization (introduced in iOS 14 and
Android 10), SSID lists in probe requests remain a reliable fingerprint.

### Mitigation

- Regularly forget networks you no longer use
- Disable auto-join for public and hotel networks
- Turn off Wi-Fi when not actively connected
- On macOS: `networksetup -removepreferredwirelessnetwork en0 'SSID'`

## Timezone vs VPN Mismatch

VPNs route your traffic through a server in another location, changing your
apparent IP address. However, your *system timezone* is set locally and does
not change when you connect to a VPN. This creates a detectable mismatch.

Websites can read your browser's timezone via JavaScript
(`Intl.DateTimeFormat().resolvedOptions().timeZone`) and compare it to your
IP geolocation. If your system says "America/New_York" but your IP resolves to
"Europe/London," the site knows you are using a VPN — and your real timezone
reveals your approximate true location.

### Mitigation

- Manually set your timezone to match your VPN exit location
- Disable automatic timezone detection:
  macOS: System Settings > General > Date & Time > Set time zone automatically > off
- Some VPN clients offer timezone synchronization — enable it if available

## macOS Location Services

macOS Location Services grants apps continuous access to your geographic
coordinates via GPS, Wi-Fi positioning, and Bluetooth beacons. Each app with
Location permission can track your movements in the background.

### The TCC Database

macOS stores permission grants in the Transparency, Consent, and Control (TCC)
database at `~/Library/Application Support/com.apple.TCC/TCC.db`. The
`kTCCServiceLocation` service controls Location access. Apps with both
Location and Camera+Microphone permissions form a complete surveillance
toolkit — they can see where you are, watch you, and listen to you.

### Significant Locations

macOS and iOS maintain a hidden feature called *Significant Locations* (formerly
"Frequent Locations") that logs places you visit regularly. This data is stored
encrypted on-device and synced via iCloud. While Apple states it is used only
for predictive suggestions, the data represents a comprehensive movement diary.

Review at: System Settings > Privacy & Security > Location Services > System
Services > Significant Locations.

## ALPR: License Plate Reader Networks

Automated License Plate Recognition (ALPR) systems are cameras — mounted on
police cars, toll booths, parking garages, and fixed poles — that photograph
every passing vehicle's license plate, along with the time and GPS coordinates.

### Scale

- The largest commercial ALPR network in the US (operated by Vigilant Solutions /
  Motorola Solutions) contains over 15 billion plate scans
- The DEA operates a nationwide ALPR network along highways and border areas
- Many police departments share plate data across jurisdictions via systems
  like the National Law Intelligence Center (NLIC)
- Private companies like Rekor and Flock Safety deploy ALPR on residential
  streets at the request of homeowner associations

### What This Means

Even without a phone, your vehicle's movements are recorded. ALPR data can
reconstruct where you have been, when, and how often. The EFF has documented
cases where ALPR data was used to track people attending protests, visiting
medical clinics, and meeting with attorneys.

Unlike digital tracking, ALPR surveillance cannot be defeated with a VPN or
privacy browser. It operates in physical space.

### Research and Further Reading

- EFF: "Automated License Plate Readers" — comprehensive overview of ALPR
  technology, privacy risks, and policy recommendations
- ACLU: "You Are Being Tracked" — report on ALPR deployment across the US
- Brennan Center for Justice: "License Plate Readers" — legal analysis of
  ALPR data retention and access policies
- Nature Scientific Reports (2025): studies on mobility pattern inference from
  sparse location data

## Why VPN Doesn't Protect Against Local Location Leaks

A VPN encrypts your internet traffic and masks your IP address. It does *not*
protect against:

- **Wi-Fi probe requests**: broadcast locally, never touch the VPN tunnel
- **System timezone**: set on your device, readable by any website via JavaScript
- **GPS/Wi-Fi positioning**: Location Services operates independently of your
  network connection
- **Bluetooth beacons**: used for indoor positioning, bypass VPN entirely
- **ALPR**: operates in physical space with cameras, completely unrelated to
  network traffic

Location privacy requires layered defenses across both digital and physical
channels.
