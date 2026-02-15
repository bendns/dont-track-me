# Application Tracking SDKs — What's Hiding Inside Your Apps

## What are tracking SDKs?

When developers build apps, they often embed third-party Software Development Kits (SDKs) for analytics, advertising, and crash reporting. These SDKs run silently inside the app and report your behavior to external servers — often without any visible indication.

Common tracking SDKs include Google Firebase Analytics, Facebook SDK, Adjust, AppsFlyer, Branch, Mixpanel, Amplitude, and Segment. Each one collects data about how you use the app: what screens you visit, how long you stay, what buttons you tap, and what you purchase.

## How SDK tracking works

### Embedded code
Tracking SDKs are compiled directly into the application binary. On macOS, they appear as frameworks inside the `.app` bundle or as symbols in the Mach-O binary. They initialize when the app launches — before you interact with it.

### Data collection
A single analytics SDK typically collects: device model, OS version, screen resolution, language, timezone, installed apps, advertising identifier, session duration, screen views, and custom events defined by the developer. Multiple SDKs in one app multiply this collection.

### Network communication
SDKs phone home to their servers on app launch and periodically during use. Even when you're not actively using the app, background refresh can trigger SDK data transmission.

## App Transport Security exceptions

macOS and iOS require apps to use HTTPS by default through App Transport Security (ATS). However, apps can declare exceptions in their `Info.plist` to allow insecure HTTP connections. These exceptions may expose your data in transit to network observers — your ISP, Wi-Fi operator, or anyone performing a man-in-the-middle attack.

Apps with `NSAllowsArbitraryLoads = true` have effectively disabled all transport security, allowing any network connection over plain HTTP.

## Why this matters

A typical user has 30-80 applications installed. If half contain 2-3 tracking SDKs each, that's 30-120 separate tracking pipelines reporting your behavior. The data from these SDKs is aggregated by data brokers to build detailed profiles that follow you across apps, devices, and platforms.

## What you can do

1. **Scan your apps** — Run `dtm apps` to see which applications contain known tracking SDKs
2. **Block tracker connections** — Use Little Snitch or LuLu to prevent apps from contacting tracker domains
3. **Prefer open-source alternatives** — Apps with public source code can be audited for tracking
4. **Use web versions** — Browser-based alternatives run inside the browser sandbox with fewer tracking capabilities
5. **Check ATS exceptions** — Apps disabling transport security are a red flag for careless data handling

## Severity

**Medium** — Tracking SDKs are pervasive and difficult to detect without binary analysis. Individual SDKs collect limited data, but the aggregate across dozens of apps creates comprehensive behavioral profiles.
