# Browser Fingerprinting

## What is browser fingerprinting?

Browser fingerprinting is a technique that identifies you by combining dozens of small signals from your browser and device — your GPU model, installed fonts, screen resolution, CPU cores, timezone, and more. Together, these create a near-unique identifier that works without cookies, survives private browsing, and persists even if you clear all your data.

Unlike cookies, you can't "delete" a fingerprint. There's no consent popup. Your browser leaks this information to every website you visit, automatically, silently.

## How it works

### Canvas fingerprinting

HTML5 Canvas renders text and shapes slightly differently depending on your GPU, graphics driver, font rendering engine, and operating system. A website draws a hidden image, extracts the pixel data, and hashes it. Your hash is almost certainly unique among hundreds of thousands of users.

### WebGL fingerprinting

WebGL exposes your exact GPU model and driver version (e.g., "ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)"). This string alone narrows your identity to a small group. Combined with supported WebGL extensions and shader precision, it's highly identifying.

### AudioContext fingerprinting

The Web Audio API processes sound slightly differently per hardware and driver configuration. By rendering a short audio signal and measuring the output, websites can derive a hardware-specific hash — even without playing any audible sound.

### Font enumeration

Websites can probe which fonts you have installed by measuring how text renders in different font families. Each additional custom font (especially unusual ones) increases your uniqueness. A system with 300 fonts is far more identifiable than one with the default 100.

### Navigator properties

Your browser exposes hardware details via the `navigator` object:
- `hardwareConcurrency` — number of CPU cores (e.g., 10)
- `deviceMemory` — amount of RAM in GB
- `maxTouchPoints` — touchscreen capability
- `languages` — preferred language list
- `platform` — operating system identifier

### Screen fingerprinting

Screen resolution, color depth, pixel ratio, and available screen area all contribute to your fingerprint. Unusual resolutions (like high-DPI displays with non-standard scaling) are especially identifying.

### Timezone

Your timezone narrows your location to a few regions. Combined with language preferences, it significantly reduces anonymity.

## Why it's worse than cookies

- **No consent**: There's no popup asking permission. Fingerprinting happens silently.
- **No delete button**: You can't clear a fingerprint like you can delete cookies.
- **Survives private mode**: Private/incognito browsing doesn't change your fingerprint.
- **Cross-browser**: Some signals (fonts, screen, GPU) are the same across browsers.
- **Invisible**: There's no browser indicator showing you're being fingerprinted.

## Why a VPN doesn't help

A VPN changes your IP address. Browser fingerprinting uses your browser and hardware characteristics, which are completely independent of your network connection. You could connect through 10 different VPNs and your fingerprint would remain identical.

## Entropy per signal (approximate)

| Signal | Entropy (bits) | Notes |
|--------|---------------|-------|
| Canvas | 8-12 | GPU + driver + font rendering |
| WebGL renderer | 6-10 | Exact GPU model string |
| Fonts | 5-8 | Depends on custom fonts installed |
| Screen resolution | 4-6 | Higher with unusual DPI/scaling |
| AudioContext | 4-8 | Hardware-specific audio processing |
| User-Agent | 4-6 | Browser + version + OS |
| Timezone | 3-5 | Narrows geographic region |
| Languages | 2-4 | Language preference list |
| CPU cores | 2-3 | navigator.hardwareConcurrency |

Combined, these signals produce 30-50+ bits of entropy — enough to uniquely identify virtually any browser among millions.

## What you can do

- **Firefox: enable `privacy.resistFingerprinting`** — the single most effective measure. It normalizes Canvas output, WebGL strings, fonts, timezone (to UTC), screen size, language, and User-Agent. Some sites may break.
- **Use Tor Browser** — all Tor users share an identical fingerprint, making individual identification impossible. The gold standard for anti-fingerprinting.
- **Install anti-fingerprinting extensions** — CanvasBlocker (Firefox), uBlock Origin in advanced mode, JShelter.
- **Minimize custom fonts** — remove fonts you don't use.
- **Use Brave with Shields** — Brave randomizes fingerprints by default, which is less effective than normalization but still helps.

## Severity

Browser fingerprinting receives a **weight of 20** in the privacy score — the highest of all modules. This reflects its power: fingerprinting is the tracking technique that survives everything else. Even if you block cookies, use a VPN, and browse in private mode, fingerprinting can still identify you.
