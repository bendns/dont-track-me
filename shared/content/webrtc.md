# WebRTC IP Leaks — Your VPN's Blind Spot

## What is WebRTC?

WebRTC (Web Real-Time Communication) is a browser technology that enables peer-to-peer audio, video, and data sharing directly between browsers — no plugins required. It powers video calls (Google Meet, Zoom in-browser), file sharing, and screen sharing.

To establish these peer-to-peer connections, browsers use **STUN** (Session Traversal Utilities for NAT) servers to discover your public and local IP addresses.

## How WebRTC leaks your IP

When a website uses WebRTC, your browser contacts STUN servers to discover the best network path for a peer-to-peer connection. This process reveals:

1. **Your public IP address** — the IP your ISP assigned to you, which identifies your household or location
2. **Your local/private IP address** — your device's address on the local network (e.g., 192.168.1.x), which reveals your network topology

Any website can trigger this discovery silently using a few lines of JavaScript. The browser performs the STUN query automatically — no user interaction or permission is required.

## Why a VPN doesn't help

This is the critical part: **WebRTC bypasses your VPN tunnel**. When your browser makes a STUN request, it may use a network interface outside the VPN tunnel, revealing your real IP address to the website — even though all other traffic goes through the VPN.

This is not a bug in your VPN. It's by design in the WebRTC specification: the protocol deliberately tries all available network interfaces to find the best connection path, including interfaces your VPN doesn't cover.

## Real-world impact

- **De-anonymization**: A website can discover your real IP while you believe you're anonymous behind a VPN
- **Location tracking**: Your public IP reveals your approximate geographic location
- **Network fingerprinting**: Your local IP address reveals details about your network setup, adding to your browser fingerprint
- **Corporate espionage**: Your internal network addresses could reveal information about your organization's network

## What to do about it

1. **Firefox**: Open `about:config` and set `media.peerconnection.enabled` to `false`
2. **Chrome/Chromium**: Install a WebRTC leak prevention extension
3. **Brave**: Settings → Privacy → set WebRTC IP Handling Policy to "Disable non-proxied UDP"
4. **Safari**: Disable WebRTC in Develop → Experimental Features
5. **Tor Browser**: WebRTC is disabled by default — don't re-enable it
6. **Test regularly**: Visit a WebRTC leak test site to verify your protection

## Trade-offs

Disabling WebRTC will break browser-based video calls and screen sharing. If you need these features, consider using a dedicated app instead of the browser version, or use a browser profile with WebRTC enabled only for trusted sites.

## Severity

**High** — WebRTC IP leaks completely defeat VPN protection. Any website can silently discover your real IP address with a few lines of JavaScript. This is one of the most common and dangerous privacy leaks for VPN users.
