# Browser Cookies & Third-Party Tracking

## What are cookies?

Cookies are small pieces of data that websites store in your browser. They were originally designed for useful purposes like keeping you logged in or remembering your shopping cart. However, they have become one of the primary tools for tracking you across the web.

## First-party vs third-party cookies

**First-party cookies** are set by the website you're visiting. When you log into example.com, it sets a cookie so it remembers you. These are generally harmless and necessary for the web to function.

**Third-party cookies** are set by domains other than the one you're visiting. When you visit a news site, dozens of ad networks, analytics platforms, and data brokers may set cookies in your browser — even though you never interacted with them directly.

## How cross-site tracking works

1. You visit **newssite.com**, which loads an ad from **adnetwork.com**
2. **adnetwork.com** sets a cookie in your browser with a unique ID (e.g., `user_id=abc123`)
3. You visit **shopsite.com**, which also loads content from **adnetwork.com**
4. **adnetwork.com** reads the same cookie — now it knows you visited both sites
5. Over time, the ad network builds a detailed profile of your browsing habits

This happens silently. You never visit adnetwork.com directly, but it tracks you across every site that uses its services.

## Cookie syncing

The problem is even worse due to **cookie syncing** (also called "cookie matching"). Different tracking companies share your unique IDs with each other, linking their separate profiles into one comprehensive record. A single page load can trigger dozens of these sync operations.

## Why SameSite matters

The `SameSite` cookie attribute controls whether a cookie is sent with cross-site requests:

- **SameSite=Strict**: Cookie only sent on same-site requests (most private)
- **SameSite=Lax**: Cookie sent on same-site requests and top-level navigations
- **SameSite=None**: Cookie sent on all requests, including cross-site (enables tracking)

Tracking cookies almost always use `SameSite=None` because they need to be readable across different websites.

## Why HttpOnly matters

Cookies without the `HttpOnly` flag can be read by JavaScript running on the page. This means any third-party script (analytics, ads, widgets) can read and potentially exfiltrate these cookies.

## Why a VPN doesn't help

A VPN hides your IP address but does nothing about cookies. Cookies persist across sessions and are tied to your browser, not your network. Even with a VPN, tracking cookies identify you the same way — by reading the unique ID they stored previously.

## Long-lived cookies

Some tracking cookies have expiration dates years in the future. A cookie that expires in 2 years means the tracker can follow you for that entire period, building an increasingly detailed profile.

## Severity

Browser cookies receive a **weight of 15** in the privacy score — the second-highest after fingerprinting. This reflects their central role in the ad-tech surveillance ecosystem. Most cross-site tracking still relies on cookies, making them one of the most impactful things to address.

## What you can do

- **Block third-party cookies** in your browser settings (Chrome, Firefox, Safari all support this)
- **Use Enhanced Tracking Protection** (Firefox) or similar built-in protections
- **Regularly clear cookies** or use a cookie management extension
- **Use a privacy-focused browser** like Brave, LibreWolf, or Firefox with strict mode
- **Use container tabs** (Firefox Multi-Account Containers) to isolate tracking between sites
