# Email Tracking Pixels — Someone Knows You Read This

## What are tracking pixels?

A tracking pixel is a tiny, invisible image (typically 1x1 pixel) embedded in an HTML email. When you open the email, your mail client automatically loads the image from the sender's server. This single HTTP request reveals:

- **Your IP address** — which maps to your approximate location
- **When you opened the email** — exact timestamp
- **How many times you opened it** — each load is a new request
- **Your device and OS** — from the User-Agent header
- **Your email client** — Thunderbird, Apple Mail, Gmail, etc.

Each tracking pixel has a unique URL tied to your email address, so the sender knows exactly who opened what, when, and where.

## Who uses tracking pixels?

### Marketing platforms (nearly all of them)
Mailchimp, HubSpot, Salesforce, Klaviyo, SendGrid, Braze, and virtually every email marketing platform embed tracking pixels by default. Open rates are a core metric in email marketing — and tracking pixels are how they're measured.

### Individual email trackers
Services like Mailtrack, Yesware, Streak, and Superhuman let individuals track whether their emails were opened. Your coworker, recruiter, or salesperson may know exactly when you read their email and how many times you re-opened it.

### Advertisers
Ad networks like Google and Facebook embed pixels in promotional emails to build cross-platform profiles. Opening a marketing email can link your email identity to your browsing profile.

## How it works technically

```
1. Sender composes email with hidden image:
   <img src="https://tracker.example.com/open?id=abc123&email=you@mail.com" width="1" height="1">

2. You open the email in your mail client

3. Mail client loads all images, including the tracking pixel

4. Tracker server receives the request:
   - IP: 203.0.113.42 (your location)
   - Time: 2024-01-15 09:32:14 UTC
   - User-Agent: Mozilla/5.0 (Macintosh; ...) Thunderbird/115.0
   - Pixel ID: abc123 → maps to you@mail.com

5. Sender sees: "you@mail.com opened the email at 9:32 AM from Paris, France"
```

## Why a VPN doesn't fully help

A VPN hides your real IP address from the tracker server, which prevents geolocation. But the tracker still records:
- That you opened the email (the open event itself)
- When and how many times
- Your device and email client information

The tracking pixel confirms your engagement regardless of your IP.

## What to do about it

1. **Disable remote image loading** — this is the single most effective defense:
   - **Apple Mail**: Settings → Privacy → check "Protect Mail Activity" (proxies images + hides IP)
   - **Thunderbird**: Settings → Privacy & Security → uncheck "Allow remote content"
   - **Gmail (web)**: Settings → General → Images → "Ask before displaying external images"
   - **Outlook**: File → Options → Trust Center → Automatic Download → block images

2. **Use a tracking-aware email provider**: ProtonMail and Tutanota block tracking pixels by default

3. **Use browser extensions**: PixelBlock (Gmail), Ugly Email (Gmail), or Trocker detect and block tracking pixels

4. **Strip pixels from saved emails**: Use `dtm protect email --apply --path ./emails/` to remove tracking images from `.eml` files

5. **Use plain text mode**: Read emails in plain text when possible — no images means no tracking

## Severity

**High** — Email tracking pixels are ubiquitous. Nearly every marketing email and many personal/professional emails contain them. They silently confirm your engagement and reveal your location without any visible indication. Unlike cookies or browser fingerprinting, most users have no idea they're being tracked simply by reading an email.
