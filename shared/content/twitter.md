# Twitter/X — Your Public Diary With a Hidden Audience

## How Twitter/X profiles you

Every interaction on Twitter generates data that feeds into your advertising profile:
- **Tweets and replies** — analyzed for topics, sentiment, political leaning, and language patterns
- **Likes and retweets** — reveal your interests, affiliations, and the content you consume silently
- **Follows and unfollows** — map your social graph and ideological alignment
- **Search queries** — expose what you're curious about, even if you never tweet about it
- **Muted and blocked accounts** — signal topics and people you want to avoid
- **Time spent reading** — Twitter tracks how long you pause on each tweet, even if you don't engage

Twitter categorizes users into 350+ interest segments visible at Settings > Ads preferences > Interests. These include granular categories like political ideology, health conditions, financial behavior, and relationship status.

## The t.co link shortener: a tracking mechanism

Every outbound link on Twitter is wrapped through `t.co`, Twitter's URL shortener. When you click any link in a tweet, the request first goes to Twitter's servers before redirecting to the destination. This gives Twitter:
- A complete log of every link you click
- The ability to correlate link clicks with your account
- Referrer data from the destination website
- Timing data showing when and how often you click external links

This means Twitter has a partial browsing history for every user — built entirely from in-app link clicks.

## Off-Twitter activity and the conversion pixel

Twitter's tracking extends beyond the platform via its conversion tracking pixel. When a website embeds Twitter's pixel (found on over 1 million websites), it reports your visit back to Twitter. This creates an off-platform browsing profile linked to your account.

The data flow works in both directions:
1. **Inbound**: websites tell Twitter when you visit, what pages you view, and what you purchase
2. **Outbound**: Twitter shares audience segments with advertisers, who can target you based on your off-platform behavior

Combined with t.co click tracking, Twitter builds a browsing profile that covers both links you click on Twitter and websites you visit independently.

## Discoverability: the deanonymization vector

Twitter's discoverability settings allow anyone to find your account using your email address or phone number. This is one of the most dangerous privacy settings because:

- **Data broker cross-referencing**: companies like Spokeo, WhitePages, and Acxiom already have your email and phone number linked to your real name and address. If discoverability is enabled, they can trivially link your Twitter account to your real identity.
- **The 2022 scraping incident**: a vulnerability in Twitter's discoverability API was exploited to scrape email-to-account mappings for over 200 million users. The resulting database was published on hacking forums, permanently linking millions of pseudonymous accounts to real email addresses.
- **Targeted attacks**: journalists, activists, and whistleblowers using pseudonymous accounts are particularly vulnerable. An adversary who knows your phone number can find your account and monitor your activity.

## DM security

Twitter Direct Messages are **not end-to-end encrypted by default**. This means:
- Twitter employees with access to internal tools can read your DMs
- DMs are stored on Twitter's servers in a format accessible to the company
- Law enforcement can obtain DMs through legal subpoenas without notifying you
- A data breach of Twitter's systems would expose your private conversations
- DMs persist even after you delete your account (they remain in the recipient's inbox)

Twitter introduced encrypted DMs for verified users in 2023, but the feature has significant limitations: no group chat support, no media encryption, and both parties must be verified.

## Inferred identity and cross-device tracking

Twitter's "inferred identity" feature uses device fingerprinting to link your activity across browsers and devices. Even if you:
- Use a different browser
- Are not logged in
- Clear your cookies

Twitter can still identify you by matching your device characteristics (screen resolution, installed fonts, timezone, browser version, IP address) against known profiles. This enables persistent tracking that survives standard privacy measures.

## Political targeting and algorithmic amplification

Twitter's ad platform enables political micro-targeting with precision. Advertisers can target users based on:
- Inferred political leaning (derived from follows, likes, and engagement patterns)
- Keywords in tweets
- Follower lookalike audiences (people who behave similarly to a candidate's followers)
- Geographic targeting down to postal code level

Research has shown that Twitter's algorithm amplifies politically charged content because it drives engagement. Your timeline is not a neutral feed — it's optimized to maximize the time you spend on the platform, which systematically favors provocative and divisive content.

## Connected apps and OAuth tokens

When you authorize a third-party app via "Sign in with Twitter," you grant it an OAuth token with specific permissions. Common permissions include:
- Read your tweets and profile
- Read your DMs
- Post tweets on your behalf
- Access your follower/following lists

These tokens **do not expire** unless you explicitly revoke them. Apps you authorized years ago and no longer use still have access to your account data. Each connected app is a potential data leak — if the app's servers are breached, your Twitter data is exposed.

## What a VPN doesn't protect

A VPN hides your IP address from websites, but Twitter tracks you by **account identity and device fingerprint**, not IP:
- Your tweets, likes, and follows are linked to your account regardless of IP
- The inferred identity system uses browser fingerprinting, not IP, for cross-device tracking
- Off-Twitter activity tracking uses cookies and pixels that persist across VPN connections
- The t.co link shortener logs clicks against your account, not your IP

A VPN protects your IP from Twitter itself (useful if you want to hide your general location), but does nothing to prevent the behavioral profiling that constitutes Twitter's primary tracking mechanism.

## Concrete steps to reduce your exposure

1. **Protect your tweets** — the single most impactful setting. Public tweets are permanently archived, scraped, and indexed.
2. **Disable all ad personalization** — Settings > Ads preferences > turn off personalized ads, inferred identity, and data sharing with business partners.
3. **Disable off-Twitter activity** — prevents websites with Twitter pixels from feeding data back to your profile.
4. **Disable discoverability** — turn off both email and phone number lookup to prevent deanonymization.
5. **Disable location tagging** — and delete location data from existing tweets.
6. **Restrict DMs** — only allow messages from people you follow.
7. **Enable 2FA** — use an authenticator app (not SMS, which is vulnerable to SIM-swap attacks and was removed for free accounts).
8. **Revoke connected apps** — review and remove any apps you no longer use.
9. **Disable contact syncing** — and delete previously uploaded contacts.
10. **Use an external browser** — avoid clicking links within the Twitter app; copy and open them in a privacy-focused browser instead.
