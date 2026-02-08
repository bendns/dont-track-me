# YouTube Profiling — Your Subscriptions Feed Google's Ad Machine

## How YouTube profiles you

YouTube is the world's second-largest search engine and the dominant video platform. Every subscription, watch, like, and search feeds into Google's advertising profile — the most comprehensive profiling system ever built.

### What your subscriptions reveal

Your YouTube subscription list is a map of your worldview:

- **Political channels**: Subscribing only to left-wing or right-wing commentators categorizes your politics with high confidence
- **Religious content**: Subscriptions to religious channels signal your faith
- **News sources**: Which news channels you follow reveals your media diet and perceived bias
- **Cultural interests**: Music, comedy, gaming preferences create lifestyle profiles

### The recommendation engine as a profiling amplifier

YouTube's algorithm creates a feedback loop:
1. You subscribe to one political channel
2. The algorithm recommends similar channels
3. You subscribe to more
4. Your profile becomes increasingly one-dimensional
5. This makes you easier to categorize and target

Research has shown YouTube's recommendation engine can radicalize users within a few hours of watching, pushing them toward increasingly extreme content within their detected ideological lane.

### Who sees this data

- **Google Ads**: Your YouTube profile determines ad targeting across all Google services and the 2M+ websites in Google's Display Network
- **Data brokers**: Google's ad categories (inferred from YouTube behavior) are partially visible to advertisers and can be reverse-engineered
- **Governments**: YouTube viewing data can be subpoenaed. In 2024, a court ordered Google to hand over YouTube viewer data for specific videos
- **Researchers**: YouTube subscription data is often publicly visible and has been used in academic studies to predict political affiliation

## Why a VPN doesn't help

YouTube profiling is based on your **Google account activity**. Whether you watch through a VPN, at a coffee shop, or at home — your subscriptions, watch history, and search history are identical. The VPN hides your IP from Google's servers but does nothing about the behavioral profile tied to your account.

## What this module does

### Audit

Connects to the YouTube Data API, fetches your complete subscription list, and classifies each channel by category and political/cultural perspective. Flags one-sided subscription patterns as profiling risks.

### Protect

Subscribes to channels from underrepresented perspectives to balance your profile. Uses the free YouTube Data API quota (~200 subscribes/day).

```bash
# Authenticate with YouTube
dtm auth youtube

# Analyze subscription bias
dtm audit youtube

# Diversify subscriptions
dtm protect youtube --apply

# Only diversify political channels
dtm protect youtube --apply --categories politics
```

## Severity

**High** — YouTube subscriptions feed directly into Google's ad network, which reaches 90%+ of internet users. Your subscription list is one of the strongest signals Google uses to categorize your beliefs, interests, and identity.
