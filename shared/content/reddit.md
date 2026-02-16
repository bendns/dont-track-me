# Reddit Tracking — Your Votes, Clicks, and Subscriptions Under Surveillance

## How Reddit tracks you

Reddit is one of the most detailed profiling platforms on the internet. Unlike Instagram or TikTok where you mostly consume content, Reddit users actively **vote, comment, and subscribe** — each action revealing beliefs, interests, and personality traits.

### What Reddit collects

- **Subscriptions**: Your subreddit list is a direct map of your interests, politics, hobbies, and identity
- **Votes**: Every upvote and downvote reveals your opinion — and by default, these are **public**
- **Click tracking**: Reddit tracks which links you click, even outside of Reddit
- **Cross-site tracking**: Reddit uses third-party data from other websites to personalize your experience
- **Ad personalization**: Your activity directly feeds Reddit's ad targeting system

### 7 tracking settings you probably haven't disabled

Reddit buries these in Settings > Privacy:

1. **Activity-relevant ads** — Reddit uses your browsing and voting to target ads
2. **Third-party data personalized ads** — external data brokers feed into Reddit's ad system
3. **Third-party site data personalized ads** — your activity on *other websites* targets Reddit ads
4. **Third-party site data personalized content** — what you do elsewhere changes what Reddit shows you
5. **Click tracking** — Reddit follows every link you click
6. **Public votes** — anyone can see what you upvote and downvote
7. **Online presence** — your status is broadcast to other users

### Subreddit profiling

Your subscription list is one of the most powerful profiling signals available:

- Subscribed to r/progressive and r/LateStageCapitalism? → Left-wing voter
- Subscribed to r/Conservative and r/Libertarian? → Right-wing voter
- Subscribed to r/islam or r/Christianity? → Religious profiling
- Subscribed to r/lgbt or r/gaybros? → Sexuality profiling

Data brokers and researchers have demonstrated that subreddit subscriptions alone can predict political affiliation with over 90% accuracy.

## Why a VPN doesn't help

Reddit tracks you through your **account activity**, not your IP. Your votes, comments, and subscriptions are the same regardless of your network path. A VPN hides your IP from Reddit's servers but does nothing about the behavioral profile they build.

## What this module does

### Audit

Reads your actual Reddit privacy settings via the API and flags every tracking-hostile setting that's enabled. Also analyzes your subscription list for ideological bias — if 80% of your political subreddits lean one direction, that's flagged.

### Protect

1. **Harden**: Disables all 7 tracking settings in a single API call — no need to click through Reddit's buried settings pages
2. **Diversify**: Subscribes to a balanced set of subreddits across all political, religious, and cultural perspectives

```bash
# Authenticate with Reddit
dtm auth reddit

# See what's exposed
dtm audit reddit

# Fix everything
dtm protect reddit --apply

# Only harden privacy settings (no subscription changes)
dtm protect reddit --apply --harden-only

# Only diversify subscriptions
dtm protect reddit --apply --diversify-only
```

## Severity

**Critical** — Reddit combines behavioral tracking (votes, clicks) with ideological profiling (subscriptions) and cross-site surveillance (third-party data). Most users have never touched the privacy settings, leaving all 7 tracking features enabled by default.
