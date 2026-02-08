"""Reddit protector — harden privacy settings and diversify subscriptions."""

from __future__ import annotations

import asyncio
import random

from dont_track_me.core.auth import AuthenticationRequired, TokenStore
from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.reddit.client import TRACKING_PREFS, RedditClient
from dont_track_me.modules.reddit.subreddits import get_balanced_subreddits


async def protect_reddit(
    dry_run: bool = True,
    harden_only: bool = False,
    diversify_only: bool = False,
    categories: str | None = None,
    per_perspective: int = 2,
    **kwargs,
) -> ProtectionResult:
    """Harden Reddit privacy settings and diversify subscriptions.

    Args:
        dry_run: Preview changes without applying.
        harden_only: Only fix privacy settings, skip diversification.
        diversify_only: Only diversify subscriptions, skip privacy settings.
        categories: Comma-separated subreddit categories for diversification.
        per_perspective: Subreddits to add per perspective.
    """
    token = TokenStore.load("reddit")
    if token is None or token.is_expired:
        raise AuthenticationRequired("reddit")

    client = RedditClient(token)
    actions_available: list[str] = []
    actions_taken: list[str] = []

    # Phase 1: Harden privacy settings
    if not diversify_only:
        try:
            prefs = await client.get_prefs()
            safe_prefs: dict = {}

            for pref_name, pref_info in TRACKING_PREFS.items():
                current = prefs.get(pref_name)
                safe = pref_info["safe_value"]
                if current != safe:
                    safe_prefs[pref_name] = safe
                    actions_available.append(
                        f"Disable {pref_name}: {pref_info['description']}"
                    )

            if safe_prefs:
                if not dry_run:
                    await client.update_prefs(safe_prefs)
                    for pref_name in safe_prefs:
                        actions_taken.append(f"Disabled {pref_name}")
            else:
                actions_available.append("All privacy settings already hardened")

        except AuthenticationRequired:
            raise
        except Exception as e:
            actions_available.append(f"Failed to read preferences: {e}")

    # Phase 2: Diversify subscriptions
    if not harden_only:
        cat_list = None
        if categories:
            cat_list = [c.strip() for c in categories.split(",")]

        new_subs = get_balanced_subreddits(
            categories=cat_list,
            per_perspective=per_perspective,
        )

        # Check which we're already subscribed to
        try:
            existing = await client.get_subscribed_subreddits()
            existing_lower = {s.lower() for s in existing}
        except Exception:
            existing_lower = set()

        to_subscribe = [
            s for s in new_subs if s["subreddit"].lower() not in existing_lower
        ]

        if to_subscribe:
            actions_available.append(
                f"Subscribe to {len(to_subscribe)} diverse subreddits"
            )
            for s in to_subscribe[:10]:
                actions_available.append(
                    f"  r/{s['subreddit']} ({s['category']}/{s['perspective']})"
                )
            if len(to_subscribe) > 10:
                actions_available.append(f"  ... and {len(to_subscribe) - 10} more")

            if not dry_run:
                for s in to_subscribe:
                    success = await client.subscribe(s["subreddit"])
                    if success:
                        actions_taken.append(
                            f"Subscribed to r/{s['subreddit']} ({s['category']}/{s['perspective']})"
                        )
                    else:
                        actions_taken.append(
                            f"Failed to subscribe to r/{s['subreddit']}"
                        )
                    # Rate limiting — Reddit allows 60 req/min
                    await asyncio.sleep(random.uniform(1.0, 2.0))
        else:
            actions_available.append("Subscription list already well diversified")

    return ProtectionResult(
        module_name="reddit",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
