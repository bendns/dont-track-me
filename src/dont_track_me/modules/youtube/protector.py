"""YouTube protector — diversify subscriptions to obfuscate profile."""

from __future__ import annotations

import asyncio
import random

from dont_track_me.core.auth import AuthenticationRequired, TokenStore
from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.youtube.channels import get_balanced_channels
from dont_track_me.modules.youtube.client import YouTubeClient


async def protect_youtube(
    dry_run: bool = True,
    categories: str | None = None,
    per_perspective: int = 2,
    **kwargs,
) -> ProtectionResult:
    """Diversify YouTube subscriptions.

    Args:
        dry_run: Preview changes without applying.
        categories: Comma-separated channel categories.
        per_perspective: Channels to add per perspective.
    """
    token = TokenStore.load("youtube")
    if token is None or token.is_expired:
        raise AuthenticationRequired("youtube")

    client = YouTubeClient(token)
    actions_available: list[str] = []
    actions_taken: list[str] = []

    cat_list = None
    if categories:
        cat_list = [c.strip() for c in categories.split(",")]

    new_channels = get_balanced_channels(
        categories=cat_list,
        per_perspective=per_perspective,
    )

    # Check which we're already subscribed to
    try:
        existing = await client.get_subscriptions()
        existing_ids = {s["channel_id"] for s in existing}
    except Exception:
        existing_ids = set()

    to_subscribe = [ch for ch in new_channels if ch["channel_id"] not in existing_ids]

    if to_subscribe:
        actions_available.append(f"Subscribe to {len(to_subscribe)} diverse channels")
        for ch in to_subscribe[:10]:
            actions_available.append(
                f"  {ch['name']} ({ch['category']}/{ch['perspective']})"
            )
        if len(to_subscribe) > 10:
            actions_available.append(f"  ... and {len(to_subscribe) - 10} more")

        # Quota estimate: ~50 units per subscribe, 10K daily quota
        quota_cost = len(to_subscribe) * 50
        actions_available.append(
            f"Estimated quota cost: {quota_cost} units (daily limit: 10,000)"
        )

        if not dry_run:
            for ch in to_subscribe:
                success = await client.subscribe(ch["channel_id"])
                if success:
                    actions_taken.append(
                        f"Subscribed to {ch['name']} ({ch['category']}/{ch['perspective']})"
                    )
                else:
                    actions_taken.append(f"Failed to subscribe to {ch['name']}")
                # Respect rate limits — random delay between subscribes
                await asyncio.sleep(random.uniform(1.0, 4.0))
    else:
        actions_available.append("Subscription list already well diversified")

    return ProtectionResult(
        module_name="youtube",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
