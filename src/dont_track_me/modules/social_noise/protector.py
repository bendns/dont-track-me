"""Social noise protector — generate balanced follow lists to obfuscate profiles."""

from __future__ import annotations

import json

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.social_noise.accounts import (
    get_all_platforms,
    get_balanced_follow_list,
    get_platform_categories,
)


def _format_follow_list(follow_list: dict[str, list[dict[str, str]]]) -> list[str]:
    """Format follow lists as readable action items."""
    lines: list[str] = []

    for platform, accounts in follow_list.items():
        if not accounts:
            continue
        lines.append(f"--- {platform.upper()} ({len(accounts)} accounts) ---")

        # Group by category for readability
        by_category: dict[str, list[dict[str, str]]] = {}
        for acc in accounts:
            cat = acc["category"]
            by_category.setdefault(cat, []).append(acc)

        for cat, accs in by_category.items():
            lines.append(f"  [{cat}]")
            for acc in accs:
                lines.append(f"    {acc['account']}  ({acc['perspective']})")

    return lines


async def protect_social_noise(
    dry_run: bool = True,
    platforms: str | None = None,
    categories: str | None = None,
    per_subcategory: int = 2,
    output_format: str = "rich",
    country: str = "us",
    **kwargs,
) -> ProtectionResult:
    """Generate balanced social media follow lists.

    Args:
        dry_run: If True, describe the strategy without generating lists.
        platforms: Comma-separated platform names (default: all).
        categories: Comma-separated category names (default: all).
        per_subcategory: Number of accounts to pick from each perspective.
        output_format: "rich" for readable output, "json" for machine-readable.
        country: ISO 3166-1 alpha-2 country code (default: us).
    """
    actions_available: list[str] = []
    actions_taken: list[str] = []

    # Parse platforms
    if platforms:
        platform_list = [p.strip() for p in platforms.split(",")]
    else:
        platform_list = get_all_platforms(country)

    # Parse categories
    cat_list = [c.strip() for c in categories.split(",")] if categories else None

    actions_available.append(f"Generate balanced follow lists for: {', '.join(platform_list)}")

    for p in platform_list:
        cats = get_platform_categories(p, country)
        if cat_list:
            cats = [c for c in cats if c in cat_list]
        if cats:
            actions_available.append(f"  {p}: categories = {', '.join(cats)}")

    actions_available.append(f"Accounts per perspective: {per_subcategory}")

    if not dry_run:
        follow_list = get_balanced_follow_list(
            platforms=platform_list,
            categories=cat_list,
            per_subcategory=per_subcategory,
            country=country,
        )

        if output_format == "json":
            actions_taken.append(json.dumps(follow_list, indent=2))
        else:
            formatted = _format_follow_list(follow_list)
            actions_taken.extend(formatted)

            # Summary
            total = sum(len(accs) for accs in follow_list.values())
            actions_taken.append(
                f"\nTotal: {total} accounts to follow across {len(follow_list)} platforms"
            )
            actions_taken.append("Follow these accounts to balance your social media profile.")

    return ProtectionResult(
        module_name="social_noise",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
