"""Search noise protector — generate and execute noise search queries."""

from __future__ import annotations

import asyncio
import random
from urllib.parse import quote_plus

import httpx

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.search_noise.queries import (
    SEARCH_ENGINES,
    USER_AGENTS,
    get_all_categories,
    get_balanced_queries,
)


async def _execute_query(
    client: httpx.AsyncClient,
    query: str,
    engine_name: str,
    engine_url: str,
) -> str:
    """Send a single search query to a search engine."""
    url = engine_url.format(quote_plus(query))
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    try:
        resp = await client.get(url, headers=headers, follow_redirects=True)
        return f"[{engine_name}] '{query}' — HTTP {resp.status_code}"
    except Exception as e:
        return f"[{engine_name}] '{query}' — Error: {e}"


async def protect_search_noise(
    dry_run: bool = True,
    categories: str | None = None,
    count: int = 50,
    engines: str | None = None,
    min_delay: float = 2.0,
    max_delay: float = 8.0,
    **kwargs,
) -> ProtectionResult:
    """Generate search noise to obfuscate your search profile.

    Args:
        dry_run: If True, show what would be searched without sending requests.
        categories: Comma-separated category names (default: all).
        count: Number of queries to send.
        engines: Comma-separated engine names (default: all).
        min_delay: Minimum delay between queries in seconds.
        max_delay: Maximum delay between queries in seconds.
    """
    actions_available: list[str] = []
    actions_taken: list[str] = []

    # Parse categories
    if categories:
        cat_list = [c.strip() for c in categories.split(",")]
    else:
        cat_list = get_all_categories()

    # Parse engines
    if engines:
        engine_list = {
            name: url
            for name, url in SEARCH_ENGINES.items()
            if name in [e.strip() for e in engines.split(",")]
        }
    else:
        engine_list = dict(SEARCH_ENGINES)

    if not engine_list:
        return ProtectionResult(
            module_name="search_noise",
            dry_run=dry_run,
            actions_available=["No valid search engines selected."],
        )

    # Generate balanced query list
    queries = get_balanced_queries(categories=cat_list, count=count)

    actions_available.append(
        f"Send {len(queries)} balanced search queries across {len(engine_list)} engines "
        f"(categories: {', '.join(cat_list)})"
    )
    actions_available.append(f"Engines: {', '.join(engine_list.keys())}")
    actions_available.append(
        f"Delay between queries: {min_delay}-{max_delay}s (randomized)"
    )

    # Show sample queries in dry-run
    sample = queries[:10]
    actions_available.append("--- Sample queries ---")
    for q in sample:
        actions_available.append(f'  "{q}"')
    if len(queries) > 10:
        actions_available.append(f"  ... and {len(queries) - 10} more")

    if not dry_run:
        async with httpx.AsyncClient(timeout=15) as client:
            for i, query in enumerate(queries):
                # Pick a random engine for each query
                engine_name = random.choice(list(engine_list.keys()))
                engine_url = engine_list[engine_name]

                result = await _execute_query(client, query, engine_name, engine_url)
                actions_taken.append(result)

                # Human-like delay between queries
                if i < len(queries) - 1:
                    delay = random.uniform(min_delay, max_delay)
                    await asyncio.sleep(delay)

    return ProtectionResult(
        module_name="search_noise",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
