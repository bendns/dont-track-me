"""Search query database — loads per-country YAML data files.

Each country file contains categories → perspectives → lists of search queries.
The goal: generate searches that span the full spectrum so no single
ideological or lifestyle profile can be inferred.

Data files live in ./data/{country}.yaml (ISO 3166-1 alpha-2, lowercase).
"""

from __future__ import annotations

import random
from functools import lru_cache
from pathlib import Path

import yaml

DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=8)
def load_queries(country: str = "us") -> dict[str, dict[str, list[str]]]:
    """Load query database for a country from YAML."""
    path = DATA_DIR / f"{country}.yaml"
    if not path.exists():
        available = sorted(p.stem for p in DATA_DIR.glob("*.yaml"))
        raise FileNotFoundError(
            f"No query data for country '{country}'. Available: {', '.join(available)}"
        )
    with open(path) as f:
        return yaml.safe_load(f)


def get_available_countries() -> list[str]:
    """Return all available country codes."""
    return sorted(p.stem for p in DATA_DIR.glob("*.yaml"))


class _QueriesProxy(dict):
    """Lazy proxy so `from queries import QUERIES` still works (loads US data)."""

    _loaded: bool = False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.update(load_queries("us"))
            self._loaded = True

    def __getitem__(self, key):  # type: ignore[override]
        self._ensure_loaded()
        return super().__getitem__(key)

    def __contains__(self, key):  # type: ignore[override]
        self._ensure_loaded()
        return super().__contains__(key)

    def __iter__(self):  # type: ignore[override]
        self._ensure_loaded()
        return super().__iter__()

    def keys(self):  # type: ignore[override]
        self._ensure_loaded()
        return super().keys()

    def values(self):  # type: ignore[override]
        self._ensure_loaded()
        return super().values()

    def items(self):  # type: ignore[override]
        self._ensure_loaded()
        return super().items()

    def __len__(self) -> int:
        self._ensure_loaded()
        return super().__len__()


QUERIES: dict[str, dict[str, list[str]]] = _QueriesProxy()  # type: ignore[assignment]

# Search engines and their query URL templates
SEARCH_ENGINES: dict[str, str] = {
    "google": "https://www.google.com/search?q={}",
    "bing": "https://www.bing.com/search?q={}",
    "duckduckgo": "https://duckduckgo.com/?q={}",
    "yahoo": "https://search.yahoo.com/search?p={}",
}

# Realistic user agents to rotate through
USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def get_all_categories(country: str = "us") -> list[str]:
    """Return all available query categories for a country."""
    return list(load_queries(country).keys())


def get_balanced_queries(
    categories: list[str] | None = None,
    count: int = 50,
    country: str = "us",
) -> list[str]:
    """Pick queries evenly across all perspectives within selected categories.

    Returns a shuffled list of `count` queries, balanced across all sides.
    """
    queries = load_queries(country)

    if categories is None:
        categories = list(queries.keys())

    # Collect all queries from selected categories
    all_queries: list[str] = []
    for cat in categories:
        if cat not in queries:
            continue
        perspectives = queries[cat]
        # Pick evenly from each perspective
        per_perspective = max(1, count // (len(perspectives) * len(categories)))
        for _perspective_name, perspective_queries in perspectives.items():
            sample_size = min(per_perspective, len(perspective_queries))
            all_queries.extend(random.sample(perspective_queries, sample_size))

    # Shuffle and trim to requested count
    random.shuffle(all_queries)
    return all_queries[:count]
