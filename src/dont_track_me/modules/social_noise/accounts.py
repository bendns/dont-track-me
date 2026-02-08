"""Social media account database — loads per-country YAML data files.

Each country file contains platform → category → perspective → lists of accounts.
The goal: follow accounts across the full spectrum so your "following"
list doesn't reveal a one-dimensional profile.

Data files live in ./data/{country}.yaml (ISO 3166-1 alpha-2, lowercase).
"""

from __future__ import annotations

import random
from functools import lru_cache
from pathlib import Path

import yaml

DATA_DIR = Path(__file__).parent / "data"


@lru_cache(maxsize=8)
def load_accounts(
    country: str = "us",
) -> dict[str, dict[str, dict[str, list[str]]]]:
    """Load account database for a country from YAML."""
    path = DATA_DIR / f"{country}.yaml"
    if not path.exists():
        available = sorted(p.stem for p in DATA_DIR.glob("*.yaml"))
        raise FileNotFoundError(
            f"No account data for country '{country}'. "
            f"Available: {', '.join(available)}"
        )
    with open(path) as f:
        return yaml.safe_load(f)


def get_available_countries() -> list[str]:
    """Return all available country codes."""
    return sorted(p.stem for p in DATA_DIR.glob("*.yaml"))


class _AccountsProxy(dict):
    """Lazy proxy so `from accounts import ACCOUNTS` still works (loads US data)."""

    _loaded: bool = False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.update(load_accounts("us"))
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


ACCOUNTS: dict[str, dict[str, dict[str, list[str]]]] = _AccountsProxy()  # type: ignore[assignment]


def get_all_platforms(country: str = "us") -> list[str]:
    """Return all available platforms for a country."""
    return list(load_accounts(country).keys())


def get_platform_categories(platform: str, country: str = "us") -> list[str]:
    """Return categories available for a platform in a country."""
    accounts = load_accounts(country)
    if platform not in accounts:
        return []
    return list(accounts[platform].keys())


def get_balanced_follow_list(
    platforms: list[str] | None = None,
    categories: list[str] | None = None,
    per_subcategory: int = 2,
    country: str = "us",
) -> dict[str, list[dict[str, str]]]:
    """Generate balanced follow lists for selected platforms.

    Returns a dict mapping platform names to lists of {account, category, perspective}.
    Picks evenly from every perspective in every category.
    """
    accounts = load_accounts(country)

    if platforms is None:
        platforms = list(accounts.keys())

    result: dict[str, list[dict[str, str]]] = {}

    for platform in platforms:
        if platform not in accounts:
            continue

        accounts_list: list[dict[str, str]] = []
        platform_data = accounts[platform]

        for cat_name, perspectives in platform_data.items():
            if categories and cat_name not in categories:
                continue

            for perspective_name, accts in perspectives.items():
                sample_size = min(per_subcategory, len(accts))
                sampled = random.sample(accts, sample_size)
                for account in sampled:
                    accounts_list.append(
                        {
                            "account": account,
                            "category": cat_name,
                            "perspective": perspective_name,
                        }
                    )

        random.shuffle(accounts_list)
        result[platform] = accounts_list

    return result
