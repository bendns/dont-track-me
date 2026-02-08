"""Configuration loading — reads optional TOML config file."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATHS = [
    Path.home() / ".config" / "dont-track-me" / "config.toml",
    Path("dtm.toml"),
]


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load configuration from a TOML file.

    Searches default paths if no explicit path is given.
    Returns an empty dict if no config file is found.
    """
    paths = [path] if path is not None else DEFAULT_CONFIG_PATHS

    for p in paths:
        if p.exists():
            with open(p, "rb") as f:
                return tomllib.load(f)

    return {}


def get_default_country() -> str:
    """Get default country code: DTM_COUNTRY env var → config.toml → 'us'."""
    env = os.environ.get("DTM_COUNTRY")
    if env:
        return env.lower()
    config = load_config()
    return config.get("country", "us").lower()
