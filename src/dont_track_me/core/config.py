"""Configuration loading — reads optional TOML config file."""

from __future__ import annotations

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
    if path is not None:
        paths = [path]
    else:
        paths = DEFAULT_CONFIG_PATHS

    for p in paths:
        if p.exists():
            with open(p, "rb") as f:
                return tomllib.load(f)

    return {}
