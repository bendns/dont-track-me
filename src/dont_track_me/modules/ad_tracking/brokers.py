"""Data broker registry — load per-country broker lists from YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_DATA_DIR = Path(__file__).parent / "data"


def load_brokers(country: str = "us") -> list[dict[str, Any]]:
    """Load data broker list for a given country.

    Falls back to US brokers if the country file does not exist.
    """
    # Sanitize to alphanumeric to prevent path traversal
    clean = "".join(c for c in country if c.isalnum()).lower() or "us"
    data_file = _DATA_DIR / f"{clean}.yaml"
    if not data_file.exists():
        data_file = _DATA_DIR / "us.yaml"

    with data_file.open() as f:
        data = yaml.safe_load(f)

    return data.get("brokers", [])
