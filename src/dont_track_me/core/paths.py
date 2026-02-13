"""Shared content directory resolution."""

from __future__ import annotations

from pathlib import Path

# Resolve from src/dont_track_me/core/paths.py → repo root → shared/
SHARED_DIR = Path(__file__).resolve().parent.parent.parent.parent / "shared"

# Fallback for installed packages (wheel includes shared as dont_track_me/_shared)
if not SHARED_DIR.exists():
    SHARED_DIR = Path(__file__).resolve().parent.parent / "_shared"
