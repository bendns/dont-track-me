"""TikTok privacy checks — loaded from shared YAML data."""

from __future__ import annotations

import yaml

from dont_track_me.core.checklist import PrivacyCheck
from dont_track_me.core.paths import SHARED_DIR


def _load_checks() -> list[PrivacyCheck]:
    path = SHARED_DIR / "checklists" / "tiktok.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    return [PrivacyCheck(**check) for check in data["checks"]]


PRIVACY_CHECKS: list[PrivacyCheck] = _load_checks()
