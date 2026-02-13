"""Scoring engine — aggregate module audit scores into an overall trackability score."""

from __future__ import annotations

from typing import TypedDict

import yaml

from dont_track_me.core.base import AuditResult
from dont_track_me.core.paths import SHARED_DIR


class _ScoreTier(TypedDict):
    min: int
    label: str
    color: str


def _load_scoring() -> tuple[dict[str, int], int, list[_ScoreTier]]:
    path = SHARED_DIR / "schema" / "scoring.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    return data["module_weights"], data["default_weight"], data["score_tiers"]


MODULE_WEIGHTS, DEFAULT_WEIGHT, _SCORE_TIERS = _load_scoring()


def compute_overall_score(results: list[AuditResult]) -> float:
    """Compute a weighted average score from multiple module results.

    Returns a float from 0.0 (fully exposed) to 100.0 (fully protected).
    """
    if not results:
        return 0.0

    total_weight = 0
    weighted_sum = 0.0

    for result in results:
        weight = MODULE_WEIGHTS.get(result.module_name, DEFAULT_WEIGHT)
        weighted_sum += result.score * weight
        total_weight += weight

    if total_weight == 0:
        return 0.0

    return round(weighted_sum / total_weight, 1)


def get_score_label(score: float) -> str:
    """Return a human-readable label for a score."""
    for tier in _SCORE_TIERS:
        if score >= tier["min"]:
            return str(tier["label"])
    return "Critical"


def get_score_color(score: float) -> str:
    """Return a Rich color name for a score."""
    for tier in _SCORE_TIERS:
        if score >= tier["min"]:
            return str(tier["color"])
    return "red"
