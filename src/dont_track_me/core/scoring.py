"""Scoring engine — aggregate module audit scores into an overall trackability score."""

from __future__ import annotations

from dont_track_me.core.base import AuditResult

# Empirical weights: how much each vector contributes to overall trackability.
# Higher weight = bigger impact on your digital footprint.
MODULE_WEIGHTS: dict[str, int] = {
    "fingerprint": 20,
    "cookies": 15,
    "dns": 12,
    "social": 12,
    "headers": 10,
    "metadata": 8,
    "email": 8,
    "search": 5,
    "search_noise": 10,
    "social_noise": 12,
    "reddit": 10,
    "youtube": 12,
    "instagram": 10,
    "tiktok": 10,
    "facebook": 10,
    "webrtc": 5,
    "behavior": 5,
    "app_permissions": 8,
    "location": 8,
    "ad_tracking": 12,
}

DEFAULT_WEIGHT = 5


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
    if score >= 90:
        return "Excellent"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Moderate"
    if score >= 30:
        return "Poor"
    return "Critical"


def get_score_color(score: float) -> str:
    """Return a Rich color name for a score."""
    if score >= 90:
        return "green"
    if score >= 70:
        return "blue"
    if score >= 50:
        return "yellow"
    if score >= 30:
        return "dark_orange"
    return "red"
