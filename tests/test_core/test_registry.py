"""Tests for the module registry and scoring engine."""

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.core.registry import get_all_modules, get_module
from dont_track_me.core.scoring import compute_overall_score, get_score_label


def test_discover_modules():
    """All 3 MVP modules should be discovered."""
    modules = get_all_modules()
    assert "dns" in modules
    assert "headers" in modules
    assert "metadata" in modules


def test_get_module():
    mod = get_module("dns")
    assert mod is not None
    assert mod.name == "dns"
    assert mod.display_name == "DNS Leak Detection"


def test_get_unknown_module():
    assert get_module("nonexistent") is None


def test_module_has_educational_content():
    mod = get_module("dns")
    content = mod.get_educational_content()
    assert "DNS" in content
    assert len(content) > 100


def test_compute_overall_score_empty():
    assert compute_overall_score([]) == 0.0


def test_compute_overall_score():
    results = [
        AuditResult(module_name="dns", score=80, findings=[], raw_data={}),
        AuditResult(module_name="headers", score=60, findings=[], raw_data={}),
    ]
    score = compute_overall_score(results)
    # dns weight=12, headers weight=10 → (80*12 + 60*10) / 22 = 1560/22 ≈ 70.9
    assert 70 <= score <= 72


def test_score_labels():
    assert get_score_label(95) == "Excellent"
    assert get_score_label(75) == "Good"
    assert get_score_label(55) == "Moderate"
    assert get_score_label(35) == "Poor"
    assert get_score_label(15) == "Critical"
