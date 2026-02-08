"""Tests for the privacy checklist infrastructure."""

from dont_track_me.core.base import ThreatLevel
from dont_track_me.core.checklist import PrivacyCheck, compute_checklist_score


def _make_checks() -> list[PrivacyCheck]:
    return [
        PrivacyCheck(
            id="critical_check",
            question="Is this critical setting enabled?",
            description="Critical setting.",
            threat_level=ThreatLevel.CRITICAL,
            remediation="Fix it.",
            category="security",
        ),
        PrivacyCheck(
            id="high_check",
            question="Is this high setting enabled?",
            description="High setting.",
            threat_level=ThreatLevel.HIGH,
            remediation="Fix it.",
            category="visibility",
        ),
        PrivacyCheck(
            id="medium_check",
            question="Is this medium setting enabled?",
            description="Medium setting.",
            threat_level=ThreatLevel.MEDIUM,
            remediation="Fix it.",
            category="data_sharing",
        ),
    ]


def test_all_safe_returns_100():
    checks = _make_checks()
    responses = {"critical_check": True, "high_check": True, "medium_check": True}
    score, findings = compute_checklist_score(checks, responses)
    assert score == 100
    assert all(f.threat_level == ThreatLevel.INFO for f in findings)


def test_all_unsafe_subtracts_penalties():
    checks = _make_checks()
    responses = {"critical_check": False, "high_check": False, "medium_check": False}
    score, findings = compute_checklist_score(checks, responses)
    # 100 - 15 (critical) - 10 (high) - 6 (medium) = 69
    assert score == 69
    unsafe = [f for f in findings if f.threat_level != ThreatLevel.INFO]
    assert len(unsafe) == 3


def test_unanswered_assumed_unsafe():
    checks = _make_checks()
    responses = {"critical_check": True}  # other two unanswered
    score, _findings = compute_checklist_score(checks, responses)
    # 100 - 10 (high) - 6 (medium) = 84
    assert score == 84


def test_score_clamped_to_zero():
    """Score should never go below 0 even with many penalties."""
    checks = [
        PrivacyCheck(
            id=f"check_{i}",
            question=f"Q{i}?",
            description="D",
            threat_level=ThreatLevel.CRITICAL,
            remediation="Fix",
            category="security",
        )
        for i in range(10)
    ]
    responses = {f"check_{i}": False for i in range(10)}
    score, _ = compute_checklist_score(checks, responses)
    assert score == 0


def test_empty_responses():
    checks = _make_checks()
    score, findings = compute_checklist_score(checks, {})
    # All assumed unsafe: 100 - 15 - 10 - 6 = 69
    assert score == 69
    assert len(findings) == 3


def test_technical_countermeasure_optional():
    """Technical countermeasure field is optional and defaults to None."""
    check = PrivacyCheck(
        id="t",
        question="Q?",
        description="D",
        threat_level=ThreatLevel.HIGH,
        remediation="Fix",
        category="security",
    )
    assert check.technical_countermeasure is None

    check_with = PrivacyCheck(
        id="t2",
        question="Q?",
        description="D",
        threat_level=ThreatLevel.HIGH,
        remediation="Fix",
        category="security",
        technical_countermeasure="Block at DNS level",
    )
    assert check_with.technical_countermeasure == "Block at DNS level"


def test_safe_answer_false():
    """Check with safe_answer=False should score safe when user answers False."""
    checks = [
        PrivacyCheck(
            id="inverted",
            question="Is tracking enabled?",
            description="Tracking.",
            threat_level=ThreatLevel.HIGH,
            remediation="Disable it.",
            category="data_sharing",
            safe_answer=False,
        ),
    ]
    score, findings = compute_checklist_score(checks, {"inverted": False})
    assert score == 100
    assert findings[0].threat_level == ThreatLevel.INFO
