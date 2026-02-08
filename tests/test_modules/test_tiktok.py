"""Tests for the TikTok privacy checklist module."""

import asyncio

from dont_track_me.modules.tiktok.auditor import audit_tiktok
from dont_track_me.modules.tiktok.checks import PRIVACY_CHECKS
from dont_track_me.modules.tiktok.module import TikTokModule
from dont_track_me.modules.tiktok.protector import protect_tiktok


def test_checks_count():
    assert len(PRIVACY_CHECKS) == 12


def test_checks_have_unique_ids():
    ids = [c.id for c in PRIVACY_CHECKS]
    assert len(ids) == len(set(ids))


def test_checks_cover_all_categories():
    categories = {c.category for c in PRIVACY_CHECKS}
    assert "visibility" in categories
    assert "data_sharing" in categories
    assert "security" in categories


def test_audit_educational_mode():
    result = asyncio.run(audit_tiktok())
    assert result.module_name == "tiktok"
    assert result.score == 30
    assert len(result.findings) >= 3


def test_audit_interactive_all_safe():
    responses = {c.id: c.safe_answer for c in PRIVACY_CHECKS}
    result = asyncio.run(audit_tiktok(responses=responses))
    assert result.score == 100


def test_audit_interactive_all_unsafe():
    responses = {c.id: not c.safe_answer for c in PRIVACY_CHECKS}
    result = asyncio.run(audit_tiktok(responses=responses))
    assert result.score < 30


def test_protect_full_guide():
    result = asyncio.run(protect_tiktok())
    assert result.module_name == "tiktok"
    assert result.dry_run is True
    assert len(result.actions_available) > 0


def test_protect_with_all_safe():
    responses = {c.id: c.safe_answer for c in PRIVACY_CHECKS}
    result = asyncio.run(protect_tiktok(responses=responses))
    assert "properly configured" in result.actions_available[0]


def test_module_has_checklist():
    mod = TikTokModule()
    assert hasattr(mod, "get_checklist")
    assert len(mod.get_checklist()) == 12


def test_module_educational_content():
    mod = TikTokModule()
    content = mod.get_educational_content()
    assert "TikTok" in content
    assert len(content) > 1000
