"""Tests for the social_noise module."""

import pytest

from dont_track_me.modules.social_noise.accounts import (
    ACCOUNTS,
    get_all_platforms,
    get_balanced_follow_list,
    get_platform_categories,
)
from dont_track_me.modules.social_noise.auditor import audit_social_noise
from dont_track_me.modules.social_noise.protector import protect_social_noise


def test_accounts_database_has_platforms():
    """Should have all major platforms."""
    platforms = get_all_platforms()
    assert "instagram" in platforms
    assert "youtube" in platforms
    assert "tiktok" in platforms
    assert "facebook" in platforms
    assert "twitter" in platforms


def test_instagram_has_balanced_politics():
    """Instagram politics should have multiple perspectives."""
    politics = ACCOUNTS["instagram"]["politics"]
    assert "left" in politics
    assert "right" in politics
    assert "center" in politics


def test_instagram_has_diverse_music():
    """Instagram music should have multiple genres."""
    music = ACCOUNTS["instagram"]["music"]
    assert len(music) >= 5  # At least 5 genres
    assert "pop" in music
    assert "metal" in music
    assert "rap_hiphop" in music
    assert "classical" in music


def test_youtube_has_politics_spectrum():
    """YouTube should cover political spectrum."""
    politics = ACCOUNTS["youtube"]["politics"]
    assert "left" in politics
    assert "right" in politics
    assert "center" in politics


def test_get_platform_categories():
    """Should return categories for a platform."""
    cats = get_platform_categories("instagram")
    assert "music" in cats
    assert "politics" in cats
    assert "news" in cats


def test_get_platform_categories_unknown():
    """Unknown platform should return empty list."""
    assert get_platform_categories("myspace") == []


def test_get_balanced_follow_list():
    """Should return balanced accounts for each platform."""
    result = get_balanced_follow_list(platforms=["instagram"], per_subcategory=1)
    assert "instagram" in result
    accounts = result["instagram"]
    assert len(accounts) > 0
    # Should have accounts from different categories
    categories = {a["category"] for a in accounts}
    assert len(categories) >= 3


def test_get_balanced_follow_list_with_category_filter():
    """Should respect category filter."""
    result = get_balanced_follow_list(
        platforms=["instagram"],
        categories=["politics"],
        per_subcategory=1,
    )
    accounts = result["instagram"]
    categories = {a["category"] for a in accounts}
    assert categories == {"politics"}


def test_get_balanced_follow_list_has_perspectives():
    """Each account should have perspective metadata."""
    result = get_balanced_follow_list(
        platforms=["youtube"], categories=["politics"], per_subcategory=1
    )
    for acc in result["youtube"]:
        assert "account" in acc
        assert "category" in acc
        assert "perspective" in acc


@pytest.mark.asyncio
async def test_audit_social_noise():
    """Audit should return educational findings."""
    result = await audit_social_noise()
    assert result.module_name == "social_noise"
    assert 0 <= result.score <= 100
    assert len(result.findings) >= 3  # Multiple educational findings


@pytest.mark.asyncio
async def test_protect_dry_run():
    """Dry-run should describe strategy without generating lists."""
    result = await protect_social_noise(dry_run=True)
    assert result.dry_run is True
    assert len(result.actions_available) > 0
    assert len(result.actions_taken) == 0


@pytest.mark.asyncio
async def test_protect_apply_generates_lists():
    """Apply should generate follow lists."""
    result = await protect_social_noise(dry_run=False, platforms="instagram")
    assert result.dry_run is False
    assert len(result.actions_taken) > 0


@pytest.mark.asyncio
async def test_protect_json_format():
    """JSON format should output valid JSON."""
    import json

    result = await protect_social_noise(
        dry_run=False, platforms="instagram", output_format="json"
    )
    assert result.dry_run is False
    assert len(result.actions_taken) == 1  # Single JSON blob
    parsed = json.loads(result.actions_taken[0])
    assert "instagram" in parsed


@pytest.mark.asyncio
async def test_protect_platform_filter():
    """Should only generate for specified platforms."""
    result = await protect_social_noise(
        dry_run=False, platforms="youtube", output_format="json"
    )
    import json

    parsed = json.loads(result.actions_taken[0])
    assert "youtube" in parsed
    assert "instagram" not in parsed
