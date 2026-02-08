"""Tests for the Reddit module (mocked API)."""

import pytest

from dont_track_me.core.auth import AuthenticationRequired
from dont_track_me.modules.reddit.subreddits import (
    SUBREDDITS,
    classify_subreddit,
    get_all_categories,
    get_balanced_subreddits,
)


def test_subreddits_has_categories():
    cats = get_all_categories()
    assert "politics" in cats
    assert "religion" in cats
    assert "news" in cats
    assert "culture" in cats
    assert "lifestyle" in cats


def test_politics_subreddits_balanced():
    politics = SUBREDDITS["politics"]
    assert "left" in politics
    assert "right" in politics
    assert "center" in politics
    for perspective, subs in politics.items():
        assert len(subs) >= 3, f"politics/{perspective} has too few subreddits"


def test_religion_subreddits_balanced():
    religion = SUBREDDITS["religion"]
    assert "christianity" in religion
    assert "islam" in religion
    assert "buddhism" in religion
    assert "atheism" in religion


def test_classify_subreddit_known():
    result = classify_subreddit("Conservative")
    assert result is not None
    cat, perspective = result
    assert cat == "politics"
    assert perspective == "right"


def test_classify_subreddit_case_insensitive():
    result = classify_subreddit("conservative")
    assert result is not None


def test_classify_subreddit_unknown():
    assert classify_subreddit("someRandomSubreddit12345") is None


def test_get_balanced_subreddits():
    subs = get_balanced_subreddits(per_perspective=1)
    assert len(subs) > 10
    # Should have multiple categories
    categories = {s["category"] for s in subs}
    assert len(categories) >= 4


def test_get_balanced_subreddits_with_filter():
    subs = get_balanced_subreddits(categories=["politics"], per_perspective=1)
    categories = {s["category"] for s in subs}
    assert categories == {"politics"}


def test_balanced_subreddits_have_metadata():
    subs = get_balanced_subreddits(per_perspective=1)
    for s in subs:
        assert "subreddit" in s
        assert "category" in s
        assert "perspective" in s


@pytest.mark.asyncio
async def test_audit_requires_auth():
    """Audit should raise AuthenticationRequired when not authenticated."""
    from unittest.mock import patch

    from dont_track_me.modules.reddit.auditor import audit_reddit

    with patch("dont_track_me.modules.reddit.auditor.TokenStore") as mock_store:
        mock_store.load.return_value = None
        with pytest.raises(AuthenticationRequired):
            await audit_reddit()


@pytest.mark.asyncio
async def test_protect_requires_auth():
    """Protect should raise AuthenticationRequired when not authenticated."""
    from unittest.mock import patch

    from dont_track_me.modules.reddit.protector import protect_reddit

    with patch("dont_track_me.modules.reddit.protector.TokenStore") as mock_store:
        mock_store.load.return_value = None
        with pytest.raises(AuthenticationRequired):
            await protect_reddit(dry_run=True)
