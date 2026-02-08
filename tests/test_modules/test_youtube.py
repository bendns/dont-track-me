"""Tests for the YouTube module (mocked API)."""

import pytest

from dont_track_me.core.auth import AuthenticationRequired
from dont_track_me.modules.youtube.channels import (
    CHANNELS,
    classify_channel,
    get_all_categories,
    get_balanced_channels,
)


def test_channels_has_categories():
    cats = get_all_categories()
    assert "politics" in cats
    assert "education" in cats
    assert "entertainment" in cats
    assert "sports" in cats


def test_politics_channels_balanced():
    politics = CHANNELS["politics"]
    assert "left" in politics
    assert "right" in politics
    assert "center" in politics
    assert "international" in politics
    for perspective, channels in politics.items():
        assert len(channels) >= 3, f"politics/{perspective} has too few channels"


def test_classify_channel_known():
    # PragerU channel ID
    result = classify_channel("UCJdKr0Bgd_5saZYqLCa9mng")
    assert result is not None
    cat, perspective, name = result
    assert cat == "politics"
    assert perspective == "right"
    assert name == "PragerU"


def test_classify_channel_unknown():
    assert classify_channel("UCxxxxxxxxxxxxxxxxxxxxxxxxx") is None


def test_get_balanced_channels():
    channels = get_balanced_channels(per_perspective=1)
    assert len(channels) > 10
    categories = {c["category"] for c in channels}
    assert len(categories) >= 3


def test_get_balanced_channels_with_filter():
    channels = get_balanced_channels(categories=["politics"], per_perspective=1)
    categories = {c["category"] for c in channels}
    assert categories == {"politics"}


def test_balanced_channels_have_metadata():
    channels = get_balanced_channels(per_perspective=1)
    for ch in channels:
        assert "channel_id" in ch
        assert "name" in ch
        assert "category" in ch
        assert "perspective" in ch


def test_channel_ids_are_strings():
    """All channel IDs should be non-empty strings."""
    for cat, perspectives in CHANNELS.items():
        for perspective, channels in perspectives.items():
            for ch in channels:
                assert isinstance(ch["id"], str) and len(ch["id"]) > 5, (
                    f"Bad channel ID in {cat}/{perspective}: {ch}"
                )


@pytest.mark.asyncio
async def test_audit_requires_auth():
    """Audit should raise AuthenticationRequired when not authenticated."""
    from unittest.mock import patch

    from dont_track_me.modules.youtube.auditor import audit_youtube

    with patch("dont_track_me.modules.youtube.auditor.TokenStore") as mock_store:
        mock_store.load.return_value = None
        with pytest.raises(AuthenticationRequired):
            await audit_youtube()


@pytest.mark.asyncio
async def test_protect_requires_auth():
    """Protect should raise AuthenticationRequired when not authenticated."""
    from unittest.mock import patch

    from dont_track_me.modules.youtube.protector import protect_youtube

    with patch("dont_track_me.modules.youtube.protector.TokenStore") as mock_store:
        mock_store.load.return_value = None
        with pytest.raises(AuthenticationRequired):
            await protect_youtube(dry_run=True)
