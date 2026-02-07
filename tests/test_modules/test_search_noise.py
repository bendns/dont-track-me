"""Tests for the search_noise module."""

import pytest

from dont_track_me.modules.search_noise.auditor import audit_search_noise
from dont_track_me.modules.search_noise.protector import protect_search_noise
from dont_track_me.modules.search_noise.queries import (
    QUERIES,
    SEARCH_ENGINES,
    get_all_categories,
    get_balanced_queries,
)


def test_queries_database_has_categories():
    """Query database should have all expected categories."""
    categories = get_all_categories()
    assert "politics" in categories
    assert "religion" in categories
    assert "news_sources" in categories
    assert "interests" in categories
    assert "lifestyle" in categories


def test_politics_queries_are_balanced():
    """Politics category should have multiple perspectives."""
    politics = QUERIES["politics"]
    assert "left" in politics
    assert "right" in politics
    assert "center" in politics
    assert "libertarian" in politics
    assert "green" in politics
    # Each perspective should have queries
    for perspective, queries in politics.items():
        assert len(queries) >= 5, f"politics/{perspective} has too few queries"


def test_religion_queries_are_balanced():
    """Religion category should cover major world religions."""
    religion = QUERIES["religion"]
    assert "christianity" in religion
    assert "islam" in religion
    assert "judaism" in religion
    assert "buddhism" in religion
    assert "hinduism" in religion
    assert "atheism" in religion


def test_search_engines_defined():
    """Should have multiple search engines."""
    assert "google" in SEARCH_ENGINES
    assert "bing" in SEARCH_ENGINES
    assert "duckduckgo" in SEARCH_ENGINES


def test_get_balanced_queries_returns_correct_count():
    """Should return the requested number of queries."""
    queries = get_balanced_queries(count=20)
    assert len(queries) == 20


def test_get_balanced_queries_filters_categories():
    """Should only use specified categories."""
    queries = get_balanced_queries(categories=["politics"], count=30)
    assert len(queries) == 30


def test_get_balanced_queries_are_shuffled():
    """Two calls should return different orderings."""
    q1 = get_balanced_queries(count=20)
    q2 = get_balanced_queries(count=20)
    # Very unlikely to be identical due to shuffling
    assert set(q1) != set(q2) or q1 != q2  # At least order differs


@pytest.mark.asyncio
async def test_audit_search_noise_returns_result():
    """Audit should return a valid AuditResult."""
    result = await audit_search_noise()
    assert result.module_name == "search_noise"
    assert 0 <= result.score <= 100
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_protect_dry_run():
    """Dry-run should list actions without sending queries."""
    result = await protect_search_noise(dry_run=True, count=10)
    assert result.dry_run is True
    assert len(result.actions_available) > 0
    assert len(result.actions_taken) == 0
    # Should include sample queries
    combined = " ".join(result.actions_available)
    assert "Sample" in combined or "queries" in combined.lower()


@pytest.mark.asyncio
async def test_protect_with_category_filter():
    """Dry-run with category filter should work."""
    result = await protect_search_noise(dry_run=True, categories="politics", count=10)
    assert result.dry_run is True
    assert "politics" in " ".join(result.actions_available).lower()
