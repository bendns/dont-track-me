"""Tests for the headers module."""

import pytest

from dont_track_me.modules.headers.auditor import TRACKING_HEADERS, audit_headers
from dont_track_me.modules.headers.protector import protect_headers


def test_tracking_headers_defined():
    """Core tracking headers should be defined."""
    assert "user-agent" in TRACKING_HEADERS
    assert "accept-language" in TRACKING_HEADERS
    assert "referer" in TRACKING_HEADERS


@pytest.mark.asyncio
async def test_audit_headers_returns_result():
    """Audit should return a valid AuditResult (needs network)."""
    result = await audit_headers()
    assert result.module_name == "headers"
    assert 0 <= result.score <= 100
    assert isinstance(result.findings, list)


@pytest.mark.asyncio
async def test_protect_headers_recommendations():
    """Protect should return browser recommendations."""
    result = await protect_headers(dry_run=True)
    assert result.module_name == "headers"
    assert len(result.actions_available) > 5
    # Should include Firefox and Chrome sections
    combined = " ".join(result.actions_available)
    assert "Firefox" in combined
    assert "Chrome" in combined
