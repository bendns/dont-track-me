"""Tests for the DNS module."""

import pytest

from dont_track_me.modules.dns.auditor import (
    PRIVATE_DNS,
    TRACKING_DNS,
    _get_system_dns_servers,
    audit_dns,
)


def test_get_system_dns_servers():
    """Should return a list of strings (may be empty in CI)."""
    servers = _get_system_dns_servers()
    assert isinstance(servers, list)
    for s in servers:
        assert isinstance(s, str)


@pytest.mark.asyncio
async def test_audit_dns_returns_result():
    """Audit should always return a valid AuditResult."""
    result = await audit_dns()
    assert result.module_name == "dns"
    assert 0 <= result.score <= 100
    assert isinstance(result.findings, list)
    assert "servers" in result.raw_data


def test_tracking_dns_known():
    """Verify our tracking DNS list includes major offenders."""
    assert "8.8.8.8" in TRACKING_DNS
    assert "208.67.222.222" in TRACKING_DNS


def test_private_dns_known():
    """Verify our private DNS list includes recommended providers."""
    assert "9.9.9.9" in PRIVATE_DNS
    assert "1.1.1.1" in PRIVATE_DNS
    assert "194.242.2.2" in PRIVATE_DNS
