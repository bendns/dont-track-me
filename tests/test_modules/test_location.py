"""Tests for the location data leakage audit module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dont_track_me.modules.location.auditor import audit_location
from dont_track_me.modules.location.module import LocationModule
from dont_track_me.modules.location.protector import protect_location

_AUTH_ALLOWED = 2


def _mock_tcc(rows: list[tuple[str,]]):
    """Create a mock sqlite3 connection returning given rows for each query."""
    mock_cursor = MagicMock()
    # Each call to execute + fetchall returns the next set of rows
    mock_cursor.fetchall.side_effect = [rows, [], []]  # location, camera, mic

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn


def _mock_httpx_response(timezone: str = "America/New_York") -> AsyncMock:
    """Create a mock httpx response with the given timezone."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "timezone": timezone,
        "country_name": "United States",
        "city": "New York",
    }
    mock_resp.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


# ---------------------------------------------------------------------------
# Audit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_returns_result():
    """Audit runs and returns AuditResult with module_name='location'."""
    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Linux",
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
    ):
        result = await audit_location()

    assert result.module_name == "location"
    assert isinstance(result.findings, list)


@pytest.mark.asyncio
async def test_audit_score_range():
    """Score is always clamped between 0 and 100."""
    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Linux",
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
    ):
        result = await audit_location()

    assert 0 <= result.score <= 100


@pytest.mark.asyncio
async def test_non_macos_wifi_skipped():
    """Wi-Fi phase is skipped on non-macOS platforms."""
    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Linux",
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
    ):
        result = await audit_location()

    # No Wi-Fi findings on Linux
    wifi_findings = [f for f in result.findings if "Wi-Fi" in f.title]
    assert len(wifi_findings) == 0


@pytest.mark.asyncio
async def test_large_wifi_history():
    """>20 remembered networks triggers a MEDIUM finding."""
    networks = [{"SSID": f"Network_{i}", "SecurityType": "WPA2"} for i in range(25)]

    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Darwin",
        ),
        patch(
            "dont_track_me.modules.location.auditor._read_wifi_plist",
            return_value=networks,
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_tcc_db_path",
        ) as mock_path,
    ):
        mock_path.return_value.exists.return_value = False
        result = await audit_location()

    large_findings = [f for f in result.findings if "Large Wi-Fi history" in f.title]
    assert len(large_findings) == 1
    assert large_findings[0].threat_level == "medium"
    assert result.score < 100


@pytest.mark.asyncio
async def test_revealing_ssids():
    """SSIDs matching hotel/airport patterns trigger a HIGH finding."""
    networks = [
        {"SSID": "Marriott_NYC_Guest", "SecurityType": "WPA2"},
        {"SSID": "HomeNetwork", "SecurityType": "WPA3"},
    ]

    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Darwin",
        ),
        patch(
            "dont_track_me.modules.location.auditor._read_wifi_plist",
            return_value=networks,
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_tcc_db_path",
        ) as mock_path,
    ):
        mock_path.return_value.exists.return_value = False
        result = await audit_location()

    revealing = [f for f in result.findings if "Location-revealing" in f.title]
    assert len(revealing) == 1
    assert revealing[0].threat_level == "high"


@pytest.mark.asyncio
async def test_open_network_detection():
    """Unsecured networks trigger a MEDIUM finding."""
    networks = [
        {"SSID": "CoffeeShop", "SecurityType": "None"},
        {"SSID": "OpenNet", "SecurityType": "Open"},
        {"SSID": "SecureHome", "SecurityType": "WPA2"},
    ]

    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Darwin",
        ),
        patch(
            "dont_track_me.modules.location.auditor._read_wifi_plist",
            return_value=networks,
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_tcc_db_path",
        ) as mock_path,
    ):
        mock_path.return_value.exists.return_value = False
        result = await audit_location()

    open_findings = [f for f in result.findings if "Open" in f.title]
    assert len(open_findings) == 1
    assert open_findings[0].threat_level == "medium"


@pytest.mark.asyncio
async def test_timezone_mismatch():
    """System timezone != IP timezone triggers a HIGH finding."""
    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Linux",
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(timezone="Europe/London"),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
    ):
        result = await audit_location()

    mismatch = [f for f in result.findings if "mismatch" in f.title.lower()]
    assert len(mismatch) == 1
    assert mismatch[0].threat_level == "high"
    assert result.score < 100


@pytest.mark.asyncio
async def test_timezone_match():
    """Same timezone region produces no mismatch finding."""
    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Linux",
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(timezone="America/Chicago"),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
    ):
        result = await audit_location()

    mismatch = [f for f in result.findings if "mismatch" in f.title.lower()]
    assert len(mismatch) == 0
    consistent = [f for f in result.findings if "consistent" in f.title.lower()]
    assert len(consistent) == 1


@pytest.mark.asyncio
async def test_timezone_api_failure():
    """httpx failure produces INFO finding, no score penalty."""
    mock_client = AsyncMock()
    mock_client.get.side_effect = httpx.ConnectError("connection refused")
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Linux",
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=mock_client,
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
    ):
        result = await audit_location()

    api_findings = [f for f in result.findings if "Could not check" in f.title]
    assert len(api_findings) == 1
    assert api_findings[0].threat_level == "info"
    assert result.score == 100  # no penalty


@pytest.mark.asyncio
async def test_many_location_apps():
    """>5 apps with location access triggers a MEDIUM finding."""
    location_rows = [(f"com.app{i}",) for i in range(8)]

    mock_cursor = MagicMock()
    mock_cursor.fetchall.side_effect = [
        location_rows,  # location query
        [],  # camera query
        [],  # microphone query
    ]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Darwin",
        ),
        patch(
            "dont_track_me.modules.location.auditor._read_wifi_plist",
            return_value=None,
        ),
        patch(
            "dont_track_me.modules.location.auditor._read_wifi_networksetup",
            return_value=None,
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_tcc_db_path",
        ) as mock_path,
        patch(
            "dont_track_me.modules.location.auditor.sqlite3.connect",
            return_value=mock_conn,
        ),
    ):
        mock_path.return_value.exists.return_value = True
        result = await audit_location()

    loc_findings = [f for f in result.findings if "Location access" in f.title]
    assert len(loc_findings) == 1
    assert loc_findings[0].threat_level == "medium"


@pytest.mark.asyncio
async def test_tracking_suite_detection():
    """App with Location + Camera + Mic is flagged as full tracking suite."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.side_effect = [
        [("com.spyware.app",)],  # location
        [("com.spyware.app",)],  # camera
        [("com.spyware.app",)],  # mic
    ]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Darwin",
        ),
        patch(
            "dont_track_me.modules.location.auditor._read_wifi_plist",
            return_value=None,
        ),
        patch(
            "dont_track_me.modules.location.auditor._read_wifi_networksetup",
            return_value=None,
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_tcc_db_path",
        ) as mock_path,
        patch(
            "dont_track_me.modules.location.auditor.sqlite3.connect",
            return_value=mock_conn,
        ),
    ):
        mock_path.return_value.exists.return_value = True
        result = await audit_location()

    suite_findings = [f for f in result.findings if "tracking suite" in f.title.lower()]
    assert len(suite_findings) == 1
    assert suite_findings[0].threat_level == "high"
    assert "com.spyware.app" in suite_findings[0].description


@pytest.mark.asyncio
async def test_protect_dry_run():
    """Protect with dry_run=True returns no actions_taken."""
    with (
        patch(
            "dont_track_me.modules.location.auditor.platform.system",
            return_value="Linux",
        ),
        patch(
            "dont_track_me.modules.location.protector.platform.system",
            return_value="Linux",
        ),
        patch(
            "dont_track_me.modules.location.auditor.httpx.AsyncClient",
            return_value=_mock_httpx_response(),
        ),
        patch(
            "dont_track_me.modules.location.auditor._get_system_timezone",
            return_value="America/New_York",
        ),
    ):
        result = await protect_location(dry_run=True)

    assert result.module_name == "location"
    assert result.dry_run is True
    assert len(result.actions_taken) == 0


def test_module_attributes():
    """Module has correct name, display_name, and description."""
    module = LocationModule()
    assert module.name == "location"
    assert module.display_name == "Location Data Leakage Audit"
    assert "location" in module.description.lower()


def test_module_educational_content():
    """Educational content mentions Wi-Fi and location, and is substantial."""
    module = LocationModule()
    content = module.get_educational_content()
    assert len(content) > 500
    assert "Wi-Fi" in content or "location" in content.lower()
