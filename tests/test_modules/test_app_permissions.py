"""Tests for the macOS app permissions module."""

from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from dont_track_me.modules.app_permissions.auditor import audit_app_permissions
from dont_track_me.modules.app_permissions.module import AppPermissionsModule
from dont_track_me.modules.app_permissions.protector import protect_app_permissions

# auth_value constants
_ALLOWED = 2
_DENIED = 0


def _mock_tcc_db(rows: list[tuple[str, str, int]]):
    """Create a mock sqlite3 connection that returns the given rows."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = rows

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.__enter__ = lambda s: s
    mock_conn.__exit__ = MagicMock(return_value=False)

    return mock_conn


def _patch_for_macos(rows: list[tuple[str, str, int]]):
    """Return a context manager that patches platform + sqlite3 + path for macOS."""
    mock_conn = _mock_tcc_db(rows)

    class _PatchContext:
        def __enter__(self):
            self._p1 = patch(
                "dont_track_me.modules.app_permissions.auditor.platform.system",
                return_value="Darwin",
            )
            self._p2 = patch(
                "dont_track_me.modules.app_permissions.auditor.sqlite3.connect",
                return_value=mock_conn,
            )
            self._p3 = patch(
                "dont_track_me.modules.app_permissions.auditor._get_tcc_db_path",
            )
            self._p1.start()
            self._p2.start()
            mock_path = self._p3.start()
            mock_path.return_value.exists.return_value = True
            return self

        def __exit__(self, *args):
            self._p1.stop()
            self._p2.stop()
            self._p3.stop()

    return _PatchContext()


@pytest.mark.asyncio
async def test_audit_returns_result():
    """Audit runs and returns AuditResult with module_name='app_permissions'."""
    rows = [("kTCCServiceCamera", "com.example.app", _ALLOWED)]

    with _patch_for_macos(rows):
        result = await audit_app_permissions()

    assert result.module_name == "app_permissions"
    assert isinstance(result.findings, list)
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_audit_score_range():
    """Score is always clamped between 0 and 100."""
    rows = [("kTCCServiceAccessibility", f"com.app{i}", _ALLOWED) for i in range(20)]

    with _patch_for_macos(rows):
        result = await audit_app_permissions()

    assert 0 <= result.score <= 100


@pytest.mark.asyncio
async def test_non_macos_returns_gracefully():
    """On non-macOS platforms, return score=100 with an INFO finding."""
    with patch(
        "dont_track_me.modules.app_permissions.auditor.platform.system",
        return_value="Linux",
    ):
        result = await audit_app_permissions()

    assert result.score == 100
    assert len(result.findings) == 1
    assert result.findings[0].threat_level == "info"
    assert "macOS" in result.findings[0].title


@pytest.mark.asyncio
async def test_accessibility_detection():
    """App with Accessibility access is flagged as CRITICAL."""
    rows = [("kTCCServiceAccessibility", "com.sketchy.keylogger", _ALLOWED)]

    with _patch_for_macos(rows):
        result = await audit_app_permissions()

    accessibility_findings = [f for f in result.findings if "Accessibility" in f.title]
    assert len(accessibility_findings) >= 1
    assert accessibility_findings[0].threat_level == "critical"
    assert result.score < 100


@pytest.mark.asyncio
async def test_full_disk_access_detection():
    """App with Full Disk Access is flagged as CRITICAL."""
    rows = [("kTCCServiceSystemPolicyAllFiles", "com.example.fda", _ALLOWED)]

    with _patch_for_macos(rows):
        result = await audit_app_permissions()

    fda_findings = [f for f in result.findings if "Full Disk Access" in f.title]
    assert len(fda_findings) >= 1
    assert fda_findings[0].threat_level == "critical"
    assert result.score < 100


@pytest.mark.asyncio
async def test_camera_mic_combo_detection():
    """App with both Camera and Microphone is flagged as HIGH."""
    rows = [
        ("kTCCServiceCamera", "com.zoom.us", _ALLOWED),
        ("kTCCServiceMicrophone", "com.zoom.us", _ALLOWED),
    ]

    with _patch_for_macos(rows):
        result = await audit_app_permissions()

    combo_findings = [f for f in result.findings if "Camera + Microphone" in f.title]
    assert len(combo_findings) == 1
    assert combo_findings[0].threat_level == "high"
    assert "com.zoom.us" in combo_findings[0].description


@pytest.mark.asyncio
async def test_screen_recording_detection():
    """App with Screen Recording access is flagged as HIGH."""
    rows = [("kTCCServiceScreenCapture", "com.example.recorder", _ALLOWED)]

    with _patch_for_macos(rows):
        result = await audit_app_permissions()

    screen_findings = [f for f in result.findings if "Screen Recording" in f.title]
    assert len(screen_findings) >= 1
    assert screen_findings[0].threat_level == "high"


@pytest.mark.asyncio
async def test_clean_system_scores_high():
    """A system with no granted permissions scores high."""
    with _patch_for_macos([]):
        result = await audit_app_permissions()

    assert result.score >= 90
    assert result.raw_data["total_grants"] == 0


@pytest.mark.asyncio
async def test_denied_permissions_not_flagged():
    """Denied permissions (auth_value=0) should not generate risk findings."""
    rows = [
        ("kTCCServiceAccessibility", "com.safe.app", _DENIED),
        ("kTCCServiceCamera", "com.safe.app", _DENIED),
        ("kTCCServiceMicrophone", "com.safe.app", _DENIED),
    ]

    with _patch_for_macos(rows):
        result = await audit_app_permissions()

    # Only the summary finding should exist, no risk findings
    risk_findings = [f for f in result.findings if f.threat_level != "info"]
    assert len(risk_findings) == 0
    assert result.score >= 90


@pytest.mark.asyncio
async def test_over_permissioned_app_detection():
    """App with 3+ high-risk permissions is flagged."""
    rows = [
        ("kTCCServiceCamera", "com.spyware.app", _ALLOWED),
        ("kTCCServiceMicrophone", "com.spyware.app", _ALLOWED),
        ("kTCCServiceAccessibility", "com.spyware.app", _ALLOWED),
        ("kTCCServiceScreenCapture", "com.spyware.app", _ALLOWED),
    ]

    with _patch_for_macos(rows):
        result = await audit_app_permissions()

    over_findings = [f for f in result.findings if "Over-permissioned" in f.title]
    assert len(over_findings) >= 1
    assert over_findings[0].threat_level == "high"
    assert "com.spyware.app" in over_findings[0].title


@pytest.mark.asyncio
async def test_protect_dry_run():
    """Protect with dry_run=True returns no actions_taken."""
    with (
        patch(
            "dont_track_me.modules.app_permissions.protector.platform.system",
            return_value="Darwin",
        ),
        _patch_for_macos([("kTCCServiceCamera", "com.example.app", _ALLOWED)]),
    ):
        result = await protect_app_permissions(dry_run=True)

    assert result.module_name == "app_permissions"
    assert result.dry_run is True
    assert len(result.actions_taken) == 0
    assert len(result.actions_available) > 0


def test_module_attributes():
    """Module has correct name, display_name, and description."""
    module = AppPermissionsModule()
    assert module.name == "app_permissions"
    assert module.display_name == "macOS App Permission Audit"
    assert "TCC" in module.description or "permission" in module.description.lower()


def test_module_educational_content():
    """Educational content mentions TCC and is substantial."""
    module = AppPermissionsModule()
    content = module.get_educational_content()
    assert "TCC" in content
    assert len(content) > 500


@pytest.mark.asyncio
async def test_tcc_unreadable():
    """When TCC database cannot be read, return a helpful finding."""
    with (
        patch(
            "dont_track_me.modules.app_permissions.auditor.platform.system",
            return_value="Darwin",
        ),
        patch(
            "dont_track_me.modules.app_permissions.auditor._get_tcc_db_path",
        ) as mock_path,
        patch(
            "dont_track_me.modules.app_permissions.auditor._read_tcc_db",
            side_effect=sqlite3.OperationalError("unable to open database"),
        ),
    ):
        mock_path.return_value.exists.return_value = True
        result = await audit_app_permissions()

    assert result.score == 50
    permission_findings = [f for f in result.findings if "Cannot read" in f.title]
    assert len(permission_findings) == 1
    assert permission_findings[0].threat_level == "medium"
