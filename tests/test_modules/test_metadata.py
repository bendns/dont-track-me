"""Tests for the metadata module."""

import pytest

from dont_track_me.modules.metadata.auditor import audit_metadata
from dont_track_me.modules.metadata.protector import protect_metadata


@pytest.mark.asyncio
async def test_audit_empty_dir(tmp_path):
    """Audit on empty directory should score 100."""
    result = await audit_metadata(path=str(tmp_path))
    assert result.module_name == "metadata"
    assert result.score == 100


@pytest.mark.asyncio
async def test_audit_image(tmp_image):
    """Audit should detect image files."""
    result = await audit_metadata(path=str(tmp_image.parent))
    assert result.module_name == "metadata"
    assert result.raw_data["files_scanned"] >= 1


@pytest.mark.asyncio
async def test_audit_pdf_with_metadata(tmp_pdf):
    """Audit should detect PDF metadata."""
    result = await audit_metadata(path=str(tmp_pdf.parent))
    assert result.module_name == "metadata"
    assert result.raw_data["files_scanned"] >= 1
    # Our test PDF has author metadata
    assert result.raw_data["files_with_metadata"] >= 1
    assert any(
        "Author" in f.title or "metadata" in f.title.lower() for f in result.findings
    )


@pytest.mark.asyncio
async def test_protect_dry_run(tmp_pdf):
    """Dry-run should list actions but not modify files."""
    result = await protect_metadata(dry_run=True, path=str(tmp_pdf.parent))
    assert result.dry_run is True
    assert len(result.actions_available) >= 1
    assert len(result.actions_taken) == 0


@pytest.mark.asyncio
async def test_protect_apply_pdf(tmp_pdf):
    """Apply should strip metadata from PDF."""
    result = await protect_metadata(dry_run=False, path=str(tmp_pdf.parent))
    assert result.dry_run is False
    assert len(result.actions_taken) >= 1

    # Verify metadata was stripped
    audit_result = await audit_metadata(path=str(tmp_pdf.parent))
    assert audit_result.raw_data["files_with_metadata"] == 0


@pytest.mark.asyncio
async def test_audit_invalid_path():
    """Audit on nonexistent path should handle gracefully."""
    result = await audit_metadata(path="/nonexistent/path")
    assert result.module_name == "metadata"
    assert result.score == 50
