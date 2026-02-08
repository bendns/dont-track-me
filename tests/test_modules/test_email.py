"""Tests for the email tracking pixel detection module."""

from __future__ import annotations

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import pytest

from dont_track_me.modules.email.auditor import (
    _classify_image,
    _extract_images_from_html,
    _ImageInfo,
    audit_email,
)
from dont_track_me.modules.email.protector import protect_email
from dont_track_me.modules.email.trackers import is_tracker_url

# --- Fixtures ---


def _make_eml(html_body: str, subject: str = "Test") -> bytes:
    """Create a multipart .eml file with HTML body."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg.attach(MIMEText("Plain text version", "plain"))
    msg.attach(MIMEText(html_body, "html"))
    return msg.as_bytes()


@pytest.fixture()
def eml_with_tracker(tmp_path: Path) -> Path:
    """Create a .eml file containing a known tracking pixel."""
    html = (
        "<html><body>"
        "<p>Hello</p>"
        '<img src="https://track.hubspot.com/open/abc123" width="1" height="1">'
        "</body></html>"
    )
    eml_path = tmp_path / "tracked.eml"
    eml_path.write_bytes(_make_eml(html, subject="Tracked Email"))
    return eml_path


@pytest.fixture()
def eml_clean(tmp_path: Path) -> Path:
    """Create a .eml file with no tracking pixels."""
    html = (
        "<html><body>"
        "<p>Hello, this is a normal email.</p>"
        '<img src="https://example.com/logo.png" width="200" height="50">'
        "</body></html>"
    )
    eml_path = tmp_path / "clean.eml"
    eml_path.write_bytes(_make_eml(html, subject="Clean Email"))
    return eml_path


@pytest.fixture()
def eml_with_tiny_pixel(tmp_path: Path) -> Path:
    """Create a .eml file with a 1x1 pixel from an unknown domain."""
    html = (
        "<html><body>"
        "<p>Newsletter</p>"
        '<img src="https://unknown-service.com/img/notify.gif" width="1" height="1">'
        "</body></html>"
    )
    eml_path = tmp_path / "tiny.eml"
    eml_path.write_bytes(_make_eml(html, subject="Tiny Pixel"))
    return eml_path


@pytest.fixture()
def eml_with_hidden_img(tmp_path: Path) -> Path:
    """Create a .eml file with a hidden image."""
    html = (
        "<html><body>"
        "<p>Update</p>"
        '<img src="https://unknown-analytics.com/event.png" style="display:none">'
        "</body></html>"
    )
    eml_path = tmp_path / "hidden.eml"
    eml_path.write_bytes(_make_eml(html, subject="Hidden Image"))
    return eml_path


# --- Tracker URL detection ---


def test_is_tracker_url_known_domain():
    """Should identify known tracker domains."""
    is_tracker, reason = is_tracker_url("https://track.hubspot.com/open/abc123")
    assert is_tracker is True
    assert "hubspot" in reason


def test_is_tracker_url_mailchimp():
    """Should identify Mailchimp tracking URLs."""
    is_tracker, _ = is_tracker_url("https://open.list-manage.com/track/open.php?u=abc")
    assert is_tracker is True


def test_is_tracker_url_path_pattern():
    """Should detect suspicious URL path patterns."""
    is_tracker, reason = is_tracker_url("https://unknown.com/pixel/track?id=123")
    assert is_tracker is True
    assert "path" in reason


def test_is_tracker_url_clean():
    """Should not flag normal image URLs."""
    is_tracker, _ = is_tracker_url("https://example.com/images/logo.png")
    assert is_tracker is False


def test_is_tracker_url_subdomain_match():
    """Should match subdomains of known tracker domains."""
    is_tracker, _ = is_tracker_url("https://email.sendgrid.net/wf/open?id=abc")
    assert is_tracker is True


# --- HTML image extraction ---


def test_extract_images_basic():
    """Should extract img tags with remote src."""
    html = '<img src="https://example.com/img.png" width="100" height="50">'
    images = _extract_images_from_html(html)
    assert len(images) == 1
    assert images[0].src == "https://example.com/img.png"
    assert images[0].width == 100
    assert images[0].height == 50


def test_extract_images_ignores_local():
    """Should ignore images without http(s) src."""
    html = '<img src="cid:logo@email"> <img src="/local/img.png">'
    images = _extract_images_from_html(html)
    assert len(images) == 0


def test_extract_images_1x1():
    """Should detect 1x1 pixel dimensions."""
    html = '<img src="https://tracker.com/pixel.gif" width="1" height="1">'
    images = _extract_images_from_html(html)
    assert len(images) == 1
    assert images[0].is_tiny is True


def test_extract_images_style_dimensions():
    """Should parse dimensions from inline style."""
    html = '<img src="https://tracker.com/p.gif" style="width:1px;height:1px">'
    images = _extract_images_from_html(html)
    assert len(images) == 1
    assert images[0].is_tiny is True


def test_extract_images_hidden():
    """Should detect display:none images."""
    html = '<img src="https://tracker.com/p.gif" style="display:none">'
    images = _extract_images_from_html(html)
    assert len(images) == 1
    assert images[0].hidden is True


def test_extract_images_visibility_hidden():
    """Should detect visibility:hidden images."""
    html = '<img src="https://tracker.com/p.gif" style="visibility: hidden">'
    images = _extract_images_from_html(html)
    assert len(images) == 1
    assert images[0].hidden is True


# --- Image classification ---


def test_classify_known_tracker():
    """Known tracker domain should be classified as HIGH."""
    img = _ImageInfo(src="https://track.hubspot.com/abc", width=1, height=1, hidden=False)
    result = _classify_image(img)
    assert result is not None
    assert result[0].value == "high"


def test_classify_tiny_unknown():
    """1x1 pixel from unknown domain should be MEDIUM."""
    img = _ImageInfo(src="https://unknown.com/img.gif", width=1, height=1, hidden=False)
    result = _classify_image(img)
    assert result is not None
    assert result[0].value == "medium"


def test_classify_hidden_unknown():
    """Hidden image from unknown domain should be MEDIUM."""
    img = _ImageInfo(src="https://unknown.com/img.gif", width=None, height=None, hidden=True)
    result = _classify_image(img)
    assert result is not None
    assert result[0].value == "medium"


def test_classify_normal_image():
    """Normal visible image from unknown domain should not be classified."""
    img = _ImageInfo(src="https://example.com/logo.png", width=200, height=50, hidden=False)
    result = _classify_image(img)
    assert result is None


# --- Audit function ---


@pytest.mark.asyncio
async def test_audit_empty_dir(tmp_path: Path):
    """Audit on empty directory should return score 100."""
    result = await audit_email(path=str(tmp_path))
    assert result.module_name == "email"
    assert result.score == 100
    assert result.raw_data["files_scanned"] == 0


@pytest.mark.asyncio
async def test_audit_with_tracker(eml_with_tracker: Path):
    """Should detect tracking pixel in .eml file."""
    result = await audit_email(path=str(eml_with_tracker.parent))
    assert result.module_name == "email"
    assert result.score < 100
    assert result.raw_data["files_scanned"] == 1
    assert result.raw_data["files_with_trackers"] == 1
    assert any("Tracking pixel" in f.title for f in result.findings)


@pytest.mark.asyncio
async def test_audit_clean_email(eml_clean: Path):
    """Should not flag clean emails."""
    result = await audit_email(path=str(eml_clean.parent))
    assert result.module_name == "email"
    assert result.score == 100
    assert result.raw_data["files_with_trackers"] == 0


@pytest.mark.asyncio
async def test_audit_tiny_pixel(eml_with_tiny_pixel: Path):
    """Should detect 1x1 pixels from unknown domains."""
    result = await audit_email(path=str(eml_with_tiny_pixel.parent))
    assert result.score < 100
    assert result.raw_data["files_with_trackers"] == 1
    assert any("1x1" in f.description for f in result.findings)


@pytest.mark.asyncio
async def test_audit_hidden_image(eml_with_hidden_img: Path):
    """Should detect hidden images."""
    result = await audit_email(path=str(eml_with_hidden_img.parent))
    assert result.score < 100
    assert any("Hidden" in f.description for f in result.findings)


@pytest.mark.asyncio
async def test_audit_single_file(eml_with_tracker: Path):
    """Should work when given a single .eml file path."""
    result = await audit_email(path=str(eml_with_tracker))
    assert result.raw_data["files_scanned"] == 1
    assert result.raw_data["files_with_trackers"] == 1


@pytest.mark.asyncio
async def test_audit_ignores_non_eml(tmp_path: Path):
    """Should ignore non-.eml files."""
    (tmp_path / "notes.txt").write_text("just a text file")
    (tmp_path / "data.html").write_text("<img src='https://track.hubspot.com/x'>")
    result = await audit_email(path=str(tmp_path))
    assert result.raw_data["files_scanned"] == 0


# --- Protector function ---


@pytest.mark.asyncio
async def test_protect_dry_run(eml_with_tracker: Path):
    """Dry-run should list actions but not modify files."""
    original = eml_with_tracker.read_bytes()
    result = await protect_email(dry_run=True, path=str(eml_with_tracker.parent))
    assert result.module_name == "email"
    assert result.dry_run is True
    assert len(result.actions_available) >= 1
    assert len(result.actions_taken) == 0
    # File should be unchanged
    assert eml_with_tracker.read_bytes() == original


@pytest.mark.asyncio
async def test_protect_apply(eml_with_tracker: Path):
    """Apply should strip tracking pixels from .eml files."""
    result = await protect_email(dry_run=False, path=str(eml_with_tracker.parent))
    assert result.dry_run is False
    assert len(result.actions_taken) >= 1
    assert any("hubspot" in a.lower() for a in result.actions_taken)

    # Verify the file was rewritten without the tracker
    rewritten = eml_with_tracker.read_bytes()
    assert b"track.hubspot.com" not in rewritten


@pytest.mark.asyncio
async def test_protect_clean_email(eml_clean: Path):
    """Protect on clean email should not modify anything."""
    original = eml_clean.read_bytes()
    result = await protect_email(dry_run=False, path=str(eml_clean.parent))
    assert len(result.actions_taken) == 0
    assert eml_clean.read_bytes() == original


@pytest.mark.asyncio
async def test_protect_recommendations():
    """Should always include general recommendations."""
    result = await protect_email(dry_run=True, path="/nonexistent")
    all_actions = " ".join(result.actions_available)
    assert "remote image" in all_actions.lower() or "Invalid" in all_actions
