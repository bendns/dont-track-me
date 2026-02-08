"""Email tracking pixel detection — scan .eml files for hidden trackers."""

from __future__ import annotations

import email
import email.errors
import itertools
import re
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.modules.email.trackers import is_tracker_url

MAX_FILES = 10_000
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


class _ImageInfo:
    """Metadata about an <img> tag found in HTML."""

    def __init__(self, src: str, width: int | None, height: int | None, hidden: bool) -> None:
        self.src = src
        self.width = width
        self.height = height
        self.hidden = hidden

    @property
    def is_tiny(self) -> bool:
        """Check if image dimensions suggest a tracking pixel (1x1 or 0x0)."""
        if self.width is not None and self.width <= 1:
            return True
        return bool(self.height is not None and self.height <= 1)


class _ImageExtractor(HTMLParser):
    """Extract <img> tags from HTML content."""

    def __init__(self) -> None:
        super().__init__()
        self.images: list[_ImageInfo] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "img":
            return

        attr_dict: dict[str, str] = {}
        for name, value in attrs:
            if value is not None:
                attr_dict[name.lower()] = value

        src = attr_dict.get("src", "")
        if not src or not src.startswith(("http://", "https://")):
            return

        width = _parse_dimension(attr_dict.get("width"))
        height = _parse_dimension(attr_dict.get("height"))

        # Check for hidden via style attribute
        style = attr_dict.get("style", "")
        hidden = _is_hidden_style(style)

        # Check dimensions in style if not in attributes
        if width is None:
            width = _parse_style_dimension(style, "width")
        if height is None:
            height = _parse_style_dimension(style, "height")

        self.images.append(_ImageInfo(src=src, width=width, height=height, hidden=hidden))


def _parse_dimension(value: str | None) -> int | None:
    """Parse a dimension attribute like '1' or '1px' to an integer."""
    if value is None:
        return None
    # Strip 'px' suffix and whitespace
    cleaned = value.strip().removesuffix("px").strip()
    try:
        return int(cleaned)
    except ValueError:
        return None


_STYLE_WIDTH_RE = re.compile(r"(?:^|;)\s*width\s*:\s*(\d+)\s*px", re.IGNORECASE)
_STYLE_HEIGHT_RE = re.compile(r"(?:^|;)\s*height\s*:\s*(\d+)\s*px", re.IGNORECASE)

_STYLE_DIM_PATTERNS: dict[str, re.Pattern[str]] = {
    "width": _STYLE_WIDTH_RE,
    "height": _STYLE_HEIGHT_RE,
}


def _parse_style_dimension(style: str, prop: str) -> int | None:
    """Extract a dimension from an inline style string."""
    pattern = _STYLE_DIM_PATTERNS.get(prop)
    if pattern is None:
        return None
    match = pattern.search(style)
    if match:
        return int(match.group(1))
    return None


def _is_hidden_style(style: str) -> bool:
    """Check if a style attribute hides the element."""
    style_lower = style.lower()
    return "display:none" in style_lower.replace(" ", "") or (
        "visibility:hidden" in style_lower.replace(" ", "")
    )


def _extract_images_from_html(html: str) -> list[_ImageInfo]:
    """Parse HTML and extract all <img> tags with remote src."""
    parser = _ImageExtractor()
    parser.feed(html)
    return parser.images


def _get_html_parts(msg: Message) -> list[str]:
    """Extract all text/html parts from an email message."""
    parts: list[str] = []
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/html":
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"
                try:
                    parts.append(payload.decode(charset, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    parts.append(payload.decode("utf-8", errors="replace"))
    return parts


def _classify_image(img: _ImageInfo) -> tuple[ThreatLevel, str] | None:
    """Classify an image as a tracking pixel and return (threat_level, reason) or None."""
    is_tracker, reason = is_tracker_url(img.src)

    if is_tracker:
        return ThreatLevel.HIGH, f"Known tracking pixel ({reason})"

    if img.is_tiny:
        return ThreatLevel.MEDIUM, "Suspicious 1x1 pixel image"

    if img.hidden:
        return ThreatLevel.MEDIUM, "Hidden image (display:none or visibility:hidden)"

    return None


async def audit_email(path: str = ".", **kwargs: Any) -> AuditResult:
    """Scan .eml files for email tracking pixels."""
    findings: list[Finding] = []
    score = 100
    target = Path(path)

    trackers_found: list[dict[str, str]] = []
    files_scanned = 0
    files_with_trackers = 0

    # Collect .eml files
    if target.is_file() and target.suffix == ".eml":
        eml_files = [target]
    elif target.is_dir():
        eml_files = list(itertools.islice(target.rglob("*.eml"), MAX_FILES))
    else:
        findings.append(
            Finding(
                title="Invalid path for email scan",
                description=f"Path '{path}' is not a file or directory.",
                threat_level=ThreatLevel.MEDIUM,
                remediation="Provide a valid path to an .eml file or directory.",
            )
        )
        return AuditResult(
            module_name="email",
            score=50,
            findings=findings,
            raw_data={},
        )

    if not eml_files:
        findings.append(
            Finding(
                title="No .eml files found",
                description=f"No email files found in '{path}'.",
                threat_level=ThreatLevel.INFO,
                remediation="Export emails as .eml files from your mail client to scan them.",
            )
        )
        return AuditResult(
            module_name="email",
            score=100,
            findings=findings,
            raw_data={"files_scanned": 0, "files_with_trackers": 0, "trackers": []},
        )

    for eml_path in eml_files:
        if not eml_path.is_file() or eml_path.is_symlink():
            continue

        try:
            if eml_path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        files_scanned += 1
        file_has_tracker = False

        try:
            raw = eml_path.read_bytes()
            msg = email.message_from_bytes(raw)
        except (OSError, email.errors.MessageError):
            continue

        html_parts = _get_html_parts(msg)
        for html in html_parts:
            images = _extract_images_from_html(html)
            for img in images:
                classification = _classify_image(img)
                if classification is None:
                    continue

                threat_level, reason = classification
                file_has_tracker = True

                trackers_found.append(
                    {
                        "file": str(eml_path.name),
                        "src": img.src,
                        "reason": reason,
                    }
                )

                findings.append(
                    Finding(
                        title=f"Tracking pixel in {eml_path.name}",
                        description=(
                            f"{reason}. Source: {img.src}. "
                            "This image reports back to the sender when you open the email, "
                            "revealing your IP address, location, and the time you read it."
                        ),
                        threat_level=threat_level,
                        remediation=(
                            "Disable remote image loading in your email client. "
                            "Use 'dtm protect email --apply' to strip tracking pixels."
                        ),
                    )
                )

        if file_has_tracker:
            files_with_trackers += 1
            # Deduct score per file (not per tracker, to avoid over-penalizing)
            has_known = any(
                t["file"] == eml_path.name and "Known" in t["reason"] for t in trackers_found
            )
            score -= 15 if has_known else 10

    score = max(0, min(100, score))

    return AuditResult(
        module_name="email",
        score=score,
        findings=findings,
        raw_data={
            "files_scanned": files_scanned,
            "files_with_trackers": files_with_trackers,
            "trackers": trackers_found,
        },
    )
