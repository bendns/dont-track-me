"""Email tracking pixel removal — strip trackers from .eml files."""

from __future__ import annotations

import email
import email.errors
import itertools
import os
import re
import tempfile
from email.generator import BytesGenerator
from email.message import Message
from io import BytesIO
from pathlib import Path
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.email.auditor import (
    MAX_FILE_SIZE,
    MAX_FILES,
    _classify_image,
    _extract_images_from_html,
    _get_html_parts,
)

# Pattern to match <img> tags with remote src (captures the full URL)
_IMG_TAG_RE = re.compile(
    r"<img\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]+)[\"']?[^>]*/?>",
    re.IGNORECASE,
)


def _strip_tracking_images(html: str, tracker_urls: set[str]) -> tuple[str, list[str]]:
    """Remove tracking pixel <img> tags from HTML.

    Uses a pre-computed set of tracker URLs (from the HTMLParser-based classifier)
    to ensure audit and protect agree on what to remove.

    Returns (cleaned_html, list_of_removed_urls).
    """
    removed: list[str] = []

    def replacer(match: re.Match[str]) -> str:
        url = match.group(1)
        if url in tracker_urls:
            removed.append(url)
            return ""
        return match.group(0)

    cleaned = _IMG_TAG_RE.sub(replacer, html)
    return cleaned, removed


def _rewrite_eml(eml_path: Path, msg: Message) -> None:
    """Write a modified email message back to disk (atomic via temp file)."""
    buf = BytesIO()
    generator = BytesGenerator(buf)
    generator.flatten(msg)
    data = buf.getvalue()

    # Write to a temp file in the same directory, then atomically replace
    fd, tmp_path = tempfile.mkstemp(dir=eml_path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, eml_path)
    except BaseException:
        Path(tmp_path).unlink(missing_ok=True)
        raise


async def protect_email(
    dry_run: bool = True,
    path: str = ".",
    **kwargs: Any,
) -> ProtectionResult:
    """Strip tracking pixels from .eml files."""
    actions_available: list[str] = []
    actions_taken: list[str] = []
    target = Path(path)

    # Collect .eml files
    if target.is_file() and target.suffix == ".eml":
        eml_files = [target]
    elif target.is_dir():
        eml_files = list(itertools.islice(target.rglob("*.eml"), MAX_FILES))
    else:
        actions_available.append(f"Invalid path: {path}")
        return ProtectionResult(
            module_name="email",
            dry_run=dry_run,
            actions_taken=actions_taken,
            actions_available=actions_available,
        )

    for eml_path in eml_files:
        if not eml_path.is_file() or eml_path.is_symlink():
            continue

        try:
            if eml_path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue

        try:
            raw = eml_path.read_bytes()
            msg = email.message_from_bytes(raw)
        except (OSError, email.errors.MessageError):
            continue

        html_parts = _get_html_parts(msg)
        if not html_parts:
            continue

        # Detect trackers using the same HTMLParser as the auditor
        tracker_urls: set[str] = set()
        for html_content in html_parts:
            images = _extract_images_from_html(html_content)
            for img in images:
                if _classify_image(img) is not None:
                    tracker_urls.add(img.src)

        if not tracker_urls:
            continue

        for url in sorted(tracker_urls):
            actions_available.append(f"Remove tracking pixel from {eml_path.name}: {url}")

        if not dry_run:
            # Rewrite HTML parts with trackers stripped
            modified = False
            for part in msg.walk():
                if part.get_content_type() != "text/html":
                    continue

                payload = part.get_payload(decode=True)
                if not isinstance(payload, bytes):
                    continue

                charset = part.get_content_charset() or "utf-8"
                try:
                    html_str = payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    html_str = payload.decode("utf-8", errors="replace")

                cleaned, removed = _strip_tracking_images(html_str, tracker_urls)
                if removed:
                    part.set_payload(cleaned, charset=charset)
                    modified = True
                    for url in removed:
                        actions_taken.append(f"Stripped tracking pixel from {eml_path.name}: {url}")

            if modified:
                _rewrite_eml(eml_path, msg)

    # General recommendations
    actions_available.extend(
        [
            "Disable remote image loading in your email client "
            "(Thunderbird: Settings → Privacy; Apple Mail: Settings → Privacy → "
            "Protect Mail Activity; Gmail: Settings → Images → Ask before displaying)",
            "Use a privacy-respecting email provider (ProtonMail, Tutanota, Tuta)",
            "Use a browser extension like PixelBlock (Gmail) or Ugly Email to detect trackers",
        ]
    )

    return ProtectionResult(
        module_name="email",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
