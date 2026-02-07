"""Metadata protector — strip privacy-leaking metadata from files."""

from __future__ import annotations

import mimetypes
from pathlib import Path

from dont_track_me.core.base import ProtectionResult


def _strip_image_metadata(file_path: Path) -> str | None:
    """Strip EXIF data from an image. Returns action description or None."""
    try:
        from PIL import Image
    except ImportError:
        return None

    try:
        img = Image.open(file_path)
        if img._getexif() is None:
            return None

        # Create a clean copy without EXIF data
        data = list(img.getdata())
        clean = Image.new(img.mode, img.size)
        clean.putdata(data)
        clean.save(file_path)
        return f"Stripped EXIF data from {file_path.name}"
    except Exception as e:
        return f"Failed to strip {file_path.name}: {e}"


def _strip_pdf_metadata(file_path: Path) -> str | None:
    """Strip metadata from a PDF. Returns action description or None."""
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError:
        return None

    try:
        reader = PdfReader(str(file_path))
        if not reader.metadata:
            return None

        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        # Remove all metadata entries explicitly
        writer.add_metadata({key: "" for key in reader.metadata})

        with open(file_path, "wb") as f:
            writer.write(f)
        return f"Stripped metadata from {file_path.name}"
    except Exception as e:
        return f"Failed to strip {file_path.name}: {e}"


async def protect_metadata(
    dry_run: bool = True,
    path: str = ".",
    **kwargs,
) -> ProtectionResult:
    """Strip metadata from files in a directory."""
    actions_available: list[str] = []
    actions_taken: list[str] = []
    target = Path(path)

    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = list(target.rglob("*"))
    else:
        return ProtectionResult(
            module_name="metadata",
            dry_run=dry_run,
            actions_available=[f"Invalid path: {path}"],
        )

    for file_path in files:
        if not file_path.is_file():
            continue

        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type is None:
            continue

        if mime_type.startswith("image/"):
            action = f"Strip EXIF data from {file_path.name}"
            actions_available.append(action)
            if not dry_run:
                result = _strip_image_metadata(file_path)
                if result:
                    actions_taken.append(result)

        elif mime_type == "application/pdf":
            action = f"Strip metadata from {file_path.name}"
            actions_available.append(action)
            if not dry_run:
                result = _strip_pdf_metadata(file_path)
                if result:
                    actions_taken.append(result)

    return ProtectionResult(
        module_name="metadata",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
