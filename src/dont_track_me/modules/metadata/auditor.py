"""Metadata auditor — scan files for privacy-leaking metadata."""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel


def _scan_image_metadata(file_path: Path) -> list[dict[str, Any]]:
    """Extract EXIF metadata from an image file."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return [{"error": "Pillow not installed"}]

    findings = []
    try:
        img = Image.open(file_path)
        exif_data = img._getexif()
        if exif_data:
            readable = {}
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                # Convert bytes to string for JSON serialization
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:
                        value = repr(value)
                readable[tag_name] = str(value)
            findings.append(
                {
                    "file": str(file_path),
                    "type": "exif",
                    "metadata": readable,
                }
            )
    except Exception:
        pass

    return findings


def _scan_pdf_metadata(file_path: Path) -> list[dict[str, Any]]:
    """Extract metadata from a PDF file."""
    try:
        from pypdf import PdfReader
    except ImportError:
        return [{"error": "pypdf not installed"}]

    findings = []
    try:
        reader = PdfReader(str(file_path))
        info = reader.metadata
        if info:
            meta = {}
            for key in info:
                value = info[key]
                if value:
                    meta[key] = str(value)
            if meta:
                findings.append(
                    {
                        "file": str(file_path),
                        "type": "pdf",
                        "metadata": meta,
                    }
                )
    except Exception:
        pass

    return findings


# Sensitive EXIF tags that reveal personal information
SENSITIVE_TAGS = {
    "GPSInfo",
    "GPSLatitude",
    "GPSLongitude",
    "GPSLatitudeRef",
    "GPSLongitudeRef",
    "Make",
    "Model",
    "Software",
    "DateTime",
    "DateTimeOriginal",
    "DateTimeDigitized",
    "Artist",
    "Copyright",
    "CameraOwnerName",
    "BodySerialNumber",
    "LensSerialNumber",
    "ImageUniqueID",
}

SENSITIVE_PDF_KEYS = {
    "/Author",
    "/Creator",
    "/Producer",
    "/CreationDate",
    "/ModDate",
    "/Title",
    "/Subject",
    "/Keywords",
}


async def audit_metadata(path: str = ".", **kwargs) -> AuditResult:
    """Scan files in a directory for privacy-leaking metadata."""
    findings: list[Finding] = []
    raw_data: list[dict[str, Any]] = []
    target = Path(path)
    files_scanned = 0
    files_with_metadata = 0

    if target.is_file():
        files_to_scan = [target]
    elif target.is_dir():
        files_to_scan = list(target.rglob("*"))
    else:
        return AuditResult(
            module_name="metadata",
            score=50,
            findings=[
                Finding(
                    title="Invalid path",
                    description=f"Path '{path}' does not exist.",
                    threat_level=ThreatLevel.INFO,
                    remediation="Provide a valid file or directory path.",
                )
            ],
            raw_data={},
        )

    for file_path in files_to_scan:
        if not file_path.is_file():
            continue

        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type is None:
            continue

        if mime_type.startswith("image/"):
            files_scanned += 1
            results = _scan_image_metadata(file_path)
            for result in results:
                if "error" in result:
                    continue
                raw_data.append(result)
                meta = result.get("metadata", {})
                # Check for GPS data
                if any(
                    tag in meta for tag in ("GPSInfo", "GPSLatitude", "GPSLongitude")
                ):
                    files_with_metadata += 1
                    findings.append(
                        Finding(
                            title=f"GPS location in {file_path.name}",
                            description=(
                                f"Image '{file_path}' contains GPS coordinates. "
                                "This reveals the exact location where the photo was taken."
                            ),
                            threat_level=ThreatLevel.CRITICAL,
                            remediation="Strip EXIF data before sharing: dtm protect metadata --apply --path .",
                        )
                    )
                elif any(tag in meta for tag in SENSITIVE_TAGS):
                    files_with_metadata += 1
                    leaked_tags = [t for t in SENSITIVE_TAGS if t in meta]
                    findings.append(
                        Finding(
                            title=f"Device metadata in {file_path.name}",
                            description=(
                                f"Image '{file_path}' contains identifying metadata: "
                                f"{', '.join(leaked_tags)}. This can identify your camera, "
                                "software, and when the photo was taken."
                            ),
                            threat_level=ThreatLevel.HIGH,
                            remediation="Strip EXIF data before sharing: dtm protect metadata --apply --path .",
                        )
                    )

        elif mime_type == "application/pdf":
            files_scanned += 1
            results = _scan_pdf_metadata(file_path)
            for result in results:
                if "error" in result:
                    continue
                raw_data.append(result)
                meta = result.get("metadata", {})
                leaked = [k for k in SENSITIVE_PDF_KEYS if k in meta]
                if leaked:
                    files_with_metadata += 1
                    findings.append(
                        Finding(
                            title=f"Author/tool metadata in {file_path.name}",
                            description=(
                                f"PDF '{file_path}' contains: {', '.join(leaked)}. "
                                "This reveals who created the document and what software was used."
                            ),
                            threat_level=ThreatLevel.MEDIUM,
                            remediation="Strip PDF metadata: dtm protect metadata --apply --path .",
                        )
                    )

    # Score: more files with metadata = lower score
    if files_scanned == 0:
        score = 100
        findings.append(
            Finding(
                title="No scannable files found",
                description=f"No image or PDF files found in '{path}'.",
                threat_level=ThreatLevel.INFO,
                remediation="Point to a directory with images or PDFs to scan.",
            )
        )
    elif files_with_metadata == 0:
        score = 100
    else:
        ratio = files_with_metadata / files_scanned
        score = max(0, int(100 * (1 - ratio)))

    return AuditResult(
        module_name="metadata",
        score=score,
        findings=findings,
        raw_data={
            "files_scanned": files_scanned,
            "files_with_metadata": files_with_metadata,
            "details": raw_data,
        },
    )
