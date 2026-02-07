"""Shared test fixtures."""

import pytest


@pytest.fixture
def tmp_image(tmp_path):
    """Create a temporary JPEG image with fake EXIF-like data."""
    try:
        from PIL import Image

        img = Image.new("RGB", (100, 100), color="red")
        path = tmp_path / "test.jpg"
        img.save(path)
        return path
    except ImportError:
        pytest.skip("Pillow not installed")


@pytest.fixture
def tmp_pdf(tmp_path):
    """Create a temporary PDF with metadata."""
    try:
        from pypdf import PdfWriter

        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        writer.add_metadata(
            {
                "/Author": "John Doe",
                "/Creator": "Secret Tool v1.0",
                "/Producer": "dont-track-me test",
            }
        )
        path = tmp_path / "test.pdf"
        with open(path, "wb") as f:
            writer.write(f)
        return path
    except ImportError:
        pytest.skip("pypdf not installed")
