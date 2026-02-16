# Metadata Leakage — Hidden Data in Your Files

## What is file metadata?

Every photo, PDF, and document contains hidden metadata — information embedded in the file that you don't see when viewing it. This metadata can reveal:

- **GPS coordinates** — the exact location where a photo was taken
- **Camera model** — which device you own (serial number included)
- **Software** — what tools you use (Photoshop, LibreOffice, etc.)
- **Author name** — your real name from your OS/software settings
- **Timestamps** — exactly when files were created or modified

## How metadata is used to track you

### Photo EXIF data
When you upload a photo to social media or share it via email, the EXIF data often travels with it. While major platforms like Twitter/X strip EXIF on upload, many forums, messaging apps, and websites do not. A single photo with GPS data can reveal your home address, workplace, or daily routine.

### Document metadata
PDFs and Office documents contain author names, organization names, revision history, and software versions. Leaked documents have been traced back to individuals through this metadata — including the case of Reality Winner, whose identity was partially confirmed through printer tracking dots and document metadata.

### Forensic profiling
Intelligence agencies and data brokers aggregate metadata across files to build profiles. Your camera's serial number, your preferred software, your timezone from timestamps — all create a unique fingerprint.

## Why a VPN doesn't help

A VPN hides your IP address, but metadata is embedded **inside the files themselves**. Whether you upload a photo through a VPN, Tor, or a public Wi-Fi network, the GPS coordinates and device information travel with the file.

## What to do about it

1. **Strip EXIF data** before sharing photos: `dtm protect metadata --apply --path ./photos/`
2. **Disable GPS tagging** in your phone's camera settings
3. **Use metadata-aware tools**: ExifTool, mat2, or this toolkit
4. **Check PDFs** before sharing — remove author/creator fields
5. **Be aware** that screenshots also contain metadata (device info, timestamps)

## Severity

**High** — A single file with GPS data can reveal your physical location. Metadata correlation across files creates a persistent identity fingerprint that survives anonymization.
