"""Browser profile discovery and configuration parsing."""

from __future__ import annotations

import json
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB for config files

# Regex to parse Firefox prefs.js: user_pref("key", value);
_PREF_RE = re.compile(r'user_pref\("([^"]+)",\s*(.+?)\);')

# Known anti-fingerprinting browser extensions (ID or name fragments)
ANTI_FP_EXTENSIONS: dict[str, str] = {
    # Firefox extension IDs
    "CanvasBlocker@AK": "CanvasBlocker",
    "jid1-KKzOGWgsW3Ao4Q@jetpack": "JShelter",
    "jid1-MnnxcxisBPnSXQ@jetpack": "Privacy Badger",
    "uBlock0@AK": "uBlock Origin",
    "{73a6fe31-595d-460b-a920-fcc0f8843232}": "NoScript",
    "AK@nickerbocker.dk": "Trace",
    "{74145f27-f039-47ce-a470-a662b129930a}": "ClearURLs",
    # Chrome extension IDs
    "nomnklagbgmblcanipdhfkpbfkgfnclb": "CanvasBlocker",
    "gcbommkclmhbdofmjdahifelcpgpbidi": "JShelter",
    "pkehgijcmpdhfbdbbnkijodmdjhbjlgp": "Privacy Badger",
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
}

# Name-based fallback matching (case-insensitive substring)
_ANTI_FP_NAME_PATTERNS = [
    "canvasblocker",
    "jshelter",
    "privacy badger",
    "ublock origin",
    "noscript",
    "trace",
    "clearurls",
    "canvas fingerprint",
    "fingerprint protect",
    "fingerprint defend",
]


@dataclass
class BrowserProfile:
    """A discovered browser profile with its configuration."""

    browser: str  # "firefox", "chrome", "brave"
    profile_path: Path
    prefs: dict[str, Any] = field(default_factory=dict)
    extensions: list[str] = field(default_factory=list)


def _safe_read_text(path: Path) -> str | None:
    """Read a text file with symlink and size guards."""
    if not path.is_file() or path.is_symlink():
        return None
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
    except OSError:
        return None
    try:
        return path.read_text(errors="replace")
    except OSError:
        return None


def _safe_read_json(path: Path) -> dict[str, Any] | None:
    """Read and parse a JSON file with guards."""
    text = _safe_read_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _parse_firefox_prefs(profile_path: Path) -> dict[str, Any]:
    """Parse Firefox prefs.js for privacy-related settings."""
    prefs: dict[str, Any] = {}
    text = _safe_read_text(profile_path / "prefs.js")
    if text is None:
        return prefs

    for match in _PREF_RE.finditer(text):
        key = match.group(1)
        raw_value = match.group(2).strip()

        # Parse value types
        if raw_value == "true":
            prefs[key] = True
        elif raw_value == "false":
            prefs[key] = False
        elif raw_value.isdigit() or (raw_value.startswith("-") and raw_value[1:].isdigit()):
            prefs[key] = int(raw_value)
        elif raw_value.startswith('"') and raw_value.endswith('"'):
            prefs[key] = raw_value[1:-1]
        else:
            prefs[key] = raw_value

    return prefs


def _parse_firefox_extensions(profile_path: Path) -> list[str]:
    """Extract installed extension names from Firefox extensions.json."""
    extensions: list[str] = []
    data = _safe_read_json(profile_path / "extensions.json")
    if data is None:
        return extensions

    for addon in data.get("addons", []):
        if not isinstance(addon, dict):
            continue
        ext_id = addon.get("id", "")
        name = (
            addon.get("defaultLocale", {}).get("name", "")
            if isinstance(addon.get("defaultLocale"), dict)
            else ""
        )
        # Check by ID first
        if ext_id in ANTI_FP_EXTENSIONS:
            extensions.append(ANTI_FP_EXTENSIONS[ext_id])
        # Fallback: check by name
        elif name and any(pat in name.lower() for pat in _ANTI_FP_NAME_PATTERNS):
            extensions.append(name)

    return extensions


def _parse_chrome_extensions(profile_path: Path) -> list[str]:
    """Extract installed extension names from Chrome/Brave Preferences."""
    extensions: list[str] = []
    data = _safe_read_json(profile_path / "Preferences")
    if data is None:
        return extensions

    settings = data.get("extensions", {}).get("settings", {})
    if not isinstance(settings, dict):
        return extensions

    for ext_id, ext_data in settings.items():
        if not isinstance(ext_data, dict):
            continue
        # Check by ID
        if ext_id in ANTI_FP_EXTENSIONS:
            extensions.append(ANTI_FP_EXTENSIONS[ext_id])
            continue
        # Check by manifest name
        manifest = ext_data.get("manifest", {})
        if isinstance(manifest, dict):
            name = manifest.get("name", "")
            if name and any(pat in name.lower() for pat in _ANTI_FP_NAME_PATTERNS):
                extensions.append(name)

    return extensions


def find_browser_profiles() -> list[BrowserProfile]:
    """Discover browser profiles on macOS and Linux.

    Returns a list of BrowserProfile with parsed prefs and extension lists.
    """
    profiles: list[BrowserProfile] = []
    home = Path.home()
    system = platform.system()

    # Define search paths per browser per platform
    search_paths: list[tuple[Path, str, str]] = []  # (base, browser, type)

    if system == "Darwin":
        search_paths = [
            (
                home / "Library" / "Application Support" / "Firefox" / "Profiles",
                "firefox",
                "firefox",
            ),
            (home / "Library" / "Application Support" / "Google" / "Chrome", "chrome", "chrome"),
            (
                home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser",
                "brave",
                "chrome",
            ),
        ]
    elif system == "Linux":
        search_paths = [
            (home / ".mozilla" / "firefox", "firefox", "firefox"),
            (home / ".config" / "google-chrome", "chrome", "chrome"),
            (home / ".config" / "BraveSoftware" / "Brave-Browser", "brave", "chrome"),
        ]

    for base_path, browser, config_type in search_paths:
        if not base_path.exists() or base_path.is_symlink():
            continue

        for profile_dir in base_path.iterdir():
            if not profile_dir.is_dir() or profile_dir.is_symlink():
                continue

            if config_type == "firefox":
                # Firefox profiles have prefs.js
                if not (profile_dir / "prefs.js").exists():
                    continue
                prefs = _parse_firefox_prefs(profile_dir)
                extensions = _parse_firefox_extensions(profile_dir)
            else:
                # Chrome/Brave profiles have Preferences
                if not (profile_dir / "Preferences").exists():
                    continue
                prefs = {}  # Chrome prefs are in the JSON, not separately useful
                extensions = _parse_chrome_extensions(profile_dir)

            profiles.append(
                BrowserProfile(
                    browser=browser,
                    profile_path=profile_dir,
                    prefs=prefs,
                    extensions=extensions,
                )
            )

    return profiles
