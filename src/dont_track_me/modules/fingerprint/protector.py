"""Browser fingerprint hardening — recommendations + optional Firefox user.js."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from dont_track_me.core.base import ProtectionResult
from dont_track_me.modules.fingerprint.browsers import find_browser_profiles

# Prefs to set in Firefox user.js for anti-fingerprinting
_FINGERPRINT_PREFS = [
    ("privacy.resistFingerprinting", "true"),
    ("webgl.disabled", "true"),
    ("privacy.firstparty.isolate", "true"),
]

_MARKER = "// dont-track-me fingerprint hardening"


def _write_user_js(profile_path: Path) -> str | None:
    """Append anti-fingerprinting prefs to a Firefox user.js file.

    Returns a description of what was written, or None if nothing changed.
    """
    user_js = profile_path / "user.js"

    # Read existing content if any
    existing = ""
    if user_js.is_file() and not user_js.is_symlink():
        try:
            existing = user_js.read_text()
        except OSError:
            return None

    # Don't write if we already added our prefs
    if _MARKER in existing:
        return None

    # Build the new content to append
    lines = [f"\n{_MARKER}\n"]
    for key, value in _FINGERPRINT_PREFS:
        lines.append(f'user_pref("{key}", {value});\n')

    new_content = existing + "".join(lines)

    # Atomic write: temp file + os.replace
    try:
        fd, tmp_path = tempfile.mkstemp(dir=profile_path, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(new_content)
            os.replace(tmp_path, user_js)
        except BaseException:
            Path(tmp_path).unlink(missing_ok=True)
            raise
    except OSError:
        return None

    return f"Set resistFingerprinting, webgl.disabled, firstparty.isolate in {profile_path.name}"


async def protect_fingerprint(
    dry_run: bool = True,
    **kwargs: Any,
) -> ProtectionResult:
    """Provide fingerprint hardening recommendations and optionally write Firefox user.js."""
    actions_available: list[str] = []
    actions_taken: list[str] = []

    # Discover Firefox profiles for actionable protection
    profiles = find_browser_profiles()
    firefox_profiles = [p for p in profiles if p.browser == "firefox"]

    # Actionable: Firefox user.js hardening
    for profile in firefox_profiles:
        user_js = profile.profile_path / "user.js"
        already_hardened = (
            user_js.is_file() and not user_js.is_symlink() and _MARKER in user_js.read_text()
        )

        if not already_hardened:
            actions_available.append(
                f"Write anti-fingerprinting prefs to Firefox profile: {profile.profile_path.name} "
                "(sets privacy.resistFingerprinting, webgl.disabled, privacy.firstparty.isolate)"
            )

            if not dry_run:
                result = _write_user_js(profile.profile_path)
                if result:
                    actions_taken.append(result)

    # Browser-specific recommendations (always included)
    actions_available.extend(
        [
            "Firefox: set privacy.resistFingerprinting = true in about:config "
            "(normalizes Canvas, WebGL, fonts, timezone, screen, and User-Agent)",
            "Firefox: set webgl.disabled = true in about:config "
            "(prevents GPU renderer string fingerprinting — may break some sites)",
            "Firefox: enable letterboxing with privacy.resistFingerprinting.letterboxing = true "
            "(prevents viewport size fingerprinting)",
            "Chrome/Brave: install CanvasBlocker or Canvas Fingerprint Defender extension",
            "Brave: enable aggressive fingerprint randomization in Settings → Shields → Fingerprinting",
            "General: use Tor Browser for maximum anti-fingerprinting "
            "(all users share an identical fingerprint)",
            "General: use Firefox with resistFingerprinting as the best non-Tor option",
            "General: minimize installed custom fonts to reduce fingerprint uniqueness",
        ]
    )

    return ProtectionResult(
        module_name="fingerprint",
        dry_run=dry_run,
        actions_taken=actions_taken,
        actions_available=actions_available,
    )
