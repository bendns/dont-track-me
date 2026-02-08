"""Browser fingerprint exposure analysis — detect fingerprinting vectors."""

from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import subprocess
import time
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel
from dont_track_me.modules.fingerprint.browsers import (
    BrowserProfile,
    find_browser_profiles,
)

# Privacy prefs that matter for fingerprinting
_KEY_PREFS = {
    "privacy.resistFingerprinting": "Normalizes canvas, WebGL, fonts, timezone, screen, and User-Agent",
    "webgl.disabled": "Prevents WebGL renderer string fingerprinting",
    "privacy.firstparty.isolate": "Isolates cookies and cache per first-party domain",
}


def _check_resist_fingerprinting(profiles: list[BrowserProfile]) -> tuple[list[Finding], int]:
    """Check if Firefox's resistFingerprinting is enabled."""
    findings: list[Finding] = []
    score_delta = 0

    firefox_profiles = [p for p in profiles if p.browser == "firefox"]
    if not firefox_profiles:
        return findings, score_delta

    any_enabled = False
    for profile in firefox_profiles:
        if profile.prefs.get("privacy.resistFingerprinting") is True:
            any_enabled = True

    if any_enabled:
        findings.append(
            Finding(
                title="Firefox resistFingerprinting enabled",
                description=(
                    "privacy.resistFingerprinting is enabled, which normalizes "
                    "Canvas, WebGL, fonts, timezone, screen dimensions, languages, "
                    "and User-Agent to reduce fingerprint uniqueness."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed — this is the strongest anti-fingerprinting measure.",
            )
        )
    else:
        findings.append(
            Finding(
                title="Firefox resistFingerprinting is disabled",
                description=(
                    "privacy.resistFingerprinting is not enabled in any Firefox profile. "
                    "This single setting is the most effective anti-fingerprinting measure "
                    "available — it normalizes dozens of fingerprinting signals at once."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Open about:config in Firefox, search for "
                    "'privacy.resistFingerprinting' and set it to true. "
                    "Or use 'dtm protect fingerprint --apply' to set it automatically."
                ),
            )
        )
        score_delta -= 25

    return findings, score_delta


def _check_webgl_exposure(profiles: list[BrowserProfile]) -> tuple[list[Finding], int]:
    """Check if WebGL is enabled (exposes GPU renderer string)."""
    findings: list[Finding] = []
    score_delta = 0

    firefox_profiles = [p for p in profiles if p.browser == "firefox"]

    # If resistFingerprinting is on, WebGL renderer is already spoofed
    rfp_enabled = any(p.prefs.get("privacy.resistFingerprinting") is True for p in firefox_profiles)
    if rfp_enabled:
        return findings, score_delta

    webgl_disabled = any(p.prefs.get("webgl.disabled") is True for p in firefox_profiles)

    if not webgl_disabled:
        findings.append(
            Finding(
                title="WebGL fingerprinting vector exposed",
                description=(
                    "WebGL is enabled and exposes your GPU vendor and renderer string "
                    "(e.g., 'ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)'). This is one of "
                    "the strongest fingerprinting signals — it uniquely identifies your "
                    "hardware configuration."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Firefox: set 'webgl.disabled = true' in about:config "
                    "(may break some websites). Or enable resistFingerprinting to spoof it."
                ),
            )
        )
        score_delta -= 10

    return findings, score_delta


def _check_anti_fingerprint_extensions(profiles: list[BrowserProfile]) -> tuple[list[Finding], int]:
    """Check for anti-fingerprinting browser extensions."""
    findings: list[Finding] = []
    score_delta = 0

    all_extensions: set[str] = set()
    for profile in profiles:
        all_extensions.update(profile.extensions)

    if all_extensions:
        findings.append(
            Finding(
                title=f"Anti-fingerprinting extensions found: {', '.join(sorted(all_extensions))}",
                description=(
                    f"Detected {len(all_extensions)} anti-fingerprinting extension(s) "
                    "across your browser profiles. These help reduce fingerprint uniqueness."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed — keep these extensions updated.",
            )
        )
    elif profiles:
        findings.append(
            Finding(
                title="No anti-fingerprinting extensions detected",
                description=(
                    "No anti-fingerprinting browser extensions were found in any profile. "
                    "Extensions like CanvasBlocker, uBlock Origin, or Privacy Badger can "
                    "significantly reduce your fingerprint uniqueness."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Install CanvasBlocker (Firefox) or a fingerprint-blocking extension. "
                    "uBlock Origin in advanced mode also blocks many fingerprinting scripts."
                ),
            )
        )
        score_delta -= 15

    return findings, score_delta


def _check_canvas_protection(profiles: list[BrowserProfile]) -> tuple[list[Finding], int]:
    """Check if Canvas fingerprinting is mitigated."""
    findings: list[Finding] = []
    score_delta = 0

    # Firefox with resistFingerprinting already covers Canvas
    firefox_rfp = any(
        p.browser == "firefox" and p.prefs.get("privacy.resistFingerprinting") is True
        for p in profiles
    )
    if firefox_rfp:
        return findings, score_delta

    # Check for CanvasBlocker or similar extension
    has_canvas_ext = any(
        ext in ("CanvasBlocker", "Canvas Fingerprint Defender")
        for p in profiles
        for ext in p.extensions
    )
    if has_canvas_ext:
        return findings, score_delta

    if profiles:
        findings.append(
            Finding(
                title="Canvas fingerprinting unprotected",
                description=(
                    "No Canvas fingerprinting protection detected. HTML5 Canvas renders "
                    "text and shapes slightly differently per GPU, driver, and font "
                    "configuration — creating a near-unique fingerprint. This is the "
                    "most common active fingerprinting technique."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Firefox: enable privacy.resistFingerprinting (normalizes Canvas output). "
                    "Chrome: install CanvasBlocker or Canvas Fingerprint Defender extension."
                ),
            )
        )
        score_delta -= 15

    return findings, score_delta


def _count_system_fonts() -> int:
    """Count installed system fonts (platform-specific)."""
    system = platform.system()
    count = 0

    if system == "Darwin":
        font_dirs = [
            Path("/Library/Fonts"),
            Path("/System/Library/Fonts"),
            Path.home() / "Library" / "Fonts",
        ]
        for font_dir in font_dirs:
            if font_dir.exists() and not font_dir.is_symlink():
                with contextlib.suppress(OSError):
                    count += sum(1 for f in font_dir.iterdir() if f.is_file())

    elif system == "Linux":
        try:
            result = subprocess.run(
                ["fc-list", "--format", "%{family}\n"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Unique font families
                families = {line.strip() for line in result.stdout.splitlines() if line.strip()}
                count = len(families)
        except (OSError, subprocess.TimeoutExpired):
            pass

    return count


def _check_font_exposure(font_count: int) -> tuple[list[Finding], int]:
    """Check if installed font count increases fingerprint uniqueness."""
    findings: list[Finding] = []
    score_delta = 0

    if font_count == 0:
        return findings, score_delta

    if font_count > 200:
        findings.append(
            Finding(
                title=f"Large font library ({font_count} fonts) increases uniqueness",
                description=(
                    f"Your system has {font_count} fonts installed. Font enumeration is "
                    "a powerful fingerprinting vector — each additional font increases "
                    "your browser's uniqueness. Most systems have 100-200 fonts."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Remove unnecessary custom fonts. Use Firefox with "
                    "resistFingerprinting (restricts font visibility) or set "
                    "layout.css.font-visibility.level = 1 in about:config."
                ),
            )
        )
        score_delta -= 5
    elif font_count > 100:
        findings.append(
            Finding(
                title=f"Moderate font library ({font_count} fonts)",
                description=(
                    f"Your system has {font_count} fonts installed. This is within "
                    "the normal range but still contributes to fingerprint uniqueness."
                ),
                threat_level=ThreatLevel.LOW,
                remediation=(
                    "Consider enabling Firefox's resistFingerprinting or setting "
                    "layout.css.font-visibility.level to restrict font access."
                ),
            )
        )
        score_delta -= 2

    return findings, score_delta


def _check_system_fingerprint() -> tuple[list[Finding], int, dict[str, Any]]:
    """Check system-level fingerprinting signals."""
    findings: list[Finding] = []
    score_delta = 0
    raw: dict[str, Any] = {}

    # CPU count (exposed as navigator.hardwareConcurrency)
    cpu_count = os.cpu_count() or 0
    raw["cpu_count"] = cpu_count
    if cpu_count > 4:
        findings.append(
            Finding(
                title=f"Hardware: {cpu_count} CPU cores exposed",
                description=(
                    f"navigator.hardwareConcurrency reports {cpu_count} cores. "
                    "Non-standard values (most common: 4, 8) add entropy to your fingerprint. "
                    "Firefox with resistFingerprinting normalizes this to 2."
                ),
                threat_level=ThreatLevel.LOW,
                remediation="Enable resistFingerprinting in Firefox to normalize to 2 cores.",
            )
        )
        score_delta -= 3

    # Timezone (exposed via Intl.DateTimeFormat)
    try:
        tz_name = time.tzname[0]
    except (IndexError, AttributeError):
        tz_name = "unknown"
    raw["timezone"] = tz_name
    if tz_name not in ("UTC", "GMT", "unknown"):
        findings.append(
            Finding(
                title=f"Timezone '{tz_name}' adds fingerprint entropy",
                description=(
                    f"Your timezone ({tz_name}) is exposed via the Intl API. "
                    "Combined with other signals, timezone helps narrow your identity. "
                    "Firefox with resistFingerprinting reports UTC."
                ),
                threat_level=ThreatLevel.LOW,
                remediation="Enable resistFingerprinting in Firefox to report UTC timezone.",
            )
        )
        score_delta -= 3

    return findings, score_delta, raw


async def _run_playwright_checks() -> tuple[list[Finding], dict[str, Any]]:
    """Run JavaScript-based fingerprint measurements via Playwright.

    Only called if Playwright is installed. Failures return empty results.
    """
    findings: list[Finding] = []
    raw: dict[str, Any] = {}

    try:
        from playwright.async_api import async_playwright  # type: ignore[import-not-found]
    except ImportError:
        return findings, raw

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                page = await browser.new_page()

                # Canvas fingerprint
                canvas_hash = await page.evaluate("""() => {
                    const canvas = document.createElement('canvas');
                    canvas.width = 200;
                    canvas.height = 50;
                    const ctx = canvas.getContext('2d');
                    ctx.textBaseline = 'top';
                    ctx.font = '14px Arial';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(125, 1, 62, 20);
                    ctx.fillStyle = '#069';
                    ctx.fillText('fingerprint', 2, 15);
                    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
                    ctx.fillText('fingerprint', 4, 17);
                    return canvas.toDataURL();
                }""")
                raw["canvas_hash"] = hashlib.sha256(canvas_hash.encode()).hexdigest()[:16]

                # WebGL renderer
                webgl_info = await page.evaluate("""() => {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    if (!gl) return null;
                    const ext = gl.getExtension('WEBGL_debug_renderer_info');
                    if (!ext) return null;
                    return {
                        vendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),
                        renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
                    };
                }""")
                if webgl_info:
                    raw["webgl_vendor"] = webgl_info.get("vendor", "")
                    raw["webgl_renderer"] = webgl_info.get("renderer", "")
                    findings.append(
                        Finding(
                            title=f"WebGL renderer: {webgl_info.get('renderer', 'unknown')}",
                            description=(
                                "Your GPU's WebGL renderer string uniquely identifies your "
                                "hardware. This is visible to every website you visit."
                            ),
                            threat_level=ThreatLevel.INFO,
                            remediation="This is informational — see WebGL findings above for mitigations.",
                        )
                    )

                # AudioContext fingerprint
                audio_hash = await page.evaluate("""() => {
                    return new Promise((resolve) => {
                        try {
                            const ctx = new OfflineAudioContext(1, 44100, 44100);
                            const osc = ctx.createOscillator();
                            osc.type = 'triangle';
                            osc.frequency.value = 10000;
                            const comp = ctx.createDynamicsCompressor();
                            osc.connect(comp);
                            comp.connect(ctx.destination);
                            osc.start(0);
                            ctx.startRendering().then((buffer) => {
                                const data = buffer.getChannelData(0);
                                let sum = 0;
                                for (let i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
                                resolve(sum.toString());
                            });
                        } catch (e) {
                            resolve(null);
                        }
                    });
                }""")
                if audio_hash:
                    raw["audio_hash"] = hashlib.sha256(audio_hash.encode()).hexdigest()[:16]

                # Navigator properties
                nav_info = await page.evaluate("""() => ({
                    hardwareConcurrency: navigator.hardwareConcurrency,
                    deviceMemory: navigator.deviceMemory || null,
                    maxTouchPoints: navigator.maxTouchPoints,
                    languages: navigator.languages,
                    platform: navigator.platform
                })""")
                if nav_info:
                    raw["navigator"] = nav_info

            finally:
                await browser.close()

    except Exception:
        raw["playwright_error"] = "Playwright execution failed"

    return findings, raw


async def audit_fingerprint(**kwargs: Any) -> AuditResult:
    """Analyze browser fingerprinting exposure."""
    findings: list[Finding] = []
    score = 100

    # Discover browser profiles
    profiles = find_browser_profiles()

    if not profiles:
        findings.append(
            Finding(
                title="No browser profiles found",
                description=(
                    "Could not locate Firefox, Chrome, or Brave profiles. "
                    "Without browser configuration data, fingerprint exposure "
                    "cannot be fully assessed."
                ),
                threat_level=ThreatLevel.INFO,
                remediation=(
                    "Ensure a supported browser is installed. "
                    "The audit checks Firefox, Chrome, and Brave profiles."
                ),
            )
        )
        # Still run system checks even without browser profiles
        score -= 20  # Unknown browser config is risky

    # Run static checks
    for check_fn in (
        _check_resist_fingerprinting,
        _check_webgl_exposure,
        _check_anti_fingerprint_extensions,
        _check_canvas_protection,
    ):
        check_findings, delta = check_fn(profiles)
        findings.extend(check_findings)
        score += delta

    # Font exposure check
    font_count = _count_system_fonts()
    font_findings, font_delta = _check_font_exposure(font_count)
    findings.extend(font_findings)
    score += font_delta

    # System fingerprint signals
    sys_findings, sys_delta, sys_raw = _check_system_fingerprint()
    findings.extend(sys_findings)
    score += sys_delta

    # Collect raw data
    raw_data: dict[str, Any] = {
        "browsers_found": sorted({p.browser for p in profiles}),
        "profiles_scanned": len(profiles),
        "resist_fingerprinting": any(
            p.prefs.get("privacy.resistFingerprinting") is True
            for p in profiles
            if p.browser == "firefox"
        ),
        "webgl_disabled": any(
            p.prefs.get("webgl.disabled") is True for p in profiles if p.browser == "firefox"
        ),
        "extensions_found": sorted({ext for p in profiles for ext in p.extensions}),
        "font_count": font_count,
        **sys_raw,
    }

    # Optional Playwright tier
    playwright_available = find_spec("playwright") is not None
    raw_data["playwright_available"] = playwright_available

    if playwright_available:
        pw_findings, pw_raw = await _run_playwright_checks()
        findings.extend(pw_findings)
        raw_data.update(pw_raw)

    score = max(0, min(100, score))

    return AuditResult(
        module_name="fingerprint",
        score=score,
        findings=findings,
        raw_data=raw_data,
    )
