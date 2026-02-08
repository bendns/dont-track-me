"""HTML audit report generator — Primer-inspired design, multi-page SPA."""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any

from dont_track_me.core.base import AuditResult, ThreatLevel
from dont_track_me.core.scoring import get_score_label

# Primer-inspired color tokens
_SCORE_COLORS = {
    "Excellent": "#1a7f37",
    "Good": "#0969da",
    "Moderate": "#9a6700",
    "Poor": "#cf222e",
    "Critical": "#cf222e",
}

_THREAT_BADGE: dict[ThreatLevel, dict[str, str]] = {
    ThreatLevel.CRITICAL: {"bg": "#ffebe9", "fg": "#cf222e", "border": "#cf222e"},
    ThreatLevel.HIGH: {"bg": "#ffebe9", "fg": "#cf222e", "border": "#ffcecb"},
    ThreatLevel.MEDIUM: {"bg": "#fff8c5", "fg": "#9a6700", "border": "#efd97a"},
    ThreatLevel.LOW: {"bg": "#ddf4ff", "fg": "#0969da", "border": "#b6d9fc"},
    ThreatLevel.INFO: {"bg": "#f6f8fa", "fg": "#656d76", "border": "#d0d7de"},
}

_CSS = """\
:root {
  --color-canvas-default: #ffffff;
  --color-canvas-subtle: #f6f8fa;
  --color-border-default: #d0d7de;
  --color-border-muted: #d8dee4;
  --color-fg-default: #1f2328;
  --color-fg-muted: #656d76;
  --color-success: #1a7f37;
  --color-danger: #cf222e;
  --color-attention: #9a6700;
  --color-accent: #0969da;
}

@media (prefers-color-scheme: dark) {
  :root {
    --color-canvas-default: #161b22;
    --color-canvas-subtle: #0d1117;
    --color-border-default: #30363d;
    --color-border-muted: #21262d;
    --color-fg-default: #e6edf3;
    --color-fg-muted: #8b949e;
    --color-success: #3fb950;
    --color-danger: #f85149;
    --color-attention: #d29922;
    --color-accent: #58a6ff;
  }
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans",
    Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  font-size: 14px;
  line-height: 1.5;
  color: var(--color-fg-default);
  background: var(--color-canvas-subtle);
  padding: 32px 16px;
}

.container {
  max-width: 960px;
  margin: 0 auto;
}

header {
  text-align: center;
  margin-bottom: 32px;
}

header h1 {
  font-size: 24px;
  font-weight: 600;
  margin-bottom: 8px;
}

header .subtitle {
  color: var(--color-fg-muted);
  font-size: 14px;
}

.score-ring {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 96px;
  height: 96px;
  border-radius: 50%;
  border: 4px solid;
  margin: 16px 0 8px;
  font-size: 28px;
  font-weight: 700;
}

.score-label {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 16px;
}

.card {
  background: var(--color-canvas-default);
  border: 1px solid var(--color-border-default);
  border-radius: 6px;
  margin-bottom: 16px;
  overflow: hidden;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--color-border-muted);
  background: var(--color-canvas-subtle);
}

.card-header h2 {
  font-size: 16px;
  font-weight: 600;
}

.score-badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 24px;
  font-size: 12px;
  font-weight: 600;
  color: #ffffff;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
  margin-bottom: 32px;
}

.grid-card {
  background: var(--color-canvas-default);
  border: 1px solid var(--color-border-default);
  border-radius: 6px;
  padding: 16px;
  cursor: pointer;
  transition: border-color 0.15s, box-shadow 0.15s;
}

.grid-card:hover {
  border-color: var(--color-accent);
  box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}

.grid-card .module-name {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 8px;
}

.grid-card .score-text {
  font-size: 20px;
  font-weight: 700;
  margin-bottom: 4px;
}

.grid-card .score-sublabel {
  font-size: 12px;
  color: var(--color-fg-muted);
}

.progress-bar {
  height: 8px;
  background: var(--color-border-muted);
  border-radius: 4px;
  overflow: hidden;
  margin-top: 8px;
}

.progress-fill {
  height: 100%;
  border-radius: 4px;
  transition: width 0.3s;
}

.finding {
  padding: 12px 16px;
  border-bottom: 1px solid var(--color-border-muted);
}

.finding:last-child {
  border-bottom: none;
}

.finding-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}

.badge {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 24px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.02em;
  border: 1px solid;
  white-space: nowrap;
}

.finding-title {
  font-weight: 600;
  font-size: 14px;
}

.finding-desc {
  color: var(--color-fg-muted);
  font-size: 13px;
  margin: 4px 0;
}

.finding-remediation {
  font-size: 13px;
  margin-top: 8px;
  padding: 8px 12px;
  background: var(--color-canvas-subtle);
  border-left: 3px solid var(--color-accent);
  border-radius: 0 4px 4px 0;
  color: var(--color-fg-default);
}

.finding-remediation strong {
  color: var(--color-accent);
  font-weight: 600;
}

.no-findings {
  padding: 16px;
  color: var(--color-success);
  font-size: 14px;
}

footer {
  text-align: center;
  color: var(--color-fg-muted);
  font-size: 12px;
  margin-top: 32px;
  padding-top: 16px;
  border-top: 1px solid var(--color-border-default);
}

.page { display: none; }
.page.active { display: block; }

.back-link {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: var(--color-accent);
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  margin-bottom: 16px;
  text-decoration: none;
}

.back-link:hover { text-decoration: underline; }

.module-header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 24px;
}

.module-header .module-score-ring {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 64px;
  height: 64px;
  border-radius: 50%;
  border: 3px solid;
  font-size: 20px;
  font-weight: 700;
  flex-shrink: 0;
}

.module-header .module-info h2 {
  font-size: 20px;
  font-weight: 600;
}

.module-header .module-info .module-sublabel {
  color: var(--color-fg-muted);
  font-size: 13px;
}

.findings-count {
  color: var(--color-fg-muted);
  font-size: 13px;
  margin-bottom: 12px;
}

@media print {
  body { background: #fff; padding: 0; }
  .card, .grid-card { break-inside: avoid; }
  .score-ring { border-width: 3px; }
  .page { display: block !important; }
  .page { page-break-before: always; }
  .page:first-child { page-break-before: avoid; }
  .back-link { display: none; }
}

@media (max-width: 640px) {
  .grid { grid-template-columns: 1fr; }
  header h1 { font-size: 20px; }
  .score-ring { width: 72px; height: 72px; font-size: 22px; }
}
"""

_JS = """\
function showPage(id) {
  document.querySelectorAll('.page').forEach(function(p) {
    p.classList.remove('active');
  });
  document.getElementById(id).classList.add('active');
  window.scrollTo(0, 0);
}
"""


def _score_color(score: int | float) -> str:
    """Return a hex color for a given score."""
    label = get_score_label(float(score))
    return _SCORE_COLORS.get(label, "#656d76")


def _esc(text: str) -> str:
    """HTML-escape user-provided text."""
    return html.escape(str(text))


def _module_id(name: str) -> str:
    """Derive a safe HTML id from a module name (alphanumeric + hyphens only)."""
    safe = "".join(c if c.isalnum() or c == "-" else "-" for c in name)
    return "mod-" + safe


def _render_badge(threat_level: ThreatLevel) -> str:
    """Render a Primer-style severity badge."""
    colors = _THREAT_BADGE[threat_level]
    return (
        f'<span class="badge" style="background:{colors["bg"]};'
        f'color:{colors["fg"]};border-color:{colors["border"]}">'
        f"{_esc(threat_level.value.upper())}</span>"
    )


def _render_finding(finding: Any) -> str:
    """Render a single finding as HTML."""
    return (
        '<div class="finding">'
        '<div class="finding-header">'
        f"{_render_badge(finding.threat_level)}"
        f'<span class="finding-title">{_esc(finding.title)}</span>'
        "</div>"
        f'<div class="finding-desc">{_esc(finding.description)}</div>'
        '<div class="finding-remediation">'
        f"<strong>Remediation:</strong> {_esc(finding.remediation)}"
        "</div>"
        "</div>"
    )


def _render_grid_card(result: AuditResult) -> str:
    """Render a clickable summary grid card for a module."""
    color = _score_color(result.score)
    label = get_score_label(float(result.score))
    mid = _module_id(result.module_name)
    return (
        f'<div class="grid-card" onclick="showPage(\'{mid}\')">'
        f'<div class="module-name">{_esc(result.module_name)}</div>'
        f'<div class="score-text" style="color:{color}">{result.score}/100</div>'
        f'<div class="score-sublabel">{_esc(label)}</div>'
        '<div class="progress-bar">'
        f'<div class="progress-fill" style="width:{result.score}%;background:{color}"></div>'
        "</div>"
        "</div>"
    )


def _render_module_page(result: AuditResult) -> str:
    """Render a full detail page for a single module."""
    color = _score_color(result.score)
    label = get_score_label(float(result.score))
    mid = _module_id(result.module_name)

    findings_html = ""
    if result.findings:
        for finding in result.findings:
            findings_html += _render_finding(finding)
    else:
        findings_html = '<div class="no-findings">No issues found.</div>'

    count = len(result.findings)
    count_text = f"{count} finding{'s' if count != 1 else ''}" if count else "No issues"

    return (
        f'<div class="page" id="{mid}">'
        '<div class="container">'
        f'<a class="back-link" onclick="showPage(\'overview\')">'
        "&larr; Back to overview</a>"
        '<div class="module-header">'
        f'<div class="module-score-ring" style="border-color:{color};color:{color}">'
        f"{result.score}"
        "</div>"
        '<div class="module-info">'
        f"<h2>{_esc(result.module_name)}</h2>"
        f'<div class="module-sublabel">{_esc(label)} &middot; {count_text}</div>'
        "</div>"
        "</div>"
        '<div class="card">'
        f"{findings_html}"
        "</div>"
        "<footer>"
        f"Generated by dont-track-me &middot; {_esc(result.module_name)}"
        "</footer>"
        "</div>"
        "</div>"
    )


def generate_html_report(results: list[AuditResult], overall_score: float) -> str:
    """Generate a self-contained HTML audit report with per-module pages.

    The report is a single-page application with an overview page showing
    all module scores in a grid, and a detail page for each module
    accessible by clicking its card.

    Args:
        results: List of module audit results.
        overall_score: Weighted overall score (0-100).

    Returns:
        Complete HTML document as a string.
    """
    color = _score_color(overall_score)
    label = get_score_label(overall_score)
    now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M UTC")

    # Sort results by score (worst first)
    sorted_results = sorted(results, key=lambda r: r.score)

    # Build overview grid cards
    grid_cards = "".join(_render_grid_card(r) for r in sorted_results)

    # Build per-module detail pages
    module_pages = "".join(_render_module_page(r) for r in sorted_results)

    return (
        "<!DOCTYPE html>"
        '<html lang="en">'
        "<head>"
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Privacy Audit Report</title>"
        f"<style>{_CSS}</style>"
        "</head>"
        "<body>"
        # Overview page
        '<div class="page active" id="overview">'
        '<div class="container">'
        "<header>"
        "<h1>Privacy Audit Report</h1>"
        f'<div class="subtitle">{_esc(now)}</div>'
        f'<div class="score-ring" style="border-color:{color};color:{color}">'
        f"{round(overall_score)}"
        "</div>"
        f'<div class="score-label" style="color:{color}">{_esc(label)}</div>'
        "</header>"
        f'<div class="grid">{grid_cards}</div>'
        "<footer>"
        f"Generated by dont-track-me &middot; {_esc(now)}"
        "</footer>"
        "</div>"
        "</div>"
        # Module detail pages
        f"{module_pages}"
        # Script
        f"<script>{_JS}</script>"
        "</body>"
        "</html>"
    )
