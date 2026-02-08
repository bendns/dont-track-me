---
name: review
description: Review code for bugs and security issues
---

# Code Review Skill

## Scope

Review only files changed on the current branch vs `main`:
```bash
git diff --name-only $(git merge-base HEAD main)..HEAD
```
Read each changed/new file in full before reviewing.

## Checklist

### Security
- Command injection: no user input in subprocess calls, no shell=True with variables
- SQL injection: parameterized queries only, read-only mode (`?mode=ro`) for audit databases
- Path traversal: no unsanitized user input in file paths
- External API calls: timeouts set, failures handled gracefully, no secrets in URLs

### Correctness
- Return type annotations match actual return values (e.g. `tuple[list[Finding], bool]` not `list[Finding]`)
- Score clamping: `max(0, min(100, ...))` in all auditors
- Resource cleanup: db connections closed via `try/finally`, httpx clients via `async with`
- Exception handling: narrow exceptions (no bare `except`), `contextlib.suppress` for pass-only handlers

### Project conventions
- `from __future__ import annotations` in every file
- `**kwargs: Any` (not bare `**kwargs` or `**kwargs: object`)
- Async audit/protect functions (`async def audit_*`, `async def protect_*`)
- Top-level imports only — lazy imports allowed only for optional deps (keyring, PIL, pypdf)
- No unused imports
- Protectors that touch dangerous state (TCC, certificates, Wi-Fi) must be recommendation-only

### Pattern consistency
- Compare with sibling modules — same structure (auditor.py, protector.py, module.py, info.md)
- Findings use correct `ThreatLevel` (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- `raw_data` dict populated for all audit phases

## Output format

Organize findings by category (Security, Bugs, Minor observations). End with a clear verdict:
- **Clean** — no issues, ready to push
- **Issues found** — list what must be fixed before pushing
