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
- Command injection: no unsanitized input in `std::process::Command` args, no shell invocations with user data
- SQL injection: parameterized queries only (`?1` placeholders in rusqlite), read-only mode for audit databases
- Path traversal: no unsanitized user input in file paths, use `Path::join` safely
- External API calls: timeouts set on reqwest clients, failures handled with `?` or explicit error handling, no secrets in URLs
- HTML output: all user content escaped before embedding in HTML report (XSS prevention)
- No `unwrap()` or `expect()` in library code (dtm-core, dtm-modules) — use `?` or anyhow

### Correctness
- Return types match actual values — `Result<T>` used consistently
- Score clamping: scores bounded to 0..=100 in all auditors
- Resource cleanup: SQLite connections dropped properly, tempfiles cleaned up
- Error handling: specific error types (not generic `anyhow::Error` catch-all where avoidable), no silently swallowed errors
- Async functions: `await` on all futures, no accidental fire-and-forget

### Project conventions
- Rust 2021 edition idioms
- `#[cfg(test)] mod tests` blocks for inline tests — no separate test files
- `#[cfg(target_os = "...")]` for platform-specific code
- `ProtectOpts` and other test-only imports belong inside `#[cfg(test)]` blocks
- Feature flags used for optional heavy deps (oauth, macho-scan, pcap-capture, certificates, metadata-parse)
- Protectors that touch dangerous state (TCC, certificates, Wi-Fi) must be recommendation-only
- No unused imports or dead code (clippy must pass clean)

### Pattern consistency
- Compare with sibling modules — same structure (mod.rs + auditor.rs, impl Module trait)
- Findings use correct `ThreatLevel` (Critical/High/Medium/Low/Info)
- `raw_data` HashMap populated for all audit phases
- Checklist modules (instagram/tiktok/facebook/twitter) follow shared checklist test pattern (12-14 tests each)
- Educational content loaded from `shared/content/<name>.md`

## Output format

Organize findings by category (Security, Bugs, Minor observations). End with a clear verdict:
- **Clean** — no issues, ready to push
- **Issues found** — list what must be fixed before pushing
