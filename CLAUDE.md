# dont-track-me

Modular anti-tracking toolkit. Audits privacy exposure and applies countermeasures.

## Project structure

```
shared/                # Cross-platform content (educational md, YAML data, checklists, schemas)
src/dont_track_me/
  cli/main.py          # Click CLI (dtm command)
  core/                # Shared infra: base models, auth, config, registry, scoring, checklist, paths
  modules/             # Each module = directory with module.py, auditor.py, protector.py
tests/
  test_core/           # Core infrastructure tests
  test_modules/        # Per-module tests
```

## Key patterns

- **Modules** extend `BaseModule` (or `OAuthModule` for API-backed ones like reddit/youtube)
- **Checklist modules** (instagram/tiktok/facebook/twitter) use `PrivacyCheck` model + `protect_checklist_module()` from `core/checklist.py`
- **Auto-discovery**: modules are found at startup via `pkgutil.iter_modules` in `core/registry.py` -- no registration needed
- **Lazy imports only for optional deps**: `keyring`, `keyring.errors`, `PIL`, `pypdf` are imported inside functions. All other imports go at file top
- The `registry.py` import of `BaseModule` inside `_discover_modules()` is intentional (avoids circular import)
- Use `raise SystemExit(1)` instead of `sys.exit(1)` after `get_module()` None checks -- pyright/basedpyright needs explicit `NoReturn` for type narrowing

## Commands

- **Lint**: `uv run ruff check src/ tests/`
- **Tests**: `uv run pytest -q` (428 tests, ~2.5s)
- **Install dev**: `uv sync --extra dev`
- **Run CLI**: `uv run dtm status`, `uv run dtm audit`, `uv run dtm score`, `uv run dtm protect`, `uv run dtm noise search`, `uv run dtm noise social`

## Ruff config

Defined in `pyproject.toml` under `[tool.ruff]`. Rule sets: E, W, F, I, N, UP, B, SIM, RUF. Always run ruff after changes.

Intentionally excluded:
- **TCH** (type-checking imports) -- too noisy for this project size
- **N818** (exception naming suffix) -- `AuthenticationRequired` is clearer than `AuthenticationRequiredError`
- **E501** (line length) -- handled by formatter

## Code conventions

- Python 3.11+, `from __future__ import annotations` in every file
- Pydantic v2 for all data models (`BaseModel`, not dataclasses)
- Async auditors/protectors (`async def audit_*`, `async def protect_*`)
- Type all `**kwargs: Any` (not bare `**kwargs` or `**kwargs: object`)
- Use `contextlib.suppress` over `try/except/pass`
- Use ternary operators for simple if/else assignments
- Narrow exceptions: catch specific types (e.g. `ValueError, KeyError`), not bare `Exception`
- No in-function imports unless the dependency is optional (PIL, pypdf, keyring)
- Educational content in `shared/content/<name>.md` (loaded automatically by BaseModule)
- Per-country data in YAML files under `shared/data/<module>/` (us.yaml, fr.yaml)
- Privacy checklists in `shared/checklists/<name>.yaml` (loaded by checks.py)
- Scoring weights and threat weights in `shared/schema/` YAML files
- File scanning uses `itertools.islice(rglob, MAX_FILES)` to prevent unbounded recursion

## Testing

- All tests use pytest + pytest-asyncio (asyncio_mode = "auto")
- Test files mirror module structure: `tests/test_modules/test_<name>.py`
- Mock external deps (keyring, httpx, subprocess) -- tests must run offline
- Use `assert obj is not None` before accessing attributes from functions returning `T | None`
- Always run both `ruff check` and `pytest` before considering work done
- Always run `/review` for security and bug checks before pushing
- Always verify that README.md and CLAUDE.md are up-to-date after any changes (new modules, new CLI flags, new conventions, new ruff rules, etc.)
- After adding modules or major features, check if the GitHub repo description and topics need updating (`gh repo edit --description`, `gh repo edit --add-topic`)
