# dont-track-me

Modular anti-tracking toolkit. Audits privacy exposure and applies countermeasures.

## Project structure

```
src/dont_track_me/
  cli/main.py          # Click CLI (dtm command)
  core/                # Shared infra: base models, auth, config, registry, scoring, checklist
  modules/             # Each module = directory with module.py, auditor.py, protector.py, info.md
tests/
  test_core/           # Core infrastructure tests
  test_modules/        # Per-module tests
```

## Key patterns

- **Modules** extend `BaseModule` (or `OAuthModule` for API-backed ones like reddit/youtube)
- **Checklist modules** (instagram/tiktok/facebook) use `PrivacyCheck` model + `protect_checklist_module()` from `core/checklist.py`
- **Auto-discovery**: modules are found at startup via `pkgutil.iter_modules` in `core/registry.py` -- no registration needed
- **Lazy imports only for optional deps**: `keyring`, `keyring.errors`, `PIL`, `pypdf` are imported inside functions. All other imports go at file top
- The `registry.py` import of `BaseModule` inside `_discover_modules()` is intentional (avoids circular import)
- Use `raise SystemExit(1)` instead of `sys.exit(1)` after `get_module()` None checks -- pyright/basedpyright needs explicit `NoReturn` for type narrowing

## Commands

- **Lint**: `ruff check src/ tests/`
- **Tests**: `pytest -q` (297 tests, ~1.2s)
- **Install dev**: `pip install -e ".[dev]"`
- **Run CLI**: `dtm status`, `dtm audit`, `dtm score`, `dtm protect`, `dtm noise search`, `dtm noise social`

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
- Educational content in `info.md` per module (Markdown)
- Per-country data in YAML files under `modules/<name>/data/` (us.yaml, fr.yaml)
- File scanning uses `itertools.islice(rglob, MAX_FILES)` to prevent unbounded recursion

## Testing

- All tests use pytest + pytest-asyncio (asyncio_mode = "auto")
- Test files mirror module structure: `tests/test_modules/test_<name>.py`
- Mock external deps (keyring, httpx, subprocess) -- tests must run offline
- Use `assert obj is not None` before accessing attributes from functions returning `T | None`
- Always run both `ruff check` and `pytest` before considering work done
- Always verify that README.md and CLAUDE.md are up-to-date after any changes (new modules, new CLI flags, new conventions, new ruff rules, etc.)
