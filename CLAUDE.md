# dont-track-me

Modular anti-tracking toolkit. Audits privacy exposure and applies countermeasures.

## Project structure

```
Cargo.toml             # Workspace root
shared/                # Cross-platform content (educational md, YAML data, checklists, schemas)
  tracker_domains.yaml
  tracker_sdks.yaml
  tracker_cookies.yaml
  email_trackers.yaml
  social_trackers.yaml
  content/             # Educational markdown (one per module)
  data/                # Per-country YAML (ad_tracking/, search_noise/, social_noise/)
  checklists/          # Privacy checklists YAML (instagram, tiktok, facebook, twitter)
  schema/              # scoring.yaml, threat_weights.yaml
crates/
  dtm-core/            # Library: models, traits, scoring, config, data loading, auth, db, report
  dtm-modules/         # Library: all 25 modules
  dtm-cli/             # Binary: the `dtm` command
```

## Key patterns

- **Module trait**: `#[async_trait] pub trait Module: Send + Sync` -- all modules implement this
- **Checklist modules** (instagram/tiktok/facebook/twitter) use `PrivacyCheck` + shared `checklist.rs` pattern
- **OAuth modules** (reddit/youtube) use `keyring` + `tiny_http` + `open` for token flow
- **Feature flags**: `oauth`, `macho-scan`, `pcap-capture`, `certificates`, `metadata-parse` -- gate optional deps
- **Platform-specific code** gated with `#[cfg(target_os = "...")]` -- modules return `is_available() = false` on unsupported OS
- **YAML data** loaded at runtime from `shared/` with `include_str!` fallback
- **Terminal output**: comfy-table + owo-colors + termimad + indicatif + dialoguer
- **HTML report**: self-contained SPA with dark mode (`report.rs`)
- **Async runtime**: tokio
- **HTTP**: reqwest (rustls-tls)

## Commands

- **Build**: `cargo build --release`
- **Tests**: `cargo nextest run` (452 tests)
- **Lint**: `cargo clippy --all-targets`
- **Format check**: `cargo fmt --check`
- **Install**: `cargo install --path crates/dtm-cli`
- **Run CLI**: `dtm status`, `dtm audit`, `dtm score`, `dtm protect`, `dtm noise search`, `dtm noise social`, `dtm apps`, `dtm monitor`

## Code conventions

- Rust 2021 edition, Cargo workspace with 3 crates
- serde for all serialization (serde_yaml, serde_json, toml)
- thiserror for library errors, anyhow for application errors
- async-trait for the Module trait
- No `unwrap()` in library code -- use `?` or anyhow
- Educational content in `shared/content/<name>.md` (loaded at runtime)
- Per-country data in YAML files under `shared/data/<module>/` (us.yaml, fr.yaml)
- Privacy checklists in `shared/checklists/<name>.yaml`
- Scoring weights and threat weights in `shared/schema/` YAML files

## Testing

- All tests inline in source files (`#[cfg(test)] mod tests`)
- Mock filesystem with `tempfile::TempDir`, SQLite with `rusqlite` in-memory
- Platform-specific tests gated with `#[cfg(target_os = "...")]`
- Always run both `cargo clippy --all-targets` and `cargo test` before considering work done
- Always run `/review` for security and bug checks before pushing
- Always verify that README.md and CLAUDE.md are up-to-date after any changes (new modules, new CLI flags, new conventions, new feature flags, etc.)
- After adding modules or major features, check if the GitHub repo description and topics need updating (`gh repo edit --description`, `gh repo edit --add-topic`)
