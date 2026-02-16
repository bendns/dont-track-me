# dtm-shared -- Cross-Platform Privacy Content

Language-agnostic content shared across all dont-track-me implementations (CLI, Android, iOS).

## Structure

```
shared/
  content/           # Educational markdown (one per module)
  data/              # Per-country YAML data files
    ad_tracking/     #   Data broker registries with opt-out URLs
    search_noise/    #   Balanced search query databases
    social_noise/    #   Balanced social media account databases
  checklists/        # Interactive privacy checklists (YAML)
  schema/            # Scoring specs and JSON schemas
    scoring.yaml     #   Module weights and score tier definitions
    threat_weights.yaml  # Penalty per threat level for checklists
    *.schema.json    #   Pydantic model schemas (for native code generation)
```

## Usage

### Python CLI (this repo)

Content is loaded via `dont_track_me.core.paths.SHARED_DIR` which resolves to this directory.

### Mobile apps (future)

Consume via git submodule or copy at build time:
- Render `content/*.md` as in-app educational screens
- Load `checklists/*.yaml` to build interactive checklist UIs
- Use `data/` for per-country broker lists and noise databases
- Implement scoring from `schema/scoring.yaml`
- Generate Swift/Kotlin model classes from `schema/*.schema.json` via [quicktype](https://quicktype.io)

## Adding content

- New module educational content: add `content/<module_name>.md`
- New country data: add `data/<module>/<country_code>.yaml` (ISO 3166-1 alpha-2, lowercase)
- New checklist: add `checklists/<module_name>.yaml` following the existing format
- New module weight: add entry to `schema/scoring.yaml` under `module_weights`
