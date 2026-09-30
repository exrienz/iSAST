# iSAST Configuration

Configuration comes from (highest wins): environment variables → `.env` →
optional YAML file (`.env` always takes priority; YAML fills gaps only).

Secrets and AI settings **never** travel through CLI arguments (blueprint §36).

## `.env` reference

Copy `.env.example` → `.env` and edit.

### Runtime

| Variable | Default | Description |
|----------|---------|-------------|
| `ISAST_WORKDIR` | `/tmp/isast` | Directory holding per-scan workspaces |

### Engine pinning (do not bump during scans)

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENGREP_VERSION` | `v1.30.0` | OpenGrep release to install into `~/.isast/bin` |
| `CODEQL_VERSION` | `2.27.1` | CodeQL CLI version to install into `~/.isast/tools/codeql` |

Engines are owned by iSAST and never auto-upgraded during a scan. Downloads
come from official GitHub releases; CodeQL bundles are sha256-verified before
installation.

### AI (OpenAI-compatible)

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_ENABLED` | `true` | Master switch for the AI layer |
| `AI_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible endpoint (Bifrost, LiteLLM, vLLM, Ollama gateways work unchanged) |
| `AI_API_KEY` | — | API key for the gateway |
| `AI_MODEL` | — | Model name the gateway expects |
| `AI_TIMEOUT` | `120` | Per-request timeout (seconds) |
| `AI_MAX_RETRIES` | `3` | Retry budget per request |
| `AI_MAX_TOKENS` | `0` | 0 = gateway default; set explicitly to defend against truncated JSON replies |
| `AI_CONCURRENCY` | `8` | Parallel validation requests |
| `AI_TEMPERATURE` | `0` | Keep deterministic |
| `AI_BATCH_SIZE` | `20` | Candidate groups per progress update / checkpoint batch |
| `AI_CONTEXT_LINES` | `30` | Code-context window (before/target/after) per finding |
| `AI_GROUP_BUDGET` | `600` | Wall-clock ceiling (seconds) per validation/dedup group; `0` disables. Groups that exhaust it stay `UNPROCESSED` and re-run on `--resume` |
| `AI_VALIDATE` | `true` | Validation stage (CONFIRMED/LIKELY/…) |
| `AI_DEDUP` | `true` | Deduplication stage (canonical ids) |
| `AI_REWRITE` | `true` | Title/description rewrite stage |
| `AI_RISK_ANALYSIS` | `true` | Severity recommendation stage |

### Build sandbox

| Variable | Default | Description |
|----------|---------|-------------|
| `BUILD_SANDBOX` | `auto` | `auto` (docker → native → none/fail-safe), `docker`, `native`, `none` |

The CLI flag `--allow-unsafe-build` is the only escape hatch to run a required
build on the host without a sandbox.

## Optional YAML config

Pass with `--config PATH` (see `config.example.yaml`):

```yaml
isast:
  workdir: /tmp/isast

ai:
  enabled: true
  timeout: 120
  max_retries: 3
  temperature: 0
  batch_size: 20
  context_lines: 30
  validate: true
  dedup: true
  rewrite: true
  risk_analysis: true

build:
  sandbox: auto
```

Flat keys (`ai_model:`) and one nested level (`ai: model:`) are both accepted;
nested keys are joined (`AI_MODEL`). YAML cannot override `.env` values.

## Installation layout

```text
~/.isast/
  bin/opengrep              OpenGrep binary
  tools/codeql/codeql       CodeQL CLI
  cache/downloads           engine downloads + checksums
  databases/                CodeQL databases per scan
  logs/
```

`--update` installs or refreshes these to the pinned versions; `--doctor`
verifies binaries, versions, Python and AI connectivity without scanning.

## Changing AI providers

Only three values change per provider:

```env
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=sk-...
AI_MODEL=gpt-5.6
```

Any OpenAI-compatible gateway (`POST {BASE_URL}/chat/completions`,
`Authorization: Bearer <key>`) works without code changes. The client
tolerates gateway response-shape variance and truncating gateways (retries +
`unparsed-model-output` handling) so gateway quirks never stall a scan.