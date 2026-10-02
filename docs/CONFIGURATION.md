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

> Renamed in Unreleased: `AI_BASE_URL` → `LLM_PROVIDER`, `AI_API_KEY` →
> `LLM_KEY`, `AI_MODEL` → `LLM_MODEL`. Update existing `.env` files.

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_ENABLED` | `true` | Master switch for the AI layer |
| `LLM_PROVIDER` | `https://api.openai.com/v1` | OpenAI-compatible endpoint (Bifrost, LiteLLM, vLLM, Ollama gateways work unchanged) |
| `LLM_KEY` | — | API key for the gateway |
| `LLM_MODEL` | — | Model name the gateway expects |
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

llm:
  provider: https://api.openai.com/v1
  model: gpt-5.6

build:
  sandbox: auto
```

Flat keys (`llm_model:`) and one nested level (`llm: model:`) are both
accepted; nested keys are joined (`llm` + `model` → `LLM_MODEL`). The `ai:`
section maps to the remaining `AI_*` behavior toggles the same way. YAML
cannot override `.env` values. (Do not put the API key in YAML — keep it in
`.env`.)

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
LLM_PROVIDER=https://api.openai.com/v1
LLM_KEY=sk-...
LLM_MODEL=gpt-5.6
```

Any OpenAI-compatible gateway (`POST {BASE_URL}/chat/completions`,
`Authorization: Bearer <key>`) works without code changes. The client
tolerates gateway response-shape variance and truncating gateways (retries +
`unparsed-model-output` handling) so gateway quirks never stall a scan.