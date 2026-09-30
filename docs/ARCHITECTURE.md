# iSAST Architecture

## Design principle

**iSAST is deterministic orchestration; AI is the analysis layer.**

- The orchestration path (detect → scan → normalize → group → report) is fully
  deterministic: same source + same engine versions ⇒ same raw findings.
- The AI layer may refine, validate and deduplicate, but it may **never delete
  raw scanner evidence**. `raw-findings.json` always contains every
  OpenGrep/CodeQL finding with its AI verdict attached.
- **AI fail-open**: any AI failure (network, auth, malformed responses) leaves
  findings `UNPROCESSED` and the scan still emits `final.csv` (exit code 5).

## Module map

```text
isast.py            CLI entry point: argparse, exit codes, command dispatch
core/
  scanner.py        the 8-stage scan orchestration (pipeline + canonical build)
  executor.py       subprocess runner — argv arrays + timeouts only, no shell
  dependency.py     engine install/update against pinned versions (~/.isast)
  workspace.py      per-scan workspace lifecycle + atomic state checkpoints
  models.py         plain stdlib dataclasses: Finding, CanonicalFinding, stats
  settings.py       .env / env vars / optional YAML config loading
  resources.py      locate packaged resources (rules etc.)
  textclamp.py      bounded-snippet helper (head+tail truncation with marker)
detection/
  language.py       language detection (LOC table)
  manifest.py       ecosystem/manifest detection (pip, npm, maven, go, …)
  build.py          build-system resolution (when CodeQL extraction needs a build)
engines/
  opengrep.py       OpenGrep runner (recall-favored baseline config)
  codeql.py         CodeQL runner: per-language DB create + analyze → SARIF
  rules/            isast-baseline-security.yaml (baseline ruleset)
builders/           maven, gradle, npm, go, cargo, cmake, dotnet build glue
sandbox/
  manager.py        sandbox decision: docker → native → none (fail safe)
  executor.py       sandboxed command execution
parsers/
  sarif.py          SARIF v2.1.0 → common finding schema + severity mapping
findings/
  normalizer.py     attach code context, fingerprints; bounded per-line context
  fingerprint.py    SHA256 cross-engine correlation fingerprints
  grouping.py       deterministic candidate grouping for AI batches
ai/
  provider.py       OpenAI-compatible HTTP client, retries, response shapes
  openai_compatible.py  gateway payload tolerance (multiple JSON shapes)
  prompts.py        validation prompt builder with anti-hallucination rules
  validator.py      per-group validation → CONFIRMED/LIKELY/…
  deduplicator.py   group → canonical F-001 + duplicate links
  analyzer.py       orchestration of validate/dedup/rewrite/risk stages
  checkpoint.py     incremental AI checkpoints (validation-partial.json, …)
  progress.py       AI stage dashboard (progress UI)
  error_report.py   ai/errors.json summarization
output/
  csv.py            final.csv writer (ingestion schema, cell sanitizing/clamping)
  json.py           raw-findings.json writer (audit trail)
tests/              pytest suites (unit + integration level)
```

## Scan pipeline (stages)

1. **Dependencies** — check/install OpenGrep + CodeQL at the pinned versions
   from `.env` into `~/.isast/`
2. **Source validation** — directory exists, readable, nonzero content
3. **Project detection** — languages (LOC table), manifests, build systems
4. **OpenGrep scan** — `scan --config auto --severity INFO` → SARIF (high recall)
5. **CodeQL scan** — per supported language: database create (sandboxed build
   when required) → security queries → SARIF. Python/JS/TS/Go/Ruby need no build
6. **Normalization** — SARIF → `Finding` (scanner, rule, file/line, severity),
   code context, SHA256 fingerprint, deterministic candidate grouping
7. **AI analysis** — validate candidates, deduplicate groups, rewrite titles/
   descriptions, recommend severity (never overwrites `scanner_severity`)
8. **Reports** — `final.csv` (ingestion schema) + `raw-findings.json` (audit)

Each stage checkpoints into `state.json`; per-language CodeQL and per-group AI
results checkpoint individually so `--resume` skips completed work.

## Scan workspace

Each scan builds `/tmp/isast/<scan-id>/` (`$ISAST_WORKDIR`):

```text
<scan-id>/
  metadata.json     source, report path, timestamps, versions
  detection.json    language/manifest/build detection results
  state.json        stage checkpoints (atomic, fail-open on corrupt)
  raw/              SARIF output per engine/language — primary debugging artifact
  normalized/       normalized findings + fingerprints
  ai/               validation.json, validation-partial.json, dedup.json
  reports/          copies of final.csv and raw-findings.json
```

- Deleted after a successful scan unless `--keep-workdir`.
- Kept after a failed/interrupted scan — `python isast.py --resume` reopens it.
- A kept workspace with `raw/` populated is the primary debugging artifact
  when scanner output looks wrong.
- **Do not defeat the checkpoint path**: `state.json` and AI partial files are
  always written atomically (`write_json_atomic`) and loaded fail-open
  (corrupt file → re-run the stage, never raise).

## Hard invariants (do not violate)

| Invariant | Detail |
|-----------|--------|
| Raw evidence survives | AI never deletes raw scanner evidence; `raw-findings.json` holds everything with its AI verdict |
| AI fail-open | AI failures leave findings `UNPROCESSED`; the scan still emits `final.csv` (exit 5) |
| No shell strings | Subprocess calls take argv arrays and timeouts; never pass repository-controlled input through a shell |
| Severity separation | `scanner_severity` is preserved verbatim; the AI produces a separate `ai_severity` |
| Pinned engines | Versions from `.env`; binaries owned in `~/.isast/`; no auto-upgrade during scans |
| Sandboxed builds | Builds run in `sandbox/`; no sandbox + required build ⇒ fail safe (`--allow-unsafe-build` is the only escape hatch) |
| Bounded output | Code context and CSV cells are clamped (`core/textclamp.py`) so minified single-line sources can never break prompts or spreadsheets |
| Normal-user CLI | No `--language`/`--opengrep-config`/`--codeql-language` flags; AI secrets never in argv |

## AI validation statuses

`CONFIRMED`, `LIKELY`, `INSUFFICIENT_EVIDENCE`, `FALSE_POSITIVE` — plus
`UNPROCESSED` when the AI never reached the finding (fail-open path). Only
`CONFIRMED` rows with a CRITICAL/HIGH/MEDIUM/LOW risk reach `final.csv`.

Prompts embed the anti-hallucination rules (blueprint §24): never claim
exploitation without evidence, never invent files/functions, never change
scanner evidence, say `INSUFFICIENT_EVIDENCE` when evidence is thin.

## Fingerprints vs. AI deduplication

`findings/fingerprint.py` SHA256 fingerprints are **cross-engine
correlation** only (same finding reported by OpenGrep and CodeQL). They are
not the AI's group-level deduplication decision, which happens on candidate
groups and produces canonical ids (`F-001`).