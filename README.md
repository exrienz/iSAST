# iSAST

**iSAST** is a zero-configuration, CLI-first SAST orchestrator that combines:

- **OpenGrep** — broad, multi-language SAST and taint analysis
- **CodeQL** — deeper semantic / data-flow analysis
- **AI analysis** — finding validation, normalization, deduplication, severity refinement and professional wording
- **CSV/JSON reporting** — designed for downstream ingestion into ThreatVault/CodXprt

The primary UX is one command:

```bash
python isast.py --source=/path/to/source --report=final.csv
```

No manual language selection. No manual OpenGrep configuration. No manual CodeQL commands.

> The authoritative functional spec is `blueprint.txt` in the repository root.

---

## Documentation

| Document | Contents |
|----------|----------|
| [`docs/CLI-REFERENCE.md`](docs/CLI-REFERENCE.md) | Every flag, exit codes, usage examples |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module map, scan pipeline, workspace, resume, invariants |
| [`docs/CSV-SCHEMA.md`](docs/CSV-SCHEMA.md) | `final.csv` ingestion schema and evidence format |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | `.env`, YAML config, engine pinning, `--doctor` |

---

## Quickstart

```bash
pip install -r requirements.txt
cp .env.example .env            # set LLM_PROVIDER / LLM_KEY / LLM_MODEL
python isast.py --update        # install the pinned engines into ~/.isast/
python isast.py --doctor        # verify engines, Python and AI connectivity

python isast.py --source=/path/to/repo --report=final.csv
```

Add a repository locator so reports carry their origin:

```bash
python isast.py --source=/path/to/repo --report=final.csv \
  --repo=org/project/app:main
```

---

## Sample commands

Scan a source tree and write the findings report:

```bash
python3 isast.py --source=code/ --report=xxx.csv
```

Re-verify a previous report against the current source (`--retest`):
flagged code that no longer exists is dropped from `--output`; kept rows are
written unchanged, and no engines or AI calls run:

```bash
python3 isast.py --source=code/ --rescan_report=cccc.csv --output=xxxx.csv --retest
```

Download findings from ThreatVault and convert to the VAPT CSV (`tv2csv.py`,
requires `pip install polars`; base URL and token come from `.env`):

```bash
python3 tv2csv.py \
  --pluginid=<plugin-uuid> \
  --productid=<product-uuid> \
  --label=<label e.g. projectpulse/v2:master> \
  --output=cccc.csv
```

---

## Commands

| Command | Purpose |
|---------|---------|
| `python isast.py --source=X --report=final.csv` | Basic scan |
| `--repo=<locator>` | Tag every CSV row's `host` column with a repo locator |
| `--threads 8 --timeout 3600` | Advanced scan controls |
| `python isast.py --resume` | Resume the most recent interrupted scan |
| `python isast.py --resume <SCAN_ID>` | Resume a specific workspace |
| `python isast.py --source=X --rescan_report=old.csv --output=clean.csv --retest` | Re-verify a previous report; rows whose code is gone are dropped |
| `--doctor` | Diagnose engines, Python version and AI connectivity |
| `--update` | Install/refresh pinned engine versions |
| `--version` | Print version |
| `--offline` | Never download anything (engines must already be installed) |
| `--non-interactive` | CI/CD mode: never prompt |
| `--keep-workdir` | Keep the per-scan workspace for audit |
| `--allow-unsafe-build` | Trusted repos only: run required builds on host without sandbox |
| `python tv2csv.py --pluginid=… --productid=… --label=… --output=x.csv` | Fetch ThreatVault findings export → VAPT CSV (uses `THREATVAULT_BASEURL` / `THREATVAULT_KEY` from `.env`) |

Exit codes: `0` complete, `1` runtime failure, `2` invalid arguments,
`3` dependency installation failure, `4` invalid source, `5` partial scan.
Finding severity never changes the exit code — that belongs to the CI/CD
policy layer.

---

## Output

Each scan writes two artifacts next to `--report`:

- **`final.csv`** — deduplicated, AI-validated findings in the fixed
  9-column ThreatVault/CodXprt ingestion schema (see
  [`docs/CSV-SCHEMA.md`](docs/CSV-SCHEMA.md))
- **`raw-findings.json`** — every raw OpenGrep/CodeQL finding with its AI
  verdict; the full, unsanitized audit trail

Cell sizes are clamped and quoting is explicit, so the CSV always opens
cleanly in Excel/LibreOffice/Google Sheets.

---

## ThreatVault export

`tv2csv.py` fetches findings from a ThreatVault/DefectDojo-style export API
and writes them in the same VAPT CSV schema (9 quoted columns, CRLF):

```bash
pip install polars    # tv2csv-only dependency, not needed by iSAST itself
```

Full runnable example: see [Sample commands](#sample-commands). Flags:
`--pluginid`, `--productid`, `--label`, `--output` (all required).

Optional flags: `--status=NEW,OPEN` (default), `--url=<base url>`,
`--token=<api token>`.

The base URL and API token resolve from `.env` (script directory first, then
cwd) so they never appear on a command line:

```env
THREATVAULT_BASEURL=http://localhost:8000
THREATVAULT_KEY=<token>
```

Resolution order: `--token` flag > `THREATVAULT_KEY` env > `.env`; `--url`
flag > `THREATVAULT_BASEURL` env > `.env` > `http://localhost:8000`.

---

## Architecture

```text
isast.py (CLI)
   → Dependency Manager (OpenGrep, CodeQL; pinned versions in ~/.isast)
   → Source Analyzer (language + manifest + build detection)
   → OpenGrep (multi-language, high recall) ─┐
   → CodeQL (per-language deep SAST) ────────┤→ SARIF Parser
                                              → Normalizer → Fingerprinting
   (build required? → build sandbox)          → Candidate grouping
                                              → AI analyzer (validate/dedup/rewrite/risk)
                                              → final.csv + raw-findings.json
```

**iSAST is deterministic scanning + orchestration. AI is the analysis layer.**
AI never deletes raw findings: `raw-findings.json` always proves what
OpenGrep/CodeQL originally reported, and separately what the AI decided.

### Application structure

```text
core/        scanner, executor, dependency, workspace, resources, models,
             settings, textclamp (bounded-snippet helpers)
detection/   language, manifest, build resolver
engines/     opengrep, codeql (+ rules/isast-baseline-security.yaml)
parsers/     SARIF v2.1.0 → common finding schema
findings/    normalizer, fingerprint, candidate grouping
builders/    maven, gradle, npm, go, cargo, cmake, dotnet
sandbox/     manager (docker/native/host decision), executor
ai/          provider (OpenAI-compatible), prompts, validator, deduplicator, analyzer
output/      final.csv / raw-findings.json writers
tests/       pytest suites
```

---

## Configuration

`.env` (see `.env.example`) — secrets and AI settings, **never CLI arguments**.
Only `LLM_PROVIDER`, `LLM_KEY` and `LLM_MODEL` change per provider — no code
change required (OpenAI-compatible `POST {BASE_URL}/chat/completions`).
Full variable reference: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

---

## Scan pipeline

1. Load `.env`, validate CLI
2. Check/install dependencies (OpenGrep, CodeQL)
3. Validate source
4. Detect languages, manifests and build systems (LOC table printed)
5. OpenGrep: `scan --config auto --severity INFO --sarif-output ...` (recall favored)
6. CodeQL: per supported language — database create (build via sandbox when required) → analyze security suite → SARIF
7. Normalize findings + SHA256 fingerprints + deterministic candidate grouping
8. AI: validation (`CONFIRMED/LIKELY/INSUFFICIENT_EVIDENCE/FALSE_POSITIVE`),
   deduplication (canonical `F-001` + duplicates), canonicalization, CWE/OWASP
   enrichment, severity recommendation
9. Write `final.csv` + `raw-findings.json` (AI never removes scanner evidence)

AI failure behavior: if the AI stage fails, the scan still produces
`final.csv` with `ai_status=UNPROCESSED` rows — raw findings always survive
(exit code `5`, partial).

---

## Python scans need no build

Python (and JS/TS/Go/Ruby) CodeQL extraction is source-only — no project build,
no sandbox, no Java/Node/Go toolchain needed by iSAST itself. Builds are only
required for compiled/managed runtimes (Java, Kotlin, C#, C/C++, Swift), and
there they run inside a sandbox (Docker with CPU/RAM/network limits, no host
credentials). If no sandbox is available iSAST **fails safe** — the build is
skipped, not silently run on the host.

---

## Development

```bash
pip install -r requirements.txt
python -m pytest tests/ -q          # full unit suite (191 tests)
python isast.py --doctor            # installation check
```

Requirements: Python 3.10+, three runtime dependencies (`python-dotenv`,
`requests`, `PyYAML`). Targets Ubuntu 22.04/24.04, Debian 12, RHEL 9 family,
and macOS (Intel/Apple Silicon).

---

## Security notes

- AI secrets come from `.env`/environment only — never CLI arguments
- All subprocess calls use argv arrays with timeouts (no shell strings)
- Builds are sandboxed; builds without a sandbox fail safe
- Raw scanner evidence is never overwritten or deleted by the AI layer