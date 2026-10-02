# Changelog

## Unreleased

- Env var rename: `AI_BASE_URL` → `LLM_PROVIDER`, `AI_API_KEY` → `LLM_KEY`,
  `AI_MODEL` → `LLM_MODEL`. Update existing `.env` files; no code change
  required otherwise.
- `tv2csv.py` (ThreatVault export → VAPT CSV): reads `THREATVAULT_BASEURL`
  and `THREATVAULT_KEY` from `.env` (script dir, then cwd); `--url`/`--token`
  flags still take precedence.
- Retest mode: `python isast.py --source=X --rescan_report=old.csv
  --output=clean.csv --retest` re-verifies a previous report against the
  current source without running engines or AI. Rows whose flagged code is
  still present are written unchanged; code-gone/unreadable/unparseable
  rows are removed. New `read_report`/`write_report` in `output/csv.py`; the
  matching is whitespace-insensitive with a ±10-line drift window and a
  specificity-gated whole-file fallback (`retest/`).

## 1.0.0 — 2026-09-30

Initial release.

- 8-stage scan pipeline: OpenGrep (recall-favored) + CodeQL (deep
  data-flow), automatic language/manifest/build detection, sandboxed builds
- AI layer (OpenAI-compatible gateway): validation, deduplication, rewrite,
  severity recommendation — fail-open, never deletes raw scanner evidence
- `final.csv` ThreatVault/CodXprt ingestion schema (9 fixed columns, UTF-8
  BOM, QUOTE_ALL) + `raw-findings.json` audit trail
- Structured evidence block:
  `Affected File: <path>` / `Affected Line: x - x` / blank line / snippet
- Bounded output: oversized minified-bundle lines are clamped at extraction
  and every CSV cell is capped under the Excel 32,767-char cell limit
- `--repo=project/path[:ref]` stamps the host column of every CSV row
- Checkpoint/resume: stage, per-language CodeQL and per-group AI checkpoints;
  `python isast.py --resume [SCAN_ID]` skips completed work
- Engine pinning in `.env`, binaries owned under `~/.isast/`, sha256-verified
  downloads
- Exit codes per blueprint §37 (0/1/2/3/4/5)