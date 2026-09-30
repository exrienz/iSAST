# Changelog

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