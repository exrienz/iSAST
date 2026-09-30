# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

iSAST is a zero-configuration, CLI-first SAST orchestrator combining OpenGrep
(broad multi-language SAST), CodeQL (deep semantic data-flow analysis), an
AI analysis layer (OpenAI-compatible), and CSV/JSON reporting for
ThreatVault/CodXprt ingestion. Spec: `blueprint.txt` (authoritative).

## Commands

```bash
python isast.py --source=/path --report=final.csv   # primary UX
python isast.py --doctor                            # diagnostics
python isast.py --update --non-interactive          # install engines
python -m pytest tests/ -q                          # test suite
```

Exit codes per blueprint §37: 0 complete, 1 runtime, 2 bad args, 3 deps,
4 bad source, 5 partial scan.

## Architecture Rules (do not violate)

- **iSAST is deterministic orchestration; AI is the analysis layer.**
  AI must never delete raw scanner evidence. `raw-findings.json` always
  contains every OpenGrep/CodeQL finding with its AI verdict.
- **AI fail-open**: any AI failure leaves findings `UNPROCESSED` and the scan
  still emits `final.csv` (exit 5).
- **No shell strings**: all subprocess calls take argv arrays and timeouts
  (`core/executor.py`). Never pass repository-controlled input through a shell.
- **Scanner severities are never overwritten** — `scanner_severity` is
  preserved; the AI produces a separate `ai_severity` (blueprint §27).
- **Engines are pinned and owned**: versions come from `.env`
  (`OPENGREP_VERSION`, `CODEQL_VERSION`), binaries live in `~/.isast/`,
  and scans never auto-upgrade engines.
- **Builds are sandboxed** (`sandbox/`): if no sandbox is available and a
  required build cannot run, iSAST fails safe — no silent host builds, only
  an explicit `--allow-unsafe-build` escape hatch. Python/JS/TS/Go/Ruby
  CodeQL extraction needs no build at all (blueprint §17).
- **CLI surface stays normal-user friendly**: no `--language`,
  `--opengrep-config`, `--codeql-language` etc. (blueprint §5); detection is
  automatic. AI secrets come from `.env`/environment, never argv (§36).

## Code Conventions

- Plain stdlib dataclasses in `core/models.py`; only three runtime deps
  (`python-dotenv`, `requests`, `PyYAML`) per blueprint §38.
- Files stay small and focused; errors surface with context, never silently.
- Fingerprints (`findings/fingerprint.py`) are for cross-engine correlation
  only — NOT the same as AI deduplication.
- AI prompts embed the anti-hallucination rules (blueprint §24) via
  `ai/prompts.py`. Validation statuses: CONFIRMED, LIKELY,
  INSUFFICIENT_EVIDENCE, FALSE_POSITIVE.

## Workspaces

Each scan builds `/tmp/isast/<scan-id>/` with
`metadata.json`, `detection.json`, `state.json` (stage checkpoints),
`raw/` (SARIF per engine/language), `normalized/`,
`ai/` (plus incremental `validation-partial.json` and `dedup.json`
checkpoints), `reports/`; it is deleted after success unless
`--keep-workdir` is passed. A kept workspace with `raw/` populated is the
primary debugging artifact for scanner issues.

Failed or interrupted scans keep the workspace, and `python isast.py
--resume [SCAN_ID]` reopens it: completed stages (per-language for CodeQL)
and already-validated AI groups are skipped without model calls.
Do not defeat the checkpoint/resume path — `state.json` and the AI partial
files must always be written atomically (`write_json_atomic`) and loaded
fail-open (corrupt → re-run the stage, never raise).