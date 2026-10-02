# iSAST CLI Reference

```bash
python isast.py [command flags]
```

## Scan flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--source` | path | — | Source directory to scan (required unless `--resume`) |
| `--report` | path | — | Path of the `final.csv` report to write (required unless `--resume`) |
| `--repo` | string | — | Repository locator, e.g. `org/project/app:main`. Written into the `host` column of every CSV row. Validated as `project/path[:ref]` |
| `--threads` | int | `4` | Scanner parallelism |
| `--timeout` | int | `3600` | Scan timeout (seconds) |
| `--workdir` | path | `$ISAST_WORKDIR` | Override the scan working directory |
| `--config` | path | — | Optional YAML config file (`.env` values take priority) |
| `--resume` | `[SCAN_ID]` | — | Resume an interrupted scan; no value resumes the most recent resumable workspace |
| `--keep-workdir` | flag | off | Keep the per-scan workspace for auditing |
| `--allow-unsafe-build` | flag | off | Trusted repos only: run required builds on the host when no sandbox is available |
| `--retest` | flag | off | Retest mode: re-verify an existing report instead of scanning |
| `--rescan_report` (`--rescan-report`) | path | — | Previous report CSV whose findings are re-verified (required by `--retest`) |
| `--output` | path | — | Cleaned report written by retest (required by `--retest`) |

## Behaviour flags

| Flag | Description |
|------|-------------|
| `--verbose` | Detailed progress output |
| `--quiet` | Suppress non-essential output (mutually exclusive with `--verbose`) |
| `--offline` | Never download anything; fail if engines are missing |
| `--non-interactive` | Never prompt — CI/CD mode |
| `--update` | Install/refresh the pinned engine versions |
| `--version` | Print the iSAST version |
| `--doctor` | Diagnose installation: engines, Python version, AI connectivity |

## Exit codes (blueprint §37)

| Code | Meaning |
|------|---------|
| `0` | Scan complete, report written |
| `1` | Runtime failure |
| `2` | Invalid arguments (includes a malformed `--repo`) |
| `3` | Dependency installation failure |
| `4` | Invalid source |
| `5` | Partial scan (AI stage failed or some engines failed; findings survive) |

Finding severity never influences the exit code — gating severity belongs to
the CI/CD policy layer, not the scanner.

## Examples

```bash
# Basic scan with AI analysis (settings from .env)
python isast.py --source=~/projects/app --report=final.csv

# Scan a repo and tag the report with its locator
python isast.py --source=~/projects/sso-v3 --report=sso-v3.csv \
  --repo=org/project/app:main

# CI/CD: never prompt, never download, fail fast on missing engines
python isast.py --source=. --report=final.csv \
  --non-interactive --offline --timeout=1800

# Keep the workspace for debugging scanner issues
python isast.py --source=. --report=final.csv --keep-workdir

# Resume after a crash
python isast.py --resume                  # most recent resumable
python isast.py --resume scan-a7112f100f60

# Retest: after a remediation pass, drop findings whose code is gone.
# Reads --rescan_report row by row, verifies the flagged code still exists
# under --source, copies surviving rows unchanged to --output.
python isast.py --source=code/ --rescan_report=cccc.csv --output=xxxx.csv --retest

# Diagnostics
python isast.py --doctor
```

## Retest mode

`--retest` is a lightweight report-cleanup mode — no engines, no AI, no
workspace, no `.env`. It cannot create or delete findings, only retire the
ones whose flagged code is gone:

- Each row's `evidence` cell (`Affected File:` / `Affected Line:` + snippet)
  is matched against the current file under `--source`, whitespace-
  insensitive and tolerant of small line drift (±10 lines) from unrelated
  edits above the finding.
- Rows still present are copied **byte-for-byte unchanged**; the file may
  be re-tagged with `--repo` (host column) but no other cell is touched.
- Rows whose code no longer matches, whose file is gone/unreadable, or
  whose evidence cannot be parsed are **removed** (aggressive cleanup).
- Reports produced by very old iSAST versions with a different evidence
  format verify as unparseable and will be emptied — regenerate them first.
- When a finding's evidence snippet is a scanner *message* rather than code
  (no code context was available at scan time), the text cannot appear in
  the source file — such rows verify as absent and are removed, even though
  the flagged code may still exist. Re-run a full scan for those.
- Because matching is by code text, a finding that remains but whose sink
  body was refactored keeps its first line in the report (`--retest` proves
  the *code* is present, not that the vulnerability is still live).
- `--threads`/`--timeout`/`--workdir` are ignored; exit codes are limited
  to `0` (complete), `1` (write failure), `2` (invalid arguments, including
  `--report` or `--resume` together with `--retest`) and `4` (missing
  `--source` or `--rescan_report`).

## CLI surface policy (blueprint §5)

There are deliberately **no** `--language`, `--opengrep-config` or
`--codeql-language` flags: language and configuration detection is automatic.
AI secrets never travel through argv (blueprint §36) — they come from
`.env`/environment.