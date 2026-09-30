# iSAST CLI Reference

```bash
python isast.py [command flags]
```

## Scan flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--source` | path | — | Source directory to scan (required unless `--resume`) |
| `--report` | path | — | Path of the `final.csv` report to write (required unless `--resume`) |
| `--repo` | string | — | Repository locator, e.g. `paynet-login/applications/sso-v3:master`. Written into the `host` column of every CSV row. Validated as `project/path[:ref]` |
| `--threads` | int | `4` | Scanner parallelism |
| `--timeout` | int | `3600` | Scan timeout (seconds) |
| `--workdir` | path | `$ISAST_WORKDIR` | Override the scan working directory |
| `--config` | path | — | Optional YAML config file (`.env` values take priority) |
| `--resume` | `[SCAN_ID]` | — | Resume an interrupted scan; no value resumes the most recent resumable workspace |
| `--keep-workdir` | flag | off | Keep the per-scan workspace for auditing |
| `--allow-unsafe-build` | flag | off | Trusted repos only: run required builds on the host when no sandbox is available |

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
  --repo=paynet-login/applications/sso-v3:master

# CI/CD: never prompt, never download, fail fast on missing engines
python isast.py --source=. --report=final.csv \
  --non-interactive --offline --timeout=1800

# Keep the workspace for debugging scanner issues
python isast.py --source=. --report=final.csv --keep-workdir

# Resume after a crash
python isast.py --resume                  # most recent resumable
python isast.py --resume scan-a7112f100f60

# Diagnostics
python isast.py --doctor
```

## CLI surface policy (blueprint §5)

There are deliberately **no** `--language`, `--opengrep-config` or
`--codeql-language` flags: language and configuration detection is automatic.
AI secrets never travel through argv (blueprint §36) — they come from
`.env`/environment.