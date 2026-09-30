# final.csv — Ingestion Schema

`final.csv` is written for downstream ingestion into ThreatVault/CodXprt.
Encoding is UTF-8 **with BOM** (`utf-8-sig`), every field is quoted
(`QUOTE_ALL`), and rows are sorted by canonical id.

## Columns (fixed 9)

| # | Column | Contents |
|---|--------|----------|
| 1 | `cve` | Empty (reserved for future CVE mapping) |
| 2 | `risk` | Final severity: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| 3 | `host` | Repository locator from `--repo` (e.g. `paynet-login/applications/sso-v3:master`); blank when `--repo` is not provided |
| 4 | `port` | Empty (reserved) |
| 5 | `name` | Finding title (AI title when present, else scanner title) |
| 6 | `description` | Professional description grounded only in the shown evidence |
| 7 | `remediation` | Recommended fix |
| 8 | `evidence` | Structured evidence block — see below |
| 9 | `vpr_score` | Empty (reserved) |

## Which findings reach final.csv

- Only `CONFIRMED` findings (LIKELY / UNPROCESSED / FALSE_POSITIVE stay in
  `raw-findings.json` only)
- Only final risk in `CRITICAL/HIGH/MEDIUM/LOW` (INFO-severity rows are dropped)
- Deduplicated: one row per canonical finding (`F-001`), with duplicates
  linked in `raw-findings.json`

## Evidence block format

```text
Affected File: <file path, repo-relative>
Affected Line: <start> - <end>
                          ← blank line
<code snippet>
```

Example:

```text
Affected File: src/presentation/html/templates/layouts/master.html
Affected Line: 59 - 59

<!--<script src="https://cdn.datatables.net/2.3.2/js/dataTables.js"></script>-->
```

- The line range is the scanner's start line through the snippet's last line.
- When no snippet is available, the scanner message is used as the snippet.
- Newlines inside the evidence cell are real newlines; `QUOTE_ALL` quoting
  makes this safe for Excel/LibreOffice/Google Sheets and standard CSV parsers.

## Cell sanitization and clamping

Every cell passes through the writer's sanitizer (`output/csv.py`):

- `\r\n`/`\r` normalized to `\n`; control characters removed (tab kept)
- Any cell longer than **32,000 characters** is clamped head+tail with an
  `…[truncated +N chars]` marker — this keeps the file under the 32,767-char
  per-cell limit of Excel/LibreOffice/Google Sheets
- Code context snippets are additionally clamped at extraction time
  (`findings/normalizer.py`, 2,000 chars per context field), so minified
  single-line bundles (a whole JS bundle on one physical line) cannot blow up
  evidence cells or AI prompts

Raw scanner evidence is never altered by any of this — `raw-findings.json`
and the workspace `raw/` SARIF files always hold the complete scanner output.

## Companions

- **`raw-findings.json`** — every raw finding, with `ai_status`,
  `canonical_id`, engine attribution and full code context. Written next to
  `final.csv` (and to the workspace `reports/` directory when
  `--keep-workdir` is used).

## Host column

Pass `--repo=project/path[:ref]` to stamp the repository locator into the
`host` column of every row:

```bash
python isast.py --source=. --report=final.csv \
  --repo=paynet-login/applications/sso-v3:master
```

Validation: `project/path[:ref]`, word characters plus `. - _ / :`.
Invalid values are rejected at argument parsing (exit code 2), before any
scan starts.