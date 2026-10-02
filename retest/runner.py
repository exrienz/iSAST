"""Retest orchestration: filter a previous report down to the findings whose
code still exists under --source, without changing any kept cell.

This is a report-cleanup stage, not a scan: no engines, no AI, no workspace,
no .env. Kept rows are written exactly as read (retest never re-derives or
reorders them); the CSV reader in output/csv.py owns the format.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from core.models import CanonicalFinding
from output.csv import read_report, write_report
from retest.verify import finding_exists, parse_evidence


@dataclass(frozen=True)
class RetestOptions:
    source: Path
    rescan_report: Path
    output: Path
    repo: Optional[str] = None  # None -> preserve each row's host cell as read


@dataclass(frozen=True)
class RetestResult:
    read: int  # data rows in the rescan report
    kept: int
    removed_absent: int  # file missing/unreadable or code no longer present
    removed_unparseable: int  # ragged row or unparseable evidence cell
    output_path: Path


def run_retest(options: RetestOptions) -> RetestResult:
    """Verify every row of the rescan report and write the cleaned output.

    Raises output.csv.ReportReadError (propagated to the CLI) when the
    rescan report is unreadable or not in iSAST's own format.
    """
    header, rows = read_report(options.rescan_report)
    expected = len(CanonicalFinding.CSV_COLUMNS)
    host_idx = CanonicalFinding.CSV_COLUMNS.index("host")
    evidence_idx = CanonicalFinding.CSV_COLUMNS.index("evidence")

    file_cache: Dict[Path, List[str]] = {}
    kept: List[List[str]] = []
    removed_absent = removed_unparseable = 0
    for row in rows:
        if len(row) != expected:
            removed_unparseable += 1
            continue
        ref = parse_evidence(row[evidence_idx])
        if ref is None:
            removed_unparseable += 1
            continue
        if not finding_exists(ref, options.source, file_cache):
            removed_absent += 1
            continue
        out_row = list(row)
        if options.repo is not None:
            out_row[host_idx] = options.repo
        kept.append(out_row)

    write_report(options.output, kept, header)
    return RetestResult(
        read=len(rows),
        kept=len(kept),
        removed_absent=removed_absent,
        removed_unparseable=removed_unparseable,
        output_path=options.output,
    )