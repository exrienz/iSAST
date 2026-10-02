"""final.csv writer (blueprint section 29).

Columns are for downstream ingestion into ThreatVault/CodXprt: only AI-
CONFIRMED findings with a CRITICAL/HIGH/MEDIUM/LOW risk survive, in the
fixed ingestion schema (cve/host/port/vpr_score left empty). Content is
JSON-safe sanitized (quotes escaped by csv module; embedded newlines are
preserved — QUOTE_ALL makes multi-line cells safe for spreadsheet and
ingestion tooling) and every cell is clamped below the 32,767-character
Excel/Sheets cell limit.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List, Optional, Tuple

from core.models import CanonicalFinding
from core.textclamp import clamp_text

# Excel, LibreOffice and Google Sheets silently truncate/break cells beyond
# 32,767 characters; keep every cell under it no matter what the source is.
MAX_CELL_CHARS = 32000


class ReportReadError(Exception):
    """A report CSV could not be read back in iSAST's own format."""


def sanitize_cell(value: Optional[str]) -> str:
    """Normalize line endings, clamp control characters and cap cell length.

    Newlines are preserved (the evidence block is structured multi-line) —
    quoting=QUOTE_ALL makes them safe for spreadsheet ingestion.
    """
    if value is None:
        return ""
    text = str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(ch for ch in text if ch in "\t\n" or (ord(ch) >= 32))
    return clamp_text(text, MAX_CELL_CHARS)


class CSVWriter:
    """Emit the deduplicated canonical findings as ThreatVault-ready CSV."""

    def write(self, target: Path, findings: List[CanonicalFinding], host: Optional[str] = None) -> Path:
        """Write the CSV; *host* (when given) fills the host column of every row."""
        target.parent.mkdir(parents=True, exist_ok=True)
        host_idx = CanonicalFinding.CSV_COLUMNS.index("host")
        with target.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle, quoting=csv.QUOTE_ALL)
            writer.writerow(CanonicalFinding.CSV_COLUMNS)
            for finding in sorted(findings, key=lambda f: (f.canonical_id,)):
                row = [sanitize_cell(cell) for cell in finding.csv_row()]
                if host is not None:
                    row[host_idx] = sanitize_cell(host)
                writer.writerow(row)
        return target


def write_report(target: Path, rows: List[List[str]], header: Optional[List[str]] = None) -> Path:
    """Write raw rows in the final.csv format, preserving the given row order.

    Used by retest, where kept rows must survive unchanged (CSVWriter always
    sorts by canonical_id and derives rows from findings — neither applies
    here). Cells still pass through sanitize_cell; on cells produced by
    csv.writer itself that is the identity, so the output is byte-identical
    while guaranteeing the retest output matches the report schema. The write
    is atomic (temp file + replace) so an interrupted write never truncates
    an existing report — retest may legitimately write over its own input.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle, quoting=csv.QUOTE_ALL)
            writer.writerow(header if header is not None else CanonicalFinding.CSV_COLUMNS)
            for row in rows:
                writer.writerow([sanitize_cell(cell) for cell in row])
        tmp.replace(target)
    finally:
        tmp.unlink(missing_ok=True)
    return target


def read_report(path: Path) -> Tuple[List[str], List[List[str]]]:
    """Read a report CSV exactly as CSVWriter produced it: header + data rows.

    Cells are returned verbatim (no re-sanitizing) so verification and
    byte-for-byte row preservation see exactly what the writer emitted.
    """
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            try:
                header = next(reader)
            except StopIteration as exc:
                raise ReportReadError(f"{path}: empty report (no header row)") from exc
            rows = [row for row in reader]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise ReportReadError(f"{path}: {exc}") from exc
    if header != CanonicalFinding.CSV_COLUMNS:
        raise ReportReadError(
            f"{path}: unexpected header (expected {CanonicalFinding.CSV_COLUMNS})"
        )
    return header, rows