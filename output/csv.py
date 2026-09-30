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
from typing import List, Optional

from core.models import CanonicalFinding
from core.textclamp import clamp_text

# Excel, LibreOffice and Google Sheets silently truncate/break cells beyond
# 32,767 characters; keep every cell under it no matter what the source is.
MAX_CELL_CHARS = 32000


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