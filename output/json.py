"""raw-findings.json writer (blueprint section 30).

Audit trail: every raw scanner finding with its scanner evidence, AI result
and canonical mapping — nothing is ever deleted by the AI layer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from core.models import Finding, ValidationResult, ValidationStatus


def findings_payload(
    findings: List[Finding],
    ai_results: Dict[str, ValidationResult],
    canonical_map: Dict[str, str],
) -> List[Dict]:
    """Attach AI results and canonical ids to the raw evidence."""
    payload: List[Dict] = []
    for finding in findings:
        short_id = finding.finding_id[:8]
        result = ai_results.get(short_id)
        payload.append(
            {
                "finding_id": finding.finding_id,
                "scanner": finding.scanner,
                "rule_id": finding.rule_id,
                "language": finding.language,
                "file": finding.file,
                "line": finding.line,
                "column": finding.column,
                "scanner_title": finding.scanner_title,
                "scanner_message": finding.scanner_message,
                "scanner_severity": finding.scanner_severity,
                "cwe": finding.cwe,
                "fingerprint": finding.fingerprint,
                "ai_status": (result.status.value if result else ValidationStatus.UNPROCESSED.value),
                "ai_confidence": (result.confidence if result else None),
                "ai_reason": (result.reason if result else None),
                "ai_severity": (result.ai_severity if result else None),
                "canonical_id": canonical_map.get(short_id),
            }
        )
    return payload


class JSONWriter:
    """Write raw-findings.json."""

    def write(self, target: Path, entries: List[Dict]) -> Path:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            json.dump(entries, handle, indent=2, default=str)
        return target