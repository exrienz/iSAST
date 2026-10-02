"""Finding normalizer (blueprint sections 18-20).

Takes SARIF-parsed findings from all engines, attaches code context,
computes fingerprints and produces Finding objects. Raw scanner evidence is
preserved verbatim; normalization never drops findings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from core.models import Finding
from core.textclamp import clamp_text
from findings.fingerprint import fingerprint as compute_fingerprint
from parsers.sarif import normalize_severity

MAX_CONTEXT_LINES = 60
# Minified bundles are one physical line and can be hundreds of KB; clamping
# here bounds the AI prompt, canonical evidence and CSV cells downstream
# (raw scanner evidence in raw/ and message/file/line stay untouched).
MAX_CONTEXT_LINE_CHARS = 2000


class FindingNormalizer:
    """Build Finding objects from SARIF payloads of any engine."""

    def __init__(self, settings) -> None:
        self.settings = settings
        self.context_lines = settings.ai_context_lines

    def normalize(
        self,
        parsed_findings: List[Dict],
        source_root: Path,
        scanner_by_rule: Optional[Dict[str, str]] = None,
    ) -> List[Finding]:
        scanner_by_rule = scanner_by_rule or {}
        findings: List[Finding] = []
        for parsed in parsed_findings:
            normalized = self._normalize_one(parsed, source_root, scanner_by_rule)
            if normalized is not None:
                findings.append(normalized)
        return findings

    def _normalize_one(
        self, parsed: Dict, source_root: Path, scanner_by_rule: Dict[str, str]
    ) -> Optional[Finding]:
        file_path = str(parsed.get("file") or "")
        line = int(parsed.get("line") or 0)
        if not file_path:
            return None
        # Explicit scanner tag wins; scanner_by_rule lets the orchestrator
        # correct per-file attribution when engines overlap.
        scanner = parsed.get("scanner") or scanner_by_rule.get(file_path) or "unknown"
        absolute = source_root / file_path
        code_context = self._extract_context(absolute, line)
        severity = normalize_severity(str(parsed.get("scanner_severity") or "INFO"))
        finding = Finding(
            scanner=scanner,
            rule_id=str(parsed.get("rule_id") or "unknown"),
            language=str(parsed.get("language") or "unknown"),
            file=file_path,
            line=line,
            column=int(parsed.get("column") or 0),
            end_line=int(parsed.get("end_line") or 0),
            scanner_title=str(parsed.get("scanner_title") or parsed.get("rule_id") or "Unknown"),
            scanner_message=str(parsed.get("scanner_message") or ""),
            scanner_severity=severity,
            cwe=parsed.get("cwe"),
            code_context=code_context,
        )
        finding.fingerprint = compute_fingerprint(
            {
                "rule_id": finding.rule_id,
                "file": finding.file,
                "line": finding.line,
                "column": finding.column,
            },
            source_root,
        )
        return finding

    def _extract_context(self, absolute_path: Path, line: int) -> Dict[str, str]:
        """before/target/after window for the AI (blueprint section 22)."""
        context: Dict[str, str] = {"before": "", "target": "", "after": ""}
        try:
            if not absolute_path.exists():
                return context
            text = absolute_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return context
        lines = text.splitlines()
        index = max(0, (line or 1) - 1)
        half = self.context_lines
        before = "\n".join(lines[max(0, index - half) : index])
        target = lines[index] if index < len(lines) else ""
        after = "\n".join(lines[index + 1 : index + 1 + half])
        return {
            "before": clamp_text(before, MAX_CONTEXT_LINE_CHARS),
            "target": clamp_text(target, MAX_CONTEXT_LINE_CHARS),
            "after": clamp_text(after, MAX_CONTEXT_LINE_CHARS),
        }


def to_json(findings: List[Finding]) -> List[Dict]:
    return [finding.to_dict() for finding in findings]