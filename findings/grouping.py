"""Candidate grouping (blueprint section 21).

Deterministic pre-AI bucketing: same file + nearby line + same/similar CWE +
same sink class → one candidate group, so AI calls scale with distinct logic
spots rather than raw finding count (1,000 findings → ~250 groups).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from core.models import Finding

NEARBY_LINE_WINDOW = 25

# Sink classes collapse rule ids that target the same dangerous APIs.
SINK_PATTERNS: List[Tuple[str, str]] = [
    ("sql", ("sql", "sqli", "injection-sql", "execute", "query")),
    ("command", ("command", "rce", "shell", "exec", "system")),
    ("path", ("path", "traversal", "file", "read", "write", "open")),
    ("xss", ("xss", "html", "reflected", "dom", "innerhtml")),
    ("ssrf", ("ssrf", "request", "urllib", "fetch", "http")),
    ("deserialization", ("deserial", "unmarshal", "pickle", "yaml.load")),
    ("crypto", ("crypto", "hash", "cipher", "weak", "md5", "sha1")),
    ("auth", ("auth", "session", "jwt", "token", "cookie", "password")),
]


def sink_class(rule_id: str) -> str:
    """Map a rule id to a coarse sink class."""
    rule_lower = rule_id.lower()
    for class_name, keywords in SINK_PATTERNS:
        for keyword in keywords:
            if keyword in rule_lower:
                return class_name
    return "other"


@dataclass
class CandidateGroup:
    """A deterministic bucket of likely-related findings."""

    key: str
    findings: List[Finding] = field(default_factory=list)

    def finding_ids(self) -> List[str]:
        return [f.finding_id for f in self.findings]

    def primary(self) -> Finding:
        """Highest scanner severity becomes the group's payload representative."""
        order = {"CRITICAL": 0, "HIGH": 1, "ERROR": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5, "WARNING": 6}
        return sorted(self.findings, key=lambda f: order.get(f.scanner_severity.upper(), 9))[0]


class CandidateGrouper:
    """Bucket findings with deterministic signals before AI analysis."""

    def group(self, findings: List[Finding]) -> List[CandidateGroup]:
        buckets: Dict[str, List[Finding]] = {}
        for finding in findings:
            buckets.setdefault(self._key(finding), []).append(finding)
        groups = [CandidateGroup(key=key, findings=members) for key, members in buckets.items()]
        # Stable ordering for reproducible AI batching.
        groups.sort(key=lambda g: (g.primary().file, g.primary().line, g.key))
        return groups

    @staticmethod
    def _key(finding: Finding) -> str:
        cwe = (finding.cwe or "nocwe").upper()
        return f"{finding.file}|{_line_band(finding.line)}|{cwe}|{sink_class(finding.rule_id)}"


def _line_band(line: int, window: int = NEARBY_LINE_WINDOW) -> int:
    return max(0, line) // window