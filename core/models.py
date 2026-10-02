"""Internal data models for iSAST.

These are plain dataclasses (stdlib only) representing the entities that flow
through the scan pipeline: detection results, scanner findings, AI results and
canonical report rows.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ValidationStatus(str, Enum):
    """AI validation verdicts (blueprint section 23)."""

    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNPROCESSED = "UNPROCESSED"


@dataclass(frozen=True)
class LanguageInfo:
    """A detected language in the source tree."""

    name: str
    loc: int
    build_system: Optional[str] = None
    codeql_supported: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "loc": self.loc,
            "build_system": self.build_system,
            "codeql_supported": self.codeql_supported,
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "LanguageInfo":
        return cls(
            name=str(payload.get("name", "")),
            loc=int(payload.get("loc", 0) or 0),
            build_system=payload.get("build_system"),
            codeql_supported=bool(payload.get("codeql_supported", False)),
        )


@dataclass(frozen=True)
class DetectionResult:
    """Aggregate language/manifest detection output for a source tree."""

    languages: List[LanguageInfo] = field(default_factory=list)
    manifests: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def language_names(self) -> List[str]:
        return [lang.name for lang in self.languages]

    @property
    def codeql_languages(self) -> List[LanguageInfo]:
        return [lang for lang in self.languages if lang.codeql_supported]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "languages": [lang.to_dict() for lang in self.languages],
            "manifests": list(self.manifests),
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "DetectionResult":
        return cls(
            languages=[
                LanguageInfo.from_dict(lang)
                for lang in (payload.get("languages") or [])
                if isinstance(lang, dict)
            ],
            manifests=[m for m in (payload.get("manifests") or []) if isinstance(m, dict)],
        )


@dataclass(frozen=True)
class BuildPlan:
    """A resolved build execution plan.

    Blueprint section 15: commands are always argv arrays, never shell strings.
    """

    required: bool
    ecosystem: Optional[str] = None
    command: Optional[List[str]] = None
    language: Optional[str] = None
    manifest_path: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "required": self.required,
            "ecosystem": self.ecosystem,
            "command": list(self.command) if self.command else None,
            "language": self.language,
            "manifest_path": self.manifest_path,
            "reason": self.reason,
        }


@dataclass
class Finding:
    """Normalized scanner finding (blueprint section 19)."""

    scanner: str
    rule_id: str
    language: str
    file: str
    line: int
    column: int
    scanner_title: str
    scanner_message: str
    scanner_severity: str
    fingerprint: str = ""
    cwe: Optional[str] = None
    # End of the flagged region as reported by the engine (SARIF endLine).
    # 0 when unknown — canonical-build code falls back to the target-line span.
    end_line: int = 0
    code_context: Dict[str, str] = field(default_factory=dict)
    scanner_count: int = 1
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Short stable id used in AI payloads and logs."""
        return self.finding_id[:8]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "language": self.language,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "scanner_title": self.scanner_title,
            "scanner_message": self.scanner_message,
            "scanner_severity": self.scanner_severity,
            "fingerprint": self.fingerprint,
            "cwe": self.cwe,
            "end_line": self.end_line,
            "code_context": dict(self.code_context),
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Finding":
        """Rebuild a Finding from ``to_dict`` output (resume path).

        Keys the normalizer wrote are preserved verbatim, including the full
        ``finding_id`` — regrouping on resume must reproduce the exact same
        groups (and representative ids) as the original run. ``scanner_count``
        and ``extra`` are not persisted by ``to_dict`` and stay at defaults.
        """
        line = payload.get("line")
        column = payload.get("column")
        return cls(
            scanner=str(payload.get("scanner", "")),
            rule_id=str(payload.get("rule_id", "")),
            language=str(payload.get("language", "")),
            file=str(payload.get("file", "")),
            line=int(line) if line is not None else 0,
            column=int(column) if column is not None else 0,
            scanner_title=str(payload.get("scanner_title", "")),
            scanner_message=str(payload.get("scanner_message", "")),
            scanner_severity=str(payload.get("scanner_severity", "")),
            fingerprint=str(payload.get("fingerprint", "")),
            cwe=payload.get("cwe"),
            end_line=int(payload.get("end_line") or 0),
            code_context=dict(payload.get("code_context") or {}),
            finding_id=str(payload.get("finding_id") or str(uuid.uuid4())),
        )


@dataclass
class ValidationResult:
    """AI validation verdict for one finding or group."""

    finding_id: str
    status: ValidationStatus = ValidationStatus.UNPROCESSED
    confidence: float = 0.0
    reason: str = ""
    title: Optional[str] = None
    category: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    ai_severity: Optional[str] = None
    exploitability: Optional[str] = None
    impact: Optional[str] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class DedupLink:
    """A duplicates relationship returned by the AI deduplicator."""

    canonical_finding_id: str
    duplicates: List[str]
    reason: str = ""


@dataclass
class CanonicalFinding:
    """One deduplicated, AI-enriched row for final.csv (blueprint section 29)."""

    canonical_id: str
    title: str
    severity: str
    confidence: float
    language: str
    file: str
    line: int
    column: int
    category: str
    cwe: str
    owasp: str
    description: str
    recommendation: str
    exploitability: str
    impact: str
    scanner_count: int
    scanners: str
    validation_status: str
    duplicate_of: Optional[str] = None
    member_ids: List[str] = field(default_factory=list)
    end_line: int = 0
    evidence: str = ""

    CSV_COLUMNS = [
        "cve",
        "risk",
        "host",
        "port",
        "name",
        "description",
        "remediation",
        "evidence",
        "vpr_score",
    ]

    def csv_row(self) -> List[str]:
        """Values for CSV_COLUMNS (ThreatVault/CodXprt ingestion format).

        cve/port/vpr_score are intentionally left empty; risk is the
        final severity (CRITICAL/HIGH/MEDIUM/LOW); host is filled at CSV
        write time from the --repo locator when the caller provides one.
        """
        return [
            "",  # cve
            self.severity,
            "",  # host
            "",  # port
            self.title,
            self.description or "",
            self.recommendation or "",
            self.evidence or "",
            "",  # vpr_score
        ]


@dataclass
class ScanStats:
    """Rolling counters for the scan banner (blueprint section 33)."""

    raw_findings: int = 0
    candidate_groups: int = 0
    validated: int = 0
    false_positive: int = 0
    insufficient_evidence: int = 0
    deduplicated: int = 0
    unprocessed: int = 0
    canonical: int = 0