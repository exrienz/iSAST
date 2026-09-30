"""Canonic-finding build tests: CONFIRMED-only filter, risk vocabulary, evidence."""

from core.scanner import _risk_severity, Scanner
from core.models import Finding, ValidationStatus, ValidationResult


def _finding(id_hex, severity="HIGH", code_context=None):
    return Finding(
        scanner="opengrep",
        rule_id="python.sql.injection",
        language="python",
        file="src/routes/auth.py",
        line=97,
        column=0,
        scanner_title="SQL Injection",
        scanner_message="msg",
        scanner_severity=severity,
        code_context=code_context or {},
        finding_id=id_hex,
    )


def _scanner():
    return Scanner.__new__(Scanner)


def test_confirmed_and_likely_kept_vs_unprocessed():
    """Only CONFIRMED rows reach final.csv (LIKELY/UNPROCESSED excluded)."""
    confirmed = _finding("cafe0101")
    likely = _finding("cafe0202")
    unprocessed = _finding("cafe0303")
    ai_results = {
        confirmed.id: ValidationResult(finding_id=confirmed.id, status=ValidationStatus.CONFIRMED, confidence=0.9),
        likely.id: ValidationResult(finding_id=likely.id, status=ValidationStatus.LIKELY, confidence=0.6),
    }
    canonical_map = {f.id: f.id for f in (confirmed, likely, unprocessed)}
    rows = _scanner()._build_canonical_findings(
        [confirmed, likely, unprocessed], ai_results, canonical_map
    )
    assert [f.canonical_id for f in rows] == [confirmed.id]


def test_info_severity_dropped():
    """risk must land in CRITICAL/HIGH/MEDIUM/LOW — INFO rows are dropped."""
    finding = _finding("cafe0404")
    ai_results = {
        finding.id: ValidationResult(
            finding_id=finding.id,
            status=ValidationStatus.CONFIRMED,
            ai_severity="INFO",
        ),
    }
    rows = _scanner()._build_canonical_findings([finding], ai_results, {finding.id: finding.id})
    assert rows == []


def test_risk_severity_normalization():
    assert _risk_severity("WARNING") == "MEDIUM"
    assert _risk_severity("ERROR") == "HIGH"
    assert _risk_severity("NOTE") == "LOW"
    assert _risk_severity("CRITICAL") == "CRITICAL"
    assert _risk_severity("INFO") is None
    assert _risk_severity(None) is None
    assert _risk_severity("weird") is None


def test_evidence_file_lines_and_snippet():
    """evidence = file + start-end lines + target snippet (AI fields win)."""
    finding = _finding(
        "cafe0505",
        code_context={"before": "def f():", "target": "q = f'SELECT * FROM u WHERE id={uid}'\ndb.execute(q)\n", "after": ""},
    )
    ai_results = {
        finding.id: ValidationResult(
            finding_id=finding.id,
            status=ValidationStatus.CONFIRMED,
            confidence=0.9,
            title="SQL Injection",
            ai_severity="HIGH",
            description="Interpolated identifier reaches db.execute.",
            recommendation="Use parameterized queries.",
        ),
    }
    rows = _scanner()._build_canonical_findings([finding], ai_results, {finding.id: finding.id})
    assert len(rows) == 1
    row = rows[0]
    assert row.end_line == 98  # line 97 + 2 target lines - 1
    assert row.evidence == (
        "Affected File: src/routes/auth.py\n"
        "Affected Line: 97 - 98\n"
        "\n"
        "q = f'SELECT * FROM u WHERE id={uid}'\ndb.execute(q)"
    )
    cve, risk, host, port, name, description, remediation, evidence, _vpr = row.csv_row()
    assert (cve, risk, host, port) == ("", "HIGH", "", "")
    assert name == "SQL Injection"
    assert remediation == "Use parameterized queries."


def test_evidence_without_context_falls_back_to_message():
    finding = _finding("cafe0606", code_context={})
    ai_results = {
        finding.id: ValidationResult(finding_id=finding.id, status=ValidationStatus.CONFIRMED),
    }
    rows = _scanner()._build_canonical_findings([finding], ai_results, {finding.id: finding.id})
    assert rows[0].end_line == 97
    assert rows[0].evidence == (
        "Affected File: src/routes/auth.py\n"
        "Affected Line: 97 - 97\n"
        "\n"
        "msg"
    )


def test_evidence_multi_line_end_line_and_snippet_lines():
    """A multi-line target extends the affected-line range to its last line."""
    finding = _finding(
        "cafe0707",
        code_context={"before": "", "target": "a()\nb()\n", "after": ""},
    )
    ai_results = {
        finding.id: ValidationResult(finding_id=finding.id, status=ValidationStatus.CONFIRMED),
    }
    rows = _scanner()._build_canonical_findings([finding], ai_results, {finding.id: finding.id})
    assert rows[0].evidence == (
        "Affected File: src/routes/auth.py\n"
        "Affected Line: 97 - 98\n"
        "\n"
        "a()\nb()"
    )