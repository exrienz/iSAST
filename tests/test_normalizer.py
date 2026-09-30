"""SARIF parsing + normalization tests."""

from pathlib import Path

from parsers.sarif import SarifParser, normalize_severity
from findings.normalizer import FindingNormalizer
from core.settings import Settings


def _sarif_document():
    return {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "python.sql.injection",
                                "shortDescription": {"text": "Potential SQL Injection"},
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["security", "cwe/cwe-089"]},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "python.sql.injection",
                        "level": "error",
                        "message": {"text": "User input reaches SQL query"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/users.py"},
                                    "region": {"startLine": 127, "startColumn": 12},
                                }
                            }
                        ],
                    },
                    {"ruleId": "orphan.rule", "message": {"text": "no location"}},
                ],
            }
        ]
    }


def test_parse_sarif_document(tmp_path):
    findings, errors = SarifParser().parse_document(_sarif_document(), "opengrep", tmp_path)
    assert errors == []
    assert len(findings) == 1  # no-location result is dropped
    finding = findings[0]
    assert finding["rule_id"] == "python.sql.injection"
    assert finding["file"] == "app/users.py"
    assert finding["line"] == 127
    assert finding["column"] == 12
    assert finding["scanner_severity"] == "ERROR"
    assert finding["cwe"] == "CWE-089"
    assert finding["scanner_title"] == "Potential SQL Injection"
    assert finding["language"] == "python"


def test_malformed_sarif_degrades(tmp_path):
    bad = tmp_path / "bad.sarif"
    bad.write_text("{not json")
    findings, errors = SarifParser().parse_file(bad, "opengrep", tmp_path)
    assert findings == []
    assert errors


def test_normalize_severity_map():
    assert normalize_severity("ERROR") == "HIGH"
    assert normalize_severity("WARNING") == "MEDIUM"
    assert normalize_severity("NOTE") == "LOW"
    assert normalize_severity("INFO") == "INFO"
    assert normalize_severity("weird") == "INFO"


def _settings():
    settings = Settings()
    return settings


def test_normalizer_attaches_context_and_fingerprint(tmp_path: Path):
    _src = tmp_path
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "users.py").write_text(
        "\n".join("; filler" for _ in range(5)) + "\nquery(input)\n" + "print('after')\n"
    )
    parsed = {
        "scanner": "opengrep",
        "rule_id": "python.sql.injection",
        "language": "python",
        "file": "app/users.py",
        "line": 6,
        "column": 1,
        "scanner_title": "SQL Injection",
        "scanner_message": "User input reaches SQL query",
        "scanner_severity": "ERROR",
    }
    findings = FindingNormalizer(_settings()).normalize([parsed], tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert "query(input)" in finding.code_context["target"]
    assert len(finding.fingerprint) == 64
    assert finding.scanner == "opengrep"


def test_minified_single_line_target_is_clamped(tmp_path: Path):
    """One 100k-char minified line must not become an oversized context/evidence
    blob (Excel caps a cell at 32,767 chars). Raw file itself is untouched."""
    from findings.normalizer import MAX_CONTEXT_LINE_CHARS

    blob = "var x=1;" + "a" * 100000
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "bundle.js").write_text(blob)
    parsed = {
        "scanner": "opengrep",
        "rule_id": "js.regex.dos",
        "language": "javascript",
        "file": "app/bundle.js",
        "line": 1,
        "column": 1,
        "scanner_title": "ReDoS",
        "scanner_message": "Regex on untrusted input",
        "scanner_severity": "ERROR",
    }
    findings = FindingNormalizer(_settings()).normalize([parsed], tmp_path)
    target = findings[0].code_context["target"]
    assert len(target) <= MAX_CONTEXT_LINE_CHARS
    assert "truncated" in target
    assert target.startswith("var x=1;")


def test_fingerprints_stable_but_distinguishing(tmp_path: Path):
    from findings.fingerprint import fingerprint

    same = {"rule_id": "r", "file": "a.py", "line": 1, "column": 0}
    other = {"rule_id": "r", "file": "a.py", "line": 2, "column": 0}
    assert fingerprint(same) == fingerprint(same)
    assert fingerprint(same) != fingerprint(other)