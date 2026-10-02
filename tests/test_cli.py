"""CLI + output + workspace tests."""

import csv
import json

import pytest

from isast import build_parser, main
from output.csv import CSVWriter, sanitize_cell
from output.json import JSONWriter, findings_payload
from core.models import CanonicalFinding, Finding, ValidationStatus, ValidationResult
from core.workspace import ScanWorkspace
from core.settings import load_settings
from pathlib import Path


def test_cli_requires_source_and_report(capsys):
    result = build_parser().parse_args(["--source=/tmp/x"])
    assert result.source == "/tmp/x" and result.report is None
    assert result.threads == 4  # defaults per blueprint section 4


def test_cli_version_and_exits(capsys):
    assert main(["--version"]) == 0
    out = capsys.readouterr().out
    assert "iSAST v" in out


def test_cli_invalid_source(capsys, tmp_path):
    args = [
        "--source", str(tmp_path / "missing"),
        "--report", str(tmp_path / "out.csv"),
        "--workdir", str(tmp_path / "workdir"),  # leak nothing into the real workdir
        "--non-interactive", "--offline",
    ]
    exit_code = main(args)
    assert exit_code in (3, 4)
    # the failed scan's workspace stays under the provided --workdir only
    created = [p for p in (tmp_path / "workdir").glob("scan-*") if p.is_dir()]
    assert len(created) <= 1


def test_sanitize_cell():
    assert sanitize_cell("line1\nline2\r\nline3") == "line1\nline2\nline3"
    assert sanitize_cell(None) == ""


def test_sanitize_cell_caps_under_excel_limit():
    """A 63k-char minified-bundle evidence cell must never exceed the
    32,767-character Excel/Sheets cell limit (regression)."""
    from output.csv import MAX_CELL_CHARS

    out = sanitize_cell("x" * 63290)
    assert len(out) <= MAX_CELL_CHARS
    assert "truncated" in out


def _confirmed_finding(**overrides):
    fields = dict(
        canonical_id="F-001",
        title="SQL Injection",
        severity="HIGH",
        confidence=0.96,
        language="python",
        file="app/users.py",
        line=127,
        column=12,
        category="Injection",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        description="User-controlled input reaches a SQL execution sink without parameterization.",
        recommendation="Use parameterized queries.",
        exploitability="HIGH",
        impact="HIGH",
        scanner_count=2,
        scanners="codeql;opengrep",
        validation_status="CONFIRMED",
        end_line=133,
        evidence=(
            "Affected File: app/users.py\n"
            "Affected Line: 127 - 133\n"
            "\n"
            'cursor.execute(f"SELECT ... WHERE id = {uid}")'
        ),
    )
    fields.update(overrides)
    return CanonicalFinding(**fields)


def test_csv_writer_columns(tmp_path):
    """final.csv is the ThreatVault ingestion schema: 9 fixed columns."""
    target = tmp_path / "final.csv"
    CSVWriter().write(target, [_confirmed_finding()])
    with target.open(encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0] == {
        "cve": "",
        "risk": "HIGH",
        "host": "",
        "port": "",
        "name": "SQL Injection",
        "description": "User-controlled input reaches a SQL execution sink without parameterization.",
        "remediation": "Use parameterized queries.",
        "evidence": (
            "Affected File: app/users.py\n"
            "Affected Line: 127 - 133\n"
            "\n"
            'cursor.execute(f"SELECT ... WHERE id = {uid}")'
        ),
        "vpr_score": "",
    }


def test_csv_writer_repo_fills_host_column(tmp_path):
    """--repo locator lands in the host column of every row; other columns
    (cve/port/vpr_score) stay blank."""
    finding = _confirmed_finding(canonical_id="F-002", title="XSS")
    target = tmp_path / "final.csv"
    CSVWriter().write(target, [finding], host="org/project/app:main")
    with target.open(encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["host"] == "org/project/app:main"
    assert rows[0]["cve"] == ""
    assert rows[0]["port"] == ""
    assert rows[0]["vpr_score"] == ""


def test_repo_pattern_validation():
    from isast import REPO_PATTERN

    assert REPO_PATTERN.match("org/project/app:main")
    assert REPO_PATTERN.match("apps/sso-v3")
    assert REPO_PATTERN.match("sso-v3:release-2.1")
    assert REPO_PATTERN.match("apps/my_app:v1.0")  # dot in ref, underscore in path
    assert not REPO_PATTERN.match("bad repo; rm -rf")
    assert not REPO_PATTERN.match("http://evil")
    assert not REPO_PATTERN.match("")


def test_csv_writer_empty_cells_and_newlines(tmp_path):
    """Optional AI fields blank out; multi-line cells survive the round trip
    (QUOTE_ALL quoting keeps embedded newlines intact for spreadsheets)."""
    finding = _confirmed_finding(
        description="first line\nsecond line",
        evidence="Affected File: app/a.py\nAffected Line: 1 - 2\n\nline one\nline two",
    )
    target = tmp_path / "final.csv"
    CSVWriter().write(target, [finding])
    with target.open(encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["description"] == "first line\nsecond line"
    assert rows[0]["evidence"].startswith("Affected File: app/a.py\n")
    assert rows[0]["evidence"].endswith("line one\nline two")


def test_findings_payload_and_writer(tmp_path):
    finding = Finding(
        scanner="opengrep",
        rule_id="python.sql.injection",
        language="python",
        file="app/users.py",
        line=127,
        column=12,
        scanner_title="SQL Injection",
        scanner_message="msg",
        scanner_severity="HIGH",
        fingerprint="cafe" * 16,
    )
    result = ValidationResult(finding_id=finding.finding_id[:8], status=ValidationStatus.CONFIRMED, confidence=0.9)
    entries = findings_payload([finding], {finding.finding_id[:8]: result}, {finding.finding_id[:8]: "F-001"})
    assert entries[0]["ai_status"] == "CONFIRMED"
    assert entries[0]["canonical_id"] == "F-001"
    target = tmp_path / "raw.json"
    JSONWriter().write(target, entries)
    payload = json.loads(target.read_text())
    assert payload[0]["scanner_severity"] == "HIGH"


def test_workspace_layout(tmp_path):
    workspace = ScanWorkspace(tmp_path)
    workspace.create()
    assert (workspace.root / "raw").is_dir()
    assert workspace.raw_opengrep.parent == workspace.root / "raw"
    workspace.write_json(workspace.normalized_findings, [{"a": 1}])
    assert workspace.read_json(workspace.normalized_findings) == [{"a": 1}]
    workspace.write_detection({"languages": []})
    assert workspace.detection_file.exists()
    workspace.cleanup()
    assert not workspace.root.exists()


def test_settings_load_env(tmp_path, monkeypatch):
    for key in ("LLM_MODEL", "AI_TIMEOUT"):
        monkeypatch.delenv(key, raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("LLM_MODEL=test-model\nAI_TIMEOUT=5\n")
    settings = load_settings(tmp_path)
    assert settings.ai_model == "test-model"
    assert settings.ai_timeout == 5
    assert settings.ai_enabled is True


def test_settings_ai_group_budget_default_and_env(tmp_path, monkeypatch):
    monkeypatch.delenv("AI_GROUP_BUDGET", raising=False)
    settings = load_settings(tmp_path)
    assert settings.ai_group_budget == 600  # default caps every AI group

    monkeypatch.setenv("AI_GROUP_BUDGET", "120")
    assert load_settings(tmp_path).ai_group_budget == 120

    monkeypatch.setenv("AI_GROUP_BUDGET", "0")  # 0 = unlimited
    assert load_settings(tmp_path).ai_group_budget == 0

    monkeypatch.setenv("AI_GROUP_BUDGET", "junk")  # invalid → default
    assert load_settings(tmp_path).ai_group_budget == 600