"""Grouping + fingerprint correlation tests."""

from core.models import Finding
from findings.grouping import CandidateGrouper, sink_class
from findings.fingerprint import normalize_path, snippet_signature


def _finding(**overrides) -> Finding:
    base = dict(
        scanner="opengrep",
        rule_id="python.sql.injection",
        language="python",
        file="app/users.py",
        line=127,
        column=12,
        scanner_title="SQL Injection",
        scanner_message="user input reaches SQL",
        scanner_severity="HIGH",
    )
    base.update(overrides)
    return Finding(**base)


def test_group_by_file_and_proximity():
    a = _finding(line=130)
    b = _finding(line=135)
    far = _finding(line=9000)
    groups = CandidateGrouper().group([a, b, far])
    keys = {g.key: g for g in groups}
    # a and b share a band; far lands elsewhere
    assert len(groups) >= 2
    same = [g for g in groups if a in g.findings]
    assert b in same[0].findings and far not in same[0].findings


def test_group_different_sink_classes():
    sql = _finding(rule_id="python.sql.injection", line=10)
    xss = _finding(rule_id="python.xss.reflected", line=12)
    groups = CandidateGrouper().group([sql, xss])
    assert len(groups) == 2


def test_sink_class_mapping():
    assert sink_class("python.sql.injection") == "sql"
    assert sink_class("js.command.injection") == "command"
    assert sink_class("unknown.rule") == "other"


def test_primary_is_highest_severity():
    low = _finding(scanner_severity="LOW", line=10)
    high = _finding(scanner_severity="CRITICAL", line=11)
    groups = CandidateGrouper().group([low, high])
    assert groups[0].primary().scanner_severity == "CRITICAL"


def test_normalize_path_variants():
    assert normalize_path("app\\users.py") == "app/users.py"
    assert normalize_path("./a/b.py") == "a/b.py"


def test_snippet_signature_tolerates_missing_file(tmp_path):
    missing = tmp_path / "nope.py"
    assert snippet_signature(missing, 10) == ""