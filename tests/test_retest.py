"""Retest mode tests: evidence parsing, code-presence verification, runner, CLI."""

import csv

import pytest

from core.models import CanonicalFinding
from isast import build_parser, main
from output.csv import MAX_CELL_CHARS, CSVWriter, ReportReadError, read_report, write_report
from retest import RetestOptions, run_retest
from retest.verify import (
    EvidenceRef,
    RETEST_LINE_WINDOW,
    finding_exists,
    parse_evidence,
)
from pathlib import Path


def _evidence(file: str, start: int, end: int, snippet: str) -> str:
    return f"Affected File: {file}\nAffected Line: {start} - {end}\n\n{snippet}"


def _ref(file: str, start: int, end: int, snippet: str) -> EvidenceRef:
    return EvidenceRef(file=file, start_line=start, end_line=end, snippet=snippet)


# ---------------------------------------------------------------- parse_evidence


def test_parse_evidence_standard_cell():
    ref = parse_evidence(_evidence("src/app/users.py", 127, 133, 'cursor.execute(f"{uid}")'))
    assert ref == _ref("src/app/users.py", 127, 133, 'cursor.execute(f"{uid}")')


def test_parse_evidence_multiline_snippet_with_blanks():
    cell = _evidence("app/a.py", 2, 5, "return {\n\n    \"uid\": uid,\n}")
    assert parse_evidence(cell).snippet == "return {\n\n    \"uid\": uid,\n}"


def test_parse_evidence_missing_file_header():
    assert parse_evidence("Affected Line: 1 - 2\n\ncode") is None


def test_parse_evidence_empty_file_path():
    assert parse_evidence("Affected File:   \nAffected Line: 1 - 2\n\ncode") is None


def test_parse_evidence_missing_line_header():
    assert parse_evidence("Affected File: app/a.py\ncode") is None
    assert parse_evidence("Affected File: app/a.py\nAffected Lines: 1 - 2\ncode") is None


def test_parse_evidence_single_span_and_clamps():
    assert parse_evidence(_evidence("a.py", 34, 34, "x")).end_line == 34
    ref = parse_evidence(_evidence("a.py", 34, 30, "x"))  # end < start clamps
    assert (ref.start_line, ref.end_line) == (34, 34)
    ref = parse_evidence(_evidence("a.py", 34, 36, "x"))  # ws-tolerant header
    assert (ref.start_line, ref.end_line) == (34, 36)


def test_parse_evidence_blank_only_snippet_parses():
    """No code to compare, but the location itself is parseable."""
    ref = parse_evidence("Affected File: app/a.py\nAffected Line: 10 - 10\n\n")
    assert ref.start_line == 10 and ref.snippet == ""


def test_parse_evidence_survives_truncation_marker():
    cell = _evidence("app/bundle.js", 3, 3, "head part\n…[truncated +4200 chars]\ntail part")
    ref = parse_evidence(cell)
    assert "…[truncated +4200 chars]" in ref.snippet


# ---------------------------------------------------------------- finding_exists


def _write_source(root: Path, rel: str, text: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _check(root: Path, ref: EvidenceRef) -> bool:
    return finding_exists(ref, root, {})


def test_finding_exists_exact_match(tmp_path):
    _write_source(tmp_path, "app/users.py", "def a():\n    pass\n\n" + "x = leak(uid)\n" * 1 + "b()\n")
    ref = _ref("app/users.py", 5, 5, "x = leak(uid)")
    assert _check(tmp_path, ref) is True


def test_finding_exists_whitespace_and_indentation_differences(tmp_path):
    content = "def f():\n    return {\n        \"uid\": uid,\n    }\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 2, 4, "return {\n\"uid\": uid,\n}")
    assert _check(tmp_path, ref) is True


def test_finding_exists_drift_within_window(tmp_path):
    # The finding moved +3 lines down (edits above), inside the ±10 window.
    content = "\n\n\n" + "x = leak(uid)\n" + "tail()\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 1, "x = leak(uid)")
    assert _check(tmp_path, ref) is True


def test_finding_exists_drift_beyond_window_with_specific_snippet(tmp_path):
    content = "\n" * (RETEST_LINE_WINDOW + 3) + "token_value = leak(uid)  # unique-anchor-77\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 1, "token_value = leak(uid)  # unique-anchor-77")
    assert _check(tmp_path, ref) is True  # whole-file fallback allowed (>=24 chars)


def test_finding_exists_short_snippet_drift_beyond_window_removed(tmp_path):
    content = "\n" * (RETEST_LINE_WINDOW + 3) + "return {\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 1, "return {")
    assert _check(tmp_path, ref) is False  # too non-specific for the fallback


def test_finding_exists_code_edited_removed(tmp_path):
    _write_source(tmp_path, "app/a.py", "fixed(): parameterized(uid)\n")
    assert _check(tmp_path, _ref("app/a.py", 1, 1, "x = leak(uid)")) is False


def test_finding_exists_insertion_inside_construct_tolerated(tmp_path):
    content = "def f():\n    log(x)\n    x = leak(uid)\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 2, "def f():\n    x = leak(uid)")
    assert _check(tmp_path, ref) is True


def test_finding_exists_too_many_inserted_lines_removed(tmp_path):
    content = "def f():\n" + "    unrelated()\n" * 4 + "    x = leak(uid)\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 2, "def f():\n    x = leak(uid)")
    assert _check(tmp_path, ref) is False


def test_finding_exists_later_occurrence_not_starved(tmp_path):
    content = "x = leak(uid)\n\n\nunrelated\nx = leak(uid)\nb()\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 2, "x = leak(uid)\nb()")
    assert _check(tmp_path, ref) is True


def test_finding_exists_minified_single_line_with_midline_marker(tmp_path):
    """The real clamped-bundle shape: marker splits ONE physical line."""
    body = "one()" + "·" * 6000 + "two()"  # one long single-line bundle
    _write_source(tmp_path, "app/a.py", body)
    head = body[:2000]
    tail = body[-2000:]
    clamped = head + f"…[truncated +{len(body) - 4000} chars]" + tail
    ref = _ref("app/a.py", 1, 1, clamped)
    assert _check(tmp_path, ref) is True


def test_finding_exists_nul_byte_path_removed(tmp_path):
    assert _check(tmp_path, _ref("app/\x00nul.py", 1, 1, "anything()")) is False


def test_finding_exists_file_deleted(tmp_path):
    assert _check(tmp_path, _ref("app/gone.py", 1, 1, "anything()")) is False


def test_finding_exists_unreadable_file(tmp_path):
    target = tmp_path / "app/private.py"
    target.parent.mkdir(parents=True)
    target.write_text("x = leak(uid)\n")
    target.chmod(0o000)
    try:
        assert _check(tmp_path, _ref("app/private.py", 1, 1, "x = leak(uid)")) is False
    finally:
        target.chmod(0o644)


def test_finding_exists_blank_snippet_location_only(tmp_path):
    _write_source(tmp_path, "app/a.py", "\n".join(f"line-{i}" for i in range(1, 21)))
    in_bounds = _check(tmp_path, _ref("app/a.py", 10, 10, ""))
    out_of_bounds = _check(tmp_path, _ref("app/a.py", 99, 99, "   \n   "))
    assert (in_bounds, out_of_bounds) == (True, False)


def test_finding_exists_truncated_snippet_head_and_tail(tmp_path):
    head = "head_part_1"
    tail = "tail_part_2"
    marker_line = "\n".join([head, f"…[truncated +{MAX_CELL_CHARS} chars]", tail])
    content = f"a()\n{head}\n" + "middle()\n" * 40 + f"{tail}\nend()\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 2, 2, marker_line)
    assert _check(tmp_path, ref) is True


def test_finding_exists_segments_out_of_order_removed(tmp_path):
    content = "tail_part_2\nhead_part_1\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 1, "head_part_1\n…[truncated +100 chars]\ntail_part_2")
    assert _check(tmp_path, ref) is False


def test_finding_exists_contiguity_guard_blocks_far_match(tmp_path):
    """More than RETEST_MAX_SKIP_LINES non-blank lines sit between the two
    snippet lines: the construct was rewritten, not just drifted."""
    content = "token_value = leak(uid)  # unique-anchor-77\n" + "unrelated()\n" * 4 + "b()\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 1, "token_value = leak(uid)  # unique-anchor-77\nb()")
    # within the window but 4 non-blank "unrelated()" lines between them
    assert _check(tmp_path, ref) is False


def test_finding_exists_blank_lines_and_insertions_between_are_skipped(tmp_path):
    content = "token_value = leak(uid)  # unique-anchor-77\n\n\nlog(x)\n\nb()\n"
    _write_source(tmp_path, "app/a.py", content)
    ref = _ref("app/a.py", 1, 1, "token_value = leak(uid)  # unique-anchor-77\nb()")
    assert _check(tmp_path, ref) is True


def test_finding_exists_absolute_path_outside_source_removed(tmp_path):
    absolute = _ref(str(Path("/etc/passwd")), 1, 1, "root")
    assert _check(tmp_path, absolute) is False


def test_finding_exists_relative_traversal_removed(tmp_path):
    _write_source(tmp_path.parent, "secret.txt", "x = leak(uid)\n")
    assert _check(tmp_path, _ref("../../secret.txt", 1, 1, "x = leak(uid)")) is False


def test_finding_exists_file_cache_reused(tmp_path, monkeypatch):
    """Repeated findings on one file read the file from disk exactly once."""
    _write_source(tmp_path, "app/a.py", "x = leak(uid)\n")
    calls = []
    real_read_text = Path.read_text

    def counting(self, *args, **kwargs):
        calls.append(self)
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counting)
    cache: dict = {}
    ref = _ref("app/a.py", 1, 1, "x = leak(uid)")
    assert finding_exists(ref, tmp_path, cache) is True
    assert finding_exists(ref, tmp_path, cache) is True
    assert calls == [tmp_path / "app" / "a.py"]


# ---------------------------------------------------------------- runner


def _canonical(**overrides) -> CanonicalFinding:
    fields = dict(
        canonical_id="F-001",
        title="SQL Injection",
        severity="HIGH",
        confidence=0.96,
        language="python",
        file="app/users.py",
        line=2,
        column=1,
        category="Injection",
        cwe="CWE-89",
        owasp="A03:2021-Injection",
        description="User input reaches a SQL sink.",
        recommendation="Use parameterized queries.",
        exploitability="HIGH",
        impact="HIGH",
        scanner_count=2,
        scanners="codeql;opengrep",
        validation_status="CONFIRMED",
        end_line=2,
        evidence="",
    )
    fields.update(overrides)
    return CanonicalFinding(**fields)


def _make_report(tmp_path, name: str, findings, host=None) -> Path:
    target = tmp_path / name
    CSVWriter().write(target, findings, host=host)
    return target


def test_run_retest_mixed_report(tmp_path):
    _write_source(tmp_path, "app/users.py", "a()\nx = leak(uid)\nb()\n")
    _write_source(tmp_path, "app/fixed.py", "parameterized()\n")
    still_there = _canonical(
        canonical_id="F-001", file="app/users.py", line=2,
        evidence=_evidence("app/users.py", 2, 2, "x = leak(uid)"),
    )
    gone = _canonical(
        canonical_id="F-002", title="XSS", file="app/fixed.py", line=1, severity="MEDIUM",
        evidence=_evidence("app/fixed.py", 1, 1, "x = leak(uid)"),  # code changed
    )
    report = _make_report(tmp_path, "rescan.csv", [still_there, gone])
    out = tmp_path / "retest" / "clean.csv"
    result = run_retest(RetestOptions(source=tmp_path, rescan_report=report, output=out))

    assert (result.read, result.kept, result.removed_absent, result.removed_unparseable) == (2, 1, 1, 0)
    with out.open(encoding="utf-8-sig", newline="") as handle:
        kept_rows = list(csv.DictReader(handle))
    assert [r["name"] for r in kept_rows] == ["SQL Injection"]


def test_run_retest_kept_rows_byte_for_byte(tmp_path):
    """Kept rows survive unchanged: same cells, same order, no re-sorting
    (CSVWriter itself sorts by canonical_id, so rows are written by hand)."""
    _write_source(tmp_path, "app/a.py", "a()\nx = leak(uid)\nb()\n")
    input_rows = [
        _canonical(
            canonical_id=f"F-{i:03d}", title=f"T{i}", file="app/a.py", line=2,
            description=f"desc {i}\nsecond line",
            evidence=_evidence("app/a.py", 2, 2, "x = leak(uid)"),
        ).csv_row()
        for i in (3, 1, 2)  # deliberately out of canonical_id order
    ]
    report = tmp_path / "rescan.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as handle:
        writer_w = csv.writer(handle, quoting=csv.QUOTE_ALL)
        writer_w.writerow(CanonicalFinding.CSV_COLUMNS)
        writer_w.writerows(input_rows)
    input_header, input_rows = read_report(report)
    out = tmp_path / "clean.csv"
    result = run_retest(RetestOptions(source=tmp_path, rescan_report=report, output=out))

    out_header, out_rows = read_report(out)
    assert (out_header, out_rows) == (input_header, input_rows)
    assert [row[4] for row in out_rows] == ["T3", "T1", "T2"]  # name col, report order kept
    assert result.kept == 3


def test_run_retest_repo_reroutes_host_and_preserves_when_absent(tmp_path):
    _write_source(tmp_path, "app/a.py", "x = leak(uid)\n")
    finding = _canonical(evidence=_evidence("app/a.py", 1, 1, "x = leak(uid)"))
    report = _make_report(tmp_path, "rescan.csv", [finding], host="old/app:master")

    out_with = tmp_path / "with_repo.csv"
    run_retest(RetestOptions(source=tmp_path, rescan_report=report, output=out_with, repo="new/app:master"))
    with out_with.open(encoding="utf-8-sig") as handle:
        assert list(csv.DictReader(handle))[0]["host"] == "new/app:master"

    out_without = tmp_path / "without_repo.csv"
    run_retest(RetestOptions(source=tmp_path, rescan_report=report, output=out_without))
    with out_without.open(encoding="utf-8-sig") as handle:
        assert list(csv.DictReader(handle))[0]["host"] == "old/app:master"


def test_run_retest_drops_ragged_and_unparseable_rows(tmp_path):
    _write_source(tmp_path, "app/a.py", "x = leak(uid)\n")
    target = tmp_path / "ragged.csv"
    with target.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, quoting=csv.QUOTE_ALL)
        writer.writerow(CanonicalFinding.CSV_COLUMNS)
        writer.writerow(_canonical(evidence=_evidence("app/a.py", 1, 1, "x = leak(uid)")).csv_row())
        writer.writerow(["short", "row"])  # ragged -> removed_unparseable
        bad_evidence = _canonical().csv_row()
        bad_evidence[CanonicalFinding.CSV_COLUMNS.index("evidence")] = "no header here"
        writer.writerow(bad_evidence)  # unparseable -> removed_unparseable
    out = tmp_path / "clean.csv"
    result = run_retest(RetestOptions(source=tmp_path, rescan_report=target, output=out))
    assert (result.read, result.kept, result.removed_unparseable) == (3, 1, 2)


def test_run_retest_empty_report(tmp_path):
    target = tmp_path / "empty.csv"
    write_report(target, [])
    out = tmp_path / "clean.csv"
    result = run_retest(RetestOptions(source=tmp_path, rescan_report=target, output=out))
    assert (result.read, result.kept) == (0, 0)
    header, rows = read_report(out)
    assert rows == [] and header == CanonicalFinding.CSV_COLUMNS


def test_run_retest_output_matches_writer_format(tmp_path):
    """retest output must be byte-identical to what CSVWriter would emit."""
    _write_source(tmp_path, "app/users.py", "a()\nx = leak(uid)\n")
    finding = _canonical(evidence=_evidence("app/users.py", 2, 2, "x = leak(uid)"))
    report = _make_report(tmp_path, "rescan.csv", [finding])
    out = tmp_path / "clean.csv"
    run_retest(RetestOptions(source=tmp_path, rescan_report=report, output=out))
    reference = tmp_path / "reference.csv"
    CSVWriter().write(reference, [finding])
    assert out.read_bytes() == reference.read_bytes()


def test_run_retest_report_read_error(tmp_path):
    with pytest.raises(ReportReadError):
        run_retest(RetestOptions(source=tmp_path, rescan_report=tmp_path / "missing.csv", output=tmp_path / "out.csv"))


def test_run_retest_multiline_cell_round_trip(tmp_path):
    """QUOTE_ALL multi-line evidence survives the whole retest pipeline."""
    _write_source(tmp_path, "app/users.py", "def f():\nx = leak(uid)\n")
    finding = _canonical(evidence=_evidence("app/users.py", 2, 2, "x = leak(uid)"))
    report = _make_report(tmp_path, "rescan.csv", [finding])
    out = tmp_path / "clean.csv"
    run_retest(RetestOptions(source=tmp_path, rescan_report=report, output=out))
    with out.open(encoding="utf-8-sig", newline="") as handle:
        row = list(csv.DictReader(handle))[0]
    assert row["evidence"].startswith("Affected File: app/users.py\n")
    assert "x = leak(uid)" in row["evidence"]


def test_run_retest_in_place_output_is_safe(tmp_path):
    """--output == --rescan_report: read happens before the atomic write, so
    the in-place clean must produce byte-identical content."""
    _write_source(tmp_path, "app/a.py", "x = leak(uid)\n")
    finding = _canonical(evidence=_evidence("app/a.py", 1, 1, "x = leak(uid)"))
    report = _make_report(tmp_path, "rescan.csv", [finding])
    before = report.read_bytes()
    result = run_retest(RetestOptions(source=tmp_path, rescan_report=report, output=report))
    assert result.kept == 1
    assert report.read_bytes() == before
    assert not (tmp_path / "rescan.csv.tmp").exists()  # no temp litter


# ---------------------------------------------------------------- CLI


def _cli_args(tmp_path, source=None, rescan=None, output=None, extra=None) -> list:
    args = []
    if source is not None:
        args.append(f"--source={source}")
    if rescan is not None:
        args.append(f"--rescan_report={rescan}")
    if output is not None:
        args.append(f"--output={output}")
    if extra:
        args.extend(extra)
    args.append("--retest")
    return args


def _seed_cli_env(tmp_path):
    _write_source(tmp_path / "src", "app/a.py", "x = leak(uid)\n")
    finding = _canonical(evidence=_evidence("app/a.py", 1, 1, "x = leak(uid)"))
    report = tmp_path / "rescan.csv"
    CSVWriter().write(report, [finding])
    return tmp_path / "src", report


def test_cli_retest_success(capsys, tmp_path):
    source, report = _seed_cli_env(tmp_path)
    out = tmp_path / "clean.csv"
    code = main(_cli_args(tmp_path, source=source, rescan=report, output=out, extra=["--workdir", str(tmp_path / "work")]))
    assert code == 0
    captured = capsys.readouterr()
    assert "1 row(s) read" in captured.out
    assert "Retest complete" in captured.out
    assert out.is_file()
    # retest never creates a scan workspace
    assert not (tmp_path / "work").exists() or not list((tmp_path / "work").glob("scan-*"))


def test_cli_retest_missing_flags(capsys, tmp_path):
    code = main(["--retest"])
    assert code == 2
    captured = capsys.readouterr()
    assert "--rescan-report" in captured.err


def test_cli_retest_report_conflict(capsys, tmp_path):
    source, report = _seed_cli_env(tmp_path)
    code = main(_cli_args(tmp_path, source=source, rescan=report, output=tmp_path / "x.csv", extra=[f"--report={tmp_path / 'elsewhere.csv'}"]))
    assert code == 2


def test_cli_retest_resume_conflict(capsys, tmp_path):
    code = main(["--retest", "--source", str(tmp_path), "--rescan_report", "a.csv", "--output", "b.csv", "--resume"])
    assert code == 2


@pytest.mark.parametrize("missing", ["--source", "--rescan_report", "--output"])
def test_cli_retest_each_missing_flag(capsys, tmp_path, missing):
    args = [f"--output={tmp_path / 'o.csv'}", "--retest"] if missing == "--source" else (
        [f"--source={tmp_path}", "--retest"] if missing == "--rescan_report" else [f"--source={tmp_path}", "--rescan_report=x.csv", "--retest"]
    )
    assert main(args) == 2
    assert missing.replace("_", "-") in capsys.readouterr().err.replace("_", "-")


def test_cli_retest_missing_report_file(capsys, tmp_path):
    code = main(_cli_args(tmp_path, source=tmp_path, rescan=tmp_path / "nope.csv", output=tmp_path / "x.csv"))
    assert code == 4


def test_cli_retest_source_not_a_directory(capsys, tmp_path):
    report = tmp_path / "rescan.csv"
    write_report(report, [])
    code = main(_cli_args(tmp_path, source=tmp_path / "missing-dir", rescan=report, output=tmp_path / "x.csv"))
    assert code == 4


def test_cli_retest_bad_repo(capsys, tmp_path):
    source, report = _seed_cli_env(tmp_path)
    code = main(_cli_args(tmp_path, source=source, rescan=report, output=tmp_path / "x.csv", extra=["--repo=bad repo; rm -rf"]))
    assert code == 2


def test_cli_retest_underscore_spelling(capsys, tmp_path):
    parsed = build_parser().parse_args(["--rescan_report=x.csv", "--output=y.csv", "--retest"])
    assert parsed.rescan_report == "x.csv"
    parsed2 = build_parser().parse_args(["--rescan-report=x.csv", "--output=y.csv", "--retest"])
    assert parsed2.rescan_report == "x.csv"


def test_cli_rescan_report_without_retest_rejected(capsys, tmp_path):
    code = main([f"--source={tmp_path}", f"--report={tmp_path / 'r.csv'}", f"--rescan_report={tmp_path / 'old.csv'}"])
    assert code == 2
    assert "--retest" in capsys.readouterr().err


def test_cli_retest_corrupt_report_exit_1(capsys, tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_bytes(b"\xff\xfe\x00\x01garbage-not-a-report")
    code = main(_cli_args(tmp_path, source=tmp_path, rescan=bad, output=tmp_path / "x.csv"))
    assert code == 1
    assert "retest failed" in capsys.readouterr().err