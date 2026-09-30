"""--resume tests: workspace discovery, stage skipping, and checkpoints."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.models import DetectionResult, Finding, LanguageInfo
from core.scanner import ScanConfig, Scanner
from core.workspace import ScanWorkspace, WorkspaceError, find_resumable, write_json_atomic
from findings.grouping import CandidateGrouper

SRC = str(Path("/tmp/src").resolve())
OTHER = str(Path("/tmp/other").resolve())


def _scan_config(source=SRC, report="/tmp/out/final.csv"):
    return ScanConfig(source=Path(source), report=Path(report))


def _settings(tmp_path, **overrides):
    base = {
        "workdir": tmp_path,
        "opengrep_version": "1.30.0",
        "codeql_version": "2.27.1",
        "ai_model": "test-model",
        "ai_enabled": True,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _workspace(tmp_path, scan_id="scan-abc123def456", **metadata_extra):
    workspace = ScanWorkspace(tmp_path, scan_id=scan_id)
    workspace.create()
    metadata = {
        "source": SRC,
        "report": "/tmp/out/final.csv",
        "threads": 4,
        "timeout": 3600,
        "opengrep_version": "1.30.0",
        "codeql_version": "2.27.1",
        "ai_model": "test-model",
        "created_at": "2026-09-30T10:00:00+00:00",
    }
    metadata.update(metadata_extra)
    workspace.write_json(workspace.metadata_file, metadata)
    return workspace


# ----------------------------------------------------------------------
# find_resumable
# ----------------------------------------------------------------------


def test_find_resumable_picks_most_recent_incomplete(tmp_path):
    _workspace(tmp_path, scan_id="scan-aaa000000001", created_at="2026-09-30T09:00:00+00:00")
    # Completed workspace exists too — but must be excluded from the pick.
    done = _workspace(
        tmp_path,
        scan_id="scan-zzz000000009",
        created_at="2026-09-30T11:00:00+00:00",
    )
    (done.root / "state.json").write_text(
        json.dumps({"stages": {"reports": {"completed_at": 1}}})
    )

    scan_id, metadata = find_resumable(tmp_path, "")
    assert scan_id == "scan-aaa000000001"
    assert metadata["source"] == SRC


def test_find_resumable_explicit_id_and_errors(tmp_path):
    _workspace(tmp_path, scan_id="scan-abc123def456")
    scan_id, metadata = find_resumable(tmp_path, "scan-abc123def456")
    assert scan_id == "scan-abc123def456"
    assert metadata["source"] == SRC

    with pytest.raises(WorkspaceError) as excinfo:
        find_resumable(tmp_path, "scan-missing")
    assert "deleted after a successful" in str(excinfo.value)

    with pytest.raises(WorkspaceError) as excinfo:
        find_resumable(tmp_path / "empty", "")  # independent workdir: nothing there
    assert "no resumable scan workspace" in str(excinfo.value)


def test_find_resumable_excludes_completed_workspaces(tmp_path):
    done = _workspace(tmp_path, scan_id="scan-done0000001")
    write_json_atomic(done.state_file, {"stages": {"reports": {"completed_at": 1}}})
    with pytest.raises(WorkspaceError):
        find_resumable(tmp_path, "")


# ----------------------------------------------------------------------
# Resume gate (_validate_resume)
# ----------------------------------------------------------------------


def _scanner(tmp_path, config=None, **settings_overrides):
    return Scanner(
        config or _scan_config(),
        _settings(tmp_path, **settings_overrides),
    )


def test_validate_resume_rejects_source_mismatch(tmp_path):
    scanner = _scanner(tmp_path, _scan_config(source=OTHER))
    workspace = ScanWorkspace(tmp_path, scan_id="scan-x")
    with pytest.raises(WorkspaceError) as excinfo:
        scanner._validate_resume(workspace, {"source": SRC})
    assert "was for source" in str(excinfo.value)


def test_validate_resume_warns_on_engine_change(tmp_path, capsys):
    scanner = _scanner(tmp_path, _scan_config(), opengrep_version="0.9.0-old")
    workspace = ScanWorkspace(tmp_path, scan_id="scan-x")
    scanner._validate_resume(
        workspace,
        {
            "source": SRC,
            "opengrep_version": "0.9.0-old-saved",
            "ai_model": "old-model",
        },
    )
    printed = capsys.readouterr().out
    assert "OpenGrep changed" in printed
    assert "AI model changed" in printed


def test_validate_resume_matching_metadata_is_silent(tmp_path, capsys):
    scanner = _scanner(tmp_path)
    workspace = ScanWorkspace(tmp_path, scan_id="scan-x")
    scanner._validate_resume(workspace, {"source": SRC})
    assert capsys.readouterr().out == ""


# ----------------------------------------------------------------------
# Loaders (detection, normalized groups)
# ----------------------------------------------------------------------


def _make_finding(index):
    return Finding(
        scanner="opengrep",
        rule_id="python.sql.injection",
        language="python",
        file=f"app_{index}.py",
        line=index * 10,
        column=0,
        scanner_title="SQL",
        scanner_message="m",
        scanner_severity="ERROR",
        fingerprint=f"fp{index}",
        cwe="CWE-89",
        finding_id=f"finding-{index:04d}-" + "abcd" * 4,
    )


def test_load_normalized_groups_restores_grouping(tmp_path):
    findings_original = [_make_finding(i) for i in range(1, 4)]
    workspace = _workspace(tmp_path)
    groups_original = CandidateGrouper().group(findings_original)
    workspace.write_json(
        workspace.normalized_findings, [f.to_dict() for f in findings_original]
    )
    scanner = _scanner(tmp_path)

    loaded_findings, loaded_groups = scanner._load_normalized_groups(workspace)

    assert loaded_findings is not None
    assert scanner.stats.raw_findings == len(findings_original)
    assert scanner.stats.candidate_groups == len(groups_original)
    # Regrouping from the persisted dicts must be deterministic: same order,
    # same representatives — so resume skips the exact same AI work.
    regrouped = CandidateGrouper().group(loaded_findings)
    assert [g.primary().finding_id for g in regrouped] == [
        g.primary().finding_id for g in groups_original
    ]


def test_load_normalized_groups_corrupt_file_reruns(tmp_path):
    workspace = _workspace(tmp_path)
    workspace.write_json(workspace.normalized_findings, [{"garbage": True}])
    (workspace.normalized_findings).write_text("{torn")

    scanner = _scanner(tmp_path)
    assert scanner._load_normalized_groups(workspace) == (None, None)


def test_load_detection_round_trip(tmp_path):
    detection = DetectionResult(
        languages=[
            LanguageInfo(name="python", loc=1000, build_system="pip", codeql_supported=True)
        ],
        manifests=[
            {"path": "/tmp/src/requirements.txt", "relative": "requirements.txt",
             "ecosystem": "pip"}
        ],
    )
    workspace = _workspace(tmp_path)
    workspace.write_detection(detection.to_dict())

    scanner = _scanner(tmp_path)
    loaded = scanner._load_detection(workspace)
    assert loaded is not None
    assert loaded.language_names == ["python"]
    assert loaded.languages[0].codeql_supported

    (workspace.detection_file).write_text("{torn")
    assert scanner._load_detection(workspace) is None


# ----------------------------------------------------------------------
# Stage checkpoints (state.json)
# ----------------------------------------------------------------------


def test_checkpoint_persists_stage_details(tmp_path):
    workspace = _workspace(tmp_path)
    scanner = _scanner(tmp_path)
    scanner._checkpoint(workspace, "opengrep", {})
    scanner._checkpoint(workspace, "codeql", {"langs": {"python": 2}})

    state = json.loads(workspace.state_file.read_text())
    assert state["stages"]["opengrep"]["completed_at"] > 0
    assert state["stages"]["codeql"]["langs"] == {"python": 2}

    # Not yet marked reports-complete → still resumable.
    scan_id, _metadata = find_resumable(tmp_path, "scan-abc123def456")
    assert scan_id == "scan-abc123def456"


def test_state_json_survives_crash_and_reloads(tmp_path):
    workspace = _workspace(tmp_path)
    scanner = _scanner(tmp_path)
    scanner._checkpoint(workspace, "detect", {})
    scanner._checkpoint(workspace, "opengrep", {})

    # Fresh scanner instance (e.g. resumed process) reloads completed stages.
    resumed = ScanWorkspace(tmp_path, scan_id="scan-abc123def456")
    state = resumed.read_json(resumed.state_file, default=None)
    assert set((state or {}).get("stages", {})) == {"detect", "opengrep"}


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def test_cli_resume_flag_parsing():
    from isast import build_parser

    parser = build_parser()
    assert parser.parse_args(["--source=s", "--report=r"]).resume is None
    assert parser.parse_args(["--source=s", "--report=r", "--resume"]).resume == ""
    assert (
        parser.parse_args(["--resume", "scan-x", "--source=s", "--report=r"]).resume
        == "scan-x"
    )


def test_scan_config_resume_fields():
    config = _scan_config()
    assert config.resume is False
    assert config.resume_scan_id is None