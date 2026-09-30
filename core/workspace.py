"""Scan workspace management (blueprint section 31).

Layout for each scan:

    <workdir>/<scan-id>/
    ├── metadata.json
    ├── detection.json
    ├── raw/            (opengrep.sarif, codeql/<lang>.sarif)
    ├── normalized/     (findings.json)
    ├── ai/             (validation.json, dedup.json, errors.json, chat-failure-*.json)
    └── reports/        (final.csv, raw-findings.json)
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


class WorkspaceError(RuntimeError):
    """Raised when the scan workspace cannot be created or used."""


def write_json_atomic(path: Path, payload: Any) -> None:
    """Overwrite ``path`` atomically (tmp file + os.replace in its dir).

    Used by checkpoints that concurrent worker threads update while the
    scan runs — a crash mid-write must never leave a torn JSON file.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise WorkspaceError(f"cannot write {path}: {exc}") from exc


class ScanWorkspace:
    """Create and manage the per-scan working directory."""

    def __init__(self, workdir: Path, scan_id: Optional[str] = None) -> None:
        self.scan_id = scan_id or f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        self.root = Path(workdir) / self.scan_id
        self.raw_opengrep = self.root / "raw" / "opengrep.sarif"
        self.raw_codeql = self.root / "raw" / "codeql"
        self.normalized_dir = self.root / "normalized"
        self.normalized_findings = self.normalized_dir / "findings.json"
        self.ai_dir = self.root / "ai"
        self.validation_file = self.ai_dir / "validation.json"
        self.dedup_file = self.ai_dir / "dedup.json"
        self.validation_partial = self.ai_dir / "validation-partial.json"
        self.reports_dir = self.root / "reports"
        self.metadata_file = self.root / "metadata.json"
        self.detection_file = self.root / "detection.json"
        self.state_file = self.root / "state.json"

    def create(self) -> "ScanWorkspace":
        try:
            for directory in (
                self.root,
                self.root / "raw",
                self.raw_codeql,
                self.normalized_dir,
                self.ai_dir,
                self.reports_dir,
            ):
                directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkspaceError(f"cannot create scan workspace {self.root}: {exc}") from exc
        return self

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
        except OSError as exc:
            raise WorkspaceError(f"cannot write {path}: {exc}") from exc

    def read_json(self, path: Path, default: Any = None) -> Any:
        if not path.exists():
            return default
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise WorkspaceError(f"cannot read {path}: {exc}") from exc

    def write_json_atomic(self, path: Path, payload: Any) -> None:
        """Method form delegating to the module-level atomic writer."""
        write_json_atomic(path, payload)

    def write_metadata(self, payload: Dict[str, Any], created_at: Optional[str] = None) -> None:
        """Stamp metadata; ``created_at`` lets --resume keep the original time."""
        stamp = created_at or datetime.now(timezone.utc).isoformat()
        self.write_json(self.metadata_file, dict(payload, created_at=stamp))

    def write_detection(self, payload: Dict[str, Any]) -> None:
        self.write_json(self.detection_file, payload)

    def cleanup(self) -> None:
        """Delete the entire workspace (called after successful scan)."""
        if self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)


def find_resumable(workdir: Path, scan_id: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    """Locate a resumable scan workspace. Returns (scan_id, metadata).

    An explicit ``scan_id`` must exist with readable metadata; the empty
    string auto-picks the most recent workspace (by metadata ``created_at``)
    whose ``state.json`` does not mark the ``reports`` stage complete —
    successful scans delete their workspace, so anything fully complete on
    disk is already closed out.
    """
    if scan_id:
        candidate = Path(workdir) / scan_id
        metadata = _read_metadata(candidate / "metadata.json")
        if metadata is None:
            raise WorkspaceError(
                f"workspace not found for scan '{scan_id}' under {workdir} "
                "(workspaces are deleted after a successful scan)"
            )
        return scan_id, metadata

    best: Optional[Tuple[str, Dict[str, Any], str]] = None
    for directory in sorted(Path(workdir).glob("scan-*")):
        if not directory.is_dir():
            continue
        metadata = _read_metadata(directory / "metadata.json")
        if metadata is None:
            continue
        state = _read_state(directory / "state.json")
        if (state or {}).get("stages", {}).get("reports") is not None:
            continue  # already completed
        stamp = str(metadata.get("created_at") or "")
        if best is None or stamp > best[0]:
            best = (stamp, metadata, directory.name)
    if best is None:
        raise WorkspaceError(
            f"no resumable scan workspace under {workdir} "
            "(workspaces are deleted after a successful scan)"
        )
    metadata = dict(best[1])
    metadata.setdefault("scan_id", best[2])
    return best[2], metadata


def _read_metadata(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            metadata = json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return metadata if isinstance(metadata, dict) and metadata.get("source") else None


def _read_state(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}