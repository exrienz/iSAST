"""Incremental AI-stage checkpoints (resume support).

While the model calls run, every completed verdict and dedup link is
written atomically to the workspace:

    ai/validation-partial.json   ({"groups": {"<rep8>": {...verdict...}}})
    ai/dedup.json                ({"groups": {"<sorted member ids>": {...}}})

A killed scan keeps everything already decided, so
``python isast.py --resume`` re-asks only the groups that never finished
(without --resume the fresh path is otherwise unaffected). Fail-open
(blueprint section 28): checkpoint failures can never break the AI stage —
a corrupt or truncated file simply reads back as empty.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.workspace import write_json_atomic

FORMAT_VERSION = 1
DEFAULT_THROTTLE_SECONDS = 2.0
# Small stages checkpoint after every completion so short runs stay fully
# resumable; large stages throttle to avoid rewriting the file per event.
IMMEDIATE_WRITE_FLOOR = 50


@dataclass
class CachedGroup:
    """One recorded per-group verdict (serialization form)."""

    finding_id: str  # representative short id (the checkpoint key)
    member_ids: List[str]
    verdict: Dict[str, Any]
    error: Optional[str]

    def to_result(self, finding_id: str) -> "ValidationResult":
        from core.models import ValidationStatus, ValidationResult

        try:
            status = ValidationStatus(str(self.verdict.get("status") or "UNPROCESSED"))
        except ValueError:
            status = ValidationStatus.UNPROCESSED
        return ValidationResult(
            finding_id=finding_id,
            status=status,
            confidence=float(self.verdict.get("confidence") or 0.0),
            reason=str(self.verdict.get("reason") or ""),
            title=self.verdict.get("title"),
            category=self.verdict.get("category"),
            cwe=self.verdict.get("cwe"),
            owasp=self.verdict.get("owasp"),
            ai_severity=self.verdict.get("ai_severity"),
            exploitability=self.verdict.get("exploitability"),
            impact=self.verdict.get("impact"),
            description=self.verdict.get("description"),
            recommendation=self.verdict.get("recommendation"),
        )


def _cached_group_from_entry(rep: str, entry: Dict[str, Any]) -> CachedGroup:
    return CachedGroup(
        finding_id=str(entry.get("finding_id") or rep),
        member_ids=[str(m) for m in entry.get("member_ids") or []],
        verdict=dict(entry.get("verdict") or {}),
        error=entry.get("error"),
    )


class AICheckpoint:
    """Thread-safe, throttled, atomic store of AI-stage progress."""

    def __init__(
        self,
        path: Path,
        dedup_path: Optional[Path] = None,
        *,
        throttle_seconds: float = DEFAULT_THROTTLE_SECONDS,
        clock: Any = time.time,
    ) -> None:
        self._path = Path(path)
        self.dedup_path = Path(dedup_path) if dedup_path is not None else None
        self._throttle = max(0.0, float(throttle_seconds))
        self._clock = clock
        self._lock = threading.Lock()
        self._groups: Dict[str, Dict[str, Any]] = {}
        self._dedup: Dict[str, Any] = {}
        self._last_write = 0.0
        self._writes = 0

    # ------------------------------------------------------------------
    # Loading (resume side)
    # ------------------------------------------------------------------

    def preload(self) -> Dict[str, CachedGroup]:
        """Load saved verdicts. Corrupt/truncated file → {} (fail-open)."""
        with self._lock:
            self._groups = dict(_read_groups(self._path))
            return {rep: _cached_group_from_entry(rep, entry) for rep, entry in self._groups.items()}

    def dedup_preload(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load saved dedup links keyed by sorted member short ids."""
        with self._lock:
            self._dedup = dict(_read_dedup(self.dedup_path))
            return {key: list(entry.get("links") or []) for key, entry in self._dedup.items()}

    @staticmethod
    def preload_file(path: Path) -> Dict[str, CachedGroup]:
        """Standalone loader (testing/tooling); tolerant like preload()."""
        return {rep: _cached_group_from_entry(rep, entry) for rep, entry in _read_groups(Path(path)).items()}

    def cached_group(self, group) -> Optional[CachedGroup]:
        """Reuse a recorded verdict for this group, or None.

        A group re-runs when its recorded entry is UNPROCESSED-with-error
        (a budget stall or transient failure gets a fresh call on resume).
        """
        try:
            rep = group.primary().finding_id[:8]
            current_members = {f.finding_id[:8] for f in group.findings}
        except Exception:  # noqa: BLE001 — never block the scan
            return None
        entry = self._groups.get(rep)
        if entry is None:
            return None
        # [:8] collision guard: the saved entry must describe this exact group.
        if set(str(m) for m in entry.get("member_ids") or []) != current_members:
            return None
        if (entry.get("verdict") or {}).get("status") == "UNPROCESSED" and entry.get("error"):
            return None  # recorded failure: worth a fresh model call
        return CachedGroup(
            finding_id=rep,
            member_ids=sorted(current_members),
            verdict=dict(entry.get("verdict") or {}),
            error=entry.get("error"),
        )

    # ------------------------------------------------------------------
    # Recording (run side)
    # ------------------------------------------------------------------

    def record(self, group, result, error: Optional[str]) -> None:
        """Persist one completed group verdict (called from worker threads)."""
        try:
            rep = result.finding_id[:8]
            member_ids = sorted(f.finding_id[:8] for f in group.findings)
        except Exception:  # noqa: BLE001 — fail-open
            return
        with self._lock:
            self._groups[rep] = {
                "finding_id": rep,
                "member_ids": member_ids,
                "verdict": _verdict_payload(result),
                "error": error,
            }
            self._write_if_due_locked()

    def record_dedup(self, members, links, error: Optional[str]) -> None:
        """Persist one completed dedup group (empty links = no duplicates)."""
        try:
            key = "|".join(sorted(str(m.get("finding_id", ""))[:8] for m in members if m))
        except Exception:  # noqa: BLE001 — fail-open
            return
        entry: Dict[str, Any] = {
            "links": [
                {
                    "canonical_finding_id": link.canonical_finding_id,
                    "duplicates": list(link.duplicates),
                    "reason": link.reason,
                }
                for link in (links or [])
                if link is not None
            ],
            "error": error,
        }
        with self._lock:
            self._dedup[key] = entry
            self._write_if_dedup_due_locked()

    def flush(self) -> None:
        """Force an immediate write (stage end / finally)."""
        with self._lock:
            self._write_locked()

    def __len__(self) -> int:
        with self._lock:
            return len(self._groups)

    # ------------------------------------------------------------------
    # Write plumbing (all under self._lock)
    # ------------------------------------------------------------------

    def _write_if_due_locked(self) -> None:
        if not self._groups:
            return
        now = self._clock()
        if self._writes <= IMMEDIATE_WRITE_FLOOR or now - self._last_write >= self._throttle:
            self._last_write = now
            self._writes += 1
            self._write_locked()

    def _write_if_dedup_due_locked(self) -> None:
        if not self._dedup:
            return
        now = self._clock()
        if self._writes <= IMMEDIATE_WRITE_FLOOR or now - self._last_write >= self._throttle:
            self._last_write = now
            self._writes += 1
            self._write_locked()

    def _write_locked(self) -> None:
        """Atomic best-effort write of both checkpoint files."""
        try:
            if self._groups:
                write_json_atomic(self._path, _document(self._groups, self._clock))
        except Exception:  # noqa: BLE001 — fail-open
            pass
        if self.dedup_path is not None:
            try:
                write_json_atomic(self.dedup_path, _document(self._dedup, self._clock))
            except Exception:  # noqa: BLE001 — fail-open
                pass


def _document(groups: Dict[str, Any], clock) -> Dict[str, Any]:
    return {"format": FORMAT_VERSION, "groups": groups, "updated_at": int(clock())}


def _read_groups(path: Path) -> Dict[str, Dict[str, Any]]:
    return _filter_entries(_read_document(path))


def _read_dedup(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {}
    return _filter_entries(_read_document(path))


def _filter_entries(document: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    groups = document.get("groups") if isinstance(document, dict) else None
    if not isinstance(groups, dict):
        return {}
    return {rep: entry for rep, entry in groups.items() if isinstance(entry, dict)}


def _read_document(path: Path) -> Dict[str, Any]:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return document if isinstance(document, dict) else {}


def _verdict_payload(result) -> Dict[str, Any]:
    """ValidationResult → plain JSON map for the checkpoint file."""
    return {
        "status": result.status.value,
        "confidence": float(result.confidence),
        "reason": str(result.reason or ""),
        "title": result.title,
        "category": result.category,
        "cwe": result.cwe,
        "owasp": result.owasp,
        "ai_severity": result.ai_severity,
        "exploitability": result.exploitability,
        "impact": result.impact,
        "description": result.description,
        "recommendation": result.recommendation,
    }