"""AIAnalyzer: orchestrates validation + deduplication over candidate groups
(blueprint sections 21-27). Produces ValidationResult/DedupLink artifacts
and never mutates raw scanner evidence.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Union

from ai.deduplicator import AIDeduplicator
from ai.progress import GroupEvent
from ai.provider import AIConfig
from ai.checkpoint import AICheckpoint, CachedGroup
from ai.openai_compatible import AIProvider
from ai.validator import AIValidator
from core.models import (
    DedupLink,
    ScanStats,
    ValidationResult,
    ValidationStatus,
)
from findings.grouping import CandidateGroup


def _emit(on_event: Optional[Callable[[GroupEvent], None]], event: GroupEvent) -> None:
    """Deliver a progress event; a display failure must never fail the scan."""
    if on_event is None:
        return
    try:
        on_event(event)
    except Exception:  # noqa: BLE001 — display-only fault
        pass


def _group_position(group: CandidateGroup) -> Tuple[str, int]:
    """Best-effort (file, line) for progress rows; never raises."""
    try:
        primary = group.primary()
        return primary.file, primary.line
    except Exception:  # noqa: BLE001 — display-only fault
        return "?", 0


class AIAnalyzer:
    """Run the AI analysis stage over candidate groups."""

    def __init__(
        self,
        config: AIConfig,
        *,
        batch_size: int = 20,
        concurrency: int = 8,
        error_dump_dir: Optional[Union[str, Path]] = None,
        checkpoint: Optional[AICheckpoint] = None,
    ) -> None:
        self.config = config
        self.batch_size = max(1, batch_size)
        self.concurrency = max(1, concurrency)
        self.checkpoint = checkpoint
        self.validator = AIValidator(config, error_dump_dir=error_dump_dir)
        # Dedup workers must not share one HTTP session; the factory hands
        # each thread its own provider (same config, same dump dir).
        self.deduplicator = AIDeduplicator(
            AIProvider(config, error_dump_dir=error_dump_dir),
            provider_factory=lambda: AIProvider(config, error_dump_dir=error_dump_dir),
        )

    def analyze_groups(
        self,
        groups: List[CandidateGroup],
        on_event: Optional[Callable[[GroupEvent], None]] = None,
    ) -> Tuple[Dict[str, ValidationResult], List[DedupLink], List[str]]:
        """Full AI stage.

        Validation calls run in a bounded thread pool (AI_CONCURRENCY);
        results are merged in submission order so output stays deterministic
        regardless of completion order.

        Progress events: "started" is emitted from the worker thread (or
        inline in serial mode) when a group's model call actually begins —
        so "in flight" means executing, not merely submitted; "completed"
        is emitted as each model call resolves.

        Returns:
            results: finding_id[:8] -> ValidationResult
            links: cross-scanner duplicate links
            errors: human-readable failures (findings fall back UNPROCESSED)
        """
        results: Dict[str, ValidationResult] = {}
        errors: List[str] = []
        members: List[List[dict]] = []
        total = len(groups)
        # __new__-built test stubs have no checkpoint attribute; treat as None.
        checkpoint = getattr(self, "checkpoint", None)

        # Resume: verdicts recorded by this run's checkpoint (or a previous
        # one) are reused without a model call; the rest go to the pool.
        cached: Dict[int, CachedGroup] = {}
        pairs = list(enumerate(groups, start=1))
        todo: List[Tuple[int, CandidateGroup]] = []
        for index, group in pairs:
            entry = None
            if checkpoint is not None:
                try:
                    entry = checkpoint.cached_group(group)
                except Exception:  # noqa: BLE001 — checkpoint is fail-open
                    entry = None
            if entry is not None:
                cached[index] = entry
            else:
                todo.append((index, group))

        def emit_started(index: int, group: CandidateGroup) -> None:
            file, line = _group_position(group)
            _emit(on_event, GroupEvent("started", index, total, file, line))

        def emit_completed(index: int, group: CandidateGroup, status: str, error: Optional[str]) -> None:
            file, line = _group_position(group)
            _emit(on_event, GroupEvent("completed", index, total, file, line, status, error))

        def emit_cached(index: int, group: CandidateGroup, entry: CachedGroup) -> None:
            file, line = _group_position(group)
            status = str(entry.verdict.get("status") or "UNPROCESSED")
            # Cached verdicts are informational on display; a recorded error
            # is not re-raised into the errors list (that would pin exit 5
            # on every resume of the same workspace).
            _emit(on_event, GroupEvent("cached", index, total, file, line, status, None))

        def validate_one(index: int, group: CandidateGroup):
            emit_started(index, group)
            deadline = None
            budget = getattr(getattr(self, "config", None), "group_budget", 0) or 0
            if budget > 0:
                deadline = time.monotonic() + budget
            try:
                representative = self._representative_payload(group)
                result, error = self.validator.validate_group(representative, deadline=deadline)
                emit_completed(index, group, result.status.value, error)
                return index, group, result, error
            except Exception as exc:  # noqa: BLE001 — keep the row moving, then re-raise
                emit_completed(index, group, "", f"unexpected AI error: {exc!r}")
                raise

        outcomes: List[Tuple[int, CandidateGroup, ValidationResult, Optional[str]]] = []
        for index, entry in cached.items():
            group = groups[index - 1]
            emit_cached(index, group, entry)
            outcomes.append((index, group, entry.to_result(entry.finding_id), entry.error))
        workers = min(self.concurrency, len(todo))
        if workers <= 1:
            for index, group in todo:
                outcomes.append(validate_one(index, group))
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(validate_one, index, group) for index, group in todo]
                for future in futures:
                    outcomes.append(future.result())
        # Merge in submission order — deterministic per-finding verdicts.
        for _index, group, result, error in sorted(outcomes, key=lambda item: item[0]):
            group_ids = [f.finding_id[:8] for f in group.findings]
            for gid in group_ids:
                results[gid] = result
            if error:
                errors.append(f"[{group.primary().file}:{group.primary().line}] {error}")
            members.append(self._group_payloads(group))
            if checkpoint is not None:
                try:
                    checkpoint.record(group, result, error)
                except Exception:  # noqa: BLE001 — fail-open
                    pass

        links: List[DedupLink] = []
        try:
            preloaded = checkpoint.dedup_preload() if checkpoint is not None else None

            def on_dedup_progress(done: int, total: int) -> None:
                file, line = "dedup", 0
                _emit(on_event, GroupEvent("dedup", done, total, file, line))

            links, dedup_errors = self.deduplicator.reduce(
                members,
                preloaded=preloaded,
                on_result=(
                    lambda m, l, e: checkpoint.record_dedup(m, l, e)
                ) if checkpoint is not None else None,
                on_progress=on_dedup_progress if on_event is not None else None,
                concurrency=self.concurrency,
            )
            errors.extend(dedup_errors or [])
        except Exception as exc:  # AI outage: report without links
            errors.append(f"dedup stage failed: {exc}")
        return results, links, errors

    def flush_checkpoint(self) -> None:
        """Best-effort force-write of the checkpoint (stage end / finally)."""
        checkpoint = getattr(self, "checkpoint", None)
        if checkpoint is None:
            return
        try:
            checkpoint.flush()
        except Exception:  # noqa: BLE001 — fail-open
            pass

    def _representative_payload(self, group: CandidateGroup) -> Dict:
        primary = group.primary()
        payload = primary.to_dict()
        payload["finding_id"] = primary.finding_id[:8]
        payload["group_size"] = len(group.findings)
        return payload

    def _group_payloads(self, group: CandidateGroup) -> List[Dict]:
        payloads = []
        for finding in group.findings:
            payload = finding.to_dict()
            payload["finding_id"] = finding.finding_id[:8]
            payloads.append(payload)
        return payloads


def apply_dedup_to_results(
    results: Dict[str, ValidationResult],
    links: List[DedupLink],
) -> Dict[str, ValidationResult]:
    """Propagate canonicalization across duplicate ids.

    Duplicates inherit the canonical finding's analysis so the final report
    emits one canonical row per dedup cluster (blueprint section 26).
    """
    merged = dict(results)
    for link in links:
        canonical_result = results.get(link.canonical_finding_id)
        if canonical_result is None:
            continue
        for duplicate_id in link.duplicates:
            if duplicate_id == link.canonical_finding_id:
                continue
            inherited = ValidationResult(
                finding_id=duplicate_id,
                status=canonical_result.status,
                confidence=canonical_result.confidence,
                reason=canonical_result.reason,
                title=canonical_result.title,
                category=canonical_result.category,
                cwe=canonical_result.cwe,
                owasp=canonical_result.owasp,
                ai_severity=canonical_result.ai_severity,
                exploitability=canonical_result.exploitability,
                impact=canonical_result.impact,
                description=canonical_result.description,
                recommendation=canonical_result.recommendation,
            )
            merged[duplicate_id] = inherited
    return merged


def summarize(results: Dict[str, ValidationResult]) -> ScanStats:
    """Turn validation results into the banner statistics."""
    stats = ScanStats()
    for result in results.values():
        if result.status == ValidationStatus.CONFIRMED or result.status == ValidationStatus.LIKELY:
            stats.validated += 1
        elif result.status == ValidationStatus.FALSE_POSITIVE:
            stats.false_positive += 1
        elif result.status == ValidationStatus.INSUFFICIENT_EVIDENCE:
            stats.insufficient_evidence += 1
        else:
            stats.unprocessed += 1
    return stats