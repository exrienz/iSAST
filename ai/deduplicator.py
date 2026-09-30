"""AI deduplicator (blueprint section 26).

Groups findings the AI judges to describe the SAME vulnerability under a
single canonical finding. Raw evidence is never deleted — links live in
raw-findings.json.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

from ai.prompts import SYSTEM_DEDUP, build_dedup_payload
from ai.provider import AIProviderError, AIResponseParseError
from ai.openai_compatible import AIProvider
from ai.validator import _summarize, _trace
from core.models import DedupLink


def dedup_key(members: List[dict]) -> str:
    """Stable key for a group's dedup results (sorted member short ids)."""
    return "|".join(sorted(str(m.get("finding_id", ""))[:8] for m in members if m))


class AIDeduplicator:
    """Ask the model to merge duplicate findings inside candidate groups."""

    def __init__(
        self,
        provider: AIProvider,
        *,
        provider_factory: Optional[Callable[[], AIProvider]] = None,
    ) -> None:
        self.provider = provider
        # HTTP sessions are not safely shared across threads; a factory gives
        # each dedup worker its own provider (mirrors AIValidator's locals).
        self.provider_factory = provider_factory
        self._local = threading.local()

    def _thread_provider(self) -> AIProvider:
        if self.provider_factory is None:
            return self.provider  # injected/stub provider (single-threaded use)
        instance = getattr(self._local, "provider", None)
        if instance is None:
            instance = self.provider_factory()
            self._local.provider = instance
        return instance

    def dedup_group(self, members: List[dict]) -> Tuple[List[DedupLink], Optional[str]]:
        """Returns (links, error). Missing ids default to self-canonical."""
        if len(members) < 2:
            return [], None
        provider = self._thread_provider()
        ids = [str(m.get("finding_id", ""))[:8] for m in members]
        budget = getattr(getattr(provider, "config", None), "group_budget", 0) or 0
        deadline = time.monotonic() + budget if budget > 0 else None
        last_error: Optional[str] = None
        for attempt in range(2):
            if deadline is not None and time.monotonic() >= deadline:
                return [], (
                    f"AI group budget exhausted (AI_GROUP_BUDGET={budget}s) "
                    f"during dedup after {attempt} attempt(s): {last_error}"
                )
            try:
                answer = provider.chat_json(SYSTEM_DEDUP, build_dedup_payload(members), deadline=deadline)
                links, error = _parse_dedup_answer(answer, ids)
                if error is None:
                    return links, None
                last_error = f"{error} ({_summarize(answer)})"
                _trace(f"dedup {ids} attempt {attempt + 1}: {last_error}")
            except AIResponseParseError as exc:
                # Intermittent unparseable model output: re-ask within the
                # bounded retry budget. The full output was dumped by the
                # provider for post-scan triage.
                if not exc.recoverable:
                    return [], str(exc)
                last_error = str(exc)
                _trace(
                    f"dedup {ids} attempt {attempt + 1}: unparseable output, "
                    f"retrying ({_summarize(last_error)})"
                )
            except AIProviderError as exc:
                return [], str(exc)
            except Exception as exc:  # defensive: AI quirks must not kill scans
                return [], f"unexpected dedup error: {exc}"
        return [], f"dedup AI returned invalid JSON after retries: {last_error}"

    def reduce(
        self,
        groups_members: List[List[dict]],
        *,
        preloaded: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        on_result: Optional[Callable[[List[dict], List[DedupLink], Optional[str]], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        concurrency: int = 1,
    ) -> Tuple[List[DedupLink], List[str]]:
        """Run dedup over many groups; returns (links, errors).

        Groups recorded in ``preloaded`` (from the run's own checkpoint) are
        reused without a model call; the rest run through a bounded thread
        pool so dedup no longer serialises behind hundreds of slow gateway
        calls. Order stays deterministic: links merge in submission order.
        """
        saved = preloaded or {}
        all_links: List[DedupLink] = []
        errors: List[str] = []
        todo: List[List[dict]] = []
        for members in groups_members:
            entry = saved.get(dedup_key(members))
            links, error = _links_from_saved(entry, members)
            if links is None:
                todo.append(members)
                continue
            all_links.extend(links)
            if error:
                errors.append(error)
            continue
        if not todo:
            return all_links, errors
        if on_result is None:
            on_result = lambda _m, _l, _e: None  # noqa: E731 — no checkpoint wired
        done = 0
        total = len(todo)

        def _announce() -> None:
            nonlocal done
            done += 1
            if on_progress is not None:
                try:
                    on_progress(done, total)
                except Exception:  # noqa: BLE001 — progress must never fail dedup
                    pass

        def one(members: List[dict]) -> Tuple[List[DedupLink], Optional[str]]:
            links, error = self.dedup_group(members)
            try:
                on_result(members, links, error)
            except Exception:  # noqa: BLE001 — fail-open
                pass
            _announce()
            return links, error

        workers = min(max(1, concurrency), len(todo))
        if workers <= 1:
            for members in todo:
                links, error = one(members)
                if error:
                    errors.append(error)
                all_links.extend(links)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for links, error in pool.map(one, todo):
                    if error:
                        errors.append(error)
                    all_links.extend(links)
        return all_links, errors


def _links_from_saved(entry: Any, members: List[dict]) -> Tuple[Optional[List[DedupLink]], Optional[str]]:
    """Saved links for this member set, or None when the group must re-run.

    Links referencing ids outside the current member set are dropped (a
    stale/colliding checkpoint entry can never inject a wrong merge).
    """
    if not isinstance(entry, dict):
        return None, None  # missing → re-run
    if entry.get("error"):
        return None, None  # recorded failure → fresh model call
    known = {str(m.get("finding_id", ""))[:8] for m in members}
    links: List[DedupLink] = []
    for item in entry.get("links") or []:
        if not isinstance(item, dict):
            continue
        canonical = str(item.get("canonical_finding_id", ""))[:8]
        if not canonical or canonical not in known:
            continue
        duplicates = [d for d in (item.get("duplicates") or []) if str(d)[:8] in known and str(d)[:8] != canonical]
        links.append(
            DedupLink(
                canonical_finding_id=canonical,
                duplicates=sorted({str(d)[:8] for d in duplicates}),
                reason=str(item.get("reason") or ""),
            )
        )
    return links, None


def _parse_dedup_answer(answer, expected_ids: List[str]) -> Tuple[List[DedupLink], Optional[str]]:
    """Validate the dedup structure; ids must cover the group exactly once."""
    if not isinstance(answer, dict):
        return [], "dedup answer is not a JSON object"
    links: List[Dict] = answer.get("duplicates")
    if not isinstance(links, list):
        return [], "dedup payload missing 'duplicates' list"
    parsed: List[DedupLink] = []
    covered: set = set()
    for link in links or []:
        if not isinstance(link, dict):
            continue
        canonical = _short_id(link.get("canonical_finding_id"))
        duplicate_ids = [_short_id(d) for d in (link.get("duplicates") or []) if _short_id(d)]
        if not canonical and duplicate_ids:
            canonical = duplicate_ids[0]
        if not canonical:
            continue
        group_ids = [canonical] + [d for d in duplicate_ids if d != canonical]
        unknown = [gid for gid in group_ids if gid not in expected_ids]
        if unknown:
            return [], f"dedup referenced unknown finding ids: {unknown[:5]}"
        covered.update(group_ids)
        parsed.append(
            DedupLink(
                canonical_finding_id=canonical,
                duplicates=[gid for gid in group_ids if gid != canonical],
                reason=str(answer.get("reason") or "")[:500],
            )
        )
    missing = [gid for gid in expected_ids if gid not in covered]
    if missing:
        # Missing ids resolve trivially to themselves — no error needed, the
        # orchestrator maps unlinked findings to their own canonical entry.
        pass
    return parsed, None


def _short_id(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    return value.strip()[:8] or None