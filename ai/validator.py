"""AI validator: per-group finding validation with JSON schema enforcement.

Fail-open semantics (blueprint section 28): any AI failure is recorded and
the affected findings fall back to UNPROCESSED — raw findings never vanish.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional, Tuple, Union

from ai.prompts import SYSTEM_VALIDATION, build_validation_payload, schema_reminder
from ai.provider import AIConfig, AIProviderError, AIResponseParseError
from ai.openai_compatible import AIProvider
from core.models import ValidationStatus, ValidationResult

TRACE = os.environ.get("ISAST_AI_TRACE") == "1"

ALLOWED_STATUSES = {s.value for s in ValidationStatus} - {"UNPROCESSED"}
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
ALLOWED_LEVELS = {"HIGH", "MEDIUM", "LOW"}


def _trace(message: str) -> None:
    """Print a one-line AI-stage trace when ISAST_AI_TRACE=1 (diagnostics)."""
    if TRACE:
        print(f"[ai-trace] {message}", file=sys.stderr, flush=True)


def _summarize(answer: Any, limit: int = 160) -> str:
    """Short description of an unusable AI answer for tracing."""
    if isinstance(answer, dict):
        return "keys=" + ",".join(sorted(answer))
    text = str(answer)
    return text[:limit].replace("\n", " ")


def _clamp_confidence(value, default: float = 0.0) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return default
    return min(1.0, max(0.0, confidence))


def _clean_severity(value, fallback: Optional[str] = None) -> Optional[str]:
    if not isinstance(value, str):
        return fallback
    upper = value.strip().upper()
    if upper == "WARNING":
        return "MEDIUM"
    if upper == "ERROR":
        return "HIGH"
    return upper if upper in ALLOWED_SEVERITIES else fallback


def _clean_level(value, fallback: Optional[str] = None) -> Optional[str]:
    if not isinstance(value, str):
        return fallback
    upper = value.strip().upper()
    return upper if upper in ALLOWED_LEVELS else fallback


class AIValidator:
    """Validate candidate groups one LLM call at a time (batch size 1 group).

    Under the analyzer's thread pool each worker thread gets its own
    AIProvider/Session — HTTP sessions are not safely shared across threads.
    """

    def __init__(
        self,
        config: AIConfig,
        retry_limit: int = 2,
        error_dump_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        self._config = config
        self.retry_limit = retry_limit
        self._error_dump_dir = error_dump_dir
        self._local = threading.local()
        self._injected_provider: Optional[AIProvider] = None

    @property
    def provider(self) -> AIProvider:
        if self._injected_provider is not None:
            return self._injected_provider
        instance = getattr(self._local, "provider", None)
        if instance is None:
            instance = AIProvider(self._config, error_dump_dir=self._error_dump_dir)
            self._local.provider = instance
        return instance

    @provider.setter
    def provider(self, value: AIProvider) -> None:
        self._injected_provider = value

    def validate_group(
        self, finding: dict, deadline: Optional[float] = None
    ) -> Tuple[ValidationResult, Optional[str]]:
        """Validate one representative finding. Returns (result, error).

        ``deadline`` (monotonic timestamp) is the group's wall-clock budget:
        once expired the group fails open to UNPROCESSED instead of chaining
        more bounded retries into an unbounded stall (blueprint section 28).
        """
        budget = getattr(getattr(self, "_config", None), "group_budget", 0) or 0
        if deadline is None and budget > 0:
            deadline = time.monotonic() + budget
        finding_id = str(finding.get("finding_id", ""))[:8]
        last_error: Optional[str] = None
        for attempt in range(self.retry_limit + 1):
            if deadline is not None and time.monotonic() >= deadline:
                return _unprocessed_result(finding_id), (
                    f"AI group budget exhausted (AI_GROUP_BUDGET={budget}s) "
                    f"after {attempt} attempt(s): {last_error}"
                )
            try:
                started = time.monotonic()
                answer = self.provider.chat_json(
                    SYSTEM_VALIDATION,
                    build_validation_payload(finding) + "\n\n" + schema_reminder(),
                    deadline=deadline,
                )
                _trace(
                    f"validation {finding_id} call {attempt + 1} took "
                    f"{time.monotonic() - started:.1f}s"
                )
                result = _parse_validation_answer(answer, finding_id)
                if result is not None:
                    return result, None
                last_error = f"unusable schema ({_summarize(answer)})"
                _trace(
                    f"validation {finding_id} attempt {attempt + 1}: {last_error}"
                )
            except AIResponseParseError as exc:
                # Intermittent unparseable model output: re-ask within the
                # retry budget (bounded — no retry storms). The full output
                # was dumped by the provider for post-scan triage.
                if not exc.recoverable:
                    return _unprocessed_result(finding_id), str(exc)
                last_error = str(exc)
                _trace(
                    f"validation {finding_id} attempt {attempt + 1}: "
                    f"unparseable output, retrying ({_summarize(last_error)})"
                )
            except AIProviderError as exc:
                return _unprocessed_result(finding_id), str(exc)
            except Exception as exc:  # defensive: never break a scan on AI quirks
                return _unprocessed_result(finding_id), f"unexpected AI error: {exc}"
        return _unprocessed_result(finding_id), (
            f"AI returned invalid JSON after retries: {last_error}"
        )


def _parse_validation_answer(answer, finding_id: str) -> Optional[ValidationResult]:
    """Extract ValidationResult from an AI answer payload."""
    if isinstance(answer, list):
        # Some gateways wrap the schema object in a one-element JSON array.
        answer = next((item for item in answer if isinstance(item, dict)), None)
    if not isinstance(answer, dict):
        return None
    node = answer
    if isinstance(node.get("results"), list):
        listed = [item for item in node["results"] if isinstance(item, dict)]
        if not listed:
            return None
        node = listed[0]
        # Batch responses carry their own finding ids; honor them.
        finding_id = str(node.get("finding_id") or finding_id)[:8]
    if "validation" not in node:
        node = _lift_flat_validation(node) or node
    validation = node.get("validation") or {}
    canonical = node.get("canonical") or {}
    risk = node.get("risk") or {}
    status_raw = str(validation.get("status") or "").upper()
    if status_raw not in ALLOWED_STATUSES:
        return None
    description = node.get("description")
    recommendation = node.get("recommendation")
    return ValidationResult(
        finding_id=finding_id,
        status=ValidationStatus(status_raw),
        confidence=_clamp_confidence(validation.get("confidence")),
        reason=str(validation.get("reason") or "")[:2000],
        title=_clean_text(canonical.get("title"), 200),
        category=_clean_text(canonical.get("category"), 100),
        cwe=_clean_text(canonical.get("cwe"), 32),
        owasp=_clean_text(canonical.get("owasp"), 64),
        ai_severity=_clean_severity(risk.get("severity")),
        exploitability=_clean_level(risk.get("exploitability")),
        impact=_clean_level(risk.get("impact")),
        description=_clean_text(description, 4000),
        recommendation=_clean_text(recommendation, 4000),
    )


def _lift_flat_validation(node: dict) -> Optional[dict]:
    """Normalize flat answers (status/confidence alongside prose) to the schema.

    Gateways vary in how strictly the model follows the requested nested
    schema: some reply with {"status": ..., "confidence": ..., "analysis"/
    "evidence"/"summary": ...} at the top level. Lifting that shape into the
    canonical nested form prevents retry storms on schema-parsing.
    """
    status = str(node.get("status") or node.get("verdict") or "").strip().upper()
    if status not in ALLOWED_STATUSES:
        return None
    impact = node.get("impact")
    return {
        "validation": {
            "status": status,
            "confidence": node.get("confidence"),
            "reason": node.get("reason")
            or node.get("analysis")
            or node.get("evidence")
            or node.get("summary"),
        },
        "canonical": {
            "title": node.get("title"),
            "category": node.get("category"),
            "cwe": node.get("cwe"),
            "owasp": node.get("owasp"),
        },
        "risk": {
            "severity": node.get("severity") or node.get("ai_severity"),
            "exploitability": node.get("exploitability"),
            "impact": impact if isinstance(impact, str) and impact.strip().upper() in ALLOWED_LEVELS else node.get("risk_level"),
        },
        "description": node.get("description")
        or node.get("summary")
        or node.get("evidence")
        or node.get("analysis")
        or (impact
            if isinstance(impact, str) and impact.strip().upper() not in ALLOWED_LEVELS
            else None),
        "recommendation": node.get("recommendation")
        or node.get("mitigation")
        or node.get("fix"),
    }


def _clean_text(value, limit: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned or cleaned.lower() in ("null", "none", "n/a"):
        return None
    return cleaned[:limit]


def _unprocessed_result(finding_id: str) -> ValidationResult:
    return ValidationResult(finding_id=finding_id, status=ValidationStatus.UNPROCESSED)