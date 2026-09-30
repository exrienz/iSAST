"""Aggregate AI-stage errors into a reportable summary.

The scan banner shows at most a few raw error strings; this module turns the
full error list into a kind histogram for the workspace artifact
`ai/errors.json`, so post-scan triage starts from a directory listing instead
of log archaeology.
"""

from __future__ import annotations

from typing import Dict, List

# Classification markers, checked in order — first match wins.
# Order matters: specific retry-exhausted messages (which embed the per-attempt
# detail after "after retries:") come before their raw markers.
_AI_ERROR_KINDS = (
    ("truncated (finish_reason=length)", "truncated-output"),
    ("finish_reason=length", "truncated-output"),
    ("unusable schema", "schema-shape"),
    ("invalid JSON after retries", "parse-after-retries"),
    ("unparseable JSON", "model-output-parse"),
    ("unexpected AI response shape", "gateway-shape"),
    ("no assistant content", "gateway-shape"),
    ("non-JSON AI response", "gateway-non-json-body"),
    ("AI request rejected", "http-rejected"),
    ("AI endpoint failed after retries", "transport-exhausted"),
    ("network error", "network"),
    ("AI analyzer unavailable", "analyzer-unavailable"),
    ("AI disabled", "disabled"),
    ("dedup AI returned invalid JSON", "parse-after-retries"),
)

_MAX_KEPT_ERRORS = 200


def classify_ai_error(message: str) -> str:
    """Map one error string to a coarse failure kind for triage."""
    text = str(message or "")
    for marker, kind in _AI_ERROR_KINDS:
        if marker in text:
            return kind
    return "unknown"


def summarize_ai_errors(errors: List[str]) -> Dict[str, object]:
    """Build the ai/errors.json payload: counts plus a capped raw list."""
    kinds: Dict[str, int] = {}
    for error in errors or []:
        kind = classify_ai_error(error)
        kinds[kind] = kinds.get(kind, 0) + 1
    kept = list(errors or [])[:_MAX_KEPT_ERRORS]
    return {
        "total_errors": len(errors or []),
        "kinds": kinds,
        "errors": kept,
        "more_errors": max(0, len(errors or []) - len(kept)),
    }