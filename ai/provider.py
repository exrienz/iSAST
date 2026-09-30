"""AI provider abstractions (blueprint sections 10-11).

provider.py holds the provider contract: config, errors and tolerant JSON
parsers. The concrete OpenAI-compatible HTTP client lives in
ai/openai_compatible.py so alternate transports can be swapped in.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterator, List, Optional, Tuple


class AIProviderError(RuntimeError):
    """Raised when the AI endpoint cannot be reached or returns bad payloads."""

    def __init__(self, message: str, recoverable: bool = True, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.recoverable = recoverable
        self.status_code = status_code


class AIResponseParseError(AIProviderError):
    """Raised when the model's assistant output cannot be parsed as JSON.

    Transport failures (HTTP errors) and gateway-shape variance raise the
    base AIProviderError and fail fast; a parse failure of model output is
    inherently transient, so this subclass stays recoverable and is re-asked
    by the validator/deduplicator retry loops (bounded by their budgets).
    """


@dataclass(frozen=True)
class AIConfig:
    """Configuration for a single OpenAI-compatible endpoint."""

    base_url: str
    api_key: str
    model: str
    timeout: int = 120
    max_retries: int = 3
    temperature: float = 0.0
    max_tokens: Optional[int] = None
    # Per-model-call wall-clock budget in seconds (validator/deadline layer);
    # 0 disables it so bare AIConfig() (doctor/ping) stays uncapped.
    group_budget: int = 0


def parse_response_payload(text: str) -> Any:
    """Parse the HTTP body as a chat-completions response object.

    Some gateways append SSE fragments (e.g. 'data: [DONE]') after the JSON
    body; json.JSONDecoder().raw_decode stops at the first complete object.
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        for opener in ("{", "["):
            start = text.find(opener)
            if start < 0:
                continue
            try:
                decoded, _end = json.JSONDecoder().raw_decode(text[start:])
                return decoded
            except ValueError:
                continue
        raise AIProviderError(f"non-JSON AI response: {text[:200]}")


def _strip_fences(text: str) -> str:
    """Inner content of a ```fenced``` block, or the text unchanged."""
    if "```" not in text:
        return text
    fence_start = text.find("```")
    after_fence = text[fence_start:]
    newline = after_fence.find("\n")
    fence_end = after_fence.rfind("```")
    if newline != -1 and fence_end > newline:
        return after_fence[newline:fence_end].strip()
    return text


def looks_truncated_json(raw: str) -> bool:
    """Heuristic: the model output ended mid-JSON (gateway cut the reply).

    Some gateways return finish_reason="stop" with an assistant payload that
    is structurally incomplete (unbalanced braces, or the reply ends inside a
    string literal). Re-asking such a gateway deterministically truncates
    again, so callers can fail fast instead of burning a retry budget.

    Only structurally incomplete JSON counts: every candidate must fail the
    scan and a balanced scan returns False, so valid-but-sloppy JSON that
    ``parse_loose_json`` could salvage never reaches this check.
    """
    text = _strip_fences((raw or "").strip())
    for opener in ("{", "["):
        start = text.find(opener)
        if start < 0:
            continue
        depth = 0
        in_string = False
        escaped = False
        for ch in text[start:]:
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch in "{[":
                depth += 1
            elif ch in "}]":
                depth -= 1
        if depth <= 0 and not in_string:
            return False  # this opener yields a balanced structure — not truncation
        return True  # unbalanced container or cut inside a literal string
    return False


def parse_loose_json(raw: str) -> Any:
    """Parse model output as JSON, stripping code fences and prose."""
    text = _strip_fences((raw or "").strip())
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Tolerate leading prose or trailing junk: raw_decode the first object.
        for opener in ("{", "["):
            start = text.find(opener)
            if start < 0:
                continue
            try:
                decoded, _end = json.JSONDecoder().raw_decode(text[start:])
                return decoded
            except ValueError:
                continue
        raise AIResponseParseError(f"AI returned unparseable JSON: {text[:200]}")


def _looks_like_sse(body: str) -> bool:
    """SSE bodies start with a `data:` line before anything else."""
    for line in body.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped.startswith("data:")
    return False


def _sse_data_payloads(body: str) -> Iterator[str]:
    """Yield the JSON payload of every `data:` line, skipping [DONE]."""
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.startswith("data:"):
            continue
        payload = stripped[len("data:"):].strip()
        if payload and payload != "[DONE]":
            yield payload


def _choice_assistant_content(choice: Any) -> str:
    """Assistant text from one choice object or stream chunk choice."""
    if not isinstance(choice, dict):
        return ""
    for container in ("message", "delta"):
        node = choice.get(container)
        if isinstance(node, str):
            return node  # some gateways flatten message/delta to a string
        if isinstance(node, dict):
            content = node.get("content")
            if isinstance(content, str):
                return content
    text = choice.get("text")
    return text if isinstance(text, str) else ""


def _completion_assistant_content(document: Any) -> str:
    """Assistant text from a chat-completion or chat.chunk JSON object."""
    if not isinstance(document, dict):
        return ""
    choices = document.get("choices")
    if not isinstance(choices, list):
        return ""
    for choice in choices:
        content = _choice_assistant_content(choice)
        if content:
            return content
    return ""


def _completion_finish_reason(document: Any) -> Optional[str]:
    """finish_reason from a completion/chunk body's first choice carrying one."""
    if not isinstance(document, dict):
        return None
    choices = document.get("choices")
    if not isinstance(choices, list):
        return None
    for choice in choices:
        reason = choice.get("finish_reason") if isinstance(choice, dict) else None
        if isinstance(reason, str):
            return reason
    return None


def _assemble_sse(body: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Assemble an SSE stream body: (content, error_message, finish_reason)."""
    parts: List[str] = []
    error: Optional[str] = None
    finish_reason: Optional[str] = None
    for payload in _sse_data_payloads(body):
        try:
            chunk = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            continue  # keep-assembled: a garbled line never breaks the stream
        if isinstance(chunk, dict) and isinstance(chunk.get("error"), dict):
            error = str(chunk["error"].get("message", "unknown error"))
            continue
        content = _completion_assistant_content(chunk)
        if content:
            parts.append(content)
        reason = _completion_finish_reason(chunk)
        if reason:
            finish_reason = reason
    return "".join(parts), error, finish_reason


def extract_chat_meta(body: str) -> Tuple[str, Optional[str]]:
    """Assistant text and finish_reason from a raw chat-completions HTTP body.

    Tolerates gateway variance beyond the canonical
    {choices: [{message: {content}}]}: SSE stream bodies (some gateways
    stream even when `stream` was not requested — deltas are joined in
    stream order), legacy completion bodies (choices[0].text), and
    array-wrapped responses. Raises AIProviderError when no assistant
    text can be located so the caller can dump the raw body.
    """
    stripped = (body or "").strip()
    if _looks_like_sse(stripped):
        content, error, finish_reason = _assemble_sse(stripped)
        if content:
            return content, finish_reason
        if error:
            raise AIProviderError(f"AI error in streamed response: {error}")
    else:
        document = parse_response_payload(stripped)
        content = _completion_assistant_content(document)
        finish_reason = _completion_finish_reason(document)
        if not content and isinstance(document, list):
            for item in document:
                content = _completion_assistant_content(item)
                if content:
                    finish_reason = _completion_finish_reason(item) or finish_reason
                    break
        if content:
            return content, finish_reason
    raise AIProviderError(
        f"no assistant content in AI response (body head: {stripped[:160]})"
    )


def extract_chat_content(body: str) -> str:
    """Extract assistant text from a raw chat-completions HTTP body."""
    content, _finish_reason = extract_chat_meta(body)
    return content