"""OpenAI-compatible chat-completions client implementation.

Speaks plain HTTP POST {LLM_PROVIDER}/chat/completions with
Authorization: Bearer bearer-token (blueprint section 10), so any
gateway (OpenAI, Bifrost, LiteLLM, vLLM, Ollama-compatible) works with
only LLM_PROVIDER / LLM_KEY / LLM_MODEL changes — no code change.
"""

from __future__ import annotations

import itertools
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

from ai.provider import (
    AIConfig,
    AIProviderError,
    AIResponseParseError,
    extract_chat_meta,
    looks_truncated_json,
    parse_loose_json,
)

# Failed-response dumps are diagnostics only; cap body size to keep the
# workspace small on pathological gateways.
_DUMP_BODY_LIMIT = 4000


class AIProvider:
    """Minimal OpenAI-compatible chat-completions client (blueprint §10)."""

    def __init__(self, config: AIConfig, error_dump_dir: Optional[Union[str, Path]] = None) -> None:
        self.config = config
        self.error_dump_dir = Path(error_dump_dir) if error_dump_dir else None
        self._dump_counter = itertools.count(1)
        self._instance_id = uuid.uuid4().hex[:6]
        self._dump_lock = threading.Lock()
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json",
            }
        )

    def _dump_failure(self, kind: str, status_code: Optional[int], body: str) -> str:
        """Best-effort persist of a failed exchange for post-scan debugging.

        Writes chat-failure-<instance>-<n>.json into error_dump_dir with the
        endpoint/model/status and the raw response body (auth headers are
        never recorded). Best-effort: a dump failure must never affect the
        scan outcome (blueprint §28 fail-open).
        """
        if self.error_dump_dir is None:
            return ""
        with self._dump_lock:
            number = next(self._dump_counter)
        name = f"chat-failure-{self._instance_id}-{number:03d}.json"
        payload = {
            "endpoint": self.endpoint,
            "model": self.config.model,
            "status_code": status_code,
            "kind": kind,
            "response_body": (body or "")[:_DUMP_BODY_LIMIT],
        }
        try:
            self.error_dump_dir.mkdir(parents=True, exist_ok=True)
            (self.error_dump_dir / name).write_text(
                json.dumps(payload, indent=2), encoding="utf-8"
            )
        except OSError:
            return ""  # diagnostics only; never block the scan
        return name

    @staticmethod
    def _dump_suffix(name: str) -> str:
        return f" (saved: {name})" if name else ""

    @property
    def endpoint(self) -> str:
        base = self.config.base_url.rstrip("/")
        return f"{base}/chat/completions"

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: Optional[float] = None,
        response_json: bool = True,
        deadline: Optional[float] = None,
    ) -> str:
        """One chat completion; retries on transient failures only.

        A 200 body from which no assistant text can be extracted
        (chat.completion, streamed chunks, or legacy completions) is not
        transient — it fails immediately (no retry budget burn) and the raw
        body is dumped to error_dump_dir when one is configured. The
        validator's own retry_limit remains the tolerance layer for
        genuinely intermittent gateway shape variance.

        ``deadline`` (monotonic timestamp) caps this call's wall clock:
        attempts stop (non-recoverable) once the budget is exhausted and
        each HTTP attempt gets at most the remaining budget as its timeout.
        """
        content, _finish_reason = self.chat_meta(
            system_prompt,
            user_prompt,
            temperature=temperature,
            response_json=response_json,
            deadline=deadline,
        )
        return content

    def _remaining(self, deadline: Optional[float]) -> Optional[float]:
        """Seconds left before the per-group deadline, or None if uncapped."""
        if deadline is None:
            return None
        return deadline - time.monotonic()

    def _backoff_sleep(self, attempt: int, deadline: Optional[float]) -> bool:
        """Sleep between HTTP retry attempts. False when this was the last
        attempt within max_retries (or the per-group deadline expired)."""
        if attempt >= self.config.max_retries:
            return False
        delay = min(2 ** attempt, 8)
        remaining = self._remaining(deadline)
        if remaining is not None:
            delay = min(delay, max(0.0, remaining))
        time.sleep(delay)
        return True

    def chat_meta(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: Optional[float] = None,
        response_json: bool = True,
        deadline: Optional[float] = None,
    ) -> Tuple[str, Optional[str]]:
        """chat() that also reports the gateway's finish_reason."""
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "temperature": self.config.temperature if temperature is None else temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if self.config.max_tokens:
            payload["max_tokens"] = self.config.max_tokens
        if response_json:
            payload["response_format"] = {"type": "json_object"}
        last_error: Optional[str] = None
        for attempt in range(self.config.max_retries + 1):
            remaining = self._remaining(deadline)
            if remaining is not None and remaining <= 1.0:
                raise AIProviderError(
                    "AI group budget exhausted (AI_GROUP_BUDGET) before AI attempt",
                    recoverable=False,
                )
            # A gateway that dribbles bytes keeps the read idle timeout from
            # ever firing; capping each attempt at the remaining budget turns
            # an unbounded call into a bounded one.
            per_attempt_timeout = (
                self.config.timeout
                if remaining is None
                else max(1.0, min(self.config.timeout, remaining))
            )
            try:
                response = self._session.post(
                    self.endpoint,
                    json=payload,
                    timeout=per_attempt_timeout,
                )
            except requests.RequestException as exc:
                last_error = f"network error: {exc}"
                if not self._backoff_sleep(attempt, deadline):
                    break
                continue
            if response.status_code == 429 or response.status_code >= 500:
                last_error = f"transient HTTP {response.status_code}: {response.text[:200]}"
                if not self._backoff_sleep(attempt, deadline):
                    break
                continue
            if response.status_code >= 400:
                raise AIProviderError(
                    f"AI request rejected ({response.status_code}): {response.text[:300]}",
                    recoverable=False,
                    status_code=response.status_code,
                )
            try:
                content, finish_reason = extract_chat_meta(response.text)
            except AIProviderError as exc:
                # "non-JSON AI response" comes from parse_response_payload
                # (raw body is not a completion at all) — dump kind keeps
                # that distinction for post-scan triage.
                non_json = "non-JSON AI response" in str(exc)
                saved = self._dump_failure(
                    "non-json-body" if non_json else "unexpected-shape",
                    response.status_code,
                    response.text,
                )
                message = str(exc) if non_json else f"unexpected AI response shape: {exc}"
                raise AIProviderError(
                    f"{message}{self._dump_suffix(saved)}",
                    recoverable=False,
                    status_code=response.status_code,
                ) from None
            return content, finish_reason
        raise AIProviderError(f"AI endpoint failed after retries: {last_error}")

    def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: Optional[float] = None,
        deadline: Optional[float] = None,
    ) -> Any:
        """Chat completion parsed as JSON, tolerating fenced/sloppy output."""
        raw, finish_reason = self.chat_meta(
            system_prompt, user_prompt, temperature=temperature, deadline=deadline
        )
        try:
            return parse_loose_json(raw)
        except AIResponseParseError as exc:
            # The HTTP body above was a valid completion; only the model's own
            # output was unparseable. Persist it for triage, then let the
            # caller's bounded retry loop re-ask the model.
            truncated = (finish_reason == "length") or looks_truncated_json(raw)
            if truncated:
                # Deterministic truncation: an identical re-ask would truncate
                # again and waste the caller's retry budget. Some gateways
                # report finish_reason="stop" while cutting the reply mid-JSON
                # (unbalanced braces — seen in production dumps); the
                # structural check short-circuits those too.
                saved = self._dump_failure("truncated-output", None, raw)
                detail = (
                    "finish_reason=length"
                    if finish_reason == "length"
                    else "reply cut mid-object despite finish_reason"
                )
                raise AIResponseParseError(
                    f"AI output truncated ({detail}); raise "
                    f"AI_MAX_TOKENS or shorten the reply{self._dump_suffix(saved)}",
                    recoverable=False,
                ) from None
            saved = self._dump_failure("unparsed-model-output", None, raw)
            raise AIResponseParseError(f"{exc}{self._dump_suffix(saved)}") from None

    def ping(self) -> bool:
        """Cheap liveness probe for --doctor."""
        try:
            self.chat(
                "You are a health check. Reply with the JSON object {\"status\": \"ok\"}.",
                "Reply with {\"status\": \"ok\"}.",
                temperature=0.0,
            )
            return True
        except AIProviderError:
            return False


def chat_messages(content: str) -> List[Dict[str, str]]:
    """Convenience message builder used by prompt smoke tests."""
    return [
        {"role": "system", "content": "You are iSAST, a security finding analyst."},
        {"role": "user", "content": content},
    ]
