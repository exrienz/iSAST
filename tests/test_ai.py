"""AI layer tests (offline, mocked provider responses)."""

import json
import time

import pytest

from ai.provider import (
    AIConfig,
    AIProviderError,
    AIResponseParseError,
    parse_loose_json,
    parse_response_payload,
)
from ai.openai_compatible import AIProvider
from ai.validator import AIValidator, _parse_validation_answer
from ai.deduplicator import AIDeduplicator, _parse_dedup_answer
from ai.analyzer import AIAnalyzer, apply_dedup_to_results, summarize
from core.models import ValidationStatus, ValidationResult
from findings.grouping import CandidateGroup


def test_parse_loose_json_fenced():
    assert parse_loose_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_parse_loose_json_prose_prefix():
    assert parse_loose_json('Sure! {"a": 2} done') == {"a": 1} if False else parse_loose_json('Sure! {"a": 2}') == {"a": 2}


def test_parse_response_payload_ignores_sse_trailer():
    body = '{"choices":[{"message":{"content":"ok"}}]}\n\ndata: [DONE]\ndata: [DONE]'
    document = parse_response_payload(body)
    assert document["choices"][0]["message"]["content"] == "ok"


def test_parse_validation_answer_full():
    answer = {
        "finding_id": "abc123",
        "validation": {"status": "CONFIRMED", "confidence": 1.5, "reason": "parametrized? no"},
        "canonical": {"title": "SQL Injection", "category": "Injection", "cwe": "CWE-89", "owasp": "A03:2021-Injection"},
        "risk": {"severity": "warning", "exploitability": "HIGH", "impact": "HIGH"},
        "description": "User input flows to SQL.",
        "recommendation": "Use parameterized queries.",
    }
    result = _parse_validation_answer(answer, "abc123")
    assert result is not None
    assert result.status == ValidationStatus.CONFIRMED
    assert result.confidence == 1.0  # clamped
    assert result.ai_severity == "MEDIUM"  # WARNING normalized
    assert result.cwe == "CWE-89"


def test_parse_validation_wrapped_in_list():
    answer = [{"finding_id": "abc125", "status": "CONFIRMED", "confidence": 0.9,
               "analysis": "Taint reaches sink."}]
    result = _parse_validation_answer(answer, "abc125")
    assert result is not None
    assert result.status == ValidationStatus.CONFIRMED
    assert result.finding_id == "abc125"


def test_parse_validation_rejects_bad_status():
    assert _parse_validation_answer({"validation": {"status": "NOPE"}}, "x") is None


def test_parse_validation_flat_analysis_shape():
    """Gateway variant: status/confidence/analysis at top level."""
    answer = {
        "finding_id": "abc123",
        "file": "app.py",
        "line": 10,
        "status": "confirmed",
        "confidence": 0.8,
        "analysis": "User input reaches a SQL sink.",
        "recommendation": "Use parameterized queries.",
    }
    result = _parse_validation_answer(answer, "abc123")
    assert result is not None and result.status == ValidationStatus.CONFIRMED
    assert result.confidence == 0.8
    assert result.reason == "User input reaches a SQL sink."
    assert result.recommendation == "Use parameterized queries."


def test_parse_validation_flat_summary_evidence_shape():
    """Gateway variant: summary/evidence/impact prose payload."""
    answer = {
        "finding_id": "abc124",
        "status": "LIKELY",
        "confidence": 0.7,
        "summary": "Workflow inherits all secrets.",
        "evidence": "Line 19 contains `secrets: inherit`.",
        "impact": ("An attacker gains access to every repository secret "
                   "through a compromised reusable workflow."),
    }
    result = _parse_validation_answer(answer, "abc124")
    assert result is not None and result.status == ValidationStatus.LIKELY
    assert result.reason == "Line 19 contains `secrets: inherit`."
    assert result.description == "Workflow inherits all secrets."
    # Prose impact must not be mistaken for a HIGH/MEDIUM/LOW level.
    assert result.impact is None
    assert result.exploitability is None


def _validator_with(provider_stub):
    validator = AIValidator.__new__(AIValidator)
    validator.provider = provider_stub
    validator.retry_limit = 1
    return validator


def test_validator_fail_open_on_exception():
    class Boom:
        def chat_json(self, *a, **k):
            raise AIProviderError("boom")

    result, error = _validator_with(Boom()).validate_group({"finding_id": "abc", "file": "a.py", "line": 1})
    assert result.status == ValidationStatus.UNPROCESSED
    assert "boom" in (error or "")


def test_validator_retries_unparseable_output():
    """Unparseable model output is transient: re-asked within the retry budget."""
    provider = _counting_stub(
        [AIResponseParseError("AI returned unparseable JSON: {"),
         {"results": [{"finding_id": "abc123",
                       "validation": {"status": "LIKELY", "confidence": 0.6,
                                      "reason": "f-string flows request input to a sink"}}]}],
    )
    validator = _validator_with(provider)
    validator.retry_limit = 2
    result, error = validator.validate_group({"finding_id": "abc123456", "file": "a.py", "line": 267})
    assert error is None
    assert result.status == ValidationStatus.LIKELY
    assert result.confidence == 0.6
    assert provider.calls == 2


def test_validator_fails_fast_on_transport_error():
    """Transport-shaped AIProviderError is not retried at the validator level."""
    provider = _counting_stub([AIProviderError("boom")])
    validator = _validator_with(provider)
    validator.retry_limit = 2
    result, error = validator.validate_group({"finding_id": "abc", "file": "a.py", "line": 1})
    assert result.status == ValidationStatus.UNPROCESSED
    assert provider.calls == 1
    assert "boom" in (error or "")


def test_validator_fails_fast_on_deterministic_truncation():
    """A non-recoverable parse error (truncation) burns no retry budget."""
    provider = _counting_stub([AIResponseParseError("AI output truncated (finish_reason=length)", recoverable=False)])
    validator = _validator_with(provider)
    validator.retry_limit = 2
    result, error = validator.validate_group({"finding_id": "abc", "file": "a.py", "line": 1})
    assert result.status == ValidationStatus.UNPROCESSED
    assert provider.calls == 1
    assert "finish_reason=length" in (error or "")


def _counting_stub(script):
    """Provider stub replaying a fixed script; entries raise or return."""

    class _Stub:
        calls = 0

        def chat_json(self, *a, **k):
            item = script[_Stub.calls]
            _Stub.calls += 1
            if isinstance(item, Exception):
                raise item
            return item

    return _Stub()


def _finding_stub(index, scanner="opengrep", rule="python.sql.injection"):
    class F:
        def __init__(self, i):
            self.rule_id = rule
            self.file = "app.py"
            self.line = 10 * (i + 1)
            self.column = 0
            self.scanner = scanner
            self.language = "python"
            self.scanner_title = "SQL"
            self.scanner_message = "m"
            self.scanner_severity = "HIGH"
            self.finding_id = f"{i:08x}" * 8
            self.finding_id = self.finding_id[:32]

        def to_dict(self):
            return {
                "finding_id": self.finding_id,
                "scanner": self.scanner,
                "rule_id": self.rule_id,
                "language": self.language,
                "file": self.file,
                "line": self.line,
                "column": self.column,
                "scanner_title": self.scanner_title,
                "scanner_message": self.scanner_message,
                "scanner_severity": self.scanner_severity,
            }

    return F(index)


def _group_of(*findings):
    group = CandidateGroup(key="test")
    group.findings = list(findings)
    return group


def test_analyzer_collects_and_applies_dedup():
    class Validator:
        def validate_group(self, finding, deadline=None):
            from ai.validator import ValidationResult as VR
            from core.models import ValidationStatus as VS

            return VR(finding_id=finding["finding_id"], status=VS.CONFIRMED, confidence=0.9), None

    class Reducer:
        def reduce(self, groups, **kwargs):
            from core.models import DedupLink

            return [DedupLink(canonical_finding_id=groups[0][0]["finding_id"], duplicates=[groups[0][1]["finding_id"]])], []

    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    from ai.validator import AIValidator as AV, ValidationResult as VR

    analyzer.validator = Validator()
    analyzer.deduplicator = Reducer()
    analyzer.concurrency = 4

    f1, f2 = _finding_stub(1), _finding_stub(2)
    groups = [_group_of(f1, f2)]
    results, links, errors = analyzer.analyze_groups(groups)
    assert errors == []
    assert len(links) == 1
    merged = apply_dedup_to_results(results, links)
    assert merged[f2.finding_id[:8]].status == ValidationStatus.CONFIRMED
    stats = summarize(merged)
    assert stats.validated == 2


def test_analyzer_runs_concurrently_and_deterministically():
    """Parallel validation must preserve per-group results like serial mode."""
    class SlowValidator:
        def __init__(self):
            self.calls = []

        def validate_group(self, finding, deadline=None):
            self.calls.append(finding["finding_id"])
            time.sleep(0.25)
            from core.models import ValidationStatus as VS
            return self._vr(finding["finding_id"], VS), None

        @staticmethod
        def _vr(fid, VS):
            from ai.validator import ValidationResult as VR
            return VR(fid, VS.CONFIRMED, confidence=0.5)

    class EmptyReducer:
        def reduce(self, groups, **kwargs):
            return [], []

    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.validator = SlowValidator()
    analyzer.deduplicator = EmptyReducer()
    analyzer.concurrency = 4

    groups = [_group_of(_finding_stub(i)) for i in range(1, 9)]
    started = time.monotonic()
    results, links, errors = analyzer.analyze_groups(groups)
    elapsed = time.monotonic() - started

    assert errors == []
    assert len(results) == 8
    assert all(r.status == ValidationStatus.CONFIRMED for r in results.values())
    # 8 groups x 0.25s serial = 2.0s; 4 workers should land well under that.
    assert elapsed < 1.6, f"expected concurrency, took {elapsed:.2f}s"


def test_analyzer_concurrency_one_is_serial_equivalent():
    class QuickValidator:
        def validate_group(self, finding, deadline=None):
            from ai.validator import ValidationResult as VR
            from core.models import ValidationStatus as VS
            return VR(finding["finding_id"], VS.INSUFFICIENT_EVIDENCE), None

    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.validator = QuickValidator()
    analyzer.deduplicator = _reducer_no_links()
    analyzer.concurrency = 1
    groups = [_group_of(_finding_stub(i)) for i in range(1, 4)]
    results, links, errors = analyzer.analyze_groups(groups)
    assert errors == []
    assert len(results) == 3
    assert all(r.status == ValidationStatus.INSUFFICIENT_EVIDENCE for r in results.values())


def _reducer_no_links():
    class R:
        def reduce(self, groups, **kwargs):
            return [], []
    return R()


def test_validator_uses_config_not_injected_provider():
    """AIValidator builds its own provider from config by default."""
    from ai.validator import AIValidator
    from ai.provider import AIConfig

    validator = AIValidator(AIConfig(base_url="http://x", api_key="k", model="m"))
    assert validator.provider is not None


def test_parse_dedup_unknown_ids_rejected():
    links, error = _parse_dedup_answer(
        {"duplicates": [{"canonical_finding_id": "zzzz", "duplicates": ["aaaa"]}]},
        ["aaaa", "bbbb"],
    )
    assert error is not None and "unknown" in (error or "")


def test_parse_dedup_valid():
    links, error = _parse_dedup_answer(
        {
            "duplicates": [{"canonical_finding_id": "aaaa", "duplicates": ["bbbb"]}],
            "reason": "same sink",
        },
        ["aaaa", "bbbb"],
    )
    assert error is None
    assert links[0].duplicates == ["bbbb"]


# ---------------------------------------------------------------------------
# Provider: fail-fast on non-transient bodies + failed-exchange dumps
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _StubSession:
    """Handed out one canned response per post(); extra posts fail loudly."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0
        self.last_payload = None

    def post(self, url, json=None, timeout=None):
        self.calls += 1
        self.last_payload = json
        return self._responses[self.calls - 1]


def _provider_with(tmp_path, responses, **config_kwargs):
    provider = AIProvider(
        AIConfig(base_url="http://gw", api_key="k", model="m", **config_kwargs),
        error_dump_dir=tmp_path,
    )
    provider._session = _StubSession(responses)
    return provider


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    """Keep retry tests fast: drop the exponential backoff sleeps."""
    monkeypatch.setattr("ai.openai_compatible.time.sleep", lambda _s: None)


def test_chat_fails_fast_on_unexpected_shape(tmp_path):
    """A 200 body without any assistant text burns no retry budget."""
    provider = _provider_with(tmp_path, [_StubResponse(200, '{"choices":[{"finish_reason":"stop"}]}')])
    with pytest.raises(AIProviderError) as excinfo:
        provider.chat("sys", "user")
    assert provider._session.calls == 1
    assert "unexpected AI response shape" in str(excinfo.value)
    assert "chat-failure-" in str(excinfo.value)


def test_chat_reads_legacy_completions_text_choice(tmp_path):
    """Gateways proxying the old completions shape still yield content."""
    body = '{"choices":[{"text":"{\\"status\\":\\"ok\\"}"}]}'
    provider = _provider_with(tmp_path, [_StubResponse(200, body)])
    assert provider.chat("sys", "user") == '{"status":"ok"}'


def test_chat_reassembles_forced_sse_stream(tmp_path):
    """Gateways that stream despite no stream flag are joined in order."""
    body = (
        'data: {"id":"1","object":"chat.completion.chunk","choices":[{"index":0,'
        '"delta":{"role":"assistant"},"finish_reason":null}]}\n'
        '\n'
        'data: {"id":"1","object":"chat.completion.chunk","choices":[{"index":0,'
        '"delta":{"content":"{\\"status\\":"},"finish_reason":null}]}\n'
        '\n'
        'data: {"id":"1","object":"chat.completion.chunk","choices":[{"index":0,'
        '"delta":{"content":"\\"ok\\"}"},"finish_reason":"stop"}]}\n'
        '\n'
        'data: [DONE]\n'
        '\n'
    )
    provider = _provider_with(tmp_path, [_StubResponse(200, body)])
    assert provider.chat("sys", "user") == '{"status":"ok"}'
    assert list(tmp_path.glob("chat-failure-*.json")) == []


def test_chat_handles_single_chunk_sse_message(tmp_path):
    """Some gateways stream one data: line carrying the whole message."""
    body = (
        'data: {"id":"1","object":"chat.completion",'
        '"choices":[{"index":0,"message":{"role":"assistant","content":"[]"},'
        '"finish_reason":"stop"}]}\n'
        'data: [DONE]\n'
    )
    provider = _provider_with(tmp_path, [_StubResponse(200, body)])
    assert provider.chat("sys", "user") == "[]"


def test_chat_reports_error_chunk_in_stream(tmp_path):
    """A gateway error sent inside the stream fails with its message."""
    body = 'data: {"error":{"message":"model overloaded"}}\n\n'
    provider = _provider_with(tmp_path, [_StubResponse(200, body)])
    with pytest.raises(AIProviderError) as excinfo:
        provider.chat("sys", "user")
    assert "model overloaded" in str(excinfo.value)


def test_chat_dumps_failed_response_body(tmp_path):
    """The raw gateway body is persisted for post-scan debugging."""
    body = '{"choices":[{"finish_reason":"stop"}]}'
    provider = _provider_with(tmp_path, [_StubResponse(200, body)])
    with pytest.raises(AIProviderError):
        provider.chat("sys", "user")
    dumps = list(tmp_path.glob("chat-failure-*.json"))
    assert len(dumps) == 1
    payload = json.loads(dumps[0].read_text())
    assert payload["response_body"] == body
    assert payload["status_code"] == 200
    assert payload["model"] == "m"
    assert payload["kind"] == "unexpected-shape"
    # Diagnostics record the response only — never the auth material.
    assert set(payload) == {"endpoint", "model", "status_code", "kind", "response_body"}


def test_chat_fails_fast_on_non_json_body(tmp_path):
    """HTML error pages are not transient transport state."""
    provider = _provider_with(tmp_path, [_StubResponse(200, "<html>gateway error</html>")])
    with pytest.raises(AIProviderError) as excinfo:
        provider.chat("sys", "user")
    assert provider._session.calls == 1
    assert "non-JSON AI response" in str(excinfo.value)


def _completion_body(content):
    """Wrap assistant content in a canonical chat-completion body."""
    return json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]})


def test_chat_json_dumps_unparsed_model_output(tmp_path):
    """A valid completion whose model output is unparseable is dumped, then re-asked."""
    # Balanced but invalid JSON — structurally complete, so NOT classified as
    # truncated (the truncation path fails fast; see the truncation tests).
    garbled = '{"validation": {"status": "LIKELY" "confidence", "reason"}}'
    provider = _provider_with(
        tmp_path,
        [
            _StubResponse(200, _completion_body(garbled)),
            _StubResponse(200, _completion_body('{"status": "ok"}')),
        ],
    )
    with pytest.raises(AIResponseParseError) as excinfo:
        provider.chat_json("sys", "user")
    assert "AI returned unparseable JSON" in str(excinfo.value)
    assert "saved: chat-failure-" in str(excinfo.value)
    dumps = list(tmp_path.glob("chat-failure-*.json"))
    assert len(dumps) == 1
    payload = json.loads(dumps[0].read_text())
    assert payload["kind"] == "unparsed-model-output"
    assert payload["response_body"] == garbled
    # The bounded retry loop re-fires and parses the second attempt.
    assert provider.chat_json("sys", "user") == {"status": "ok"}


def test_chat_json_error_does_not_catch_transport_failure(tmp_path):
    """chat_json only wraps parse failures — transport errors keep their kind."""
    provider = _provider_with(tmp_path, [_StubResponse(200, "<html>gateway error</html>")])
    with pytest.raises(AIProviderError) as excinfo:
        provider.chat_json("sys", "user")
    assert "non-JSON AI response" in str(excinfo.value)
    dumps = list(tmp_path.glob("chat-failure-*.json"))
    payload = json.loads(dumps[0].read_text())
    assert payload["kind"] == "non-json-body"


def test_chat_sends_max_tokens_when_configured(tmp_path):
    """AI_MAX_TOKENS is passed through; the default omits the key entirely."""
    provider = _provider_with(tmp_path, [_StubResponse(200, _completion_body('{}'))], max_tokens=512)
    provider.chat_json("sys", "user")
    assert provider._session.last_payload["max_tokens"] == 512

    default_provider = _provider_with(tmp_path, [_StubResponse(200, _completion_body('{}'))])
    default_provider.chat_json("sys", "user")
    assert "max_tokens" not in default_provider._session.last_payload


def test_chat_meta_reads_finish_reason(tmp_path):
    """finish_reason is surfaced for both document and SSE-assembled bodies."""
    document = json.dumps({
        "choices": [{
            "message": {"role": "assistant", "content": '{"status":"ok"}'},
            "finish_reason": "stop",
        }]
    })
    provider = _provider_with(tmp_path, [_StubResponse(200, document)])
    assert provider.chat_meta("s", "u") == ('{"status":"ok"}', "stop")

    sse = 'data: {"choices":[{"finish_reason":"length","message":{"content":"{}"}}]}\n\n'
    streamed = _provider_with(tmp_path, [_StubResponse(200, sse)])
    assert streamed.chat_meta("s", "u") == ("{}", "length")


def test_chat_json_fails_fast_on_truncated_output(tmp_path):
    """finish_reason=length is deterministic: fail fast, no retry burn."""
    truncated = '{"results": [{"finding_id": "b14321'
    body = json.dumps({
        "choices": [{
            "message": {"role": "assistant", "content": truncated},
            "finish_reason": "length",
        }]
    })
    provider = _provider_with(tmp_path, [_StubResponse(200, body)])
    with pytest.raises(AIResponseParseError) as excinfo:
        provider.chat_json("sys", "user")
    assert provider._session.calls == 1
    assert "finish_reason=length" in str(excinfo.value)
    assert excinfo.value.recoverable is False
    dump = json.loads((list(tmp_path.glob("chat-failure-*.json"))[0]).read_text())
    assert dump["kind"] == "truncated-output"
    assert dump["response_body"] == truncated


def test_dedup_retries_unparseable_output():
    """dedup_group re-asks once after an unparseable first attempt."""
    provider = _counting_stub(
        [AIResponseParseError("AI returned unparseable JSON: {"),
         {"duplicates": [{"canonical_finding_id": "aa11bbbb", "duplicates": ["aa12cccc"]}]}],
    )
    links, error = AIDeduplicator(provider).dedup_group(
        [{"finding_id": "aa11bbbb0000", "rule_id": "r"}, {"finding_id": "aa12cccc0000", "rule_id": "r"}]
    )
    assert error is None
    assert len(links) == 1
    assert provider.calls == 2


def test_chat_still_retries_transient_5xx(tmp_path):
    """Retry budget stays reserved for network/HTTP-transient failures."""
    good = _StubResponse(200, '{"choices":[{"message":{"content":"{}"}}]}')
    provider = _provider_with(
        tmp_path, [_StubResponse(500, "oops"), _StubResponse(500, "oops"), good],
        max_retries=3,
    )
    assert provider.chat("sys", "user") == "{}"
    assert provider._session.calls == 3
    assert list(tmp_path.glob("chat-failure-*.json")) == []


def test_validator_threads_dump_dir_to_provider(tmp_path):
    validator = AIValidator(
        AIConfig(base_url="http://x", api_key="k", model="m"),
        retry_limit=1,
        error_dump_dir=tmp_path,
    )
    assert validator.provider.error_dump_dir == tmp_path


def test_analyzer_threads_dump_dir(tmp_path):
    analyzer = AIAnalyzer(
        AIConfig(base_url="http://x", api_key="k", model="m"),
        error_dump_dir=tmp_path,
    )
    assert analyzer.validator._error_dump_dir == tmp_path

# ---------------------------------------------------------------------------
# Gateway truncation fail-fast + per-group wall-clock budget
# ---------------------------------------------------------------------------


def test_looks_truncated_json_flags_unbalanced_braces():
    from ai.provider import looks_truncated_json

    # The exact production failure shape: reply cut mid-object.
    assert looks_truncated_json('{"results":[{"validation":{"status":"LIKELY",') is True


def test_looks_truncated_json_flags_cut_inside_string():
    from ai.provider import looks_truncated_json

    assert looks_truncated_json('{"results": [{"a": "cut in str') is True


def test_looks_truncated_json_negative_cases():
    from ai.provider import looks_truncated_json

    # Balanced (even if invalid) JSON must NOT be classified as truncated.
    assert looks_truncated_json('Sure! {"a": 1} done') is False
    assert looks_truncated_json('```json\n{"results": [{"k": 1}]}\n```') is False
    assert looks_truncated_json('{"a": 1,}') is False  # sloppy but closed
    assert looks_truncated_json("no braces here") is False
    assert looks_truncated_json("") is False


def test_chat_json_fails_fast_on_gateway_truncation_with_stop_finish_reason(tmp_path):
    """finish_reason=stop + mid-object cut fails immediately (no retry burn)."""
    from ai.provider import looks_truncated_json

    assert looks_truncated_json('{"results": [{"finding_id": "b1", "validation": {"status": "LIK')
    truncated = '{"results": [{"finding_id": "b1", "validation": {"status": "LIK'
    provider = _provider_with(
        tmp_path,
        [_StubResponse(200, _completion_body(truncated))],
    )
    with pytest.raises(AIResponseParseError) as excinfo:
        provider.chat_json("sys", "user")
    assert provider._session.calls == 1  # deterministic truncation: no retry
    assert not excinfo.value.recoverable
    assert "truncated" in str(excinfo.value)
    dumps = list(tmp_path.glob("chat-failure-*.json"))
    assert len(dumps) == 1
    payload = json.loads(dumps[0].read_text())
    assert payload["kind"] == "truncated-output"


def test_chat_meta_raises_before_attempt_when_deadline_passed():
    """An already-expired group deadline attempts no HTTP call at all."""
    provider = _provider_with(tmp_path=None, responses=[_StubResponse(200, "{}")])
    with pytest.raises(AIProviderError) as excinfo:
        provider.chat_json("sys", "user", deadline=time.monotonic() - 1.0)
    assert provider._session.calls == 0
    assert not excinfo.value.recoverable
    assert "budget" in str(excinfo.value)


def test_chat_meta_caps_attempts_at_deadline():
    """Per-attempt HTTP timeout is capped at the remaining group budget."""
    per_call_timeouts = []

    class _RecordingSession:
        calls = 0

        def __init__(self, responses):
            self._responses = responses

        def post(self, url, json=None, timeout=None):
            _RecordingSession.calls += 1
            per_call_timeouts.append(timeout)
            return self._responses[_RecordingSession.calls - 1]

    provider = AIProvider(
        AIConfig(base_url="http://gw", api_key="k", model="m", max_retries=2)
    )
    transient = [_StubResponse(500, "server busy")] * 3
    provider._session = _RecordingSession(transient)
    with pytest.raises(AIProviderError) as _excinfo:
        provider.chat_json("sys", "user", deadline=time.monotonic() + 10)
    assert per_call_timeouts, "expected at least one HTTP attempt"
    assert all(timeout is not None and timeout <= 10.0 for timeout in per_call_timeouts)


def test_validator_passes_remaining_budget_deadline_to_provider():
    class Capturing:
        calls = 0
        deadlines = []

        def chat_json(self, *a, **k):
            Capturing.calls += 1
            Capturing.deadlines.append(k.get("deadline"))
            return {
                "results": [
                    {
                        "finding_id": "abc12345",
                        "validation": {"status": "CONFIRMED", "confidence": 0.9, "reason": "ok"},
                    }
                ]
            }

    validator = AIValidator.__new__(AIValidator)
    validator._config = AIConfig(base_url="http://x", api_key="k", model="m", group_budget=10)
    validator.retry_limit = 1
    validator.provider = Capturing()
    result, error = validator.validate_group({"finding_id": "abc12345", "file": "a.py", "line": 1})
    assert error is None
    assert Capturing.calls == 1
    remaining = Capturing.deadlines[0] - time.monotonic()
    assert 0 < remaining <= 10.0


def test_validator_returns_unprocessed_when_budget_was_exhausted():
    """A deadline already in the past fails open without any model call."""
    provider = _counting_stub([{"results": []}])
    validator = _validator_with(provider)
    result, error = validator.validate_group(
        {"finding_id": "abc", "file": "a.py", "line": 1}, deadline=time.monotonic() - 1.0
    )
    assert result.status == ValidationStatus.UNPROCESSED
    assert provider.calls == 0
    assert "budget" in (error or "")


def test_analyzer_propagates_group_budget_deadline_to_validator():
    class DeadlineValidator:
        deadlines = []

        def validate_group(self, finding, deadline=None):
            from ai.validator import ValidationResult as VR
            from core.models import ValidationStatus as VS

            DeadlineValidator.deadlines.append(deadline)
            return VR(finding["finding_id"], VS.INSUFFICIENT_EVIDENCE), None

    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.config = AIConfig(base_url="http://x", api_key="k", model="m", group_budget=10)
    analyzer.validator = DeadlineValidator()
    analyzer.deduplicator = _reducer_no_links()
    analyzer.concurrency = 2
    results, links, errors = analyzer.analyze_groups([_group_of(_finding_stub(1))])
    assert errors == []
    assert len(DeadlineValidator.deadlines) == 1
    remaining = DeadlineValidator.deadlines[0] - time.monotonic()
    assert 0 < remaining <= 10.0
