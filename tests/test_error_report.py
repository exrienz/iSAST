"""ai.error_report: error-kind classification for the ai/errors.json artifact."""

from ai.error_report import classify_ai_error, summarize_ai_errors


def test_classify_truncated_output():
    message = (
        "AI output truncated (finish_reason=length); raise AI_MAX_TOKENS "
        "or shorten the reply (saved: chat-failure-x-001.json)"
    )
    assert classify_ai_error(message) == "truncated-output"


def test_classify_model_output_parse():
    assert classify_ai_error(
        "AI returned unparseable JSON: {\"results\" [..] (saved: chat-failure-x-002.json)"
    ) == "model-output-parse"


def test_classify_retry_exhausted_paths():
    schema = "AI returned invalid JSON after retries: unusable schema (keys=status)"
    assert classify_ai_error(schema) == "schema-shape"
    parse = ("AI returned invalid JSON after retries: AI returned unparseable "
             "JSON: {\"results\" (saved: chat-failure-x-003.json)")
    assert classify_ai_error(parse) == "parse-after-retries"


def test_classify_transport_and_gateway():
    assert classify_ai_error("AI endpoint failed after retries: network error: ...") == "transport-exhausted"
    assert classify_ai_error("AI request rejected (401): invalid key") == "http-rejected"
    assert classify_ai_error("unexpected AI response shape: no assistant content") == "gateway-shape"
    assert classify_ai_error("non-JSON AI response: <html>") == "gateway-non-json-body"


def test_classify_disabled_and_unknown():
    assert classify_ai_error("AI disabled or not configured; findings marked UNPROCESSED") == "disabled"
    assert classify_ai_error("AI analyzer unavailable: missing api key") == "analyzer-unavailable"
    assert classify_ai_error("weird unexplainable failure") == "unknown"


def test_classifier_order_is_specific_first():
    """A retry-exhausted message embedding 'unusable schema' stays schema-shape."""
    message = "AI returned invalid JSON after retries: unusable schema (keys=status)"
    assert classify_ai_error(message) == "schema-shape"


def test_summarize_counts_kinds_and_caps_errors():
    errors = (["AI returned unparseable JSON: x"] * 3
              + ["AI output truncated (finish_reason=length); raise AI_MAX_TOKENS"]
              + ["unexpected AI response shape: no assistant content"])
    report = summarize_ai_errors(errors)
    assert report["total_errors"] == 5
    assert report["kinds"] == {"model-output-parse": 3, "truncated-output": 1, "gateway-shape": 1}
    assert len(report["errors"]) == 5
    assert report["more_errors"] == 0


def test_summarize_caps_long_error_lists():
    errors = ["AI returned unparseable JSON: x"] * 350
    report = summarize_ai_errors(errors)
    assert report["total_errors"] == 350
    assert len(report["errors"]) == 200
    assert report["more_errors"] == 150
    assert report["kinds"] == {"model-output-parse": 350}


def test_summarize_empty():
    report = summarize_ai_errors([])
    assert report["total_errors"] == 0
    assert report["kinds"] == {}
    assert report["errors"] == []